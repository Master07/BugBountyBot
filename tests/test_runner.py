"""Runner end-to-end: scope guard -> audit log -> run module -> persist + dedup."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

import pytest

from bugbountybot.payloads.loader import PayloadLibrary
from bugbountybot.runner.service import ScopedRunner
from bugbountybot.storage.audit import recent
from bugbountybot.storage.db import Finding


class EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        params = dict(parse_qsl(urlsplit(self.path).query))
        q = params.get("q", "")
        if self.path.startswith("/xss"):
            body = f"<html>results for {q}</html>".encode()
        else:
            body = b"ok"
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture()
def scoped_runner(session, scoped_program, artifacts, server):
    # scope fixture has *.acme.com but server is 127.0.0.1 — add it in scope
    from bugbountybot.tracker.service import add_scope

    add_scope(session, scoped_program.id, "127.0.0.1", kind="ip")
    return ScopedRunner(
        session,
        program_id=scoped_program.id,
        library=PayloadLibrary.from_directory("payloads"),
        artifacts=artifacts,
        oob=None,
        confirm=False,
    )


def test_runner_blocks_out_of_scope(session, scoped_runner, server):
    run = scoped_runner.run_module("xss", "https://evil.com/x", max_tier=2)
    assert run.blocked >= 1
    # audit log recorded the block
    entries = recent(session, 10)
    assert any(not e.allowed for e in entries)


def test_runner_requires_confirm_for_tier3(session, scoped_runner, server):
    # ssrf is tier 3 — without --confirm it should be blocked even if the
    # scope guard would otherwise allow tier 3.
    run = scoped_runner.run_module("ssrf", f"{server}/fetch", max_tier=3)
    assert run.blocked >= 1
    assert run.findings == []


def test_runner_tier3_runs_with_confirm(session, scoped_program, artifacts, server):
    from bugbountybot.tracker.service import add_scope

    add_scope(session, scoped_program.id, "127.0.0.1", kind="ip")
    runner = ScopedRunner(
        session,
        program_id=scoped_program.id,
        library=PayloadLibrary.from_directory("payloads"),
        artifacts=artifacts,
        oob=None,
        confirm=True,
    )
    # With --confirm but no OOB listener, SSRF is still blocked (needs OOB).
    run = runner.run_module("ssrf", f"{server}/fetch", max_tier=3)
    assert run.blocked >= 1
    assert run.findings == []


def test_runner_persists_and_dedupes(session, scoped_runner, server):
    endpoints = [{"url": f"{server}/xss", "method": "GET", "params": "q"}]
    # inject endpoints directly into the runner's program inventory
    from bugbountybot.tracker.service import add_endpoint

    add_endpoint(session, scoped_runner.scope.program_id, f"{server}/xss", params="q")

    run = scoped_runner.run_module("xss", f"{server}/xss", max_tier=2)
    stored = scoped_runner.persist_findings(scoped_runner.scope.program_id, run)
    assert stored, "expected at least one finding persisted"
    keys = {f.dedup_key for f in session.query(Finding).all()}
    assert keys  # dedup keys are set

    # run again — dedup should prevent new rows
    run2 = scoped_runner.run_module("xss", f"{server}/xss", max_tier=2)
    stored2 = scoped_runner.persist_findings(scoped_runner.scope.program_id, run2)
    assert stored2 == []


def test_audit_log_append_only(session, scoped_runner, server):
    before = len(recent(session, 100))
    scoped_runner.run_module("xss", "https://evil.com/x", max_tier=2)
    after = len(recent(session, 100))
    assert after > before
