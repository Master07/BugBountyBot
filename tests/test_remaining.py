"""GraphQL module + businesslogic extensions + backup + settings tests."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from bugbountybot.payloads.loader import PayloadLibrary
from bugbountybot.vuln.base import run_module
from bugbountybot.vuln.graphql import GraphQLModule


class GqlHandler(BaseHTTPRequestHandler):
    """Introspection-enabled GraphQL server."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "replace")
        try:
            q = json.loads(raw).get("query", "")
        except Exception:
            q = ""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if "__schema" in q:
            body = {"data": {"__schema": {"types": [{"name": "Query"}]}}}
        elif "users" in q or "orders" in q:
            body = {"data": {"users": {"__typename": "User"}}}
        else:
            body = {"data": {}}
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def gql_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), GqlHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


# ---- GraphQL ----
def test_graphql_detects_introspection(gql_server):
    lib = PayloadLibrary.from_directory("payloads")
    with httpx.Client(timeout=10) as client:
        m = GraphQLModule(client, lib)
        findings = run_module(m, f"{gql_server}/graphql", max_tier=2, endpoints=[])
        assert findings, "expected introspection finding"
        assert any("introspection" in f.detail for f in findings)


def test_graphql_no_findings_on_closed():
    """A server that returns 404/not-JSON must produce no findings."""
    import threading as _t
    from http.server import BaseHTTPRequestHandler as _H, ThreadingHTTPServer as _T

    class Closed(_H):
        def do_POST(self):  # noqa: N802
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")

        def log_message(self, *a):
            pass

    httpd = _T(("127.0.0.1", 0), Closed)
    _t.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    lib = PayloadLibrary.from_directory("payloads")
    with httpx.Client(timeout=10) as client:
        m = GraphQLModule(client, lib)
        findings = run_module(m, f"{base}/graphql", max_tier=2, endpoints=[])
        assert findings == []
    httpd.shutdown()


# ---- business-logic new categories ----
def test_businesslogic_new_categories(session, program):
    # ensure the businesslogic tables are registered on the shared Base
    import bugbountybot.businesslogic.models as _bl  # noqa: F401

    from bugbountybot.businesslogic.generator import generate_plan
    from bugbountybot.tracker.service import add_scope

    add_scope(session, program.id, "127.0.0.1", kind="ip")
    for cat in ("auth", "cart", "signup", "coupon"):
        plan = generate_plan(session, program.id, category=cat, target="http://127.0.0.1:9/x")
        assert plan.category == cat
        assert len(plan.steps) >= 2


# ---- backup ----
def test_backup_copies_data(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from bugbountybot.cli.main import app
    from bugbountybot.storage.db import init_db

    data_dir = tmp_path / "data"
    init_db(data_dir)
    (data_dir / "artifacts").mkdir(exist_ok=True)
    (data_dir / "artifacts" / "x.http").write_text("req/resp")

    monkeypatch.setenv("BUGBOUNTY_DATA_DIR", str(data_dir))
    import bugbountybot.config.settings as _cfg

    _cfg._settings = None  # reset the singleton so it re-reads env
    r = CliRunner().invoke(app, ["backup"])
    assert r.exit_code == 0
    backups = list((data_dir / "backups").iterdir())
    assert backups, "backup folder created"
    copied = list(backups[0].rglob("x.http"))
    assert copied and copied[0].read_text() == "req/resp"


# ---- typed settings ----
def test_settings_typed_and_env_override(monkeypatch):
    from bugbountybot.config.settings import Settings, get_settings

    monkeypatch.setenv("BUGBOUNTY_DATA_DIR", "/tmp/override-data")
    # get_settings is a singleton; construct a fresh one to test env reading
    s = Settings()
    assert str(s.data_dir) == "/tmp/override-data"
    assert s.recon_tools["subfinder"] == "subfinder"
    assert get_settings() is not None


def test_json_logger():
    from bugbountybot.storage.logging import get_logger, log_event

    logger = get_logger("test.ops")
    # smoke: emitting doesn't raise, format is JSON
    import logging

    class Capture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []

        def emit(self, record):
            self.records.append(record)

    cap = Capture()
    logger.addHandler(cap)
    log_event(logger, "scan done", program="acme", count=3)
    assert cap.records and cap.records[0].program == "acme"
