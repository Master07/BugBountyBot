"""Session profile + nuclei tests."""
from __future__ import annotations

import pytest

from bugbountybot.runner.nuclei import _parse_jsonl, _SEV_MAP
from bugbountybot.runner.session import (
    add_session,
    list_sessions,
    parse_cookie_string,
    parse_header_lines,
    profile_cookies,
    profile_headers,
)
from bugbountybot.tracker.service import add_scope


# ---- session parsing ----
def test_parse_cookie_string():
    assert parse_cookie_string("session=abc123; user=42") == {"session": "abc123", "user": "42"}
    assert parse_cookie_string("") == {}


def test_parse_header_lines():
    assert parse_header_lines("Authorization: Bearer xyz\nX-API-Key: k") == {
        "Authorization": "Bearer xyz",
        "X-API-Key": "k",
    }


# ---- session CRUD ----
def test_add_and_list_session(session, program):
    sp = add_session(session, program.id, name="logged-in", cookies="sid=abc; uid=1", headers="Authorization: Bearer t")
    assert sp.id
    assert profile_cookies(sp) == {"sid": "abc", "uid": "1"}
    assert profile_headers(sp) == {"Authorization": "Bearer t"}
    assert len(list_sessions(session, program.id)) == 1


# ---- runner uses session cookies ----
def test_runner_sends_session_cookies(session, program, artifacts, monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from bugbountybot.tracker.service import add_program, add_scope, add_endpoint

    captured = {"cookie": "", "count": 0}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            captured["cookie"] = self.headers.get("Cookie", "")
            captured["count"] += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>results for x</html>")

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    from bugbountybot.payloads.loader import PayloadLibrary
    from bugbountybot.runner.service import ScopedRunner

    add_scope(session, program.id, "127.0.0.1", kind="ip")
    add_endpoint(session, program.id, f"{base}/xss", params="q")
    sp = add_session(session, program.id, cookies="session=SECRETCOOKIE")
    runner = ScopedRunner(
        session,
        program_id=program.id,
        library=PayloadLibrary.from_directory("payloads"),
        artifacts=artifacts,
        session_profile=sp,
    )
    runner.run_module("xss", f"{base}/xss", max_tier=2)
    assert captured["count"] > 0, "module should have made requests"
    assert captured["cookie"] == "session=SECRETCOOKIE", "runner must send the session cookie"

    httpd.shutdown()


# ---- nuclei parsing ----
def test_nuclei_parse_jsonl():
    stdout = (
        '{"template-id":"cve-2020-1234","info":{"name":"Some CVE","severity":"high"},"matched-at":"https://x.com/","matcher-name":"status-1"}\n'
        '{"template-id":"misconfig-1","info":{"name":"Bad Config","severity":"medium"},"matched-at":"https://x.com/a","matcher-name":"header-1"}\n'
        "not-json\n"
    )
    findings = _parse_jsonl(stdout)
    assert len(findings) == 2
    assert findings[0]["template"] == "cve-2020-1234"
    assert findings[0]["severity"] == "high"
    assert findings[1]["matcher"] == "header-1"


def test_nuclei_severity_map():
    assert _SEV_MAP["critical"] == "critical"
    assert _SEV_MAP["unknown"] == "info"


# ---- nuclei scope gating ----
def test_nuclei_blocks_out_of_scope(session, program):
    from bugbountybot.runner.nuclei import run_nuclei

    result = run_nuclei(session, program.id, "https://evil.com/")
    assert result.blocked == 1
    assert result.findings == []
