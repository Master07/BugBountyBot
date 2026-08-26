"""Vuln module tests against a real local HTTP server (in-scope target)."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from bugbountybot.payloads.loader import PayloadLibrary
from bugbountybot.vuln.base import run_module
from bugbountybot.vuln.cors import CORSModule
from bugbountybot.vuln.redirect import RedirectModule
from bugbountybot.vuln.sqli import SQLiModule
from bugbountybot.vuln.xss import XSSModule


class VulnHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qsl, urlsplit

        params = dict(parse_qsl(urlsplit(self.path).query))
        q = params.get("q", "")

        if self.path.startswith("/xss"):
            body = f"<html><body>results for {q}</body></html>".encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/sqli"):
            # Simulate a boolean-differentiable SQLi: 1=1 returns content,
            # 1=2 returns the error page. Quote probes error out (fingerprint).
            if "1=1" in q:
                body = b"<html>user: admin (1=1 true)</html>"
            elif "1=2" in q:
                body = b"<html>SQL syntax error near ... MySQL</html>"
            elif "'" in q or '"' in q:
                body = b"<html>SQL syntax error near ... MySQL</html>"
            else:
                body = b"<html>ok</html>"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/redirect"):
            target = params.get("url") or params.get("q", "")
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
        elif self.path.startswith("/cors"):
            self.send_response(200)
            origin = self.headers.get("Origin", "")
            if "evil.com" in origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path.startswith("/notfound"):
            self.send_response(404)
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), VulnHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture()
def library():
    return PayloadLibrary.from_directory("payloads")


def _endpoints(base, path, param):
    return [{"url": f"{base}{path}", "method": "GET", "params": param}]


def test_xss_detects_reflection(server, library):
    with httpx.Client(timeout=10) as client:
        m = XSSModule(client, library)
        points = m.discover_injection_points(
            f"{server}/xss", _endpoints(server, "/xss", "q")
        )
        assert points
        from bugbountybot.vuln.base import run_module

        findings = run_module(m, f"{server}/xss", max_tier=2, endpoints=_endpoints(server, "/xss", "q"))
        # The server reflects q unencoded; at least one payload should confirm.
        assert findings, "expected at least one confirmed XSS"


def test_xss_no_false_positive_on_clean(server, library):
    with httpx.Client(timeout=10) as client:
        m = XSSModule(client, library)
        # /notfound does not reflect; should yield no findings
        findings = run_module(m, f"{server}/notfound", max_tier=2, endpoints=_endpoints(server, "/notfound", "q"))
        assert findings == []


def test_sqli_error_detection(server, library):
    with httpx.Client(timeout=10) as client:
        m = SQLiModule(client, library)
        findings = run_module(m, f"{server}/sqli", max_tier=2, endpoints=_endpoints(server, "/sqli", "q"))
        assert findings, "expected SQLi candidate"


def test_redirect_detects_location(server, library):
    with httpx.Client(timeout=10) as client:
        m = RedirectModule(client, library)
        # realistic redirect param name
        findings = run_module(m, f"{server}/redirect", max_tier=2, endpoints=_endpoints(server, "/redirect", "url"))
        assert findings, "expected open redirect finding"


def test_cors_reflects_evil_origin(server, library):
    with httpx.Client(timeout=10) as client:
        m = CORSModule(client, library)
        findings = run_module(m, f"{server}/cors", max_tier=2)
        assert findings, "expected CORS finding"


def test_idor_injects_and_flags(server, library):
    """IDOR must actually inject (sentinel payload) and flag a 200 on the
    substituted resource ID."""
    from bugbountybot.vuln.idor import IDORModule

    with httpx.Client(timeout=10) as client:
        m = IDORModule(client, library)
        # /users/12345 → substitute ID → server returns 200
        endpoints = [{"url": f"{server}/users/12345", "method": "GET", "params": ""}]
        findings = run_module(m, f"{server}/users/12345", max_tier=2, endpoints=endpoints)
        assert findings, "expected IDOR candidate"


# ---- P3 negative tests: confirmation must NOT fire on false-positive pages ----
class FpHandler(BaseHTTPRequestHandler):
    """/sqli-dynamic: per-request nonce makes 1=1 and 1=2 differ -> must NOT confirm.
    /redirect-benign: 200 body containing 'location' -> must NOT flag."""

    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qsl, urlsplit
        import uuid

        params = dict(parse_qsl(urlsplit(self.path).query))
        q = params.get("q", "")
        if self.path.startswith("/sqli-dynamic"):
            # dynamic page: each response has a unique nonce
            body = f"<html>nonce={uuid.uuid4()} q={q}</html>".encode()
        elif self.path.startswith("/redirect-benign"):
            body = b"<html>location: somewhere not a redirect, no Location header</html>"
        else:
            body = b"ok"
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def fp_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FpHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_sqli_does_not_confirm_on_dynamic_page(fp_server, library):
    """A page whose responses differ per-request must not produce a SQLi confirm."""
    from bugbountybot.vuln.sqli import SQLiModule

    with httpx.Client(timeout=10) as client:
        m = SQLiModule(client, library)
        findings = run_module(
            m, f"{fp_server}/sqli-dynamic", max_tier=2,
            endpoints=_endpoints(fp_server, "/sqli-dynamic", "q"),
        )
        assert findings == [], "dynamic page must not confirm SQLi"


def test_redirect_does_not_flag_benign_location(fp_server, library):
    """A 200 body mentioning 'location' without a 3xx must not flag."""
    from bugbountybot.vuln.redirect import RedirectModule

    with httpx.Client(timeout=10) as client:
        m = RedirectModule(client, library)
        findings = run_module(
            m, f"{fp_server}/redirect-benign", max_tier=2,
            endpoints=_endpoints(fp_server, "/redirect-benign", "url"),
        )
        assert findings == [], "benign 'location' body must not flag as redirect"


# ---- P2: JSON-body injection ----
class JsonHandler(BaseHTTPRequestHandler):
    """Reflects the 'q' JSON field into the response body."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        import json as _json

        try:
            q = _json.loads(raw).get("q", "")
        except Exception:
            q = ""
        body = f"<html>json result: {q}</html>".encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def json_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), JsonHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_xss_json_body_injection(json_server, library):
    """XSS via a JSON body param must be detected and confirmed."""
    from bugbountybot.vuln.base import InjectionPoint, run_module
    from bugbountybot.vuln.xss import XSSModule

    with httpx.Client(timeout=10) as client:
        m = XSSModule(client, library)
        # endpoint with a json-located param
        point = InjectionPoint(
            url=f"{json_server}/api/search", param="q", location="json", context="html_body"
        )
        findings = run_module(m, f"{json_server}/api/search", max_tier=2, endpoints=[{"url": f"{json_server}/api/search", "method": "POST", "params": "q"}])
        # run_module uses discover_injection_points -> query fallback; drive inject directly instead
        findings = []
        for p in m.select_payloads(point, 2):
            resp = m.inject(point, p, [])
            d = m.detect(resp, p, [])
            if d.matched:
                cf = m.confirm(d)
                if cf:
                    findings.append(cf)
        assert findings, "expected JSON-body XSS confirmed"
