"""OOB listener + SSRF module test.

Exercises the PRODUCTION select_payloads/inject path: the module itself
templates {{OOB}} into a live callback URL, the target fetches it, and the
callback confirms SSRF. No monkeypatching.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

import httpx
import pytest

from bugbountybot.oob.server import OOBServer
from bugbountybot.payloads.loader import PayloadLibrary
from bugbountybot.vuln.base import InjectionPoint, run_module
from bugbountybot.vuln.ssrf import OOB_PLACEHOLDER, SSRFModule


class SSRFHandler(BaseHTTPRequestHandler):
    """Fetches the value of q (simulating a server-side fetch)."""

    def do_GET(self):  # noqa: N802
        params = dict(parse_qsl(urlsplit(self.path).query))
        q = params.get("q", "")
        if self.path.startswith("/fetch") and q.startswith("http"):
            try:
                httpx.get(q, timeout=3)
            except httpx.HTTPError:
                pass
        body = b"<html>fetched</html>"
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def ssrf_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), SSRFHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture()
def oob(artifacts):
    server = OOBServer(port=0, artifact_store=artifacts).start()
    yield server
    server.stop()


@pytest.fixture()
def library():
    return PayloadLibrary.from_directory("payloads")


def test_oob_server_catches_callback(oob):
    token = oob.make_token()
    assert not oob.has_callback(token)
    httpx.get(oob.callback_url(token), timeout=5)
    assert oob.has_callback(token)
    assert oob.callbacks_for(token)


def test_ssrf_templating_replaces_placeholder(oob, library):
    """select_payloads must rewrite {{OOB}} into the live callback URL."""
    with httpx.Client(timeout=10) as client:
        m = SSRFModule(client, library, oob=oob)
        pt = InjectionPoint(url="http://x/fetch", param="q")
        payloads = m.select_payloads(pt, 3)
        templated = [p for p in payloads if OOB_PLACEHOLDER in p.payload]
        assert not templated, "no payload should still contain the placeholder"
        assert any(oob.base_url in p.payload for p in payloads)
        tokens = {p.detection.get("token") for p in payloads if p.detection.get("token")}
        assert len(tokens) == 1 and next(iter(tokens))


def test_ssrf_module_confirms_via_oob_production_path(ssrf_server, oob, library):
    """Full production path: templated payload -> target fetches -> callback."""
    with httpx.Client(timeout=10) as client:
        m = SSRFModule(client, library, oob=oob, callback_wait=0.05)
        endpoints = [
            {"url": f"{ssrf_server}/fetch", "method": "GET", "params": "q"}
        ]
        findings = run_module(m, f"{ssrf_server}/fetch", max_tier=3, endpoints=endpoints)
        assert findings, "expected SSRF confirmed via OOB callback through production path"


def test_ssrf_without_oob_does_not_confirm(ssrf_server, library):
    """Without a listener, the module must not produce confirmations."""
    with httpx.Client(timeout=10) as client:
        m = SSRFModule(client, library, oob=None, callback_wait=0.05)
        endpoints = [
            {"url": f"{ssrf_server}/fetch", "method": "GET", "params": "q"}
        ]
        findings = run_module(m, f"{ssrf_server}/fetch", max_tier=3, endpoints=endpoints)
        assert findings == []
