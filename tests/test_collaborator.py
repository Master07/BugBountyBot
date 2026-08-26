"""External SSRF collaborator tests."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from bugbountybot.oob.collaborator import CollaboratorClient
from bugbountybot.oob.server import OOBServer


class FakeCollaborator(BaseHTTPRequestHandler):
    """Simulates an interactsh API: callbacks POSTed to /<token> are returned
    via GET /api/v1/interactsh/<token>."""

    callbacks: dict = {}

    def do_POST(self):  # noqa: N802
        token = self.path.strip("/")
        self.callbacks.setdefault(token, []).append({"protocol": "http", "path": self.path})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/api/v1/interactsh/"):
            token = self.path.split("/")[-1]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"data": self.callbacks.get(token, [])}).encode())
        else:
            self.send_response(200)
            self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture()
def collaborator():
    FakeCollaborator.callbacks = {}
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeCollaborator)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base
    httpd.shutdown()


def test_collaborator_callback_url(collaborator):
    client = CollaboratorClient(collaborator, poll_interval=0.1, poll_timeout=5)
    token = "abc123"
    url = client.callback_url(token)
    assert url == f"{collaborator}/{token}"
    client.close()


def test_collaborator_confirms_callback(collaborator):
    client = CollaboratorClient(collaborator, poll_interval=0.1, poll_timeout=5)
    token = "deadbeef"
    assert not client.has_callback(token)
    # simulate the target fetching the callback URL
    httpx.post(client.callback_url(token), timeout=5)
    assert client.has_callback(token)
    cbs = client.callbacks_for(token)
    assert cbs and cbs[0]["path"].strip("/") == token
    client.close()


def test_collaborator_no_callback_times_out(collaborator):
    client = CollaboratorClient(collaborator, poll_interval=0.05, poll_timeout=0.3)
    assert not client.has_callback("never-called")
    client.close()


def test_public_base_url_uses_external():
    srv = OOBServer(port=0, public_base_url="https://collab.example.com")
    assert srv.callback_url("tok123") == "https://collab.example.com/tok123"
    assert srv.callback_url("tok123").startswith("https://")
