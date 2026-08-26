"""JWT auth-flaw module tests."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from bugbountybot.vuln.jwt_auth import (
    JWTModule,
    _decode_jwt,
    _sign,
    _sign_none,
    _verify_hmac,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_token(secret: str = "secret", alg: str = "HS256", payload: dict | None = None) -> str:
    header = {"alg": alg, "typ": "JWT"}
    body = payload or {"sub": "user1", "role": "admin"}
    if alg == "none":
        return _sign_none(header, body)
    return _sign(header, body, secret, alg)


class JwtHandler(BaseHTTPRequestHandler):
    """/me accepts ANY token with a valid signature check; specifically:
    - alg:none tokens are ACCEPTED (vuln)
    - HS256 tokens signed with 'secret' are accepted
    - everything else -> 401"""

    def do_GET(self):  # noqa: N802
        auth = self.headers.get("Authorization", "")
        if not auth.lower().startswith("bearer "):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"unauthorized")
            return
        token = auth.split(" ", 1)[1].strip()
        decoded = None
        try:
            h, p, s = token.split(".")
            header = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
            if header.get("alg") == "none":
                decoded = True  # vuln: accepts alg:none
            elif header.get("alg") == "HS256" and _verify_hmac(token, "secret"):
                decoded = True
        except Exception:
            decoded = False
        if decoded:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"user":"user1"}')
        else:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"unauthorized")

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def jwt_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), JwtHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


# ---- unit: helpers ----
def test_decode_jwt():
    tok = _make_token("secret")
    h, p, sig = _decode_jwt(tok)
    assert h["alg"] == "HS256"
    assert p["sub"] == "user1"


def test_sign_none():
    tok = _make_token(alg="none")
    h, p, sig = _decode_jwt(tok)
    assert h["alg"] == "none"
    assert sig == "" or sig is None


def test_verify_hmac_correct_and_wrong():
    tok = _make_token("secret")
    assert _verify_hmac(tok, "secret")
    assert not _verify_hmac(tok, "wrong")


# ---- integration: module detects the vuln ----
def test_jwt_module_alg_none_confirmed(jwt_server):
    """A server that accepts alg:none -> the module confirms it."""
    from bugbountybot.payloads.loader import PayloadLibrary
    from bugbountybot.runner.session import add_session
    from bugbountybot.vuln.base import run_module

    lib = PayloadLibrary.from_directory("payloads")
    with httpx.Client(timeout=10) as client:
        m = JWTModule(client, lib)
        # supply a session with a valid token so the module can forge from it
        m.session_profile = _FakeProfile(token=_make_token("secret"))
        findings = run_module(m, f"{jwt_server}/me", max_tier=2, endpoints=[])
        assert findings, "expected alg:none JWT finding"
        assert "alg:none" in findings[0].detail.lower() or "weak" in findings[0].detail.lower()


def test_jwt_module_no_token_no_finding(jwt_server):
    """Without a token, the module must not produce findings."""
    from bugbountybot.payloads.loader import PayloadLibrary
    from bugbountybot.vuln.base import run_module

    lib = PayloadLibrary.from_directory("payloads")
    with httpx.Client(timeout=10) as client:
        m = JWTModule(client, lib, session_profile=None)
        findings = run_module(m, f"{jwt_server}/me", max_tier=2, endpoints=[])
        assert findings == []


class _FakeProfile:
    """Minimal stand-in for a SessionProfile with an Authorization header."""

    def __init__(self, token: str):
        self.cookies_json = "{}"
        self.headers_json = json.dumps({"Authorization": f"Bearer {token}"})
