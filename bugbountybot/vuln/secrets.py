"""Secrets / exposure module — probes common exposed files + secret patterns.

Safe tier-2 GET probes: checks for .git/.env/backups with known content markers,
and scans JS/bundle responses for high-signal secret regexes. Paths and patterns
are data files under payloads/secrets/.
"""
from __future__ import annotations

import re

import httpx

from bugbountybot.payloads.models import Payload
from bugbountybot.vuln.base import (
    ConfirmedFinding,
    DetectionResult,
    InjectionPoint,
    VulnModule,
)

# path marker -> content that must be present to confirm exposure
_PATH_MARKERS = {
    "/.git/config": "[core]",
    "/.git/HEAD": "ref: refs/heads",
    "/.env": "=",  # validated by _ENV_LINE_RE, not a bare substring (see detect)
    "/.aws/credentials": "aws_access_key_id",
    "/wp-config.php.bak": "DB_PASSWORD",
    "/config.php.bak": "DB_PASSWORD",
    "/server-status": "Apache Server Status",
    "/.htaccess": "RewriteEngine",
}

# A hit whose body is an HTML document is the app's SPA catch-all (200 index.html
# for any unmatched path), NOT a real exposed file. Real .env/.git/config/creds
# files are plain text and never HTML documents. (server-status is legitimately
# HTML, so it is exempted below.)
_HTML_DOC_RE = re.compile(r"<!doctype\s+html|<html[\s>]", re.I)
# A real .env has KEY=VALUE lines; the bare "=" marker matched any HTML attribute.
_ENV_LINE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S", re.M)


def _is_html_document(body: str) -> bool:
    return bool(_HTML_DOC_RE.search(body[:1000]))


def _marker_confirms(path: str, marker: str, body: str) -> bool:
    """True only if `body` is a genuine exposure of `path` (not the SPA shell)."""
    # server-status is HTML by design; its marker is specific enough on its own.
    if path != "/server-status" and _is_html_document(body):
        return False
    if path == "/.env":
        return bool(_ENV_LINE_RE.search(body))
    return marker in body

# secret patterns loaded from the data file at init
_SECRET_PATTERNS: list[re.Pattern] = []


def _load_patterns() -> list[re.Pattern]:
    global _SECRET_PATTERNS
    if _SECRET_PATTERNS:
        return _SECRET_PATTERNS
    from pathlib import Path

    p = Path(__file__).resolve().parent.parent.parent / "payloads" / "secrets" / "patterns.txt"
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    _SECRET_PATTERNS.append(re.compile(line))
                except re.error:
                    pass
    return _SECRET_PATTERNS


class SecretsModule(VulnModule):
    name = "secrets"
    cwe = ["CWE-200"]
    default_tier = 2
    required_discovery = ["params"]

    def discover_injection_points(self, target_url: str, endpoints: list | None = None):
        # For the target host, probe the known exposure paths.
        from urllib.parse import urlsplit

        parsed = urlsplit(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return [
            InjectionPoint(url=f"{base}{path}", param="", location="path", context="html_body")
            for path in _PATH_MARKERS
        ]

    def select_payloads(self, point: InjectionPoint, max_tier: int):
        # Paths are the injection points themselves; one sentinel payload drives the loop.
        return [Payload(id=f"secrets-{point.url}", category="secrets", payload=point.url, tier=2)]

    def inject(self, point: InjectionPoint, payload, encoder_chain: list[str]):
        return self.client.get(point.url, headers=point.headers, timeout=10)

    def detect(self, response: httpx.Response, payload, encoder_chain: list[str]):
        # path-marker check first
        for path, marker in _PATH_MARKERS.items():
            if path in payload.payload and _marker_confirms(path, marker, response.text):
                return DetectionResult(
                    signal="header",
                    matched=True,
                    detail=f"Exposed file {path} (marker '{marker}' present)",
                    response=response,
                    payload=payload,
                )
        # secret-pattern check on any response body
        body = response.text
        for pat in _load_patterns():
            m = pat.search(body)
            if m:
                return DetectionResult(
                    signal="error",
                    matched=True,
                    detail=f"Secret pattern {pat.pattern[:30]} found in response",
                    response=response,
                    payload=payload,
                )
        return DetectionResult(signal="header", matched=False, detail="no exposure")

    def confirm(self, candidate: DetectionResult) -> ConfirmedFinding | None:
        return ConfirmedFinding(
            title=candidate.detail,
            severity="high",
            detail=candidate.detail,
            url=str(candidate.response.request.url),
            module=self.name,
            cwe="CWE-200",
            cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            payload_id=candidate.payload.id if candidate.payload else "",
            request_text=f"GET {candidate.response.request.url} HTTP/1.1",
            response_text=self._response_text(candidate.response),
            dedup_key=f"secrets:{candidate.response.request.url}",
        )
