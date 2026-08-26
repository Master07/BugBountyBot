"""SSRF module — CWE-918. Injects URLs pointing at an OOB callback listener.

Real payload templating: each payload containing the {{OOB}} placeholder is
rewritten at inject time with a unique callback URL (listener base + token),
so a callback to that token proves the server fetched OUR listener.

Requires an OOBServer (or any object with callback_url() and has_callback()).
For real external targets the listener must be externally reachable
(config-provided public base URL) — a pure-localhost listener can only confirm
SSRF against localhost targets. Non-localhost binds require explicit approval
per AGENTS.md.
"""
from __future__ import annotations

import re
import urllib.parse

import httpx

from bugbountybot.payloads.encoders import apply_chain
from bugbountybot.payloads.models import Payload
from bugbountybot.vuln.base import (
    ConfirmedFinding,
    DetectionResult,
    InjectionPoint,
    VulnModule,
)

OOB_PLACEHOLDER = "{{OOB}}"


class SSRFModule(VulnModule):
    name = "ssrf"
    cwe = ["CWE-918"]
    default_tier = 3  # needs --confirm
    required_discovery = ["params"]

    def __init__(self, client, library=None, *, oob=None, callback_wait: float = 1.0):
        super().__init__(client, library)
        self.oob = oob
        self.callback_wait = callback_wait

    def discover_injection_points(self, target_url: str, endpoints: list | None = None):
        points = []
        for ep in endpoints or []:
            for p in (ep.get("params") or "").split(","):
                if p:
                    points.append(InjectionPoint(url=ep["url"], param=p, context="url_param"))
        if not points:
            for p, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(target_url).query):
                points.append(InjectionPoint(url=target_url, param=p, context="url_param"))
        return points

    def select_payloads(self, point: InjectionPoint, max_tier: int):
        """Return payloads with {{OOB}} replaced by a live per-run callback URL.

        If no OOB listener is configured, return the static payloads as-is so
        the module can still probe internal/cloud-metadata URLs (detection is
        then callback-less and will not confirm).
        """
        base = self.library.by_category("ssrf") if self.library else []
        base = [p for p in base if p.enabled and p.tier <= max_tier][:5]

        if self.oob is None:
            return base

        token = self.oob.make_token()
        callback = self.oob.callback_url(token)
        templated: list[Payload] = []
        for p in base:
            if OOB_PLACEHOLDER in p.payload:
                templated.append(
                    Payload(
                        id=p.id,
                        category=p.category,
                        payload=p.payload.replace(OOB_PLACEHOLDER, callback),
                        tier=p.tier,
                        tags=p.tags,
                        detection={"type": "oob", "token": token},
                        source=p.source,
                    )
                )
            else:
                templated.append(p)
        return templated

    def inject(self, point: InjectionPoint, payload, encoder_chain: list[str]):
        value = apply_chain(payload.payload, encoder_chain)
        url = self._build_url(point, value)
        return self.client.get(url, headers=point.headers, timeout=10)

    def _token_for(self, payload) -> str:
        """Extract the OOB token from the payload's callback URL."""
        raw = urllib.parse.unquote(payload.payload)
        # token is the last path segment of the callback URL
        m = re.search(r"/([0-9a-f]{32})(?:[/?#]|$)", raw)
        if m:
            return m.group(1)
        # fall back to the detection field set at templating time
        det = payload.detection or {}
        return det.get("token", "")

    def detect(self, response: httpx.Response, payload, encoder_chain: list[str]):
        if self.oob is None:
            return DetectionResult(signal="oob", matched=False, detail="no OOB listener configured")
        token = self._token_for(payload)
        if not token:
            return DetectionResult(signal="oob", matched=False, detail="payload has no OOB token")
        import time

        time.sleep(self.callback_wait)
        matched = self.oob.has_callback(token)
        return DetectionResult(
            signal="oob",
            matched=matched,
            detail=f"OOB callback {'received' if matched else 'not received'} for {token[:8]}",
            response=response,
            payload=payload,
            encoder_chain=encoder_chain,
        )

    def confirm(self, candidate: DetectionResult) -> ConfirmedFinding | None:
        payload = candidate.payload
        if self.oob is None:
            return None
        token = self._token_for(payload)
        callbacks = self.oob.callbacks_for(token)
        if not callbacks:
            return None
        return ConfirmedFinding(
            title="SSRF (OOB callback)",
            severity="high",
            detail=f"Server fetched our listener URL ({token[:8]}...) — {len(callbacks)} callback(s).",
            url=str(candidate.response.request.url),
            module=self.name,
            cwe="CWE-918",
            cvss="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            payload_id=payload.id,
            request_text=f"GET {candidate.response.request.url} HTTP/1.1",
            response_text=self._response_text(candidate.response),
            dedup_key=f"ssrf:{candidate.response.request.url}",
        )
