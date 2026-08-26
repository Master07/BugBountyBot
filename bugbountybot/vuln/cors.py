"""CORS Misconfiguration module — CWE-942. Sends attacker-controlled Origins and
checks for permissive Access-Control-Allow-Origin reflection + credentials.
"""
from __future__ import annotations

import httpx

from bugbountybot.vuln.base import (
    ConfirmedFinding,
    DetectionResult,
    InjectionPoint,
    VulnModule,
)

# Origins that should never be trusted if reflected.
_EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.evil.com",
    "null",
]


class CORSModule(VulnModule):
    name = "cors"
    cwe = ["CWE-942"]
    default_tier = 2
    required_discovery = ["headers"]

    def discover_injection_points(self, target_url: str, endpoints: list | None = None):
        return [InjectionPoint(url=target_url, location="header", context="header")]

    def select_payloads(self, point: InjectionPoint, max_tier: int):
        # CORS probes send Origin headers directly; the sentinel payload just
        # drives the run_module loop to call inject() once.
        from bugbountybot.payloads.models import Payload

        return [
            Payload(
                id="cors-origin-probe",
                category="cors",
                payload=_EVIL_ORIGINS[0],
                tier=2,
            )
        ]

    def inject(self, point: InjectionPoint, payload, encoder_chain: list[str]):
        # CORS probes send Origin headers directly; ignore payload set.
        return self.client.get(
            point.url,
            headers={**point.headers, "Origin": _EVIL_ORIGINS[0]},
            timeout=10,
        )

    def detect(self, response: httpx.Response, payload, encoder_chain: list[str]):
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")
        # Reflection of evil origin, or wildcard + credentials (browsers block it,
        # but a wildcard with credentials is still a misconfig worth flagging).
        if "evil.com" in acao or acao == "null":
            matched = True
            detail = f"ACAO reflects attacker origin: {acao}"
        elif acao == "*" and acac.lower() == "true":
            matched = True
            detail = "ACAO wildcard with Allow-Credentials: true"
        else:
            matched = False
            detail = f"ACAO={acao} (not exploitable)"
        return DetectionResult(
            signal="header",
            matched=matched,
            detail=detail,
            response=response,
        )

    def confirm(self, candidate: DetectionResult) -> ConfirmedFinding | None:
        return ConfirmedFinding(
            title="CORS Misconfiguration",
            severity="medium",
            detail=candidate.detail,
            url=str(candidate.response.request.url),
            module=self.name,
            cwe="CWE-942",
            cvss="AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
            payload_id="cors-origin-probe",
            request_text=f"GET {candidate.response.request.url} HTTP/1.1\nOrigin: {_EVIL_ORIGINS[0]}",
            response_text=self._response_text(candidate.response),
            # normalize trailing slash so /x and /x/ dedupe together
            dedup_key=f"cors:{str(candidate.response.request.url).rstrip('/')}",
        )
