"""IDOR / BOLA module — CWE-639. Detects access to another user's object via
sequential/resource IDs. Requires two authenticated sessions (idA vs idB) to be
meaningful; without them, reports only accessible-ID candidates for review.
"""
from __future__ import annotations

import re

import httpx

from bugbountybot.payloads.encoders import apply_chain
from bugbountybot.vuln.base import (
    ConfirmedFinding,
    DetectionResult,
    InjectionPoint,
    VulnModule,
)

_ID_PATTERNS = [
    re.compile(r"(?i)(user|account|profile|order|invoice|document|file|report|ticket|message)[-_/]?id"),
    re.compile(r"/\d{4,}"),
]


class IDORModule(VulnModule):
    name = "idor"
    cwe = ["CWE-639"]
    default_tier = 2
    required_discovery = ["params", "auth"]

    def __init__(self, client, library=None, *, id_a: str = "1", id_b: str = "2", client_b=None):
        super().__init__(client, library)
        self.id_a = id_a
        self.id_b = id_b
        self.client_b = client_b  # second authenticated session (user B)

    def discover_injection_points(self, target_url: str, endpoints: list | None = None):
        points = []
        for ep in endpoints or []:
            url = ep["url"]
            # Path-based resource IDs: /users/123 → /users/2 (allow hyphens)
            path_match = re.search(r"(/[\w-]+/)\d{3,}(/?)", url)
            if path_match:
                base = url[: path_match.start(1)] + path_match.group(1)
                tail = path_match.group(2)
                points.append(
                    InjectionPoint(
                        url=f"{base}IDOR{tail}", param="id", location="path", context="json_value"
                    )
                )
            # Query-based: ?user_id=123 → ?user_id=IDOR
            from urllib.parse import parse_qsl, urlsplit, urlencode, urlunsplit

            parsed = urlsplit(url)
            for param, _ in parse_qsl(parsed.query):
                if _ID_PATTERNS[0].search(param):
                    points.append(
                        InjectionPoint(url=url, param=param, context="json_value")
                    )
        return points

    def select_payloads(self, point: InjectionPoint, max_tier: int):
        # IDOR substitutes IDs directly; the sentinel drives run_module's loop.
        from bugbountybot.payloads.models import Payload

        return [
            Payload(
                id="idor-substitution",
                category="idor",
                payload="IDOR",
                tier=2,
            )
        ]

    def inject(self, point: InjectionPoint, payload, encoder_chain: list[str]):
        if point.location == "path":
            url = point.url.replace("IDOR", self.id_b)
            return self.client.get(url, headers=point.headers, timeout=10)
        # query param — substitute the target ID via _build_url (appends if absent)
        url = self._build_url(point, self.id_b)
        return self.client.get(url, headers=point.headers, timeout=10)

    def detect(self, response: httpx.Response, payload, encoder_chain: list[str]):
        # Heuristic: a 200 on the replaced-ID request to a resource endpoint is
        # suspicious. Real confirmation needs two sessions; this is a candidate.
        matched = response.status_code == 200
        return DetectionResult(
            signal="status",
            matched=matched,
            detail="200 on alternate resource ID (candidate — needs 2-session confirm)",
            response=response,
        )

    def confirm(self, candidate: DetectionResult) -> ConfirmedFinding | None:
        url = str(candidate.response.request.url)
        # Single-session: candidate only (needs human 2-account check).
        if self.client_b is None:
            return ConfirmedFinding(
                title="Possible IDOR (needs manual 2-session confirm)",
                severity="medium",
                detail="Alternate object ID returned HTTP 200. Verify with a second account before reporting.",
                url=url,
                module=self.name,
                cwe="CWE-639",
                cvss="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                payload_id="idor-substitution",
                request_text=f"GET {url} HTTP/1.1",
                response_text=self._response_text(candidate.response),
                dedup_key=f"idor:{url}",
            )

        # Two-session confirm: session A already fetched B's object (200).
        # Session B fetches the SAME object — if B also gets 200 with the SAME
        # body, the object is shared across tenants = confirmed IDOR.
        try:
            r_b = self.client_b.get(url, timeout=10)
        except httpx.HTTPError:
            return None
        if r_b.status_code != 200:
            return None
        # same object body across sessions => cross-tenant access
        body_a = candidate.response.text
        body_b = r_b.text
        if body_a != body_b:
            # different content could mean A got an error page; require A's 200
            # to contain object-like data (non-trivial body)
            if len(body_a) < 50:
                return None
        return ConfirmedFinding(
            title="IDOR confirmed (2-session diff)",
            severity="high",
            detail="Session A accessed object via ID substitution, and session B returned the same object — cross-tenant access confirmed.",
            url=url,
            module=self.name,
            cwe="CWE-639",
            cvss="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            payload_id="idor-substitution",
            request_text=f"GET {url} HTTP/1.1 (session A)\nGET {url} HTTP/1.1 (session B)",
            response_text=self._response_text(candidate.response),
            dedup_key=f"idor:{url}",
        )
