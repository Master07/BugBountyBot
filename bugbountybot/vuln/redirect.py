"""Open Redirect module — CWE-601. Sends redirect-triggering payloads in a
redirect param and confirms a Location header to an attacker-controlled host.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

import httpx

from bugbountybot.payloads.encoders import apply_chain
from bugbountybot.payloads.selectors import select_for_context
from bugbountybot.vuln.base import (
    ConfirmedFinding,
    DetectionResult,
    InjectionPoint,
    VulnModule,
)

_REDIRECT_PARAMS = re.compile(
    r"(?i)(redirect|return|returnurl|return_url|next|url|dest|destination|continue|target|out|view|image_url)"
)


class RedirectModule(VulnModule):
    name = "redirect"
    cwe = ["CWE-601"]
    default_tier = 2
    required_discovery = ["params"]

    def discover_injection_points(self, target_url: str, endpoints: list | None = None):
        points = []
        for ep in endpoints or []:
            # Params may come from the inventory (ep["params"]) even when not
            # yet present in the URL query string.
            params = (ep.get("params") or "").split(",")
            params += [p for p, _ in parse_qsl(urlsplit(ep["url"]).query)]
            for param in params:
                if param and _REDIRECT_PARAMS.search(param):
                    points.append(
                        InjectionPoint(url=ep["url"], param=param, context="url_param")
                    )
        return points

    def select_payloads(self, point: InjectionPoint, max_tier: int):
        return select_for_context(self.library, "redirect", point.context, max_tier=max_tier, limit=8)

    def inject(self, point: InjectionPoint, payload, encoder_chain: list[str]):
        value = apply_chain(payload.payload, encoder_chain)
        url = self._build_url(point, value)
        # No redirect following — we only inspect the Location header.
        return self.client.get(
            url, headers=point.headers, timeout=10, follow_redirects=False
        )

    def detect(self, response: httpx.Response, payload, encoder_chain: list[str]):
        # Only a real 3xx with the probe in Location is a redirect candidate.
        location = response.headers.get("Location", "")
        probe = payload.payload
        if 300 <= response.status_code < 400 and probe in location:
            return DetectionResult(
                signal="header",
                matched=True,
                detail=f"Location contains probe: {location[:100]}",
                response=response,
                payload=payload,
                encoder_chain=encoder_chain,
            )
        return DetectionResult(signal="header", matched=False, detail="no redirect")

    def confirm(self, candidate: DetectionResult) -> ConfirmedFinding | None:
        return ConfirmedFinding(
            title="Open Redirect",
            severity="low",
            detail="Server reflected attacker-controlled host in redirect Location header.",
            url=str(candidate.response.request.url),
            module=self.name,
            cwe="CWE-601",
            cvss="AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
            payload_id=candidate.payload.id if candidate.payload else "",
            request_text=f"GET {candidate.response.request.url} HTTP/1.1",
            response_text=self._response_text(candidate.response),
            dedup_key=f"redirect:{candidate.response.request.url}",
        )
