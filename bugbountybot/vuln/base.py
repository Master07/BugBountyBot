"""VulnModule interface + shared engine helpers.

Every module in bugbountybot/vuln/ implements this interface. The engine
orchestrates: discovery of injection points -> payload selection -> injection
-> detection -> confirmation. Confirmation is the false-positive gate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from bugbountybot.payloads.models import Payload


@dataclass
class InjectionPoint:
    url: str
    method: str = "GET"
    param: str = ""
    location: str = "query"  # query | body | header | cookie | path | json
    context: str = "html_body"
    headers: dict = field(default_factory=dict)
    body: dict | None = None


@dataclass
class DetectionResult:
    signal: str  # reflection | error | diff | timing | oob | status | header
    matched: bool
    detail: str = ""
    response: httpx.Response | None = None
    payload: Payload | None = None
    encoder_chain: list[str] = field(default_factory=list)


@dataclass
class ConfirmedFinding:
    title: str
    severity: str
    detail: str
    url: str
    module: str
    cwe: str
    cvss: str
    payload_id: str
    request_text: str
    response_text: str
    dedup_key: str
    evidence: list[str] = field(default_factory=list)  # artifact-relative paths


class VulnModule:
    name: str = "base"
    cwe: list[str] = []
    default_tier: int = 2
    required_discovery: list[str] = ["params"]

    def __init__(self, client: httpx.Client, library=None):
        self.client = client
        self.library = library

    # --- overridable ---
    def discover_injection_points(self, target_url: str, endpoints: list | None = None) -> list[InjectionPoint]:
        raise NotImplementedError

    def select_payloads(self, point: InjectionPoint, max_tier: int) -> list[Payload]:
        raise NotImplementedError

    def inject(self, point: InjectionPoint, payload: Payload, encoder_chain: list[str]) -> httpx.Response:
        raise NotImplementedError

    def detect(self, response: httpx.Response, payload: Payload, encoder_chain: list[str]) -> DetectionResult:
        raise NotImplementedError

    def confirm(self, candidate: DetectionResult) -> ConfirmedFinding | None:
        """Reduce false positives. Default: treat detection as confirmed."""
        return None

    # --- shared helpers ---
    def _build_url(self, point: InjectionPoint, value: str) -> str:
        if point.location != "query" or not point.param:
            return point.url
        import urllib.parse

        parsed = urllib.parse.urlsplit(point.url)
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        replaced = [(k, value if k == point.param else v) for k, v in params]
        if not any(k == point.param for k, _ in replaced):
            replaced.append((point.param, value))
        query = urllib.parse.urlencode(replaced)
        return urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment)
        )

    def _inject(
        self, client: httpx.Client, point: InjectionPoint, value: str, *, timeout: int = 10
    ) -> httpx.Response:
        """Send the injected value in the point's location (query or json body)."""
        import json as _json

        if point.location == "json" and point.param:
            body = dict(point.body or {})
            body[point.param] = value
            return client.post(
                point.url,
                json=body,
                headers={**point.headers, "Content-Type": "application/json"},
                timeout=timeout,
            )
        if point.location in ("body",) and point.param:
            data = dict(point.body or {})
            data[point.param] = value
            return client.post(
                point.url,
                data=data,
                headers=point.headers,
                timeout=timeout,
            )
        url = self._build_url(point, value)
        return client.get(url, headers=point.headers, timeout=timeout)

    def _request_text(self, point: InjectionPoint, value: str, response: httpx.Response) -> str:
        lines = [f"{point.method} {point.url} HTTP/1.1"]
        for k, v in point.headers.items():
            lines.append(f"{k}: {v}")
        if point.body:
            lines.append("")
            lines.append(str(point.body))
        return "\n".join(lines)

    def _response_text(self, response: httpx.Response) -> str:
        try:
            body = response.text
        except Exception:
            body = f"<{len(response.content)} bytes binary>"
        return f"HTTP {response.status_code} {response.reason_phrase}\n\n{body[:4000]}"


def run_module(
    module: VulnModule,
    target_url: str,
    *,
    max_tier: int = 2,
    endpoints: list | None = None,
    encoder_chain: list[str] | None = None,
) -> list[ConfirmedFinding]:
    """Drive one module end to end over all its injection points."""
    encoder_chain = encoder_chain or []
    findings: list[ConfirmedFinding] = []
    for point in module.discover_injection_points(target_url, endpoints):
        for payload in module.select_payloads(point, max_tier):
            try:
                response = module.inject(point, payload, encoder_chain)
            except (httpx.HTTPError, httpx.InvalidURL):
                # A malformed probe must not kill the whole run.
                continue
            result = module.detect(response, payload, encoder_chain)
            if not result.matched:
                continue
            confirmed = module.confirm(result)
            if confirmed:
                findings.append(confirmed)
    return findings
