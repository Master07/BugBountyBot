"""Reflected XSS module — CWE-79. Probes query params for reflection."""
from __future__ import annotations

import re

import httpx

from bugbountybot.payloads.encoders import apply_chain
from bugbountybot.payloads.selectors import select_for_context
from bugbountybot.vuln.base import (
    ConfirmedFinding,
    DetectionResult,
    InjectionPoint,
    VulnModule,
)


class XSSModule(VulnModule):
    name = "xss"
    cwe = ["CWE-79"]
    default_tier = 2
    required_discovery = ["params"]

    def discover_injection_points(self, target_url: str, endpoints: list | None = None):
        points = []
        for ep in endpoints or []:
            params = (ep.get("params") or "").split(",")
            for p in params:
                if p:
                    points.append(
                        InjectionPoint(url=ep["url"], param=p, context="html_body")
                    )
        if not points:
            # Fall back: inject into every existing query param.
            from urllib.parse import parse_qsl, urlsplit

            params = [k for k, _ in parse_qsl(urlsplit(target_url).query)]
            if params:
                for p in params:
                    points.append(
                        InjectionPoint(url=target_url, param=p, context="html_body")
                    )
        return points

    def select_payloads(self, point: InjectionPoint, max_tier: int):
        return select_for_context(self.library, "xss", point.context, max_tier=max_tier, limit=10)

    def inject(self, point: InjectionPoint, payload, encoder_chain: list[str]):
        value = apply_chain(payload.payload, encoder_chain)
        return self._inject(self.client, point, value)

    def detect(self, response: httpx.Response, payload, encoder_chain: list[str]):
        probe = payload.payload[:64]
        reflected = probe and probe in response.text
        matched = reflected
        return DetectionResult(
            signal="reflection",
            matched=matched,
            detail="probe reflected in response" if matched else "no reflection",
            response=response,
            payload=payload,
            encoder_chain=encoder_chain,
        )

    def confirm(self, candidate: DetectionResult) -> ConfirmedFinding | None:
        payload = candidate.payload
        # Re-inject the full script tag into the SAME param that flagged, not a
        # synthetic __xss__ param.
        probe = '<script>alert(1)</script>'
        req = candidate.response.request
        req_url = str(req.url)
        from urllib.parse import parse_qsl, urlsplit
        import json as _json

        parsed = urlsplit(req_url)

        # Recover the injected param: query params for GET, JSON body keys for POST.
        is_json = "json" in str(req.headers.get("content-type", ""))
        param = ""
        if is_json:
            try:
                body = _json.loads(req.content.decode("utf-8", "replace"))
                for k, v in (body or {}).items():
                    if isinstance(v, str) and payload.payload in v:
                        param = k
                        break
            except Exception:
                pass
        else:
            params = parse_qsl(parsed.query)
            if params:
                param = params[0][0]

        if not param:
            return None
        from bugbountybot.vuln.base import InjectionPoint

        point = InjectionPoint(
            url=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            param=param,
            location="json" if is_json else "query",
        )
        value = apply_chain(probe, candidate.encoder_chain)
        resp = self._inject(self.client, point, value)
        if "<script>alert(1)</script>" not in resp.text:
            return None

        # Minimal context check: a reflection inside <textarea>, an HTML
        # comment, or a quoted attribute value is NOT executable — downgrade.
        context = _reflection_context(resp.text, probe)
        if context not in ("html_body", "attribute_unquoted", "js_executable"):
            return None  # non-executable context → no confirm (avoid false positive)

        confirm_url = str(resp.request.url)
        req_text = f"{point.method} {confirm_url} HTTP/1.1"
        return ConfirmedFinding(
            title="Reflected XSS",
            severity="medium",
            detail=f"Payload {payload.id!r} reflected in executable context ({context}).",
            url=confirm_url,
            module=self.name,
            cwe="CWE-79",
            cvss="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            payload_id=payload.id,
            request_text=req_text,
            response_text=self._response_text(resp),
            dedup_key=f"xss:{confirm_url}",
        )


def _reflection_context(body: str, probe: str) -> str:
    """Heuristic: is the probe reflected in an executable HTML position?"""
    idx = body.find(probe)
    if idx == -1:
        return "none"
    before = body[max(0, idx - 200) : idx]
    after = body[idx + len(probe) : idx + len(probe) + 200]

    # Inside an HTML comment
    if before.rfind("<!--") > before.rfind("-->"):
        return "comment"
    # Inside <textarea>...</textarea>
    if before.rfind("<textarea") > before.rfind("</textarea>"):
        return "textarea"
    # Inside a quoted attribute value: look back for an unclosed quote
    # preceded by '=' (attribute context)
    quote_before = before.rfind('"')
    attr_marker = before.rfind("=")
    if quote_before > attr_marker and before.rfind("'") < quote_before:
        return "attribute_quoted"
    # Inside a <script> block (js_executable)
    if before.rfind("<script") > before.rfind("</script>"):
        return "js_executable"
    # Otherwise treat as raw body context (executable if the tag survives)
    return "html_body"
