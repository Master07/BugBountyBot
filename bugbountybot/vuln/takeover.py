"""Subdomain takeover module — dangling CNAME -> unclaimed service fingerprint.

For an in-scope host: resolve its CNAME; if the CNAME target belongs to a
cloud service (S3, GitHub Pages, Heroku, Azure, etc.) and the service responds
with its "not claimed" signature (NXDOMAIN / NoSuchBucket / 404-with-marker),
flag as a takeover candidate. Human verifies before reporting.
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

# CNAME target fingerprint -> (service, dangling-marker regex)
_CNAME_FINGERPRINTS: list[tuple[re.Pattern, str, re.Pattern]] = [
    (re.compile(r"\.s3(?:[.-][\w-]*)?\.amazonaws\.com$"), "AWS S3", re.compile(r"NoSuchBucket|does not exist", re.I)),
    (re.compile(r"\.github\.io$"), "GitHub Pages", re.compile(r"There isn't a GitHub Pages site here", re.I)),
    (re.compile(r"\.herokuapp\.com$"), "Heroku", re.compile(r"No such app", re.I)),
    (re.compile(r"\.azurewebsites\.net$"), "Azure", re.compile(r"404 Web Site not found", re.I)),
    (re.compile(r"\.cloudfront\.net$"), "CloudFront", re.compile(r"ERROR: The request could not be satisfied", re.I)),
    (re.compile(r"\.netlify\.app$"), "Netlify", re.compile(r"Not Found - Request ID", re.I)),
    (re.compile(r"\.pantheonsite\.io$"), "Pantheon", re.compile(r"404 error unknown site", re.I)),
    (re.compile(r"\.fastly\.net$"), "Fastly", re.compile(r"Fastly error: unknown domain", re.I)),
]


class TakeoverModule(VulnModule):
    name = "takeover"
    cwe = ["CWE-350"]
    default_tier = 2
    required_discovery = ["hosts"]

    def discover_injection_points(self, target_url: str, endpoints: list | None = None):
        from urllib.parse import urlsplit

        host = urlsplit(target_url).hostname or ""
        return [InjectionPoint(url=f"https://{host}", param="", location="path", context="html_body")]

    def select_payloads(self, point: InjectionPoint, max_tier: int):
        return [Payload(id="takeover-probe", category="takeover", payload=point.url, tier=2)]

    def inject(self, point: InjectionPoint, payload, encoder_chain: list[str]):
        # Fetch the host; detect() will resolve the CNAME and, if it points at
        # an unclaimed service, check that service's response.
        return self.client.get(point.url, timeout=10, follow_redirects=True)

    def _cname_target(self, host: str) -> str | None:
        import dns.resolver

        try:
            answers = dns.resolver.resolve(host, "CNAME")
            return str(answers[0].target).rstrip(".")
        except dns.resolver.NXDOMAIN:
            return "NXDOMAIN"  # host's DNS is gone — strong takeover signal
        except Exception:
            return None

    def detect(self, response: httpx.Response, payload, encoder_chain: list[str]):
        from urllib.parse import urlsplit

        host = urlsplit(payload.payload).hostname or ""
        cname = self._cname_target(host)

        # NXDOMAIN on the host itself: the CNAME chain is broken → takeover candidate
        # (check the body too — many services return their "not claimed" page).
        if cname == "NXDOMAIN":
            body = response.text
            if any(fp[2].search(body) for fp in _CNAME_FINGERPRINTS):
                return DetectionResult(
                    signal="header",
                    matched=True,
                    detail=f"Host NXDOMAIN with unclaimed-service marker in body",
                    response=response,
                    payload=payload,
                )
            return DetectionResult(signal="status", matched=False, detail="host NXDOMAIN, no service marker", response=response)

        if not cname:
            return DetectionResult(signal="status", matched=False, detail="no CNAME", response=response)

        for cname_re, service, dangling_re in _CNAME_FINGERPRINTS:
            if cname_re.search(cname):
                body = response.text
                if dangling_re.search(body):
                    return DetectionResult(
                        signal="header",
                        matched=True,
                        detail=f"Dangling CNAME -> {service} ({cname}) with unclaimed marker",
                        response=response,
                        payload=payload,
                    )
                return DetectionResult(signal="status", matched=False, detail=f"CNAME to {service} (claimed)", response=response)
        return DetectionResult(signal="status", matched=False, detail="CNAME not a known takeover service", response=response)

    def confirm(self, candidate: DetectionResult) -> ConfirmedFinding | None:
        return ConfirmedFinding(
            title="Subdomain takeover candidate",
            severity="high",
            detail=candidate.detail,
            url=str(candidate.response.request.url),
            module=self.name,
            cwe="CWE-350",
            cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            payload_id="takeover-probe",
            request_text=f"GET {candidate.response.request.url} HTTP/1.1",
            response_text=self._response_text(candidate.response),
            dedup_key=f"takeover:{candidate.response.request.url}",
        )
