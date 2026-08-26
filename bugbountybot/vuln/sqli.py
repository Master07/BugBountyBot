"""SQL Injection module — CWE-89. Lightweight error-based + boolean probes.

Per plan, sqlmap is manual-confirm only; this module does safe probes (tier 2)
and marks suspected candidates. No destructive payloads.
"""
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

# Common DB error fingerprints (fragments, case-insensitive).
_ERROR_PATTERNS = [
    re.compile(r"SQL syntax.*MySQL", re.I),
    re.compile(r"Warning.*mysql_.*", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"ORA-[0-9]{5}", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
    re.compile(r"Unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"SQLite/JDBCDriver", re.I),
    re.compile(r"you have an error in your SQL syntax", re.I),
    re.compile(r"SQLITE_ERROR", re.I),
    re.compile(r"near \".*\": syntax error", re.I),  # SQLite/Sequelize syntax errors
    re.compile(r"SequelizeDatabaseError", re.I),
]


class SQLiModule(VulnModule):
    name = "sqli"
    cwe = ["CWE-89"]
    default_tier = 2
    required_discovery = ["params"]

    def discover_injection_points(self, target_url: str, endpoints: list | None = None):
        points = []
        for ep in endpoints or []:
            for p in (ep.get("params") or "").split(","):
                if p:
                    points.append(
                        InjectionPoint(url=ep["url"], param=p, context="sql_string")
                    )
        if not points:
            from urllib.parse import parse_qsl, urlsplit

            for p, _ in parse_qsl(urlsplit(target_url).query):
                points.append(InjectionPoint(url=target_url, param=p, context="sql_string"))
        return points

    def select_payloads(self, point: InjectionPoint, max_tier: int):
        return select_for_context(self.library, "sqli", point.context, max_tier=max_tier, limit=10)

    def inject(self, point: InjectionPoint, payload, encoder_chain: list[str]):
        value = apply_chain(payload.payload, encoder_chain)
        return self._inject(self.client, point, value)

    def detect(self, response: httpx.Response, payload, encoder_chain: list[str]):
        body = response.text
        for pattern in _ERROR_PATTERNS:
            if pattern.search(body):
                return DetectionResult(
                    signal="error",
                    matched=True,
                    detail=f"DB error fingerprint: {pattern.pattern[:60]}",
                    response=response,
                    payload=payload,
                    encoder_chain=encoder_chain,
                )
        # Row-count signal: a payload that returns MORE results than the
        # baseline (e.g. `' OR '1'='1` returning all rows) is a strong SQLi
        # indicator, common on JSON APIs like Juice Shop.
        try:
            import json as _json

            baseline = self._baseline_len(payload)
            data_len = len(_json.loads(body).get("data", [])) if "data" in body else -1
            if baseline is not None and data_len > baseline:
                return DetectionResult(
                    signal="diff",
                    matched=True,
                    detail=f"row-count diff: {data_len} rows vs baseline {baseline} (boolean/union signal)",
                    response=response,
                    payload=payload,
                    encoder_chain=encoder_chain,
                )
        except Exception:
            pass
        return DetectionResult(
            signal="error", matched=False, detail="no DB error fingerprint",
            response=response, payload=payload, encoder_chain=encoder_chain,
        )

    def _baseline_len(self, payload) -> int | None:
        """Number of rows the baseline (non-injected) request returns, if JSON."""
        import json as _json
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

        try:
            url = str(payload.payload) if hasattr(payload, "payload") else str(payload)
            # The detection payload may BE the URL; rebuild a baseline by
            # replacing the payload value with a neutral '1'.
            parsed = urlsplit(url)
            params = parse_qsl(parsed.query)
            neutral = [(k, "1" if "q" in k else v) for k, v in params]
            base_url = urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, urlencode(neutral), "")
            )
            r = self.client.get(base_url, timeout=10)
            return len(_json.loads(r.text).get("data", [])) if "data" in r.text else None
        except Exception:
            return None

    def confirm(self, candidate: DetectionResult) -> ConfirmedFinding | None:
        """Confirm with a stability baseline + two signals.

        Error-fingerprint signal: a DB error page on a quote probe (with a
        stable baseline) is sufficient confirmation — this catches error-based
        and union SQLi that boolean-diff can't (e.g. Juice Shop's 500 on `'`).
        Otherwise fall back to boolean-diff (1=1 vs 1=2) with a stable baseline.
        """
        payload = candidate.payload
        url = str(candidate.response.request.url)
        import urllib.parse

        parsed = urllib.parse.urlsplit(url)
        detected = urllib.parse.parse_qsl(parsed.query)
        if not detected:
            return None
        param_name = detected[0][0]

        def _probe(value):
            p = {k: (value if k == param_name else v) for k, v in detected}
            return self.client.get(
                urllib.parse.urlunsplit(
                    (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(p), "")
                ),
                timeout=10,
            )

        # 1. Stability baseline: identical request twice must match.
        base_value = detected[0][1] or "1"
        r_a = _probe(base_value)
        r_b = _probe(base_value)
        if r_a.status_code != r_b.status_code or r_a.text != r_b.text:
            return None  # dynamic page — no confirm

        # 2. Error-fingerprint signal: the detection already matched a DB error
        #    page; with a stable baseline that is a confirmed error-based SQLi.
        if candidate.signal == "error":
            return ConfirmedFinding(
                title="SQL Injection (error-based)",
                severity="high",
                detail=f"DB error fingerprint on stable baseline (param {param_name}).",
                url=url,
                module=self.name,
                cwe="CWE-89",
                cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                payload_id=payload.id,
                request_text=f"GET {url} HTTP/1.1",
                response_text=self._response_text(candidate.response),
                dedup_key=f"sqli:{url}",
            )

        # 3. Boolean-diff fallback: clean numeric probes, stable baseline.
        probe_true = base_value + " AND 1=1"
        probe_false = base_value + " AND 1=2"
        r_true = _probe(probe_true)
        r_false = _probe(probe_false)

        # 3. Normalized comparison: status + body length + similarity threshold.
        if r_true.status_code != r_false.status_code:
            return None
        if abs(len(r_true.text) - len(r_false.text)) < 20 and r_true.text == r_false.text:
            return None
        # A stable baseline (step 1) already rules out dynamic pages, so ANY
        # difference between 1=1 and 1=2 is meaningful. Compute diff for the
        # report but don't reject on it.
        diff = _diff_score(r_true.text, r_false.text)
        if diff < 0.001:
            return None

        return ConfirmedFinding(
            title="SQL Injection",
            severity="high",
            detail=f"Boolean-diff confirm passed on {param_name}: 1=1 vs 1=2 differ "
                   f"(stable baseline, diff_score={diff:.2f}).",
            url=url,
            module=self.name,
            cwe="CWE-89",
            cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            payload_id=payload.id,
            request_text=f"GET {url} HTTP/1.1",
            response_text=self._response_text(r_true),
            dedup_key=f"sqli:{url}",
        )


def _diff_score(a: str, b: str) -> float:
    """Fraction of differing characters between two bodies (0.0 = identical)."""
    if not a and not b:
        return 0.0
    n = max(len(a), len(b), 1)
    diffs = sum(1 for i in range(min(len(a), len(b))) if a[i] != b[i])
    diffs += abs(len(a) - len(b))
    return diffs / n
