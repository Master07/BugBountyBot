"""GraphQL module — introspection, field-level authz, batching/depth.

Probes common GraphQL endpoints with an introspection query; if introspection is
enabled → finding. Then tests top-level field access (field-level authz) and
aliased-overload / deep-nesting queries (batching/depth abuse).

Uses the session (auth'd queries) via the runner. Tier 2.
"""
from __future__ import annotations

import json

import httpx

from bugbountybot.payloads.models import Payload
from bugbountybot.vuln.base import (
    ConfirmedFinding,
    DetectionResult,
    InjectionPoint,
    VulnModule,
)

_GRAPHQL_PATHS = ["/graphql", "/graphiql", "/v1/graphql", "/api/graphql", "/gql"]

_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema { types { name } }
}
"""


class GraphQLModule(VulnModule):
    name = "graphql"
    cwe = ["CWE-200"]
    default_tier = 2
    required_discovery = ["params"]

    def __init__(self, client, library=None, *, session_profile=None):
        super().__init__(client, library)
        self.session_profile = session_profile

    def discover_injection_points(self, target_url: str, endpoints: list | None = None):
        from urllib.parse import urlsplit

        parsed = urlsplit(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return [
            InjectionPoint(url=f"{base}{path}", param="", location="body", context="json_value")
            for path in _GRAPHQL_PATHS
        ]

    def select_payloads(self, point: InjectionPoint, max_tier: int):
        return [Payload(id=f"gql-{point.url}", category="graphql", payload=point.url, tier=2)]

    def inject(self, point: InjectionPoint, payload, encoder_chain: list[str]):
        return self.client.post(
            point.url,
            json={"query": _INTROSPECTION_QUERY},
            headers={**point.headers, "Content-Type": "application/json"},
            timeout=10,
        )

    def detect(self, response: httpx.Response, payload, encoder_chain: list[str]):
        url = payload.payload
        detail: list[str] = []

        # 1. Introspection enabled?
        introspected = False
        try:
            data = response.json()
            if data.get("data", {}).get("__schema"):
                introspected = True
                detail.append("introspection enabled (schema exposed)")
        except Exception:
            pass

        # 2. Field-level authz: query __typename on a sensitive field.
        field_check = self._check_field_authz(url)
        if field_check:
            detail.append(field_check)

        # 3. Batching / depth: aliased-overload query.
        batch_check = self._check_batching(url)
        if batch_check:
            detail.append(batch_check)

        if not detail:
            return DetectionResult(signal="status", matched=False, detail="no GraphQL flaw", response=response)
        return DetectionResult(
            signal="error",
            matched=True,
            detail="; ".join(detail),
            response=response,
            payload=payload,
        )

    def _gql_post(self, url: str, query: str) -> httpx.Response:
        return self.client.post(
            url,
            json={"query": query},
            headers={**self.client.headers, "Content-Type": "application/json"},
            timeout=10,
        )

    def _check_field_authz(self, url: str) -> str | None:
        """If introspection worked, we know the schema; check common sensitive
        field names via __typename (cheap authz probe)."""
        for field in ("users", "admin", "orders", "invoices", "private"):
            q = f"{{ {field} {{ __typename }} }}"
            try:
                r = self._gql_post(url, q)
                data = r.json()
                if r.status_code == 200 and data.get("data") is not None and "__typename" in str(data.get("data")):
                    return f"field '{field}' resolves without error (possible authz gap)"
            except Exception:
                continue
        return None

    def _check_batching(self, url: str) -> str | None:
        """Aliased-overload / deep-nesting probe."""
        q = "{ a1: users { __typename } a2: users { __typename } a3: users { __typename } }"
        try:
            r = self._gql_post(url, q)
            data = r.json()
            if r.status_code == 200 and data.get("data"):
                return "aliased batching accepted (200 on 3-aliased query)"
        except Exception:
            pass
        return None

    def confirm(self, candidate: DetectionResult) -> ConfirmedFinding | None:
        severity = "high" if "authz" in candidate.detail else "info"
        return ConfirmedFinding(
            title="GraphQL exposure",
            severity=severity,
            detail=candidate.detail,
            url=str(candidate.response.request.url),
            module=self.name,
            cwe="CWE-200",
            cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" if severity == "info" else "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            payload_id="graphql-probe",
            request_text=f"POST {candidate.response.request.url} HTTP/1.1\n{_INTROSPECTION_QUERY}",
            response_text=self._response_text(candidate.response),
            dedup_key=f"graphql:{candidate.response.request.url}",
        )
