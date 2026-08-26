"""Scoped Test Runner — orchestrates the pipeline: scope check -> inject -> detect
-> confirm -> store finding + evidence. Every request is audit-logged.

The runner is the ONLY place that talks to the network on a program's behalf,
and it never does so without passing the Scope Guard first.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from bugbountybot.oob.server import OOBServer
from bugbountybot.payloads.loader import PayloadLibrary
from bugbountybot.scope.guard import ProgramScope, ScopeGuard
from bugbountybot.storage.artifacts import ArtifactStore
from bugbountybot.storage.audit import log_request
from bugbountybot.storage.db import Finding
from bugbountybot.tracker.service import add_evidence, add_finding, list_endpoints
from bugbountybot.vuln.base import ConfirmedFinding, run_module
from bugbountybot.vuln.cors import CORSModule
from bugbountybot.vuln.graphql import GraphQLModule
from bugbountybot.vuln.idor import IDORModule
from bugbountybot.vuln.jwt_auth import JWTModule
from bugbountybot.vuln.redirect import RedirectModule
from bugbountybot.vuln.secrets import SecretsModule
from bugbountybot.vuln.sqli import SQLiModule
from bugbountybot.vuln.ssrf import SSRFModule
from bugbountybot.vuln.takeover import TakeoverModule
from bugbountybot.vuln.xss import XSSModule

MODULE_REGISTRY = {
    "xss": XSSModule,
    "sqli": SQLiModule,
    "idor": IDORModule,
    "redirect": RedirectModule,
    "cors": CORSModule,
    "ssrf": SSRFModule,
    "secrets": SecretsModule,
    "takeover": TakeoverModule,
    "jwt": JWTModule,
    "graphql": GraphQLModule,
}


def make_oob(artifacts: ArtifactStore, port: int = 0):
    """Return the OOB object for SSRF: a CollaboratorClient when an external
    collaborator is configured (no local bind), else the local OOBServer."""
    from bugbountybot.config.settings import OOB_BASE_URL
    from bugbountybot.oob.collaborator import CollaboratorClient

    if OOB_BASE_URL:
        return CollaboratorClient(OOB_BASE_URL)
    return OOBServer(port=port, artifact_store=artifacts).start()


@dataclass
class RunResult:
    module: str
    findings: list[ConfirmedFinding]
    blocked: int = 0  # requests blocked by scope guard


class ScopedRunner:
    def __init__(
        self,
        session: Session,
        *,
        program_id: int,
        library: PayloadLibrary,
        artifacts: ArtifactStore,
        oob: OOBServer | None = None,
        confirm: bool = False,
        session_profile=None,
        session_b=None,
        rate: float = 5.0,
    ):
        self.session = session
        self.scope = ProgramScope.load(session, program_id)
        self.guard = ScopeGuard(self.scope)
        self.library = library
        self.artifacts = artifacts
        self.oob = oob
        self.confirm = confirm
        self.session_profile = session_profile
        self.session_b = session_b
        # per-program policy rate (req/sec), default 5
        if self.scope.policy is not None and self.scope.policy.max_rate:
            rate = float(self.scope.policy.max_rate)
        from bugbountybot.runner.ratelimit import RateLimiter

        self.ratelimiter = RateLimiter(rate=rate)

    def _allowed(self, url: str, tier: int, module: str) -> bool:
        decision = self.guard.check(url, tier=tier, module=module)
        snapshot = f"program={self.scope.program_id}"
        log_request(
            self.session,
            url=url,
            tier=tier,
            scope_snapshot=snapshot,
            allowed=decision.allowed,
            reason=decision.reason,
        )
        return decision.allowed

    def run_module(self, module_name: str, target_url: str, max_tier: int = 2) -> RunResult:
        if module_name not in MODULE_REGISTRY:
            raise KeyError(f"unknown module: {module_name}")

        module_cls = MODULE_REGISTRY[module_name]
        default_tier = module_cls.default_tier
        effective_tier = max_tier

        # Tier 3 modules need --confirm (or program policy allowing tier 3).
        if default_tier >= 3 and not self.confirm:
            log_request(
                self.session,
                url=target_url,
                tier=default_tier,
                scope_snapshot=f"program={self.scope.program_id}",
                allowed=False,
                reason=f"module {module_name} requires --confirm (tier {default_tier})",
            )
            return RunResult(module=module_name, findings=[], blocked=1)

        # SSRF needs an OOB listener; without one it can't confirm.
        if module_name == "ssrf" and self.oob is None:
            log_request(
                self.session,
                url=target_url,
                tier=default_tier,
                scope_snapshot=f"program={self.scope.program_id}",
                allowed=False,
                reason="ssrf requires --oob listener",
            )
            return RunResult(module=module_name, findings=[], blocked=1)

        if not self._allowed(target_url, tier=1, module=module_name):
            return RunResult(module=module_name, findings=[], blocked=1)

        # Only inject into endpoints on the TARGET's host — otherwise a program
        # with thousands of inventory endpoints makes every scan crawl them all.
        target_host = (urlparse(target_url).hostname or "").lower()
        endpoints = [
            {"url": ep.url, "method": ep.method, "params": ep.params}
            for ep in list_endpoints(self.session, self.scope.program_id)
            if (urlparse(ep.url).hostname or "").lower() == target_host
        ]
        # Cap per-scan endpoints so one host's big inventory can't stall a run.
        MAX_ENDPOINTS_PER_SCAN = 20
        endpoints = endpoints[:MAX_ENDPOINTS_PER_SCAN]
        if not endpoints and module_name in ("secrets", "takeover", "cors", "jwt", "graphql"):
            # these modules derive their own injection points from the target
            pass

        client_kwargs = {"timeout": 10, "follow_redirects": True}
        client_b_kwargs = None
        if self.session_profile is not None:
            from bugbountybot.runner.session import profile_cookies, profile_headers

            client_kwargs["cookies"] = profile_cookies(self.session_profile)
            client_kwargs["headers"] = profile_headers(self.session_profile)
        if self.session_b is not None:
            from bugbountybot.runner.session import profile_cookies, profile_headers

            client_b_kwargs = {"timeout": 10, "follow_redirects": True}
            client_b_kwargs["cookies"] = profile_cookies(self.session_b)
            client_b_kwargs["headers"] = profile_headers(self.session_b)

        with httpx.Client(**client_kwargs) as client:
            client_b = httpx.Client(**client_b_kwargs) if client_b_kwargs else None
            kwargs = {"client": client, "library": self.library}
            if module_name == "ssrf":
                kwargs["oob"] = self.oob
            if module_name == "idor":
                kwargs["id_a"] = "1"
                kwargs["id_b"] = "2"
                if client_b is not None:
                    kwargs["client_b"] = client_b
            module = module_cls(**kwargs)
            if module_name == "jwt":
                module.session_profile = self.session_profile

            confirmed: list[ConfirmedFinding] = []
            blocked = 0
            for point in module.discover_injection_points(target_url, endpoints):
                for payload in module.select_payloads(point, effective_tier):
                    if not self._allowed(point.url, tier=payload.tier, module=module_name):
                        blocked += 1
                        continue
                    # rate limit before the request (shared per-host bucket)
                    allowed, reason = self.ratelimiter.before_request(point.url)
                    if not allowed:
                        blocked += 1
                        continue
                    try:
                        response = module.inject(point, payload, [])
                    except (httpx.HTTPError, httpx.InvalidURL):
                        continue
                    self.ratelimiter.after_response(str(response.request.url), response.status_code, response.headers.get("retry-after", ""))
                    result = module.detect(response, payload, [])
                    if not result.matched:
                        continue
                    confirmed_finding = module.confirm(result)
                    if confirmed_finding:
                        confirmed.append(confirmed_finding)

        return RunResult(module=module_name, findings=confirmed, blocked=blocked)

    def run_all(
        self,
        module_names: list[str],
        target_url: str,
        max_tier: int = 2,
    ) -> list[tuple[RunResult, Exception | None]]:
        """Run several modules crash-safely: a failing module is recorded as a
        failed ScanRun, partial results persist, and remaining modules still run."""
        results: list[tuple[RunResult, Exception | None]] = []
        for m in module_names:
            try:
                run = self.run_module(m, target_url, max_tier=max_tier)
                results.append((run, None))
            except Exception as e:  # never let one module kill the scan
                self.record_run(
                    self.scope.program_id,
                    target=target_url,
                    modules=m,
                    tier=max_tier,
                    status="failed",
                    error=f"{type(e).__name__}: {e}",
                )
                results.append((RunResult(module=m, findings=[], blocked=0), e))
        return results

    def persist_findings(self, program_id: int, run: RunResult) -> list[Finding]:
        """Write confirmed findings + evidence to the DB, deduped by dedup_key."""
        existing_keys = {
            f.dedup_key
            for f in self.session.query(Finding).filter(Finding.program_id == program_id).all()
        }
        stored: list[Finding] = []
        for cf in run.findings:
            if cf.dedup_key in existing_keys:
                continue
            finding = add_finding(
                self.session,
                program_id=program_id,
                submission_id=None,
                title=cf.title,
                module=cf.module,
                cwe=cf.cwe,
                cvss=cf.cvss,
                severity=cf.severity,
                url=cf.url,
                detail=cf.detail,
                payload_id=cf.payload_id,
                dedup_key=cf.dedup_key,
                status="confirmed",
            )
            rel_path = self.artifacts.save_request_response(
                cf.request_text, cf.response_text
            )
            add_evidence(
                self.session, finding.id, kind="request_response", path=rel_path
            )
            existing_keys.add(cf.dedup_key)
            stored.append(finding)
        return stored

    def record_run(
        self,
        program_id: int,
        *,
        target: str,
        modules: str,
        tier: int,
        confirm: bool = False,
        findings_created: int = 0,
        blocked: int = 0,
        status: str = "completed",
        error: str = "",
    ):
        """Record a scan run's details in the DB (scan history).

        status: running|completed|failed — failures are recorded, never silent.
        """
        from bugbountybot.storage.db import ScanRun, with_retry

        def _write():
            self.session.add(
                ScanRun(
                    program_id=program_id,
                    target=target,
                    modules=modules,
                    tier=tier,
                    confirm=confirm,
                    findings_created=findings_created,
                    blocked=blocked,
                    status=status,
                    error=error,
                )
            )
            self.session.commit()

        with_retry(_write)
