"""Scope Guard — validates every request against program scope before execution.

The guard is the only gate between the runner and the network. It blocks
out-of-scope domains/IPs and Tier 4 payloads unless the program policy
explicitly allows them. Every decision is audit-logged by the caller.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from bugbountybot.storage.db import ScopeRule, VulnPolicy

# Max tier the guard will pass without explicit program opt-in.
DEFAULT_MAX_TIER = 3
TIER4_ENABLED = False  # global kill-switch for destructive payloads


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str = ""
    matched_rule: str = ""


@dataclass
class ProgramScope:
    """In-memory view of a program's scope rules + policy."""

    program_id: int
    rules: list[ScopeRule] = field(default_factory=list)
    policy: VulnPolicy | None = None

    @classmethod
    def load(cls, session: Session, program_id: int) -> "ProgramScope":
        rules = (
            session.query(ScopeRule)
            .filter(ScopeRule.program_id == program_id)
            .all()
        )
        policy = (
            session.query(VulnPolicy)
            .filter(VulnPolicy.program_id == program_id)
            .first()
        )
        return cls(program_id=program_id, rules=rules, policy=policy)

    def allowed_tiers(self) -> set[int]:
        if self.policy is None:
            return {1, 2}
        return {int(t) for t in self.policy.allowed_tiers.split(",") if t.strip()}

    def blocked_modules(self) -> set[str]:
        if self.policy is None:
            return set()
        return {m.strip() for m in self.policy.blocked_modules.split(",") if m.strip()}


def _domain_matches(host: str, pattern: str, kind: str) -> bool:
    """Match a host against one scope rule."""
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if kind in ("domain", "wildcard"):
        if pattern.startswith("*."):
            base = pattern[2:]
            return host == base or host.endswith("." + base)
        if pattern.startswith("*"):
            return fnmatch.fnmatch(host, pattern)
        return host == pattern
    if kind == "ip":
        try:
            return ipaddress.ip_address(host) == ipaddress.ip_address(pattern)
        except ValueError:
            return False
    if kind == "cidr":
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False
    return False


class ScopeGuard:
    def __init__(self, scope: ProgramScope):
        self.scope = scope

    def _check_tier(self, tier: int, module: str = "") -> ScopeDecision:
        allowed = tier <= DEFAULT_MAX_TIER
        if not allowed:
            return ScopeDecision(False, f"tier {tier} exceeds max {DEFAULT_MAX_TIER}")
        if tier not in self.scope.allowed_tiers():
            return ScopeDecision(False, f"tier {tier} not allowed by program policy")
        if module and module in self.scope.blocked_modules():
            return ScopeDecision(False, f"module {module} blocked by program policy")
        return ScopeDecision(True)

    def check(
        self,
        url: str,
        *,
        tier: int = 1,
        module: str = "",
    ) -> ScopeDecision:
        """Validate a URL + tier + module against scope. The single gate."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host:
            return ScopeDecision(False, "no host in url")

        tier_ok = self._check_tier(tier, module)
        if not tier_ok.allowed:
            return tier_ok

        if tier == 4 and not TIER4_ENABLED:
            return ScopeDecision(False, "tier 4 payloads blocked by default")

        in_scope = False
        matched = ""
        for rule in self.scope.rules:
            if _domain_matches(host, rule.pattern, rule.kind):
                if rule.in_scope:
                    in_scope = True
                    matched = rule.pattern
                else:
                    # An out-of-scope rule wins even if a broader in-scope rule matched.
                    return ScopeDecision(False, f"host {host} is out of scope ({rule.pattern})")
        if not in_scope:
            return ScopeDecision(False, f"host {host} not in scope")

        return ScopeDecision(True, matched_rule=matched)


def add_scope_rule(
    session: Session,
    program_id: int,
    pattern: str,
    kind: str = "domain",
    in_scope: bool = True,
) -> ScopeRule:
    rule = ScopeRule(program_id=program_id, pattern=pattern, kind=kind, in_scope=in_scope)
    session.add(rule)
    session.commit()
    return rule
