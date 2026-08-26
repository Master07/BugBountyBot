"""Scope Guard unit tests — the most critical safety surface."""
from __future__ import annotations

import pytest

from bugbountybot.scope.guard import ProgramScope, ScopeGuard


@pytest.fixture()
def guard(session, scoped_program):
    scope = ProgramScope.load(session, scoped_program.id)
    return ScopeGuard(scope)


def test_in_scope_domain_allowed(guard):
    assert guard.check("https://acme.com/login", tier=1).allowed


def test_wildcard_subdomain_allowed(guard):
    assert guard.check("https://api.acme.com/v1/users", tier=2).allowed


def test_out_of_scope_domain_blocked(guard):
    d = guard.check("https://evil.com/x", tier=1)
    assert not d.allowed
    assert "not in scope" in d.reason


def test_third_party_sibling_blocked(guard):
    d = guard.check("https://acme.evil.com/x", tier=1)
    assert not d.allowed


def test_cidr_ip_allowed(guard):
    assert guard.check("http://10.1.2.3/health", tier=1).allowed


def test_ip_outside_cidr_blocked(guard):
    assert not guard.check("http://192.168.1.1/", tier=1).allowed


def test_out_of_scope_rule_wins(guard, session, scoped_program):
    from bugbountybot.tracker.service import add_scope

    add_scope(session, scoped_program.id, "admin.acme.com", kind="domain")
    # explicit out-of-scope rule for admin subdomain
    from bugbountybot.storage.db import ScopeRule

    session.add(
        ScopeRule(
            program_id=scoped_program.id,
            pattern="admin.acme.com",
            kind="domain",
            in_scope=False,
        )
    )
    session.commit()
    guard2 = ScopeGuard(ProgramScope.load(session, scoped_program.id))
    d = guard2.check("https://admin.acme.com/", tier=1)
    assert not d.allowed
    assert "out of scope" in d.reason


def test_tier_blocked_by_default(guard):
    d = guard.check("https://acme.com/x", tier=4)
    assert not d.allowed


def test_tier_above_policy_blocked(guard):
    # policy allows tiers 1,2 only; tier 3 should be blocked
    d = guard.check("https://acme.com/x", tier=3)
    assert not d.allowed
