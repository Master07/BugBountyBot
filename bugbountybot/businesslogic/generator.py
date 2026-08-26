"""Business-logic test-plan generator.

LLM-guided when configured; deterministic category templates otherwise. Produces
a TestPlan with ordered PlanSteps. Every step URL must be in program scope.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from bugbountybot.agent.llm import LLMAdapter
from bugbountybot.businesslogic.models import PlanStep, TestPlan
from bugbountybot.scope.guard import ProgramScope, ScopeGuard
from bugbountybot.storage.db import Endpoint, Program

# Deterministic templates per category: (method, url_template, params, body, expect)
# {target} is replaced with the endpoint URL, {id} with a sample resource id.
_TEMPLATES: dict[str, list[dict]] = {
    "price": [
        {"method": "POST", "url": "{target}", "params": {"price": "-1"}, "body": {}, "expect": "negative price accepted?"},
        {"method": "POST", "url": "{target}", "params": {"quantity": "-1"}, "body": {}, "expect": "negative quantity accepted?"},
        {"method": "POST", "url": "{target}", "params": {"price": "0"}, "body": {}, "expect": "zero price accepted?"},
        {"method": "POST", "url": "{target}", "params": {"currency": "USD", "price": "0.01"}, "body": {}, "expect": "decimal rounding / currency confusion?"},
    ],
    "workflow": [
        {"method": "GET", "url": "{target}", "params": {}, "body": {}, "expect": "step accessible out of order?"},
        {"method": "POST", "url": "{target}", "params": {"step": "finalize"}, "body": {}, "expect": "skip-payment / state jump accepted?"},
        {"method": "POST", "url": "{target}", "params": {"state": "complete"}, "body": {}, "expect": "forced state change?"},
    ],
    "priv": [
        {"method": "GET", "url": "{target}/admin", "params": {}, "body": {}, "expect": "admin endpoint reachable?"},
        {"method": "POST", "url": "{target}/admin/users", "params": {"role": "admin"}, "body": {}, "expect": "privilege escalation?"},
        {"method": "PATCH", "url": "{target}/settings", "params": {"permission": "manage_settings"}, "body": {}, "expect": "cross-permission change?"},
    ],
    "race": [
        {"method": "POST", "url": "{target}/redeem", "params": {"coupon": "TEST"}, "body": {}, "expect": "coupon double-redeem?"},
        {"method": "POST", "url": "{target}/withdraw", "params": {"amount": "10"}, "body": {}, "expect": "double-spend?"},
        {"method": "POST", "url": "{target}/apply", "params": {"gift_card": "TEST"}, "body": {}, "expect": "gift card reused?"},
    ],
    "idor": [
        {"method": "GET", "url": "{target}/{id}", "params": {}, "body": {}, "expect": "other user's object accessible?"},
        {"method": "GET", "url": "{target}/{id}/invoice", "params": {}, "body": {}, "expect": "other user's invoice?"},
        {"method": "PATCH", "url": "{target}/{id}", "params": {"owner": "me"}, "body": {}, "expect": "cross-tenant write?"},
    ],
    "auth": [
        {"method": "POST", "url": "{target}/login", "params": {"username": "admin", "password": "admin"}, "body": {}, "expect": "default creds accepted?"},
        {"method": "GET", "url": "{target}/logout", "params": {}, "body": {}, "expect": "logout invalidates session?"},
        {"method": "GET", "url": "{target}/profile", "params": {"role": "admin"}, "body": {}, "expect": "privilege after login?"},
        {"method": "POST", "url": "{target}/reset", "params": {"email": "victim@example.com"}, "body": {}, "expect": "reset-token leak / enumeration?"},
    ],
    "cart": [
        {"method": "POST", "url": "{target}/cart/add", "params": {"product": "1", "qty": "-1"}, "body": {}, "expect": "negative quantity?"},
        {"method": "POST", "url": "{target}/cart/add", "params": {"product": "1", "qty": "999999"}, "body": {}, "expect": "overflow quantity?"},
        {"method": "POST", "url": "{target}/cart/apply", "params": {"price": "0.01"}, "body": {}, "expect": "price override?"},
        {"method": "GET", "url": "{target}/cart/checkout", "params": {}, "body": {}, "expect": "checkout skips payment?"},
    ],
    "signup": [
        {"method": "POST", "url": "{target}/signup", "params": {"email": "a@a.com", "role": "admin"}, "body": {}, "expect": "mass-assignment role?"},
        {"method": "POST", "url": "{target}/signup", "params": {"email": "a@a.com", "is_admin": "true"}, "body": {}, "expect": "mass-assignment is_admin?"},
        {"method": "GET", "url": "{target}/users/{id}", "params": {}, "body": {}, "expect": "user object after signup?"},
    ],
    "coupon": [
        {"method": "POST", "url": "{target}/coupon/redeem", "params": {"code": "TEST10"}, "body": {}, "expect": "coupon reused?"},
        {"method": "POST", "url": "{target}/coupon/redeem", "params": {"code": "TEST10", "qty": "100"}, "body": {}, "expect": "coupon stacking?"},
        {"method": "POST", "url": "{target}/coupon/create", "params": {"code": "FREE", "value": "100"}, "body": {}, "expect": "coupon value injection?"},
    ],
}


def _build_steps(target: str, category: str) -> list[PlanStep]:
    steps: list[PlanStep] = []
    for i, t in enumerate(_TEMPLATES.get(category, _TEMPLATES["workflow"])):
        url = t["url"].format(target=target, id="12345")
        steps.append(
            PlanStep(
                order=i,
                method=t["method"],
                url=url,
                params=json.dumps(t["params"]),
                body=json.dumps(t["body"]),
                headers="{}",
                expect=t["expect"],
            )
        )
    return steps


def _llm_steps(adapter: LLMAdapter, target: str, category: str, program: str) -> list[PlanStep]:
    """Ask the LLM for a structured multi-step plan; parse into steps."""
    prompt = (
        f"Design a multi-step business-logic security test plan for category "
        f"'{category}' against {target} (program: {program}). "
        "Return ONLY a JSON list of steps, each: "
        '{"method": "GET|POST|PATCH", "url": "<full url, must contain the target host>", '
        '"params": {...}, "body": {...}, "expect": "what to check"}. '
        "Make 3-5 realistic steps (e.g. create resource, manipulate it, verify). "
        "Do not include destructive actions."
    )
    raw = adapter._chat("You are a bug bounty test-plan designer.", prompt)
    try:
        start = raw.find("[")
        end = raw.rfind("]")
        data = json.loads(raw[start : end + 1])
        steps = []
        for i, s in enumerate(data):
            steps.append(
                PlanStep(
                    order=i,
                    method=str(s.get("method", "GET")).upper(),
                    url=s.get("url", target),
                    params=json.dumps(s.get("params", {})),
                    body=json.dumps(s.get("body", {})),
                    headers="{}",
                    expect=str(s.get("expect", "")),
                )
            )
        return steps
    except Exception:
        return []  # fall back to templates


def generate_plan(
    session: Session,
    program_id: int,
    *,
    category: str = "workflow",
    target: str | None = None,
    title: str | None = None,
) -> TestPlan:
    """Generate and persist a business-logic test plan for a program."""
    from bugbountybot.businesslogic.models import CATEGORIES

    if category not in CATEGORIES:
        raise ValueError(f"unknown category: {category} (choose from {CATEGORIES})")

    program = session.get(Program, program_id)
    if program is None:
        raise ValueError("program not found")

    # Pick a target: explicit, else first in-scope endpoint, else program URL.
    if target:
        resolved = target
    else:
        ep = (
            session.query(Endpoint)
            .filter(Endpoint.program_id == program_id)
            .order_by(Endpoint.id)
            .first()
        )
        resolved = ep.url if ep else (program.url or "")

    # Validate the target is in scope before building steps.
    scope = ProgramScope.load(session, program_id)
    decision = ScopeGuard(scope).check(resolved, tier=2)
    if not decision.allowed:
        raise ValueError(f"target {resolved!r} is not in scope: {decision.reason}")

    adapter = LLMAdapter()
    steps = _llm_steps(adapter, resolved, category, program.name) if adapter.available else []
    if not steps:
        steps = _build_steps(resolved, category)

    plan = TestPlan(
        program_id=program_id,
        title=title or f"{category} logic test — {resolved}",
        category=category,
        description=f"Business-logic test plan for {resolved} (category: {category}).",
        status="draft",
    )
    session.add(plan)
    session.flush()
    for s in steps:
        s.plan_id = plan.id
        session.add(s)
    session.commit()
    return plan
