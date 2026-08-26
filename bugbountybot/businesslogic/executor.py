"""Business-logic test-plan executor.

Runs each step in a plan via httpx, gated by the Scope Guard and audit-logged
per request (same discipline as the vuln runner). Interesting responses become
candidate findings (module `business_logic`).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx
from sqlalchemy.orm import Session

from bugbountybot.businesslogic.models import PlanStep, TestPlan, parse_json
from bugbountybot.scope.guard import ProgramScope, ScopeGuard
from bugbountybot.storage.audit import log_request
from bugbountybot.tracker.service import add_evidence, add_finding


@dataclass
class PlanResult:
    plan_id: int
    total_steps: int = 0
    executed: int = 0
    blocked: int = 0
    interesting: list[PlanStep] = field(default_factory=list)
    findings_created: int = 0


def _looks_interesting(step: PlanStep) -> bool:
    """Heuristic: a 2xx/3xx on a logic step that should fail, or any 200 with
    the expected marker present. This is a candidate gate, not proof."""
    status = step.result_status or 0
    if status == 0:
        return False
    # A step that returned success (2xx) when we probed a forbidden/invalid
    # action is worth a human look.
    if 200 <= status < 300:
        return True
    if status in (302, 303) and "skip" in step.expect.lower():
        return True
    return False


def execute_plan(
    session: Session,
    plan_id: int,
    *,
    parallel: bool = False,
    session_b=None,
) -> PlanResult:
    """Execute a plan's steps in order (or in parallel for race plans).

    session_b: a second authenticated httpx client — when provided, each step is
    also re-run as user B so cross-tenant business logic is caught.
    """
    plan = session.get(TestPlan, plan_id)
    if plan is None:
        raise ValueError(f"no plan #{plan_id}")
    program_id = plan.program_id
    scope = ProgramScope.load(session, program_id)
    guard = ScopeGuard(scope)
    snapshot = f"program={program_id}"

    result = PlanResult(plan_id=plan_id, total_steps=len(plan.steps))
    steps = plan.steps
    if parallel:
        # Race: fire all steps concurrently, then collect.
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=min(8, len(steps) or 1)) as pool:
            futures = {pool.submit(_exec_one, s, guard, snapshot, session): s for s in steps}
            for fut, s in futures.items():
                ok, blocked, note = fut.result()
                s.result_note = note
                if blocked:
                    result.blocked += 1
                elif ok:
                    result.executed += 1
                session.commit()
    else:
        with httpx.Client(timeout=15, follow_redirects=False) as client:
            for s in steps:
                ok, blocked, note = _exec_one(s, guard, snapshot, session, client=client)
                # re-run as user B when a second session is provided
                if session_b is not None and ok and not blocked:
                    _b_ok, _b_blocked, _b_note = _exec_one(s, guard, snapshot, session, client=session_b)
                    s.result_note = f"{note} | B: {_b_note}"
                else:
                    s.result_note = note
                if blocked:
                    result.blocked += 1
                elif ok:
                    result.executed += 1
                session.commit()

    plan.status = "executed"
    session.commit()

    # Create candidate findings for interesting steps.
    for s in steps:
        if _looks_interesting(s):
            result.interesting.append(s)
            finding = add_finding(
                session,
                program_id=program_id,
                submission_id=None,
                title=f"Business logic candidate ({plan.category}): {s.url}",
                module="business_logic",
                severity="medium",
                url=s.url,
                detail=f"Plan '{plan.title}' step {s.order + 1}: {s.expect} — status {s.result_status}.",
                status="candidate",
                dedup_key=f"bl:{plan_id}:{s.order}",
            )
            rel = _save_evidence(s)
            if rel:
                add_evidence(session, finding.id, kind="request_response", path=rel)
            result.findings_created += 1
    plan.findings_count = result.findings_created
    session.commit()
    return result


def _exec_one(step: PlanStep, guard, snapshot, session, client=None):
    """Run one step. Returns (ok, blocked, note)."""
    decision = guard.check(step.url, tier=2)
    log_request(
        session,
        url=step.url,
        tier=2,
        scope_snapshot=snapshot,
        allowed=decision.allowed,
        reason=decision.reason,
    )
    if not decision.allowed:
        return False, True, f"BLOCKED: {decision.reason}"

    own_client = client is None
    c = client or httpx.Client(timeout=15, follow_redirects=False)
    try:
        params = parse_json(step.params, {})
        body = parse_json(step.body, {})
        headers = parse_json(step.headers, {})
        resp = c.request(
            step.method,
            step.url,
            params=params or None,
            json=body or None,
            headers=headers or None,
        )
        step.result_status = resp.status_code
        note = f"HTTP {resp.status_code}"
        if resp.status_code in (200, 201) and "error" not in resp.text[:200].lower():
            note += " (no error marker)"
        return True, False, note
    except httpx.HTTPError as e:
        step.result_status = 0
        return False, False, f"error: {type(e).__name__}"
    finally:
        if own_client:
            c.close()


def _save_evidence(step: PlanStep) -> str:
    """Persist the step's request/response as an evidence artifact."""
    try:
        from bugbountybot.config.settings import DATA_DIR
        from bugbountybot.storage.artifacts import ArtifactStore

        params = parse_json(step.params, {})
        body = parse_json(step.body, {})
        req = f"{step.method} {step.url} params={params} body={body}"
        resp = (
            f"HTTP {step.result_status}\n{step.result_note}"
            if step.result_status
            else "no response"
        )
        return ArtifactStore(DATA_DIR).save_request_response(req, resp)
    except Exception:
        return ""
