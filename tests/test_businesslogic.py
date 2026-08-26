"""Business-logic test plan tests — generator fallback, executor gating + audit."""
from __future__ import annotations

import pytest

from bugbountybot.businesslogic.executor import execute_plan
from bugbountybot.businesslogic.generator import generate_plan
from bugbountybot.businesslogic.models import TestPlan as BLPlan
from bugbountybot.storage.audit import recent
from bugbountybot.storage.db import Finding
from bugbountybot.tracker.service import add_scope


@pytest.fixture()
def bl_program(session, program):
    add_scope(session, program.id, "acme.com", kind="domain")
    add_scope(session, program.id, "127.0.0.1", kind="ip")
    return program


def test_generate_plan_price_template(session, bl_program):
    plan = generate_plan(session, bl_program.id, category="price", target="http://127.0.0.1:9/cart")
    assert plan.category == "price"
    assert len(plan.steps) >= 3
    assert plan.status == "draft"
    assert all(s.url.startswith("http://127.0.0.1:9") for s in plan.steps)


def test_generate_plan_rejects_out_of_scope(session, bl_program):
    with pytest.raises(ValueError):
        generate_plan(session, bl_program.id, category="price", target="https://evil.com/cart")


def test_generate_plan_unknown_category(session, bl_program):
    with pytest.raises(ValueError):
        generate_plan(session, bl_program.id, category="nope", target="http://127.0.0.1:9/x")


def test_execute_plan_scope_blocks_out_of_scope(session, bl_program):
    # Build a plan whose steps point at an out-of-scope host.
    from bugbountybot.businesslogic.models import PlanStep

    plan = BLPlan(program_id=bl_program.id, title="bad", category="workflow", status="draft")
    session.add(plan)
    session.flush()
    session.add(PlanStep(plan_id=plan.id, order=0, method="GET", url="https://evil.com/x", params="{}", body="{}", headers="{}", expect="x"))
    session.commit()

    result = execute_plan(session, plan.id)
    assert result.blocked == 1
    assert result.executed == 0
    # audit logged the block
    assert any(not e.allowed for e in recent(session, 5))


def test_execute_plan_creates_candidate_on_success(session, bl_program):
    from bugbountybot.businesslogic.models import PlanStep

    plan = BLPlan(program_id=bl_program.id, title="price test", category="price", status="draft")
    session.add(plan)
    session.flush()
    # Step against a live local server that returns 200.
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    session.add(PlanStep(plan_id=plan.id, order=0, method="GET", url=f"{base}/cart", params="{}", body="{}", headers="{}", expect="negative price accepted?"))
    session.commit()

    result = execute_plan(session, plan.id)
    assert result.executed == 1
    assert result.interesting, "200 on a logic probe should be flagged as candidate"
    findings = session.query(Finding).filter(Finding.module == "business_logic").all()
    assert findings
    assert findings[0].status == "candidate"

    httpd.shutdown()
