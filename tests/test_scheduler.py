"""Scheduler tests — scheduled recon, alerts, and the recon loop."""
from __future__ import annotations

from datetime import timedelta

import pytest

from bugbountybot.scheduler.models import Alert, ScheduledRun, now_utc
from bugbountybot.scheduler.service import (
    ReconLoop,
    add_alert,
    get_scheduled_run,
    list_alerts,
    mark_alerts_read,
    run_scheduled_recon,
)
from bugbountybot.tracker.service import add_scope


@pytest.fixture()
def recon_program(session, program):
    add_scope(session, program.id, "acme.com", kind="domain")
    add_scope(session, program.id, "*.acme.com", kind="wildcard")
    return program


def test_scheduled_recon_records_run(session, recon_program, monkeypatch):
    from bugbountybot.recon.adapters import ToolResult

    monkeypatch.setattr("bugbountybot.scheduler.service.run_recon", lambda *a, **k: _fake_recon())
    summary = run_scheduled_recon(session, recon_program.id)
    assert summary["new_endpoints"] == 1
    row = get_scheduled_run(session, recon_program.id)
    assert row is not None
    assert row.last_hosts_found == 2


def test_scheduled_recon_creates_alert_on_new_assets(session, recon_program, monkeypatch):
    monkeypatch.setattr("bugbountybot.scheduler.service.run_recon", lambda *a, **k: _fake_recon())
    run_scheduled_recon(session, recon_program.id)
    alerts = list_alerts(session)
    assert any(a.kind == "new_asset" for a in alerts)


def test_scheduled_recon_handles_failure(session, recon_program, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr("bugbountybot.scheduler.service.run_recon", boom)
    summary = run_scheduled_recon(session, recon_program.id)
    assert "error" in summary
    assert any(a.kind == "recon" for a in list_alerts(session))


def test_alerts_read_marking(session, recon_program):
    add_alert(session, recon_program.id, "recon", "hello")
    assert list_alerts(session)[0].read is False
    mark_alerts_read(session)
    assert list_alerts(session)[0].read is True


def test_recon_loop_due_logic(session, recon_program):
    factory = session.get_bind()
    loop = ReconLoop(lambda: session, interval_hours=24)

    # fresh program: due
    assert loop._due(session, recon_program.id) is True

    # just ran: not due
    run = ScheduledRun(program_id=recon_program.id, last_run_at=now_utc())
    session.add(run)
    session.commit()
    assert loop._due(session, recon_program.id) is False

    # ran 25h ago: due
    run.last_run_at = now_utc() - timedelta(hours=25)
    session.commit()
    assert loop._due(session, recon_program.id) is True


def _fake_recon():
    class _R:
        hosts_discovered = ["a.acme.com", "b.acme.com"]
        hosts_live = ["http://a.acme.com"]
        endpoints_new = [_FakeEndpoint()]
        blocked = []

    return _R()


class _FakeEndpoint:
    url = "http://a.acme.com/search"
