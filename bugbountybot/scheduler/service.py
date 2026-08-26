"""Scheduler service — runs the recon loop and records alerts."""
from __future__ import annotations

import time
import traceback
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from bugbountybot.recon.pipeline import run_recon
from bugbountybot.scheduler.models import Alert, ScheduledRun, now_utc
from bugbountybot.scope.guard import ProgramScope
from bugbountybot.storage.db import Program


def get_scheduled_run(session: Session, program_id: int) -> ScheduledRun | None:
    return (
        session.query(ScheduledRun).filter(ScheduledRun.program_id == program_id).first()
    )


def add_alert(session: Session, program_id: int, kind: str, message: str, detail: str = "") -> Alert:
    alert = Alert(program_id=program_id, kind=kind, message=message, detail=detail)
    session.add(alert)
    session.commit()
    return alert


def list_alerts(session: Session, limit: int = 50) -> list[Alert]:
    return session.query(Alert).order_by(Alert.id.desc()).limit(limit).all()


def mark_alerts_read(session: Session):
    session.query(Alert).filter(Alert.read.is_(False)).update({"read": True})
    session.commit()


def run_scheduled_recon(session: Session, program_id: int, max_hosts: int = 200) -> dict:
    """Run recon for one program on schedule. Returns a summary dict."""
    scope = ProgramScope.load(session, program_id)
    try:
        result = run_recon(session, program_id, scope=scope, max_hosts=max_hosts)
    except Exception as e:  # never let a recon failure kill the loop
        traceback.print_exc()
        add_alert(session, program_id, "recon", f"Recon failed: {e}", str(e))
        return {"error": str(e), "new": 0}

    row = get_scheduled_run(session, program_id)
    if row is None:
        row = ScheduledRun(program_id=program_id)
        session.add(row)
    row.last_run_at = now_utc()
    row.last_hosts_found = len(result.hosts_discovered)
    row.last_endpoints_new = len(result.endpoints_new)
    session.commit()

    if result.endpoints_new:
        hosts = ", ".join(e.url for e in result.endpoints_new[:5])
        add_alert(
            session, program_id, "new_asset",
            f"{len(result.endpoints_new)} new endpoint(s) discovered",
            hosts,
        )
    return {
        "hosts": len(result.hosts_discovered),
        "live": len(result.hosts_live),
        "new_endpoints": len(result.endpoints_new),
        "blocked": len(result.blocked),
    }


class ReconLoop:
    """Background loop: re-recon every program at an interval (hours)."""

    def __init__(self, session_factory, interval_hours: float = 24.0, max_hosts: int = 200):
        self.session_factory = session_factory
        self.interval = timedelta(hours=interval_hours)
        self.max_hosts = max_hosts
        self._stop = False

    def _due(self, session: Session, program_id: int) -> bool:
        row = get_scheduled_run(session, program_id)
        if row is None or row.last_run_at is None:
            return True
        last = row.last_run_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return now_utc() - last >= self.interval

    def tick_once(self) -> list[dict]:
        """Run recon for all due programs. Returns per-program summaries."""
        session = self.session_factory()
        summaries: list[dict] = []
        try:
            programs = session.query(Program).all()
            for p in programs:
                if self._stop:
                    break
                if not self._due(session, p.id):
                    continue
                summary = run_scheduled_recon(session, p.id, max_hosts=self.max_hosts)
                summary["program"] = p.name
                summaries.append(summary)
        finally:
            session.close()
        return summaries

    def run_forever(self, check_every_seconds: int = 60):
        """Blocking loop; call from a thread or `bugbounty scheduled`."""
        while not self._stop:
            self.tick_once()
            # sleep in slices so stop() is responsive
            for _ in range(max(1, check_every_seconds // 5)):
                if self._stop:
                    return
                time.sleep(5)

    def stop(self):
        self._stop = True
