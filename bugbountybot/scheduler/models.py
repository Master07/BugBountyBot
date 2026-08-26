"""Scheduler — scheduled re-recon and scope-change alerting.

A background loop re-runs recon per program on an interval, diffs the platform
scope for changes, and records alerts. The loop is process-local (started by
`bugbounty scheduled`); state (last run, alerts) persists in SQLite.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from bugbountybot.storage.db import Base


class ScheduledRun(Base):
    """Last re-recon state per program."""

    __tablename__ = "scheduled_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"), unique=True)
    last_run_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    last_hosts_found: Mapped[int] = mapped_column(Integer, default=0)
    last_endpoints_new: Mapped[int] = mapped_column(Integer, default=0)

    program = relationship("Program")


class Alert(Base):
    """Scope-change / recon alerts surfaced in the dashboard."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    kind: Mapped[str] = mapped_column(String(30), default="recon")  # new_asset|recon|scope_change
    message: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[DateTime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    read: Mapped[bool] = mapped_column(Boolean, default=False)

    program = relationship("Program")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
