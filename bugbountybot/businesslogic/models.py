"""Business-logic test plans — SQLite models."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from bugbountybot.storage.db import Base

CATEGORIES = ("price", "workflow", "priv", "race", "idor", "auth", "cart", "signup", "coupon")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TestPlan(Base):
    __tablename__ = "test_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    title: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(30), default="workflow")
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="draft")  # draft|executed
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[DateTime] = mapped_column(DateTime, default=_now)

    program = relationship("Program")
    steps: Mapped[list["PlanStep"]] = relationship(
        back_populates="plan", cascade="all, delete-orphan", order_by="PlanStep.order"
    )


class PlanStep(Base):
    __tablename__ = "plan_steps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("test_plans.id"))
    order: Mapped[int] = mapped_column(Integer, default=0)
    method: Mapped[str] = mapped_column(String(10), default="GET")
    url: Mapped[str] = mapped_column(Text)
    params: Mapped[str] = mapped_column(Text, default="{}")  # JSON
    body: Mapped[str] = mapped_column(Text, default="{}")  # JSON
    headers: Mapped[str] = mapped_column(Text, default="{}")  # JSON
    expect: Mapped[str] = mapped_column(Text, default="")
    result_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    result_note: Mapped[str] = mapped_column(Text, default="")

    plan: Mapped[TestPlan] = relationship(back_populates="steps")


def parse_json(value: str, default) -> dict:
    try:
        return json.loads(value) if value else default
    except json.JSONDecodeError:
        return default


def dumps_json(value: dict) -> str:
    return json.dumps(value)
