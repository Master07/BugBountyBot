"""Program & Bounty Tracker — program/submission/finding CRUD + scope + policy.

All data lives in SQLite via SQLAlchemy. Secrets never touch these tables.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from bugbountybot.scope.guard import add_scope_rule
from bugbountybot.storage.db import (
    Endpoint,
    Evidence,
    Finding,
    Program,
    Submission,
    VulnPolicy,
)


# ---- Programs ----
def add_program(
    session: Session,
    name: str,
    *,
    platform: str = "",
    url: str = "",
    notes: str = "",
    allowed_tiers: str = "1,2",
    blocked_modules: str = "",
    max_rate: int = 5,
) -> Program:
    program = Program(name=name, platform=platform, url=url, notes=notes)
    session.add(program)
    session.flush()
    session.add(
        VulnPolicy(
            program_id=program.id,
            allowed_tiers=allowed_tiers,
            blocked_modules=blocked_modules,
            max_rate=max_rate,
        )
    )
    session.commit()
    return program


def list_programs(session: Session) -> list[Program]:
    return session.query(Program).order_by(Program.name).all()


def get_program(session: Session, name: str) -> Program | None:
    return session.query(Program).filter(Program.name == name).first()


def add_scope(
    session: Session, program_id: int, pattern: str, kind: str = "domain", in_scope: bool = True
):
    return add_scope_rule(session, program_id, pattern, kind, in_scope=in_scope)


# ---- Submissions ----
def new_submission(session: Session, program_id: int, title: str) -> Submission:
    sub = Submission(program_id=program_id, title=title)
    session.add(sub)
    session.commit()
    return sub


def list_submissions(session: Session, program_id: int | None = None) -> list[Submission]:
    q = session.query(Submission)
    if program_id is not None:
        q = q.filter(Submission.program_id == program_id)
    return q.order_by(Submission.id.desc()).all()


def update_submission_status(session: Session, submission_id: int, status: str) -> Submission | None:
    sub = session.get(Submission, submission_id)
    if sub:
        sub.status = status
        session.commit()
    return sub


# ---- Findings ----
def add_finding(
    session: Session,
    *,
    program_id: int,
    submission_id: int | None,
    title: str,
    module: str = "",
    cwe: str = "",
    cvss: str = "",
    severity: str = "info",
    url: str = "",
    detail: str = "",
    payload_id: str = "",
    dedup_key: str = "",
    status: str = "candidate",
) -> Finding:
    finding = Finding(
        program_id=program_id,
        submission_id=submission_id,
        title=title,
        module=module,
        cwe=cwe,
        cvss=cvss,
        severity=severity,
        url=url,
        detail=detail,
        payload_id=payload_id,
        dedup_key=dedup_key,
        status=status,
    )
    session.add(finding)
    session.commit()
    return finding


def list_findings(session: Session, program_id: int | None = None) -> list[Finding]:
    q = session.query(Finding)
    if program_id is not None:
        q = q.filter(Finding.program_id == program_id)
    return q.order_by(Finding.id.desc()).all()


def add_evidence(session: Session, finding_id: int, kind: str, path: str, summary: str = "") -> Evidence:
    ev = Evidence(finding_id=finding_id, kind=kind, path=path, summary=summary)
    session.add(ev)
    session.commit()
    return ev


def add_endpoint(session: Session, program_id: int, url: str, method: str = "GET", params: str = "") -> Endpoint:
    ep = Endpoint(program_id=program_id, url=url, method=method, params=params, source="manual")
    session.add(ep)
    session.commit()
    return ep


def list_endpoints(session: Session, program_id: int) -> list[Endpoint]:
    return (
        session.query(Endpoint).filter(Endpoint.program_id == program_id).order_by(Endpoint.id).all()
    )
