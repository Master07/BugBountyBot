"""SQLite schema + session handling. Source of truth lives under data/ (gitignored)."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
    func,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


class Base(DeclarativeBase):
    pass


# ---- Audit log ----
class AuditEntry(Base):
    """Append-only log of every request. Never update or delete rows."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    url: Mapped[str] = mapped_column(Text)
    payload_hash: Mapped[str] = mapped_column(String(64), default="")
    tier: Mapped[int] = mapped_column(Integer, default=1)
    scope_snapshot: Mapped[str] = mapped_column(Text, default="")
    allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    reason: Mapped[str] = mapped_column(Text, default="")


# ---- Tracker ----
class Program(Base):
    __tablename__ = "programs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    platform: Mapped[str] = mapped_column(String(50), default="")
    url: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())

    scope_rules: Mapped[list["ScopeRule"]] = relationship(
        back_populates="program", cascade="all, delete-orphan"
    )
    vuln_policy: Mapped["VulnPolicy"] = relationship(
        back_populates="program", cascade="all, delete-orphan", uselist=False
    )
    submissions: Mapped[list["Submission"]] = relationship(
        back_populates="program", cascade="all, delete-orphan"
    )


class ScopeRule(Base):
    __tablename__ = "scope_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    pattern: Mapped[str] = mapped_column(Text)  # domain, wildcard, IP, CIDR
    kind: Mapped[str] = mapped_column(String(20), default="domain")  # domain|ip|cidr|wildcard
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)

    program: Mapped[Program] = relationship(back_populates="scope_rules")


class VulnPolicy(Base):
    __tablename__ = "vuln_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    allowed_tiers: Mapped[str] = mapped_column(String(50), default="1,2")  # e.g. "1,2,3"
    blocked_modules: Mapped[str] = mapped_column(Text, default="")  # comma-separated
    max_rate: Mapped[int] = mapped_column(Integer, default=5)  # req/sec

    program: Mapped[Program] = relationship(back_populates="vuln_policy")


class Submission(Base):
    __tablename__ = "submissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(30), default="draft")
    # draft -> submitted -> triaged -> accepted|rejected -> paid
    payout: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())

    program: Mapped[Program] = relationship(back_populates="submissions")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="submission", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    submission_id: Mapped[int | None] = mapped_column(
        ForeignKey("submissions.id"), nullable=True
    )
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    title: Mapped[str] = mapped_column(String(300))
    module: Mapped[str] = mapped_column(String(50), default="")
    cwe: Mapped[str] = mapped_column(String(20), default="")
    cvss: Mapped[str] = mapped_column(String(50), default="")  # CVSS 3.1 vector
    severity: Mapped[str] = mapped_column(String(20), default="info")
    status: Mapped[str] = mapped_column(String(30), default="candidate")
    # candidate -> confirmed -> in_report -> submitted -> accepted/rejected
    url: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    payload_id: Mapped[str] = mapped_column(String(100), default="")
    dedup_key: Mapped[str] = mapped_column(String(100), default="", index=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())

    submission: Mapped[Submission | None] = relationship(back_populates="findings")
    program: Mapped[Program] = relationship()
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    kind: Mapped[str] = mapped_column(String(30), default="request_response")
    # request_response | oob_callback | screenshot | note
    path: Mapped[str] = mapped_column(Text, default="")  # relative to data/artifacts/
    summary: Mapped[str] = mapped_column(Text, default="")

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class Endpoint(Base):
    """Inventory from recon/discovery — params and endpoints stored here."""

    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    url: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(String(10), default="GET")
    params: Mapped[str] = mapped_column(Text, default="")  # comma-separated
    source: Mapped[str] = mapped_column(String(30), default="manual")
    found_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())


class ScanRun(Base):
    """Record of every scan run — target, modules, results, timestamp.

    status: running|completed|failed — a mid-scan failure is recorded, never
    silently dropped. Partial results are persisted before failure is marked.
    """

    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    target: Mapped[str] = mapped_column(Text)
    modules: Mapped[str] = mapped_column(String(200), default="")
    tier: Mapped[int] = mapped_column(Integer, default=2)
    confirm: Mapped[bool] = mapped_column(Boolean, default=False)
    findings_created: Mapped[int] = mapped_column(Integer, default=0)
    blocked: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="completed")  # running|completed|failed
    error: Mapped[str] = mapped_column(Text, default="")
    ran_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())


class SessionProfile(Base):
    """Authenticated session (cookies + headers) for scanning. Local-only."""

    __tablename__ = "session_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    name: Mapped[str] = mapped_column(String(100), default="default")
    cookies_json: Mapped[str] = mapped_column(Text, default="{}")
    headers_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())


def _enable_fk(engine):
    """SQLite pragmas on every connection: FK enforcement + busy timeout.

    journal_mode=WAL is set once at engine init (it's a DB-file property, not
    per-connection). busy_timeout + synchronous run per-connection.
    """
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


def init_db(data_dir: str | Path) -> sessionmaker:
    """Create the DB file + schema and return a session factory."""
    # ensure all sub-package models register on the shared Base before create_all
    import bugbountybot.businesslogic.models  # noqa: F401
    import bugbountybot.scheduler.models  # noqa: F401

    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{data_dir / 'bugbounty.db'}",
        connect_args={"check_same_thread": False},
    )
    _enable_fk(engine)
    # WAL is a DB-file setting — set it once on a dedicated connection.
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL"))
    Base.metadata.create_all(engine)
    _migrate(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    return factory


def _migrate(engine):
    """Lightweight additive migrations for pre-existing DBs (create_all doesn't
    alter existing tables). Add columns that newer code expects."""
    from sqlalchemy import inspect, text as _text

    insp = inspect(engine)
    with engine.begin() as conn:
        # scan_runs.status/error (crash-safe runs)
        if insp.has_table("scan_runs"):
            cols = {c["name"] for c in insp.get_columns("scan_runs")}
            if "status" not in cols:
                conn.execute(_text("ALTER TABLE scan_runs ADD COLUMN status VARCHAR(20) DEFAULT 'completed'"))
            if "error" not in cols:
                conn.execute(_text("ALTER TABLE scan_runs ADD COLUMN error TEXT DEFAULT ''"))
        # test_plans.findings_count (business-logic observability)
        if insp.has_table("test_plans"):
            cols = {c["name"] for c in insp.get_columns("test_plans")}
            if "findings_count" not in cols:
                conn.execute(_text("ALTER TABLE test_plans ADD COLUMN findings_count INTEGER DEFAULT 0"))


def with_retry(fn, *, attempts: int = 3, base_delay: float = 0.2):
    """Run fn, retrying on SQLite 'database is locked' with backoff.

    WAL + busy_timeout handle most contention; this catches the rest so a
    concurrent write from the dashboard/scheduler never kills a scan.
    """
    import time

    from sqlalchemy.exc import OperationalError

    for i in range(attempts):
        try:
            return fn()
        except OperationalError as e:
            if "locked" not in str(e).lower() or i == attempts - 1:
                raise
            time.sleep(base_delay * (2 ** i))


# Default data dir for CLI use.
DEFAULT_DATA_DIR = Path("data")
