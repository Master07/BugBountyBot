"""FastAPI server for the local web dashboard.

Binds to 127.0.0.1 only. Every endpoint goes through the same services the
CLI uses (tracker, scope guard, runner, reporter), so the UI and CLI share one
engine and one safety model. No auto-submit anywhere.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from bugbountybot.config.settings import DATA_DIR, PAYLOADS_DIR
from bugbountybot.oob.server import OOBServer
from bugbountybot.payloads.loader import PayloadLibrary
from bugbountybot.reporter.service import generate_report, program_stats
from bugbountybot.runner.service import MODULE_REGISTRY, ScopedRunner
from bugbountybot.scope.guard import ProgramScope
from bugbountybot.storage.artifacts import ArtifactStore
from bugbountybot.storage.audit import recent
from bugbountybot.storage.db import init_db
from bugbountybot.tracker import service as tracker


def _session():
    factory = init_db(DATA_DIR)
    return factory()


def _library() -> PayloadLibrary:
    return PayloadLibrary.from_directory(PAYLOADS_DIR)


def _artifacts() -> ArtifactStore:
    return ArtifactStore(DATA_DIR)


# ---- request models ----
class ProgramIn(BaseModel):
    name: str
    platform: str = ""
    url: str = ""
    notes: str = ""
    allowed_tiers: str = "1,2"


class ImportIn(BaseModel):
    platform: str
    handle: str = ""
    csv_file: str = ""
    program_name: str = ""


class ScopeIn(BaseModel):
    pattern: str
    kind: str = Field(default="domain", pattern="^(domain|wildcard|ip|cidr)$")
    in_scope: bool = True


class EndpointIn(BaseModel):
    url: str
    method: str = "GET"
    params: str = ""


class ScanIn(BaseModel):
    program: str
    target: str
    modules: str
    tier: int = 2
    confirm: bool = False
    oob_port: int = 0
    session_id: int = 0


class SessionIn(BaseModel):
    program: str
    name: str = "default"
    cookies: str = ""
    headers: str = ""


class ReportIn(BaseModel):
    program: str | None = None
    finding_ids: str = ""
    template: str = "markdown"


def _serialize_program(session, p) -> dict:
    scope = ProgramScope.load(session, p.id)
    return {
        "id": p.id,
        "name": p.name,
        "platform": p.platform,
        "url": p.url,
        "notes": p.notes,
        "allowed_tiers": sorted(scope.allowed_tiers()),
        "blocked_modules": sorted(scope.blocked_modules()),
        "rules": [
            {"pattern": r.pattern, "kind": r.kind, "in_scope": r.in_scope}
            for r in scope.rules
        ],
        "findings": len(tracker.list_findings(session, p.id)),
    }


def _serialize_finding(f) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "module": f.module,
        "cwe": f.cwe,
        "cvss": f.cvss,
        "severity": f.severity,
        "status": f.status,
        "url": f.url,
        "detail": f.detail,
        "payload_id": f.payload_id,
        "evidence": [{"kind": e.kind, "path": e.path} for e in f.evidence],
    }


@asynccontextmanager
async def _lifespan(app: FastAPI):
    yield


app = FastAPI(title="BugBounty Bot Pro", lifespan=_lifespan)


# ---- programs ----
@app.post("/api/import")
def api_import(body: ImportIn):
    """Import a program's scope from HackerOne/Bugcrowd or a CSV file."""
    from bugbountybot.importer.bugcrowd import import_bugcrowd
    from bugbountybot.importer.csv_import import import_csv
    from bugbountybot.importer.hackerone import import_hackerone
    from bugbountybot.importer.service import apply_import

    session = _session()
    try:
        if body.platform == "hackerone":
            if not body.handle:
                raise HTTPException(400, "handle required for hackerone")
            result = import_hackerone(body.handle)
        elif body.platform == "bugcrowd":
            if not body.handle:
                raise HTTPException(400, "handle required for bugcrowd")
            result = import_bugcrowd(body.handle)
        elif body.platform == "csv":
            if not body.csv_file:
                raise HTTPException(400, "csv_file required for csv")
            result = import_csv(body.csv_file, body.program_name)
        else:
            raise HTTPException(400, "platform must be hackerone|bugcrowd|csv")
    except RuntimeError as e:
        # e.g. HackerOne credentials not configured — give a clear 400, not a 500.
        raise HTTPException(400, str(e))

    if result.errors:
        raise HTTPException(502, "; ".join(result.errors))

    apply_import(session, result, program_name=body.program_name or None)
    return {
        "platform": result.platform,
        "handle": result.handle,
        "program_name": body.program_name or result.program_name,
        "rules_added": result.rules_added,
        "in_scope": result.in_scope,
        "out_of_scope": result.out_of_scope,
        "skipped": result.skipped,
    }


@app.get("/api/programs")
def api_programs():
    session = _session()
    return [_serialize_program(session, p) for p in tracker.list_programs(session)]


@app.post("/api/programs")
def api_program_create(body: ProgramIn):
    session = _session()
    if tracker.get_program(session, body.name):
        raise HTTPException(400, f"program {body.name!r} already exists")
    p = tracker.add_program(
        session,
        body.name,
        platform=body.platform,
        url=body.url,
        notes=body.notes,
        allowed_tiers=body.allowed_tiers,
    )
    return _serialize_program(session, p)


@app.post("/api/programs/{program_id}/scope")
def api_scope_add(program_id: int, body: ScopeIn):
    session = _session()
    p = session.get(tracker.Program, program_id)
    if not p:
        raise HTTPException(404, "program not found")
    tracker.add_scope(session, program_id, body.pattern, kind=body.kind, in_scope=body.in_scope)
    return _serialize_program(session, p)


@app.post("/api/programs/{program_id}/endpoints")
def api_endpoint_add(program_id: int, body: EndpointIn):
    session = _session()
    p = session.get(tracker.Program, program_id)
    if not p:
        raise HTTPException(404, "program not found")
    tracker.add_endpoint(session, program_id, url=body.url, method=body.method, params=body.params)
    return {"ok": True}


@app.get("/api/programs/{program_id}/endpoints")
def api_endpoints(program_id: int):
    session = _session()
    eps = tracker.list_endpoints(session, program_id)
    return [
        {"id": e.id, "url": e.url, "method": e.method, "params": e.params, "source": e.source}
        for e in eps
    ]


class ReconIn(BaseModel):
    tools: str = "subfinder,httpx,katana,gau"
    wordlist: str = ""


@app.post("/api/programs/{program_id}/recon")
def api_recon(program_id: int, body: ReconIn):
    """Trigger attack-surface discovery for a program. Scope-guarded."""
    from bugbountybot.recon.service import ReconService

    session = _session()
    p = session.get(tracker.Program, program_id)
    if not p:
        raise HTTPException(404, "program not found")
    svc = ReconService(session)
    tool_list = [t.strip() for t in body.tools.split(",") if t.strip()]
    result = svc.run(program_id, tools=tool_list, wordlist=body.wordlist)
    return {
        "hosts_discovered": len(result.hosts_discovered),
        "hosts_live": len(result.hosts_live),
        "endpoints_found": len(result.endpoints_found),
        "endpoints_new": len(result.endpoints_new),
        "blocked": len(result.blocked),
        "tool_stats": [
            {"tool": t.tool, "available": t.available, "found": t.found, "error": t.error}
            for t in result.tool_stats
        ],
    }


# ---- findings ----
@app.get("/api/findings")
def api_findings(program: str | None = None):
    session = _session()
    pid = None
    if program:
        p = tracker.get_program(session, program)
        if not p:
            raise HTTPException(404, "program not found")
        pid = p.id
    return [_serialize_finding(f) for f in tracker.list_findings(session, pid)]


@app.get("/api/findings/{finding_id}")
def api_finding(finding_id: int):
    session = _session()
    f = session.get(tracker.Finding, finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    return _serialize_finding(f)


class FindingUpdateIn(BaseModel):
    status: str = ""
    severity: str = ""


@app.patch("/api/findings/{finding_id}")
def api_finding_update(finding_id: int, body: FindingUpdateIn):
    """Update a finding's status/severity (candidate→confirmed→in_report→submitted...)."""
    session = _session()
    f = session.get(tracker.Finding, finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    if body.status:
        f.status = body.status
    if body.severity:
        f.severity = body.severity
    session.commit()
    return _serialize_finding(f)


@app.get("/api/evidence/{path:path}")
def api_evidence(path: str):
    """Serve a stored evidence artifact (request/response text)."""
    from fastapi.responses import PlainTextResponse

    try:
        content = _artifacts().read(path)
    except FileNotFoundError:
        raise HTTPException(404, "evidence not found")
    return PlainTextResponse(content.decode("utf-8", errors="replace"))


# ---- submissions ----
class SubmissionIn(BaseModel):
    program: str
    title: str


class SubmissionUpdateIn(BaseModel):
    status: str = ""
    payout: float | None = None


def _serialize_submission(s) -> dict:
    return {
        "id": s.id,
        "program_id": s.program_id,
        "title": s.title,
        "status": s.status,
        "payout": s.payout,
        "created_at": s.created_at.isoformat() if s.created_at else "",
    }


@app.get("/api/submissions")
def api_submissions(program: str | None = None):
    session = _session()
    pid = None
    if program:
        p = tracker.get_program(session, program)
        if not p:
            raise HTTPException(404, "program not found")
        pid = p.id
    return [_serialize_submission(s) for s in tracker.list_submissions(session, pid)]


@app.post("/api/submissions")
def api_submission_new(body: SubmissionIn):
    session = _session()
    p = tracker.get_program(session, body.program)
    if not p:
        raise HTTPException(404, f"program {body.program!r} not found")
    s = tracker.new_submission(session, p.id, body.title)
    return _serialize_submission(s)


@app.patch("/api/submissions/{submission_id}")
def api_submission_update(submission_id: int, body: SubmissionUpdateIn):
    session = _session()
    s = session.get(tracker.Submission, submission_id)
    if not s:
        raise HTTPException(404, "submission not found")
    if body.status:
        s.status = body.status
    if body.payout is not None:
        s.payout = body.payout
    session.commit()
    return _serialize_submission(s)


# ---- scan ----
@app.post("/api/scan")
def api_scan(body: ScanIn):
    session = _session()
    p = tracker.get_program(session, body.program)
    if not p:
        raise HTTPException(404, f"program {body.program!r} not found")
    lib = _library()
    artifacts = _artifacts()

    oob = None
    from bugbountybot.config.settings import OOB_BASE_URL
    from bugbountybot.oob.collaborator import CollaboratorClient

    if OOB_BASE_URL:
        # external collaborator — SSRF templates {{OOB}} with it, no local bind
        oob = CollaboratorClient(OOB_BASE_URL)
    elif body.oob_port:
        # Reuse the UI-managed listener if it's running on the same port,
        # otherwise start one for this scan.
        global _OOB
        if _OOB is not None and _OOB.running and _OOB.port == body.oob_port:
            oob = _OOB
        else:
            if _OOB is not None and _OOB.running:
                _OOB.stop()
            _OOB = OOBServer(port=body.oob_port, artifact_store=artifacts).start()
            oob = _OOB

    runner = ScopedRunner(
        session,
        program_id=p.id,
        library=lib,
        artifacts=artifacts,
        oob=oob,
        confirm=body.confirm,
        session_profile=_load_session(session, body.session_id),
    )
    module_list = [m.strip() for m in body.modules.split(",") if m.strip()]
    unknown = [m for m in module_list if m not in MODULE_REGISTRY]
    if unknown:
        if oob:
            oob.stop()
        raise HTTPException(400, f"unknown modules: {unknown}")

    results = []
    total_new = 0
    try:
        for m in module_list:
            run = runner.run_module(m, body.target, max_tier=body.tier)
            stored = runner.persist_findings(p.id, run)
            total_new += len(stored)
            results.append(
                {
                    "module": m,
                    "confirmed": len(run.findings),
                    "new": len(stored),
                    "blocked": run.blocked,
                    "findings": [_serialize_finding(f) for f in stored],
                }
            )
    finally:
        if oob:
            oob.stop()

    return {"program": body.program, "results": results, "total_new": total_new}


# ---- report ----
@app.post("/api/report")
def api_report(body: ReportIn):
    session = _session()
    ids = [int(x) for x in body.finding_ids.split(",") if x.strip()] or None
    pid = None
    if body.program:
        p = tracker.get_program(session, body.program)
        if not p:
            raise HTTPException(404, "program not found")
        pid = p.id
    text = generate_report(session, ids, template=body.template, program_id=pid)
    return {"report": text}


@app.get("/api/stats")
def api_stats(program: str):
    session = _session()
    p = tracker.get_program(session, program)
    if not p:
        raise HTTPException(404, "program not found")
    stats = program_stats(session, p.id)
    submissions = tracker.list_submissions(session, p.id)
    by_status: dict[str, int] = {}
    for s in submissions:
        by_status[s.status] = by_status.get(s.status, 0) + 1
    total_payout = sum(s.payout for s in submissions if s.payout)
    stats["submissions"] = len(submissions)
    stats["submissions_by_status"] = by_status
    stats["total_payout"] = total_payout
    return stats


@app.get("/api/triage")
def api_triage(program: str | None = None):
    """Rank a program's findings by triage priority (LLM or deterministic)."""
    from bugbountybot.agent.llm import LLMAdapter

    session = _session()
    pid = None
    if program:
        p = tracker.get_program(session, program)
        if not p:
            raise HTTPException(404, "program not found")
        pid = p.id
    findings = [
        {"title": f.title, "severity": f.severity, "module": f.module, "url": f.url}
        for f in tracker.list_findings(session, pid)
    ]
    ranking = LLMAdapter().triage_rank(findings)
    return {"count": len(findings), "ranking": ranking}


# ---- business logic plans ----
class LogicPlanIn(BaseModel):
    program: str
    category: str = "workflow"
    target: str = ""
    title: str = ""


@app.post("/api/logic/plan")
def api_logic_plan(body: LogicPlanIn):
    from bugbountybot.businesslogic.generator import generate_plan

    session = _session()
    p = tracker.get_program(session, body.program)
    if not p:
        raise HTTPException(404, f"program {body.program!r} not found")
    try:
        plan = generate_plan(session, p.id, category=body.category, target=body.target or None, title=body.title or None)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _serialize_plan(plan)


class LogicRunIn(BaseModel):
    parallel: bool = False


@app.post("/api/logic/plan/{plan_id}/run")
def api_logic_run(plan_id: int, body: LogicRunIn):
    from bugbountybot.businesslogic.executor import execute_plan

    session = _session()
    try:
        result = execute_plan(session, plan_id, parallel=body.parallel)
    except ValueError as e:
        raise HTTPException(404, str(e))
    return {
        "plan_id": result.plan_id,
        "executed": result.executed,
        "blocked": result.blocked,
        "findings_created": result.findings_created,
        "interesting": [
            {"url": s.url, "status": s.result_status, "note": s.result_note}
            for s in result.interesting
        ],
    }


@app.get("/api/logic/plans")
def api_logic_plans(program: str | None = None):
    from bugbountybot.businesslogic.models import TestPlan

    session = _session()
    q = session.query(TestPlan)
    if program:
        p = tracker.get_program(session, program)
        if not p:
            raise HTTPException(404, "program not found")
        q = q.filter(TestPlan.program_id == p.id)
    return [_serialize_plan(plan) for plan in q.order_by(TestPlan.id.desc()).all()]


def _serialize_plan(plan) -> dict:
    return {
        "id": plan.id,
        "program_id": plan.program_id,
        "title": plan.title,
        "category": plan.category,
        "description": plan.description,
        "status": plan.status,
        "steps": [
            {
                "id": s.id,
                "order": s.order,
                "method": s.method,
                "url": s.url,
                "expect": s.expect,
                "result_status": s.result_status,
                "result_note": s.result_note,
            }
            for s in plan.steps
        ],
    }


def _load_session(session, session_id: int):
    if not session_id:
        return None
    from bugbountybot.runner.session import get_session

    return get_session(session, session_id)


# ---- sessions ----
@app.get("/api/sessions")
def api_sessions(program: str | None = None):
    from bugbountybot.runner.session import list_sessions

    session = _session()
    pid = None
    if program:
        p = tracker.get_program(session, program)
        if not p:
            raise HTTPException(404, "program not found")
        pid = p.id
    return [
        {
            "id": sp.id,
            "program_id": sp.program_id,
            "name": sp.name,
        }
        for sp in list_sessions(session, pid)
    ]


@app.post("/api/sessions")
def api_session_add(body: SessionIn):
    from bugbountybot.runner.session import add_session

    session = _session()
    p = tracker.get_program(session, body.program)
    if not p:
        raise HTTPException(404, f"program {body.program!r} not found")
    sp = add_session(session, p.id, name=body.name, cookies=body.cookies, headers=body.headers)
    return {"id": sp.id, "program_id": sp.program_id, "name": sp.name}


# ---- nuclei ----
class NucleiIn(BaseModel):
    program: str
    target: str = ""
    recon: bool = False


@app.post("/api/nuclei")
def api_nuclei(body: NucleiIn):
    from bugbountybot.runner.nuclei import run_nuclei

    session = _session()
    p = tracker.get_program(session, body.program)
    if not p:
        raise HTTPException(404, f"program {body.program!r} not found")

    targets = []
    if body.target:
        targets = [body.target]
    elif body.recon:
        targets = [
            e.url for e in session.query(tracker.Endpoint).filter(tracker.Endpoint.program_id == p.id).all()
        ]
        targets = list(dict.fromkeys(targets))[:20]
    if not targets:
        raise HTTPException(400, "provide target or recon=true")

    results = []
    for t in targets:
        r = run_nuclei(session, p.id, t)
        results.append(
            {
                "target": t,
                "available": r.available,
                "error": r.error,
                "blocked": r.blocked,
                "matches": len(r.findings),
                "new": getattr(r, "findings_count", 0),
                "findings": [
                    {"template": f["template"], "name": f["name"], "severity": f["severity"], "matched": f["matched"]}
                    for f in r.findings[:20]
                ],
            }
        )
    return {"results": results}


# ---- scheduler / alerts ----
@app.get("/api/alerts")
def api_alerts(limit: int = 50):
    from bugbountybot.scheduler.service import list_alerts

    session = _session()
    return [
        {
            "id": a.id,
            "program_id": a.program_id,
            "kind": a.kind,
            "message": a.message,
            "detail": a.detail,
            "created_at": a.created_at.isoformat() if a.created_at else "",
            "read": a.read,
        }
        for a in list_alerts(session, limit)
    ]


@app.post("/api/alerts/read")
def api_alerts_read():
    from bugbountybot.scheduler.service import mark_alerts_read

    session = _session()
    mark_alerts_read(session)
    return {"ok": True}


@app.get("/api/scheduler/status")
def api_scheduler_status():
    from bugbountybot.scheduler.service import get_scheduled_run

    session = _session()
    runs = []
    for p in session.query(tracker.Program).all():
        row = get_scheduled_run(session, p.id)
        runs.append(
            {
                "program": p.name,
                "last_run_at": row.last_run_at.isoformat() if row and row.last_run_at else None,
                "last_hosts_found": row.last_hosts_found if row else 0,
                "last_endpoints_new": row.last_endpoints_new if row else 0,
            }
        )
    return {"programs": runs}


# ---- OOB listener (process-local singleton) ----
_OOB: OOBServer | None = None


class OOBStartIn(BaseModel):
    port: int = 8080


@app.get("/api/oob/status")
def api_oob_status():
    from bugbountybot.config.settings import OOB_BASE_URL

    if OOB_BASE_URL:
        return {"running": True, "base_url": OOB_BASE_URL, "collaborator": True}
    if _OOB is not None and _OOB.running:
        return {"running": True, "port": _OOB.port, "base_url": _OOB.base_url}
    return {"running": False}


@app.post("/api/oob/start")
def api_oob_start(body: OOBStartIn):
    global _OOB
    from bugbountybot.config.settings import OOB_BASE_URL

    if OOB_BASE_URL:
        # external collaborator configured — no local listener needed
        return {"running": True, "base_url": OOB_BASE_URL, "collaborator": True}
    if _OOB is not None and _OOB.running:
        return {"running": True, "port": _OOB.port, "base_url": _OOB.base_url}
    _OOB = OOBServer(port=body.port, artifact_store=_artifacts()).start()
    return {"running": True, "port": _OOB.port, "base_url": _OOB.base_url}


@app.post("/api/oob/stop")
def api_oob_stop():
    global _OOB
    if _OOB is not None and _OOB.running:
        _OOB.stop()
    _OOB = None
    return {"running": False}


# ---- payloads ----
@app.get("/api/payloads")
def api_payloads(category: str | None = None, max_tier: int = 2, search: str = ""):
    lib = _library()
    items = lib.by_category(category) if category else lib.all
    if search:
        items = [p for p in items if search.lower() in p.payload.lower()]
    items = [p for p in items if p.tier <= max_tier and p.enabled]
    return {
        "count": len(items),
        "payloads": [
            {"id": p.id, "category": p.category, "tier": p.tier, "payload": p.payload[:120]}
            for p in items[:200]
        ],
    }


@app.get("/api/meta")
def api_meta():
    return {"modules": sorted(MODULE_REGISTRY), "templates": ["markdown", "hackerone", "bugcrowd"]}


# ---- audit ----
@app.get("/api/audit")
def api_audit(limit: int = 50):
    session = _session()
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
            "url": e.url,
            "payload_hash": e.payload_hash,
            "tier": e.tier,
            "allowed": e.allowed,
            "reason": e.reason,
        }
        for e in recent(session, limit)
    ]


# ---- static UI ----
@app.get("/")
def api_index():
    ui = Path(__file__).resolve().parent / "static" / "index.html"
    return FileResponse(ui)


def run(host: str = "127.0.0.1", port: int = 8787):
    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="info")
