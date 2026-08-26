"""Typer CLI — the bugbounty command.

Grouped: program / submission / finding / scan / payloads / vuln / fuzz / oob /
report / audit / stats.
"""
from __future__ import annotations

from pathlib import Path

import typer
from sqlalchemy.orm import Session

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

app = typer.Typer(help="BugBounty Bot Pro — local, single-user bug bounty agent.")
program_app = typer.Typer(help="Program & bounty tracker.")
submission_app = typer.Typer(help="Submission lifecycle.")
finding_app = typer.Typer(help="Findings.")
scan_app = typer.Typer(help="Recon & discovery.")
payloads_app = typer.Typer(help="Payload management.")
vuln_app = typer.Typer(help="Vulnerability testing.")
oob_app = typer.Typer(help="Self-hosted OOB callback listener.")
report_app = typer.Typer(help="Report generation.")
audit_app = typer.Typer(help="Audit log (append-only).")

app.add_typer(program_app, name="program")
app.add_typer(submission_app, name="submission")
app.add_typer(finding_app, name="finding")
app.add_typer(scan_app, name="scan")
app.add_typer(payloads_app, name="payloads")
app.add_typer(vuln_app, name="vuln")
app.add_typer(oob_app, name="oob")
app.add_typer(report_app, name="report")
app.add_typer(audit_app, name="audit")


def _session() -> Session:
    factory = init_db(DATA_DIR)
    return factory()


def _library() -> PayloadLibrary:
    return PayloadLibrary.from_directory(PAYLOADS_DIR)


def _artifacts() -> ArtifactStore:
    return ArtifactStore(DATA_DIR)


def _require_program(session: Session, name: str):
    program = tracker.get_program(session, name)
    if program is None:
        raise typer.BadParameter(f"program {name!r} not found — add it first: bugbounty program add")
    return program


# ---------- program ----------
@program_app.command("add")
def program_add(
    name: str,
    platform: str = "",
    url: str = "",
    notes: str = "",
    allowed_tiers: str = "1,2",
):
    """Add a program with a default vuln policy."""
    session = _session()
    if tracker.get_program(session, name):
        raise typer.BadParameter(f"program {name!r} already exists")
    p = tracker.add_program(
        session, name, platform=platform, url=url, notes=notes, allowed_tiers=allowed_tiers
    )
    typer.echo(f"Added program {p.name!r} (id={p.id}) — allowed tiers {allowed_tiers}")


@program_app.command("list")
def program_list():
    session = _session()
    for p in tracker.list_programs(session):
        typer.echo(f"#{p.id} {p.name} ({p.platform or 'no platform'})")


@program_app.command("show")
def program_show(name: str):
    session = _session()
    p = _require_program(session, name)
    scope = ProgramScope.load(session, p.id)
    typer.echo(f"Program: {p.name} (id={p.id})")
    typer.echo(f"  URL: {p.url or '-'}")
    typer.echo(f"  Notes: {p.notes or '-'}")
    typer.echo(f"  Allowed tiers: {sorted(scope.allowed_tiers())}")
    typer.echo(f"  Blocked modules: {scope.blocked_modules() or 'none'}")
    typer.echo("  Scope rules:")
    for r in scope.rules:
        mark = "in" if r.in_scope else "OUT"
        typer.echo(f"    [{mark}] {r.kind}: {r.pattern}")


@program_app.command("add-scope")
def program_add_scope(
    name: str,
    pattern: str,
    kind: str = typer.Option("domain", help="domain|wildcard|ip|cidr"),
    out_of_scope: bool = typer.Option(False, "--out", help="mark as out-of-scope"),
):
    session = _session()
    p = _require_program(session, name)
    tracker.add_scope(session, p.id, pattern, kind=kind, in_scope=not out_of_scope)
    typer.echo(f"Added {'OUT-of-scope' if out_of_scope else 'in-scope'} rule {pattern!r} ({kind})")


@program_app.command("import")
def program_import(
    name: str,
    platform: str = typer.Option(..., "--platform", help="hackerone|bugcrowd|csv"),
    handle: str = typer.Option("", "--handle", help="program handle/code (hackerone/bugcrowd)"),
    csv_file: str = typer.Option("", "--csv", help="path to CSV (platform=csv)"),
    program_name: str = typer.Option("", "--program-name", help="override program name (default: handle)"),
):
    """Import a program's scope from HackerOne/Bugcrowd or a CSV file."""
    from bugbountybot.importer.bugcrowd import import_bugcrowd
    from bugbountybot.importer.csv_import import import_csv
    from bugbountybot.importer.hackerone import import_hackerone
    from bugbountybot.importer.service import apply_import

    session = _session()

    if platform == "hackerone":
        if not handle:
            raise typer.BadParameter("--handle required for hackerone")
        result = import_hackerone(handle)
    elif platform == "bugcrowd":
        if not handle:
            raise typer.BadParameter("--handle required for bugcrowd (program code)")
        result = import_bugcrowd(handle)
    elif platform == "csv":
        if not csv_file:
            raise typer.BadParameter("--csv required for platform=csv")
        result = import_csv(csv_file, program_name or name)
    else:
        raise typer.BadParameter("--platform must be hackerone|bugcrowd|csv")

    if result.errors:
        typer.echo("Import failed:")
        for err in result.errors:
            typer.echo(f"  ✗ {err}")
        raise typer.Exit(code=1)

    apply_import(session, result, program_name=program_name or None)
    typer.echo(
        f"Imported {result.platform} '{result.handle}': "
        f"{result.rules_added} scope rules added "
        f"({result.in_scope} in-scope, {result.out_of_scope} out-of-scope, {result.skipped} skipped)."
    )
    typer.echo(f"Program name: {program_name or result.program_name or name}")


@program_app.command("credentials")
def program_credentials(platform: str = typer.Option(..., "--platform", help="hackerone")):
    """Store platform API credentials in the system keychain."""
    if platform != "hackerone":
        raise typer.BadParameter("only hackerone credentials are supported")
    username = typer.prompt("HackerOne username")
    token = typer.prompt("HackerOne API token (Settings → API)", hide_input=True)
    from bugbountybot.importer.secrets import set_hackerone_credentials

    set_hackerone_credentials(username, token)
    typer.echo("Credentials stored in keychain.")


# ---------- submission ----------
@submission_app.command("new")
def submission_new(name: str, title: str):
    session = _session()
    p = _require_program(session, name)
    s = tracker.new_submission(session, p.id, title)
    typer.echo(f"Created submission #{s.id} [{s.status}] {s.title}")


@submission_app.command("list")
def submission_list(name: str):
    session = _session()
    p = _require_program(session, name)
    for s in tracker.list_submissions(session, p.id):
        typer.echo(f"#{s.id} [{s.status}] {s.title}")


@submission_app.command("update")
def submission_update(submission_id: int, status: str):
    session = _session()
    s = tracker.update_submission_status(session, submission_id, status)
    if not s:
        raise typer.BadParameter(f"no submission #{submission_id}")
    typer.echo(f"Submission #{s.id} → {s.status}")


# ---------- finding ----------
@finding_app.command("list")
def finding_list(name: str | None = typer.Option(None, "--program")):
    session = _session()
    program = tracker.get_program(session, name) if name else None
    for f in tracker.list_findings(session, program.id if program else None):
        typer.echo(f"#{f.id} [{f.severity:7}] {f.title} — {f.url} ({f.status})")


@finding_app.command("show")
def finding_show(finding_id: int):
    session = _session()
    f = session.get(tracker.Finding, finding_id)
    if not f:
        raise typer.BadParameter(f"no finding #{finding_id}")
    typer.echo(f"#{f.id} {f.title}")
    typer.echo(f"  module={f.module} cwe={f.cwe} cvss={f.cvss} severity={f.severity}")
    typer.echo(f"  url={f.url}")
    typer.echo(f"  payload_id={f.payload_id}")
    typer.echo(f"  detail={f.detail}")
    for ev in f.evidence:
        typer.echo(f"  evidence [{ev.kind}]: {ev.path}")


# ---------- scan ----------
@scan_app.command("discover")
def scan_discover(name: str, url: str, params: str = ""):
    """Manually add an endpoint + params to a program's inventory."""
    session = _session()
    p = _require_program(session, name)
    tracker.add_endpoint(session, p.id, url=url, params=params)
    typer.echo(f"Added endpoint {url} (params: {params or 'none'}) to {p.name!r}")


@scan_app.command("recon")
def scan_recon(
    name: str,
    tools: str = typer.Option("subfinder,httpx,katana,gau", "--tools"),
    wordlist: str = typer.Option("", "--wordlist"),
    limit: int = typer.Option(200, "--limit", help="max hosts to probe per run"),
):
    """Run attack-surface discovery (subdomains -> live hosts -> endpoints).

    Requires recon tools (subfinder/httpx/katana/gau/ffuf) on PATH or set via
    BUGBOUNTY_* env vars. Missing tools are skipped and reported.
    """
    from bugbountybot.recon.pipeline import run_recon as _run_recon
    from bugbountybot.scope.guard import ProgramScope

    session = _session()
    p = _require_program(session, name)
    tool_list = [t.strip() for t in tools.split(",") if t.strip()]
    scope = ProgramScope.load(session, p.id)
    result = _run_recon(session, p.id, tools=tool_list, wordlist=wordlist, scope=scope, max_hosts=limit)
    typer.echo(result.summary())
    for ep in result.endpoints_new:
        typer.echo(f"  + {ep.url} params={ep.params or '-'}")


@scan_app.command("list")
def scan_list(name: str, source: str = typer.Option("all", "--source", help="all|manual|recon")):
    """List a program's endpoint inventory."""
    from bugbountybot.recon.service import ReconService

    session = _session()
    p = _require_program(session, name)
    svc = ReconService(session)
    eps = svc.list_all_endpoints(p.id) if source == "all" else svc.list_recon_endpoints(p.id)
    if not eps:
        typer.echo("No endpoints.")
    for ep in eps:
        typer.echo(f"  [{ep.source}] {ep.method} {ep.url} params={ep.params or '-'}")


# ---------- payloads ----------
@payloads_app.command("list")
def payloads_list(category: str | None = None, max_tier: int = 2):
    lib = _library()
    items = lib.by_category(category) if category else lib.all
    items = [p for p in items if p.tier <= max_tier and p.enabled]
    typer.echo(f"{len(items)} payloads (tier ≤ {max_tier})")
    for p in items[:50]:
        typer.echo(f"  [{p.tier}] {p.id:32} {p.payload[:60]!r}")


@payloads_app.command("search")
def payloads_search(needle: str):
    lib = _library()
    for p in lib.search(needle)[:30]:
        typer.echo(f"  [{p.tier}] {p.id:32} {p.payload[:60]!r}")


@payloads_app.command("stats")
def payloads_stats():
    lib = _library()
    typer.echo(f"Total payloads: {lib.count()}")
    for cat in sorted({p.category for p in lib.all}):
        n = len(lib.by_category(cat))
        typer.echo(f"  {cat}: {n}")


# ---------- vuln ----------
@vuln_app.command("run")
def vuln_run(
    program: str = typer.Option(..., "--program", "-p", help="program name"),
    modules: str = typer.Option(..., "--modules", "-m", help="comma-separated modules"),
    target: str = typer.Option(..., "--target", "-t", help="target URL"),
    tier: int = typer.Option(2, "--tier"),
    confirm: bool = typer.Option(False, "--confirm", help="allow tier-3 exploit confirm"),
    oob_port: int = typer.Option(0, "--oob", help="start local OOB listener on this port"),
    session_id: int = typer.Option(0, "--session", help="session profile id (authenticated scan)"),
    session_b_id: int = typer.Option(0, "--session-b", help="second session id (2-session IDOR confirm)"),
):
    """Run vuln modules against a target within program scope."""
    session = _session()
    p = _require_program(session, program)
    lib = _library()
    artifacts = _artifacts()

    profile = None
    if session_id:
        from bugbountybot.runner.session import get_session

        profile = get_session(session, session_id)
        if profile is None:
            raise typer.BadParameter(f"no session #{session_id}")

    profile_b = None
    if session_b_id:
        from bugbountybot.runner.session import get_session

        profile_b = get_session(session, session_b_id)
        if profile_b is None:
            raise typer.BadParameter(f"no session #{session_b_id}")

    oob = None
    from bugbountybot.config.settings import OOB_BASE_URL
    from bugbountybot.oob.collaborator import CollaboratorClient

    if OOB_BASE_URL:
        oob = CollaboratorClient(OOB_BASE_URL)
        typer.echo(f"SSRF via external collaborator: {OOB_BASE_URL}")
    elif oob_port:
        oob = OOBServer(port=oob_port, artifact_store=artifacts).start()
        typer.echo(f"OOB listener on {oob.base_url}")

    runner = ScopedRunner(
        session,
        program_id=p.id,
        library=lib,
        artifacts=artifacts,
        oob=oob,
        confirm=confirm,
        session_profile=profile,
        session_b=profile_b,
    )

    module_list = [m.strip() for m in modules.split(",") if m.strip()]
    unknown = [m for m in module_list if m not in MODULE_REGISTRY]
    if unknown:
        if oob:
            oob.stop()
        raise typer.BadParameter(f"unknown modules: {unknown} (available: {', '.join(MODULE_REGISTRY)})")

    total_findings = 0
    for m in module_list:
        run = runner.run_module(m, target, max_tier=tier)
        stored = runner.persist_findings(p.id, run)
        total_findings += len(stored)
        typer.echo(f"[{m}] {len(run.findings)} confirmed, {len(stored)} new stored, {run.blocked} blocked")
        for f in stored:
            typer.echo(f"    -> #{f.id} {f.title} ({f.url})")

    if oob:
        oob.stop()
    typer.echo(f"Done. {total_findings} new findings stored.")


# ---------- oob ----------
@oob_app.command("start")
def oob_start(port: int = 8080):
    """Start the OOB callback listener (localhost only) or use the configured
    external collaborator. Ctrl-C to stop."""
    from bugbountybot.config.settings import OOB_BASE_URL

    artifacts = _artifacts()
    if OOB_BASE_URL:
        typer.echo(f"External collaborator configured: {OOB_BASE_URL} — no local listener needed.")
        typer.echo("SSRF payloads will template {{OOB}} with the collaborator URL.")
        return
    server = OOBServer(port=port, artifact_store=artifacts).start()
    typer.echo(f"OOB listener on {server.base_url} — callbacks logged to artifact store.")
    try:
        import time

        while server.running:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
        typer.echo("\nStopped.")


@oob_app.command("status")
def oob_status():
    from bugbountybot.config.settings import OOB_BASE_URL

    if OOB_BASE_URL:
        typer.echo(f"External collaborator: {OOB_BASE_URL} (SSRF uses it, no local listener)")
    else:
        typer.echo("OOB listener is process-local — run `bugbounty oob start` to launch one.")


# ---------- report ----------
@report_app.command("generate")
def report_generate(
    finding_ids: str = "",
    program: str | None = None,
    template: str = "markdown",
):
    session = _session()
    ids = [int(x) for x in finding_ids.split(",") if x.strip()] or None
    pid = None
    if program:
        p = _require_program(session, program)
        pid = p.id
    text = generate_report(session, ids, template=template, program_id=pid)
    typer.echo(text)


@report_app.command("stats")
def report_stats(program: str):
    session = _session()
    p = _require_program(session, program)
    stats = program_stats(session, p.id)
    typer.echo(f"Program: {stats['program']}")
    typer.echo(f"Findings: {stats['findings']}")
    for sev, n in sorted(stats["by_severity"].items()):
        typer.echo(f"  {sev}: {n}")


# ---------- serve ----------
@app.command("serve")
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8787, "--port"),
):
    """Start the local web dashboard (binds to localhost only)."""
    from bugbountybot.api.server import run

    typer.echo(f"Dashboard on http://{host}:{port} — Ctrl-C to stop.")
    run(host=host, port=port)


# ---------- scheduled ----------
@app.command("scheduled")
def scheduled(
    interval_hours: float = typer.Option(24.0, "--interval", help="hours between re-recon"),
    max_hosts: int = typer.Option(200, "--max-hosts"),
):
    """Run scheduled re-recon in the foreground (Ctrl-C to stop).

    Re-runs recon per program on the interval, records scope-change alerts,
    and surfaces new assets. Run it alongside `bugbounty serve`.
    """
    from bugbountybot.scheduler.service import ReconLoop
    from bugbountybot.storage.db import init_db as _init_db

    factory = _init_db(DATA_DIR)
    loop = ReconLoop(factory, interval_hours=interval_hours, max_hosts=max_hosts)
    typer.echo(f"Scheduled re-recon every {interval_hours}h (Ctrl-C to stop).")
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.stop()
        typer.echo("\nStopped.")


# ---------- session ----------
session_app = typer.Typer(help="Authenticated session profiles.")
app.add_typer(session_app, name="session")


@session_app.command("add")
def session_add(
    program: str,
    name: str = typer.Option("default", "--name"),
    cookies: str = typer.Option("", "--cookies", help='cookie string, e.g. "session=abc; user=1"'),
    headers: str = typer.Option("", "--headers", help='headers, e.g. "Authorization: Bearer xyz"'),
):
    """Store an authenticated session (cookies/headers) for scanning.

    Stored in the local DB only. Never exported in reports or the audit log.
    """
    from bugbountybot.runner.session import add_session

    session = _session()
    p = _require_program(session, program)
    profile = add_session(session, p.id, name=name, cookies=cookies, headers=headers)
    typer.echo(f"Session #{profile.id} '{profile.name}' saved for {p.name!r}")


@session_app.command("list")
def session_list(program: str | None = typer.Option(None, "--program")):
    from bugbountybot.runner.session import list_sessions

    session = _session()
    pid = None
    if program:
        p = _require_program(session, program)
        pid = p.id
    for sp in list_sessions(session, pid):
        from bugbountybot.runner.session import profile_cookies, profile_headers

        n_c = len(profile_cookies(sp))
        n_h = len(profile_headers(sp))
        typer.echo(f"#{sp.id} '{sp.name}' program={sp.program_id} cookies={n_c} headers={n_h}")


# ---------- nuclei ----------
@app.command("nuclei")
def nuclei_run(
    program: str = typer.Option(..., "--program", "-p", help="program name"),
    target: str = typer.Option("", "--target", help="in-scope target URL"),
    recon: bool = typer.Option(False, "--recon", help="scan all recon-discovered endpoints"),
    tags: str = typer.Option("", "--tags", help='nuclei template tags, e.g. "headers,exposure" (empty=all)'),
):
    """Run nuclei (community templates) against in-scope targets.

    Requires nuclei on PATH (brew install nuclei). Results stored as findings
    with template-id evidence.
    """
    from bugbountybot.runner.nuclei import run_nuclei
    from bugbountybot.scope.guard import ProgramScope
    from bugbountybot.storage.db import Endpoint

    session = _session()
    p = _require_program(session, program)

    targets = []
    if target:
        targets = [target]
    elif recon:
        targets = [e.url for e in session.query(Endpoint).filter(Endpoint.program_id == p.id).all()]
        targets = list(dict.fromkeys(targets))[:20]
    else:
        raise typer.BadParameter("provide --target or --recon")

    for t in targets:
        result = run_nuclei(session, p.id, t, tags=tags)
        if not result.available:
            typer.echo(f"[nuclei] unavailable: {result.error}")
            raise typer.Exit(code=1)
        if result.blocked:
            typer.echo(f"[nuclei] BLOCKED {t}: {result.error}")
            continue
        n = getattr(result, "findings_count", 0)
        typer.echo(f"[nuclei] {t}: {len(result.findings)} matches, {n} new stored")
        for f in result.findings[:10]:
            typer.echo(f"    [{f['severity']:8}] {f['template']} — {f['name'][:60]}")
        if result.error:
            typer.echo(f"    err: {result.error[:120]}")


# ---------- benchmark ----------
@app.command("benchmark")
def benchmark():
    """Measure per-module precision/recall/FP-rate against labeled fixtures.

    Any module above the 20% FP budget (W1) fails the run — the honest
    credibility number for the detection suite.
    """
    from benchmark.run import run_benchmark, verify, FP_BUDGET

    typer.echo("Running benchmark against labeled fixture targets…")
    result = run_benchmark()
    typer.echo(result.summary_table())
    ok = verify(result)
    typer.echo("")
    if ok:
        typer.echo(f"All modules within FP budget (≤{FP_BUDGET:.0%}) and recall floor. ✅")
    else:
        typer.echo(f"FAIL: modules above FP budget or below recall floor: {result.failed_modules}")
        raise typer.Exit(code=1)


# ---------- backup ----------
@app.command("backup")
def backup():
    """Back up data/ (DB + artifacts + imports) to a timestamped folder.

    Target: data/backups/<timestamp>/ by default, or BUGBOUNTY_BACKUP_DIR.
    """
    import shutil
    from datetime import datetime

    from bugbountybot.config.settings import BACKUP_DIR, get_settings

    src = get_settings().data_dir
    if not src.exists():
        typer.echo(f"Nothing to back up — {src} does not exist.")
        return
    base = Path(BACKUP_DIR) if BACKUP_DIR else src / "backups"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = base / stamp
    dest.mkdir(parents=True, exist_ok=True)

    # copy DB, artifacts, imports (skip the backups dir itself)
    for item in src.iterdir():
        if item.name == "backups":
            continue
        target = dest / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True)
        else:
            shutil.copy2(item, target)
    typer.echo(f"Backup created: {dest}")


# ---------- logic ----------
logic_app = typer.Typer(help="Business-logic test plans.")
app.add_typer(logic_app, name="logic")


@logic_app.command("plan")
def logic_plan(
    program: str,
    category: str = typer.Option("workflow", "--category", help="price|workflow|priv|race|idor"),
    target: str = typer.Option("", "--target", help="in-scope target URL (default: first endpoint)"),
    title: str = typer.Option("", "--title"),
):
    """Generate a business-logic test plan (LLM-guided or template)."""
    from bugbountybot.businesslogic.generator import generate_plan

    session = _session()
    p = _require_program(session, program)
    plan = generate_plan(session, p.id, category=category, target=target or None, title=title or None)
    typer.echo(f"Plan #{plan.id} [{plan.category}] {plan.title}")
    for s in plan.steps:
        typer.echo(f"  {s.order + 1}. {s.method} {s.url}  — {s.expect}")
    typer.echo(f"Run it: bugbounty logic run {plan.id}")


@logic_app.command("run")
def logic_run(plan_id: int, parallel: bool = typer.Option(False, "--parallel", help="fire steps concurrently (race)")):
    """Execute a test plan (scope-gated, audit-logged)."""
    from bugbountybot.businesslogic.executor import execute_plan

    session = _session()
    result = execute_plan(session, plan_id, parallel=parallel)
    typer.echo(f"Plan #{result.plan_id}: {result.executed} executed, {result.blocked} blocked, {result.findings_created} candidate finding(s)")
    for s in result.interesting:
        typer.echo(f"  ! {s.url} -> {s.result_status} ({s.result_note})")


@logic_app.command("list")
def logic_list(program: str | None = typer.Option(None, "--program")):
    from bugbountybot.businesslogic.models import TestPlan

    session = _session()
    q = session.query(TestPlan)
    if program:
        p = _require_program(session, program)
        q = q.filter(TestPlan.program_id == p.id)
    for plan in q.order_by(TestPlan.id.desc()).all():
        typer.echo(f"#{plan.id} [{plan.status}] {plan.category:10} {plan.title}")


# ---------- audit ----------
@audit_app.command("recent")
def audit_recent(limit: int = 20):
    session = _session()
    for entry in recent(session, limit):
        flag = "ALLOW" if entry.allowed else "BLOCK"
        typer.echo(
            f"[{flag}] t{entry.tier} {entry.url} hash={entry.payload_hash[:8]} "
            f"reason={entry.reason or '-'}"
        )


def main():
    app()


if __name__ == "__main__":
    main()
