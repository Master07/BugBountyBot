"""Nuclei integration — breadth via the community template library.

Runs `nuclei` as a subprocess (like the recon tools), parses JSONL output into
findings, scope-gates the target, and records a scan run. Missing binary is
reported, not fatal.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from bugbountybot.config.settings import DATA_DIR
from bugbountybot.scope.guard import ProgramScope, ScopeGuard
from bugbountybot.storage.audit import log_request
from bugbountybot.storage.db import Endpoint, Finding
from bugbountybot.tracker.service import add_evidence, add_finding

# nuclei severity -> tool severity
_SEV_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


@dataclass
class NucleiResult:
    target: str
    findings: list[dict] = field(default_factory=list)
    blocked: int = 0
    error: str = ""
    available: bool = True


def _run_nuclei(
    target: str,
    timeout: int = 240,
    tags: str = "",
    rate_limit: int = 50,
    concurrency: int = 10,
) -> tuple[int, str, str]:
    """Run nuclei against a target; returns (returncode, stdout, stderr).

    Rate-limited and concurrency-capped. `tags` limits to a template tag set
    (e.g. 'headers,exposure,misconfig') for faster runs; empty = all templates.
    Heavy tags (fuzz/brute/dos) are always excluded.
    """
    binary = shutil.which("nuclei")
    if not binary:
        return -1, "", "nuclei binary not found"
    cmd = [
        binary,
        "-u", target,
        "-jsonl",
        "-silent",
        "-timeout", "10",
        "-rate-limit", str(rate_limit),
        "-c", str(concurrency),
        "-etags", "fuzz,brute,dos,http-fuzz",
    ]
    if tags:
        cmd += ["-tags", tags]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _parse_jsonl(stdout: str) -> list[dict]:
    findings: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append(
            {
                "template": rec.get("template-id", ""),
                "name": rec.get("info", {}).get("name", ""),
                "severity": _SEV_MAP.get(rec.get("info", {}).get("severity", "unknown"), "info"),
                "matched": rec.get("matched-at", ""),
                "matcher": rec.get("matcher-name", ""),
                "type": rec.get("type", ""),
            }
        )
    return findings


def run_nuclei(session: Session, program_id: int, target: str, *, tags: str = "", rate: float = 5.0) -> NucleiResult:
    """Run nuclei against one in-scope target and store findings."""
    result = NucleiResult(target=target)
    scope = ProgramScope.load(session, program_id)
    guard = ScopeGuard(scope)
    snapshot = f"program={program_id}"

    decision = guard.check(target, tier=2)
    log_request(
        session, url=target, tier=2,
        scope_snapshot=snapshot, allowed=decision.allowed, reason=decision.reason,
    )
    if not decision.allowed:
        result.blocked = 1
        result.error = decision.reason
        return result

    # rate limit before the run (shared per-host bucket)
    from bugbountybot.runner.ratelimit import RateLimiter

    limiter = RateLimiter(rate=rate)
    allowed, _reason = limiter.before_request(target, timeout=60)
    if not allowed:
        result.blocked = 1
        result.error = "rate-limited"
        return result

    rc, stdout, stderr = _run_nuclei(target, tags=tags)
    if rc == -1:
        result.available = False
        result.error = stderr
        return result
    if rc != 0 and not stdout:
        result.error = stderr.strip()[:200]
        return result

    result.findings = _parse_jsonl(stdout)
    _store_findings(session, program_id, result)
    return result


def _store_findings(session: Session, program_id: int, result: NucleiResult):
    existing = {
        f.dedup_key
        for f in session.query(Finding).filter(Finding.program_id == program_id).all()
    }
    from bugbountybot.storage.db import ScanRun

    for f in result.findings:
        dedup = f"nuclei:{f['template']}:{f['matched']}"
        if dedup in existing:
            continue
        finding = add_finding(
            session,
            program_id=program_id,
            submission_id=None,
            title=f"{f['name'] or f['template']} ({f['type']})",
            module=f"nuclei/{f['template']}",
            cwe="",
            severity=f["severity"],
            url=f["matched"] or result.target,
            detail=f"Nuclei template {f['template']} matched at {f['matched']} (matcher: {f['matcher']}).",
            status="confirmed",
            dedup_key=dedup,
        )
        _save_evidence(session, finding.id, f)
        existing.add(dedup)
        result.findings_count = getattr(result, "findings_count", 0) + 1

    session.add(
        ScanRun(
            program_id=program_id,
            target=result.target,
            modules=f"nuclei",
            tier=2,
            findings_created=getattr(result, "findings_count", 0),
        )
    )
    session.commit()


def _save_evidence(session: Session, finding_id: int, f: dict):
    try:
        from bugbountybot.storage.artifacts import ArtifactStore

        text = (
            f"Template: {f['template']}\n"
            f"Name: {f['name']}\n"
            f"Severity: {f['severity']}\n"
            f"Matched: {f['matched']}\n"
            f"Matcher: {f['matcher']}\n"
            f"Type: {f['type']}"
        )
        rel = ArtifactStore(DATA_DIR).save_text(text, suffix=".nuclei")
        add_evidence(session, finding_id, kind="nuclei", path=rel, summary=f['template'])
    except Exception:
        pass
