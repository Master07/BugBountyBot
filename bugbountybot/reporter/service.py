"""Report Generator — turns confirmed findings into submission-ready drafts.

Drafts only. Never auto-submits. Strips internal payload DB IDs and artifact
paths from the export; evidence is attached as sanitized request/response text.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from bugbountybot.storage.db import Finding, Program

TEMPLATES = ("markdown", "hackerone", "bugcrowd")

# CWE -> OWASP ASVS reference (short).
ASVS_BY_CWE = {
    "CWE-79": "ASVS 5.1 (Output Encoding)",
    "CWE-89": "ASVS 5.2 (SQL Injection)",
    "CWE-918": "ASVS 5.4 (Server-Side Request Forgery)",
    "CWE-639": "ASVS 4.2 (Authorization)",
    "CWE-601": "ASVS 11.1 (Open Redirect)",
    "CWE-942": "ASVS 14.5 (CORS)",
}


def _sanitize(text: str) -> str:
    """Strip internal references that shouldn't ship: artifact paths, payload IDs."""
    for marker in ("artifacts/", "payloads/"):
        text = text.replace(marker, "[internal] ")
    return text


def _render_finding_md(f: Finding) -> str:
    cwe = f.cwe or "CWE-??? "
    asvs = ASVS_BY_CWE.get(cwe, "ASVS reference not mapped")
    lines = [
        f"### {f.title}",
        "",
        f"- **Severity:** {f.severity}",
        f"- **CWE:** {cwe}",
        f"- **CVSS 3.1:** {f.cvss or 'n/a'}",
        f"- **Reference:** {asvs}",
        f"- **URL:** {f.url}",
        "",
        f"**Detail:** {f.detail}",
    ]
    for ev in f.evidence:
        lines.append("")
        lines.append(f"**Evidence ({ev.kind}):**")
        lines.append("```")
        lines.append(_sanitize(ev.summary or ev.path))
        lines.append("```")
    return "\n".join(lines)


def generate_report(
    session: Session,
    finding_ids: list[int] | None = None,
    *,
    template: str = "markdown",
    program_id: int | None = None,
) -> str:
    """Generate a report draft for findings (all confirmed if no ids given)."""
    if template not in TEMPLATES:
        raise ValueError(f"unknown template: {template} (choose from {TEMPLATES})")

    q = session.query(Finding)
    if finding_ids:
        q = q.filter(Finding.id.in_(finding_ids))
    if program_id is not None:
        q = q.filter(Finding.program_id == program_id)
    findings = q.order_by(Finding.id).all()

    if template == "hackerone":
        return _render_h1(findings)
    if template == "bugcrowd":
        return _render_bugcrowd(findings)
    return _render_markdown(findings)


def _render_markdown(findings: list[Finding]) -> str:
    if not findings:
        return "# Report\n\nNo findings.\n"
    lines = ["# Bug Bounty Report (Draft)", ""]
    summary = _executive_summary(findings)
    if summary:
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(summary)
        lines.append("")
    for f in findings:
        lines.append(_render_finding_md(f))
        lines.append("")
    return "\n".join(lines)


def _executive_summary(findings: list[Finding]) -> str:
    """LLM summary when configured; deterministic fallback otherwise."""
    try:
        from bugbountybot.agent.llm import LLMAdapter

        adapter = LLMAdapter()
    except Exception:
        adapter = None

    if adapter is not None and adapter.available:
        try:
            summary = " ".join(f"{f.severity} {f.title}" for f in findings[:10])
            return adapter.draft_report_intro(summary)
        except Exception:
            pass  # fall through to deterministic

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    parts = [f"{n} {sev}" for sev, n in sorted(sev_counts.items(), key=lambda x: x[0])]
    return (
        f"This report covers {len(findings)} confirmed finding(s): "
        f"{', '.join(parts) if parts else 'n/a'}. "
        "All testing was performed against in-scope assets only; see per-finding "
        "details and evidence below."
    )


def _render_h1(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    out = []
    for f in findings:
        out.append(
            f"## {f.title}\n\n"
            f"**Asset:** {f.url}\n"
            f"**Weakness:** {f.cwe}\n"
            f"**Severity:** {f.severity}\n\n"
            f"{f.detail}\n\n"
            f"**Steps to reproduce:**\n"
            f"1. {f.detail}\n\n"
            f"**Impact:** See CVSS {f.cvss or 'n/a'}.\n"
        )
    return "\n---\n".join(out)


def _render_bugcrowd(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    out = ["# Vulnerability Report", ""]
    for f in findings:
        out.append(
            f"## {f.title}\n\n"
            f"**Vulnerability Type:** {f.cwe}\n"
            f"**Target:** {f.url}\n"
            f"**Severity:** {f.severity}\n\n"
            f"**Description:**\n{f.detail}\n\n"
            f"**Reproduction Steps:**\n1. Visit {f.url}\n2. See detail above.\n\n"
            f"**Remediation:** {ASVS_BY_CWE.get(f.cwe, 'Apply OWASP ASVS guidance for this class.')}\n"
        )
    return "\n---\n".join(out)


def program_stats(session: Session, program_id: int) -> dict:
    program = session.get(Program, program_id)
    findings = session.query(Finding).filter(Finding.program_id == program_id).all()
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return {
        "program": program.name if program else program_id,
        "findings": len(findings),
        "by_severity": by_sev,
    }
