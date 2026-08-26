"""Recon pipeline — enum -> scope-gate -> probe -> discover -> store.

The Scope Guard is applied to EVERY discovered host before it is probed or
stored. A subdomain that appears via enumeration but is not in program scope
is dropped and audit-logged as BLOCK — this is the safety net for wildcard
scope drift.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from sqlalchemy.orm import Session

from bugbountybot.recon import adapters
from bugbountybot.recon.adapters import ToolResult
from bugbountybot.scope.guard import ProgramScope, ScopeGuard
from bugbountybot.storage.audit import log_request
from bugbountybot.storage.db import Endpoint


@dataclass
class ReconStats:
    tool: str
    available: bool
    found: int
    new: int = 0
    error: str = ""


@dataclass
class ReconResult:
    program_id: int
    hosts_discovered: list[str] = field(default_factory=list)
    hosts_live: list[str] = field(default_factory=list)
    endpoints_found: list[str] = field(default_factory=list)
    endpoints_new: list[Endpoint] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    tool_stats: list[ReconStats] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"hosts discovered: {len(self.hosts_discovered)}",
            f"live: {len(self.hosts_live)}",
            f"endpoints found: {len(self.endpoints_found)}",
            f"endpoints stored (new): {len(self.endpoints_new)}",
            f"blocked (out of scope): {len(self.blocked)}",
        ]
        for t in self.tool_stats:
            status = "ok" if t.available else "unavailable"
            lines.append(f"  [{t.tool}] {status} found={t.found}")
            if t.error:
                lines.append(f"    err: {t.error[:120]}")
        return "\n".join(lines)


def _is_recon_endpoint(url: str) -> bool:
    return bool(urlsplit(url).netloc)


def _dedupe(session: Session, program_id: int, urls: list[str]) -> list[str]:
    """Filter out URLs whose base+params already exist for the program.

    Compares the normalized (base, params) form used when storing, so a URL
    with a query string dedupes against the stored base endpoint.
    """
    existing = {
        (e.url, e.params)
        for e in session.query(Endpoint).filter(Endpoint.program_id == program_id).all()
    }
    return [
        u for u in urls
        if not _recon_key(u) in existing
    ]


def _recon_key(url: str) -> tuple[str, str]:
    base, params = _extract_endpoint(url)
    return base, params


def _extract_endpoint(url: str, method: str = "GET") -> tuple[str, str]:
    """Split a discovered URL into a base endpoint + comma-joined params."""
    parsed = urlsplit(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = ",".join(k for k, _ in parse_qsl(parsed.query))
    return base, params


def run_recon(
    session: Session,
    program_id: int,
    *,
    tools: list[str] | None = None,
    wordlist: str = "",
    scope: ProgramScope | None = None,
    max_hosts: int = 200,
) -> ReconResult:
    """Run the recon pipeline for a program. Tools list = subfinder, httpx,
    katana, gau, ffuf. Missing binaries are reported, not fatal.
    max_hosts caps the candidate pool probed per run (default 200)."""
    result = ReconResult(program_id=program_id)
    scope = scope or ProgramScope.load(session, program_id)
    guard = ScopeGuard(scope)

    allowed = {t for t in (tools or ["subfinder", "httpx", "katana", "gau"]) if t}
    snapshot = f"program={program_id}"

    # 1. Enum: root domains from in-scope domain/wildcard rules.
    roots = [
        r.pattern.removeprefix("*.")
        for r in scope.rules
        if r.in_scope and r.kind in ("domain", "wildcard")
    ]

    # 2. Subdomain enumeration (scope-gated). Enumerate per in-scope root
    # domain (not just the first), cap the candidate pool to keep runs sane.
    subdomains: list[str] = []
    if "subfinder" in allowed:
        found_any = False
        for root in roots:
            sf = adapters.subfinder(root)
            if not sf.available:
                continue
            found_any = True
            result.tool_stats.append(
                ReconStats(tool="subfinder", available=True, found=len(sf.items), error=sf.error)
            )
            for host in sf.items:
                if len(subdomains) >= max_hosts:
                    break
                decision = guard.check(f"http://{host}", tier=1)
                log_request(
                    session, url=f"http://{host}", tier=1,
                    scope_snapshot=snapshot, allowed=decision.allowed, reason=decision.reason,
                )
                if decision.allowed:
                    subdomains.append(host)
                else:
                    result.blocked.append(host)
            if len(subdomains) >= max_hosts:
                break
        if not found_any:
            result.tool_stats.append(
                ReconStats(tool="subfinder", available=False, found=0, error="binary not found")
            )
            # Fall back to the root domains themselves (still scoped).
            subdomains = [f"https://{r}" for r in roots]
    else:
        subdomains = [f"https://{r}" for r in roots]
        result.tool_stats.append(
            ReconStats(tool="subfinder", available=False, found=0, error="skipped")
        )

    # De-duplicate while preserving order.
    subdomains = list(dict.fromkeys(subdomains))
    result.hosts_discovered = subdomains

    # 3. Probe live hosts.
    if "httpx" in allowed:
        # httpx takes hosts on stdin; feed them as args-free input via echo.
        live: list[str] = []
        hp = adapters.httpx(subdomains)
        result.tool_stats.append(
            ReconStats(tool="httpx", available=hp.available, found=len(hp.items), error=hp.error)
        )
        for line in hp.items:
            url = line.split()[0] if line.split() else line
            decision = guard.check(url, tier=1)
            log_request(
                session, url=url, tier=1,
                scope_snapshot=snapshot, allowed=decision.allowed, reason=decision.reason,
            )
            if decision.allowed:
                live.append(url)
            else:
                result.blocked.append(url)
        if not live:
            live = subdomains  # httpx unavailable or empty: treat enumerated as live
        result.hosts_live = live
    else:
        result.hosts_live = subdomains
        result.tool_stats.append(
            ReconStats(tool="httpx", available=False, found=0, error="skipped")
        )

    # 4. Discover endpoints.
    discovered: list[str] = []
    if "gau" in allowed and roots:
        g = adapters.gau(roots[0])
        result.tool_stats.append(
            ReconStats(tool="gau", available=g.available, found=len(g.items), error=g.error)
        )
        discovered.extend(g.items)
    if "katana" in allowed:
        k = adapters.katana(result.hosts_live[:10])
        result.tool_stats.append(
            ReconStats(tool="katana", available=k.available, found=len(k.items), error=k.error)
        )
        discovered.extend(k.items)
    if "ffuf" in allowed and wordlist:
        for host in result.hosts_live[:5]:
            f = adapters.ffuf(host, wordlist)
            result.tool_stats.append(
                ReconStats(tool="ffuf", available=f.available, found=len(f.items), error=f.error)
            )
            discovered.extend(f"https://{fitem}" if not fitem.startswith("http") else fitem for fitem in f.items)

    # 5. Scope-gate discovered URLs, dedupe, store.
    seen = set()
    for url in discovered:
        if not _is_recon_endpoint(url) or url in seen:
            continue
        seen.add(url)
        decision = guard.check(url, tier=1)
        log_request(
            session, url=url, tier=1,
            scope_snapshot=snapshot, allowed=decision.allowed, reason=decision.reason,
        )
        if not decision.allowed:
            result.blocked.append(url)
            continue
        result.endpoints_found.append(url)

    new_urls = _dedupe(session, program_id, result.endpoints_found)
    for url in new_urls:
        base, params = _extract_endpoint(url)
        ep = Endpoint(program_id=program_id, url=base, method="GET", params=params, source="recon")
        session.add(ep)
        session.flush()
        result.endpoints_new.append(ep)
    session.commit()

    return result
