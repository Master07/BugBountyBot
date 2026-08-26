"""Recon tool adapters — subprocess wrappers with explicit config.

Every tool runs via subprocess with an explicit binary path, flags, and timeout.
No shell, no unsanitized input. A missing binary is reported as unavailable,
never fatal. Output is parsed into plain data (domains, urls).
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

from bugbountybot.config.settings import RECON_TOOLS


@dataclass
class ToolResult:
    tool: str
    available: bool = True
    error: str = ""
    items: list[str] = field(default_factory=list)


def _binary_for(tool: str) -> str | None:
    """Resolve a tool's binary path. Env override (BUGBOUNTY_<TOOL>) wins;
    falls back to PATH lookup. None if not found."""
    import os

    env_name = f"BUGBOUNTY_{tool.upper()}"
    configured = os.getenv(env_name) or RECON_TOOLS.get(tool, tool)
    path = shutil.which(configured) if not configured.startswith("/") else configured
    return path


def _run(tool: str, args: list[str], timeout: int = 60) -> ToolResult:
    path = _binary_for(tool)
    if not path:
        return ToolResult(tool=tool, available=False, error="binary not found")
    proc = subprocess.Popen(
        [path, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # preserve partial output — a slow root shouldn't lose its results
        proc.kill()
        stdout, stderr = proc.communicate()
        items = [ln.strip() for ln in (stdout or "").splitlines() if ln.strip()]
        return ToolResult(tool=tool, available=True, items=items, error="timeout (partial results)")
    if proc.returncode != 0:
        # Tools return non-zero on no-results or partial failures; surface stderr.
        return ToolResult(tool=tool, available=True, error=stderr.strip()[:200])
    items = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    return ToolResult(tool=tool, available=True, items=items)


def _run_stdin(tool: str, args: list[str], input_text: str, timeout: int = 60) -> ToolResult:
    """Run a tool with targets fed on stdin (e.g. httpx reads hosts from stdin)."""
    path = _binary_for(tool)
    if not path:
        return ToolResult(tool=tool, available=False, error="binary not found")
    try:
        proc = subprocess.run(
            [path, *args],
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(tool=tool, available=True, error="timeout")
    if proc.returncode != 0:
        return ToolResult(tool=tool, available=True, error=proc.stderr.strip()[:200])
    items = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    return ToolResult(tool=tool, available=True, items=items)


# ---- enum ----
def subfinder(domain: str, timeout: int = 60) -> ToolResult:
    """Enumerate subdomains: `subfinder -d <domain> -silent`.

    -max-time makes subfinder self-terminate quickly on huge roots (e.g.
    shopify.com with 20k+ subdomains) instead of stalling the run.
    """
    return _run(
        "subfinder",
        ["-d", domain, "-silent", "-max-time", "30"],
        timeout=timeout,
    )


# ---- probe ----
def httpx(urls: list[str]) -> ToolResult:
    """Probe live hosts: `httpx -silent -status-code -tech-detect -no-color`.

    Hosts are fed on stdin (httpx reads targets from stdin when no -u given).
    """
    if not urls:
        return ToolResult(tool="httpx", available=False, error="no hosts to probe")
    return _run_stdin(
        "httpx",
        ["-silent", "-status-code", "-tech-detect", "-no-color", "-timeout", "10"],
        input_text="\n".join(urls),
        timeout=180,
    )


# ---- discover ----
def katana(urls: list[str]) -> ToolResult:
    """Crawl endpoints: `katana -u <url> -silent -kf all` per URL."""
    if not urls:
        return ToolResult(tool="katana", available=False, error="no live hosts to crawl")
    found: list[str] = []
    for url in urls[:10]:  # cap crawl targets to keep runtime sane
        r = _run("katana", ["-u", url, "-silent", "-kf", "all"], timeout=120)
        found.extend(r.items)
    return ToolResult(tool="katana", available=True, items=found)


def gau(domain: str, timeout: int = 120) -> ToolResult:
    """Public-archive URLs: `gau <domain>`.

    Large programs can return thousands of URLs and take a while; timeout is
    generous but capped so a slow root can't stall a run indefinitely.
    """
    return _run("gau", [domain], timeout=timeout)


def ffuf(url: str, wordlist: str, threads: int = 5) -> ToolResult:
    """Directory/endpoint fuzz: `ffuf -u <url>/FUZZ -w <wordlist> -mc 200,301,302`."""
    return _run(
        "ffuf",
        ["-u", f"{url}/FUZZ", "-w", wordlist, "-mc", "200,301,302", "-t", str(threads), "-s"],
        timeout=180,
    )
