"""Recon pipeline tests — fake adapters, scope gating, dedup, storage."""
from __future__ import annotations

import pytest

from bugbountybot.recon.adapters import ToolResult
from bugbountybot.recon.pipeline import run_recon
from bugbountybot.recon.service import ReconService
from bugbountybot.storage.db import Endpoint
from bugbountybot.tracker.service import add_scope


@pytest.fixture()
def fake_adapters(monkeypatch):
    """Point recon adapters at fakes: subfinder returns hosts (one out of
    scope), httpx returns live URLs, gau returns endpoint URLs."""
    import bugbountybot.recon.pipeline as pipeline

    def fake_subfinder(domain):
        return ToolResult(
            tool="subfinder",
            items=["api.acme.com", "admin.acme.com", "www.acme.com"],
        )

    def fake_httpx(urls):
        return ToolResult(tool="httpx", items=["http://api.acme.com", "http://www.acme.com"])

    def fake_gau(domain):
        return ToolResult(
            tool="gau",
            items=[
                "http://api.acme.com/search?q=1",
                "http://api.acme.com/search?q=2&page=1",
                "http://www.acme.com/profile?user_id=1",
                "http://outofscope.evil.com/x",  # not in scope — should be blocked
            ],
        )

    def fake_katana(urls):
        return ToolResult(tool="katana", items=[])

    monkeypatch.setattr(pipeline.adapters, "subfinder", fake_subfinder)
    monkeypatch.setattr(pipeline.adapters, "httpx", fake_httpx)
    monkeypatch.setattr(pipeline.adapters, "gau", fake_gau)
    monkeypatch.setattr(pipeline.adapters, "katana", fake_katana)


@pytest.fixture()
def recon_program(session, program):
    add_scope(session, program.id, "acme.com", kind="domain")
    add_scope(session, program.id, "*.acme.com", kind="wildcard")
    add_scope(session, program.id, "admin.acme.com", kind="domain", in_scope=False)
    return program


def test_recon_stores_scoped_endpoints(session, recon_program, fake_adapters):
    result = run_recon(session, recon_program.id, tools=["subfinder", "httpx", "gau"])
    assert result.endpoints_new, "expected recon to store endpoints"
    stored = {e.url for e in result.endpoints_new}
    assert "http://api.acme.com/search" in stored
    assert "http://www.acme.com/profile" in stored


def test_recon_blocks_out_of_scope_hosts(session, recon_program, fake_adapters):
    result = run_recon(session, recon_program.id, tools=["subfinder", "httpx", "gau"])
    # admin.acme.com subdomain (explicit --out) + evil.com URL must be blocked
    assert "admin.acme.com" in result.blocked or "admin.acme.com" in [h for h in result.blocked]
    assert any("outofscope.evil.com" in b for b in result.blocked)


def test_recon_dedupes_on_rerun(session, recon_program, fake_adapters):
    r1 = run_recon(session, recon_program.id, tools=["subfinder", "httpx", "gau"])
    assert r1.endpoints_new
    count1 = len(r1.endpoints_new)
    r2 = run_recon(session, recon_program.id, tools=["subfinder", "httpx", "gau"])
    assert r2.endpoints_new == [], "re-run should not duplicate endpoints"


def test_recon_skips_missing_tools(session, recon_program, monkeypatch):
    """When subfinder binary is absent, pipeline falls back to roots and continues."""
    import bugbountybot.recon.pipeline as pipeline
    from bugbountybot.recon.adapters import ToolResult

    def fake_httpx(urls):
        return ToolResult(tool="httpx", items=["http://acme.com"])

    monkeypatch.setattr(pipeline.adapters, "subfinder", lambda d: ToolResult(tool="subfinder", available=False, error="binary not found"))
    monkeypatch.setattr(pipeline.adapters, "httpx", fake_httpx)
    monkeypatch.setattr(pipeline.adapters, "gau", lambda d: ToolResult(tool="gau", items=[]))
    monkeypatch.setattr(pipeline.adapters, "katana", lambda u: ToolResult(tool="katana", items=[]))

    result = run_recon(session, recon_program.id, tools=["subfinder", "httpx", "gau"])
    stats = {t.tool: t for t in result.tool_stats}
    assert stats["subfinder"].available is False
    # fallback: root domain https://acme.com treated as host
    assert result.hosts_discovered


def test_recon_service_lists(session, recon_program, fake_adapters):
    svc = ReconService(session)
    run_recon(session, recon_program.id, tools=["subfinder", "httpx", "gau"])
    eps = svc.list_recon_endpoints(recon_program.id)
    assert eps
    assert all(e.source == "recon" for e in eps)


def test_recon_endpoints_consumed_by_runner(session, recon_program, fake_adapters, artifacts):
    """Endpoints discovered by recon feed the vuln runner."""
    from bugbountybot.payloads.loader import PayloadLibrary
    from bugbountybot.runner.service import ScopedRunner

    run_recon(session, recon_program.id, tools=["subfinder", "httpx", "gau"])
    runner = ScopedRunner(
        session,
        program_id=recon_program.id,
        library=PayloadLibrary.from_directory("payloads"),
        artifacts=artifacts,
    )
    # list_endpoints must now include recon-sourced rows
    from bugbountybot.tracker.service import list_endpoints

    urls = [e.url for e in list_endpoints(session, recon_program.id)]
    assert any("api.acme.com" in u for u in urls)


def test_httpx_adapter_feeds_stdin(tmp_path, monkeypatch):
    """httpx must receive hosts on stdin (not via args, which it ignores)."""
    stub = tmp_path / "httpx-stub"
    stub.write_text(
        "#!/bin/sh\n"
        "read -r line\n"
        "printf '%s [200]\\n' \"$line\"\n"
    )
    stub.chmod(0o755)
    monkeypatch.setenv("BUGBOUNTY_HTTPX", str(stub))

    from bugbountybot.recon.adapters import httpx

    result = httpx(["http://api.acme.com", "http://www.acme.com"])
    assert result.available
    assert result.items == ["http://api.acme.com [200]"]
