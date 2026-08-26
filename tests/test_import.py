"""Program import tests — fake HTTP for H1/Bugcrowd, CSV, kind mapping, upsert."""
from __future__ import annotations

import httpx
import pytest

from bugbountybot.importer.bugcrowd import parse_bugcrowd_json
from bugbountybot.importer.csv_import import parse_csv, import_csv
from bugbountybot.importer.hackerone import (
    _classify_hackerone,
    parse_structured_scope,
    import_hackerone,
)
from bugbountybot.importer.service import apply_import
from bugbountybot.scope.guard import ProgramScope, ScopeGuard


# ---- HackerOne classification ----
def test_hackerone_kind_mapping():
    assert _classify_hackerone("WILDCARD", "*.acme.com").kind == "wildcard"
    assert _classify_hackerone("URL", "https://acme.com").kind == "domain"
    assert _classify_hackerone("CIDR", "10.0.0.0/8").kind == "cidr"
    assert _classify_hackerone("IP", "1.2.3.4").kind == "ip"


def test_hackerone_skips_non_web():
    a = _classify_hackerone("APPLE_APP_STORE", "id123")
    assert a.skipped
    assert "non-web" in a.reason


def test_hackerone_strips_scheme():
    a = _classify_hackerone("URL", "https://api.acme.com/")
    assert a.identifier == "api.acme.com"


def test_parse_structured_scope():
    data = {
        "data": [
            {"attributes": {"asset_identifier": "*.acme.com", "asset_type": "WILDCARD"}},
            {"attributes": {"asset_identifier": "https://acme.com", "asset_type": "URL"}},
            {"attributes": {"asset_identifier": "10.0.0.0/8", "asset_type": "CIDR"}},
            {"attributes": {"asset_identifier": "mobile-app", "asset_type": "GOOGLE_PLAY_APP_ID"}},
        ]
    }
    assets = parse_structured_scope(data["data"])
    assert [a.identifier for a in assets if not a.skipped] == ["*.acme.com", "acme.com", "10.0.0.0/8"]
    assert sum(1 for a in assets if a.skipped) == 1


# ---- HackerOne import with fake HTTP ----
def test_import_hackerone(monkeypatch, tmp_path):
    fake = {
        "data": [
            {"attributes": {"asset_identifier": "*.acme.com", "asset_type": "WILDCARD"}},
            {"attributes": {"asset_identifier": "https://acme.com", "asset_type": "URL"}},
        ]
    }

    def fake_get(url, **kwargs):
        assert "api.hackerone.com" in url
        assert kwargs["auth"] == ("u", "t")
        request = httpx.Request("GET", url)
        return httpx.Response(200, json=fake, request=request)

    monkeypatch.setattr("bugbountybot.importer.hackerone.httpx.get", fake_get)
    monkeypatch.setenv("HACKERONE_USERNAME", "u")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "t")

    result = import_hackerone("acme")
    assert result.errors == []
    assert result.in_scope == 2


def test_import_hackerone_no_credentials(monkeypatch):
    monkeypatch.delenv("HACKERONE_USERNAME", raising=False)
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    import keyring

    monkeypatch.setattr(keyring, "get_password", lambda *a, **k: None)
    with pytest.raises(RuntimeError):
        import_hackerone("acme")


def test_import_hackerone_http_error(monkeypatch):
    def fake_get(url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(404, text="no such program", request=request)

    monkeypatch.setattr("bugbountybot.importer.hackerone.httpx.get", fake_get)
    monkeypatch.setenv("HACKERONE_USERNAME", "u")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "t")
    result = import_hackerone("nope")
    assert result.errors
    assert "404" in result.errors[0]


# ---- Bugcrowd ----
def test_bugcrowd_parse():
    data = {
        "name": "Acme VDP",
        "targets": [
            {
                "in_scope": [
                    {"target": "acme.com"},
                    {"target": "*.acme.com"},
                    {"target": "10.0.0.0/24"},
                    {"target": "https://api.acme.com"},
                ]
            }
        ],
    }
    assets = parse_bugcrowd_json(data)
    kinds = {a.identifier: a.kind for a in assets}
    assert kinds["acme.com"] == "domain"
    assert kinds["*.acme.com"] == "wildcard"
    assert kinds["10.0.0.0/24"] == "cidr"
    assert kinds["api.acme.com"] == "domain"


def test_bugcrowd_parse_out_of_scope():
    data = {
        "targets": [
            {
                "in_scope": [{"target": "acme.com"}, {"target": "*.acme.com"}],
                "out_of_scope": [{"target": "admin.acme.com"}, {"target": "*.test.acme.com"}],
            }
        ]
    }
    assets = parse_bugcrowd_json(data)
    in_scope = {a.identifier for a in assets if a.in_scope}
    out_scope = {a.identifier for a in assets if not a.in_scope}
    assert "admin.acme.com" in out_scope
    assert "*.test.acme.com" in out_scope
    assert "acme.com" in in_scope


# ---- CSV ----
def test_csv_parse(tmp_path):
    f = tmp_path / "scope.csv"
    f.write_text(
        "acme.com,domain,true\n"
        "*.acme.com,wildcard,true\n"
        "admin.acme.com,domain,false\n"
        "# comment line\n"
        "10.0.0.0/8,cidr,\n"
    )
    assets = parse_csv(f)
    assert len(assets) == 4
    assert assets[2].in_scope is False
    assert assets[3].kind == "cidr"


def test_csv_import_unknown_kind(tmp_path):
    f = tmp_path / "bad.csv"
    f.write_text("acme.com,banana,true\n")
    result = import_csv(f, "acme")
    assert result.skipped == 1


# ---- apply to DB + scope guard ----
def test_apply_import_creates_program_and_rules(session):
    from bugbountybot.importer.hackerone import ImportResult, ImportedAsset

    result = ImportResult(platform="hackerone", handle="acme", program_name="acme")
    result.assets = [
        ImportedAsset("*.acme.com", "wildcard", in_scope=True),
        ImportedAsset("acme.com", "domain", in_scope=True),
        ImportedAsset("admin.acme.com", "domain", in_scope=False),
    ]
    apply_import(session, result)
    assert result.rules_added == 3

    # scope guard honors the imported out-of-scope rule
    from bugbountybot.tracker.service import get_program

    program = get_program(session, "acme")
    assert program.platform == "hackerone"
    guard = ScopeGuard(ProgramScope.load(session, program.id))
    assert guard.check("https://api.acme.com/x", tier=1).allowed
    assert not guard.check("https://admin.acme.com/x", tier=1).allowed


def test_apply_import_upserts_no_dupes(session):
    from bugbountybot.importer.hackerone import ImportResult, ImportedAsset
    from bugbountybot.tracker.service import add_program, add_scope

    p = add_program(session, "acme")
    add_scope(session, p.id, "acme.com", kind="domain")

    result = ImportResult(platform="hackerone", handle="acme", program_name="acme")
    result.assets = [ImportedAsset("acme.com", "domain", in_scope=True)]
    apply_import(session, result)
    assert result.rules_added == 0, "existing rule should not be duplicated"
