"""API server tests — dashboard endpoints exercise the same services as the CLI."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from bugbountybot.api.server import app


@pytest.fixture()
def client(monkeypatch, tmp_path):
    # Point the API at a temp data dir so tests don't touch real data/.
    import bugbountybot.api.server as server

    monkeypatch.setattr(server, "DATA_DIR", tmp_path)
    return TestClient(app)


def test_index_serves_dashboard(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "BugBounty" in r.text


def test_meta(client):
    r = client.get("/api/meta")
    assert r.status_code == 200
    assert "xss" in r.json()["modules"]
    assert "hackerone" in r.json()["templates"]


def test_program_lifecycle(client):
    r = client.post("/api/programs", json={"name": "acme", "platform": "hackerone"})
    assert r.status_code == 200
    pid = r.json()["id"]

    r = client.post(
        f"/api/programs/{pid}/scope",
        json={"pattern": "acme.com", "kind": "domain", "in_scope": True},
    )
    assert r.status_code == 200
    assert any(x["pattern"] == "acme.com" for x in r.json()["rules"])

    r = client.get("/api/programs")
    assert len(r.json()) == 1


def test_scan_blocked_out_of_scope(client):
    client.post("/api/programs", json={"name": "acme"})
    # target host not in scope -> blocked, no crash
    r = client.post(
        "/api/scan",
        json={"program": "acme", "target": "https://evil.com/x", "modules": "xss", "tier": 2},
    )
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert res["blocked"] >= 1


def test_report_empty(client):
    r = client.post("/api/report", json={"template": "markdown"})
    assert r.status_code == 200
    assert "No findings" in r.json()["report"]


def test_payloads_endpoint(client):
    r = client.get("/api/payloads?search=alert")
    assert r.status_code == 200
    assert r.json()["count"] >= 1


# ---- submissions ----
def test_submissions_crud(client):
    client.post("/api/programs", json={"name": "acme"})

    r = client.post("/api/submissions", json={"program": "acme", "title": "XSS in search"})
    assert r.status_code == 200
    sid = r.json()["id"]
    assert r.json()["status"] == "draft"

    r = client.patch(f"/api/submissions/{sid}", json={"status": "submitted"})
    assert r.status_code == 200
    assert r.json()["status"] == "submitted"

    r = client.patch(f"/api/submissions/{sid}", json={"payout": 500})
    assert r.status_code == 200
    assert r.json()["payout"] == 500

    r = client.get("/api/submissions?program=acme")
    assert len(r.json()) == 1


def test_submissions_require_existing_program(client):
    r = client.post("/api/submissions", json={"program": "nope", "title": "x"})
    assert r.status_code == 404


def test_import_hackerone_no_credentials_is_400(client, monkeypatch):
    """Missing HackerOne creds must be a clear 400, not a 500."""
    monkeypatch.delenv("HACKERONE_USERNAME", raising=False)
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    import keyring

    monkeypatch.setattr(keyring, "get_password", lambda *a, **k: None)
    r = client.post("/api/import", json={"platform": "hackerone", "handle": "security"})
    assert r.status_code == 400
    assert "credentials" in r.json()["detail"].lower()


def test_triage_ranks_by_severity(client):
    client.post("/api/programs", json={"name": "acme"})
    from bugbountybot.storage.db import Finding
    from bugbountybot.api.server import _session
    from bugbountybot.tracker.service import add_finding as _af, get_program

    s = _session()
    p = get_program(s, "acme")
    _af(s, program_id=p.id, submission_id=None, title="Low one", module="xss", severity="low", dedup_key="l1")
    _af(s, program_id=p.id, submission_id=None, title="Critical one", module="idor", severity="critical", dedup_key="c1")
    r = client.get("/api/triage?program=acme")
    assert r.status_code == 200
    ranking = r.json()["ranking"]
    # deterministic fallback must put critical before low
    assert ranking.index("CRITICAL") < ranking.index("LOW")


def test_report_has_executive_summary(client):
    client.post("/api/programs", json={"name": "acme"})
    from bugbountybot.api.server import _session
    from bugbountybot.tracker.service import add_finding as _af, get_program

    s = _session()
    p = get_program(s, "acme")
    _af(s, program_id=p.id, submission_id=None, title="XSS", module="xss", severity="medium", dedup_key="x1")
    r = client.post("/api/report", json={"program": "acme", "template": "markdown"})
    assert "Executive Summary" in r.json()["report"]


def test_logic_plans_api(client):
    client.post("/api/programs", json={"name": "acme"})
    from bugbountybot.api.server import _session
    from bugbountybot.tracker.service import add_scope, get_program

    s = _session()
    p = get_program(s, "acme")
    add_scope(s, p.id, "127.0.0.1", kind="ip")

    r = client.post("/api/logic/plan", json={"program": "acme", "category": "workflow", "target": "http://127.0.0.1:9/x"})
    assert r.status_code == 200
    plan_id = r.json()["id"]
    assert len(r.json()["steps"]) >= 3

    r = client.get("/api/logic/plans")
    assert len(r.json()) == 1
    assert r.json()[0]["id"] == plan_id

    r = client.post(f"/api/logic/plan/{plan_id}/run", json={"parallel": False})
    assert r.status_code == 200
    # 127.0.0.1 is in scope so no scope block; connection refused = no interesting finding.
    assert r.json()["blocked"] == 0
    assert r.json()["findings_created"] == 0


# ---- finding status update ----
def test_finding_update(client):
    from bugbountybot.storage.db import Finding
    from bugbountybot.api.server import _session

    s = _session()
    client.post("/api/programs", json={"name": "acme"})
    program = tracker_get(s, "acme")
    from bugbountybot.tracker.service import add_finding as _af

    _af(s, program_id=program.id, submission_id=None, title="XSS", module="xss", dedup_key="k1")
    fid = s.query(Finding).first().id

    r = client.patch(f"/api/findings/{fid}", json={"status": "confirmed", "severity": "high"})
    assert r.status_code == 200
    assert r.json()["status"] == "confirmed"
    assert r.json()["severity"] == "high"


def test_stats_extended(client):
    client.post("/api/programs", json={"name": "acme"})
    client.post("/api/submissions", json={"program": "acme", "title": "one"})
    client.post("/api/submissions", json={"program": "acme", "title": "two"})
    client.patch("/api/submissions/2", json={"status": "paid", "payout": 250})
    r = client.get("/api/stats?program=acme")
    assert r.status_code == 200
    body = r.json()
    assert body["submissions"] == 2
    assert body["submissions_by_status"].get("paid") == 1
    assert body["total_payout"] == 250


# ---- OOB lifecycle ----
def test_oob_lifecycle(client):
    r = client.get("/api/oob/status")
    assert r.json()["running"] is False

    r = client.post("/api/oob/start", json={"port": 0})
    assert r.status_code == 200
    assert r.json()["running"] is True
    assert r.json()["port"] > 0

    r = client.get("/api/oob/status")
    assert r.json()["running"] is True

    r = client.post("/api/oob/stop")
    assert r.json()["running"] is False

    r = client.get("/api/oob/status")
    assert r.json()["running"] is False


def tracker_get(session, name):
    from bugbountybot.tracker.service import get_program

    return get_program(session, name)
