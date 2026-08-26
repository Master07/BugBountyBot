"""Reliability tests — rate limiter, WAL concurrency, crash-safe runs."""
from __future__ import annotations

import threading
import time

import pytest

from bugbountybot.runner.ratelimit import RateLimiter, TokenBucket, retry_with_jitter
from bugbountybot.storage.db import init_db, with_retry


# ---- token bucket ----
def test_token_bucket_limits_rate():
    bucket = TokenBucket(rate=10.0)  # 10/sec
    # burst capacity = rate*2 = 20 tokens available instantly
    start = time.monotonic()
    acquired_immediate = 0
    for _ in range(20):
        if bucket.acquire(timeout=0.001):
            acquired_immediate += 1
    elapsed_immediate = time.monotonic() - start
    assert acquired_immediate <= 20
    assert elapsed_immediate < 0.5  # burst drained fast
    # after the burst, refill is rate-limited: next acquire must wait ~1/10s
    t0 = time.monotonic()
    assert bucket.acquire(timeout=1.0)  # blocks until a token refills
    waited = time.monotonic() - t0
    assert waited >= 0.05  # had to wait for refill (not instant)


# ---- rate limiter ----
def test_rate_limiter_blocks_over_rate():
    rl = RateLimiter(rate=1.0)  # 1/sec, capacity 2
    allowed = 0
    blocked = 0
    for _ in range(10):
        ok, _ = rl.before_request("http://127.0.0.1:9/x", timeout=0.01)
        if ok:
            allowed += 1
        else:
            blocked += 1
    # capacity 2 allows the first two, the rest block within 10ms
    assert blocked >= 7
    assert allowed <= 3


def test_rate_limiter_backoff_on_429():
    rl = RateLimiter(rate=100.0)
    ok, _ = rl.before_request("http://127.0.0.1:9/x")
    assert ok
    rl.after_response("http://127.0.0.1:9/x", 429, retry_after="5")
    # immediately after a 429 with Retry-After: 5, must be blocked
    ok, reason = rl.before_request("http://127.0.0.1:9/x")
    assert not ok
    assert "backoff" in reason


def test_circuit_breaker_after_repeated_5xx():
    rl = RateLimiter(rate=100.0)
    for i in range(5):
        ok, _ = rl.before_request("http://127.0.0.1:9/x")
        assert ok, f"iteration {i} should still be allowed"
        rl.after_response("http://127.0.0.1:9/x", 503)
    # 5th 503 opens the circuit; the next request must be skipped
    ok, reason = rl.before_request("http://127.0.0.1:9/x")
    assert not ok
    assert "circuit" in reason


def test_retry_with_jitter_retries_once():
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise TimeoutError("transient")
        return "ok"

    from bugbountybot.runner.ratelimit import retry_with_jitter as _rj

    # retry_with_jitter expects status-code responses; test the raw retry path
    import bugbountybot.runner.ratelimit as rl

    # call the private loop via a status-returning fn
    def fn():
        calls2 = {"n": 0}

        def inner():
            calls2["n"] += 1
            if calls2["n"] == 1:
                raise TimeoutError("boom")
            return type("R", (), {"status_code": 200})()

        return inner

    resp = rl.retry_with_jitter(fn(), attempts=2)
    assert resp.status_code == 200


# ---- SQLite WAL + with_retry ----
def test_wal_mode_enabled(tmp_path):
    from sqlalchemy import create_engine, text

    eng = create_engine(f"sqlite:///{tmp_path / 't.db'}")
    with eng.connect() as c:
        c.execute(text("PRAGMA journal_mode"))
        # WAL is a per-connection setting; our init_db sets it via the event hook.
    # verify init_db's engine reports WAL
    factory = init_db(tmp_path)
    with factory() as s:
        row = s.execute(text("PRAGMA journal_mode")).fetchone()
        assert "wal" in str(row[0]).lower()


def test_concurrent_writes_no_lock_error(tmp_path):
    """Two sessions writing concurrently must not raise 'database is locked'."""
    from bugbountybot.tracker.service import add_program

    factory = init_db(tmp_path)
    errors: list[Exception] = []

    def writer(n):
        try:
            for i in range(20):
                with factory() as s:
                    add_program(s, f"p{n}-{i}", platform="hackerone")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, f"concurrent writes failed: {errors[:3]}"


def test_with_retry_swallows_transient_lock(tmp_path, monkeypatch):
    from sqlalchemy.exc import OperationalError

    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise OperationalError("stmt", {}, Exception("database is locked"))
        return "ok"

    assert with_retry(flaky) == "ok"
    assert calls["n"] == 2


def test_migration_adds_new_columns_to_old_db(tmp_path):
    """A pre-migration DB (missing scan_runs.status/error) must be upgraded by
    init_db so newer code doesn't crash on insert."""
    import sqlite3

    db_path = tmp_path / "data" / "bugbounty.db"
    db_path.parent.mkdir(parents=True)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, program_id INTEGER, "
        "target TEXT, modules TEXT, tier INTEGER, confirm INTEGER, "
        "findings_created INTEGER, blocked INTEGER, ran_at TEXT)"
    )
    conn.commit()
    conn.close()

    from sqlalchemy import inspect

    from bugbountybot.storage.db import init_db

    factory = init_db(tmp_path / "data")
    engine = factory.kw["bind"]
    cols = {c["name"] for c in inspect(engine).get_columns("scan_runs")}
    assert "status" in cols and "error" in cols, "migration must add status/error"


# ---- crash-safe scan runs ----
def test_run_all_records_failed_module(session, program, artifacts):
    from bugbountybot.payloads.loader import PayloadLibrary
    from bugbountybot.runner.service import ScopedRunner
    from bugbountybot.storage.db import ScanRun
    from bugbountybot.tracker.service import add_scope

    add_scope(session, program.id, "127.0.0.1", kind="ip")
    runner = ScopedRunner(
        session,
        program_id=program.id,
        library=PayloadLibrary.from_directory("payloads"),
        artifacts=artifacts,
    )

    # a module against a closed port raises httpx errors (caught), so force a
    # real failure by monkeypatching run_module for one name
    def boom(*a, **k):
        raise RuntimeError("module exploded")

    import bugbountybot.runner.service as svc

    original = runner.run_module
    runner.run_module = boom
    try:
        results = runner.run_all(["xss", "sqli"], "http://127.0.0.1:9/x")
    finally:
        runner.run_module = original
    # both modules failed -> both recorded as failed runs
    failed = session.query(ScanRun).filter(ScanRun.status == "failed").all()
    assert len(failed) == 2
    assert all("exploded" in f.error for f in failed)
