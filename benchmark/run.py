"""Benchmark runner — measures per-module precision/recall/FP-rate.

Runs each vuln module against labeled fixture routes, computes the honest
numbers, and enforces the W1 FP budget (any module > 20% FP fails).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from benchmark.fixtures.server import GROUND_TRUTH, start_fixture
from bugbountybot.config.settings import DATA_DIR, PAYLOADS_DIR
from bugbountybot.payloads.loader import PayloadLibrary
from bugbountybot.runner.service import ScopedRunner
from bugbountybot.scope.guard import ProgramScope
from bugbountybot.storage.artifacts import ArtifactStore
from bugbountybot.storage.db import Program, init_db
from bugbountybot.tracker.service import add_program, add_scope

FP_BUDGET = 0.20  # W1: disable-by-default if >20% junk
RECALL_FLOOR = 0.50


@dataclass
class ModuleScore:
    module: str
    true_pos: int = 0
    false_pos: int = 0
    true_neg: int = 0
    false_neg: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_pos + self.false_pos
        return self.true_pos / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_pos + self.false_neg
        return self.true_pos / denom if denom else 0.0

    @property
    def fp_rate(self) -> float:
        denom = self.false_pos + self.true_neg
        return self.false_pos / denom if denom else 0.0


@dataclass
class BenchmarkResult:
    scores: list[ModuleScore] = field(default_factory=list)
    failed_modules: list[str] = field(default_factory=list)

    def by_module(self) -> dict[str, ModuleScore]:
        return {s.module: s for s in self.scores}

    def summary_table(self) -> str:
        lines = [
            f"{'module':10} {'precision':>9} {'recall':>6} {'FP-rate':>7}  verdict",
            "-" * 52,
        ]
        for s in sorted(self.scores, key=lambda x: x.module):
            verdict = "OK" if s.fp_rate <= FP_BUDGET else "FAIL (FP)"
            lines.append(
                f"{s.module:10} {s.precision:>9.2f} {s.recall:>6.2f} {s.fp_rate:>7.2f}  {verdict}"
            )
        return "\n".join(lines)


def run_benchmark(session: Session | None = None) -> BenchmarkResult:
    """Run all modules against the fixture; returns the scored result."""
    httpd = start_fixture()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        if session is None:
            factory = init_db("data")
            session = factory()

        program = add_program(session, "benchmark")
        add_scope(session, program.id, "127.0.0.1", kind="ip")

        lib = PayloadLibrary.from_directory(PAYLOADS_DIR)
        artifacts = ArtifactStore(DATA_DIR)
        result = BenchmarkResult()

        for module, routes in GROUND_TRUTH.items():
            score = ModuleScore(module=module)
            for prefix, expected_vuln in routes:
                # fresh program per (module, route) so modules only scan their
                # own route — shared endpoints cross-contaminate the scores
                prog = add_program(session, f"bench-{module}-{prefix.strip('/').replace('/', '_')}")
                add_scope(session, prog.id, "127.0.0.1", kind="ip")
                runner = ScopedRunner(
                    session,
                    program_id=prog.id,
                    library=lib,
                    artifacts=artifacts,
                )
                if module == "idor":
                    url = f"{base}{prefix}/12345"
                    params = ""
                elif module == "secrets":
                    url = f"{base}{prefix}"
                    params = ""
                elif module == "redirect":
                    url = f"{base}{prefix}"
                    params = "url"
                else:
                    url = f"{base}{prefix}"
                    params = "q"
                from bugbountybot.tracker.service import add_endpoint

                add_endpoint(session, prog.id, url=url, params=params)
                run = runner.run_module(module, f"{url}?{params}=test", max_tier=2)
                found = len(run.findings) > 0
                if found and expected_vuln:
                    score.true_pos += 1
                elif found and not expected_vuln:
                    score.false_pos += 1
                elif not found and expected_vuln:
                    score.false_neg += 1
                else:
                    score.true_neg += 1
            result.scores.append(score)
            if score.fp_rate > FP_BUDGET:
                result.failed_modules.append(module)

        # cleanup benchmark programs (children first for FK)
        from bugbountybot.storage.db import Endpoint, Finding, ScanRun

        for bp in session.query(Program).filter(Program.name.like("bench%")).all():
            session.query(Endpoint).filter(Endpoint.program_id == bp.id).delete()
            session.query(ScanRun).filter(ScanRun.program_id == bp.id).delete()
            session.query(Finding).filter(Finding.program_id == bp.id).delete()
            session.delete(bp)
        session.commit()
        return result
    finally:
        httpd.shutdown()


def verify(result: BenchmarkResult) -> bool:
    """FP budget + recall floor. False if any module fails either."""
    ok = True
    for s in result.scores:
        if s.fp_rate > FP_BUDGET:
            ok = False
        if s.recall < RECALL_FLOOR and (s.true_pos + s.false_neg) > 0:
            ok = False
    return ok


def run_corpus(session: Session | None = None) -> list[dict]:
    """Run every regression-corpus case; returns per-case verdicts.

    A TP case must produce a finding; an FP case must NOT. Any mismatch is a
    regression. The fixture serves each case at /corpus/<id>.
    """
    from benchmark.fixtures.server import _CORPUS, start_fixture
    from bugbountybot.tracker.service import add_endpoint, add_scope

    httpd = start_fixture()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        if session is None:
            factory = init_db("data")
            session = factory()
        program = add_program(session, "corpus")
        add_scope(session, program.id, "127.0.0.1", kind="ip")
        lib = PayloadLibrary.from_directory(PAYLOADS_DIR)
        artifacts = ArtifactStore(DATA_DIR)

        verdicts: list[dict] = []
        for case_id, case in _CORPUS.items():
            module = case["module"]
            runner = ScopedRunner(session, program_id=program.id, library=lib, artifacts=artifacts)
            url = f"{base}/corpus/{case_id}"
            if module == "idor":
                add_endpoint(session, program.id, url=f"{url}/12345", params="")
                target = f"{url}/12345"
            elif module == "secrets":
                add_endpoint(session, program.id, url=url, params="")
                target = url
            else:
                add_endpoint(session, program.id, url=url, params="q")
                target = f"{url}?q=test"
            run = runner.run_module(module, target, max_tier=2)
            found = len(run.findings) > 0
            expected = case["kind"] == "tp"
            verdicts.append(
                {
                    "id": case_id,
                    "module": module,
                    "kind": case["kind"],
                    "found": found,
                    "match": found == expected,
                    "note": case.get("note", ""),
                }
            )
        # cleanup corpus program
        from bugbountybot.storage.db import Endpoint, Finding, ScanRun

        bp = session.query(Program).filter(Program.name == "corpus").first()
        if bp is not None:
            session.query(Endpoint).filter(Endpoint.program_id == bp.id).delete()
            session.query(ScanRun).filter(ScanRun.program_id == bp.id).delete()
            session.query(Finding).filter(Finding.program_id == bp.id).delete()
            session.delete(bp)
            session.commit()
        return verdicts
    finally:
        httpd.shutdown()
