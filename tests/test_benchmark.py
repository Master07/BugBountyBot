"""Benchmark test — asserts the W1 FP budget and recall floor hold."""
from __future__ import annotations

import pytest

from benchmark.run import FP_BUDGET, RECALL_FLOOR, run_benchmark, verify


@pytest.fixture()
def benchmark_result(session):
    """Run the full benchmark against a temp-DB session (no real data touched)."""
    result = run_benchmark(session)
    return result


def test_benchmark_runs_all_modules(benchmark_result):
    assert {s.module for s in benchmark_result.scores} == {
        "xss", "sqli", "redirect", "cors", "idor", "secrets",
    }


def test_benchmark_fp_budget_holds(benchmark_result):
    """No module may exceed the W1 20% false-positive budget."""
    for s in benchmark_result.scores:
        assert s.fp_rate <= FP_BUDGET, f"{s.module} FP-rate {s.fp_rate:.2f} exceeds budget"


def test_benchmark_recall_floor(benchmark_result):
    """Modules with labeled vuln cases must meet the recall floor."""
    for s in benchmark_result.scores:
        if s.true_pos + s.false_neg > 0:
            assert s.recall >= RECALL_FLOOR, f"{s.module} recall {s.recall:.2f} below floor"


def test_benchmark_verify_passes(benchmark_result):
    assert verify(benchmark_result) is True


def test_benchmark_detects_vuln_cases(benchmark_result):
    """The vuln-labeled routes must actually be found (recall sanity)."""
    by = benchmark_result.by_module()
    # XSS reflected route must be a true positive
    assert by["xss"].true_pos >= 1
    # SQLi boolean route must be a true positive
    assert by["sqli"].true_pos >= 1
    # redirect open route must be a true positive
    assert by["redirect"].true_pos >= 1
