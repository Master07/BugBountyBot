"""Regression-corpus tests — every labeled case must match."""
from __future__ import annotations

import pytest

from benchmark.run import run_corpus


@pytest.fixture()
def corpus_verdicts(session):
    """Run the full regression corpus against a temp-DB session."""
    return run_corpus(session)


def test_corpus_runs_all_cases(corpus_verdicts):
    assert len(corpus_verdicts) >= 8, "corpus should have seeded cases"
    ids = {v["id"] for v in corpus_verdicts}
    assert "cors-superhuman-tp" in ids
    assert "xss-encoded-fp" in ids
    assert "secrets-gitconfig-tp" in ids


def test_corpus_all_cases_match(corpus_verdicts):
    mismatches = [v for v in corpus_verdicts if not v["match"]]
    assert not mismatches, f"corpus regressions: {mismatches}"


def test_corpus_tp_cases_found(corpus_verdicts):
    tps = [v for v in corpus_verdicts if v["kind"] == "tp"]
    assert tps, "corpus has TP cases"
    for v in tps:
        assert v["found"], f"TP case {v['id']} not found — regression"


def test_corpus_fp_cases_not_flagged(corpus_verdicts):
    fps = [v for v in corpus_verdicts if v["kind"] == "fp"]
    assert fps, "corpus has FP cases"
    for v in fps:
        assert not v["found"], f"FP case {v['id']} flagged — false positive regression"


def test_corpus_catches_xss_regression(session, monkeypatch):
    """Proof: if the XSS module regressed to flag any reflection (detect +
    confirm both loosened), the corpus must fail the xss-encoded-fp case."""
    from bugbountybot.vuln import xss as xss_mod

    orig_detect = xss_mod.XSSModule.detect
    orig_confirm = xss_mod.XSSModule.confirm

    def broken_detect(self, response, payload, encoder_chain=None):
        from bugbountybot.vuln.base import DetectionResult

        return DetectionResult(
            signal="reflection", matched=True, detail="regression",
            response=response, payload=payload,
        )

    def broken_confirm(self, candidate):
        from bugbountybot.vuln.base import ConfirmedFinding

        return ConfirmedFinding(
            title="Reflected XSS (broken confirm)", severity="medium",
            detail="regression", url="x", module="xss", cwe="CWE-79",
            cvss="", payload_id="x", request_text="", response_text="", dedup_key="x",
        )

    monkeypatch.setattr(xss_mod.XSSModule, "detect", broken_detect)
    monkeypatch.setattr(xss_mod.XSSModule, "confirm", broken_confirm)
    try:
        verdicts = run_corpus(session)
        encoded_fp = [v for v in verdicts if v["id"] == "xss-encoded-fp"][0]
        assert not encoded_fp["match"], "corpus must catch the XSS regression"
    finally:
        monkeypatch.setattr(xss_mod.XSSModule, "detect", orig_detect)
        monkeypatch.setattr(xss_mod.XSSModule, "confirm", orig_confirm)
