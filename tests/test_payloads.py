"""Payload Engine unit tests."""
from __future__ import annotations

from bugbountybot.payloads.encoders import apply_chain
from bugbountybot.payloads.loader import PayloadLibrary, load_directory
from bugbountybot.payloads.mutators import apply_mutators
from bugbountybot.payloads.selectors import select_for_context


def test_load_directory_finds_payloads():
    lib = PayloadLibrary.from_directory("payloads")
    assert lib.count() > 0
    assert len(lib.by_category("xss")) > 0


def test_encoder_chain_url():
    from bugbountybot.payloads.encoders import url

    assert url("<script>alert(1)</script>") == "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"


def test_apply_chain_unknown_encoder_fails():
    import pytest

    with pytest.raises(KeyError):
        apply_chain("x", ["nope"])


def test_mutators_produce_variants():
    variants = apply_mutators("<script>alert(1)</script>", ["case", "comment"])
    assert len(variants) >= 1
    assert "<script>alert(1)</script>" in variants


def test_selector_context_fallback():
    lib = PayloadLibrary.from_directory("payloads")
    picked = select_for_context(lib, "xss", "html_body", max_tier=2, limit=3)
    assert len(picked) <= 3
    assert all(p.category == "xss" for p in picked)
