"""Built-in mutators — structural variations applied automatically or via --mutate.

Each mutator takes a payload string and returns one or more variants. Variants
are capped to avoid combinatorial blowup.
"""
from __future__ import annotations

import random
import unicodedata

VARIANT_CAP = 8


def case_toggle(value: str) -> list[str]:
    variants: set[str] = set()
    for _ in range(4):
        variants.add(
            "".join(
                ch.upper() if random.random() < 0.5 else ch.lower() for ch in value
            )
        )
    return list(variants)


def inline_comment(value: str) -> list[str]:
    """Insert HTML comment markers inside tag names: <scr<!-- -->ipt>"""
    variants: list[str] = []
    for tag in ("script", "img", "svg", "iframe", "body"):
        if tag in value:
            split = tag[:3]
            variants.append(value.replace(tag, f"{split}<!-- -->{tag[3:]}", 1))
    return variants


def whitespace(value: str) -> list[str]:
    return [
        value.replace(" ", "\t"),
        value.replace(" ", "\n"),
        value.replace(" ", "\r\n"),
    ]


def double_encode(value: str) -> list[str]:
    from bugbountybot.payloads.encoders import double_url, url

    return [url(value), double_url(value)]


def unicode_normalize(value: str) -> list[str]:
    """NFKC normalization bypass: fullwidth chars look like ASCII after normalize."""
    full = {
        "a": "ａ", "b": "ｂ", "c": "ｃ", "s": "ｓ", "i": "ｉ", "p": "ｐ", "t": "ｔ",
        "r": "ｒ", "e": "ｅ", "v": "ｖ", "l": "ｌ", "o": "ｏ", "n": "ｎ", "g": "ｇ",
        "<": "＜", ">": "＞", "'": "＇", '"': "＂", "/": "／",
    }
    return ["".join(full.get(ch, ch) for ch in value)]


def null_byte_insert(value: str) -> list[str]:
    return [value.replace("/", "/%00", 1)] if "/" in value else []


def param_pollution(value: str) -> list[str]:
    """Duplicate-key variant for HTTP parameter pollution testing."""
    return [f"{value}&{value}"]


def apply_mutators(payload: str, names: list[str]) -> list[str]:
    """Apply each named mutator; returns a flat, deduplicated variant list."""
    registry = {
        "case": case_toggle,
        "comment": inline_comment,
        "whitespace": whitespace,
        "double_encode": double_encode,
        "unicode": unicode_normalize,
        "null_byte": null_byte_insert,
        "param_pollution": param_pollution,
    }
    variants = {payload}
    for name in names:
        fn = registry.get(name)
        if fn is None:
            raise KeyError(f"unknown mutator: {name}")
        variants.update(fn(payload))
    return list(variants)[:VARIANT_CAP]
