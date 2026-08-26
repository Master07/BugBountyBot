"""Encoder chains — applied to payloads before injection. Each encoder is a pure
function; chains are applied left to right, e.g. ["url", "double_url"].
"""
from __future__ import annotations

import base64
import html
import random
from urllib.parse import quote, unquote

_HTML_ENTITY_MAP = {
    "<": "&#60;",
    ">": "&#62;",
    '"': "&#34;",
    "'": "&#39;",
    "&": "&#38;",
}


def url(value: str) -> str:
    return quote(value, safe="")


def double_url(value: str) -> str:
    return quote(quote(value, safe=""), safe="")


def html_entity(value: str) -> str:
    return "".join(_HTML_ENTITY_MAP.get(ch, ch) for ch in value)


def attr_escape(value: str) -> str:
    return value.replace('"', "&quot;").replace("'", "&#39;")


def js_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'")


def unicode_escape(value: str) -> str:
    return "".join(f"\\u{ord(ch):04x}" if ord(ch) > 127 else ch for ch in value)


def base64url(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")


def null_byte(value: str) -> str:
    return value.replace("/", "%00/")


def sql_comment(value: str) -> str:
    return value + " --"


def path_encode(value: str) -> str:
    return value.replace("../", "..%2f").replace("/", "%2f")


def header_fold(value: str) -> str:
    return value.replace("\r\n", "\r\n ")


def case_mutation(value: str) -> str:
    """Randomize letter case while keeping HTML/JS keywords recognizable."""
    return "".join(ch.upper() if random.random() < 0.5 else ch.lower() for ch in value)


ENCODERS = {
    "url": url,
    "double_url": double_url,
    "html_entity": html_entity,
    "attr_escape": attr_escape,
    "js_escape": js_escape,
    "unicode": unicode_escape,
    "base64url": base64url,
    "null_byte": null_byte,
    "sql_comment": sql_comment,
    "path_encode": path_encode,
    "header_fold": header_fold,
    "case": case_mutation,
}


def apply_chain(payload: str, chain: list[str]) -> str:
    """Apply encoders in order. Unknown encoder names are skipped (fail loud via log)."""
    result = payload
    for name in chain:
        encoder = ENCODERS.get(name)
        if encoder is None:
            raise KeyError(f"unknown encoder: {name}")
        result = encoder(result)
    return result
