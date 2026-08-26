"""Bugcrowd program import — fetches the public program brief JSON.

Bugcrowd exposes a public JSON with target/scope info per program at
https://bugcrowd.com/{code}.json — no auth required. The JSON shape varies by
program; this parser handles the common `targets[]` structure.
"""
from __future__ import annotations

import httpx

from bugbountybot.importer.hackerone import ImportResult, ImportedAsset

API_BASE = "https://bugcrowd.com"
_BASE_URL = f"{API_BASE}/{{code}}.json"


def fetch_bugcrowd_json(code: str) -> dict:
    resp = httpx.get(_BASE_URL.format(code=code), timeout=30, follow_redirects=True)
    resp.raise_for_status()
    return resp.json()


def _classify(identifier: str, in_scope: bool) -> ImportedAsset:
    cleaned = identifier.strip()
    if not cleaned:
        return ImportedAsset(cleaned, "domain", in_scope, skipped=True, reason="empty identifier")
    if "/" in cleaned and not cleaned.startswith(("*", "http")):
        # e.g. "10.0.0.0/24"
        return ImportedAsset(cleaned, "cidr", in_scope)
    if cleaned.startswith("*"):
        return ImportedAsset(cleaned, "wildcard", in_scope)
    if cleaned.startswith("http"):
        return ImportedAsset(cleaned.split("://")[-1].rstrip("/"), "domain", in_scope)
    return ImportedAsset(cleaned, "domain", in_scope)


def parse_bugcrowd_json(data: dict) -> list[ImportedAsset]:
    assets: list[ImportedAsset] = []
    targets = data.get("targets", [])
    if isinstance(targets, dict):
        targets = [targets]
    for target in targets:
        if not isinstance(target, dict):
            continue
        for section, in_scope in (("in_scope", True), ("out_of_scope", False)):
            items = target.get(section, []) or []
            for item in items:
                identifier = item.get("target") if isinstance(item, dict) else str(item)
                assets.append(_classify(identifier, in_scope=in_scope))
    return assets


def import_bugcrowd(code: str) -> ImportResult:
    result = ImportResult(platform="bugcrowd", handle=code)
    try:
        data = fetch_bugcrowd_json(code)
    except httpx.HTTPStatusError as e:
        result.errors.append(f"Bugcrowd fetch error: {e.response.status_code}")
        return result
    except httpx.HTTPError as e:
        result.errors.append(f"Bugcrowd network error: {e}")
        return result

    result.assets = parse_bugcrowd_json(data)
    for a in result.assets:
        if a.skipped:
            result.skipped += 1
        elif a.in_scope:
            result.in_scope += 1
        else:
            result.out_of_scope += 1
    result.program_name = data.get("name") or code
    return result
