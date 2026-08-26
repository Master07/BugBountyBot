"""HackerOne program import — fetches structured_scope via the API.

Auth: Basic (username + API token from Settings → API). Credentials come from
env (HACKERONE_USERNAME / HACKERONE_API_TOKEN) or keyring. Never the DB.

Note: the structured_scope endpoint returns in-scope assets only. Programs
that list explicit exclusions in their policy need those added manually with
`program add-scope --out`.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from bugbountybot.importer.secrets import get_hackerone_credentials

API_BASE = "https://api.hackerone.com"
SCOPE_URL = f"{API_BASE}/v1/hackers/programs/{{handle}}/structured_scope"

# asset_type -> (scope kind, is_web)
_KIND_MAP = {
    "WILDCARD": "wildcard",
    "URL": "domain",
    "CIDR": "cidr",
    "IP": "ip",
    "OTHER": "domain",  # ambiguous; keep as domain so the guard still checks it
}
_NON_WEB = {
    "APPLE_APP_STORE",
    "GOOGLE_PLAY_APP_ID",
    "SOURCE_CODE",
    "DOWNLOADABLE_EXECUTABLE",
    "HARDWARE",
    "WINDOWS_STORE",
}


@dataclass
class ImportedAsset:
    identifier: str
    kind: str
    in_scope: bool
    skipped: bool = False
    reason: str = ""


@dataclass
class ImportResult:
    platform: str
    handle: str
    program_name: str = ""
    rules_added: int = 0
    in_scope: int = 0
    out_of_scope: int = 0
    skipped: int = 0
    assets: list[ImportedAsset] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _strip_scheme(identifier: str) -> str:
    return identifier.split("://")[-1].rstrip("/")


def _classify_hackerone(asset_type: str, identifier: str) -> ImportedAsset:
    if asset_type in _NON_WEB:
        return ImportedAsset(identifier, "", in_scope=True, skipped=True, reason=f"non-web asset type {asset_type}")
    kind = _KIND_MAP.get(asset_type, "domain")
    cleaned = _strip_scheme(identifier) if kind == "domain" else identifier
    return ImportedAsset(cleaned, kind, in_scope=True)


def fetch_structured_scope(handle: str, username: str, token: str) -> list[dict]:
    url = SCOPE_URL.format(handle=handle)
    resp = httpx.get(
        url,
        auth=(username, token),
        headers={"Accept": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("data", [])


def parse_structured_scope(data: list[dict]) -> list[ImportedAsset]:
    assets: list[ImportedAsset] = []
    for item in data:
        attrs = item.get("attributes", {})
        identifier = attrs.get("asset_identifier", "")
        asset_type = attrs.get("asset_type", "URL")
        if not identifier:
            continue
        assets.append(_classify_hackerone(asset_type, identifier))
    return assets


def import_hackerone(handle: str) -> ImportResult:
    """Fetch a program's in-scope assets. Raises if no credentials configured."""
    creds = get_hackerone_credentials()
    if not creds:
        raise RuntimeError(
            "HackerOne credentials not configured. Set HACKERONE_USERNAME and "
            "HACKERONE_API_TOKEN (or run `bugbounty program credentials hackerone`)"
        )
    username, token = creds
    result = ImportResult(platform="hackerone", handle=handle)
    try:
        data = fetch_structured_scope(handle, username, token)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            result.errors.append(
                "HackerOne API returned 401 for structured_scope. This token is valid for "
                "public program lists but lacks structured-scope access. Create a new API "
                "token (Settings → API) with the scope that includes program scope/structured "
                "data, and ensure your HackerOne account is a member of the program you're importing."
            )
        else:
            result.errors.append(f"HackerOne API error: {e.response.status_code} {e.response.text[:200]}")
        return result
    except httpx.HTTPError as e:
        result.errors.append(f"HackerOne network error: {e}")
        return result

    result.assets = parse_structured_scope(data)
    for a in result.assets:
        if a.skipped:
            result.skipped += 1
        elif a.in_scope:
            result.in_scope += 1
    result.program_name = handle
    return result
