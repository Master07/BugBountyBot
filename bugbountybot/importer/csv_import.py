"""CSV scope import — a simple, platform-agnostic way to onboard a program.

CSV columns: pattern,kind,in_scope
  - pattern: domain / wildcard / ip / cidr
  - kind: domain|wildcard|ip|cidr
  - in_scope: true|false (empty = true)

Example:
    acme.com,domain,true
    *.acme.com,wildcard,true
    admin.acme.com,domain,false
"""
from __future__ import annotations

import csv
from pathlib import Path

from bugbountybot.importer.hackerone import ImportResult, ImportedAsset

VALID_KINDS = {"domain", "wildcard", "ip", "cidr"}


def parse_csv(path: str | Path) -> list[ImportedAsset]:
    assets: list[ImportedAsset] = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if not row or row[0].strip().startswith("#"):
                continue
            if len(row) < 2:
                continue
            pattern = row[0].strip()
            kind = (row[1] or "domain").strip().lower()
            in_scope = row[2].strip().lower() != "false" if len(row) > 2 else True
            if kind not in VALID_KINDS:
                assets.append(ImportedAsset(pattern, kind, in_scope, skipped=True, reason=f"unknown kind {kind}"))
                continue
            assets.append(ImportedAsset(pattern, kind, in_scope))
    return assets


def import_csv(path: str | Path, program_name: str) -> ImportResult:
    result = ImportResult(platform="csv", handle=str(path), program_name=program_name)
    try:
        result.assets = parse_csv(path)
    except FileNotFoundError:
        result.errors.append(f"file not found: {path}")
        return result
    for a in result.assets:
        if a.skipped:
            result.skipped += 1
        elif a.in_scope:
            result.in_scope += 1
        else:
            result.out_of_scope += 1
    return result
