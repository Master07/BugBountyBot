"""Import service — turns a platform ImportResult into program + scope rows.

Creates the program if missing (updates name/platform if present), then upserts
scope rules: in-scope rows are added; out-of-scope rows are added as --out
rules so the guard blocks them even if a broader in-scope rule matches.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from bugbountybot.importer.hackerone import ImportResult
from bugbountybot.storage.db import Program, ScopeRule
from bugbountybot.tracker.service import get_program


def apply_import(session: Session, result: ImportResult, *, program_name: str | None = None) -> ImportResult:
    """Persist an import result. Returns the result with rules_added set."""
    if result.errors:
        return result

    name = program_name or result.program_name or result.handle
    program = get_program(session, name)
    if program is None:
        program = Program(name=name, platform=result.platform, url="")
        session.add(program)
        session.flush()
    elif not program.platform:
        program.platform = result.platform
        session.flush()

    existing = {
        (r.pattern, r.kind) for r in session.query(ScopeRule).filter(ScopeRule.program_id == program.id).all()
    }
    added = 0
    for asset in result.assets:
        if asset.skipped or not asset.identifier:
            continue
        key = (asset.identifier, asset.kind)
        if key in existing:
            continue
        session.add(
            ScopeRule(
                program_id=program.id,
                pattern=asset.identifier,
                kind=asset.kind,
                in_scope=asset.in_scope,
            )
        )
        existing.add(key)
        added += 1
    session.commit()
    result.rules_added = added
    result.out_of_scope = sum(1 for a in result.assets if not a.skipped and not a.in_scope)
    return result
