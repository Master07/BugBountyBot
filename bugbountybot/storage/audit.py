"""Append-only audit log. Rows are never updated or deleted — the guard blocks SQLAlchemy
update/delete on AuditEntry by construction (callers only use add()).
"""
from __future__ import annotations

import hashlib

from sqlalchemy.orm import Session

from bugbountybot.storage.db import AuditEntry


def _payload_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_request(
    session: Session,
    *,
    url: str,
    payload: str = "",
    tier: int = 1,
    scope_snapshot: str = "",
    allowed: bool = True,
    reason: str = "",
) -> AuditEntry:
    """Record one request attempt. Allowed=False marks a scope-guard block."""
    entry = AuditEntry(
        url=url,
        payload_hash=_payload_hash(payload),
        tier=tier,
        scope_snapshot=scope_snapshot,
        allowed=allowed,
        reason=reason,
    )
    session.add(entry)
    from bugbountybot.storage.db import with_retry

    with_retry(session.commit)
    return entry


def recent(session: Session, limit: int = 50) -> list[AuditEntry]:
    return (
        session.query(AuditEntry)
        .order_by(AuditEntry.id.desc())
        .limit(limit)
        .all()
    )
