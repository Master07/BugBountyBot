"""Context-aware payload selection — picks the right payloads for an injection
point's context (html_body, attribute, js_string, sql_string, json_value, ...).
"""
from __future__ import annotations

from bugbountybot.payloads.models import Payload


def select_for_context(
    library,
    category: str,
    context: str,
    *,
    max_tier: int = 2,
    limit: int | None = None,
) -> list[Payload]:
    """Select enabled payloads matching a category+context within a max tier.

    Falls back to category-only when no context-tagged payloads exist for the
    category (plain-text payloads carry no context tags).
    """
    candidates = [
        p
        for p in library.by_category(category)
        if p.enabled and p.tier <= max_tier
    ]
    contextual = [p for p in candidates if context in p.context]
    picked = contextual or candidates
    if limit:
        picked = picked[:limit]
    return picked
