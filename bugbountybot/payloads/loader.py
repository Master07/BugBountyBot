"""Payload loader — reads payload libraries from YAML/JSON records and plain-text
files under payloads/. Plain .txt files become one payload per non-comment line.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from bugbountybot.payloads.models import Payload

COMMENT_PREFIXES = ("#", "//", "<!--")


def _parse_line_file(path: Path, category: str, subcategory: str, default_tier: int) -> list[Payload]:
    payloads: list[Payload] = []
    for i, raw in enumerate(path.read_text(encoding="utf-8").splitlines()):
        line = raw.strip()
        if not line or line.startswith(COMMENT_PREFIXES):
            continue
        pid = f"{category}-{subcategory or 'misc'}-{i + 1:04d}"
        payloads.append(
            Payload(
                id=pid,
                category=category,
                subcategory=subcategory,
                payload=line,
                tier=default_tier,
                source=f"file:{path.name}",
            )
        )
    return payloads


def _parse_record(path: Path) -> list[Payload]:
    """YAML/JSON record files: either a list of payload records or a single record."""
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) if path.suffix in (".yaml", ".yml") else json.loads(text)
    records = data if isinstance(data, list) else [data]
    payloads: list[Payload] = []
    for i, rec in enumerate(records):
        pid = rec.get("id") or f"{rec.get('category', 'misc')}-{i + 1:05d}"
        payloads.append(
            Payload(
                id=pid,
                category=rec.get("category", path.parent.name),
                subcategory=rec.get("subcategory", ""),
                context=rec.get("context", []),
                tier=rec.get("tier", 2),
                tags=rec.get("tags", []),
                payload=rec.get("payload", ""),
                encoders=rec.get("encoders", []),
                detection=rec.get("detection", {}),
                source=rec.get("source", f"file:{path.name}"),
                enabled=rec.get("enabled", True),
            )
        )
    return payloads


def load_directory(payloads_dir: str | Path, categories: list[str] | None = None) -> list[Payload]:
    """Load every payload file under payloads_dir (optionally only given categories).

    Disabled (Tier 4) payloads are still loaded with enabled=False so the engine
    can see them but never inject them.
    """
    root = Path(payloads_dir)
    loaded: list[Payload] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in (".yaml", ".yml", ".json", ".txt"):
            continue
        category = path.relative_to(root).parts[0]
        if categories and category not in categories:
            continue
        if path.suffix in (".yaml", ".yml", ".json"):
            loaded.extend(_parse_record(path))
        else:
            subcategory = path.parent.name if path.parent != root else ""
            if subcategory == category or subcategory == "wordlists":
                subcategory = ""
            loaded.extend(_parse_line_file(path, category, subcategory, default_tier=2))
    return loaded


class PayloadLibrary:
    """In-memory cache of loaded payloads with query helpers."""

    def __init__(self, payloads: list[Payload] | None = None):
        self._payloads = payloads or []

    @classmethod
    def from_directory(cls, payloads_dir: str | Path, categories: list[str] | None = None):
        return cls(load_directory(payloads_dir, categories=categories))

    @property
    def all(self) -> list[Payload]:
        return self._payloads

    def by_category(self, category: str) -> list[Payload]:
        return [p for p in self._payloads if p.category == category]

    def by_context(self, context: str) -> list[Payload]:
        return [p for p in self._payloads if context in p.context]

    def search(self, needle: str) -> list[Payload]:
        needle_l = needle.lower()
        return [
            p
            for p in self._payloads
            if needle_l in p.payload.lower() or needle_l in p.tags or needle_l in p.id
        ]

    def by_tier(self, max_tier: int) -> list[Payload]:
        return [p for p in self._payloads if p.tier <= max_tier and p.enabled]

    def count(self) -> int:
        return len(self._payloads)
