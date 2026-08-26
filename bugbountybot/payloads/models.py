"""Payload record — the unit of data the Payload Engine loads and the Vuln Engine injects."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Payload:
    id: str
    category: str
    subcategory: str = ""
    context: list[str] = field(default_factory=list)
    tier: int = 2
    tags: list[str] = field(default_factory=list)
    payload: str = ""
    encoders: list[str] = field(default_factory=list)
    detection: dict = field(default_factory=dict)
    source: str = "builtin"
    enabled: bool = True

    @property
    def is_tier4(self) -> bool:
        return self.tier >= 4
