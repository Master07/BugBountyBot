"""Config — typed Settings loaded from .env once.

Secrets (API keys) come from env vars only; never from code or the DB.
Module-level attrs (DATA_DIR, PAYLOADS_DIR, LLM_*, RECON_TOOLS, OOB_BASE_URL)
are kept for backward compat and read from the singleton.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("BUGBOUNTY_DATA_DIR", PROJECT_ROOT / "data")))
    payloads_dir: Path = field(default_factory=lambda: Path(os.getenv("BUGBOUNTY_PAYLOADS_DIR", PROJECT_ROOT / "payloads")))
    backup_dir: str = field(default_factory=lambda: os.getenv("BUGBOUNTY_BACKUP_DIR", ""))

    llm_base_url: str = field(default_factory=lambda: os.getenv("LLM_BASE_URL", ""))
    llm_api_key: str = field(default_factory=lambda: os.getenv("LLM_API_KEY", ""))
    llm_model: str = field(default_factory=lambda: os.getenv("LLM_MODEL", ""))

    recon_tools: dict = field(
        default_factory=lambda: {
            "subfinder": os.getenv("BUGBOUNTY_SUBFINDER", "subfinder"),
            "httpx": os.getenv("BUGBOUNTY_HTTPX", "httpx"),
            "katana": os.getenv("BUGBOUNTY_KATANA", "katana"),
            "gau": os.getenv("BUGBOUNTY_GAU", "gau"),
            "ffuf": os.getenv("BUGBOUNTY_FFUF", "ffuf"),
        }
    )

    oob_base_url: str = field(default_factory=lambda: os.getenv("BUGBOUNTY_OOB_BASE_URL", ""))


_settings: Settings | None = None


def get_settings() -> Settings:
    """Typed settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


# Backward-compat module attrs (read from the singleton).
_s = get_settings()
DATA_DIR = _s.data_dir
PAYLOADS_DIR = _s.payloads_dir
LLM_BASE_URL = _s.llm_base_url
LLM_API_KEY = _s.llm_api_key
LLM_MODEL = _s.llm_model
RECON_TOOLS = _s.recon_tools
OOB_BASE_URL = _s.oob_base_url
BACKUP_DIR = _s.backup_dir
