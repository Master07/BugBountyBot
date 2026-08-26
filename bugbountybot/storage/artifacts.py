"""Artifact store — request/response pairs, OOB callbacks, screenshots, notes.

Files live under data/artifacts/ as flat uuid-named files; the DB row links
them to a finding. Never write secrets into artifact content.
"""
from __future__ import annotations

import uuid
from pathlib import Path


class ArtifactStore:
    def __init__(self, data_dir: str | Path):
        self.root = Path(data_dir) / "artifacts"
        self.root.mkdir(parents=True, exist_ok=True)

    def save_bytes(self, content: bytes, suffix: str = ".bin") -> str:
        """Write raw bytes, return the artifact-relative path."""
        name = f"{uuid.uuid4().hex}{suffix}"
        (self.root / name).write_bytes(content)
        return f"artifacts/{name}"

    def save_text(self, content: str, suffix: str = ".txt") -> str:
        return self.save_bytes(content.encode("utf-8"), suffix=suffix)

    def read(self, relative_path: str) -> bytes:
        return (self.root / Path(relative_path).name).read_bytes()

    def save_request_response(
        self, request_text: str, response_text: str
    ) -> str:
        """Save a request/response pair as one text file, return relative path."""
        body = f"=== REQUEST ===\n{request_text}\n\n=== RESPONSE ===\n{response_text}\n"
        return self.save_text(body, suffix=".http")
