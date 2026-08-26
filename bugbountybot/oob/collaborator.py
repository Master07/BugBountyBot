"""External SSRF collaborator client — interactsh-compatible polling.

When BUGBOUNTY_OOB_BASE_URL is configured (e.g. a self-hosted interactsh, a
reverse-proxied listener, or a public tunnel), the SSRF module templates
{{OOB}} with the external URL and callbacks are confirmed by polling the
collaborator's API — so a REMOTE target can reach the callback, which a
127.0.0.1 listener never could.

Exposes the same interface the SSRF module uses: callback_url(token),
has_callback(token), callbacks_for(token).
"""
from __future__ import annotations

import json
import time
import urllib.parse

import httpx

from bugbountybot.config.settings import OOB_BASE_URL


class CollaboratorClient:
    """Polls an interactsh-compatible collaborator for callbacks by token."""

    def __init__(
        self,
        base_url: str | None = None,
        *,
        poll_interval: float = 1.0,
        poll_timeout: float = 30.0,
        client: httpx.Client | None = None,
    ):
        self.base_url = (base_url or OOB_BASE_URL).rstrip("/")
        self.poll_interval = poll_interval
        self.poll_timeout = poll_timeout
        self._client = client or httpx.Client(timeout=10)
        self._callbacks: dict[str, list[dict]] = {}

    def callback_url(self, token: str) -> str:
        """The externally-reachable URL a target would fetch."""
        return f"{self.base_url}/{token}"

    def _poll(self, token: str) -> list[dict]:
        """Fetch callbacks for a token from the collaborator API."""
        url = f"{self.base_url}/api/v1/interactsh/{urllib.parse.quote(token)}"
        try:
            resp = self._client.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            records = data.get("data", []) if isinstance(data, dict) else data
            return records if isinstance(records, list) else []
        except Exception:
            return []

    def _refresh(self, token: str) -> list[dict]:
        if token not in self._callbacks:
            self._callbacks[token] = []
        # poll until we have callbacks or the timeout elapses
        deadline = time.monotonic() + self.poll_timeout
        while not self._callbacks[token] and time.monotonic() < deadline:
            self._callbacks[token] = self._poll(token)
            if not self._callbacks[token]:
                time.sleep(self.poll_interval)
        return self._callbacks[token]

    def has_callback(self, token: str) -> bool:
        return bool(self._refresh(token))

    def callbacks_for(self, token: str) -> list[dict]:
        self._refresh(token)
        return self._callbacks.get(token, [])

    def close(self):
        self._client.close()
