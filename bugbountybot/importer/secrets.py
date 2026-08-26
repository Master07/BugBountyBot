"""Secrets access for platform APIs — keyring first, env vars fallback.

Never store credentials in the DB or code. HackerOne uses Basic auth
(username + API token); Bugcrowd's public program JSON needs no auth.
"""
from __future__ import annotations

import os

import keyring

SERVICE = "bugbountybot"


def get_hackerone_credentials() -> tuple[str, str] | None:
    """Return (username, api_token) from env or keyring, or None."""
    username = os.getenv("HACKERONE_USERNAME") or keyring.get_password(SERVICE, "hackerone_username")
    token = os.getenv("HACKERONE_API_TOKEN") or keyring.get_password(SERVICE, "hackerone_token")
    if not username or not token:
        return None
    return username, token


def set_hackerone_credentials(username: str, token: str):
    keyring.set_password(SERVICE, "hackerone_username", username)
    keyring.set_password(SERVICE, "hackerone_token", token)
