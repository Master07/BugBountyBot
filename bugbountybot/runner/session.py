"""Authenticated session profiles — cookies + headers for scanning.

Sessions live in the local DB only. They are never written to the audit log,
reports, or evidence — the audit stays URL + tier + hash so secrets can't leak.
"""
from __future__ import annotations

import json

from sqlalchemy.orm import Session

from bugbountybot.storage.db import SessionProfile


def parse_cookie_string(cookies: str) -> dict:
    """Parse 'k=v; k2=v2' into a dict."""
    out: dict[str, str] = {}
    for part in cookies.split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            if k:
                out[k.strip()] = v.strip()
    return out


def parse_header_lines(headers: str) -> dict:
    """Parse 'Name: value' lines (one per line or '; ' separated) into a dict."""
    out: dict[str, str] = {}
    for line in headers.replace(";", "\n").splitlines():
        if ":" in line:
            k, _, v = line.strip().partition(":")
            if k:
                out[k.strip()] = v.strip()
    return out


def add_session(
    session: Session,
    program_id: int,
    *,
    name: str = "default",
    cookies: str = "",
    headers: str = "",
) -> SessionProfile:
    profile = SessionProfile(
        program_id=program_id,
        name=name,
        cookies_json=json.dumps(parse_cookie_string(cookies)),
        headers_json=json.dumps(parse_header_lines(headers)),
    )
    session.add(profile)
    session.commit()
    return profile


def list_sessions(session: Session, program_id: int | None = None) -> list[SessionProfile]:
    q = session.query(SessionProfile)
    if program_id is not None:
        q = q.filter(SessionProfile.program_id == program_id)
    return q.order_by(SessionProfile.id).all()


def get_session(session: Session, profile_id: int) -> SessionProfile | None:
    return session.get(SessionProfile, profile_id)


def profile_cookies(profile: SessionProfile) -> dict:
    try:
        return json.loads(profile.cookies_json or "{}")
    except json.JSONDecodeError:
        return {}


def profile_headers(profile: SessionProfile) -> dict:
    try:
        return json.loads(profile.headers_json or "{}")
    except json.JSONDecodeError:
        return {}
