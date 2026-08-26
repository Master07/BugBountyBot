"""Shared test fixtures."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from bugbountybot.storage.artifacts import ArtifactStore
from bugbountybot.storage.db import init_db
from bugbountybot.tracker import service as tracker


@pytest.fixture()
def data_dir(tmp_path: Path) -> Path:
    return tmp_path / "data"


@pytest.fixture()
def session(data_dir: Path) -> Session:
    from sqlalchemy import create_engine

    # register all sub-package models before create_all
    import bugbountybot.businesslogic.models  # noqa: F401
    import bugbountybot.scheduler.models  # noqa: F401
    from bugbountybot.storage.db import Base

    data_dir.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{data_dir / 'bugbounty.db'}")
    Base.metadata.create_all(engine)
    from sqlalchemy.orm import sessionmaker

    s = sessionmaker(bind=engine)()
    yield s
    s.close()
    engine.dispose()


@pytest.fixture()
def artifacts(data_dir: Path) -> ArtifactStore:
    return ArtifactStore(data_dir)


@pytest.fixture()
def program(session: Session):
    return tracker.add_program(
        session,
        "acme",
        platform="hackerone",
        url="https://acme.com",
        allowed_tiers="1,2",
    )


@pytest.fixture()
def scoped_program(session: Session, program):
    tracker.add_scope(session, program.id, "acme.com", kind="domain")
    tracker.add_scope(session, program.id, "*.acme.com", kind="wildcard")
    tracker.add_scope(session, program.id, "10.0.0.0/8", kind="cidr")
    return program
