"""ReconService — per-program recon runs and queries over the endpoint inventory."""
from __future__ import annotations

from sqlalchemy.orm import Session

from bugbountybot.recon.pipeline import ReconResult, run_recon
from bugbountybot.storage.db import Endpoint


class ReconService:
    def __init__(self, session: Session):
        self.session = session

    def run(self, program_id: int, tools: list[str] | None = None, wordlist: str = "") -> ReconResult:
        return run_recon(self.session, program_id, tools=tools, wordlist=wordlist)

    def list_recon_endpoints(self, program_id: int) -> list[Endpoint]:
        return (
            self.session.query(Endpoint)
            .filter(Endpoint.program_id == program_id, Endpoint.source == "recon")
            .order_by(Endpoint.id)
            .all()
        )

    def list_all_endpoints(self, program_id: int) -> list[Endpoint]:
        return (
            self.session.query(Endpoint)
            .filter(Endpoint.program_id == program_id)
            .order_by(Endpoint.id)
            .all()
        )
