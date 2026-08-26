"""Provider-agnostic LLM adapter — report drafting, test-plan suggestions.

Calls any OpenAI-compatible endpoint (local Ollama, vLLM, cloud). If no
LLM_BASE_URL is configured, summarization falls back to deterministic text.
Never call a provider directly from vuln modules — go through here.
"""
from __future__ import annotations

import httpx

from bugbountybot.config.settings import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL


class LLMAdapter:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
    ):
        self.base_url = (base_url or LLM_BASE_URL).rstrip("/")
        self.api_key = api_key if api_key is not None else LLM_API_KEY
        self.model = model or LLM_MODEL or "default"

    @property
    def available(self) -> bool:
        return bool(self.base_url)

    def _chat(self, system: str, user: str) -> str:
        if not self.available:
            return ""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        resp = httpx.post(
            f"{self.base_url}/chat/completions",
            json=body,
            headers=headers,
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    def draft_report_intro(self, findings_summary: str) -> str:
        return self._chat(
            "You write concise, professional bug bounty report intros.",
            f"Write a 2-3 sentence executive summary for these findings:\n{findings_summary}",
        )

    def triage_rank(self, findings: list[dict]) -> str:
        """Rank findings by likely payout priority (severity + program context).

        Returns a short deterministic ranking; LLM improves the rationale when
        configured. findings: list of {title, severity, module, url}.
        """
        if not findings:
            return ""
        lines = [
            f"{f.get('severity', 'info').upper():8} {f.get('module', '?')} — {f.get('title', '')}"
            for f in findings
        ]
        if not self.available:
            # Deterministic fallback: severity order, high first.
            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            ordered = sorted(
                findings, key=lambda f: sev_rank.get(f.get("severity", "info"), 5)
            )
            return "Priority order (by severity):\n" + "\n".join(
                f"  {i + 1}. {f['severity'].upper()} {f.get('title', '')}"
                for i, f in enumerate(ordered)
            )
        return self._chat(
            "You are a bug bounty triage assistant. Rank findings by expected payout "
            "priority, considering severity, likely exploitability, and dupe risk. "
            "Return a short numbered list with one-line reasons.",
            "Rank these findings:\n" + "\n".join(lines),
        )

    def suggest_test_plan(self, target: str, module: str) -> str:
        return self._chat(
            "You suggest safe, in-scope security test plans.",
            f"Suggest 3 concrete next test steps for {module} testing on {target}. Keep them non-destructive.",
        )
