# AGENTS.md — BugBountyBot Pro

Project-specific rules. The global rules at `~/.commandcode/AGENTS.md` still apply; where they conflict, the stricter rule wins.

## Mission

Build a local, single-user bug bounty agent: program tracking, scoped security testing, payload engine, evidence-backed reporting. Personal use only.

## Security Rules (non-negotiable)

- **Only test in-scope targets.** Every request must pass Scope Guard before execution. Out-of-scope domains, IPs, third-party assets, and CDN edges not in scope are blocked.
- **Tier gating.** T1/T2 run automatically with rate limits. T3 (exploit confirmation) requires explicit `--confirm`. T4 (brute-force, DoS, data destruction, mass enumeration) is blocked by default; only enable per-program, per-session, with explicit user approval.
- **No auto-submit.** Reports are drafts for human review only. Never submit to HackerOne/Bugcrowd/etc. automatically.
- **Secrets stay local.** API keys, tokens, and credentials live in Keychain (via `keyring`) or `.env` (gitignored). Never write secrets to code, tests, logs, commits, or the SQLite DB.
- **Destructive payloads are disabled by default.** Payload files marked Tier 4 ship with `enabled: false`.
- **Respect target rules.** Honor program-specific restrictions: no DoS, no social engineering, no mass enumeration, respect rate limits.
- **Audit everything.** Every request goes to the append-only audit log: URL, payload hash, tier, timestamp, scope snapshot. Never edit or delete audit entries.

## Engineering Rules

- **Read before write.** Read the file, its callers, and shared utilities before modifying. Cite `file:line` for public-surface changes.
- **Surgical changes.** Only what the task requires. Match existing style. No drive-by refactors, no unsolicited logging or comments.
- **One pattern.** When conventions conflict, pick one and say why in one sentence. Don't blend.
- **Tests encode intent.** A test that passes while the business rule is broken is wrong. Lock the *why*, not just the shape.
- **Fixed scope.** Mid-task expansion needs explicit agreement. No "while I was in there."
- **Fail loud.** No silent skips, mocks, or `xfail`. Cite the verification command and its output.
- **Checkpoint after each unit.** State: Done / Verified by / Next. Restart rather than sprawl.

## Architecture Constraints

- SQLite + local files are the source of truth. Data lives under `data/` (gitignored).
- Vuln modules implement the `VulnModule` interface in `bugbountybot/vuln/base.py` — one file per vuln class.
- Payloads are data files under `payloads/`, loaded by the Payload Engine. Never hardcode payloads in module code.
- External tools run through subprocess adapters only — explicit binary path, flags, timeout, rate limit. Never shell out with unsanitized input.
- The OOB listener binds to localhost only. Never expose it beyond 127.0.0.1 without explicit user approval.
- LLM access goes through the provider-agnostic adapter in `bugbountybot/agent/`. Never call a provider directly from modules.
