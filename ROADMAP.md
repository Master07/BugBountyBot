# BugBountyBot Pro — Maturity Roadmap

_Drafted 2026-08-26. Companion to [CORRECTNESS_PLAN.md](CORRECTNESS_PLAN.md) (P0–P3, executed)._
_Goal: turn a safety-gated scanner into a reliable, always-on pentesting + bounty platform._

---

## Strategic thesis (read this first)

Automated reflected-XSS/SQLi against mature programs almost never earns — those
classes are duped and WAF'd. **Automation earns in four places, three of which this
codebase already scaffolds:**

1. **First on new attack surface** — recon diff → untested new asset. (`scheduler` + `recon` + alerts.) **← strongest edge.**
2. **Breadth on huge scopes** — nuclei across thousands of hosts. (`runner/nuclei.py`.)
3. **Fresh-CVE / misconfig / exposure / leaked-secret sweeps.** (Partly there.)
4. **Human-in-the-loop on candidates** — tool surfaces leads, human confirms.

**Direction: stop out-scanning crowded classes; build a monitoring + breadth + triage
machine that feeds human judgment.** Everything below serves that.

---

## Workstreams

### W1 — Detection correctness (credibility)
Every finding class needs a written **confirmation contract**: signal → confirm bar →
required evidence → severity.

- [ ] Per-module **false-positive budget**; disable-by-default if >20% junk on benchmark.
- [ ] Shared **stability/baseline oracle** (same request twice ⇒ same response) before any diff-based confirm (SQLi, IDOR).
- [ ] XSS **reflection-context** detection extended to attribute break-out + JS context.
- [ ] **Statistical confirmation** for time-based signals (N repeats + control), not single-shot.
- [ ] **Derived CVSS/severity** from context, not hardcoded per-module string literals.

### W2 — Coverage that pays (ordered by bounty ROI)
1. [x] **Authenticated IDOR/BOLA with real 2-session diff** (wire two `SessionProfile`s). *Highest-value automatable class.*
2. [x] **Secrets / exposure** — `.git`/`.env`/backups, keys in JS bundles, S3 misconfig.
3. [x] **Subdomain takeover** — CNAME → dangling-service fingerprint (recon already enumerates subs).
4. [x] **SSRF via fixed OOB path** + external collaborator + cloud-metadata confirm. *(`BUGBOUNTY_OOB_BASE_URL` → interactsh-compatible collaborator; local listener still default)*
5. [x] **Auth/session flaws** — JWT alg-none/weak-secret, missing auth on API routes, reset-token issues. *(`jwt` module: alg:none + weak-secret brute; needs --session)*
6. [x] **Business logic** (candidate-only; human-guided) — extend `businesslogic`. *(+auth/cart/signup/coupon categories, 2-session runs, findings_count)*
7. [x] **GraphQL / API authz** — introspection, field-level access. *(`graphql` module)*
- [ ] **Deprioritized:** more XSS/SQLi payloads (diminishing returns).

### W3 — Reliability (safe to leave running)
- [x] **Per-host rate limiter** + honor `Retry-After` + backoff on 429/403. *(#1 gap — ban risk.)*
- [x] **SQLite WAL + `busy_timeout` + write retry** (`serve`/`scheduled`/CLI contend on one DB).
- [x] **Per-request timeout, retry-with-jitter, circuit breaker** — one hung host can't stall a scan.
- [x] **Crash-safe scan runs** — mid-scan failure ⇒ `ScanRun` marked `failed` + partial results, never silent death.
- [ ] **Resumable / idempotent scans** for huge scopes (checkpoint progress).
- [ ] **Externally-reachable OOB** (config URL or interactsh), gated behind explicit approval per [AGENTS.md](AGENTS.md).
- [x] **Bounded worker pool** — controlled parallelism, not unbounded threads.

### W4 — Safety model hardening (wider scope = stricter guard)
- [ ] Scope-guard edge cases: punycode/IDN, trailing dots, ports, userinfo, case, IPv6.
- [ ] **Re-check scope on redirect** — a 302 out of scope must be blocked before following.
- [ ] **SSRF/rebinding safety** — never pivot to RFC1918/link-local unless program allows.
- [ ] **Per-program rate + tier + testing-hours** enforcement from stored policy.
- [ ] **Global kill switch** honored immediately by runner + scheduler.
- [ ] **Scope-guard fuzz test** covering the above.

### W5 — Evidence & reporting (get accepted + paid)
- [ ] **Copy-paste `curl` PoC** in every export (request/response already stored).
- [ ] **Dedup vs. own history + known-CVE** before surfacing/reporting.
- [ ] **Impact narrative** drafted by the LLM adapter **from evidence** (never invented).
- [ ] **Conservative severity self-calibration** (over-claiming hurts platform reputation).
- [ ] **Secret-leak export test** — grep exports/audit/artifacts for session/token markers.

### W6 — Operational maturity (product, not script)
- [x] **CI** (lint + type-check + full suite + **anti-monkeypatch canary**).
- [ ] Dependency pinning + lockfile; reproducible venv. *(ranges pinned in pyproject; lockfile is best-effort)*
- [x] **Structured JSON logging**, separate from the append-only audit log. *(`storage/logging.py`)*
- [x] **Consolidated typed config** (retire scattered `.env` constants). *(`config/settings.py` → typed Settings)*
- [x] **Backups of `data/`** (findings/audit are work product). *(`bugbounty backup`)*
- [x] **Scheduler as a service** (launchd/systemd) for set-and-forget monitoring. *(documented in USER_GUIDE)*

### W7 — Validation (how you *know* it works — foundational)
- [x] **Benchmark target suite** with ground truth: Juice Shop, DVWA, testphp.vulnweb, custom containers. *(fixture server with labeled routes — `benchmark/fixtures/server.py`)*
- [x] **Precision/recall per module** against ground truth (the honest FP-rate — un-measurable on real targets, which have no labels). *(`bugbounty benchmark`; all 5 modules 1.00/1.00/0.00 on the fixture set)*
- [x] **Regression corpus** — every real finding + every FP becomes a permanent fixture. *(`benchmark/fixtures/corpus.yaml` + `run_corpus`; 8 labeled cases incl. real superhuman.com behavior)*
- [x] **Scan-run observability** — duration, requests, blocked, errors, findings-by-status per run. *(crash-safe ScanRun status/error; rate-limiter stats)*

### W8 — Legal / ethical spine (non-negotiable)
- [ ] Scope is law — never add a "test everything" mode.
- [ ] **Authorization record per program** — URL + policy snapshot + accept date.
- [ ] Honor no-DoS / no-destructive; keep Tier 4 dead by default.
- [ ] Never test a host without an active, verified program authorizing that exact host.

---

## Execution sequence

| Phase | Items | Why first |
|-------|-------|-----------|
| **0. Verify** | Confirm P1 (SQLi/redirect/XSS) fixes hold | Don't build on unverified fixes; history shows green tests can lie |
| **1. Measure** | W7 benchmark suite + observability | Can't mature what you can't measure |
| **2. Harden** | W3 rate limiter + WAL + crash-safe | Safe to leave running = definition of reliable |
| **3. Lock** | W6 CI + anti-monkeypatch canary | Regressions can't hide |
| **4. Earn** | W2 #1–3 (2-session IDOR, secrets/exposure, takeover) | The actually-payable classes |
| **5. Monitor** | W6 scheduler-as-service + recon-diff alerts | The "first on new assets" money engine |
| **6. Convert** | W5 curl-PoC + dedup + impact narrative | Findings that get accepted and paid |

---

## Honest bottom line

The path to real bounties is **not** a better XSS scanner. It's a reliable, always-on
**monitoring + breadth + triage system** that surfaces high-signal candidates (new
assets, exposures, takeovers, access-control anomalies) for a human to weaponize —
backed by a benchmark suite that proves every automated claim. Build that; skip the
pile of GET-param payloads.
