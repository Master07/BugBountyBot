# BugBounty Bot Pro — HackerOne & Bugcrowd Usage Guide

A practical, platform-focused guide: how to use this tool from the day you join a
HackerOne or Bugcrowd program — from onboarding a program, through recon, testing,
to generating a submission-ready report draft and tracking the payout.

> **The safety model is non-negotiable and built in:** the tool only ever tests
> hosts you have explicitly declared in scope. Anything else is blocked and
> audit-logged. Reports are drafts only — **nothing is ever auto-submitted.**
> You always copy the draft into HackerOne/Bugcrowd yourself.

---

## 0. First-time setup

```bash
cd ~/BugBountyBot
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/bugbounty --help
```

Everything is stored locally:

| What | Where |
|------|-------|
| SQLite DB (programs, findings, submissions, audit log) | `data/bugbounty.db` |
| Evidence artifacts (request/response pairs, OOB callbacks) | `data/artifacts/` |
| Payload library | `payloads/` |
| Secrets (API keys) | Keychain via `keyring`, or `.env` — never in the DB |

**Two ways to use the tool — pick one (or both):**

- **Web dashboard (recommended)** — `.venv/bin/bugbounty serve` → open `http://127.0.0.1:8787`
- **CLI** — `.venv/bin/bugbounty <command>`

The UI and CLI share the same engine, DB, scope guard, and safety model.

---

## 1. Onboarding a program (HackerOne or Bugcrowd)

### 1.1 Import the program's scope automatically

The tool fetches a program's scope from the platform so you don't hand-type it.

**HackerOne** — needs API credentials (username + token from HackerOne → Settings → API):

```bash
# store credentials once (saved in your system keychain)
.venv/bin/bugbounty program credentials hackerone

# import a program by its handle (the URL slug, e.g. "security")
.venv/bin/bugbounty program import acme --platform hackerone --handle security
```

**Bugcrowd** — public brief JSON, no credentials needed:

```bash
.venv/bin/bugbounty program import acme --platform bugcrowd --handle acme
```

**CSV** — any scope table exported to a file:

```bash
# columns: pattern,kind,in_scope  (kind: domain|wildcard|ip|cidr; in_scope: true|false)
.venv/bin/bugbounty program import acme --platform csv --csv ~/scope.csv
```

**From the dashboard:** Programs → "⇩ Import from Platform" → pick HackerOne/Bugcrowd/CSV → enter handle/path.

> **Important:** HackerOne's API returns in-scope assets only. If the program's
> policy text lists explicit exclusions, add them manually with `--out` (or the
> dashboard's scope form with "in scope: no"). Bugcrowd's out-of-scope section
> is imported automatically.

### 1.2 Verify and adjust scope

```bash
.venv/bin/bugbounty program show acme
```

Add any missing rules by hand:

```bash
.venv/bin/bugbounty program add-scope acme "*.acme.com" --kind wildcard
.venv/bin/bugbounty program add-scope acme "admin.acme.com" --kind domain --out
```

### 1.3 Respect the program's rules

Check the platform page for: no DoS, no social engineering, no mass enumeration,
no brute-force, rate limits, "use test accounts only" clauses. The tool enforces
tiers (see §4), but reading the program policy is your responsibility.

---

## 2. Recon — find the attack surface

Recon discovers subdomains → live hosts → endpoints + params automatically, and
stores them in the DB (scope-gated). This is what makes scans cover **real**
attack surface instead of just the URLs you type.

```bash
# install the tools once (any missing tool is skipped and reported)
brew install subfinder httpx katana gau ffuf

# run recon for a program (all available tools)
.venv/bin/bugbounty scan recon acme

# limit to specific tools, or supply a wordlist for ffuf
.venv/bin/bugbounty scan recon acme --tools subfinder,httpx
.venv/bin/bugbounty scan recon acme --wordlist ~/tools/wordlist.txt

# see the endpoint inventory
.venv/bin/bugbounty scan list acme
.venv/bin/bugbounty scan list acme --source recon
```

**Dashboard:** Recon screen → pick program + tools → Run Recon. Shows hosts
discovered, live hosts, new endpoints, blocked (out-of-scope), and per-tool
availability. The endpoint inventory table is right below.

> Every discovered host is checked against the scope guard before it's probed or
> stored. Out-of-scope subdomains are dropped and audit-logged as BLOCK — this is
> the safety net for wildcard scope drift.

---

## 3. Run scans

### 3.1 Manual endpoint registration (optional)

Recon fills the inventory, but you can add endpoints by hand too:

```bash
.venv/bin/bugbounty scan discover acme "https://api.acme.com/search" --params "q,page"
```

### 3.2 Safe scan (tier 2)

```bash
.venv/bin/bugbounty vuln run \
  --program acme \
  --modules xss,sqli,redirect,cors \
  --target "https://api.acme.com/search?q=test" \
  --tier 2
```

**What each MVP module does:**

| Module | Tests | Notes |
|--------|-------|-------|
| `xss` | Reflected XSS via param reflection | confirm re-injects a full script tag into the flagged param |
| `sqli` | Error-based + boolean-diff probes | safe probes only; sqlmap is manual confirm |
| `idor` | Path/query ID substitution (e.g. `/users/12345` → `/users/2`) | **candidate** — needs manual 2-account confirm before reporting |
| `redirect` | Open redirect on redirect-ish params (`url`, `next`, `return_url`...) | checks Location header |
| `cors` | Sends attacker `Origin` header, checks ACAO reflection/credentials | |
| `ssrf` | OOB callback via local listener | tier 3 — needs `--confirm` **and** OOB listener |

### 3.3 Tier-3 confirm + SSRF (from the dashboard)

SSRF needs the OOB listener running **and** `--confirm`. From the **Run Scan**
screen: set the OOB port (default 8080), click **Start OOB**, tick
**--confirm**, and run the scan with `ssrf` in the modules. The scan reuses the
listener you started; you can stop it after.

CLI equivalent:

```bash
# terminal 1
.venv/bin/bugbounty oob start --port 8080
# terminal 2
.venv/bin/bugbounty vuln run --program acme --modules ssrf \
  --target "https://api.acme.com/fetch?url=..." --tier 3 --confirm --oob 8080
```

A confirmed SSRF is one where the target actually fetched the listener's callback
URL — recorded as evidence.

---

## 4. Review findings & triage

```bash
.venv/bin/bugbounty finding list --program acme
.venv/bin/bugbounty finding show 1
```

**Dashboard — Findings screen:** click any finding to open the detail modal,
where you can:

- change **status** (candidate → confirmed → in_report → submitted → accepted/rejected)
- change **severity**
- view **evidence** inline (request/response pairs — click the evidence kind)
- generate a **report draft** for just that finding

---

## 5. Track submissions & payouts

**Dashboard — Submissions screen:** new submission, filter by program, edit
status (`draft → submitted → triaged → accepted/rejected → paid`) and payout.

```bash
.venv/bin/bugbounty submission new acme "Reflected XSS on api.acme.com/search"
.venv/bin/bugbounty submission list acme
.venv/bin/bugbounty submission update 1 submitted
.venv/bin/bugbounty submission update 1 paid
```

---

## 6. Generate report drafts

```bash
# single finding
.venv/bin/bugbounty report generate 3 --template hackerone

# all findings for a program
.venv/bin/bugbounty report generate --program acme --template hackerone
.venv/bin/bugbounty report generate --program acme --template bugcrowd
.venv/bin/bugbounty report generate --program acme --template markdown
```

**Dashboard — Report screen:** pick program + template, see stats cards (findings
by severity, submissions by status, total payout, dupe signal), then generate and
preview inline.

The draft includes severity, CWE, CVSS 3.1 vector, OWASP ASVS reference, and
finding detail. **Copy it into the platform manually.** Internal payload IDs and
artifact paths are stripped from the export.

---

## 7. The dashboard at a glance

| Screen | What you can do |
|--------|-----------------|
| **Dashboard** | stats: programs, findings, payloads, submissions, scope-guard blocks |
| **Programs** | add program, import from platform, add scope rules (in/out), endpoints |
| **Recon** | run discovery, per-tool availability, endpoint inventory |
| **Findings** | list, detail, status/severity editor, evidence, per-finding report |
| **Submissions** | new, filter by program, status + payout |
| **Run Scan** | modules, tier, --confirm, OOB start/stop/status, live results |
| **Report** | stats cards, template, generate + preview |
| **Payloads** | browse/search the 163 built-in payloads |
| **Audit Log** | append-only request log with allow/block flags |
| **Alerts** | new-asset alerts, recon results, mark-read; unread count in the sidebar |

## 8. Scheduled re-recon & alerts (the first-bounty play)

Platforms rotate scope constantly — new in-scope assets nobody has tested are the
easiest bounties. The scheduler re-runs recon per program on an interval and
records alerts when new endpoints appear.

```bash
# run the scheduler in its own terminal (alongside bugbounty serve)
.venv/bin/bugbounty scheduled --interval 24 --max-hosts 200
```

- Re-runs recon for every program whose last run is older than the interval.
- New endpoints → **alerts** (dashboard Alerts screen, unread badge in the sidebar).
- Per-program last-run state lives in the DB (`scheduled_runs` table).

> `--max-hosts` caps how many hosts are probed per run — keep it modest (100–300)
> so scheduled runs complete quickly on huge programs like Shopify (20k+ subdomains).

## 9. Triage & report summaries

- **Triage** — the tool ranks findings by expected payout priority (severity +
  exploitability). Deterministic by default; when `LLM_BASE_URL` is configured in
  `.env`, an LLM provides the reasoning. Dashboard: `GET /api/triage?program=X`.
- **Report summaries** — generated reports now include an **Executive Summary**
  (deterministic fallback, or LLM-drafted when configured).

To enable LLM features, set in `.env`:

```
LLM_BASE_URL=http://127.0.0.1:11434/v1   # e.g. local Ollama
LLM_MODEL=llama3.1
LLM_API_KEY=                              # optional for local
```

## 10. Business-logic test plans (where bounties actually are)

Generic XSS/SQLi is crowded and mostly duped. Business-logic flaws — price
manipulation, workflow bypass, privilege escalation, race conditions, IDOR with
impact — are app-specific, hard to automate, and rarely duped. This is where
Shopify-type programs actually pay.

The **Logic** feature generates multi-step test plans per category, executes them
in-scope (scope-guarded + audit-logged), and turns interesting responses into
candidate findings.

```bash
# generate a plan (LLM-guided if configured, template otherwise)
.venv/bin/bugbounty logic plan shopify --category price --target "https://your-store.myshopify.com"

# run it (scope-gated; every request audit-logged)
.venv/bin/bugbounty logic run 1

# list plans
.venv/bin/bugbounty logic list --program shopify
```

Categories: `price` · `workflow` · `priv` · `race` · `idor`. Dashboard: **Logic**
screen — pick program + category + target, generate, view steps, run, and see
candidate findings in the Findings screen.

> Honest expectation: a candidate finding is a *lead*, not proof. Business logic
> needs your judgment (and usually a real account/session) to confirm impact
> before reporting. The tool gives you the structure, the in-scope execution,
> the audit trail, and the evidence — you supply the exploit reasoning.

## 11. Authenticated sessions & nuclei (depth + breadth)

### Authenticated scanning (depth)
Most real bugs are behind login. Store a session (cookies/headers) and the runner
sends it on every request:

```bash
# store a session for a program (local DB only, never in reports/audit)
.venv/bin/bugbounty session add shopify --name "staff-acct" \
  --cookies "session=abc123; storefront_digest=xyz" \
  --headers "Authorization: Bearer ..."

# use it on a scan (CLI)
.venv/bin/bugbounty vuln run --program shopify --modules xss,sqli,idor \
  --target "https://your-store.myshopify.com/admin" --tier 2 --session 1

# dashboard: Run Scan → Session picker → pick the profile
```

### Nuclei (breadth)
Thousands of community templates (CVEs, misconfigs, exposures) via one adapter:

```bash
brew install nuclei   # once

# full template library against a target
.venv/bin/bugbounty nuclei --program superhuman --target https://superhuman.com

# faster: limit to a tag set (headers, exposure, misconfig, cve)
.venv/bin/bugbounty nuclei --program superhuman --target https://superhuman.com --tags headers

# scan all recon-discovered endpoints
.venv/bin/bugbounty nuclei --program superhuman --recon
```

Nuclei findings are stored with template-id evidence. Severity maps to the tool's
severity scale. Rate-limited + concurrency-capped by default; heavy tags
(fuzz/brute/dos) excluded.

## 12. How the safety tiers map to platform rules

| Tier | Runs when | Examples | Typical platform clause |
|------|-----------|----------|-------------------------|
| **T1** | auto | header checks, passive probes | "passive testing allowed" |
| **T2** | auto (rate-limited) | reflected XSS probes, open redirect, CORS, IDOR read | "safe active testing allowed" |
| **T3** | only with `--confirm` | SSRF callback, SQLi confirm | "no active exploitation" |
| **T4** | blocked by default | brute-force, DoS, data destruction | "no DoS / no brute-force" |

---

## 13. HackerOne vs Bugcrowd — what's different in this tool

| | HackerOne | Bugcrowd |
|--|-----------|----------|
| Report template | `--template hackerone` | `--template bugcrowd` |
| Import | API (username + token) | public JSON (no auth) |
| Out-of-scope import | manual `--out` (API returns in-scope only) | automatic (brief includes out_of_scope) |
| Submission statuses | New → Triaged → Resolved | Open → Investigating → Resolved |

---

## 14. The audit log — proof of scope discipline

```bash
.venv/bin/bugbounty audit recent
```

Every request: URL, payload hash, tier, scope snapshot, ALLOW/BLOCK — append-only.

---

## 15. Realistic expectations & known limitations

- **Payload depth:** 163 built-in payloads for the 6 MVP classes — a solid starter
  set, not a SecLists replacement. Importing SecLists/PayloadsAllTheThings is
  planned but not built.
- **IDOR findings are candidates** — substitute IDs + 200 = candidate; prove
  cross-tenant access with two accounts before reporting.
- **SQLi confirm is boolean-diff based** — targets that don't differentiate
  `1=1` vs `1=2` aren't confirmed. sqlmap is manual confirm only.
- **SSRF needs the OOB listener** — start it in the UI (or `oob start`) before
  running ssrf; without it the module reports nothing.
- **Recon needs the tools installed** — missing binaries are skipped and reported;
  install subfinder/httpx/katana/gau/ffuf for full coverage.
- **HackerOne import is in-scope-only** — add exclusions by hand with `--out`.

---

## 16. Quick reference — every command

```bash
# Programs & scope
bugbounty program add <name> [--platform X] [--url U] [--allowed-tiers "1,2,3"]
bugbounty program import <name> --platform hackerone|bugcrowd|csv [--handle H] [--csv FILE]
bugbounty program credentials hackerone
bugbounty program list | show <name>
bugbounty program add-scope <name> <pattern> --kind domain|wildcard|ip|cidr [--out]

# Recon & inventory
bugbounty scan recon <name> [--tools subfinder,httpx,katana,gau] [--wordlist FILE]
bugbounty scan list <name> [--source all|manual|recon]
bugbounty scan discover <name> <url> --params "q,page"

# Testing
bugbounty vuln run --program <name> --modules xss,sqli,idor,redirect,cors,ssrf \
  --target <url> [--tier 2] [--confirm] [--oob 8080]

# OOB listener
bugbounty oob start --port 8080
bugbounty oob status

# Findings & reports
bugbounty finding list [--program <name>]
bugbounty finding show <id>
bugbounty report generate [<id>] [--program <name>] [--template hackerone|bugcrowd|markdown]
bugbounty report stats <name>

# Submissions
bugbounty submission new <name> "<title>"
bugbounty submission list <name>
bugbounty submission update <id> submitted|triaged|accepted|rejected|paid

# Payloads
bugbounty payloads list [--category xss] [--max-tier 2]
bugbounty payloads search "alert(1)"
bugbounty payloads stats

# Audit & UI
bugbounty audit recent
bugbounty serve   # web dashboard at http://127.0.0.1:8787

# Scheduled re-recon (run alongside serve)
bugbounty scheduled --interval 24 --max-hosts 200

# Business-logic test plans
bugbounty logic plan <program> --category price|workflow|priv|race|idor [--target URL]
bugbounty logic run <plan-id> [--parallel]
bugbounty logic list [--program <name>]

# Authenticated sessions
bugbounty session add <program> --name label --cookies "k=v; k2=v2" [--headers "H: v"]
bugbounty session list [--program <name>]

# Nuclei (breadth)
bugbounty nuclei --program <name> --target <url> [--tags headers,exposure] [--recon]

# GraphQL
bugbounty vuln run --program <name> --modules graphql --target <url>

# Operations
bugbounty backup          # copy data/ (DB + artifacts) to data/backups/<timestamp>/
bugbounty scheduled --interval 24 --max-hosts 200   # as a launchd service, see below
```

### Running the scheduler as a service (macOS launchd)

Create `~/Library/LaunchAgents/com.bugbountybot.scheduler.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.bugbountybot.scheduler</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/navneetkumar/BugBountyBot/.venv/bin/bugbounty</string>
    <string>scheduled</string>
    <string>--interval</string><string>24</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/bugbounty-scheduler.log</string>
  <key>StandardErrorPath</key><string>/tmp/bugbounty-scheduler.err</string>
</dict>
</plist>
```

```bash
launchctl load ~/Library/LaunchAgents/com.bugbountybot.scheduler.plist
```

Backups: run `bugbounty backup` on a schedule too (or set `BUGBOUNTY_BACKUP_DIR`).

---

## 17. Step-by-step: your first HackerOne program (UI-first)

1. Read the program policy. Note scope and prohibited testing.
2. `bugbounty program credentials hackerone` — store your API token once.
3. **Dashboard → Programs → Import from Platform** → HackerOne → handle → Import.
4. Add any policy exclusions as out-of-scope rules.
5. **Recon screen** → run discovery → endpoints land in the inventory.
6. **Run Scan** → pick the program, target, `xss,sqli,redirect,cors`, tier 2 → run.
7. **Findings** → open each candidate → set status, view evidence, verify manually
   (IDOR needs 2 accounts).
8. For SSRF: **Run Scan → Start OOB** → tick confirm → add `ssrf` → run.
9. **Submissions** → new submission → link the finding.
10. **Report** → pick program/template → generate → preview → **submit manually**
    on HackerOne.
11. **Submissions** → update status → triaged → accepted → paid. Track payout.
