# First Dollar Plan — Earning Your First Bounty with BugBountyBot Pro

_Drafted 2026-08-26. A realistic, sequenced playbook. Honest about odds and effort._
_Companion to [ROADMAP.md](ROADMAP.md), [USER_GUIDE.md](USER_GUIDE.md), [AGENTS.md](AGENTS.md)._

---

## The honest premise

You will **not** earn by pressing "scan" on a mature program and collecting a payout.
Reflected XSS/SQLi on Shopify-tier programs are duped and WAF'd. Your first dollar
comes from **being first on fresh attack surface** and from **low-competition,
high-certainty bug classes** — exactly what this tool's recon + monitoring + nuclei +
exposure/takeover modules are built for.

**Realistic expectation:** first valid finding in **2–6 weeks** of consistent effort
(1–2 hrs/day). First *paid* finding may take longer — many first wins are on VDPs
(reputation, not cash) that build the profile that gets you into paying programs.
Treat rep + a first "resolved" as the real milestone; the dollar follows.

**The tool's job:** keep you in-scope, go wide fast, surface high-signal candidates,
and organize evidence/reports. **Your job:** judgment, confirmation, and the write-up.

---

## Phase 0 — Prove the tool before you trust it (½ day)

Never point an unproven scanner at a real program and trust its output.

- [x] Stand up a known-vulnerable app locally (OWASP **Juice Shop** via Docker).
      *(Done 2026-08-26 — ran v20.2.0 from the prebuilt release, no Docker needed:
      `node build/app` on port 3000.)*
- [x] Add it as a program, scope `127.0.0.1`, run recon + the modules against it.
- [x] Confirm it actually finds the planted bugs and that evidence/reports look sane.
- [x] Note which modules fire cleanly and which are noisy — trust the clean ones.

**_Phase 0 result (2026-08-26):** the engine found **2 real vulnerabilities** on
Juice Shop — SQL injection (error-based) on `/rest/products/search`, and exposed
`/.env`. Both stored with request/response evidence. The validation also exposed
**2 genuine detector gaps** that were then fixed: the SQLi error fingerprints
didn't include `SQLITE_ERROR`/Sequelize errors, and confirm was boolean-diff-only
(which misses error/union-based SQLi). XSS and redirect found nothing — Juice
Shop's XSS is DOM/stored, outside the reflected-only scope (known limitation).

_Outcome: you know first-hand what the tool catches and what it misses. Skip this and
you'll waste triage time chasing your own false positives on real targets._

---

## Phase 1 — Pick the right program (½ day)

Target selection is 80% of first-bounty success. **Avoid** the famous, crowded
programs. **Seek:**

- [x] **VDPs and new/low-signal programs** on HackerOne/Bugcrowd (filter: recently
      launched, lower bounty or points-only, **wide scope with wildcards**).
- [x] **Wildcard scope** (`*.example.com`) — this is where new-asset monitoring pays.
      A giant static scope with one host = crowded. A wildcard = constant new surface.
- [x] **Programs that pay for exposures/misconfig/takeover**, not just "critical RCE."
- [ ] Read the policy: confirm no-DoS/rate limits, note exclusions, note what they pay for.

Onboard 3–5 such programs so you always have surface to work:

```bash
.venv/bin/bugbounty program import acme --platform hackerone --handle <handle>
# add policy exclusions the API won't return:
.venv/bin/bugbounty program add-scope acme "admin.acme.com" --kind domain --out
```

**_Onboarded (2026-08-26, from the HackerOne dataset via public scope):**
- **Henkel** (`henkel_vdp`) — 257 assets, 207 wildcards, VDP, 100% response. 16 live hosts seeded.
- **ION Group** (`ion`) — 1443 assets, 665 wildcards, VDP. 4 live hosts seeded (acuris.com, activistmonitor.com, etc.).
- Scheduler running (24h) with new-asset alerts firing; both scopes imported and seeded.

---

## Phase 2 — Go wide, then monitor (the core loop)

This is the tool's real edge. Do it for every onboarded program.

### 2a. Full recon → inventory
```bash
brew install subfinder httpx katana gau nuclei   # once
.venv/bin/bugbounty scan recon acme
.venv/bin/bugbounty scan list acme --source recon
```

### 2b. Breadth sweep with nuclei (where first bugs actually appear)
```bash
# exposures + misconfigs first — highest hit rate, lowest dupe
.venv/bin/bugbounty nuclei --program acme --recon --tags exposure,misconfig
# then CVEs across all live hosts
.venv/bin/bugbounty nuclei --program acme --recon --tags cve
```

### 2c. Targeted high-certainty modules
```bash
# subdomain takeover across recon hosts — classic easy first bounty
# secrets/exposure — leaked keys, .git, .env, backups
# (run the secrets + takeover modules against the recon inventory)
```

### 2d. Leave the monitor running (the "first on new assets" money engine)
```bash
.venv/bin/bugbounty serve &                        # dashboard
.venv/bin/bugbounty scheduled --interval 24 --max-hosts 200
```
- [ ] Check the **Alerts** screen daily. A brand-new in-scope host nobody has tested
      is your best shot at an un-duped bug. Test new assets **the day they appear.**

---

## Phase 3 — Hunt the payable classes (your daily 1–2 hrs)

Ranked by first-dollar ROI for a beginner with this tool:

1. **Subdomain takeover** — dangling CNAME to an unclaimed service. High certainty,
   easy to prove (claim it, show control), widely paid. Tool surfaces candidates;
   you verify the service is actually claimable.
2. **Exposure / secrets** — exposed `.git`, `.env`, config backups, API keys in JS
   bundles, open S3. Nuclei + secrets module find these; you verify impact.
3. **Nuclei CVE hits** on forgotten hosts — verify it's real and in-scope, not a
   false match. Check it isn't a known/duped issue first.
4. **Access-control / IDOR** — with two real accounts, use the 2-session diff. Prove
   cross-tenant access before reporting. Higher effort, higher pay.
5. **Info disclosure / security-header issues** — low pay or VDP-only, but easy
   "resolved" marks that build your profile.

> Rule: every automated candidate is a **lead, not a finding**. Confirm manually,
> in-scope, before you write anything up.

---

## Phase 4 — Confirm, then report (what actually gets paid)

Triagers reject on weak evidence more than weak bugs.

- [ ] **Reproduce manually** and capture a clean request/response (the tool stores it).
- [ ] **Dedup**: search the program's disclosed reports + Google for the same issue.
      A duplicate earns nothing — check before you spend an hour writing.
- [ ] **Write impact, not just the class.** "Exposed .git" → "full source disclosure
      including DB credentials in config X." Impact is what sets the payout.
- [ ] Generate the draft, then **submit manually** — the tool never auto-submits:
```bash
.venv/bin/bugbounty report generate --program acme --template hackerone
```
- [ ] Track it:
```bash
.venv/bin/bugbounty submission new acme "<title>"
.venv/bin/bugbounty submission update <id> submitted
```

---

## Phase 5 — Iterate (the part that actually earns)

The first dollar is a numbers game on top of a good process.

- [ ] Run the recon → nuclei → monitor loop across all your programs, weekly.
- [ ] Act on new-asset alerts within 24h.
- [ ] Log every dup/reject as a fixture/lesson; refine which modules you trust.
- [ ] Widen your program pool over time as your reputation opens paying programs.

---

## Guardrails (non-negotiable)

- **Only ever test in-scope hosts.** The tool enforces it; you honor it too.
- **Respect rate limits and no-DoS clauses.** Keep `--max-hosts` modest.
- **No auto-submit, no exploitation beyond proof.** Confirm impact minimally.
- **Never test a host without an active program authorizing that exact asset.**

---

## Reality check

- Most first wins are **exposures, takeovers, or CVE-on-forgotten-host** — not clever
  XSS. Lean into those.
- Expect **dupes and N/As** early; they're tuition, not failure.
- The tool's durable edge is **coverage + monitoring + discipline**, letting you work
  many programs safely and be first on new surface. Your edge is **judgment**.
- **The first dollar validates the process, not the tool.** Once you have a repeatable
  loop that produces valid findings, the earnings scale with time spent — that's the
  real goal.

### This week
1. Phase 0: Juice Shop, prove the tool. (½ day)
2. Phase 1: onboard 3 wide-scope VDP/low-signal programs. (½ day)
3. Phase 2: recon + nuclei exposure/misconfig sweep on all three; start the scheduler.
4. Phase 3: chase takeover + exposure candidates first.
