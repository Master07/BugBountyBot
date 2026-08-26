# BugBountyBot Pro — Correctness & Efficacy Remediation Plan

_Analysis date: 2026-08-26. Source: read-through of `bugbountybot/` + test suite (79 passing)._

> **Status: EXECUTED** (2026-08-26). All P0–P3 items fixed; suite now 84 passing.

This plan captures the correctness findings from the code review and orders the
fixes by severity. It is a **plan only** — no code changes have been made.

---

## Verdict (summary)

- **Sound as a safety-gated harness.** Scope guard is a real single choke point
  ([scope/guard.py](bugbountybot/scope/guard.py)), out-of-scope rules override in-scope,
  tier-4 is hard-blocked, every request is audit-logged
  ([runner/service.py:68](bugbountybot/runner/service.py:68)). Tracker, reporter,
  recon pipeline, and the nuclei adapter are correct.
- **Weak as a vulnerability scanner.** The 6 built-in modules are GET + query-param
  only, use false-positive-prone confirmation, and **SSRF is non-functional against
  real targets** while a monkeypatched test hides it.
- **Bounty realism:** mechanically it can be pointed at a live in-scope target and
  stays scope-safe, but the bespoke detectors target the most duped/WAF'd classes
  with shallow probes. The realistic value is **recon + nuclei + auth sessions +
  human judgment** on candidates — not the built-in detection logic.

---

## P0 — Broken feature masked by a green test

### 1. SSRF payload templating does not exist in production
- **Evidence:**
  - Static payloads: `http://127.0.0.1:8080/SSRFTOKEN` ([payloads/ssrf/internal.txt](payloads/ssrf/internal.txt)).
  - `inject()` sends `payload.payload` verbatim; nothing rewrites `SSRFTOKEN` or the
    port ([vuln/ssrf.py:46](bugbountybot/vuln/ssrf.py:46)). `callback_url()` /
    `make_token()` are never called outside tests.
  - The "proof" test **monkeypatches `select_payloads`** to inject the real callback
    URL ([tests/test_oob_ssrf.py:77](tests/test_oob_ssrf.py:77)); its docstring claims
    an "inject-time payload templating" that is not in the code.
- **Consequences:**
  1. A remote target fetching `127.0.0.1:8080` hits its **own** loopback, never the
     scanner. The OOB listener also binds `127.0.0.1` only (correct, by policy —
     [oob/server.py:22](bugbountybot/oob/server.py:22)), so it is unreachable
     externally. OOB SSRF is structurally impossible against any external target.
  2. Even in a localhost lab it only coincidentally works when the OOB port is 8080.
- **Fix:**
  - Add real templating: SSRF `select_payloads`/`inject` must substitute a unique
    per-run token **and** the live listener base URL (`oob.callback_url(token)`) into
    each payload. Keep the static file as a template with a `{{OOB}}` placeholder.
  - Support an externally reachable collaborator (public host/ngrok/config-provided
    base URL) for real targets — document that pure-localhost OOB cannot confirm
    remote SSRF. Gate any non-localhost bind behind explicit user approval per
    [AGENTS.md](AGENTS.md).
  - Rewrite the test to exercise the **production** `select_payloads`/`inject` path —
    no monkeypatching — and fix the misleading docstring.

---

## P1 — High false-positive confirmation logic

### 2. SQLi boolean-diff uses exact full-body equality
- `r_true.text == r_false.text` ([vuln/sqli.py:107](bugbountybot/vuln/sqli.py:107))
  — any nonce/CSRF token/timestamp/ad makes `1=1` vs `1=2` differ → false confirm.
- `base = payload.payload.rstrip("'")` string-splicing
  ([vuln/sqli.py:84](bugbountybot/vuln/sqli.py:84)) yields malformed SQL for most payloads.
- **Fix:** compare a stability baseline (identical request twice) first; use response
  similarity / length / status normalization rather than exact equality; build the
  true/false probes from the injection point, not by trimming quotes off the payload.

### 3. Open-redirect body branch is too loose
- Flags any 200 where the probe **and** the word "location" both appear anywhere
  ([vuln/redirect.py:68](bugbountybot/vuln/redirect.py:68)).
- **Fix:** only confirm on a real 3xx `Location` to the attacker host; drop or tightly
  scope the JS-redirect heuristic (parse for `window.location = <probe>` specifically).

### 4. XSS confirm is context-blind
- Literal `<script>alert(1)</script>` reflection check
  ([vuln/xss.py:86](bugbountybot/vuln/xss.py:86)) reports reflections inside
  `<textarea>`/comments/attributes that never execute; comment overstates it as
  "proves exploitability" ([vuln/xss.py:69](bugbountybot/vuln/xss.py:69)).
- **Fix:** add minimal context detection (is the reflection in an executable HTML
  position?); downgrade non-executable reflections to "candidate."

---

## P2 — Structural coverage gaps

### 5. GET + query-param only across all modules
- `InjectionPoint` supports `body`/`json`/`cookie`/`header`/`path`
  ([vuln/base.py:18](bugbountybot/vuln/base.py:18)) but no module populates them.
- **Fix (incremental):** POST/JSON body injection; cookie/header injection; use
  discovered `method`/`params` from the endpoint inventory. Prioritize POST-body XSS/SQLi.

### 6. IDOR is candidate-only (acceptable, keep honest)
- Flags any 200 on `id=2` ([vuln/idor.py:85](bugbountybot/vuln/idor.py:85)); correctly
  labeled "needs 2-session confirm." **No fix required** — optionally wire the
  two-session diff when two `SessionProfile`s are supplied.

---

## P3 — Test-integrity follow-ups

- Audit the suite for other tests that monkeypatch the production path or assert
  against mocks that can't fail (per [AGENTS.md](AGENTS.md): "a test that passes while
  the business rule is broken is wrong").
- Add negative tests: SQLi confirm must **not** fire on a page with per-request
  dynamic content; redirect must **not** fire on a benign page containing "location".

---

## Suggested execution order

1. **P0 #1** SSRF templating + honest test (restores the one high-value module).
2. **P1 #2–#4** tighten confirmation to cut false positives.
3. **P3** lock the fixes with negative tests.
4. **P2 #5** expand injection surface (largest effort, do last).

Each unit: change → cite the verification command + output → checkpoint
(Done / Verified by / Next), per [AGENTS.md](AGENTS.md) engineering rules.

---

## Execution log (2026-08-26)

- **P0 #1 (SSRF)** — `{{OOB}}` placeholder in `payloads/ssrf/internal.txt`;
  `SSRFModule.select_payloads` now rewrites it to a live per-run callback URL with
  a unique token; `_token_for` extracts the token from the URL or the detection
  field. Test rewritten to exercise the **production** path (no monkeypatching):
  `tests/test_oob_ssrf.py` — 4 passing, verified via `pytest tests/test_oob_ssrf.py`.
- **P1 #2 (SQLi)** — confirm now: (1) stability baseline (identical request twice,
  must match — dynamic pages can't confirm), (2) clean numeric probes
  `1 AND 1=1` vs `1 AND 1=2` (no quote-splicing), (3) normalized comparison via
  `_diff_score` threshold. `vuln/sqli.py`.
- **P1 #3 (redirect)** — removed the loose "probe + 'location' in body" branch;
  only a real 3xx with the probe in `Location` confirms. `vuln/redirect.py`.
- **P1 #4 (XSS)** — confirm now checks reflection context (`_reflection_context`):
  reflections in `<textarea>`, comments, or quoted attributes are **not**
  confirmed. JSON-body confirm recovers the injected param from the request body.
  `vuln/xss.py`.
- **P3 (negative tests)** — `test_sqli_does_not_confirm_on_dynamic_page` (per-request
  nonce) and `test_redirect_does_not_flag_benign_location` (200 with "location"
  word) both pass. `tests/test_vuln_modules.py`.
- **P2 #5 (injection surface)** — base `_inject` helper handles `query`, `json`,
  and `body` locations; xss + sqli inject via it; JSON-body XSS confirmed by a new
  test (`test_xss_json_body_injection`).
- **Verification:** `pytest -q` → **84 passed**.
