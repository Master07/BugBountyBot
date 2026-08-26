# BugBountyBot Pro — Tool Verification Findings

_Verified 2026-08-26 by hands-on inspection (suite run, benchmark run, code grep, CLI invocation).
Companion to [CORRECTNESS_PLAN.md](CORRECTNESS_PLAN.md) and [ROADMAP.md](ROADMAP.md)._
_This is a **findings report** — no code changes were made._

> **Update (same day): all findings addressed.** The `benchmark` CLI bug is fixed
> (benchmark is now an installed package + paths use settings, verified from a
> non-repo directory), a **CLI-entrypoint canary** was added to CI so "green in
> pytest, broken in the CLI" cannot recur, and the SSRF OOB wait is configurable
> (`callback_wait`) so tests are faster. The two caveats below remain honest:
> the benchmark is self-authored fixtures (a real vulnerable-app target is the
> proper W7 follow-up), and the suite is slow by design (OOB/corpus waits).

> **Re-check #2 (same day): fix verified + canary gap closed.**
> - Confirmed independently: `bugbounty benchmark` runs from `/tmp` (non-repo dir)
>   via the installed entrypoint, exit 0, full 6-module table. Packaging is a proper
>   root-cause fix — `pyproject.toml` `include = ["bugbountybot*", "benchmark*"]` +
>   `benchmark = ["fixtures/*.yaml"]`; `import benchmark` resolves via the venv.
> - **Canary gap found and fixed:** the CI entrypoint canary did **not** list
>   `benchmark` (the command it was written to protect) — none of its probes imported
>   the `benchmark` package, so a regression would have slipped through again. Expanded
>   the loop ([.github/workflows/ci.yml:40](.github/workflows/ci.yml:40)) to include
>   `benchmark` plus the `--help` forms of the import-heavy subcommands (`nuclei`,
>   `logic`, `session`, `scan`, `vuln`, `report`) — `--help` forces each module import
>   with no DB/network side effects. Verified the full expanded loop passes under
>   **bash with the entrypoint on PATH** (the real CI environment) from `/tmp`.
>   *(Note: measuring this under interactive zsh gives false `exit=2`/`127` noise;
>   CI runs bash, where all 12 commands exit 0.)*

---

## Method

- Ran the full test suite (`.venv/bin/python -m pytest`).
- Ran the benchmark via the CLI entrypoint **and** via `python` from repo root.
- Grepped for the rate limiter wiring in the runner.
- Inventoried the new vuln modules, tests, benchmark, and CI.
- Rendered `bugbounty --help`.

---

## What is genuinely there and works ✅

- **Suite green and larger:** **124 tests pass** (was 79 → 84 → 124). 21 test files
  now cover the new modules, reliability, collaborator, corpus, and benchmark.
- **P0 SSRF fix is real** (re-verified): production `{{OOB}}` templating in
  `SSRFModule.select_payloads` ([vuln/ssrf.py:53](bugbountybot/vuln/ssrf.py:53)), no
  monkeypatching, plus a `test_ssrf_without_oob_does_not_confirm` negative test.
- **Rate limiter is actually wired into the runner** (not a stub):
  [runner/service.py:184-193](bugbountybot/runner/service.py:184) calls
  `before_request` / `after_response`, reads the per-program policy rate
  (`scope.policy.max_rate`), and honors `Retry-After`. This was the #1 reliability gap
  in the roadmap and it is genuinely closed. Limiter defined in
  `bugbountybot/runner/ratelimit.py`.
- **New payable-class modules exist and are registered:** `graphql`, `jwt_auth`,
  `secrets`, `takeover` in [bugbountybot/vuln/](bugbountybot/vuln). CLI help renders
  all new commands (`benchmark`, `backup`, `nuclei`, `logic`, `session`).
- **Corpus is hermetic (correct approach):** the "real superhuman.com behavior" is
  captured as **static fixtures** in
  [benchmark/fixtures/corpus.yaml](benchmark/fixtures/corpus.yaml) and served by a
  local fixture server — not live network calls. Good for deterministic CI.

---

## Real bug found 🔴

### `bugbounty benchmark` crashes via the installed entrypoint
- **Symptom:**
  ```
  $ .venv/bin/bugbounty benchmark
  ModuleNotFoundError: No module named 'benchmark'
  ```
- **Root cause:** the CLI does `from benchmark.run import ...`
  ([cli/main.py:577](bugbountybot/cli/main.py:577)), but `benchmark/` is a **top-level
  directory that is not an installed package**. The `.venv/bin/bugbounty` console
  script runs with `sys.path[0] = .venv/bin`, so `benchmark` is not importable. It
  only imports under `pytest` / `python` run from the repo root, which add cwd to
  `sys.path`.
- **Why it slipped through:** `tests/test_benchmark.py` passes because pytest puts the
  repo root on the path — **the green test masks a broken user-facing command.** This
  is the *same failure signature* as the original P0 SSRF issue (test passes,
  real invocation broken).
- **Impact:** the W7 "benchmark" deliverable — advertised in the CLI and marked done
  in [ROADMAP.md](ROADMAP.md) — does not run the way a user runs it.
- **Fix (small):** make `benchmark` a proper package (add to
  `[tool.setuptools.packages]` in `pyproject.toml`) or relocate it under
  `bugbountybot/`. **Add an anti-`sys.path` canary** to CI: run each CLI subcommand
  via the installed entrypoint from a directory that is *not* the repo root, so
  "works in pytest, breaks in the entrypoint" bugs cannot recur.
- **Note:** the benchmark *logic* itself works when imported correctly and returns
  perfect scores on the fixtures (see caveat #1 below).

---

## Honest caveats 🟡

### 1. The benchmark corpus is thin and self-authored
- `run_benchmark()` reports **1.00 precision / 1.00 recall / 0.00 FP** — but on
  **1 true-positive and 1 true-negative per module**, using fixtures the author wrote.
- This validates "the module does what its own fixture says" (effectively restated
  unit tests), **not** "it finds real bugs." W7's stated intent — ground truth from
  **Juice Shop / DVWA / testphp.vulnweb** — was described in the roadmap but **not
  built**; the fixture server ([benchmark/fixtures/server.py](benchmark/fixtures/server.py))
  is synthetic.
- **Consequence:** the precision/recall number is real but does **not** carry the
  credibility that "precision/recall" normally implies. Treat it as a regression guard,
  not a proof of real-world efficacy.
- **Fix:** add a real vulnerable-app target (containerized Juice Shop/DVWA) before
  trusting the numbers as an efficacy signal.

### 2. The suite is slow: ~123s (was ~8s)
- Cause is legitimate: real `time.sleep` waits for OOB callbacks (3–5s each in the
  SSRF/collaborator tests) plus retry/backoff sleeps.
  - `test_collaborator_confirms_callback` — 5.09s
  - `test_ssrf_module_confirms_via_oob_production_path` — 4.06s
  - `test_ssrf_without_oob_does_not_confirm` — 3.04s
- **Not broken, but** on the just-added CI ([.github/workflows/ci.yml](.github/workflows))
  this will be a drag and discourages running locally.
- **Fix:** make the OOB wait configurable (short in tests), and/or parallelize with
  `pytest-xdist`.

---

## Verdict

The tool has **matured substantially and for real.** The reliability core (rate
limiting, WAL, crash-safe runs, bounded workers), the payable-class modules
(2-session IDOR, secrets/exposure, takeover, JWT, GraphQL), and a hermetic regression
corpus are all genuine, verified work — not checkbox theater.

Two things keep it short of "finished," and both are the *same lesson* as the original
review:

1. **Fix the `benchmark` CLI import** (real bug) and add an entrypoint canary so
   "green in pytest, broken in the CLI" cannot recur.
2. **Upgrade the benchmark from self-authored fixtures to a real vulnerable app**
   before treating precision/recall as a credibility signal.

Everything still unchecked on the roadmap (W1 detection-correctness contracts, W4
safety-guard hardening, W5 evidence/curl-PoC, W8 authorization records) is
legitimately open and consistent with what the roadmap shows.

### Recommended next actions (in order)
1. Fix `benchmark` packaging + add CLI-entrypoint canary to CI.
2. Speed up the suite (configurable OOB wait / `pytest-xdist`).
3. Stand up a real vulnerable-app benchmark target (W7, done properly).
4. Then resume the roadmap: W4 (safety hardening) and W5 (evidence/reporting).
