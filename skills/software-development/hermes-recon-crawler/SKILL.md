---
name: hermes-recon-crawler
description: "Use when changing HERMES recon crawl/frontier code."
---

# HERMES recon crawler (M2)

`/root/hermes-recon/lib/crawler.py` is the recursive same-scope crawler. It is a
bounded job type (`crawl_site`) scheduled by `lib/planner.py` and executed by
`scripts/cycle.py:execute_job` — never a second scheduler or a second DB.

## State

- `crawl_frontier(run_id,url)` PK = per-run dedup; states PENDING/VISITED/FAILED/
  SKIPPED/REJECTED. `run_id = "crawl-<job_id>"`.
- `crawl_runs` = one row per run with the compact result + telemetry `detail`.
- `store.crawl_run_prune()` keeps the newest 20 runs; frontier rows die with them.

## Invariants — do not break these

- **GET only.** Never construct POST/PUT/PATCH/DELETE. State-changing paths
  (`logout|delete|update|action|checkout|...`) are skipped.
- **Scope on the normalized final URL**, plus every redirect hop. Never trust the
  source page host. `candidate_verdict()` is the pre-fetch guard.
- **`MAX_CRAWL_DEPTH = 2` is a hard ceiling**, clamped even if a caller asks for
  more. Depth 3+ is never requested.
- **Never raise an existing safety limit.** `_body_cap()`/`_timeout()` take
  `min(M2 value, workers.<value>)`; the global 15 req/s ceiling, per-target
  adaptive rate, target cooldown and server-health gate are reused objects.
- **Sequential.** No threads, pool, asyncio or multiprocessing (test V enforces).
- **Fragments are dropped in `normalize_url()`** — `/page#a` and `/page#b` are one
  crawl URL. Do not normalize path/query beyond duplicate slashes and ports.
- A new `crawl_run()` keyword arg must not be named `con`/`conn`.

## Signal safety (learned the hard way)

`cycle.py` arms SIGALRM for its own `JOB_MAX_S` (180 s) job cap. `crawl_run()` must:
1. only arm its own per-URL alarm when `signal.getitimer()` shows no timer
   pending, and
2. restore the previous handler + remaining timer in `finally`,
3. keep `CRAWL_RUN_MAX_S` (150) < `JOB_MAX_S` (180) so the run reports its own
   result instead of being aborted mid-flight.
Verify with `python3 scripts/m2_signal_probe.py` (must print SIGNAL SAFETY: PASS).

## Retry semantics

`recover_jobs()` returns interrupted RUNNING jobs to PENDING, so the same
`run_id` legitimately runs twice. `store.crawl_run_start()` therefore DELETEs the
frontier rows for that run_id first — otherwise the retry sees its own leftovers
as "already visited" and reports BLOCKED.

## Failure containment

Every keyed dict read in the loop (`r.get(...)`, `headers.get(...)`) matters: a
`KeyError` inside the loop body is caught by the outer handler and turns the run
into `status="ERROR"`. Keep tests for timeout, DNS failure, malformed HTML,
empty response, no-status and unknown content-type.

## Tests

- `scripts/test_m2_crawler.py` (30 checks A–Y) — throwaway DB via `HERMES_DB`,
  fake opener; must print `30/30 passed`.
- `scripts/m2_signal_probe.py`, `scripts/m2_job_probe.py`,
  `scripts/m2_live_verify.py`, `scripts/m2_measure.py`.
- Regression: every `scripts/test_m1*.py`, `xss_selftest`, `telegram_selftest`,
  `budget_selftest`, `phase34_selftest`, `fix_selftest`.
- Record production counts (findings/xss_candidates/finding_reviews/
  correlation_groups) before and after any live crawl; they must not change.
- A fake-opener probe pointed at a real in-scope host MUST pass
  `store_urls=False`, or its invented URLs land in the production `urls` table.
- `verify_routing.py` has three PRE-EXISTING failures (config context_length and
  `model.default` were changed after that check was written) — report them as
  pre-existing, do not "fix" them as part of crawler work.
