---
name: hermes-probe-lane-authoring
category: autonomous-ai-agents
description: Use when adding an active-probe lane to HERMES recon.
---
# Authoring a HERMES active-probe lane

Covers CORS / subdomain-takeover / any future bounded verifier lane. A lane
confirms ONE deterministic property by sending a bounded request to in-scope hosts,
then writes a `poc_verifications` row so `lib/validator_agent.py` promotes a
`VERIFIED` row into a typed finding. Reference implementations:
`lib/cors_verifier.py`, `lib/takeover_verifier.py`.

## The blueprint (copy it, do not invent a new shape)

1. **Offline pre-filter.** Build the worklist from STORED data (`http_samples.headers`,
   `pd_dns_observations`) so selection sends nothing, and gate every host through
   `scope_guard.check()` fail-closed. Sort deterministically.
2. **One bounded GET** via `crawler.fetch_one`, which re-checks scope on every
   redirect hop, shares the global rate limiter and caps the body. It takes an
   optional `extra_headers` (additive: the default UA is always sent; omitting it
   preserves prior behaviour byte-for-byte).
3. **Deterministic verdict** from the measured response only. Map state -> verdict
   class in a dict; keep provider/fingerprint tables as DATA.
4. **Gate via `poc_verifier.final_verdict(...)`** — never re-implement it.
5. **Ledger** under `state/<lane>/ledger.jsonl`, keyed on a stable identity, that
   records every probe (including negatives) to dedupe across runs.
6. **Wiring**: job type in `CLASS_BY_JOB` (CLASS_NETWORK for network-facing lanes;
   do NOT take the single `CLASS_INVESTIGATION` slot), added to
   `RESERVED_JOB_TYPES`, a per-cycle budget entry, a planner cadence with its own
   `_x_job_pending`/`_x_work_exists`/`_x_due` trio (the work check reads the lane's
   OWN ledger and fails CLOSED), an executor in `scripts/cycle.py`, and validator
   `CLASS_BY_CHECK`/`CLASS_BY_FAMILY` entries.
7. **OFF by default**: `is_armed()` needs `HERMES_ACTIVE_DISCOVERY_ENABLED=1` AND
   the lane's own flag (`_TOOL_ARM_ENV` in `lib/active_discovery.py`). The module
   must REFUSE a live run while unarmed. Adding the flag to the systemd unit is the
   OPERATOR's action — implement it, do not arm it.

## Verdict-class traps

- **`final_verdict` needs a DERIVED agreement.** It returns `REFUTED` only for
  `WEAKENS`+`DISAGREES` and `VERIFIED` only for `SUPPORTS`+`AGREES`. Passing
  `agreement="AGREES"` unconditionally makes every clean "not vulnerable" result
  report `NEEDS_HUMAN` and leaves `REFUTED` unreachable. Derive it:
  `{"SUPPORTS":"AGREES","WEAKENS":"DISAGREES"}.get(vclass, "UNDECIDED")`.
- **Distinct severities need distinct `check_kind`s.** The validator classifies by
  `(family, check_kind)`, so two promotable states with different severities must
  not share a kind, or a Medium is classified High.
- **Keep advisory states advisory.** A fingerprint that needs account-level control
  (CORS wildcard, non-claimable providers) must not promote — give it its own
  Info-severity kind, write no PoC file, and assert in tests that it creates no
  finding.
- **A negative is not always safe.** For takeover, a CNAME with no resolvable
  address (`NO_ADDRESS`) is the shape MOST dangling records have; a GET reaches
  nothing, so there is no body to fingerprint. Recording it `REFUTED` hides the
  real bug — it is advisory.
- `family_check` can be `FAMILY_OK` for a lane whose probe is objective; the
  hunter-family gate belongs to `poc_verifier` and is untouched.

## Persistence: write the evidence BEFORE the dedupe record

**Persist each probe immediately and only then write its ledger entry.** Doing both
at the end loses everything when the job exceeds the scheduler's
`JOB_RUNTIME_TIMEOUT_S` (180 s) — a real production CORS sweep probed 115 hosts,
wrote 115 ledger entries, and produced ZERO rows, so those probes became both
unrecorded and (via the cooldown) unrepeatable. A probe whose row cannot be written
must simply not be ledgered, so the next sweep retries it.

## Fingerprint lanes: a bare 200 proves nothing

For a lane whose verdict is a content fingerprint (exposed files, VCS dirs), the
status code must NEVER be the signal: SPAs and soft-404s answer 200 with
`index.html` for ANY path. Every positive needs a strict fingerprint, and every
fingerprint needs a NEGATIVE test alongside the positive (the soft-404 body, a
lookalike that satisfies only half the rule).

- **Anything outside 2xx is `DENIED`, not `NO_MATCH`.** Writing the status test as
  `st in (401,403) or st >= 500 or (st != 200 and st < 300)` silently excludes 404,
  which then falls through to the fingerprint test and reports the wrong state.
  Use `if st < 200 or st >= 300`.
- **Require the secret-ish name to BE the key.** For `.env`, testing the whole body
  lets an unrelated HTML page that contains `APP_KEY=` and the word "password"
  promote. Extract the `KEY=` names and test those.
- **Check the whole word list in the secret regex against the spec's own example.**
  A regex with `db_password` but not plain `password` misses the spec's canonical
  `/config.json` case.
- **Know what the fetcher will never give you.** `crawler.BINARY_CTYPE` includes
  `application/octet-stream`, so `fetch_one` keeps NO body for a binary response
  (`out["binary"]=True`, empty body). Any fingerprint needing bytes of a binary
  file is UNVERIFIABLE through this fetcher — record it as advisory
  (`INCONCLUSIVE`/`NEEDS_HUMAN`), never as REFUTED, and say so plainly rather than
  claiming the path was checked. Do not add a new fetch capability to make one row
  promote.
- **Redact evidence.** A snippet of a secret-bearing file can itself be a
  credential: strip long token-like strings before storing any excerpt, and keep the
  excerpt short.

## ci_gate false positives (do NOT bypass them)

- **`EXEC_ADD`** (`\b(...|eval|exec)\b`) scans ADDED lines: spelling a
  dynamic-execution SINK NAME as a literal in a data set trips it. DERIVE the set
  from an existing constant instead of re-typing the word.
- **"removes a safety/auth guard"** fires on a REMOVED line containing `in_scope`,
  `scope_ok`, `no_exploitation`, etc. Wrapping a loop that contains a scope check in
  `try/finally` re-indents that check, so the diff shows it as deleted. Keep the
  loop's original indentation and move the new work into a helper (e.g. a
  `_persist_now` that opens its own connection).
- Verify before committing: regex the `git diff <base> -- <file>` added lines
  against `EXEC_ADD` and require 0 hits, and confirm no removed line mentions a
  guard keyword. Never use `--allow-manual` to clear either.

## Attribution / commit rules

- Operator directive: a probe-expansion commit carries **no Claude attribution**.
  Author and commit as the implementing tool. `git commit -F <msg>` with
  `Co-Authored-By: Hermes Agent <hermes-agent@local>`; never add a Claude trailer.
- Check the right things: `git log -1 --format='%B' | grep -ci claude` must be 0,
  and the code files must be 0. A whole-tree `git grep claude` will NOT be 0
  (pre-existing `claude_red_skills.py` etc.) and the spec document's own prose
  counts too — a non-zero there is not a violation.

## Testing a lane

- **Redirect `store.BASE` BEFORE importing the lane.** Its `LEDGER_FILE`/`POC_DIR`
  are module-level constants, so importing first and redirecting after leaks the
  ledger into production (learned the hard way — `state/cors/` appeared with
  loopback rows). Assert `LEDGER_FILE.startswith(TMP)` after import.
- Use the REAL `store` module with `ST.DB` pointed at a throwaway copy, so
  `add_finding` and the whole promotion path are genuinely exercised.
- **Once production has real rows in the copied DB, assert DELTAS**, not absolute
  counts (`== BASE + 1`), or a passing lane will look like a failure.
- Cover: every verdict class, advisory never promoting, determinism, both refusals
  (live-without-apply, live-while-unarmed), cooldown dedupe, in-scope-only
  selection, and the 21-column insert.
- **Never generate target traffic in a test**: serve probes from a fixture fetch
  with synthetic responses. To prove a request header really leaves, use a loopback
  `HTTPServer` and patch `crawler.scope_verdict` for that local server only.

## Confirming the lane actually ran in production

Read `poc_verify_runs.summary_json`, then **reconcile it against the ledger**.
`probed=10` next to a 125-line ledger was the clue that a sweep had been killed
mid-run; two `ts` clusters in the ledger (one large, one small) confirmed it. Also
check `poc_verifications` row counts by `kind` and that the validator created no
unexpected findings — the lane is inert until the operator arms it, so `0` rows is
correct pre-arming, not a bug.

## Data-shape traps found in this DB

- `http_samples` has NO `url` column (one row per host); the page URL comes from its
  `Link: <...>; rel=shortlink` header.
- `pd_dns_observations.dns_cname` is a comma-joined CHAIN, not one value (767
  candidates) — a suffix test on the whole string matches whichever provider sits at
  the END. Split per element and store the terminal record.
- `xss_candidates` PK is `candidate_id`; `confidence` is TEXT (alphabetical sort is
  a bug); `severity` values in `findings` are title-case and `Critical` ranks above
  `High` in `findings_state.SEV_RANK`.
