# EPIC10 — Incremental DNS Resolution & Pipeline Scope Control v1

Status: **READY TO PUSH: YES** (commit pushed, promotion request created, awaiting
operator APPROVE).

Branch: `agent/daily-development`
Commit: `8f1c4d2` — `feat(ns): incremental DNS resolution selection (EPIC10)`
Promotion: `agent-reports/promotions/PROMOTION-REQUEST-20260924-XXXX.md`

---

## 1. What was asked, and what was built

The promoted chunking fix (`b58d0b2`) bounds the *invocation* of dnsx but does not
reduce the *total work*: `indeed.net` grew to 206,080 names (201,076 of them daily
brute force, +~40,000/day) and needs ~5h of query time per night inside a 6h
pipeline window. EPIC10 adds a deterministic eligibility layer so the nightly run
resolves only what it must, while guaranteeing that no new, changed, unresolved or
retry-eligible name is lost.

Deliverables:

| Piece | File |
|---|---|
| Eligibility selector, policy, retry store, run report | `utils/dns_incremental.py` (new, ~950 lines incl. docs) |
| Hook: selection **before** chunking on the real DNS path | `utils/common.py` (`_dnsx_run_plan`, `run_command_in_zsh_ns`) |
| Runtime state ignore rule | `.gitignore` (`ai_data/dns/`) |
| Architecture / operations documentation | `docs/incremental-dns-resolution.md` (new) |
| Tests (245 new) | `tests/test_epic10_*.py` (7 modules) + `tests/epic10_fixtures.py` |
| Fixture adaptation of the two pre-existing NS suites | `tests/test_ns_chunking.py`, `tests/test_ns_failfast.py` |

## 2. Eligibility (EPIC10 SS2/SS3)

One authoritative, deterministic classifier (`classify_dns_candidate`, a pure
function — same inputs, same verdict). Precedence: `INVALID` > `FORCE` > `NEW` >
`CHANGED` > `RETRY_ELIGIBLE` > `RETRY_BACKOFF` > `STALE` > `FRESH`.

| Category | Signal | Queried |
|---|---|---|
| `INVALID` | fails `validate_dns_name` (empty, whitespace, `*`, no dot, bad label, >253 chars, not lowercase) | no, reported with reason |
| `FORCE` | `DNS_RESOLUTION_FORCE=true` | yes |
| `NEW` | no `LiveSubdomains` row, no prior attempt | yes |
| `CHANGED` | `Subdomains.last_update > LiveSubdomains.last_update` | yes |
| `RETRY_ELIGIBLE` | no `LiveSubdomains` row, attempts > 0, backoff elapsed | yes |
| `RETRY_BACKOFF` | as above, backoff not elapsed (extension to the SS2 minimum set) | no, reported with `next_retry_at` |
| `STALE` | resolved, unchanged, age ≥ `freshness_hours` | yes |
| `FRESH` | resolved, unchanged, age < `freshness_hours` | no |

Signals are pre-existing and not inferred: `upsert_lives()` refreshes
`LiveSubdomains.last_update` on every successful resolution;
`upsert_subdomain()` bumps `Subdomains.last_update` **only** when a new provider is
merged. No change detection is invented where none exists (SS5).

## 3. Freshness (SS7) and retry (SS6)

Both defaults are derived from existing project behavior rather than invented, and
**neither changes nightly coverage**:

* `DNS_RESOLUTION_FRESHNESS_HOURS=12` — matches the project's existing 12h recency
  convention (`app.py`). Runs are ~24h apart, so last night's results are ≥12h old
  tonight and are revalidated as `STALE`; the window's real effect is
  **duplicate-run protection** (a second run inside 12h does no DNS work).
* `DNS_RETRY_BACKOFF_HOURS=12` (single rung) — a name that failed tonight is retried
  on tomorrow's run; a duplicate run within 12h does not hammer resolvers.

Real work reduction is available and measured (SS13, below), but it trades
detection latency, so it is **not** the default: the mission's SS3/SS7 explicitly
allow preserving current behavior as the safe default rather than inventing a hidden
policy.

## 4. Never lose new discoveries (SS4)

The canonical case is pinned by test: with `a` and `b` FRESH and `c` newly
discovered, the selector returns exactly `["c"]`. Also covered: a new name is
selected even when every other name in the scope is fresh; 500 new names are all
selected; a name that never resolves stays selected on every subsequent run; a name
discovered between two runs is selected on the next run; duplicates (same name under
two programs) collapse to one query; `selected + deferred == valid candidates`
(no name lost, no name double-counted).

## 5. Order: selection before chunking (SS9)

```
candidates -> eligibility -> dedupe -> chunk <= 15000 -> dnsx
```

Measured with the real numbers: a 206,080-name list with 200,000 FRESH names
produces **one** invocation carrying 6,080 names (not 14 chunks of the full scope).
The 15,000 bound is unchanged and is asserted under FORCE too.

## 6. Fail-closed (SS11)

Selector failure (corrupt/unreadable state file, bad schema, Mongo failure,
malformed policy value) raises `DnsSelectionError` and aborts the DNS step:
tests assert that **dnsx is never invoked** in that path — no fallback to
"everything is eligible", which is the failure mode that would re-create the 5h run.
Bookkeeping failures after the run are non-fatal by design (results already exist)
and are reported as `Attempt state: FAILED (...)`; the affected names simply stay
NEW/retry-eligible.

## 7. Tests (SS14)

**245 new tests**, all offline (no DNS, no Mongo, no network):

| Module | Tests | Focus |
|---|---|---|
| `test_epic10_eligibility.py` | 72 | full classification matrix, precedence, determinism, every category reachable |
| `test_epic10_discovery.py` | 23 | new-name guarantees, duplicates, change detection, no candidate lost |
| `test_epic10_retry.py` | 40 | bookkeeping, ladder escalation/cap, no high-frequency retries, store corruption fail-closed, pruning, atomicity, previous data preserved |
| `test_epic10_freshness.py` | 37 | before/at/after threshold, defaults, env parsing, run report |
| `test_epic10_chunking.py` | 28 | 0/1/14999/15000/15001/206080 boundaries, selection-before-chunking, no loss/duplication, temp hygiene |
| `test_epic10_safety.py` | 25 | fail-closed, no full-scope fallback, read-only AST guards, no command construction, no credentials, downstream compatibility |
| `test_epic10_pipeline.py` | 20 | end-to-end through the real runner, reporting, failure propagation, pinned files byte-identical, duplicate-run protection |

Full regression: see section 11 (worktree run vs the recorded HEAD baseline).

## 8. Security (SS20)

* No new capability: the selector executes nothing, builds no command string, opens
  no socket (AST-pinned: no `subprocess`/`socket`/`ssl`/`urllib`/`http`/`requests`,
  no `os.system`/`popen`, no string literal containing a `dnsx` invocation).
* It may only **read** the pinned collections (AST guard: no `save`/`update`/
  `delete`/`modify`/`insert` calls rooted at `Subdomains`/`LiveSubdomains`/
  `Programs`/`DnsBruteStatus`).
* Scope, authorization, wildcard detection, resolver rate limit, shell escaping and
  the command shape are all in pinned files and are **byte-identical to production**
  (asserted by hash for `ns/*`, `run-pipeline.sh`, `pipeline_lib.sh`).
* No secrets: the state file holds hostnames and counters only (pinned by test); no
  credential-shaped literal appears in the new module; the delivery guard's
  `SECRET_CONTENT` scan is clean.
* `scripts/check-aec-readonly.sh` → VERIFIED (no pinned file drifted).

## 9. Production validation (SS15)

Read-only against the real collections (no DNS executed, nothing written):

```
indeed.net candidates (Subdomains rows): 206,080
LiveSubdomains rows                    :  16,842
valid candidates                       : 206,067
invalid (malformed)                    :      13   (all literal wildcard entries "*...")
never resolved                         : 189,225
changed since last resolution          :       8
resolution age  <12h 3,216 | 24-48h 2,340 | >7d 11,286
providers       dynamicBF 201,076 | subfinder 4,990 | findomain 2,334 | assetfinder 1,768 | crtsh 1,718 | ...
```

Selection under candidate freshness policies (MEASURED timestamps, retry state
empty on a fresh install):

```
freshness=  0h -> selected 206,067   fresh_skipped      0
freshness= 12h -> selected 202,851   fresh_skipped  3,216
freshness= 48h -> selected 200,511   fresh_skipped  5,556
freshness=168h -> selected 200,511   fresh_skipped  5,556
```

Full-scope selection through the production provider (read-only, no DNS):

```
FULL SCOPE selection : 103.75s for 206,080 names
  selected 202,851 | scope indeed.net | duplicates 0 | invalid 13
  NEW 189,225 | CHANGED 8 | STALE 13,618 | FRESH 3,216 | RETRY_BACKOFF 0
  chunks at 15,000   : 14
```

**At the next scheduled run (2026-09-24 20:30 UTC) with the default policy the
classification is `NEW 189,225 / STALE 16,834 / CHANGED 8 / FRESH 0`** — i.e. the
nightly candidate set is unchanged (206,067 valid names, 13 malformed names now
excluded and reported). What the defaults buy is duplicate-run protection, and that
is measurable today: a second run right now would skip the 3,216 names resolved in
the last 12h.

End-to-end proof in production is **the next scheduled run** — stated honestly, not
faked: no manual pipeline run was started (SS15 forbids a multi-hour unscheduled
production recon run).

## 10. Measured vs estimated performance (SS13)

**Measured** (this host, this scope):

* dnsx throughput: 11.4 names/second (25,001 real names in 2,201s, whole list
  queried, exit 0) — from the promoted ops work.
* Scope shape: 206,080 candidates; 16,842 resolved; 189,225 never resolved.
* Selection cost through the **production Mongo provider**: **103.75s for
  206,080 names** (11 bounded `$in` batches per collection). The fixture-path
  figure is ~1.2s; the real number is the Mongo one and is quoted as such.
  Provider correctness was cross-checked on a real 5,000-name slice against
  direct queries: 0 missing entries, 0 resolved mismatches, 0 change-detection
  mismatches.
* Freshness effect: at most 5,556 of 206,080 names skippable (2.7%) at any window.

**Estimated** (clearly labelled; requires several real runs to measure):

Simulated steady state over the real 189,225 never-resolved names (40 runs at a 24h
cadence, assuming they stay unresolved):

| `DNS_RETRY_BACKOFF_HOURS` | unresolved queried per run | saved |
|---|---|---|
| `12` (default) | 189,225 (100%) | 0% |
| `12,72` | 66,228 (35%) | 65% |
| `12,72,168` | 37,845 (20%) | 80% |
| `168` | 28,383 (15%) | 85% |

At 11.4 names/s the ~5h DNS step would fall to roughly 1-2h with a ladder. The first
run after enabling one is unchanged (every unresolved name is NEW once).

**Conclusion for the operator:** freshness alone cannot fix this scope — 92% of the
names never resolve, so the *retry ladder* is the lever that matters, and it is a
one-variable decision with the numbers above.

## 11. Regression and gates

* Focused: **274 tests green** (245 new EPIC10 tests + the 29 tests of the two
  adapted pre-existing NS suites).
* Full discovery in the worktree: **11,218 tests, 372 failing entries**
  (243 failures + 129 errors, 17 skipped).
* Same discovery on a `git archive HEAD` baseline: **10,587 tests, 379 failing
  entries** (253 + 123, 18 skipped) — i.e. the change adds 631 tests and the
  failing-entry count went **down** by 7.
* Failing-set diff: **no EPIC10 / NS / DNS / utils.common test fails in either
  run** (0 of 372). The 10 names that appear only in the worktree run all belong
  to `tests/test_investigations_api.py`, which (a) imports nothing on the DNS
  path, (b) passes **14/14 in isolation** with the change present, and (c) is
  data-dependent on the untracked `ai_data/investigations/` directory that
  `git archive` cannot copy into the baseline — a baseline artifact, not a
  regression. The remaining differences are the long-standing
  order/state-dependent AI-ops/command-center/UI failures recorded in earlier
  EPICs.
* `scripts/check-aec-readonly.sh` → READ-ONLY VERIFIED (116 pinned files, no
  drift; 200 unrelated dirty paths reported as informational).
* Security/guard suites (`test_aec_import_guard`, `test_aec_readonly_guard`,
  `test_delivery_guard`, `test_delivery_policy`): **109 tests OK**.
* `scripts/check-aec-readonly.sh` → READ-ONLY VERIFIED.
* Delivery gates (`check.sh`): BRANCH / COMMIT / TESTS / PATH_GUARD / REPORT /
  PRODUCTION — all PASS; `diff_guard.py` verdict PASS.

## 12. Downstream compatibility (SS16)

`FRESH ≠ deleted`, `FRESH ≠ unresolved`, `FRESH = intentionally not queried this
run`. The selector never writes to the collections: a skipped name keeps its
`LiveSubdomains` row (IPs, CDN, timestamps) untouched, so the HTTP stage
(`LiveSubdomains.objects(scope=..., cdn__ne="Internal")`) keeps scanning it exactly
as before. Pinned by test (a fake collection reproducing the HTTP stage's query still
returns a FRESH name) and by the run report, which states `Queried`/`Resolved`
separately from `Skipped`.

## 13. Configuration (SS17)

`DNS_RESOLUTION_ENABLED` (true) · `DNS_RESOLUTION_FRESHNESS_HOURS` (12) ·
`DNS_RETRY_BACKOFF_HOURS` (12) · `DNS_RESOLUTION_FORCE` (false) ·
`DNS_RESOLUTION_STATE_FILE` (`ai_data/dns/incremental_state.json`) ·
`NS_DNSX_CHUNK_SIZE` (15000, unchanged code constant).

No `.env` change is required — `run-pipeline.sh` already exports the environment to
every step and every knob has a working default. **Production configuration change
required: none.**

## 14. Known limitations (SS19)

1. Default policy yields no work reduction by design (safety over savings); the
   reduction is one env var away, with measured numbers.
2. Freshness has little leverage on brute-force-heavy scopes.
3. Attempt state is a bounded, atomic, gitignored file, not a database; deleting it
   makes unresolved names NEW again (safe, just more work).
4. Change detection is provider-based only (no input content hash exists in the
   schema).
5. The hook lives in `utils/common.py` because `ns/watch_ns_all.py` is pinned
   read-only; moving it into the caller needs a read-only-manifest decision.
6. End-to-end production proof is the next scheduled run.

## 15. Production impact

* Production checkout untouched: `b58d0b2`, 27 dirty entries preserved (verified
  before and after).
* No pinned file modified; no destructive git operation; history not rewritten.
* The change is inert until promoted: the NS step keeps its current behavior until
  `/opt/watch` carries the new code.
