# Incremental DNS Resolution & Pipeline Scope Control (EPIC10)

Status: implemented, tested, awaiting promotion. Owner: agent/daily-development.

## 1. The problem this solves

The NS step (`ns/watch_ns_all.py`) resolves **every** name collected for a scope on
**every** nightly run. Two separate problems follow from that:

1. **Invocation safety** — one `dnsx -l` call over a whole scope is bounded by
   `NS_COMMAND_TIMEOUT` (3600s). `indeed.net` reached 206,080 names, which needs
   ~5h of query time, so the call died every night from 2026-09-17 and
   `watch.service` failed. *Fixed by chunking* (`NS_DNSX_CHUNK_SIZE = 15000` in
   `utils/common.py`): the work per invocation is bounded.
2. **Total work** — chunking bounds each invocation but does not reduce the total.
   The scope grows by ~40,000 names/day (201,076 of 206,080 names come from the
   daily `dynamicBF` brute force), so the nightly DNS step grows without limit and
   will keep pressing against the pipeline's 6h window. *This document* describes
   the fix for problem 2: resolve only the names that are **eligible**.

## 2. Where the selection happens

`ns/watch_ns_all.py` is **pinned read-only** by `aec/readonly_manifest.json`, so the
selection cannot live in the caller. It lives in the **unpinned** helper every DNS
query already passes through — `utils/common.py` (`_dnsx_run_plan` /
`run_command_in_zsh_ns`) — which sees the bulk `dnsx -l <file>` command before it is
chunked:

```
all discovered candidates          (the list file the pinned caller wrote)
      -> eligibility filter        (utils/dns_incremental.py)
      -> deduplicate
      -> chunk <= 15000            (utils/common.py, unchanged)
      -> dnsx                      (unchanged command shape, unchanged timeout)
      -> wildcard filter + upsert_lives (pinned caller, untouched)
```

The pinned caller, its log line, its wildcard filtering and its persistence are
byte-identical to before. The selector only decides *which names are put in front of
dnsx*.

## 3. Eligibility states

Every candidate gets exactly one category. Precedence is high → low:

| Category | Meaning | Queried? |
|---|---|---|
| `INVALID` | not a resolvable DNS name (empty, whitespace, `*`, no dot, bad label, >253 chars, not lowercase) | no, reported with reason |
| `FORCE` | `DNS_RESOLUTION_FORCE=true`; every valid name regardless of state | yes |
| `NEW` | no successful resolution on record (`LiveSubdomains` row absent) and no previous attempt | yes |
| `CHANGED` | resolved before, but the discovery record changed after it (`Subdomains.last_update > LiveSubdomains.last_update`, i.e. a new provider/source was merged) | yes |
| `RETRY_ELIGIBLE` | never resolved, previous attempt(s), retry backoff elapsed | yes |
| `RETRY_BACKOFF` | never resolved, previous attempt(s), backoff not yet elapsed | no, reported with `next_retry_at` |
| `STALE` | resolved before, unchanged, at least `freshness_hours` old | yes |
| `FRESH` | resolved before, unchanged, younger than `freshness_hours` | no |

`RETRY_BACKOFF` is an extension to the mission's minimum vocabulary: a name waiting
for its next retry is neither "eligible" nor "fresh", and calling it anything else
would hide why it was not queried.

Signals used (all pre-existing):

* `LiveSubdomains.last_update` — `upsert_lives()` refreshes it on every successful
  resolution, so it is the resolution timestamp.
* `Subdomains.last_update` — `upsert_subdomain()` bumps it **only** when a new
  provider is merged for an existing name, so `Subdomains.last_update >
  LiveSubdomains.last_update` is a real "the input changed after we resolved it"
  signal. No change is ever inferred from an unrelated timestamp.

## 4. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DNS_RESOLUTION_ENABLED` | `true` | `false` = pre-EPIC10 behavior (resolve everything, no state reads, no state writes) |
| `DNS_RESOLUTION_FRESHNESS_HOURS` | `12` | a resolved name younger than this is FRESH (not queried). `0` disables freshness skipping |
| `DNS_RETRY_BACKOFF_HOURS` | `12` | comma-separated ladder, e.g. `12,72,168`. `0` = retry every run |
| `DNS_RESOLUTION_FORCE` | `false` | `true` = resolve every valid candidate this run |
| `DNS_RESOLUTION_STATE_FILE` | `ai_data/dns/incremental_state.json` | attempt-state file (gitignored, hostnames + counters only) |
| `NS_DNSX_CHUNK_SIZE` | `15000` | unchanged code constant; FORCE does not raise it |

Nothing in `.env` needs to change: `run-pipeline.sh` already exports the
environment to every step, and every knob has a working default.

### Why these defaults

Both defaults are derived, not invented:

* **freshness 12h** — the project already treats `last_update >= now-12h` as
  "recently updated" (`app.py`). Nightly runs are ~24h apart, so a name resolved in
  last night's run is ≥12h old at tonight's run and is revalidated as `STALE`:
  **nightly coverage is unchanged**. What the window buys is duplicate-run
  protection — a second run (manual, retried, or a lock miss) inside 12h does no
  DNS work at all.
* **retry ladder 12h** — same reasoning: a name that failed tonight is retried on
  tomorrow's run (≥12h later), so nightly retry coverage is unchanged, while a
  duplicate run within 12h does not hammer resolvers with the failing names.

Neither default silently changes what gets resolved at the nightly cadence. The
levers for real work reduction are documented (and measured) below.

## 5. Freshness: what it can and cannot save

Measured on the real `indeed.net` scope (2026-09-24, read-only):

* 206,080 candidate rows, of which **189,225 have never resolved**, 16,842 have
  resolved, 13 are `INVALID` (all of them literal wildcard entries `*...` that were
  being handed to dnsx every night).
* Resolution age of the resolved names: `<12h` 3,216 · `24-48h` 2,340 · `>7d` 11,286.
* Selected set by policy: `0h` → 206,067 · `12h` → 202,851 · `48h` → 200,511 ·
  `168h` → 200,511.
* Cost of the selection itself, through the production Mongo provider:
  **~104s for 206,080 names** (11 bounded `$in` batches per collection), against
  ~5h of DNS work it filters. The attempt store is read once per run.

So freshness alone saves at most ~2.7% of the scope, because it can only skip names
that *resolved* — and 92% of this scope never resolves. At the default (12h) the
next nightly run selects 206,067 names, i.e. exactly today's coverage.

## 6. Retry: where the real reduction is

Attempt history did not exist anywhere: `Subdomains`/`LiveSubdomains` are pinned
models with no attempt fields, and an unresolved name simply has no row. The
selector therefore keeps its own bounded state file (`ai_data/dns/`, gitignored)
holding, per unresolved name: attempt count, consecutive-failure streak, last
attempt, last answer. Success is still owned by `LiveSubdomains` — the state file
never marks anything resolved.

Retry eligibility = `last_attempt + ladder[min(streak, len(ladder)) - 1]` hours.
The ladder escalates and caps; a name that fails forever is never dropped, it is
retried at the final rung's cadence.

Simulated steady state over the **real** 189,225 never-resolved names (40 runs at a
24h cadence, assuming they stay unresolved — an estimate, not a measurement):

| `DNS_RETRY_BACKOFF_HOURS` | unresolved queried per run | saved |
|---|---|---|
| `12` (default) | 189,225 (100%) | 0% |
| `12,72` | 66,228 (35%) | 65% |
| `12,72,168` | 37,845 (20%) | 80% |
| `168` | 28,383 (15%) | 85% |

At 11.4 names/s (the measured dnsx rate for this host/scope), today's ~5h DNS step
would fall to roughly 1-2h with a ladder. **The first run after enabling a ladder is
unchanged** (every unresolved name is `NEW` and must be attempted once); the
reduction accumulates from the following runs.

Trade-off to accept knowingly: with `12,72,168`, a hostname that has failed three
times is only re-checked weekly, so a newly-live host can take up to a week to be
noticed. That is why the default does not do it.

## 7. FORCE

`DNS_RESOLUTION_FORCE=true` selects every valid candidate. It is still:

* chunked at 15,000 names per invocation,
* wildcard-filtered by the pinned caller,
* timeout-bounded per invocation,
* written to the same report and the same attempt state.

FORCE never means an unbounded dnsx invocation. `INVALID` names are still excluded
(they cannot resolve) and are still reported.

## 8. Fail-closed

Any failure while **reading** prior state — unreadable or corrupt state file,
unsupported schema, Mongo unavailable, malformed policy value — raises
`DnsSelectionError` and aborts the DNS step:

* dnsx is never invoked with the full candidate list (no "assume everything is
  eligible" fallback — that is the failure mode that would re-create the 5h run),
* the step exits non-zero, which `pipeline_lib.sh` turns into a failed pipeline run,
* existing `LiveSubdomains` data is untouched, temp files are cleaned up.

Failure to **write** post-run bookkeeping is different: the DNS results already
exist and are returned, so it is reported (`Attempt state: FAILED (...)`) and the
affected names simply stay `NEW`/retry-eligible next run — the safe direction.

## 9. Downstream semantics

**FRESH ≠ deleted. FRESH ≠ unresolved. FRESH = intentionally not queried this run.**

The selector never writes to `Subdomains` or `LiveSubdomains`. A skipped name keeps
its row — IPs, CDN, `created_at`, `last_update` — exactly as it was. The HTTP stage
reads `LiveSubdomains.objects(scope=..., cdn__ne="Internal")` and therefore keeps
scanning a FRESH name exactly as before; the Watch UI's "new in 24h"/"updated in
12h" views are unchanged. The only thing that did not happen is a DNS query.

The run report states `Queried` and `Resolved` separately from `Skipped`, so "not
queried" is never presented as "did not resolve".

## 10. Observability

Every NS invocation prints a selection block followed by a results block:

```
DNS Resolution (incremental selection)
-------------------------
Candidates:          206,080
Scope:               indeed.net
Duplicates:                0
New                    189,225
Stale                   16,834
Changed                      8
Invalid                     13
Selected:            206,067
Skipped:                  13
Skip reasons:     INVALID=13
Policy:              enabled=True freshness=12h retry_backoff=12h force=False
Selection time:          1.204s

DNS Resolution results
-------------------------
Queried:             206,067
Resolved:             16,842
Unresolved:          189,225
Chunks:          14/14 ok
DNS time:            18121.3s
Attempt state:    ok
```

Counts only — hostname lists are never logged. For any individual name,
`skip reasons` plus the category counts answer "why was this not queried?":
`FRESH` (within freshness), `RETRY_BACKOFF` (waiting for its next retry),
`INVALID` (cannot be a DNS name).

## 11. Operational recipes

| Goal | Setting |
|---|---|
| Duplicate-run protection only (default) | `DNS_RESOLUTION_FRESHNESS_HOURS=12`, `DNS_RETRY_BACKOFF_HOURS=12` |
| Moderate reduction, weekly worst-case recheck | `DNS_RETRY_BACKOFF_HOURS=12,72,168` |
| Aggressive reduction | `DNS_RETRY_BACKOFF_HOURS=24,168`, `DNS_RESOLUTION_FRESHNESS_HOURS=48` |
| Emergency full re-resolution | `DNS_RESOLUTION_FORCE=true` (one run) |
| Roll back entirely | `DNS_RESOLUTION_ENABLED=false` |

## 12. Known limitations

1. **No reduction at the default policy.** The defaults protect against duplicate
   runs and keep nightly coverage identical; the reduction must be switched on
   knowingly (section 6) because it trades detection latency for work.
2. **Freshness leverage is small for brute-force-heavy scopes** — most names never
   resolve, so only the retry policy moves the needle (section 5).
3. **Attempt state is a new file.** It is bounded (30-day prune, entry cap), atomic,
   and gitignored, but it is not a database: deleting it makes every unresolved name
   `NEW` again (safe, just more work). It is not consulted for names that have a
   `LiveSubdomains` row.
4. **Change detection is provider-based.** A name is `CHANGED` only when its
   provider/source list changed. There is no content hash of the discovery input,
   because none exists in the schema; this is documented rather than faked.
5. **The hook lives in `utils/common.py`.** `ns/watch_ns_all.py` is pinned
   read-only, so eligibility is decided in the unpinned helper on the same path.
   Moving it into the caller needs an operator decision to change the read-only
   manifest.
6. **Not proven end-to-end in production yet.** The selector is validated against
   fixtures and against the real collections read-only; the first full nightly run
   after promotion is the first end-to-end proof.
