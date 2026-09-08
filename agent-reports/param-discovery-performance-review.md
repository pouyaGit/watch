# Param Discovery - Performance & Code Review

Task: analyze `crawl/watch_param_discovery.py` and the supporting
`database/db.py` to identify safe, local performance improvements that do
NOT change discovery semantics. No production scans, no DB schema changes,
no commits.

Baseline under analysis (provided by user, not modified):
- x8 4.3.1-main, `User-Agent: curl/8.5.0`
- wordlist: `burp_params_unique.txt` (6453 unique params)
- x8 flags: `-c 8 -W 2 --timeout 10 --verify -X GET`
- outer per-endpoint x8 timeout: 60s (`X8_TIMEOUT`)
- 4GB RAM / 2 CPU VPS
- production test on 13 Indeed WordPress endpoints:
  - GET-only: 13 endpoints in ~10.6 min, 225 new params
  - GET+POST was ~2x slower (rejected)

---

## A. Current Architecture

Single-file driver `crawl/watch_param_discovery.py` (575 lines) with no
parallelism of its own - parallelism is delegated entirely to the `x8`
binary. The Python loop is a strict serial queue over MongoDB-endpoints
collection. The hot path per endpoint is:

```
main()
  -> get_pending_endpoints()          # 1 query, all results fetched eagerly
  -> for ep in endpoints:             # serial loop
        check budget / skip if !example_url
        build_x8_target_url(ep.example_url)
        run_x8(target, get_wordlist_for_program(ep.program_name))
             subprocess.call(["which", "x8"])         # <-- per endpoint
             write tempfile
             build cmd list
             subprocess.run(cmd, capture_output=True, timeout=60)   # x8 does the work
             parse JSON, normalize, dedupe
        update ep.param_records / params_from_x8 / params / x8_checked
        ep.save()                       # 1 full doc save per endpoint
        time.sleep(0.5)                 # inter-endpoint delay
  -> export_wordlists()                # runs ONCE at the end
        Endpoints.objects.distinct("program_name")
        for each program:
            Endpoints.objects(program_name=prog).only("params")
            aggregate -> write <prog>_params.txt
  -> send_telegram(summary)
```

### What lives where

| File | Role |
|---|---|
| `crawl/watch_param_discovery.py` | Driver, x8 invocation, parsing, dedupe, save, wordlist export. |
| `database/db.py:128-155` | `Endpoints` Document - the only collection the discovery loop reads/writes. |
| `database/db.py:738-770` | `_snapshot_endpoint_params` (used by crawl, not by discovery). |
| `wordlists/burp_params_unique.txt` | 6453-entry canonical wordlist. |
| `wordlists/params_priority.txt` / `params_common.txt` / `params_1000/1500/2000.txt` | Pre-existing reduced variants - currently NOT used by the driver. |
| `wordlists/{dell,indeed,Unknown}_params.txt` | Per-program exports written by `export_wordlists()` after each run. |

### Vocabulary contract (from `watch_param_discovery.py:49-55`)
```
method   ∈ {GET, POST, PUT, PATCH}
location ∈ {query, body}
source   ∈ {crawl, x8}
```

`None` vs `[]` semantics (line 123-127, 466-472):
- `None` = x8 did NOT run to completion (binary missing / 60s timeout
  / execution error / unparseable JSON). Caller MUST NOT mark the
  endpoint `x8_checked=True`.
- `[]`  = x8 ran cleanly and found nothing. Endpoint is
  `x8_checked=True`. (Recompute on rerun is redundant but harmless -
  noted in the source at `watch_param_discovery.py:370-374`.)

### Selection, retry, legacy requeue
- Selection: `x8_checked=False AND example_url__exists=True AND
  example_url NOT IN ["", None]`, ordered by `-hit_count`
  (`watch_param_discovery.py:297-308`). This already filters out the
  no-target infinite-loop class.
- Retry: implicit. An endpoint that x8 could not complete simply
  remains `x8_checked=False` and is re-selected next run.
- Legacy requeue: `--recheck-legacy-x8` (`watch_param_discovery.py:355-389`)
  flips `x8_checked` back to False ONLY for rows that have
  `x8_checked=True AND no param_records AND no params_from_x8`. Safe,
  idempotent, untouched by this review.

---

## B. Top 5 Bottlenecks, Ranked by Expected Impact

Ranked by how much wall-clock and/or per-endpoint latency they cost
without changing the result x8 produces.

### B1. `subprocess.call(["which", "x8"])` runs once per endpoint
- Where: `crawl/watch_param_discovery.py:135-137`
- It is called inside `run_x8`, which is invoked from the per-endpoint
  loop. On a run of N endpoints you fork+exec `which` N times, just to
  test a static fact that never changes during the run. For N=13 in
  the test, this is negligible, but for a 300-minute run hitting
  hundreds of endpoints it is pure overhead and is also a place where
  a single misfire (`which` returns 127 spuriously, missing x8, etc.)
  can hide.
- Expected impact: low absolute time, but pure win. Cheap fix.

### B2. `Endpoints.objects(...)` in `get_pending_endpoints` does NOT use `.only(...)` and materializes the full Document
- Where: `crawl/watch_param_discovery.py:297-308`
- The driver only needs `program_name`, `example_url`, `param_records`
  (for the in-loop dedupe), and `x8_checked` (already filtered server
  side). Today it pulls `path`, `subdomain`, `params`,
  `params_from_crawl`, `params_from_x8`, `hit_count`, `created_date`,
  `last_update`, `x8_last_checked` for every row. On 596k endpoints
  this is the single biggest read cost (the index on `x8_checked`
  is selective, but the document payload is large).
- A `.only("program_name", "example_url", "param_records")` and
  iterating without materializing (`.no_dereference()` semantics are
  not available on mongoengine, but `.only().timeout(False)` plus a
  pymongo cursor under the hood does the same) is the standard fix.
- This is the largest fixable per-run wall-clock win on the
  "select all pending endpoints" path.

### B3. `ep.save()` after every endpoint is a full-document write
- Where: `crawl/watch_param_discovery.py:535-538`
- The driver already uses `update_one` style operations when
  appending param records, but the code reassigns
  `ep.param_records`, `ep.params_from_x8`, `ep.params` then calls
  `ep.save()`. That serializes the full document and writes every
  field, including unchanged ones. With a 60-200s per-endpoint budget
  this is the second-largest write cost.
- Switching to `Endpoints._get_collection().update_one(
   {"_id": ep.id},
   {"$set": {"x8_checked": True, "x8_last_checked": now,
             "last_update": now},
    "$addToSet": {"param_records": {"$each": new_records},
                  "params_from_x8": {"$each": new_x8_names},
                  "params": {"$each": new_x8_names}}
   })` preserves semantics (param_records are unique-tuple on
  `(name, method, location, source)` - `$addToSet` on a DictField
  treats the whole dict as the key, which is correct for that
  purpose; the existing tuple-dedupe in the Python loop is then
  redundant for correctness but cheap and clear, so keep it) and
  avoids re-writing `hit_count`, `example_url`, etc.
- Expected impact: medium. Per-endpoint DB time drops from a full
  doc write to a tiny $addToSet patch. The bigger value is that it
  does not regress under large `param_records` growth (the array is
  embedded in the document, so a $set is the only thing that scales).

### B4. `export_wordlists()` re-queries `Endpoints` once per program at the end of the run
- Where: `crawl/watch_param_discovery.py:311-332`
- After the main loop, it does one `distinct("program_name")` plus
  one full collection scan per program. It already uses `.only("params")`
  (good), but it does N queries, one per program, and materializes
  the cursor into Python (`for ep in Endpoints.objects(...)`). On a
  corpus with 596k rows and ~10 programs this is on the order of
  several seconds; the bigger cost is the per-program query
  round-trip.
- Fix: collapse to ONE aggregation using `$group` over
  `program_name` with `$addToSet` on `params`, server-side. This
  trades N round-trips for 1 and avoids the `Endpoints.objects()`
  Python-level cursor overhead.
- Expected impact: medium-low. End-of-run only, not in the hot loop,
  but easy and safe.

### B5. The in-loop "seen" set is rebuilt from the full `param_records` array on every endpoint
- Where: `crawl/watch_param_discovery.py:480-510`
- `param_records` can grow without bound (every x8 finding for the
  endpoint is appended). For an endpoint with thousands of records,
  building the `seen` set from `ep.param_records or []` is O(R) per
  endpoint where R is the existing record count, and then we still
  do `O(F)` membership tests where F is the new finding count.
- The dedupe is also redundant: x8 is only run once per
  `(name, method, location, source)` 4-tuple within an endpoint
  (unless legacy requeue), and the unique-tuple constraint in
  `_append_param_records` / `upsert_endpoint` is what makes the
  persistence safe. The Python `seen` set is only an optimization to
  avoid re-sending the same data to Mongo, not a correctness need.
  The simplest correct optimization is to drop the `seen` set and
  use the `$addToSet` semantics on the write path (per B3) so Mongo
  does the dedupe.
- Expected impact: low-medium per-endpoint. The x8 run itself
  dominates endpoint time, so this is in the noise for endpoints
  with <1000 records, but on a corpus where some endpoints have
  tens of thousands of params it matters.

### Other items considered and ranked below the top 5

- **Subprocess overhead (`capture_output=True`)**:
  `subprocess.run(cmd, capture_output=True, text=True, timeout=60)`
  drains x8's stdout/stderr into Python strings. x8's verbose output
  on 6453-param runs is non-trivial. We do not use the output (we
  read JSON from the file), so the drain is pure overhead. Using
  `stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL` is a tiny
  safe win. Ranked below top 5 because x8 already does its own I/O
  buffering and the absolute byte volume is small.
- **Wordlist re-read on every call**: `get_wordlist_for_program()`
  returns the same constant `WORDLIST` per call, so there is no I/O
  per endpoint here. Not a bottleneck.
- **`time.sleep(X8_RATE_LIMIT_DELAY)` (0.5s)**: deliberate, not a
  bug. Kept as is.
- **`X8_TIMEOUT = 60` outer timeout**: see Section D - the
  "intelligent handling" question is a benchmark, not a code change.

---

## C. Safe Optimizations We Can Implement Now

All items below are local to `crawl/watch_param_discovery.py` and
`database/db.py`, do NOT change discovery semantics, do NOT change
the `-c 8 -W 2 --timeout 10 --verify -X GET` baseline, do NOT change
the wordlist, and do NOT touch the schema.

### C1. Hoist the `which x8` probe to a one-shot check
- `crawl/watch_param_discovery.py:135-137`
- Replace the per-call `subprocess.call(["which", "x8"], ...)` with
  a module-level cached boolean (or call `shutil.which("x8")` from
  `shutil` once at startup and reuse the string path).
- Behavior change: none. x8 was already found at startup; we just
  stop paying for it on every endpoint.

### C2. Slim the pending-endpoints query
- `crawl/watch_param_discovery.py:297-308`
- Add `.only("program_name", "example_url", "param_records")` to the
  pending query, plus `Endpoints._get_collection().find(...)` with a
  projection if a leaner iteration is desired. The current index on
  `x8_checked` (`database/db.py:152`) already supports the filter.
- Behavior change: none. Only the network payload to Python is
  reduced; the loop still has the fields it needs.

### C3. Drop unnecessary capture of x8 stdout/stderr
- `crawl/watch_param_discovery.py:163-170`
- Switch to `stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL`
  and drop the `text=True` flag. The output is unused - we read
  results from the JSON file x8 writes.
- Behavior change: none. We already treat any non-zero/non-timeout
  failure as `None` (no-finding-or-fail = `None`), so capturing
  stderr was never used.

### C4. Bypass the in-loop `seen` set; let Mongo dedupe via $addToSet
- `crawl/watch_param_discovery.py:479-510`
- Drop the `seen` set, build `new_records` directly, and write via
  `update_one(..., {"$addToSet": {"param_records": {"$each": records}}})`.
  This requires the change in C5 to land in the same commit, but it
  is local and safe.
- Behavior change: equivalent at the storage level (param_records is
  unique on the (name,method,location,source) dict shape, so
  `$addToSet` produces the same set the Python loop did).

### C5. Replace per-endpoint `ep.save()` with a targeted update_one
- `crawl/watch_param_discovery.py:535-538`
- Use `Endpoints._get_collection().update_one(
     {"_id": ep.id},
     {"$set": {"x8_checked": True,
               "x8_last_checked": datetime.now(),
               "last_update": datetime.now()},
      "$addToSet": {"param_records": {"$each": new_records},
                    "params_from_x8": {"$each": new_x8_names},
                    "params":         {"$each": new_x8_names}}
      })`
  when there ARE new records, and a `$set` only (no `$addToSet`)
  when there are none.
- Behavior change: equivalent. The `seen`/Python dedupe is replaced
  by `$addToSet`'s set semantics on the embedded dict; both produce
  the same `param_records` array.

### C6. Single-aggregation `export_wordlists()`
- `crawl/watch_param_discovery.py:311-332`
- Replace the N-query loop with a single pymongo aggregation:
  `Endpoints._get_collection().aggregate([
     {"$unwind": {"path": "$params", "preserveNullAndEmptyArrays": False}},
     {"$group": {"_id": "$program_name",
                 "params": {"$addToSet": "$params"}}},
     {"$project": {"params": 1}}
  ])`, then write the file per program. No schema change.
- Behavior change: identical file contents. Faster, one round-trip
  instead of N+1.

### C7. Cached `requests.Session` for Telegram
- `crawl/watch_param_discovery.py:92-104`
- `send_telegram` is called up to ~3 times per run (start, end, plus
  checkpoint every 200). Create a module-level `requests.Session()`
  and reuse it; enable HTTP keep-alive.
- Behavior change: identical message bytes, faster TCP/TLS.

These seven items are the "now" set. None of them changes which
endpoints are scanned, which params are discovered, or how the
results are persisted.

---

## D. Optimizations That Need an Idle-Server Benchmark

These are real wins but their cost/value depends on hardware
behavior, especially on the 4GB / 2-core box, so they are out of
scope for a safe no-prod change.

### D1. Bump x8 `-W` (workers)
- The user explicitly flagged this as a future benchmark, not a
  code change. The driver code has NO hidden bottleneck that would
  make `-W > 2` unsafe today (we are not holding any per-worker
  state in Python - the loop is strictly serial over the
  `_get_collection().find(...)` cursor, and there is no global
  lock). What would need to be measured:
  - resident set after bumping `-W` to 3 or 4 with the current
    wordlist of 6453;
  - swap-in / CPU steal under concurrent x8 invocations;
  - whether the MongoDB `Endpoints` collection can absorb the
    resulting per-second `update_one` rate (B3 helps here).
- Code change required if benchmark supports it: only the
  `"-W", "2"` literal at `crawl/watch_param_discovery.py:155`.
  No other refactor.

### D2. The 60s outer `X8_TIMEOUT` and how to handle it intelligently
- Today's behavior (`watch_param_discovery.py:164-170`):
  if x8 exceeds 60s, the endpoint is left `x8_checked=False` and
  retried next run. This is correct but expensive on misbehaving
  endpoints - one slow target can consume 60s of the loop plus
  another 0.5s rate-limit delay.
- Smart alternatives (each requires a benchmark):
  1. `X8_TIMEOUT` reduced to 30s and add a per-endpoint
     "slow_count" field; deprioritize endpoints that have timed
     out 3+ times. This needs schema for `slow_count`, so it is
     blocked until a schema change is approved.
  2. Add a soft "fast path" - run x8 with `--max 1` and the top-N
     wordlist on the first attempt; full run only if the fast
     pass finds something. This is a benchmark, not a code edit.
  3. Pre-flight HEAD with curl, skip x8 if HEAD times out. Also
     a benchmark, and changes semantics if HEAD returns 200 but
     x8 needs a different endpoint.
- Recommendation: do NOT change this in code yet. The 60s timeout
  is the safety belt; reducing it without idle-server data risks
  dropping real findings.

### D3. Wordlist segmentation (common + observed + program-specific)
- The user already tested reducing burp from 6453 -> 1000 / 2000
  and lost recall (e.g. `sid` was missed). The math from the
  existing per-program exports is the deciding data point:
  - `dell_params.txt` has 141 unique names not in burp
  - `indeed_params.txt` has 66 unique names not in burp
  - i.e. the program-specific tail is small (~2-3% of the base)
    but contains exactly the kind of obscure names that get
    missed in random sampling.
- The CURRENT code architecture DOES support a clean wordlist
  composition. `get_wordlist_for_program(program_name)` is
  already the single entry point (`watch_param_discovery.py:107-112`),
  and the returned path is passed straight to `run_x8`. So the
  change to "compose a temp file = common + observed + program
  extras" is purely a function rewrite plus a one-line change
  to the run loop (it would no longer be a constant path; it
  would have to be re-written when the observed set changes).
- BUT: the architecture assumes a stable file path. x8 reads
  the file from disk per call; rewriting a file 6453*200
  times is fine on tmpfs, but writing a per-program
  composition every iteration is wasteful. A more honest
  design is:
  - One precomputed per-program file
    `wordlists/params_<program>.txt` that is the union of
    `burp_params_unique.txt` and the program-specific tail,
    computed by `export_wordlists()` after each run.
  - For programs with no observed tail, fall back to burp.
  - For `params_common.txt` / `params_priority.txt` (already on
    disk), leave them as future benchmarks and DO NOT wire
    them in.
- This is a benchmark because the win is "fewer x8 requests per
  endpoint -> faster wall clock" and that needs measurement on
  real targets to know whether the small wordlist cut actually
  shortens x8's runtime proportionally or is dominated by
  network latency. We have not measured that.
- Recommendation: implement and benchmark a SMALL prototype
  (1 program, 1 endpoint) offline; do NOT ship to production
  until the benchmark shows the expected wall-clock reduction
  without losing findings.

### D4. `Endpoints.objects` eager materialization in the main loop
- The list returned by `get_pending_endpoints` (`watch_param_discovery.py:308`)
  is `list(query)`. On 596k rows this materializes every
  document in memory. The loop only needs ~`max_minutes *
  (throughput per minute)` rows. Iterating the cursor directly
  and re-querying when the cursor dries up is more memory-safe,
  but on the current 4GB box the 596k rows of small documents
  are fine (~hundreds of MB at worst), and changing to
  cursor-iteration changes the time-budget math
  (`len(endpoints)` in the Telegram checkpoint is wrong if the
  cursor is lazy). Not worth a code change until the corpus
  grows past ~1M rows.

### D5. Endpoint prioritization / "deprioritize without deleting"
- Today ordering is by `-hit_count` (`watch_param_discovery.py:305`).
  A clean deprioritization signal is "this endpoint has been
  x8-checked at least once AND yielded zero new params AND
  has not been re-crawled in K days". That is a triage
  heuristic, not a delete. It needs a new field (`x8_zero_count`
  or `low_value`) and a new index - which is a schema change
  and is OUT of scope for this review. Recommend a separate
  ticket.

---

## E. Exact Files / Lines That Would Need Modification

If/when the "now" set (C1-C7) is implemented, the diffs are:

| Item | File | Lines (current) | Change |
|---|---|---|---|
| C1 | `crawl/watch_param_discovery.py` | 135-137 | Replace per-call `subprocess.call(["which", "x8"], ...)` with a one-shot check at startup. |
| C2 | `crawl/watch_param_discovery.py` | 297-308 | Add `.only("program_name", "example_url", "param_records")` to the pending query. |
| C3 | `crawl/watch_param_discovery.py` | 163-170 | Switch `subprocess.run` to `stdout=DEVNULL, stderr=DEVNULL`, drop `text=True`. |
| C4 | `crawl/watch_param_discovery.py` | 479-510 | Drop the `seen` set; build `new_records` directly. |
| C5 | `crawl/watch_param_discovery.py` | 535-538 | Replace `ep.save()` with `Endpoints._get_collection().update_one(...)`. |
| C6 | `crawl/watch_param_discovery.py` | 311-332 | Replace per-program cursor loop with a single aggregation. |
| C7 | `crawl/watch_param_discovery.py` | 92-104 | Use a module-level `requests.Session()` in `send_telegram`. |
| D1 | `crawl/watch_param_discovery.py` | 155 | Change `"-W", "2"` ONLY after the idle benchmark. |
| D2 | `crawl/watch_param_discovery.py` | 43, 164-170 | Adjust `X8_TIMEOUT` ONLY after the idle benchmark. |
| D3 | `crawl/watch_param_discovery.py` | 107-112, 461-464 | Compose per-program wordlist from a precomputed file. Benchmark first. |

`database/db.py` is NOT touched by the "now" set. The `Endpoints`
indexes (`database/db.py:149-155`) already cover the filter and
ordering used by the driver.

---

## F. Tests Run and Results

The user asked for only fast tests, no network scans, no production
jobs. I ran:

### F1. `py_compile` on both modified (read-only) files
- `python3 -c "import py_compile; py_compile.compile('crawl/watch_param_discovery.py', doraise=True); py_compile.compile('database/db.py', doraise=True); print('OK')"`
- Result: `OK`. Both files compile clean.

### F2. Static review of imports / call sites
- All call sites of `Endpoints` and `param_records` referenced by
  the driver are accounted for. No dead imports, no references to
  fields that are not in the Document.
- `run_x8` callers: only `main()` (`watch_param_discovery.py:461-464`).
  The function signature is stable, so the in-line changes (C1, C3)
  are local.

### F3. Tests NOT run (intentionally)
- No `pytest` suite exists in the repo. The only "test" file is
  `test_telegram.py`, which is a manual smoke script, not a unit
  test. The user's instruction is "no network scans, no
  production jobs", so I did not create or run a unit test suite
  either. Creating a new test framework + tests for the
  optimizations is recommended in a follow-up (see
  Section G "deliberately not made").

### F4. Schema / data integrity checks (static, not run against Mongo)
- `Endpoints.meta.indexes` (`database/db.py:149-155`):
  - `(program_name, subdomain, path)` unique - covers the discovery
    write path.
  - `x8_checked` - supports the pending filter.
  - `-hit_count` - supports the order-by. Good.
- `Endpoints.param_records` is `ListField(DictField(), default=[])`
  with no explicit size cap. The proposed C5 `$addToSet` patch does
  not grow beyond the current `ep.save()` semantics.

### F5. Sanity of wordlist math
- `burp_params_unique.txt` = 6453 unique params
- `dell_params.txt` has 141 names not in burp (program-specific tail)
- `indeed_params.txt` has 66 names not in burp (program-specific tail)
- `params_priority.txt` is a subset (457 not in burp), `params_common.txt` is a subset (256 not in priority). These two are
  pre-existing reduced variants that the driver does NOT use today;
  leaving them alone until the D3 benchmark is done.

---

## G. Proposed Changes I Deliberately Did NOT Make

For each, the reason is one of: out-of-scope (schema / production),
or no measured evidence the change is a net win.

1. **No change to `X8_TIMEOUT` (60s)** - reducing this is a
   benchmark, not a code fix; the current value is the safety belt.
2. **No change to `-c 8 -W 2 --timeout 10 --verify -X GET`** - these
   are the user's pinned baseline. The driver has NO hidden
   bottleneck that would make higher `-W` unsafe; it just has not
   been measured. D1 is a benchmark.
3. **No schema changes** - the user explicitly forbade them. In
   particular:
   - No `slow_count`, `low_value`, or `x8_zero_count` field.
   - No new index.
   - No requeue of legacy endpoints beyond what the existing
     `--recheck-legacy-x8` does.
4. **No wordlist swap to `params_1000.txt` / `params_2000.txt`** -
   user already verified that loses recall (e.g. `sid`). The
   D3 per-program composition idea is left as a benchmark.
5. **No removal of the `seen` set without also adopting C5** - that
   would be a silent behavior change (Mongo `$addToSet` on a
   `DictField` is correct here, but I am not going to commit it
   unless both halves of the swap are reviewed together).
6. **No rewrite of `param_records` to a separate collection** -
   that would be a schema change, and the embedded-list design is
   working fine for current sizes.
7. **No new test framework** - the user asked for analysis + safe
   code preparation only, and "fast tests only". Adding a `tests/`
   directory + pytest fixtures + DB mocks is a separate task; I
   mention it in recommendations but did not do it.
8. **No change to `crawl/watch_crawl_all.py` /
   `watch_crawl_fresh.py` / `watch_crawl_wildcard.py` / DNS /
   brute-force / recon** - user forbade modifying DNS/recon/crawl
   behavior.
9. **No commit / push** - user forbade it.
10. **No change to `export_wordlists` file naming or output
    format** - downstream (next-run) wordlist composition in D3 may
    want to read these files, so their format is part of the
    contract; not touched.

---

## Recommendations (next steps, not in this report's scope)

1. Apply C1-C7 in a single small PR against
   `crawl/watch_param_discovery.py` only. Re-run a test
   (`--filter indeed.com --max-minutes 20`) to confirm the 13-endpoint
   10.6-minute baseline still produces 225 new params within noise.
2. When the box is idle (e.g. next maintenance window), run D1 and
   D2 as benchmarks. Capture `free -h` and `top` deltas.
3. After D1 lands, do D3 with the per-program composition as a
   secondary pass. If the small wordlist shows the same recall,
   promote the change to a separate run-mode flag.
4. Add `tests/test_watch_param_discovery.py` with unit tests for
   `map_x8_location`, `normalize_param_record`, `build_x8_target_url`,
   `is_legacy_x8_endpoint`, and a fake-`subprocess` test for `run_x8`
   to lock the None vs [] semantics.
