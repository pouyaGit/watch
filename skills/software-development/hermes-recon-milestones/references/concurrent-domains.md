# Concurrent domain scheduling (recon + research loops)

Use for milestones that make independent loops run concurrently over the shared
persistent queue (e.g. a recon domain and a research/intelligence domain).

Existing architecture to reuse — do NOT build parallel systems:

- `lib/concurrent_domains.py` carries the persistent `scheduler_domains` table
  (per-domain: workers cap, claims/completed/failed totals, `starvation_flags`,
  owner_pid), `claim_for_domain()` (type-scoped claims over the existing atomic
  `store.claim_job`), `DomainWorkers` (bounded threads with an INJECTED executor),
  `observe_fairness()` and `ConcurrentScheduler`. Extend it; do not re-derive.
- The daemon main loop stays the ONE scheduler: wire the domain tick inside the
  existing exception-wrapped periodic block. A second loop is how duplicate work
  starts.
- Stage 4 `worker_observability` is the only worker registry — domain workers
  register there, never in a new table.

## Rules that cost time when missed

- Domain separation is job_type OWNERSHIP over the existing `jobs` table, not a
  second queue. `store.claim_job()` is already atomic
  (`UPDATE ... WHERE status='PENDING'`), so duplicate claims are structurally
  impossible — prove it with N parallel claimers on one row, not by assertion.
- Keep the layer executor-free until the balancing milestone exists:
  `ConcurrentScheduler()` with no executors must STILL persist its domain rows
  (state-only mode), so the daemon tick owns state independent of attached
  executors. Attaching live executors early is how a scheduling milestone
  silently ships the next stage.
- Because of that, this layer is CONTROL PLANE ONLY, and the report must say so:
  `claims_total = 0` with `state = ACTIVE` is the signature of domains that have
  never executed anything. A milestone that lands domain state without an executor
  has NOT made production concurrent — recon still runs as a periodic `cycle.py`
  subprocess and research as a daily singleton child, with no executor at all
  between them. Never sign READY FOR PRODUCTION for concurrency on the strength of
  domain rows plus green unit tests; state the measured duty cycle and dead zones
  instead, and leave the runtime claim for the milestone that attaches executors.
- Fairness before balancing is OBSERVATION ONLY: bump `starvation_flags` when a
  domain has pending work, has claimed nothing past the window, and the other
  domain is completing. Never steal capacity, never retune caps; deterministic
  fixed per-domain worker caps are the only bound.
- Registration and ticking must be idempotent under restart
  (`INSERT OR IGNORE` + `UPDATE`; a SELECT-then-INSERT check is a TOCTOU race that
  flakes only when several workers register at once — run the suite repeatedly),
  and counters must survive re-registration.
- Prove loop isolation with injected failing executors (one domain raises, the
  other completes) — never by exercising real recon/research paths in a test.
- Assert the global invariants inside the test file: `safety.GLOBAL_CEILING`,
  `len(scope_guard.TARGETS)` unchanged, and the new module exposes no fetch/http
  API at all. A scheduling layer that can make network calls would bypass the
  global ceiling by construction.
- Tick DB failure must be caught per domain and reported as an error string in
  the result dict — a raising tick crash-loops the daemon.

## Pre-existing suite traps in this project

- `scripts/test_pd_migration.py` has a rollback test that hard-codes
  byte-identical expectations for files it does not own (`lib/notify.py`,
  `lib/status.py`, `scripts/cycle.py`). Any milestone touching those files makes
  it report ~2 failures — classify them TEST_STALE / PRE_EXISTING in the report
  and do not chase them; fixing the expected-hash list is its own maintenance
  task.
