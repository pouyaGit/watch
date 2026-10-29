---
name: hermes-recon-milestones
description: "Use when delivering a HERMES recon milestone brief."
---

# Delivering a HERMES recon milestone

The HERMES recon project (`/root/hermes-recon`) is advanced one numbered milestone
per brief. Each brief is terse, numbered, and self-contained, and ends with a
mandated report format and an instruction to STOP. This skill is the delivery
protocol that applies to EVERY milestone; the per-area skills carry the depth.
For the Telegram/notification presentation surface specifically, see
`hermes-recon-telegram-ux` (renderer map, frozen alert gates, suppression ladder).

## Non-negotiable completion gate

Reconcile the brief's required checks with machine evidence before writing the final
report. A focused smoke test is not a substitute for a required suite: record each
command's real exit code, bounded completion marker, and saved output. A timeout,
nonzero exit, missing runner row, or unreported delegated review is a disclosed
limitation, never a silent PASS. Classify every failure (NEW_REGRESSION,
PRE_EXISTING, STALE_TEST, or ENVIRONMENTAL) from evidence; labels do not turn an
unfinished gate green. If any required gate is incomplete, the final result must be
INCOMPLETE or FAILED and the reason must name the exact missing/failed check.

For storage-sensitive milestones, snapshot free space and relevant database/hash or
row-count state before and after validation — and quiesce the writer (stop the daemon)
before the FIRST snapshot, not only the second. A live worker mutating the file between
two reads makes hash/size/mtime drift that proves nothing about your change, because
the delta is the system's own routine traffic. When drift is found that way, redo the
proof under quiescence instead of explaining the delta: "the daemon was running" is a
hypothesis, and an unchanged-bytes result is the evidence. Tests and probes follow
CREATE → USE →
CLEANUP, clean temporary artifacts on every exit path, and verify cleanup after the
process exits. When live validation must not mutate production, inspect production
read-only and exercise mutations on a frozen copy; never label a fixture as a live
signal. A read-only observer must use an isolated connection, never a caller
`query_only` pragma, and the regression test must prove both isolation and the
caller's continued writability.

Keep the canonical report template, Persian timestamps, and STOP boundary. Do not
start a later stage, add a scheduler/executor, use Git for verification, or claim
production readiness when any required check failed. For sprint briefs, read every
required document in the stated order before inspecting code; distinguish the canonical
architecture source from secondary architecture notes and record each required read
explicitly in the report. Do not treat an audit as delivery when the brief requires
implementation. If an audit-only stop is genuinely required, measure that no implementation,
test, or production mutation occurred; otherwise continue through the requested build,
test, offline E2E, and regression gates before reporting.

**A long regression is a gate, not a narrative.** Once the code is frozen, launch
the canonical full runner and record its PID, log path, exit-marker path, and the
last observed row. Do not write a final report from partial rows. If the session
ends while the runner is still active, report `PENDING_<RUN>` or `INCOMPLETE`,
name the missing summary/exit marker, and wait for an explicit continuation; do
not classify the unobserved remainder as passing, failing, or pre-existing.

- **A closure / status-check brief is answered from ARTIFACTS, never from memory.**
  Before reporting a run's state: list processes matching the run's own name (a results
  file with no process means it finished), read that run's results artifact — per-suite
  exit codes plus its terminal markers such as `FAILED_SUITES:` / `INTEGRITY_RC:` — and
  classify only from what those say. Never relaunch a battery that may still be running,
  and satisfy exactly the blockers the brief names: an unfinished item is reported as
  MISSING in the status block, not quietly completed under a different heading.

- `hermes-recon-crawler` (M2 crawl/frontier) · `hermes-recon-js-analysis` (M3)
- `hermes-recon-js-params` (M4 parameter discovery)
- `hermes-recon-scheduler` (M5/Stage 7 concurrency, fairness + persistent execution plane)
- `hermes-recon-nuclei` (M6 external scanner execution)
- `hermes-recon-hardening` (budgets, routing, XSS gates, selftest isolation)
- `references/research-skill-factory.md`: reusable research-to-skill contract, identity, provenance, consumer, and closure gates.
- `references/regression-failure-disposition.md`: multi-baseline set diff, edit-window derivation, import-closure shortlist, and live-state movers.

`references/regression-certification.md`: interrupted-run recovery. `references/natural-window-validation.md`: passive natural-window Scheduler validation. `references/routing-cleanup-restoration.md`: corrective routing/restoration and report closure. `references/optional-provider-shadow.md`: optional external-provider shadow integrations. `references/live-daemon-verification.md`: live-change proof. `references/sqlite-lock-forensics.md`: startup crash-loop triage, finding the real WAL-write holder in `/proc/locks`, and clearing an agent-process self-hold. `references/telegram-activity-pulse.md`: 10m pulse layer. `references/concurrent-domains.md`: recon+research domain scheduling.-observability.md`: live worker observability. `references/concurrent-domain-scheduling.md`: worker domains over the shared queue (state-only wiring, starvation observation, TEST_STALE hash suites). `references/canonical-architecture-briefs.md`: canonical /home/ubuntu doc + ALIGNMENT block.


`references/planning-layer-model.md` carries the reusable shape for a layer that
produces bounded, auditable REQUESTS for another component to execute (plan fields,
bounded status vocabulary, ceilings, expiry, dependencies, competition, the
analyst-decision rule, the human-facing surface, and the RESEARCH-LOOP delta for a
layer whose unit is an uncertainty to reduce rather than an action to take). Reach
for it before reinventing a planner model.

`references/outcome-calibration-layer.md` carries the shape for the layer that
CLOSES a loop: canonical outcome record, expected-vs-observed, yield, resolution
kept separate from success, effectiveness with sample bands, contextual
dimensions, drift, replanning feedback, and the no-data-leakage rule — plus the
experience-record contract (identity vs direction, distinct-observation counters,
contradiction precedence, redact-vs-reject, and the reuse map of the stores that
already exist here). Reach for it before inventing an outcome, feedback or
experience model.

`references/coverage-scheduling-layer.md` carries the shape for a layer that decides
WHAT TO REFRESH NEXT: the entity/stage model with evidence-only completion, freshness
from the stage's own timestamp, a priority built from counted dimensions, fairness
apportionment, backpressure, target health, ceiling ordering, and the STAGED fixture
recipe a boundedness test needs. Reach for it before inventing a scheduling model.

`references/differential-change-layer.md` carries the shape for a layer that answers
WHAT CHANGED since the previous trusted observation: content-addressed fingerprints with
their normalizers, the baseline state set, the comparison window, the conservative removal
policy, the assembly of a change event, significance-vs-severity, alert gating, and the
fixture recipe a change suite needs. Reach for it before inventing a diff model.

`scripts/audit_layer_consumption.py` measures, for any module under `lib/`, whether it
is wired to MATTER: importers (flagging a gate-only one), how many modules reference its
output tables, whether it makes cross-milestone writes, its user-facing surface, and its
live row counts. Run it before designing a milestone whose objective the brief left to
you — zero consumers on every owned table plus an empty cross-write list IS the seam.

`scripts/changed_file_inventory.py` proves — with mtime plus SHA-256 and no
repository-management command — that the files a milestone CLAIMS to have changed did
change, and that the authority/pipeline modules it claims to have left alone are still
older than the work window. Pass the window start and the touched/untouched lists as
JSON; a missing `untouched` path is `n/a` (never created, never modified), while a stale
or missing `touched` path fails the verdict.

## Analyst command surface (Telegram → CLI → reporter)

Commands the analyst types in Telegram are served deterministically by running the
CLI and relaying the output verbatim (with the `Model: none (deterministic — no LLM)`
line): `/status` `/unread` `/targets` `/findings` … → `hermes-recon <cmd>` →
`scripts/reporter.py <cmd>`. Since the PD migration: `/recon …` maps to
`hermes-recon recon …` → `reporter.py recon <sub> [args]` — subcommands
`subdomains <target> [limit]`, `http <target> [status|limit]`,
`tech <name> [target] [limit]`, `new-http [hours|limit]`,
`changes <target> [hours] [limit]`, `techchanges [hours] [limit]`. `/recon` is
READ-ONLY over persisted data (pd_* / asset_technologies / assets / recon_changes);
it never launches subfinder/dnsx/httpx or any job, is bounded (default 20, cap 50,
counts always shown), and unknown targets return a refusal line, never a crash.

## Standing constraints — non-negotiable, every milestone

- **No repository-management commands, ever.** No `git status/diff/log/branch/commit/
  checkout/reset/restore/clean`, no `pull/push`, no clone, no "repo workflow". Work
  directly on the live filesystem. Verify changed files with timestamps, direct reads,
  tests and runtime behaviour. A brief that must forbid this will not ask twice.
- **Never start the next milestone.** Finish the current one, stop after the report.
  A re-issued brief for a milestone already shipped means RE-VERIFY, not re-implement,
  and its leading `DO NOT` list is the operating contract: treat every named prohibition
  as binding for the whole turn, and satisfy the named blockers only — a closure brief
  that lists the remaining items does not authorise touching anything else.
- **Additive and reversible.** Prefer `CREATE TABLE IF NOT EXISTS`, `ALTER TABLE ADD
  COLUMN` guarded by a `PRAGMA table_info` check, new modules and new functions.
  Never rewrite a working subsystem to make a new feature cleaner. The schema is
  split on `;` before execution, so no SQL COMMENT may contain a semicolon — it
  truncates the statement and silently breaks table creation. Do not "document" that
  trap in a comment that itself contains a quoted semicolon. The schema is a STRING, not
  code: putting Python in it (a `for` loop, a call) fails at CONNECTION time with
  `sqlite3.OperationalError: near "for": syntax error`, so every `conn()` call in the
  process dies. Additive `ALTER TABLE` work belongs in the Python migration block beside
  the other `PRAGMA table_info` guards, never inside the DDL.
- **`CREATE TABLE IF NOT EXISTS` does NOT add a column to a table that already
  exists.** A table created by an earlier attempt (or a previous run of your own
  script) is already present, so a column you add to the CREATE block is silently
  absent on that database — the table looks right, the INSERT omits a value, the
  column reads NULL, and nothing errors. Any column a NEW table needs must ALSO be
  listed in the additive `ALTER TABLE` migration loop, so it exists on both a fresh
  DB and one where the table already exists.
- **Check the table NAME does not already belong to another milestone before creating
  it.** `CREATE TABLE IF NOT EXISTS` on a name that already exists is a silent no-op, so
  the new layer's inserts land in the OTHER component's table — its run log quietly gains
  your rows and its own counters go wrong, while your table 'exists' with the wrong
  columns and every read merely looks empty. Grep the schema and the whole `lib/` tree
  for the name first; when it is taken, prefix the new table with the milestone
  (`research_loop_runs`, not `research_runs`) and say why in a comment beside it.
- **Never reuse one column list for both the INSERT and an idempotency filter.**
  Freezing fields to keep an upsert idempotent (excluding `created_at`, `expires_at`,
  counters) must exclude them from the UPDATE half only. Filtering them out of the
  single shared list also drops them from the INSERT, so the field is never written
  at all — NULL on every row, and every reader of that field breaks downstream.
  Keep the frozen set as a separate exclusion applied at UPDATE time, and assert a
  freshly created row has a non-NULL value for each frozen field. The same trap fires in
  the opposite direction: a column list built as "the keys present in the row dict"
  silently drops the PRIMARY KEY, because the id is not one of the measurement fields —
  SQLite accepts a NULL id, the one-row-per-key invariant dies, and every later pass
  inserts a fresh duplicate while the upsert still reports success. Name the key column
  explicitly and assert one row per key.
- **Never delete or reset production data**, and never delete production data just to
  make a count match. Removing genuinely-fabricated rows is a separate, explicitly
  justified action with a script and a stated count.
- **Never raise an existing safety ceiling** to make a feature look more capable.
  New bounds are added ABOVE the old one, or the ceiling is left alone and the
  limitation is reported.
- **Failures are disclosed, not hidden.** If a required test or live verification did
  not pass, the ready-status is NO with the exact blocker named — regardless of how
  much else works.

## Adding a bounded capability layer

Milestones from M8 onward follow the same shape: a NEW analysis/intelligence layer
that must not widen any existing authority. Get these right or the layer is unsafe
by construction.

- **Route, never execute.** A capability that needs another component's authority
  expresses a REQUEST and lets that component decide. A Nuclei need becomes a
  `route="m6"` request serviced by the existing executor; a research need is
  ROUTABLE to the research source policy. Never import the other component and call
  its internals, and never start its process from the new layer.
- **Derive the routing vocabulary from the existing authority; never publish a second
  taxonomy.** When a brief names actions the system has no exact equivalent for, own a
  SMALL bounded enum in the new module and build its downstream fields as a MAPPING
  INTO the existing module's constants (`new_action -> existing_next_action`,
  `new_action -> existing_destination`). The new enum is then a caller, the existing
  module stays the sole authority, and adding one does not change the identifier or
  digest that other components already derive from those constants. Assert every value
  of the new enum maps somewhere, and assert the mapping is a total function so a new
  action cannot silently fall through to a default destination.
- **Reuse the existing I/O path; never write a second client.** Extend the existing
  helper (add the argument it lacks, e.g. a `method` parameter) rather than creating
  a parallel HTTP client, so scope guard, rate limiter, redirect guard, timeout and
  body cap are inherited rather than re-implemented. Then assert the new module
  imports no network library at all.
- **Planning and execution are separate functions, and the gate re-runs immediately
  before execution.** Never trust a stored action because it was once classified
  safe: re-derive its safety class from the authoritative mapping and re-check every
  precondition against live state. A disagreement between a stored class and the
  derived class is itself a denial.
- **Minimum action first.** Prefer re-reading existing evidence over any request,
  and the cheapest network action over a costlier one. This must be STRUCTURAL, not
  a convention: suppress a network action when stored evidence already answers the
  question, and — the subtle half — suppress a cheap LOCAL re-read when it provably
  cannot surface anything new, or the no-op wins on cost rank and hides the action
  that would have worked.
- **Gate EVERY traffic class, not just the obvious one.** An M6-routed scanner
  request is still target-facing activity; a traffic check placed after a per-class
  branch silently lets one through a "no traffic" run.
- **Default to no network, opt in explicitly.** Ship the executor so it performs
  zero requests unless an explicit env flag is set, and make the live verification
  prove the refusal. When the data does not justify action, report
  `NO LIVE ... JUSTIFIED` and show the refusal — a fabricated request to make the
  feature look exercised is a failure, not a demo.
- **Negative evidence is first-class.** Record "we looked and found nothing" as an
  explicit typed item with provenance; never discard it in favour of an empty result.
- **New evidence never overwrites old.** Persist both, raise an explicit conflict
  record, and let automation resolve only on strictly stronger confidence AND a
  strictly newer timestamp — otherwise mark it for human review. Never silently pick
  a winner, and never resolve a conflict by deleting the loser.
- **Redact before persisting, and keep the FACT of redaction.** Never store
  credential-shaped values; carry a per-item marker plus minimal provenance so an
  analyst can see something was present and withheld. **Order matters: SCREEN, then
  redact, then bound.** A forbidden-content check run on already-redacted text sees the
  redactor's own placeholder and lets through anything it only PARTIALLY masked —
  validate the raw input first. Keep the two token classes apart: an
  execution/authority shape (a URL, `curl`, a shell, a scanner, `M6`, a confirmation
  status) is REJECTED outright, while a credential shape (a bearer token, a key, a
  password) is REDACTED and counted. Putting credential NOUNS in the reject list is a
  common over-reach that destroys the audit fact that something was present and
  withheld — and it makes the layer refuse records it should be able to keep safely.
- **Never consult a gate that STAMPS before checking there is work to do.** A
  cadence getter that records "last planned at" as a side effect of being asked will
  burn the entire interval on a cycle that had nothing to do, deferring real work by
  hours. Order the condition so the cheap READ-ONLY work check runs first and the
  stamp is consumed only when work genuinely exists; then assert it, because the bug
  is invisible in normal operation — an empty cycle must leave the window OPEN.
- **Persist the WHY in a column, and re-record it when the row already exists.**
  Computing the selection reason and returning it in the run payload leaves an audit field
  that vanishes on the next pass, so 'preserve the selection reason / no hidden decisions'
  holds only in memory. Give the row a real column — and because the write is
  `INSERT OR IGNORE`, an EXISTING row never gains the value: issue an explicit UPDATE of
  the audit fields each pass. The decision is deterministic, so this re-records the same
  value rather than reconstructing one. A re-record only lands where the pass actually
  VISITS the row: a row whose parent is at its ceiling, or whose subject is otherwise
  skipped, is never reprocessed and keeps its NULL forever. Pair the update with a
  BOUNDED backfill sweep over rows still missing the value, report how many it filled,
  and — when a re-derivation disagrees with the stored choice — record the disagreement
  instead of overwriting, because a stored decision that no longer follows from current
  state is information, not dirt.
- **Preserve the upstream component's DECLARED order; never re-sort by a local
  heuristic.** When you reuse an upstream mapping, its ORDER is part of its
  judgement: an ordered candidate tuple encodes "take the first that is actually
  justified", and it deliberately does not coincide with cost rank. Sorting those
  candidates by cost (or any local preference) silently overrides the upstream
  decision while looking like a tidy implementation detail. Enumerate the source
  sequence and rank by index in it.
- **Bind a reused helper's return SHAPE, not its truthiness.** A predicate that
  *looks* boolean but returns a `(bool, reason)` tuple is ALWAYS truthy, so `not
  helper(x)` is False for every input and the guard refuses everything — which reads
  as a policy failure, not a bug in your call. Read the helper's real signature
  before wiring it, unwrap the tuple, and assert both branches (an allowed input and
  a refused one) so a guard that can never permit is not mistaken for a strict one.
- **Pass a validator the REAL row, never `None` for 'not applicable'.** A precondition
  checker that names a concrete fact in its reason ('the underlying claim row is gone')
  asserts that fact whenever it is handed nothing — so every item is marked STALE with a
  confident, untrue reason, nothing stays routable, and the failure reads as a data
  problem rather than a call-site bug. Build the lookup for the rows the validator needs
  and pass them; a strict validator fed `None` is not being conservative, it is lying.
- **The new layer's state ceiling is the previous milestone's ceiling.** Enumerate
  the states it may surface and omit the stronger one entirely, so a reader cannot
  infer a capability that does not exist.
- **A per-run ceiling must gate EVERY write branch, and be proven reachable.** A
  budget enforced in the main loop but not in a trailing per-row loop (records
  written one per input) lets hundreds of rows through a declared cap — the ceiling
  becomes fiction, and only a test run with MORE inputs than the cap catches it.
  Apply the shared budget counter to every branch that writes, and assert the cap is
  REPORTED as hit (`ceilings_hit`), not merely declared. Separately: a bound that
  counts EVENTS needs its identity to include the per-round dimension — a dedup id
  that collapses every repeat onto one row makes "max N retries" unreachable dead
  policy. Prove a ceiling by reaching it, then prove the next attempt is refused
  with a human-review verdict rather than silently allowed. **Order the ceilings so each
  is the BINDING one somewhere.** A per-stage bound set above the global per-pass cap, or
  above the ceiling the component it feeds already publishes, can never fire — the outer
  bound always trips first, so the inner bound is fiction and its `ceilings_hit` entry is
  dead code. Set production values so every bound is reachable, and in the test raise the
  OUTER bounds out of the way so the bound under test is the one that binds.
- **With a scarce budget, process never-attempted items before retrying
  failures.** A resume that interleaves them spends the remaining calls on
  repeat failures — each burning attempt plus retry — and starves the healthy
  items that would have succeeded first, so the ceiling is consumed by the
  worst candidates. Sort resumable work untouched-first, failures last.
- **Put a per-subject ceiling at the PERSISTENCE boundary, not in the orchestrator.**
  A cap applied while SELECTING work is bypassed by every other writer — a seeding path,
  the CLI, an analyst command — and only a test that writes through those paths catches
  it (a cap of 5 with 8 open rows stored still reads as a healthy run). Enforce it inside
  the store helper that inserts the row, on BOTH the single and batched paths, counting
  only OPEN members for that subject so an already-stored member consumes no new budget.
- **A guard must not read its state from a parent row that may be absent.** Ceilings
  read off a plan row silently reset to zero when that row is missing (pruned, never
  persisted), so the guard permits unbounded retries — a guard that disables itself
  is worse than none. Fall back to the record that always carries the fields (the
  child/outcome), and test the guard with the parent deliberately absent.
- **Enforce a classification's consequences in the constructor, not at each call
  site.** Whatever a classifier decides (CONTRADICTORY, NOT_EXECUTED, EXPIRED,
  BLOCKED) must be honoured by the record built from it: a contradiction yields a
  contradicted resolution without the caller re-passing a flag, and an action that
  never ran records NO observed evidence whatever the caller passed. Per-call-site
  enforcement guarantees one caller eventually forgets, and "a plan that never
  executed claims it observed X" is the fabricated fact you were trying to avoid.
- **Bind every counter before the branch that fills it.** Counters assigned inside a
  conditional block but read in the returned payload raise `UnboundLocalError` on
  the path that skips the block — the empty-corpus path crashes instead of reporting
  zero, which is the case you most need to be honest about.
- **Every branch that appends to a result list must emit the SAME key set.** A refusal
  path that carries the identifier but omits the detail fields (owner, gain, cost) crashes
  any consumer that selects rows by 'has an identifier' — `KeyError` in the CLI, from a
  case the engine treats as a normal refusal. Add an explicit discriminator
  (`routed: True/False`) and select on that, and let the renderer read optional fields
  defensively.
- **A "created" counter is not a "rows written" counter.** An upsert that also
  rewrites a row whose measurements changed makes rows-written overstate creation,
  so a scheduled re-run looks like it is minting records. Snapshot the identity set
  before and after each run and report the honest created/updated split.

- **Registering a NEW EXECUTION DOMAIN is one atomic checklist, not a series of
  edits.** A domain that is only half-registered looks live and is not: claim it
  lists (`PLANE_*_TYPES`), the single ownership map (`concurrent_domains.domain_of`),
  `JOB_CLASS` + `CLASS_LIMITS` (own single-slot class, never a shared one that
  mutually blocks with HEAVY/LOCAL), `planner.CEIL` + a pending-singleton guard,
  `cycle.budgets`, the `execute_job` dispatch, the capacity controller's
  `<domain>_allowed` tier arithmetic, `queue_health`'s domain loop AND its OTHER
  exclusion list, and the status render's domain loops. Miss `queue_health`'s OTHER
  list and the new jobs are counted as reserved/cycle-path; miss capacity and the
  workers spin without ever being admitted. Then assert one job of the new type
  travels enqueue → claim → execute → COMPLETE through the REAL dispatcher.

- **A status/reporter render must not run DDL.** Calling `ensure_schema()` (or any
  `CREATE TABLE`) on the render path makes an "observability" read into a writer, and
  it trips any write-free-render authorizer an earlier milestone installed. Query
  `sqlite_master` first and degrade to an explicit "not initialised yet" line; the
  executor path owns schema creation.
- **A render wrapped in ONE broad try/except turns one bad row into a total blackout.**
  A JSON field extractor throws on a single unparseable payload, the section's except
  swallows it, and the operator loses EVERY counter — including the ones that were
  fine. Guard the parse at the SQL level (`CASE WHEN json_valid(col) THEN json_extract(col, ...) END`),
  map the unreadable case to an explicit label such as `UNKNOWN` rather than dropping
  the row or the whole section, and add a check that seeds a deliberately malformed row
  and asserts the surviving counters are still correct. Also assert the section
  renders both states: populated, and unavailable-without-creating-the-table.
- **A read-only renderer must not MUTATE the connection it was handed.** Setting
  `PRAGMA query_only=1` on the caller's handle to guarantee your own read-only-ness
  poisons that connection for the rest of its life: every later write on the same
  handle fails with "attempt to write a readonly database", so an UNRELATED suite that
  reuses the connection goes red while your own suite stays green. Open a SEPARATE
  read-only handle for the render, assert `PRAGMA query_only` on YOUR handle, and never
  on theirs. When the render takes `conn` as a parameter, that parameter is a lease the
  caller still owns.
- **A static "no writes" detector must scan the SQL ARGUMENTS, not the file text.**
  Walking every `ast.Constant` matches a docstring that says "no INSERT" and a Persian
  sentence containing the word "CREATE"; scanning the raw source matches both too. Collect
  only string constants passed to `.execute(...)`, then assert no write verb appears in
  THAT blob. Pair it with a non-vacuity probe: the detector must fire on a literal
  `SELECT 1; DROP TABLE findings;`. Anchor the extraction on `INSERT ... INTO`
  specifically: a generic `(?:INSERT|UPDATE|DELETE)\s+(\w+)` captures `SET` from
  `UPDATE t SET x=?` and then fails the subset assertion with a bogus table name, which
  reads as "the module writes outside its tables".

- **Setting `HERMES_DB` does not isolate a suite that runs in a PERSISTENT agent
  process.** `store` caches a module-level connection that an EARLIER import in the
  same interpreter already bound to the live file, so the fixture env var is
  ignored and the suite writes to production. Put a guard before the first write:
  resolve `PRAGMA database_list` through `store.conn()` and `sys.exit(3)` unless it
  equals the fixture path. Discover this by checking the LIVE db for rows whose ids
  match the fixture namespace (`references/live-daemon-verification.md`), not by
  trusting the env var.
- **A forked "does it survive a restart" check proves nothing about persistence.**
  `os.fork()` inherits the parent's module state, so an in-process counter reads
  IDENTICAL in the child for reasons unrelated to storage — the check passes on any
  implementation. Restart tests must assert the PERSISTED rows through a fresh handle
  (and a separately persisted snapshot reloaded by run id), and must EXCLUDE the
  by-design in-process counters from the comparison. Two traps in the harness itself:
  a guard that exits via `SystemExit` is a `BaseException` and escapes `except
  Exception`, so the child dies nonzero for the wrong reason — catch `BaseException`
  and write the child's measurement to a file the parent reads; and have the child
  re-verify it opened the fixture, never assume the inherited connection is right.

- **A matcher that feeds a downstream consumer needs a false-positive GATE, and
  fixtures alone cannot find one.** Token overlap between a learned pattern and an
  observed asset looks like relevance and is routinely meaningless: a shared
  generic word (`server`, `services`, `management`) is boilerplate present in
  dozens of unrelated technologies. Run the matcher over the REAL corpus read-only
  and read every distinct emitted match by eye — a green fixture proves the
  positive path, never the absence of noise. Gate it: a generic-word blocklist, plus
  a requirement that a single shared token be a product fingerprint
  (`openssl`, `nginx`) or be corroborated by a second token, with a `weak_match`
  counter for the refused ones. Every tightening must ship with a positive probe
  proving the intended matches still fire, or the fix kills true matches silently.

- **A zero result is only honest if the matcher is proven to reject noise.** After
  hardening a matcher, state whether the empty live table means "no relevant
  signal" or "the gate is refusing everything" — distinguish them by re-running
  the matcher in-process over the real corpus and reporting `strong` vs `weak`
  counts. Zero rows with a proven-reachable positive branch is a result; zero rows
  from an unproven gate is a silent outage.

- **Verify the report's own structure before sending it.** Extract the section
  numbers and assert they are exactly `1..N` with no duplicate or gap, assert every
  mandated field string is present verbatim, and assert the file ends with the
  mandated terminator. Patching a report by hand drifts the numbering (a renumber
  lands after the section it renames, then a second renumber lands out of order);
  a programmatic check finds it in one call instead of five patch round-trips.

## A regenerated row must never overwrite a human decision

Any layer whose rows carry a DETERMINISTIC identity regenerates the same row on
 every run. That is what makes dedup work — and it is also how an analyst decision
gets silently undone: the planner re-derives the identical id, writes its own
status back, and the plan is live again.

- **Guard the write, not the read.** Before upserting, check the EXISTING row's
  status; if it is a decision-held state (rejected/cancelled/deferred) and a stored
  decision of yours records that choice, skip the row entirely and count it as
  `preserved`. Reporting the preservation count is how you prove the guard fired.
- **The decision records outrank the derived status.** A terminal or held state is
  part of the human record and is never rewritten by automation; only a new decision
  may move it.
- **A terminal decision is final for its entity.** `REJECT` / `CANCEL` / `RESOLVE` end
  that line of work: refuse any LATER decision on the same entity with an explicit
  'already carries the terminal decision' error. Without it a later `APPROVE` gets a
  different decision identity, inserts a second row, and silently reverses the analyst's
  stop — the very overwrite the guard exists to prevent, arriving by the front door
  instead of through the automated re-run.
- **Tie-break "the latest decision" deterministically.** `ORDER BY created_at DESC`
  alone is not deterministic when two decisions land in the same second, so which
  one wins depends on row order and an overridden decision can come back. Add
  `rowid DESC` (true insertion order) to the ORDER BY.
- **Make the pairing mutual:** assert that after an automated re-run the decision is
  still the analyst's, AND that a rejected plan is not routable. Test the re-run,
  not just the decision call — the overwrite only happens on the second pass.
- **A new decision mints a NEW plan; it never edits the old one.** Replanning
  produces a fresh deterministic identity (and provenance naming what it came from)
  while the original row and its decision stay intact and auditable.

## Finding the next layer's objective — audit the PREVIOUS layer's CONSUMERS

A brief that says "identify the exact M<n> objective" is not asking for a design
opinion. It is asking you to find the seam the previous milestone left open, and the
seam is measured, never inferred.

- **Count the CONSUMERS of the previous layer's output tables.** For each table the
  previous milestone wrote, grep the modules that own the NEXT authority — case
  manager, prioritizer, orchestrator, learning, confidence, calibration, reporter —
  for that table's name. **Zero consumers IS the finding**: the layer detects and
  persists correctly and nothing in the system acts on it.
- **Corroborate with three independent signals before believing it.** (1) the previous
  module's own docstring naming downstream consumers it never calls; (2) an AST pass
  over that module for calls that write outside its own tables (`add_finding`,
  `enqueue_job`, `enqueue_alert`) returning an EMPTY list; (3) live row counts of its
  output tables. When the prose names consumers that the code and the data do not
  have, the objective is "build the consumption hop that was declared but never
  built". Run `scripts/audit_layer_consumption.py <module>` for all five measurements
  in one pass.
- **Check the user-facing surface too.** A layer with zero reporter/dispatcher
  references has no operator-visible output at all — the same gap in its strongest
  form. Two import sites, both a work-gate and a dispatcher, means it is wired to
  RUN, not to MATTER.
- **Re-read the previous module's docstring before designing anything.** Prior
  milestones state their own downstream consumers in prose, and that prose is the
  specification you are being handed.
- **A brief that leaves the objective to you has an ownership fork in it — present it
  and STOP.** The landing point of any consumption layer is choose-your-authority:
  attach to the case layer, feed the prioritizer, expose an orchestrator candidate, or
  record a learning observation — each already owned by a different milestone. Give the
  options with your recommendation FIRST, name what you will not do without
  instruction, and do not build a large module on your own inference. The brief's own
  "stop if the scope is ambiguous" clause exists for exactly this fork.
- **Do not quietly repurpose the previous milestone's surface.** Writing its dead
  table, or mutating any of its rows, is that milestone's territory — report it as an
  open decision and leave it untouched.
- **An audit-only phase must PROVE nothing was built.** Before reporting: the new
  module does not exist, no new suite exists, the live table count is unchanged, every
  proposed table name is still absent from the live schema, and the previous milestone
  is byte-identical. "I did not implement anything" is a claim; those are measurements.

## Validating a CLOSED pipeline, not extending it

A brief that says "prove X can influence Y" and names the chain is asking for a
measurement, not a feature. The deliverable is the measured state of every hop, the
exact hop where the chain stops, and isolated fixtures for the rest. Four rules keep
this from quietly becoming an expansion.

- **Verify EVERY hop has a code reference before validating any of them.** A chain can
  look complete in the brief and be missing a hop entirely: the consumer reads the
  proposals, the prioritiser fills the dimension, and the plan builder never opens the
  prioritiser's table at all — carrying a hardcoded null in the lineage column instead.
  Grep each hop's consumer for the upstream table NAME. A hop with zero references is a
  FINDING to report, not a defect to fix, because closing it is expansion the brief
  forbids. Assert the absence structurally (zero references, hardcoded null present) so
  the finding is reproducible by the next session, and check whether the lineage column
  already belongs to a DIFFERENT component before proposing any new meaning for it.
- **When a dimension already has a base value, measure the DELTA, not the absolute.** A
  live score column is rarely uniform: it commonly carries a base value where the corpus
  qualifies and 0 where it does not. Assert the distribution you actually read
  (`SELECT DISTINCT`, grouped) rather than a guessed "all zero", and prove influence
  with a TWO-ARM differential — identical corpus in both arms, the upstream record
  present in one — then compare the STORED rows.
- **Drive the real engine entry point, not the leaf it calls.** Scoring a dimension
  directly proves arithmetic and nothing about persistence, the lineage stamp or the
  ownership boundary. Call the public entry point on a throwaway DB so the write path,
  the stamp and the authority checks all execute.
- **Launch the long poles before writing the report.** The full regression battery and
  any multi-minute natural-validation window are the longest items; start both as soon as
  the code is frozen, then write the report ONCE with their real numbers. A report drafted
  while they run must be re-patched when they land, and a tool budget exhausted mid-battery
  leaves the final block permanently INCOMPLETE.

## Procedure

1. **Audit before changing anything.** Read the live code and measure the real
   behaviour (query a COPY of `state/hermes.db`, never the live file, and set
   `PRAGMA query_only=1`). Produce the audit as a file under `reports/` — the brief
   usually demands it before implementation. Do not assume the brief's own
   characterisation of the bug is right; measure it.
   **Before implementing a REPAIR, inventory whether it already exists**: sha+mtime of
   every file the brief names, a grep for the defect's own markers (the gate expression,
   the mapping call site, the comparator branch) and a search for a pre-existing focused
   suite and report. A prior session often shipped the code fix and left only the report
   unwritten — then the deliverable is VERIFY (run its suite) + EXTEND (add the brief's
   missing fixtures) + VALIDATE on production data, and `§Code Changes` must state that
   the repair pre-dates this milestone with before/after hashes. Re-implementing a fix
   already on disk is how a milestone ends up modifying working code for nothing.
   **When the source fix pre-dates the milestone, preserve its hashes and make the missing test boundary the only code change.** Do not describe a pre-existing production patch as work performed by this milestone; report it as pre-existing, tested source-tree behavior.
2. **Implement against the existing extension points** (`budgets`, `JOB_CLASS`,
   `planner.CEIL`, `add_finding` optional columns, the `execute_job` dispatch). Never
   add a second scheduler, pool, database, or network client.
   **Prove a new enqueue path in ISOLATION before claiming the daemon wiring works.**
   Static assertions that a symbol appears in the planner/scheduler/dispatcher files
   show only that the text exists, never that a job gets queued. Copy a
   production-derived database to a temp dir, set `HERMES_DB` (and the module's own
   `DB`/`BASE` attributes) BEFORE importing the module, then drive the REAL entry point:
   read its name from the CALLER in `scripts/cycle.py`, not from a guess —
   `AttributeError: module 'x' has no attribute 'y'` means you invented a name, not
   that the wiring is broken. Assert the row is created, that it is a SINGLETON (a
   second pass enqueues nothing), that the cadence stamp was written, and that the
   work gate REFUSES when no work exists — plus the fixture-path guard from the
   isolation rule, so the proof cannot have pointed at production.
3. **Write a focused test suite** for the milestone, numbered like the brief's list,
   against a throwaway DB (`HERMES_DB`/`HERMES_STATE`/`HERMES_LOCK_DIR`). **Put every
   helper definition ABOVE its first call site, and never above a module-level
   `sys.exit`.** A script that computes its verdict and exits before its `def` blocks
   have executed raises `NameError` from inside the check — which reads as a broken
   engine rather than a misplaced function, and costs a full debugging cycle in every
   suite you write that way. Reorder the file so all helpers sit above the first
   check, then re-run.
   **Credential-shaped fixture samples must be inert placeholders.** Never
   paste a real (or once-real) key into test content — a fixture line is a
   credential leak like any other. If one turns up in an existing fixture,
   replace it with an inert placeholder, delete any backup copies you made
   of that file, and grep the tree until the token is gone.
   **Write the golden fixture expectations BEFORE the implementation.**
   Emit the fixture rows (input + expected outcome) first, then build the
   parser/adapter/policy against them: every mismatch is fixed in the
   implementation or the test harness, never in the expectation, so the
   fixtures stay an independent oracle. Ground metric literals the same
   way — run `SELECT DISTINCT` on the stored column before writing a
   report query, because a guessed status enum silently reports 0.
4. **Verify with a real end-to-end run**, not just the focused suite. A suite that
   drives the selector/pool/parser directly will pass while `cycle.main()` fails
   every job — real wiring bugs (`NameError`, `UnboundLocalError`, missing import)
   only surface through the real executor. When the requested E2E is explicitly offline,
   use SQLite's backup API to make a frozen copy, run the real consumer path against that
   copy, then reload through a fresh connection and verify provenance and canonical-case
   linkage; report network/target requests and production mutation as measured counters,
   not inferred guarantees.
5. **Snapshot production before and after** (`scripts/m3_snapshot.py` →
   `state/<m>_evidence/`), then diff both counts AND ids on the protected tables
   (`findings`, `xss_candidates`, `finding_reviews`, `correlation_groups`). Explain
   every non-zero delta; an unexplained deletion is a failure.
   A test runner that writes an evidence artifact is still a writer: disclose the
   artifact separately from production-table mutation, and include it in the report's
   changed-file inventory.
6. **Restart the daemon** to load `lib/` changes — it holds the old code — then verify
   `systemctl --user show hermes-recon -p ActiveState,SubState,MainPID,NRestarts`,
   a fresh `state/heartbeat.json`, and real job lines in `logs/cycle_*.log`.
   For a source-only scheduler fix, do not infer production effectiveness from a
   passing isolated test: record the active process start/reload boundary and keep
   the live readiness verdict separate from the source-tree verdict.
7. **Run the directly-affected suites FIRST (minutes), then the whole battery.** The
   full runner is `python3 scripts/m11_regression.py`; it owns the `PREEXISTING` /
   `ENV_DEPENDENT` classifications quoted below and writes
   `state/m11_evidence/m11_regression.json`. Classify any focused-run failure against
   THOSE sets before launching it, so a long run is never burned on a known break.
   Then run the whole regression battery, not just the new suite. Do NOT "fix"
   unrelated historical failures to make the suite green; report them as pre-existing.
   A SHARED runner's summary strings must be milestone-NEUTRAL and must honour every
   classification it defines: a verdict line that names a past milestone for any
   unclassified failure, and that ignores an `ENV_DEPENDENT` class it already maintains,
   reports an environmental miss as a regression — the most expensive kind of false alarm
   because it sends the next session hunting a defect that was never introduced. Fix the
   label to report the actual classification before citing it as evidence.
   **Preserve the previous run's FAIL list before you launch the battery:**
   `state/m11_evidence/m11_regression.json` is overwritten at each run's end,
   and the exact failure-set diff against the PRIOR run's output is what
   proves pre-existence row by row — keep the prior stdout log (or copy the
   JSON) first, and record the copy's content hash, mtime, suite count, and
   pass/fail counts. A copied artifact with a preserved timestamp is still a
   BASELINE, not a current run: current evidence requires a complete runner
   summary and a matching artifact write after the final code/test freeze.
   Only that diff upgrades the runner's static labels from hypothesis to evidence.

   **A killed shared runner is a missing gate, not a partial PASS.** If the
   process has no terminal summary and the official artifact is unchanged, the
   current regression result is not complete. Use the gap-certification recipe
   in `references/regression-certification.md` to finish only unobserved rows;
   flush them to a separate artifact, preserve provenance, and never overwrite
   the production evidence file with partial rows. A tool/session kill is
   reported as `INCOMPLETE` unless every required row has a real verdict.

   **A shared runner's one-line summary is not a diagnostic.** The m11 runner
   records only the last non-empty output line per suite; separator lines such
   as `====` contain no cause. For a failed row, read its full stdout/stderr
   artifact or run a bounded diagnostic, and keep that diagnostic separate from
   the certified result. Never infer a failure class from a summary line that
   contains no assertion or error text.
   **A focused blocker requires raw counter reconstruction, not a passing rerun
   of a nearby suite.** When the artifact retains only a check name or separator,
   reproduce that exact check on a consistent frozen copy and persist the raw
   before/after values, expected migration, and per-run results. For a WAL
   database, use SQLite's backup API rather than `cp`; otherwise the copied
   state can be stale or incomplete. Trace the function/call path before calling
   a shared store or authority module relevant, and keep unrelated check
   failures separate from the focused check's disposition.
8. **Fill final-status numbers only from a COMPLETED run.** Verify
   completion from the machine — exit marker or summary line present, pids
   gone, log stopped growing — before writing final metrics. An assertion
   (from a user or a stale completion notice) is verified, not trusted; a
   run still mid-flight gets a `PENDING_<RUN>` gate and the report waits,
   because provisional numbers inside a final block are fabrication.
   **When the process is already gone, recover its record from the runtime, not from
   memory:** `~/.hermes/logs/process-results/proc_*.json` holds the command, `started_at`,
   `exit_code`, `completion_reason`, `termination_source` and captured stdout — the
   wrapper's `<LABEL>=$?` echo lands THERE, not in the file the command redirected to, so
   redirected output can end mid-suite with no exit marker while the termination signal
   stays fully recoverable. Classify ACTIVE / STALLED / TERMINATED from a BOUNDED
   observation (two size+mtime+row-count snapshots ~60-90 s apart) and scan
   `/proc/*/cmdline`, `/proc/*/environ` AND `/proc/*/fd` for the output path — a
   `grep`/`pgrep` for the run's own name matches its own command line, so drop your own pid
   before believing a hit. Silence is never the evidence: sample the CHILD's
   `utime+stime` over a bounded interval and read its state + `wchan` (a child in `R`
   at ~100% CPU is computing, one in `S` on a pipe/poll is waiting on the suite) —
   a runner inside a suite with a 300-900 s timeout can be quiet for 30 minutes and
   still be progressing. Corroborate with a growing executed-row count in the log,
   a log mtime inside the observation window, and fresh temp-fixture mtimes; report
   the executed-row count and the last suite name as PARTIAL, never as a verdict.
   A background run is SIGTERM'd when its launching session closes
   (`termination_source: agent_close`); plan around that as a normal, recoverable end, never
   treat it as a process still working.
9. **Report in exactly the mandated sections, in order, ending in STOP.**

## Certifying a complete regression run: classify failures with controlled evidence

A completed runner can still produce misleading classifications. A process wrapper
that exits 0 only means the wrapper completed; inspect the inner runner's terminal
summary and its own exit code. A one-line summary containing separators such as
`====` is not a diagnostic: recover the failed suite's full stdout/stderr or run a
bounded targeted reproduction. For every failed suite record: exact check/assertion,
last output, duration, network/temp/baseline dependencies, and whether the touched
Day 1 modules are in the call/data path.

Classify only from evidence:
- `PRE_EXISTING`: the same normalized failure appears in a preserved pre-change
  baseline, and the relevant files/data are unchanged.
- `STALE_TEST`: targeted reproduction proves the assertion encodes an obsolete
  contract or fixture expectation; do not call it a test-side failure from the
  filename alone.
- `ENVIRONMENTAL`: the suite's own output or a controlled differential proves the
  result depends on DNS, upstream freshness, cooldown, wall clock, or another
  stated environment condition. A closed network namespace is evidence only for
  suites that actually perform DNS/network work; otherwise use a fixture/mock.
- `BASELINE_ARTIFACT_MISSING`: the suite explicitly fails because a required
  historical artifact is absent. Never create a synthetic baseline merely to turn
  the check green.
- `NEW_REGRESSION`: the failure is absent from all preserved baselines and the
  Day 1 code/data path is demonstrably involved. A static runner tag alone is not
  proof.
- `UNKNOWN`: evidence is insufficient; keep it unresolved rather than inferring
  intent from a short summary.

If a targeted check exposes a failure's exact assertion, read the baseline and
current code/data identities before changing anything. Do not broaden a cleanup
classification from a stale assertion to a production regression, and do not
mark a mixed suite as pre-existing when only one of its checks is pre-existing.
When a suite has several failures, split the dispositions by check. A green core
suite plus unresolved failures on shared store/authority paths leaves the overall
status INCOMPLETE, even when no new regression is proven.

For snapshot suites, verify the baseline path and existence read-only first. Keep
missing historical artifacts as evidence; never generate a fake `/tmp` baseline.
For network-dependent suites, use a two-arm reproduction when possible: normal
environment versus a controlled no-network environment, or a documented stub with
the expected fetch/persistence counters. If the exact output is absent from the
run artifact, say so and use `UNKNOWN` where attribution matters.

Do not let a wrapper's exit code, a baseline count, or a stale report override the
current run's machine evidence. Keep the current-run artifact, the preserved
baseline, and any targeted diagnostic as separate evidence objects.

See `references/regression-failure-disposition.md` for the reusable disposition
matrix and evidence recipe.


See `references/regression-certification.md` for the full recipe (gap computation, AST
reuse of the runner's definitions, batching budget, merge format, classification table).
Standing rules:

- **Cover only rows that were never observed.** Compute the gap against the runner's
  suite list, assert observed ∩ gap = ∅, then merge. Re-running a row that already
  produced a verdict destroys the one thing you cannot recreate: the state it ran against.
- **Reuse the runner's definitions without touching it** — parse `SUITES` /
  `PREEXISTING` / `ENV_DEPENDENT` from its source with `ast`. A module-level runner
  EXECUTES its whole battery on import, and editing a runner or test definition to turn a
  row green destroys the evidence that row exists to produce.
- **A partial run never writes the production evidence file.** Emit rows to a separate
  artifact, merge with a provenance header naming which process produced which rows, and
  when no single process ran the full set report the per-process exit codes and state that
  a single-process exit code does not exist — never infer one to fill the field.
- **Size long work in sub-5-minute foreground batches.** A script past ~5 minutes needs a
  consent that can expire unanswered, and silence is not consent — nothing runs. Budget
  from the prior run's per-row durations with margin, put the longest row alone, flush
  every completed row as it lands so a mid-batch cut keeps progress, and carry each
  batch's exit code into the report. One background call instead loses the whole run: it
  dies with its session.
- **Classify from baselines, never runner labels.** Look failures up by suite name in the
  pre-change outputs and compare assertion text with durations stripped (timings differ
  every run and fake a mismatch). A row absent from every baseline is the only one that
  can be INTRODUCED: prove code identity (sha + mtime of module and test scripts across
  every baseline run and the edit window) plus input non-modification before calling it
  ENVIRONMENTAL, else it is UNKNOWN. `INTRODUCED > 0` or `UNKNOWN > 0` blocks PASS; a tag
  such as `[REGRESSION]` is a hypothesis, not evidence.
- **Disclose the residual uncertainty of an environmental call.** If the passing baseline
  condition cannot be reproduced retroactively, say so beside the classification. Zero
  introduced regressions can make the regression gate PASS while `READY FOR PRODUCTION`
  stays NO because a live verification is currently failing — report both verdicts, never
  let one stand in for the other.

## Read-only audit mechanics

Every milestone starts with an audit (Procedure step 1); these are the rules that
make its numbers trustworthy.

### Building a read-only layer over live state (query/UI/report surfaces)

Whenever a milestone adds a new read path — a query module, a report/UI page, a
`rows()` helper, an API — these rules apply. They come from a class of bug where a
*typo or a swallowed exception* makes a large, populated table render as "0 rows, no
data", which reads as a real finding and is not.

- **A shared query helper MUST NOT swallow `sqlite3.Error` into an empty list.**
  `except sqlite3.Error: return []` makes a column typo, a `LIMIT` syntax error, and
  a lock/timeout indistinguishable from "this genuinely has no data" — the exact
  claim the page exists to make. Count the error, record the message, and (for a
  user-facing path) surface or fail loudly; never let an exception masquerade as an
  empty result. In one run this turned a 22,515-row table into an empty explorer page
  with exit 0 and a green-looking response.
- **Confirm real column names with `PRAGMA table_info(<t>)` BEFORE writing the
  query.** The schema is large and the natural-language column guess is often wrong:
  `hunt_intelligence` is keyed by `subject` (a topic like `cisa_kev`), not `target`;
  `hunt_decisions` has no `case_id`; `evidence_actions` has no `host` (it lives on
  `evidence_items`). Each wrong guess is a `no such column` that — if the helper
  above swallows errors — becomes a silently empty section. A `WHERE <col>=?` against
  a table with many rows is not proof you picked a real, populated column; check the
  error and a sample row.
- **When a per-row/per-entity subquery is UNCORRELATED but repeated, it is O(N·M).**
  Per-row correlated `MAX()` over a ~30k-row table, and subqueries joining a 44k-asset
  table to a 13k-url table per row, turn a page into a 40 s+ query. Hoist to a single
  aggregate/`GROUP BY`, a `ROW_NUMBER()` window, or a `LEFT JOIN` over a pre-aggregated
  subquery. Check the page's wall time against the row count; >1 s on a "list" page
  means the query shape is wrong, not the data.
- **Agree on the return arity of every route/helper and keep one shape.** A `_notfound`
  returning a 5-tuple where every real page returns a 6-tuple silently unpacks into
  `(content=<the whole tuple>, …)` and renders a blank page for every miss. When a
  page is unexpectedly empty, print `len(result)` and the types before editing SQL.
- **A test probe that reports "0 rows" must distinguish a counting shape bug from a
  real empty result.** Probes that read `total`/`rows` keys mis-measure domain dicts
  (which return different keys) as 0 and manufacture false alarms; probes that pick
  `ORDER BY id LIMIT 1` can select a FIXTURE row (blank title, NULL url) instead of a
  real record and manufacture false passes. Measure content by walking the actual
  returned shape, and select the row that has real data (`WHERE title IS NOT NULL AND
  url IS NOT NULL`), not merely the first row. Reused/stale probe variables silently
  reference the wrong entity's fields — pass explicit per-probe locals.
- **Distinguish a REFUSED write from a NO-OP write when proving read-only.** A
  `DROP TABLE IF EXISTS <a table that does not exist>` is *accepted* by SQLite (it
  writes nothing) and is correct, not a hole; a genuine `DROP`/`DELETE`/`UPDATE`/
  `INSERT`/`CREATE` against a real table is refused with "attempt to write a readonly
  database". Assert the refusals on statements that WOULD write, and assert a no-op
  separately by showing the schema is unchanged after it. Use valid, real-schema
  statements for the refusal test — a bad column name fails during preparation and
  proves nothing about write authority.
- **Prefer a stdlib `http.server`/no-new-dependency read layer over adding a web
  framework** when the surrounding system is stdlib-only; the read-only requirement
  plus `mode=ro` makes a dependency a net cost. Bind loopback, allow GET only (map
  every other verb to 405), and let the *status code* match the content (a missing
  page must be 404, not 200 — otherwise any monitor or cache reads a miss as real
  data). See `references/read-only-layer-build.md` for the full recipe.

- **Never IMPORT `lib/` modules during a read-only audit.** The import chain
  reaches `store.conn()`, which executes the schema string and any pending
  migration DDL against whatever DB is configured — a write path firing inside a
  no-production-writes mandate. Either rebind `HERMES_DB` to a throwaway path
  before any import, or replicate the pure function under test STANDALONE
  (re-read its regex/KB/data-file inputs from disk) and run it against the frozen
  copy. Executing the logic is necessary evidence; importing it is not.
- **This schema has TWO target key spaces, and a query across them fails
  silently.** `findings`, `xss_candidates`, `correlation_groups` store the target
  LABEL (`*.wien.at`); `jobs`, `urls`, `parameters`, `http_samples`, `assets`
  store the directory KEY (`wien-at`). Translate through `TARGET_DIRS` at every
  join or filter. A `WHERE target=?` fed the wrong space returns **0 rows, no
  error** — which is indistinguishable from "this pipeline produced nothing".
  Before reporting a pipeline empty, re-run the identical query in the OTHER key
  space; only if both are empty is emptiness proven. (This is how a whole
  milestone-long pipeline turned out to be dead: its call site passed the key,
  its tables held the label.)
- **Never write a per-row correlated `MAX()` subquery over `jobs`.**
  `WHERE created_at = (SELECT MAX(created_at) FROM jobs WHERE job_type=j.job_type)`
  is O(N²) against a ~34k-row table: it burns the entire 300 s cell timeout, the
  kernel dies, and ALL state from the call is lost. Use `GROUP BY` for aggregates
  and `ROW_NUMBER() OVER (PARTITION BY job_type ORDER BY <ts> DESC)` for
  latest-per-type — both run in well under a second on the same data.
- **Count every funnel stage as its OWN table before naming a root cause.** In
  this system candidate (`xss_candidates`), finding (`findings`), canonical
  (a read view over both, addressable by id), and alert (`alert_queue`) are four
  distinct objects with independent counts; join them by id, never by assuming a
  `ref_kind`. "X is dominant" can be true at exactly one stage and false at the
  others, and the stage that is dominant IS the root cause — state per-stage,
  per-class counts first, then select causes.
- **Epoch-stamp every windowed count.** The daemon writes continuously, so
"last 24h" read at two moments differs; a number without its measurement epoch
cannot be reproduced or defended. Absolute totals are stable across passes —
quote windows with the epoch, totals without hedging.
- **Never quote a figure you have not read back from that run's own output
  artifact.** Tool success only means the call completed: an audit script can
  die on a SyntaxError (leaving a traceback where the data should be) and a
  nested heredoc can drop its stdout silently, so the artifact holds less than
  you assume. Read the output file and see the values before publishing any
  of them; if unverified numbers already went out in an audit report, issue a
  visible correction naming the voided figures — carrying them forward is the
  fabrication, not the initial slip.

## Report rules

### Orchestration layer lessons (M18)

- **A cycle with in-flight work reports NO terminal verdict: `stop_reason=None` with
  `routes_created=0` is correct when `waits_created>0`** — `stop_reason_for()` returns
  None as soon as any route or wait is persisted, and `routes_created` counts only
  first-time inserts. Assertions over a cycle must accept three branches (`STOP_*`
  reason, `waits_created>0`, `routes_created>0`) using the module's own `STOP_*`/`CYCLE_*`
  vocabulary and reject malformed, unknown and FAILED states. An unreachable constant
  (`STOP_ALL_WAITING`) is a limitation to record, not to repair — it changes M18
  semantics.
- **M18 writes only `orchestration_*` via `store.orch_*`, and live suites run on a temp
  copy of the production DB** — a production row-count delta over a ~9 s window cannot be
  attributed to the suite, so prove mechanism: copy path, `mode=ro` on every production
  connect in the suite's own source (scan executable lines only), strict equality on the
  reachable family, and other deltas passing only inside a disclosed counter set. The
  ~316 MB copies are not self-cleaned — delete them.
- **Assertion-vs-contract disputes are settled in
  `references/live-gate-assertion-repair.md`, never by editing `lib/orchestrator.py`**
  unless evidence shows the contract itself is wrong.

### Learning / feedback layer lessons (M19)

- **Snapshot baselines stored in /tmp die on host reboot, and a missing baseline makes a snapshot suite FAIL.** `m19_snapshot` lost `/tmp/m19_snapshot_prev.json` and `m18_snapshot` had no baseline at ...[truncated] M17 safety asserted `store.case_count() == 9`, the number observed on the day it was written; the daemon kept opening M16 cases and the suite reported a regression at 11 with no code change. When a check's own NAME states the property ("the run created no case/finding/evidence row"), assert THAT — measure before and after and require equality — and add a non-vacuity guard (the table is non-empty) so the equality cannot pass on an empty corpus.
- **A 0/1-row HEARTBEAT table is not evidence of a deletion.** `activity` holds ONE row naming the current job, and `clear_activity()` DELETES it as normal operation when nothing is running, so its count oscillates `1 <-> 0` several times a minute. A snapshot diff that counts a decrease on it reports a healthy idle daemon as "a protected table lost rows". Name the heartbeat/marker tables alongside the queue tables as live-owned, and keep every OTHER decrease failing.
- **"Not empty" is an environment-conditional claim.** A check asserting a live-owned table still has rows after a drain silently asserts "a job is running right now". Assert the property on the tables that actually REFILL (queue/frontier) and let the marker tables sit at zero.
- **Separate the milestone-CAUSED deletion verdict from the ALL-ACTORS live diff.** Only the frozen-copy isolation run can attribute a deletion to your code; the live diff necessarily includes the daemon. Printing one "ZERO DELETIONS" from the live diff makes your own feature look destructive when the daemon merely finished a job.

- **`learning_runs` already belonged to M11, so `CREATE TABLE IF NOT EXISTS` was a silent no-op.** A milestone whose THEME is claimed by an earlier milestone ("learning" = M11) collides on the obvious run-log name: its inserts land in the other table and its own run log reads empty. Prefix the new log with the milestone (`policy_learning_runs`) and assert the two column sets are genuinely different, not merely that the table exists.
- **A later definition of an existing function silently steals it — and a NOTIFY helper is where this bites.** M11 already owned `register_learning_alert` / `format_learning_alert` and its own suite calls them with ONE positional argument; redefining the same names binds the LAST def, so the older milestone breaks only when ITS suite runs. Grep `lib/` for the symbol first; prefer a milestone-qualified name.
- **An inner ceiling tighter than an outer one makes the outer bound fiction.** With one model per subject, `MAX_MODELS_PER_RUN=500` could never fire while `MAX_SUBJECTS_PER_RUN=400` tripped first. Order ceilings so each is REACHABLE and prove each with a corpus sized against THAT bound.
- **A NULL content hash silently deduplicates everything.** When a caller omits the hash the lookup matches the FIRST NULL row, so every later hash-less row is skipped while the run reports success. Derive a missing hash AND make the store refuse a hash-less row.
- **Below the minimum sample, publish NOTHING rather than a low score** (`score = NULL`, explicit `INSUFFICIENT_DATA`), and never count a NOT_EXECUTED source as a decided observation — that blames an action for never running.
- **Integrating into an existing scorer means filling a dimension, not adding one.** A weighted sum with an asserted `sum == 1.00` cannot take a new dimension, so supply the measurement to the dimension that already means that (`historical_yield`) and leave weights, bands and thresholds untouched. Prove both directions: emptied source -> the ORIGINAL value; populated source -> the measured value.
- **Reporting a count from memory is how a report becomes wrong.** Read every `N/N passed` from the CURRENT run log; a suite run before the last engine fix is not evidence for it.

### Coverage / refresh scheduling layer lessons (M20)

Distilled into `references/coverage-scheduling-layer.md` (recent-window health, per-host
scope verdicts, exact payload reuse with own bookkeeping, the fairness stamp and its
repeated-pass proof, the clamped idle term, top-N bounding of the expensive derivation, the
deferral ceiling with the selected row exempted, and the shared batch connection). Read it
before building or reviewing a coverage/refresh pass — this file keeps the closure and
reporting rules only.

- **A module constant you redefine silently steals another milestone's behaviour.** Python takes the LAST definition, so reusing a name that already exists module-wide (M18's `_DEC_INSERT` vs M17's) makes the earlier caller write nothing while still reporting success. Grep existing module-level constants before adding one.
- **A semicolon inside a SQL comment breaks a split-on-";" schema loader.** The comment swallows the next statement and the table silently never gets created. Never put `;` in DDL comments here.
- **"Written" and "created" are different numbers at a bounded-write boundary.** After de-duplication the rows actually persisted are far fewer than the rows built. Stop-reason, budget and accounting logic must use the PERSISTED count or an honest no-op cycle reports `None`.
- **A route must never outlive its decision.** When a per-cycle cap trims the decision list, intersect the route list with the survivors; otherwise routes point at decision ids that were never stored.
- **Identity must come from a STABLE key, not a clock.** A `cycle_id` built from the run timestamp while the row's upsert key is stable orphans every child row (`cycle_id=NULL`). Derive ids from the content key; treat timestamps as data.
- **Evaluate scope at DISCOVERY, not only inside the run loop.** If the verdict lives in one caller, another entry point can build the same candidate list and route an out-of-scope object.
- **Live-diff snapshots cannot attribute a decrease.** A running daemon drains queue/frontier rows between two reads. Prove "this milestone deletes nothing" by running it end-to-end on a FROZEN COPY and diffing that copy; report live churn separately and never call it a deletion.
- **A safety check written as a substring scan will flag your own correctly-named function.** Prefer behavioural/AST assertions; when scanning literals keep names unambiguous (`observe_route_outcomes`, not `record_outcomes`).
- **For count assertions, assert the RECONCILIATION, not an inequality.** `written + already + skipped == considered` catches real accounting holes that `written + skipped == considered` hides.
- **The terminal tool rejects some command SHAPES before running them.** `nohup`/
  `disown` is refused — use its own `background=true` + `notify=true`; if the
  harness rejects `notify` (it has, across sessions, for both boolean and list
  forms), launch silent and poll a marker line the command appends to its log
  instead of re-sending the parameter. A long inline
  heredoc (`python3 - <<'PY'`) can be refused as a false positive by a safety guard that
  pattern-matches the script body, which silently costs a call and can look like a code
  error. For anything longer than a couple of lines write the script to a file with
  `write_file` and run the FILE — that is also what survives a timeout, since the script
  stays on disk and is re-runnable instead of half-applied.
- **If `write_file` then refuses an existing file as stale even after a full
  read of it, write the content to a fresh sibling path and `mv` it into
  place** — one move, no read-then-write loop.

- **A new check must be shown NON-VACUOUS.** After replacing a proxy assertion with a
  real one, deliberately break a copy and confirm the check FAILS (e.g. reverse the two
  calls and confirm the decider returns False). A check that cannot fail proves nothing;
  the vacuity proof is part of the deliverable.

- **A cross-day / scheduled-run gate is verified from persistent rows, item by item.**
  While the run has not fired: `CROSS_DAY_REQUEUE = PENDING_VALIDATION` — never trigger
  it, never poll for it. Once it HAS fired: verify every item the brief lists against that
  run's own rows (retention, eligibility, selection, budget, dedup, clearing), label any
  item with no eligible real case `NO_ELIGIBLE_CASE`, and report an unobservable
  sub-check as such rather than as success. Re-derive each due-time from state instead of
  restating a figure an earlier report quoted; if the key that held it is gone, say the
  figure is not re-derivable.
- **When production contains no eligible case, report `NO_ELIGIBLE_CASE` and prove the
  path with fixtures plus the code that serves it — never with a synthesized production
  row.**
- **Clean only the temp artifacts THIS milestone created.** Before removing anything
  under `/tmp`, grep `reports/` for that path: an earlier report may cite it as retained
  evidence, and deleting it turns a true claim in that report into a false one.
- Use the brief's section headings verbatim and in its order. Do not add, rename,
  merge or reorder sections.
- The ready-status line is exactly `READY FOR PRODUCTION: YES` or
  `READY FOR PRODUCTION: NO` — no other phrasing, and no Git/repository vocabulary
  anywhere in the report.
- **Answer a status-check brief with its own field names, in its own order**
  (`X STATUS: PASS/INCOMPLETE/FAILED`, `REGRESSION: …`, `X PROOF: PASS/MISSING`,
  `FINAL REPORT: WRITTEN/NOT WRITTEN`, `READY …: YES/NO`). A status check answered in
  prose is the one that hides the field still missing; if any field is MISSING say so
  in that block and hold every READY line at NO.
- **When your own feature ran live BEFORE the integrity snapshot, itemise that window
  instead of claiming blanket "production unchanged."** Give the job id, its
  created/started/finished epochs and each row delta as intended milestone activity
  (with its traffic counters), then present the snapshot comparison as a SEPARATE,
  byte-identical result. An unchanged-bytes claim that silently spans a live run of
  your own feature cannot be defended by the next session — and the same applies to a
  test that wrote an artifact, which is disclosed separately from table mutation.
- **Re-read hash baselines before writing the integrity section.** A protected-file
  baseline goes stale by design once a milestone must register into existing
  infrastructure: verify each listed file's sha256 against the current bytes and report
  the unchanged count PLUS every DIFF by name with its justification. Never publish the
  full-set match remembered from an earlier milestone, and never hide the delta to keep
  the count green.
- State real numbers: file sizes, line counts, test counts as `N/N passed`, job PIDs,
  versions, durations. Prefer measured values over adjectives.
- List REMAINING ISSUES as actual defects/limits only, including any you introduced.
  A milestone report with an empty remaining-issues section is usually dishonest.
- When you changed a test or safety assertion, say so explicitly and why. An
  assertion that cannot fail is worse than none — see "Assertions that can actually
  fail" below.
- Stop after the report. Do not begin the next milestone, do not "wrap up".
- **A milestone cut short by a spent tool budget reports INCOMPLETE, not a verdict.**
  An engine that is built and has had its defects driven out is not a milestone: name
  exactly which gates were last green, which have NOT been re-run against the final
  code, what root causes were fixed, and what remains — as a numbered resume list.
  Never carry an earlier green number forward over code that changed afterwards, and
  never let 'no gate failed' read as readiness. `READY FOR PRODUCTION: NO` with a
  resume list is the honest report; the required sections keep their headings and the
  report ends in STOP as always.
- **A capability gated by a multi-hour cooldown is proved by ONE real dispatch plus the
  local executor path — and the limitation is stated.** Do not imply a repeatedly
  observed live run when the cadence makes a second observation hours away. Cite the real
  dispatch that did happen (job id, status, its run-log row, the scheduler fields that
  show it was granted no network budget), then state plainly that the recurring proof is
  the scheduler/executor path on a throwaway DB, not a fresh live dispatch.
- **When the layer's own verification runs mutated production state, disclose the
  corrective passes by name.** Two dry-run-first, additive, no-deletion scripts that
  repaired ids and closed duplicate threads are part of the report, not housekeeping: say
  what changed, what the row counts were before and after, and that nothing was deleted.

## Assertions that can actually fail

An assertion structurally incapable of failing is worse than no assertion: it
manufactures confidence and hides the defect it was written to catch. Every check
you add or touch gets a non-vacuity pass before it counts as verification.

- **Prove the detector fires.** Run the check against a synthetic positive case
  that MUST fail it, beside the real (clean) input. A boundary detector that never
  triggers on the hostile shape is not a boundary.
- Reject these shapes outright: `getattr(x, "Y", None) or True`,
  `True if cond else True`, `x or True`, an assertion whose condition is constant —
  and `all(cond and k != EXCLUDE for k in KEYS)`, which is FALSE for the excluded key
  and therefore false for every input. An exclusion is a FILTER on the iterable
  (`for k in KEYS if k != EXCLUDE`), never a conjunct inside the predicate; the wrong
  form ships as a permanently-red check that reads like a real product defect.
- **`X or not PRECONDITION` is vacuous in exactly the case it was written for.** A check
  shape like `assert stops_recorded or not ceilings_hit` ("either a stop was recorded, or
  no ceiling applied") passes on an empty corpus and on the very regression it targets —
  the ceiling only stops applying once the bug is fixed. Assert the property directly on
  the path that produces it, and drive the writer to the state where the property must
  hold, rather than guarding the assertion against the case you are trying to catch.
- **Scope the check to code, not file text.** A bare substring over a module matches
  the docstring that says the OPPOSITE, a constant declaration, and unrelated APIs
  (`"compile(" in src` matches `re.compile(`). Use the AST for calls and writes and
  reason about what a match MEANS.
- **Do not over-match either.** A detector keyed on a broad vocabulary flags
  legitimate READ helpers (`_trusted_template_available` reads inventory — the
  opposite of promoting). Match write verbs and subscript-store shapes, not nouns.
  The same applies to banned-TOKEN lists in static tests: a bare `socket`
  entry matches the legitimate `websocket` keyword, so give such tokens word
  boundaries or their dotted/qualified form.
- Assert the property that matters, not a proxy. "No traffic was fabricated" is
  `requests == 0 and acquired == 0`, not "no action ran" — a completed LOCAL action
  ran without acquiring anything.
- **Scope a process/network watcher to YOUR process.** A system-wide
  `/proc/net/tcp` count is dominated by the daemon's legitimate concurrent traffic
  and fails on noise; count this process's own socket fds instead, which is a
  property the module under test can actually violate.
- **Never assert a capability by finding its name in the source.** A command-surface
  suite that checks each `/command` string appears in the dispatcher file passes
  while every one of those commands exits non-zero with `unknown command` — the name
  is in the table, the wiring is not. "Present in the file" is not "reachable":
  invoke the surface (CLI and reporter) and assert the exit status and output.
- **Prefer tightening a weak check to deleting it**, then re-run it.
- **A failing SAFETY assertion is repaired in the code it guards, never in
  the assertion.** When a redaction/sanitisation test goes red, the fix is
  hardening the production rule to cover the token class it missed — editing
  the expectation to match current behaviour trades the guard for a green
  line. State explicitly which side you changed.
  Exception: when the implementation's own contract documents the observed value as
  correct, the assertion moves instead — `references/live-gate-assertion-repair.md`.
- **A test that calls a real side-effecting path really side-effects.** A smoke test
  that reaches the real notifier/enqueuer queues a row and the daemon DELIVERS it to
  the operator's Telegram — once per run, because the suite needs a fresh dedup key
  to be able to test dedup at all. Point EVERY suite that touches a notify/gate path
  at an isolated throwaway DB, not only the one where you first noticed it: grep the
  test tree for the gate symbol and check each hitter for isolation.
- **Isolating a suite removes the data it was asserting on, so seed a fixture.**
  Pointing a suite at an empty DB is right, but its "renders a stored plan/record"
  checks then fail with 0 rows for the wrong reason. Write the fixture through the
  REAL store API (not a hand-built table) so the detail/rendering path is still
exercised against the real schema, and give the fixture a recognisable id prefix
  such as `fixture`/`gate` so it is never mistaken for production data.
- **Correct a leaked row by PREFIX, not by exact id.** A reclassification script
  keyed on an exact ref_id misses every row whose id carries a timestamp suffix, so
  the leak silently continues while the script reports success. Match the fixture
  namespace by PREFIX, dry-run first and report what will change, then UPDATE the
  status — never DELETE, so the audit trail survives and the row count stays
  inspectable.
- **Give a dedup-path test a per-run unique key.** A fixed key makes the second
  execution correctly deduplicate, so the test fails on a re-run for the wrong
  reason and reads as a regression.
- **Prove fixture absence in the LIVE db by fixture-UNIQUE identity, never by id
  shape.** Sequential ids (`F-000004`) are minted by production from the same counter,
  so a leak query keyed on an id range false-positives on a real row and reports a leak
  that did not happen. Key the leak query on the fixture's distinctive namespace
  (`finding_type`, candidate-id prefix, `dedup_key` fragment), open production
  `mode=ro`, and require zero rows.
- **`bound_observed <= bound_declared` is ALWAYS true and proves nothing.** A cap check
  whose actual value came out zero passes for every ceiling — the one shape that can
  never catch an unenforced cap. Require the corpus to offer MORE candidates than the cap
  (assert that too, as its own check) and require the observed value to EQUAL the
  effective bound. Where a bound is legitimately shadowed by another, assert
  `min(own_cap, upstream_cap)` so the check still fails if nothing binds at all.
- **A fixture must reach the code path under test, not merely populate the database.**
  A pipeline is a CHAIN, so a fixture that leaves every entity at stage 1 only ever
  exercises stage 1's bound; a fixture that inserts the very evidence the stage under
  test is supposed to produce satisfies the stage instead of testing it. Walk the chain
  in the fixture and return the ELIGIBLE-CANDIDATE count, then assert it exceeds the cap.
- **A fixture target that fails a VALIDATOR the path applies renders every result as
  zero, and reads as a broken engine.** A scope guard, a state whitelist or a routing
  predicate applied to a synthetic target makes every candidate ineligible — zero rows
  written, zero proposals, no error anywhere. Seed the fixture with a key the real
  validator ACCEPTS (an existing in-scope directory key, not a made-up label), assert the
  validator's own verdict before concluding anything about the code under test, and treat
  "my fixture produced no rows" as a fixture defect until the validator is proven satisfied.
- **A fan-out router means one upstream row is not one downstream row.** A routing helper
  that expands by `asset_kind` or category can emit N records per input, so asserting
  "one feedback row → one proposal" fails on correct behaviour. Read the router, count its
  real expansion, and assert the relation it actually implements.
- **A state whitelist is a gate, not a hint.** A consumer accepting only
  `PATTERN_REVIEW_REQUIRED` correctly refuses every other plausible-sounding state, so a
  fixture seeded with `ADVISORY` or `ACTIVE` silently produces nothing. Copy the accepted
  value from the gate's own constant, and keep a SEPARATE case proving a non-accepted
  state is refused.
- **A source-scan check whose fallback is "or the name appears anywhere" cannot fail.**
  "the table is one of my seven" evaluated as `(table || name in src)` is true for every
  input. Derive the property mechanically instead — collect every write target from the
  SQL (`INTO x`, `UPDATE x`) and assert the set is a SUBSET of the owned set — and add a
  companion check that the expected count was actually reached, so an empty set cannot
  pass.
- **Shim the pool when a bound and a config both gate the same call.** When the fair
  selector and the caller's explicit argument are separate inputs, a shim that ignores its
  argument makes a later explicit-target call resolve against the wrong pool and crash with
  `TypeError` that reads like an engine bug. Make the shim return the injected pool and
  also honour the argument. Related: `ast.Assign` targets are NODES — `t.id` raises
  `AttributeError`, use `t.targets[0].id` guarded by `isinstance(t.targets[0], ast.Name)`.
- **Use the id the STORE returns, never your own label.** `add_finding()` mints the
  authoritative `F-*` id; a fixture that keeps its own label and feeds THAT to
  `register_finding_alert`/`mark_alerted`/row lookups leaves `alert_queue.ref_id`
  pointing at a row that does not exist — the queue row appears anyway (a ref is just a
  string), the id join reads 0, `alert_status` stays NULL, and `/unread` lists a third
  id, so every downstream assertion silently reads empty while the feature works.
  Consume the returned id exactly as the production call site does.
- **Assert the SPECIFIC record, not aggregate emptiness, when the corpus can yield
  several legitimate matches.** "input at the bound → NO hits" fails the moment a second
  entry with a wider bound correctly matches the same input; assert that the specific
  identity (that entry's CVE/id) is absent — or present — instead of that the whole
  result list is empty.
- **A negative fixture must be negative under the PRE-EXISTING matching policy.** Read
  the actual predicate before writing the adversarial case: a substring key rule
  (`key in observed`) intentionally matches `Microsoft-IIS` to `iis`, so an invented
  near-miss product "must not match" expectation tests a policy that does not exist and
  goes red for the wrong reason. Design the negative for the policy AS WRITTEN, and
  whenever you change a matcher, pair it with a positive probe proving the INTENDED
  matches still fire — otherwise the change that kills a false positive also kills a
  true one, unnoticed.

## A merged module must be checked for DUPLICATED definitions

When a module is written as several parts and concatenated, a part can be appended
twice. Python binds the LAST definition, so every fix applied to the earlier copy
becomes DEAD CODE while the file still visibly contains the fix — grep, inspection
and code review all pass and the behaviour is wrong. This cost a full debugging
cycle in M11: the bucketed-identity fix was present twice-over-dead, so derived
events kept regenerating and it read exactly like "identity hashes a changing
count".

- **Anchor a range replacement on the NEXT definition, and re-check the symbol set
  after it.** Deleting from 'the function I am rewriting' to 'wherever the next block
  ended' silently removes every function in between: they are gone from the module, the
  file still imports, and only a later caller fails. Find the exact index of the
  following `def`, assert it, then after the replacement assert every symbol that lived
  in the range still resolves before running the duplicate-name pass.
- **Two write paths for one table must share ONE column list and ONE argument builder.**
  A single-row insert and a batched insert that each carry their own copy drift the moment
  a column is added, and the batched one silently stops writing it (or dies on arity)
  exactly where it is used. Hold the SQL and the arg tuple in one place and have both
  paths call it.
- After any part-merge, run an AST pass over the module for duplicated top-level
  `FunctionDef`/`ClassDef` names, and delete the stale copy rather than patching it.
  Assert the block you are about to delete does NOT contain the fix, and that the
  surviving copy DOES (count the markers before and after), then re-parse.
- Hazard = duplicated FUNCTION/CLASS anywhere, or a divergent ALL-CAPS constant in
  `lib/`. Duplicated loop variables (`c`, `rows`) and a reassigned constant in a
  SCRIPT are ordinary top-to-bottom flow, not hazards — do not cry wolf, or the
  audit gets ignored.
- When a signature changes, the OLD copy is the one that will run: a duplicate is
  why "I already fixed that" is false. Verify by behaviour (a frozen-copy run), not
  by reading the file.
- **A TIMED-OUT append may still have written its content.** A `cat >> file <<'EOF'`
  (or long heredoc write) that reports a tool timeout can have flushed most of the
  block before being killed, so RETRYING IT APPENDS A SECOND COPY — the exact
  duplicate above, self-inflicted. After any timeout on an append, check whether the
  content landed (`wc -l`, tail, an AST pass for duplicated names) BEFORE re-issuing
  it. Prefer writing the block to a scratch file and appending it in-process, so a
  killed call leaves the scratch intact and re-runnable instead of half-appended.

## Determinism and idempotency of derived data

A layer that writes derived or aggregate rows must converge on re-run, or every
verification measures a moving target.

- **Take timestamps from the EVIDENCE, not the run clock.** Setting
  `observed_at`/`last_seen` to `now` rewrites every row on every run, so the table
  churns and nothing is ever "unchanged". Read each source's own real timestamp — and
  verify the column exists per table (`findings` uses `first_seen`, not `created_at`;
  a wrong name only raises when you actually run it).
- **Finalize run statistics by RECOUNTING the persisted tables, never from
  invocation-local counters.** Local accumulators start empty on every resume,
  so a resume that processes nothing writes zeroes over the previous
  invocation's saved stats and the published totals silently shrink on the
  second pass. Derive final stats from the rows themselves (cumulative table
  truth), REPLACE them keyed by run id, and add a regression case in which
  the second invocation analyzes NOTHING and the stats must be unchanged.
- Keep `first_seen`/`created_at` stable across runs and key rows by a deterministic
  identity so a re-run UPDATES instead of duplicating.
- **Verify idempotency over THREE consecutive runs and require runs 2 and 3 to be
  fully unchanged.** Run 1 after a change legitimately updates rows whose underlying
  evidence genuinely moved; treating that residue as a defect sends you chasing a
  bug that is not there.
- **Test bounded storage against a FROZEN COPY of production, not the live DB.**
  The daemon writes source rows continuously, so against the live file "unchanged
  source data" is false and `new>0` measures daemon activity, not churn. Copy the DB
  to a temp dir, fingerprint the source tables before and after to PROVE the source
  set did not move, then run the writer repeatedly.
- **Snap any window bound that enters an IDENTITY to a fixed bucket.** A window end
  derived from the run clock means every scheduled pass mints a fresh identity for
  the SAME window — unbounded growth plus no idempotency across restarts, and it
  looks like ordinary re-calibration. Bucket the bound BEFORE deriving the id and
  before building the row, so the stored window matches the stored identity.
- **An identity must EXCLUDE the dimension the record is meant to accumulate.** Put
  the outcome/direction/result label into a dedup identity and each direction gets its
  own row, so the two can never meet and a CONTRADICTION becomes structurally
  undetectable — the layer reports a clean history for a subject whose evidence
  actively disagrees with itself. Identity is the SUBJECT (type + pattern/fingerprint +
  family + Skill + version); the outcome, counts and refs are CONTENT updated in place.
  Then assert it: the same subject observed in both directions must resolve to ONE
  record with both sides populated.
- **Never put a GROWING member set into an identity or a content hash.** An identity of
  `hash(subject, member_set, version, window)` whose members are admitted in bounded
  batches changes on every pass, so the SAME logical thread mints a NEW id each time it is
  opened — burning the per-subject budget (three 'reopened' threads where there is one
  thread) while dedup looks correct within a single run. Identify by the subject and the
  window only, and keep the member set as CONTENT you update in place.
- **A windowed identity still mints a NEW entity in every new window — reuse the
  subject's OPEN one.** Fixing the growing-member-set bug by identifying on
  `(subject, window)` dedups correctly WITHIN a window and then quietly duplicates the
  work in the next one: each rollover opens a second entity for a subject whose thread is
  still open, doubling the work and consuming the per-subject budget twice. Before
  creating one, look for an OPEN entity for that subject and CONTINUE it (refresh its
  contents in place); mint a new id only when none is open. Then assert it: after the
  rollover, the subject still has exactly ONE open entity.
- **A per-subject budget must not be consumed by TERMINAL entities.** Counting every
  entity ever created means three abandoned (cancelled/stale/expired) threads permanently
  exhaust the budget and the subject can never be planned again — a ceiling that ratchets
  shut instead of bounding current work. Count only the non-terminal members, and keep the
  terminal set as one named constant so the two directions (a ceiling that can never be
  reached, a ceiling that can never be escaped) are both covered by a test.
- **Allow exactly ONE run to migrate, and require zero from run 2 on.** Changing an
  identity scheme (e.g. adding a time bucket to a content hash) re-identifies every
  pre-existing row once. Assert `new==0 for runs[1:]` — not `new==0` for run 1,
  which fails a legitimate migration, and not `new` loosely, which would hide real
  churn. Label the migration explicitly in the report; it is a disclosed event, not
  a defect.
- **When an identity SCHEME changes, migrate the ids — do not mark the old rows stale.**
  Rows written under the previous formula carry ids the new model cannot derive, and a
  stale status ORPHANS their children: child rows still reference the old id, so the
  subject keeps counting that work while a duplicate thread appears beside it. RENAME the
  id in every table that references it (one `UPDATE` per referencing column, plus the
  parent), dry-run first, print the old->new mapping, refuse the run if two rows would
  collide, and assert the row counts are unchanged in EVERY table — that is what keeps
  `ZERO DELETIONS: YES` true while the identity becomes verifiable.
- **Do not assert a raw row cap against the live DB.** Snapshot/aggregate row count
  tracks CONTENT CHANGES (every distinct content state is legitimately its own row),
  so a cap fails on ordinary production activity. Assert content-addressing
  directly — extras over distinct hashes must equal the known legacy collisions —
  and leave the boundedness proof to the frozen-copy test.
- **With bounded admission, 'a second pass creates nothing' is only true AT
  saturation.** A per-run cap means a run legitimately admits the next batch, so a test
  asserting run 2 is empty fails on CORRECT behaviour and reads as churn. Drive the writer
  to saturation (loop until a pass adds nothing, with a hard iteration ceiling), assert the
  TOTAL is bounded by the declared ceiling, and only then assert that repeat passes change
  no row count. Derive the bound from the constants instead of hard-coding an expected
  count.
- A daemon-race assertion must state the property, not the race: allow at most run 1
to add, require runs 2..n to add nothing, and re-run the suite 3× before believing
it is deterministic.
- A silent default limit makes "found nothing" indistinguishable from "did not
  look". Default to an explicit hard ceiling plus coverage telemetry that reports how
  many rows were scanned, so a zero result is provable rather than assumed.

## Tool-loop and staleness discipline

- Background completions that arrive after you already consumed their output are
  STALE: acknowledge in one line, confirm no state change, do not re-run the work. A FAILURE notice is stale the same way: match its command payload against the defect you already fixed before re-diagnosing it — a process launched before the fix keeps executing the OLD code, so its exit code describes that snapshot of the tree, not the current one, and re-fixing what is already fixed is how a correct file gets reverted.
- A long-running poller can outlive its usefulness; stop pollers you no longer need
  and never leave one running past the final report.
- Prefer several medium batched calls appending to files over one giant call: work
  survives a timeout. Persist measurements to `state/<m>_evidence/*.json`.
- Prefer reading the DB and computing aggregates in Python over streaming raw rows
  into the transcript; long outputs get truncated and lose the detail you need.
- **A fresh import missing a just-added symbol is STALE BYTECODE, not a failed patch.**
  After editing a `lib/` module mid-session a new interpreter can load the old `.pyc`
  (source edited in the same second `py_compile` wrote it): the source contains the
  symbol and compiles clean, yet `dir(module)` lacks it. Bust the cache (drop the module
  from `sys.modules`, delete its `__pycache__` entry) and re-import before touching the
  file again — re-editing a correct file to satisfy one stale import is how a real fix
  gets reverted.
- **Compile and import-probe a module before launching any batch that
  consumes it.** A patch can land text that never literally existed (the
  matcher accepts nearby content and writes the replacement verbatim),
  leaving a module that dies at import — every suite launched afterward
  crashes for the wrong reason and any regression spanning that window is
  invalid. Seconds of `py_compile` + a one-line import probe prevent it;
  runs that overlapped a defect window are discarded and disclosed in the
  report, never cited as evidence.
- **Grep operational logs by LINE SHAPE, not by bare token.** The planner lines embed
  every job-type name (`planner replenish ... 'version_cve': 8 ...`), so a content grep
  for a module name matches hundreds of them and floods a quarter-megabyte into the
  transcript while proving nothing. Count first (`output_mode="count"`) or anchor on the
  exact line format you need, and prefer the DB over logs for anything countable — the
  DB-aggregate rule above applies double to logs.

- **A live verifier that consumes its own inputs degrades permanently.** A verifier
  that picks its candidates from a HARD-CODED list gets steadily less able to test
  anything: once every id in the list is already cached/stored, it silently stops
exercising the path and reports `requests=0 docs=0` — which reads as a cluster of
  live FAILURES for a path that is perfectly healthy, and it passes earlier the same
  day. Derive candidates from the real corpus (filtered to those not already
  handled), and when the corpus is genuinely exhausted, say so EXPLICITLY instead of
  letting a cooldown skip masquerade as a failure.
- **Attribute before you fix.** When a previously-passing suite goes red with no code
  change, prove which component owns the failure before editing anything: exercise
  the production path directly with an input OUTSIDE the verifier's list and confirm
  it still fetches/normalises/persists. Then the fix belongs to the VERIFIER, not the
  component it tests — say so with the evidence, and state that no production module
  was touched. Proving a path is intact is a real deliverable; silently widening the
  test to go green is not.
- **The same discipline applies to a test that has NEVER passed — do not call a
  remaining failure "test-side" because it lives in a test file.** Reproduce the
  mechanism first: assert whether the ENGINE or the FIXTURE owns it. Two failures
  reported as test bugs were both real engine defects (a counter that was not frozen
  at the threshold, and a fixture whose "incomplete observation" premise was wrong), and
  the engine fixes were the deliverable. A correct fixture that starts passing once the
  engine is fixed is the proof; classifying from the filename is not.

## Environment-conditional assertions

Never bake a current environment fact ("the binary is not installed", "coverage is
cold") into a test as a hard assertion — it goes red the moment the environment
changes, and looks like a regression when it is a stale assertion. Assert the
INVARIANT ("when available, a real path and version are reported; when not, an
unavailable state with a reason and no fabrication"), and keep the other branch
covered by explicitly forcing it.

## Delivered-layer lessons (M16, M17, M20, M22, M23, M24)

Per-layer implementation lessons for the delivered milestones live in
`references/delivered-layer-lessons.md` — read the section for the layer you are
building or auditing (table-name collisions, region-slice bounds, coverage
counting, idempotent identities, ceiling enforcement, runner classifications,
pre-existing regression classification).
