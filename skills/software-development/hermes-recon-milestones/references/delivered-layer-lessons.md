# Delivered-layer implementation lessons (M16, M17, M20, M22, M23, M24)

Distilled lessons from the delivered HERMES layers. Read the section for the layer
you are building or auditing; the general delivery protocol stays in SKILL.md.

## Case/organizational-layer lessons (M16)

- **Check every proposed table name against the live schema BEFORE writing DDL.**
`CREATE TABLE IF NOT EXISTS` on a name another milestone already owns is a SILENT
NO-OP that routes your rows into their table (M15 hit this with M8's `research_runs`).
Also grep `lib/` and `scripts/` for the token: a name can be free as a table but
already used as a function or command — and a NEW suite name can collide with a
legacy one (the pre-existing `M15 finding view` / `M16 finding alert` suites are M1.5
finding-view work, not milestones M15/M16).
- **The daemon holds old code only for its OWN in-process paths; the job path reloads
every cycle.** `daemon.py` spawns `python3 scripts/cycle.py` as an isolated subprocess
per cycle, so `cycle.py` and the `lib/` modules IT imports pick up edits on the very
next cycle with NO restart (measured: live behaviour changed while `MainPID` was
unchanged and `NRestarts=0`). What stays stale until `systemctl --user restart
hermes-recon` is what the daemon imported at startup — `notify` delivery/status loops,
`findings_state`, heartbeat paths. Restart AFTER the regression and snapshot so it
cannot perturb their deltas, then confirm via a changed `MainPID` and observe a real
job reach COMPLETED; never claim FULL liveness from the subprocess pickup alone — the
in-process surfaces need the restart. Corollary: edits to live `cycle.py`/`lib/` race
the running subprocess, so a syntax-broken window fails REAL cycles (the daemon counts
`rc!=0` toward `consec_fail` and backs off) — `py_compile` immediately after every
patch and keep the window short.
- **A ceiling every call site must remember to test is not a ceiling.** Enforce the
budget INSIDE the emit/insert helper. M16's `MAX_EVENTS_PER_RUN=4` produced 43 events
because creation ignored the counter the refresh loop maintained.
- **Instrument a run's shared truth once per PASS, not once per row.** A reader that
opens a connection per row (and is called once per case) breached the runtime ceiling
(66s vs 60s); reading it once per pass gave 9.9s.
- **When adding a notification route, add the module's OWN `enqueue_<thing>_alert`.** The
engine fallback probes `enqueue_case_alert` → `enqueue_research_alert` →
`enqueue_alert`; a missing function silently routes the new milestone's alerts through
the PREVIOUS milestone's gate and inherits its policy.
- **Never let a local signal outrank an authoritative one.** Cap local priority signals
so upstream authority (M9) always survives, and compute the effective value as the
STRONGER of the two — that makes a downgrade structurally impossible.
- **A guard whose exception is swallowed can silently disable itself.** A work-check
referenced a name the module never imported; the `except` turned the `NameError` into
"no work" on every database. Assert the happy path on an EMPTY database too.
- **A part-merge can leave a redundant constant (`EV_X = EV_X`) — dead code the
duplicate auditor flags as hazardous.** Fold parts and then run the dupes audit on the
merged module, not just on the parts.
- **`node.test` walking yields BoolOp/Compare/Name nodes — only `ast.Call` has `.func`.**
Guard with `isinstance(c, ast.Call)` before `getattr(c.func, ...)`.
- **Run the full M1→Mn regression, not just the new suites.** It caught a defect the
standalone suites passed. Re-run the WHOLE regression after any fix — a run that
predates the fix is not evidence.

## Coverage / refresh layer lessons (M20)

- **A COUNT of the obvious column is not the coverage it looks like.** `assets.http_status` was non-NULL for all 7,839 assets, so "HTTP coverage" read as complete while only 312 hosts had a stored response sample — `0` was the never-fetched sentinel. Before believing any coverage number, find the table that holds the ACTUAL observation (`http_samples`) and count that.
- **Count ACTIONABLE gaps, not raw asset counts.** Only 1,475 of 7,839 assets resolved, so `dell` reported an HTTP gap of 3,042 when 2,897 of those hosts could never be fetched. Report `outstanding` AND `blocked` AND `actionable` separately, and drive priority, fairness and selection from `actionable` — otherwise an unreachable asset is a permanent, never-closable shortfall.
- **A per-stage ceiling at or above the planner's own per-class ceiling is unreachable fiction.** The live planner caps `http_recon` at 8/cycle and `tech_analysis` at 3, so `MAX_TECH_ENQUEUES_PER_RUN=24` could never once fire. Set each new ceiling STRICTLY BELOW the cap that values it — and below the parent total, or the total binds first. Prove each with a corpus that offers MORE candidates than the cap.
- **A pipeline is a CHAIN, so a fixture for a late stage must satisfy every earlier one.** A corpus of unresolvable hosts can only ever exercise the DNS ceiling; a "TECH" fixture that inserts the tech ledger row satisfies the stage under test. Build fixtures through the REAL evidence tables, stage by stage, and return the eligible-candidate count so the test can assert non-vacuity.
- **The daemon's health counters are LIFETIME TOTALS, not consecutive counts.** `ok=1986, neterr=505` for one live target; thresholding those marks every long-lived healthy target as COOLDOWN and the layer schedules nothing. Derive health from a recent window of real attempt rows.
- **`CREATE TABLE IF NOT EXISTS` on a table the project already owns is a silent no-op — and `coverage` was already taken by M1.** Check the name against the live schema AND `lib/` first; prefix with the milestone.
- **An identity column dropped from the INSERT list writes NULLs that duplicate everything.** A column filter of "is it in the measured fields" dropped `coverage_id`, so SQLite accepted NULL primary keys and every re-run added a whole duplicate set. Assert the primary key is in the column list, and assert the one-row-per-key invariant over LIVE rows.
- **Retiring bad rows without deleting them needs a marker AND a read filter.** 255 NULL-id rows in live data were re-identified with a `-L` suffix and marked SUPERSEDED; every read accessor then had to exclude them, or a normal report double-counts them — reintroducing the very defect the correction fixed. Dry-run first, report before/after counts, assert the row count is unchanged, and prove idempotency.
- **A freshness default that is TIGHTER than the existing planner's threshold silently increases refresh frequency.** Two of the brief's suggested windows (TECH 24h, JS 48h) were tighter than the live `TECH_STALE_S=48h` / `ANALYSIS_STALE_S=72h`. Adopt the LOOSER value, compare against the constant READ FROM THE MODULE, and state the deviation in the report.
- **`store.conn()` re-executes the whole schema**, so any per-candidate call is a performance cliff (6,155 checks cost 98s of a 154s pass). Add a batch-connection context the accessors borrow, keeping one SQL text per table, and bound a planner work-check to the targets a pass can actually serve.
- **A later milestone's append lands INSIDE an earlier suite's "to end of file" region scan.** A write-target check that slices `lib/store.py` from its OWN marker with no end bound (`src[src.index('# M20 owns ...'):]`) silently annexes every milestone added afterwards, so the earlier suite reports `wrote=14 of 7` — a REGRESSION INTRODUCED BY YOUR MILESTONE, in a suite you never touched. As soon as you append a region to a shared module, grep EVERY suite for an unbounded slice (`index('# ...'):]` with no second bound) and give it an end marker, and add your own region's marker so the next milestone has an anchor. Do NOT relax the earlier check's substance.
- **A substring safety scan will fire on your own explanatory COMMENT.** `test_m5_scheduler.py` check 33 bans execution primitives by substring over `lib/scheduler.py`, and a docblock reading "spawns zero subprocesses" contains the banned token — an M5 regression caused entirely by M21's prose. Reword YOUR comment ("starts no child process", "runs in-process"); never widen the earlier milestone's detector. Run the earlier suite that owns the file BEFORE the full regression.
- **An audit ceiling that is a safety net is not proven by REACHABILITY.** With one decision row per asset, `MAX_DECISIONS_PER_RUN` (400) is reached, but a deferral budget far above what the working caps can generate never is — and asserting reachability sends you hunting a bug that does not exist. Assert ENFORCEMENT instead: tighten the ceiling deliberately, confirm the write count is honoured and `ceilings_hit` reports it, and separately assert `audit_cap > working_cap` so the ordering is stated.
- **Two independent names for one concept WILL drift.** The target-level inventory key was written as `inventory` and read as `#inventory`, so the target-level `NEW_ASSET` path never ran and the pseudo-host was diffed as an asset — and a later one-sided rename revived it. Use ONE module-level constant (`INVENTORY_HOST`) on both sides. Same for a per-entity budget that stopped gating writes when persistence moved into a new helper: the cap was checked while BUILDING rows and then every built row was persisted (193 rows against a declared 60). A budget must trim the list that is actually WRITTEN, and it must be spent in exactly ONE place — spending it twice makes the write path see zero and store nothing while still reporting the cap as hit.
- **Removal and first-observation are the two halves of "it is not there".** A set difference in the inventory fingerprint reports every partial look as a deletion. Removal belongs ONLY to a per-host presence policy that requires a COMPLETE observation plus a persisted run of consecutive absences; the counter must advance ONE per pass per host (two baseline keys exist per host, so per-MATCH incrementing halves the threshold), must be FROZEN at the threshold when the removal fires, and every dimension baseline of a removed asset must be superseded, not just the presence row — a live DNS baseline for a deleted asset keeps reading as a valid comparison, and a superseded record must be EXCLUDED from comparison or its change re-emits forever.
- **A rotation needs its own progress stamp; the evidence's timestamp will not do.** Ordering assets by the source's own `observed_at` re-selects the same rows on every pass (an unchanged observation keeps its timestamp forever) so the tail of a large inventory is never reached. Stamp `compared_at` on the rows the pass actually compared and order by THAT. Corollary: a target may be stamped as served ONLY when rows were really written for it, and an "in flight" set must mean STARTED AND NOT FINISHED — treating "has a remainder" as in-flight makes an unopened target look busy, spends the opening budget before anything starts, and the layer deadlocks doing nothing.
- **Re-verify an end-to-end capability against the FULL engine after any engine fix, not once.** The functional suite passed while the live verifier's corpus path was structurally excluded by a rotation that had not been exercised; and an engine rewrite can invalidate an earlier idempotency proof.
- **A shared runner's exit verdict must honour every class it defines.** `regressions`
  filtered only `PREEXISTING` while the runner also maintained `ENV_DEPENDENT`, so an
  environmental miss made the whole run exit 1 and read as a regression — the most
  expensive kind of false alarm, because it sends the next session hunting a defect that
  was never introduced. Filter on every class the runner defines and record each
  classification in the evidence JSON.

### Consumption / impact layer lessons (M22)

- **A milestone that declares downstream consumers it never wired is only half built.**
  M21's docstring named M16/M17/M18/M19 as consumers, but an AST scan found **zero**
  cross-milestone write calls and three tables with zero readers. Before building a new
  layer, measure the CONSUMPTION side the same way you measure the input side: count the
  accessors of your output tables from modules that are not yours.
- **Branch `SOURCE_MODULES` is not logic — and a `[REGRESSION]` label is a hypothesis.**
  M18's live check went red the moment M22 was added to `SOURCE_MODULES`. Three
  measurements cleared it: M22 contributed **0** candidates (its table was empty), the
  constant is referenced only by that suite's own membership check and never inside the
  discovery/policy path, and **reverting only M22's lines reproduced the failure
  identically**. Attribute before you fix. The real cause was a data-conditional assertion
  (candidate count outgrew the per-cycle decision cap, so no route is actionable and the
  honest empty has no `stop_reason`) — a defect in the EARLIER suite, which you must report
  rather than repair, since fixing another milestone's check to green your tally is the
  forbidden move.
- **Registering a suite can fail silently when the shell wrapper is rejected.** A suite
  registration issued alongside a background wrapper was refused wholesale, so the edit
  never ran and the next regression completed as a 112-suite run with **zero** new suites
  in it — which read as a clean pass. Read the registration BACK from disk (count the
  entries, confirm each file exists) before launching the run that certifies it.
- **A gate nothing calls is dead code, and it hides a missing capability.** M22 declared a
  narrow alert gate, wired it nowhere, and every suite stayed green: the escalation was
  recorded but the analyst was never told. Grep for each new public function outside the
  file that defines it, and assert REACHABILITY by firing the real path and requiring the
  downstream row to appear.
- **`evaluate_policy`-style dispatch matches the LIST POSITION, not the ordinal column.**
  Inserting ordinal 13 before ordinal 12 makes `POLICY_ORDER` non-increasing and the
  milestone's own `policy_order_is_deterministic()` self-check fail — while every other
  test passes. When adding a policy to an ordered tuple, append at the END and re-check the
  monotonicity invariant; better still, do not add one (a per-milestone policy is how a
  second orchestrator gets built).
- **A milestone's region slice must be bounded at BOTH ends, and that is not enough for the
  DDL.** The schema is ONE string, so an earlier suite's `index('"""', start)` runs
  straight through every later milestone's `CREATE TABLE` and counts them as its own. Give
  each new milestone an in-schema marker comment and make the earlier scan stop there. Two
  suites (M20 F2b, M21 C5) failed this way one milestone apart.
- **Separate the MEASUREMENT from the ROUTE.** Writing a signal only on the branch that
  routes it hides the measurement for every object owned by a different authority — a
  material change on a case-owned target still invalidates that target's research. Persist
  the measurement for every entity the pass served; let routing be a separate decision.
- **A real end-to-end dispatch is the only thing that catches an entry-point mismatch.**
  The executor called `run_pass(mode=…)` while the public entry was `run(mode=…)`; every
  unit suite and the whole safety battery stayed green and only the real dispatch caught it.
  Drive the executor through the actual dispatch table, not by calling the function.
- **A live verifier must diff its own frozen copy, not the live database.** Comparing LIVE
  (read later) against an earlier snapshot attributes the running daemon's continuous
  writes to your milestone and reports a foreign table as modified. Capture the copy's
  pre-state, run on the copy, compare the copy with itself.
- **A fixture that commits on a different connection silently writes nothing.**
  `_conn().execute(...)` followed by `_conn().commit()` commits the SECOND handle's empty
  transaction, so the seeded row vanishes and the failure reads as an engine bug. Commit on
  the same handle, and assert the fixture persisted before testing anything against it.

## Decision-closure layer lessons (M24)

- **Anchor a closure layer on the POPULATED surface, not the newest one.** The brief's diagram
  pointed at the M21→M23 chain, but production had `change_impact = 0` and
  `adaptive_threads = 0` — anchoring there meant nothing to ever close over. Keying on the M14
  CLAIM (720 rows, already linked to cases) made the layer live from its first pass. Query the
  row counts for EVERY candidate anchor before choosing.
- **A module merged from parts silently clobbers duplicate constants.** `D_HUMAN` was defined as
  a decision state in one part and as a route destination in another; the later definition won,
  so every human-bound decision returned `None` while all other tests passed. The merge tool must
  refuse a module-level name defined more than once — a name check, not a substring check.
- **A self-check that raises cannot report anything.** `verify()` asserting a broken-policy state
  crashed instead of reporting it, so the non-vacuity probe proved nothing. Self-checks catch and
  report.
- **A state that no rule can reach is a dead state.** `NO_ACTION_REQUIRED` required two
  conditions the fallback already covered. Enumerate the closed vocabulary and assert EVERY value
  is reachable from a real fixture.
- **A budget that bounds bookkeeping starves the work.** `MAX_ROUTES_PER_RUN` was spent by twelve
  `NO_ROUTE` no-op rows, so the single human-bound closure got no route record — the one record
  that matters. Bound ATTEMPTS that do work; bound bookkeeping by the closure cap.
- **A ceiling enforced by truncation elsewhere is never REPORTED.** The thread cap was applied by
  rotation before any budget spend, so it never appeared in `ceilings_hit`: an operator cannot
  tell a small queue from a capped one. Report a cap at the point it binds.
- **Column names must be verified by preparing the real queries, not by grepping source.** A
  regex over concatenated SQL string literals gave a false all-clear; running `correlate()`
  against the live schema found three non-existent columns. Run the real code path.
- **A missing store handle turns your bug into another milestone's refusal.** Without `Ctx.conn`,`
  M16's `attach_member` raised and the failure was recorded as an M16 refusal — a wrong
  attribution. Pass the real handle and close it in a `finally`.
- **Assert the real invariant, not the convenient counter.** `closures_written` counts UPSERTS;
  a changed basis legitimately yields a new identity (SUPERSEDED) while an unchanged one is
  upserted in place. The assertion that means something is "no closure identity removed".
- **An alert table is append-only, not invariant.** Asserting `alert_queue` identity failed the
  moment M24 did its job — a human-review decision is supposed to alert the analyst. Classify
  tables into identical / append-only / M24-owned, and say which.
- **Test the failure you cannot see: the queue.** A runtime suite drove the executor directly and
  passed, while the live job sat PENDING behind a 121-group backlog. Only watching the real
  daemon dispatch it proved the reserved-slot path. Note the measured queue wait.
- **A regression flagged by the runner is a HYPOTHESIS.** Three were flagged; two were my own
  test defects and one (`M17 live`) was environmental — proven by (a) passing 5/5 alone
  including under load, (b) an M24 pass changing zero M17 tables, (c) M17 referencing zero M24
  tables. It passed in the next run with M17 untouched. Never repair another milestone's test to
  green your tally.
- **Never write the verdict before the certifying run finishes.** A provisional PASS was written
  into the report while run 2 was at 63/133; it had to be corrected. The final numbers, and only
  those, go in the final report.

## Adaptive outcome loop layer lessons (M23)

The full model is in `references/adaptive-outcome-loop.md`. These are the rules that cost a
debugging cycle each.

- **Audit the OUTCOME stage before designing the loop: the terminal surface may be empty.**
  Measured live: 51 M13 outcomes with **zero** `USEFUL`, 0/30 case threads resolved, 0/25
  research loops resolved, all 20 M18 routes `WAITING`. A layer that measures only "did a
  USEFUL outcome arrive" measures nothing forever. Correlate **every** surface that already
  records the outcome, and treat silence as its own state (`INSUFFICIENT_DATA`) — never as
  progress and never as failure.
- **Precedence is the design, and three orderings were wrong before they were right.**
  (a) an in-flight `WAITING` route masked a measured `NO_PROGRESS`, making that state
  unreachable; (b) a "not enough history" floor buried **explicit statements by the owning
  authority** (case `WAITING_HUMAN`, blocked coverage) — a real blocker answered with "wait
  longer". Correct order: evidence-bearing rules → measurement floor → bare in-flight
  fallback. And a neutral value (`ACTIVE`) must NOT clear the floor: existence is not outcome.
- **A documented hard ceiling that is only ever used as a read LIMIT is not enforced.**
  `MAX_OBSERVATIONS_PER_THREAD` appeared in `ceilings()` and gated every read, while the
  append path was unbounded. Grep every ceiling constant for a place that actually REFUSES,
  and test each by seeding past it — a bound that can never bind is fiction.
- **A refusal must be recorded under the name an operator would look up.** `ceilings_hit`
  reported the internal budget key (`routes`) instead of `MAX_ROUTES_PER_THREAD`, so neither
  a test nor a human could tell which ceiling refused.
- **An observation identity must be the SEMANTIC transition, never incidental fields or
  prose.** A repeat appended a second identical history row because the identity included the
  `before_state` (absent on the first pass, present afterwards) — and would also have drifted
  on any reason text quoting a live count.
- **A clock-only run id silently REPLACES a run.** Two passes inside one second share an id,
  so the second overwrites the first in the runs table and the observability trail loses a
  real run. Add a counter discriminator, and keep run identity clock-based (a run IS an event)
  while keeping thread/observation identities content-addressed (never clock-derived).
- **Safety scans must run on AST-stripped code, not on prose.** A counter merely *named*
  `subprocess_execs` tripped a substring ban, while the same scan on prose would also miss
  nothing real. Strip string constants, then scan — and self-test the scanner on a known-bad
  snippet so a scan that matches nothing is reported as vacuous, not as a pass.
- **`repr(sqlite3.Row)` contains the object's MEMORY ADDRESS.** Digesting it compares
  pointers, so a before/after table comparison reports a change on every run and blames the
  milestone under test. Convert to `dict(row)` first. Reproduce in isolation before believing
  a "your pass modified a protected table" result.
- **A truthy-string verdict is not a boolean.** `scope_guard.check()` returns
  `(verdict, target_dir)` and `"OUT_OF_SCOPE"` is a truthy string, so testing `[0]` truthiness
  accepted every host. Compare against the exact enum value.
- **Compare copy-pre vs copy-post, never live-now.** A snapshot check flagged 5 tables
  (`jobs`, `activity`, `assets`, …) as modified by the milestone; measurement showed the live
  daemon adds `jobs` rows continuously. Any check that reads the live DB twice attributes the
  daemon's writes to your code.
- **Verify table names against the live schema before asserting on them.** `orch_*` never
  existed — the real M18 tables are `orchestration_*` — so a presence check asserted that
  non-existent tables were present.
- **A wrong test assertion makes a WORKING feature look broken.** `enqueue_alert` returns
  `lastrowid` (an `int`); asserting `isinstance(..., str)` failed a gate that had in fact
  fired and written its row. Check the API's real return type, then assert the downstream row
  exists.
- **A fixture must vary the evidence the ENGINE reads.** Writing a raw column the correlate
  step never hashes left the evidence identical, so content-addressed dedup correctly refused
  and two ceilings were unreachable. Read the fingerprint's inputs from the code, then vary
  those.
- **Stray edits during a regression invalidate it.** Stop the run rather than report from it,
  freeze the hashes, launch one final run, and re-verify the hashes afterwards.
- **Restarting the daemon is what makes a new scheduler class live.** Until the restart the
  running process holds the previous code, so the live schema/code claim is unproven. Assert
  the live schema equals the fresh-DB schema (count AND set), not just that the tables appear.


## Product-identity / attribution layer lessons (M9)

The M9 milestone class is SEMANTIC: decide what an observation is allowed to
assert, without changing which rows exist, what priority they carry, or what
downstream cases result.

- **Find the DECISION point before changing any field.** Trace the real path
  (observation -> normaliser -> state -> persisted row -> consumer) and read the
  branch that emits the state. A `NO_PRODUCT_MATCH` verdict often means "the
  asset's token did not resolve", not "attribution was refused" -- so upstream
  input classification, not the downstream gate, is the defect. Reading the
  consumer first sends you to widen the wrong module.
- **A value that flows into an identity hash cannot be cleared to fix a semantic
  problem.** `canonical_product` fed `dedup_key()`, correlation identity, huntplan
  and evidence. Nulling it for a whole class would delete correlations and re-key
  history. Keep the value, and enforce the new semantics at the single point where
  the class is USED for the disallowed purpose (here: refuse to ask the research
  store whether an infrastructure name has CVE ranges). Then prove row identity
  is untouched: same correlation keys, same states, same row counts before/after.
- **Derive the classification set from data, not from intuition, and state the
  derivation.** The rule used was "every canonical alias value with NO
  intersection with the stored research product set", which yields the class
  mechanically (14 names) and stays correct as the research set grows.
  Re-check the class's own premise before trusting it: a comment claiming "the
  canonical value MUST also be a plausible M8 product name" was true for only
  2 of 29 alias entries.
- **The existing "too generic" set is not the same class as "infrastructure".**
  `AMBIGUOUS_NAMES` holds generic LABELS (`server`, `proxy`, `gateway`); the new
  class holds real vendors and serving stacks (`nginx`, `vercel`, `cloudflare`).
  Extending the ambiguous set would have been wrong — those names are precise,
  they just do not identify a product. Keep the classes separate and test each.
- **A shared-infrastructure baseline is measurable, and it disqualifies the
  signal.** Count distinct targets per technology: `hsts` spanned 15 targets /
  1193 hosts, `apache http server` 6 / 1259. Any fingerprint that broad cannot
  attribute a host to a target. Quote these numbers when rejecting a signal.
- **Real product names on third-party hosts are not target attribution.** A
  WordPress version found on a tenant subdomain is that tenant's software. Do not
  blanket-reject the product (it is a legitimate stored research product, and
  suppressing it suppresses evidence) and do not accept it as attribution --
  record it and separate the two questions.
- **An honest negative result is a PASS for a semantic milestone.** The
  classification got more truthful while the attributable population stayed at
  zero. Report the semantic improvement and the unchanged attribution count as
  separate fields, and say explicitly that no new vulnerability was found.
- **List every suite that shares the changed mechanism, not just the one that
  failed.** A check replaced in one suite existed in four others in different
  spellings; grepping for the mechanism's SHAPE found them all.

## Ranking / prioritization layer lessons (M17)

- **A ranking row's identity must include its CONTENT, or the ranking silently goes stale.**
If the primary key is `(target, action)` while the content hash covers the body, then a
CHANGED ranking hits the PRIMARY-KEY conflict, `INSERT OR IGNORE` skips it silently, and
the caller still reports `created=True`. Identity must include the content hash, and the
store must report the REAL insert outcome (`cur.rowcount`), never assume success.
- **Anything timestamp- or freshness-derived must be excluded from `content_hash`, or every
pass mints a new row.** Conversely, anything that genuinely changes the meaning (the
evidence set, the confidence) MUST be in it — a hash that covers only score+band can
never update when the evidence underneath changes.
- **Never key one live row on the run id.** A decision keyed on `sha(run_id, ...)` inserts a
fresh set every pass, and any reader that orders across runs (e.g. `ORDER BY rank`) then
hands back a MIXTURE of stale and current rows — including duplicate `rank=1`.
- **When a brief asks the planner to "consume" recommendations, implement the consumption
and prove it.** Importing the module to gate its own pass is NOT consumption. Wire it into
the single funnel every target-facing job passes through (`add()`), change only the
priority LABEL, keep the rate limit/concurrency/dedup/scope untouched, cap the number of
boosts per cycle, and degrade to `{}` if the tables are unavailable.
- **A "no change on the second pass" assertion against a copy of production is usually
wrong.** The live daemon wrote at a different timestamp, so the first pass legitimately
records real transitions. Assert CONVERGENCE (the history stops growing; a fully settled
pass adds zero) and measure passes until it settles — do not assert instant zero.
- **`ast.Import` has no `.module`** (only `ImportFrom` does) — guard before attribute access.
- **Never flag a bare attribute name as a dangerous primitive.** A set containing `get`
matches every dict lookup (one module had 166) and cannot discriminate; require the
DOTTED form (`requests.get`, `socket.socket`).
- **An env-var ceiling helper can only TIGHTEN a bound**; verify both directions.
- **Report the intermediate failures too.** When a post-change regression shows N failures
and a later run is clean, state the intermediate tally and classify each failure — a clean
final run does not erase a real over-strict assertion that had to be found and fixed.
  If you ALREADY published a classification that later proved wrong (calling engine
  defects "test-side", or naming the wrong owner of a red suite), correct it explicitly
  in the next report rather than letting the quieter final tally replace it.
