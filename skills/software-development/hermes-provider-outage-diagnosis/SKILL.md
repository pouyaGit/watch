---
name: hermes-provider-outage-diagnosis
description: "Use when Hermes reports JEV/LLM unavailable or idle, or when a pipeline is enabled but produces zero output."
category: software-development
---

# Hermes provider-outage diagnosis

For read-only triage of alerts like `JEV=JEV_UNAVAILABLE`,
`LLM=LLM_UNAVAILABLE`, or "hunter X shows no activity". The governing rule:
**a persisted status string is a CLAIM about a past event, not a fact about
now.** Every one of these can be a bug in the consumer rather than an outage.

Also covers the neighbouring class: a feature is enabled and scheduled, every
knob looks right, and the artifact count is still 0. See
`references/zero-output-funnel.md` for the counter-vs-state, retry-pool, and
stale-error-text procedure.

## 1. Read the reason string, not the status

The status alone is uninformative; the `*_reason` beside it names the branch.

- Query the real event payload (`case_events.metadata`), parse it, and read the
  provenance block — `jev_reason`, `llm_reason`, `decision_source`. The generic
  status is produced by a dozen call sites; the reason is unique to one.
- Find every producer before theorising:
  `grep -rn "JEV_UNAVAILABLE\|LLM_UNAVAILABLE" lib/`. Note the LINE per
  producer; a status with several origins needs the reason to disambiguate.
- **Persisted reasons are historical.** A failure string timestamped hours ago
  says nothing about the provider now. Always probe live before concluding
  anything about current health.
- **Distinguish historical decision fallback from current provider state.** A
  persisted string like `Automatic decisions unavailable: JEV=..., LLM=...`
  stored in a database column (such as `case_reason`) records the fallback state
  at the time that specific row/case was created. Check the creation timestamp
  and subsequent decision records before assuming a current outage or bug.
- **Inspect environment vs code contract before assuming a bug in `kind` guards.**
  When an adapter appears to return `Unavailable...` on a mode like `live`
  (e.g. `if kind in ("unavailable", "live"): return Unavailable...`), check what
  the production environment actually sets: in many architectures, production
  operates on an *empty/unset* environment variable (falling through to a default
  configured runtime), while `kind` values are reserved test fixture switches.
- **Check service process freshness before diagnosing code vs behavior.** If on-disk
  code appears right or tests pass in isolation but the service/user observes old
  behavior, inspect the PID's start time (`systemctl show -p ActiveEnterTimestamp`).
  Python services do not hot-reload disk edits.
- **Strict safety rule on decision paths:** Never auto-patch or bypass the JEV/LLM
  decision execution path without explicit human instruction and verification.
  Investigation of provider availability must remain strictly diagnostic and
  read-only; do not synthesize artificial bypasses.

### Closing the question with one query instead of a theory

An "is this still broken?" debate is settled by a timestamp comparison, not by
reading more code. Run the query over the FAILURE-SIGNATURE column, take
`MAX(created_at)` of the matching rows, and compare it against the mtime of the
config/credential change that would have fixed it. If the newest failing row
predates the fix, the issue is closed and the remaining rows are history. If any
row postdates it, there is a live problem and you have your starting set. Do this
before writing a single line of code, and quote both timestamps side by side.

- **A branch can look like a bug and be unreachable in production.** A suspicious
  mode test (a `kind` value grouped with a failure mode) is only a defect if
  production can reach it. Read the live environment for the selector variable:
  if it is UNSET, control falls to the default branch and the suspicious line is
  dead in production while remaining live only for test fixtures. Then read the
  contract tests that pin that behaviour — they often assert the override is
  *deliberately* not honoured in production, which makes "fixing" the line a
  regression. Check reachability and intent before proposing a change.
- **When a brief asserts a bug at a specific line, verify the line before acting
  on it.** Quote the actual source, report what the production environment
  resolves to, and state plainly that the suspected condition is not met. The
  deliverable for a diagnosis brief is EVIDENCE for each numbered item, not a fix.
- **Report per-item evidence even when the answer is "nothing is wrong."** An
  operator who asked for four specific checks wants four answers, each with the
  command, the source, and the value. A confident "all healthy" summary with no
  per-item evidence is not an acceptable substitute and invites re-asking.
- **A skill file you edited mid-session may be questioned as a potential
  auto-patch.** When an operator asks what a skill patch did, show the diff and
  state plainly that a skill is inert documentation, not code, and that the
  decision path is unchanged. Do not let the question go unanswered.

## 1b. Stop the fix chain when its verification is unreachable

A brief can list several fixes in sequence and end with a step that must be
demonstrated end-to-end. Check that the last step is reachable **before**
starting, because each unverified fix is a half-verified fix.

- Map the requested chain onto its dependencies. If the final proof consumes an
  artifact the upstream is responsible for producing, and the upstream is
  broken, the final step cannot be proven no matter how correct the middle fix
  is.
- Deliver the upstream diagnosis with measurements, state exactly which of the
  requested fixes you can prove offline right now, and say which you cannot prove
  at all until the blocker clears. "This half is verified, the verifying half is
  not reachable yet" is a complete deliverable; reporting the reachable half as
  done is not.
- Offer sequencing options and let the operator choose, with a recommendation.
  When the blocker is a single defect standing between the operator and the
  artifact they actually want, fixing it first is usually the shorter path.
- Do not quietly reorder the brief's steps. The operator may have ordered them
  for a reason (cheap-and-safe first, risky-and-central second), and silently
  reordering hides a decision that is theirs.

## 2. Probe the provider directly, once

One bounded call, from a script, with no retry loop. Compare against the last
known-good recorded in the report (e.g. a prior validation status/model), and
do not assume it still holds.

- The probe result usually contradicts the alert. Healthy provider + persisted
  `UNAVAILABLE` is the signature of a CONSUMER bug, and it reframes the whole
  investigation — check the consumer's handling of the provider's success states
  before touching config, credentials, or the network.
- **Watch for a cache/idempotency state being misread as failure.** A cache hit
  that returns a sentinel state with an EMPTY payload is a SUCCESS being reported
  as unavailable: the consumer tests `or not payload` and the legitimate cached
  result has no payload attached. Check the store's return dict for an empty
  payload on the success path. The usual mechanism is that the store persisted
  the request METADATA and never the response body, so a repeat of an idempotent
  key can only ever come back empty.
- One request is enough. Repeating to "confirm" is a load decision, not a
  diagnostic, and a brief that says one call means one call.

### A failure class raised in the parse layer describes the ENVELOPE, not the content

Classes like `MISSING_CHOICES`, `MISSING_FIELD` or `EMPTY_RESPONSE` state what
the parser could not find. They are raised in the parse layer, so they carry no
information about whether the model produced a usable answer — a decoder
choking on bytes trailing a valid JSON object reports the same class as a model
that returned nothing.

Before you repeat one of those classes back to the user as the cause, capture
the **raw response body**: its length, its decoded top-level keys, and the bytes
that trail the first complete JSON value. Decode with a streaming decoder
(`json.JSONDecoder().raw_decode`) and print the remainder — gateways and proxies
append stream terminators (`data: [DONE]`, SSE comments, keep-alives) even to
responses requested as non-streaming, and a strict whole-body `json.loads`
turns a perfect answer into "Extra data" and thus into `MISSING_CHOICES`.

Then validate the **inner** object against the schema the pipeline requires. If
that passes with zero errors while the pipeline reports failure, the content is
fine and the defect is in the parse layer — say so explicitly. Recipe and the
three-way discrimination table: `references/envelope-and-size-probes.md`.

- **Disprove a size theory with a size ladder, not one big test.** When the
  hypothesis is "the input is too large", time the same call at the real size,
  at half, and at roughly 2x the cap. Non-monotonic latency across the rungs, or
  every rung failing with the identical error, kills the hypothesis — a single
  oversized test cannot separate "too big" from "always broken".
- **Print the real input-length distribution before believing a size claim.** A
  configured cap says nothing about what flows through it; a pipeline whose
  largest artifact is 4 KB cannot be context-bound whatever its limit is set to.
  When a brief asserts a size that the data contradicts, measure and correct it
  rather than testing the asserted number.
- **Absence of usage data is not absence of throughput, and never a reason to
  estimate.** An empty `usage` object means tok/s cannot be computed: say so and
  move on. A throughput figure back-computed from wall time and a guessed output
  size is fabrication, and worse than an acknowledged gap.

### Repairing an empty-payload cache, not renaming it

Renaming the sentinel state to the success state is the wrong repair: it makes the
label lie while the payload stays missing, and every later consumer inherits the
lie. Fix the three layers instead.

- **Persist the body.** Add the payload to the record that already exists (an
  additive column, NULL for historical rows) and write the validated payload when
  the live call succeeds.
- **Replay, do not re-report.** On a cache hit, re-validate the stored payload
  against the contracts the caller actually asked for, then return it as the
  provider decision. A replayed answer is a provider answer; a fresh request is a
  fresh request. Do not silently convert one into the other.
- **A stored-success row with no usable payload is neither success nor failure.**
  It means the cache predates the payload column. Let it fall through to exactly
  ONE fresh request, then cache the result. Reporting it as unavailable is the
  original bug; reporting it as available is the renamed bug.
- **Prove the replay is non-vacuous in both directions**: seed a cache row with a
  valid payload and assert the consumer returns that decision with zero provider
  calls; seed one with an empty or malformed payload and assert it re-requests
  exactly once. Test only the happy direction and the branch is untested.

## 2b. When the fix is a STATUS DISPLAY, not a repair

A brief may ask you to make a provider's CURRENT health visible instead of
repairing it. The provider is usually healthy; the defect is that a historical
string is the only provider-state text on the page.

- **The producer is the proof that it is historical.** Trace the string to the
  exact line that writes it (`grep -rn "<phrase>" lib/`) and read the function
  around it. A `case_reason` written inside `trigger_human_review_alert` is a
  record of one past decision, not a health field.
- **Do not rewrite the stored row.** Echo it verbatim in a block labelled as
  historical, and put current health in a separate, separately-justified block.
  Assert the row is byte-identical afterwards, and say so.
- **Do not call the provider's own `health()` to get current state.** It can
  write: `OptionalJevProvider.health()` -> `_read_state()` -> `_ensure_schema()`
  runs `CREATE TABLE` + `commit()`. Read the same rows (`jev_state`,
  `jev_requests`) through the read-only handle instead. A "status" helper that
  bootstraps its own schema is a writer.
- **Do not send a probe to fill a badge.** Prefer inert sources; for an LLM that
  is often a pure config resolver (`research_llm._hermes_default_runtime()`
  answers "is there base_url + model + credential" without a request). State in
  the output that it is resolution-only, or the claim gets over-read.
- **Never map config presence to AVAILABLE.** An enabled adapter with no
  recorded success is UNKNOWN, not AVAILABLE. A recorded success older than a
  named `STALE_S` is DEGRADED, not AVAILABLE — quoting a stale success as current
  repeats the exact lie being fixed. Make the threshold a module constant so it
  is tunable, and disclose that the reading has a shelf life.
- Prove inertness on the AST, not on prose: a docstring saying "opens no socket"
  matches a substring grep for `socket` and fails your own check. Walk
  `ast.Import`/`ImportFrom`/`Call` and assert an empty intersection with a
  network-name set.

## 3. Separate the service's environment from yours

A provider that works in your shell but 401s for the daemon is an ENVIRONMENT
gap, not an outage — and the two look identical from the alert.

- Read the live process's env, not the unit file:
  `tr '\0' '\n' < /proc/$(systemctl --user show svc -p MainPID --value)/environ | grep -iE 'KEY|TOKEN|URL|MODEL'`
  showing NAMES with values redacted.
- Check whether the unit declares `EnvironmentFile=` at all. A unit that omits it
  loads nothing, and a config file sitting on disk is inert.
- Resolve the key's SOURCE, then compare per-variable presence. Credentials
  resolved from a runtime/provider resolver come from an indirectly-named env var
  (e.g. a slugified custom-provider name) that is easy to miss when grepping for
  the obvious prefix.
- Prove it by SIMULATING the service environment: delete that one variable, call
  the provider, and observe the exact failure. This converts an inference into a
  reproduction, and identifies the precise fix (inject the var) instead of a
  vague "check your config".
- Redact every secret in all output: names and set/not-set, lengths, never values.
- A config file read DIRECTLY by application code (not via process env) is a
  third case — check whether the loader reads a path, and it works even with an
  empty environ. Resolve which mechanism is actually in use before classifying.
  Note that a unit lacking `EnvironmentFile=` is not a failure of the provider
  config at all, so classify the mechanism before touching credentials.
- **Install the secret without ever materialising it in the transcript.** Resolve
  the credential from the config the application itself reads, write it to a
  root-only file, and set restrictive permissions BEFORE writing any content. Add
  the file to the unit as an environment source, then reload and start. Proof is
  the service reporting the variable as present with its value redacted, and a
  live call made from the service environment returning success.
- **A secret value must never appear in a unit file, a report, or an echoed
  command.** If a heredoc or one-liner you are about to run contains a
  value-bearing literal, write a script file instead — a shell transcript is
  durable.

### Probe parent and child side by side, inside the child's own namespace

An alert that "works in my shell, 401s for the daemon" is settled by running
the *same* probe in both processes and diffing the output. Do not reason about
which layer loses the credential — resolve it and spawn a child the way the
daemon does, then compare.

```
PID=$(systemctl --user show <svc> -p MainPID --value)
nsenter -t $PID -m -p -- python3 <project>/scripts/cred_probe.py parent
# then, from inside that namespace, re-spawn with the daemon's own construction:
nsenter -t $PID -m -p -- python3 -c "
import os,subprocess
env=os.environ.copy(); env['<THE_FLAG>']='1'
print(subprocess.run(['python3','<project>/scripts/cred_probe.py','child'],
      env=env,capture_output=True,text=True).stdout)"
```

Print presence, length, and the resolver's own verdict only. Four lines to emit
per process: env var names+lengths, the resolver's `model`/`base_url`/key
presence, `get_provider()`'s class and `available()`, and the flag the parent
injects. Identical output in both processes means the credential is not being
lost, and the hypothesis about the child is disproved.

`scripts/cred_probe.py` in this skill is that probe, ready to copy into the
project. It prints names, lengths, the resolver's verdict, and the `/tmp`
visibility check, and it never prints a value.

- **Put the probe script in the project tree, never in `/tmp`.** With
  `PrivateTmp=true` the unit has a private `/tmp`, so `nsenter -m` cannot see a
  script you just wrote there — the probe fails with `can't open file` and looks
  like a product bug. Confirm the namespace is real by listing `/tmp` inside it
  (an empty listing proves the private mount), then move the script and re-run.
- **`credential_pool` in the resolved runtime means the key came from a resolver
  object, not a file read**, so `ProtectSystem`/`ProtectHome` cannot be blocking
  it. Check that field before chasing filesystem permissions at all.
- **Absence of `Permission denied` in the journal is the positive result.** Once
  the probe succeeds inside the namespace, a permissions theory is dead; do not
  keep grepping the journal for an error that was never logged.
- **A hypothesis the operator proposes is a hypothesis, not a mechanism.** When a
  brief offers a specific mechanism (namespace isolation hides the credential,
  the parent drops the env var), simulate it and report the measurement even
  when it disproves the theory. A confident "yes, that's it" that the next
  measurement refutes costs more turns than saying "I don't think that is it,
  here is what I measured".

## 4. "Dormant subsystem" is a routing claim until proven

A component showing no activity has several distinct causes; they need different
fixes and must be separated by measurement, not assumed.

- **Feed the router the REAL production signal shape, not a convenient one.**
  Reconstruct the exact dict the production caller builds (its `kind`, its
  fields) and route it. Routing raw table rows can look healthy while the live
  path never produces those kinds.
- **Grep the router's kind-guards and check the live kind against every one.**
  A default/fallback branch (`if not chosen: add(DEFAULT)`) means any kind not
  named in any guard routes 100% to the default. That single fact explains
  "only the general handler ever runs" without touching the scheduler.
- Read the UPSTREAM producer of that signal, not just the consumer: the
  investigation path may synthesise one `kind` for every work item, making the
  other branches structurally unreachable. Confirm with a distribution over real
  persisted work items (`_signal_for_context` and equivalents), not a sample.
- Distinguish, and report separately: (A) never triggered, (B) triggered with no
  match, (C) matched but downstream provider failed, (D) downstream provider
  failed, (E) intentionally dormant by policy. "No pending eligible work" and
  "eligible work exists but unconsumed" are different findings and the second
  one is the alarming one.
- Approved/available configuration is NOT evidence of use. A registry with N
  approved entries and a single active consumer means the entries are only
  reachable through that consumer — say so instead of reporting them as
  in use.

### Repairing a structural routing gap

Once the kind-guard mismatch is confirmed, the fix is a routing RULE backed by
evidence, not a reordering of branches and not a widened default.

- **Enrich the signal from real persisted rows before routing.** The signal the
  producer emits is too coarse to discriminate, so derive the discriminators the
  router needs from what production actually recorded: technologies, parameters,
  endpoints, auth context, API context. Never invent a label to make a branch
  fire.
- **Keep the default as the default.** The general handler must remain the
  fallback for insufficient evidence, otherwise the fix renames the same
  concentration. Report the BEFORE and AFTER distribution over the full real
  population, not a sample — the before number is what proves the gap existed.
- **Cap fan-out.** A signal that legitimately matches two families is fine; one
  that matches every family means the rules are too loose to discriminate. State
  the cap and assert it.
- **Match text on separators, never on word boundaries.** `\b` does not treat
  underscore as a boundary, so the single most common real-world parameter
  (`user_id`) never matches `\buser\b`. Use an explicit separator class anchored
  to a start-of-string alternative (`(^|[^a-z0-9])`) so a token at position zero
  still matches.
- **Stringify list evidence explicitly.** A helper that renders a container via
  its generic string form produces Python `repr` syntax, and a matcher written
  for natural text silently sees brackets and quotes. Join lists before
  matching, and add a test that passes a list.
- **Test the routing with the caller's real container shape** — see
  `hermes-verification-discipline` on container-shape contracts.
- Reachability is a separate claim from experience. Once all branches are
  reachable, the report must distinguish which families have actually produced
  persisted records from which merely could. Claiming a family's effectiveness
  from reachability alone is the error the diagnostic was commissioned to fix.
  Reachability is in turn separate from consumption, and both are separate from
  effect: the supporting-outcome rate for the work a family actually attracted is
  the only measure of value, and a rising route share can be wasted work if the
  new routes are drawing load onto units whose premise is already contradicted.
  When the follow-on milestone is an observation brief, see
  `hermes-verification-discipline` -> `references/effectiveness-observation.md`.

### An armed agent that runs on schedule and decides nothing

`state=COMPLETED` in a runs table means the pass finished, not that it decided
anything. An agent can run every 30 minutes for days and produce a decision row
per case while every single verdict is the fallback.

- **Measure the DECISION table's verdict distribution, not the run table's
  state.** `SELECT verdict, COUNT(*) FROM <decisions> GROUP BY verdict` is the
  only query that answers "is this agent doing anything". A runs table showing
  88 COMPLETED rows was consistent with 436 decisions that were all
  `STILL_NEEDS_HUMAN`.
- **A fail-closed gate hides a dead component indefinitely.** When a two-source
  gate requires both sources to agree, and one source is only *called* when the
  other returns a non-fallback answer, that source can be 100% broken with zero
  symptoms: its call counter stays at `0` in every run summary and reads as
  "budget saved" rather than "this leg has never executed". Print per-leg call
  counts AND per-leg success counts, and treat a long-lived `0` on a conditional
  leg as a finding.
- **A conservative upstream makes a downstream bug unreachable, so probe each
  leg independently.** A model asked to decide can answer `INSUFFICIENT` with
  ~0.97 confidence on the whole population, which short-circuits the second leg
  entirely. Do not conclude "the gate works, it is just cautious" — call each leg
  directly with a real packet and check it returns a usable value at all.
- **A stored reason string names the evidence the row was opened against; a
  "newest matching row" re-fetch silently evaluates a DIFFERENT fact.** When a
  case's `*_reason` cites a specific evidence id, resolve THAT id — a helper that
  re-queries by `(target, host) ORDER BY updated_at DESC LIMIT 1` returns the
  newest row for the host, which after a re-run is a different record. Measured:
  112 of 125 cases had a resolved id different from the one their own reason
  named, and 42 resolved to nothing at all. Assert the resolved id equals the
  cited id, or the decision is about a fact the case never referenced.
- **Distinguish "cannot decide" from "decided not to".** Both persist as the
  same fallback verdict. The `gate_reason` column separates them: a reason of
  "provider unavailable/invalid" is a component failure, "below the grounded
  bar" is an evidence limitation, and only the first is a bug.

- **A structural bar that can never be met is a permanent zero, not
  conservatism.** If the confirm predicate requires a state that upstream
  cannot yet produce, every case is guaranteed to fall through. Report the bar
  as unsatisfiable-by-construction with the count of cases it holds, instead of
  presenting the fallback as healthy caution.

## 5. Disclose probe side effects; a "read-only" diagnostic is not read-only

A probe can write even when you believe it cannot.

- **State-marker rows are historical, not current health.** Retry/exhaustion
  counters, `last_error`, and `last_failed_at` describe work that happened at the
  time of the last attempt. Reading them and concluding "the provider is
  failing" repeats the governing error of this skill one layer down: you have
  substituted a persisted claim about a past event for a fact about now. Before
  naming any row as the live cause, date it against the fix that would have
  resolved it (`MAX(created_at)` of the failure signature vs the mtime of the
  config/credential change). A pool full of exhausted rows stamped last week is
  *state left behind by* a fixed defect, not evidence the defect is live.
- **Say so out loud when you correct yourself.** If an earlier message in the
  same session called something live and a later measurement disproved it, state
  the correction plainly and name the class of error, rather than quietly
  restating the correct conclusion. The operator needs to know which of your
  earlier claims to discard.
- **A downstream state left behind by a fix is a second defect, not a
  resurrection of the first.** Once the credential is verified working, stale
  exhausted markers will keep a pipeline at zero even though the blocker is
  gone. Report those as their own finding with their own remedy; clearing them
  may be a production write the operator has to authorise.

- Passing `store_mod=None` is NOT proof of no write: check for a fallback like
  `if self._store is not None: ... else: import store` that resolves to the
  global handle. A helper that self-installs a store bypasses your override.
- **Diff the table row counts before and after any probe** and attribute every
  delta. A count that moved is yours, and the report must say so with the row's
  timestamp and run id. Never report `PRODUCTION MUTATION: NONE` while a row you
  created sits in the table.
- If the brief demands a read-only guarantee, prefer a genuinely inert path
  (read-only URI, an explicit non-persisting transport) and verify the row count
  afterwards rather than trusting the signature.
- This is the same class as §12's fixture discipline: your own probe is a write
  unless you have proven otherwise.

## 6. Report structure that lands

- State the correction FIRST when you caused a mutation, before the findings it
  affects.
- For each component: STATUS | ROOT CAUSE | EVIDENCE | CATEGORY | ACTION. The
  evidence column carries the line numbers and the measured probe output, so the
  next reader can re-run it.
- Categories: CONFIGURATION / NETWORK / PROVIDER / CODE / SCHEDULER / QUEUE /
  DATA / CIRCUIT_BREAKER / EXPECTED_IDLE. Never leave a root cause UNKNOWN when
  the producing line is in hand; "the consumer misreads a cache sentinel" is CODE.
- **Answer "one problem or several" explicitly.** Independent subsystems with
  independent causes must not be collapsed into one narrative.
- **Answer "would a restart help" per component, without restarting.** A restart
  fixes a missing env var only after it is injected; it never fixes a code bug or
  a structural routing gap. Say which is which — that is the decision the reader
  needs.
- Verify the brief's own inputs. Case ids in a brief may be TRUNCATED: match on
  the prefix and resolve the full id rather than reporting the rows as missing.

Reference files: `references/zero-output-funnel.md` (counter-vs-state, retry
pool, keyword-gate inversion, schema-before-query) and
`references/envelope-and-size-probes.md` (raw-envelope capture, parse-layer vs
content, size ladders).

Related: `hermes-verification-discipline` (proving non-vacuity, disclosing
failures), `hermes-skill-governance` (the registry this diagnostic often finds
dormant), `systematic-debugging` (phase discipline).
