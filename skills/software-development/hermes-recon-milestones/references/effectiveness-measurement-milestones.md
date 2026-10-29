# Measuring whether a component actually changes an outcome

Use when a brief asks "does X improve / affect / change Y?" about an EXISTING
pipeline component, and forbids implementing the change to make the number
look better. This is the class of work that produces honest `NO_MEASURED_EFFECT`
and `ARCHITECTURAL_GAP` verdicts instead of a manufactured win.

The hard part is never computing the metric. It is resisting the three traps:
declaring a structural finding "just a sample-size problem", wiring the
measured component into the consumer to make it look effective, and reporting
"identical plans, so no effect" when the plans were never read by the consumer.

## 1. Trace the decision function, do not infer it

The first question is never "is it connected?" — it is **which function actually
decides, and what does that function read**. A component can be wired end to end
with perfect lineage and still have zero influence, because the decision reads
a different variable.

- Locate the real decision function by inspection (grep for the vocabulary, not
  for the milestone's guess of the name) and read it whole. A brief that says
  "the outcome is decided primarily from X" is usually right, and the rest of
  the chain is decoration.
- **Count token occurrences of the injected fields inside the decision
  function's own body.** Slice the source from `def <decision>()` to the next
  top-level def, then count. `plan` 8 and `evidence_needed` 0 in the same body is
  the whole finding in two numbers. Report the counts; they are reproducible and
  a reader can re-derive them.
- A zero-occurrence scan over the CONSUMER module is the blunt version and is
  worth running too: "0 occurrences of `skill` in this 1,485-line module" is a
  complete, falsifiable claim.
- **Prove the wiring is real before crediting it.** A module that mentions the
  upstream's name only in comments is not a consumer. Grep the call sites; if
  the only reference is `# no skill promotion, no M6.`, that is a comment, not
  a hop.

## 2. Establish the negative BEFORE the change, so the proof is causal

Structural findings about a *planned* change need a baseline you can compare
against. Capture the pre-change property with the same probe you will use after,
on real data, read-only:

- For "the plan is identical with and without the component", run a two-arm
  differential on every comparable real input and report the rate
  (`42/42 byte-identical`). That number is what later proves the gap closed.
- Assert the arms differ ONLY in the component. Same signal, target, scope,
  evidence state and hard constraints — otherwise a hidden variable explains the
  result and the measurement is void.
- If the brief forbids changing production to obtain a baseline, replay against
  a throwaway copy: back up production with SQLite's backup API, redirect the
  project's store handle at the copy, suppress the component, and run the real
  entry point.

## 3. A changed artifact proves CONSUMPTION, never EFFECTIVENESS

This distinction is the deliverable, and briefs usually name both explicitly.
Keep them in separate report fields.

- `BASE_PLAN != GUIDED_PLAN` establishes **integration**: content reached the
  artifact. Say exactly that and no more.
- Effectiveness requires a **downstream** difference. If the two arms produce
  identical outcomes, the honest verdict is `NO_MEASURED_EFFECT` — not
  `INSUFFICIENT_SAMPLE` — because you have established something stronger than
  smallness: the mechanism cannot transmit.
- Distinguish the three negative verdicts, because they imply different work:
  | verdict | meaning | what resolves it |
  |---|---|---|
  | `NO_MEASURED_EFFECT` | the mechanism is present but provably cannot reach the consumer | a real architectural change |
  | `INSUFFICIENT_SAMPLE` | mechanism reachability unproven, n too small | more natural observation |
  | `NEGATIVE_SIGNAL` | repeated evidence of harmful/irrelevant work | a fix |
  A structural finding must NOT be filed as a sample-size problem; that sends
  the next session to collect samples that cannot change the answer.

## 4. Check whether the dominant consumer outcome is masking everything

Before measuring, find which branch of the consumer's decision actually fires.

- Persisted records usually carry the deciding rule in a provenance field.
  Aggregate it across the whole history. If one branch accounts for ~100% of
  outcomes, every measurement you take will return that value regardless of the
  component, and the reason is now known before you burn the window.
- **Read the branch ORDER, not just the branch set.** A short-circuit branch
  evaluated above a "positive" branch makes the positive one unreachable for
  every input that trips it. Quantify the trip condition against the real corpus
  (`57/101 correlations`) so the reader sees how much of the space is affected.
- Explicitly separate "the policy is correct here and the component is
  legitimately irrelevant" from "the policy masks the component's value". A
  measurement cannot distinguish them; say that it cannot.

## 5. Refuse the mapping that only works on keywords

When asked whether component text can map onto an existing closed vocabulary,
build the narrowest possible mapping and then measure it honestly.

- Define mapping rules that name ONLY an operation the consumer already
  performs, then run them over the real corpus and report the ratio.
- **A high keyword-overlap ratio is a warning, not a success.** If a requirement
  maps only because it happens to contain a word the consumer already keys on
  ("already-observed response"), that is coincidence, not semantics — mapping
  "compare handshake and per-message authorization" onto a header fetch would
  be a false claim. Report the overlap AND decline to call it integration.
- Print the unmappable items verbatim. Their text is the evidence for the gap:
  a requirement naming a capability the consumer must never acquire is a
  different finding from one that merely needs wiring.

## 6. Make the negative test non-vacuous in both directions

A test asserting "the consumer ignores the component" must fail when that stops
being true, or it certifies nothing.

- **Poison probe:** inject every field the component supplies, including a
  hostile payload (`curl | sh`, `exfiltrate the database`), directly into the
  consumer's input dict, re-plan, and assert byte-identical output. If the
  output ever changes, the architecture moved and the report is stale.
- **Disable-the-bridge probe:** flip the enabling condition off and assert the
  suite goes red with the expected count, then restore the file byte-for-byte
  and re-run green. Without this, a suite can pass because the feature is
  absent.
- When a suite encodes a PREVIOUS milestone's finding, it will go red when you
  change that behaviour. That is the suite working. Invert the assertions to the
  new contract and record the superseded history in the docstring — do not
  delete the old file and do not weaken the new assertions to match.

## 7. Report the honest negatives without manufacturing a positive

- `PRODUCTION_MUTATION: NONE` is a valid and often correct outcome when the
  brief permits a change only if existing architecture supports it. Check each
  of the brief's numbered conditions; if the mapping needs a new gap type or a
  new action-selection input, that is a larger architectural change, so report
  the gap and stop.
- Surface the human decision the measurement forces, in one line: the component
  shapes the artifact and stops there. Whether it *should* reach the consumer is
  a design question for the owner, and it is the actual deliverable of a
  measurement milestone.
- Separate pre-existing cost from cost you added, and measure the added part in
  isolation (per-call mean over many calls). When the milestone added no runtime
  path at all, report the incremental cost as zero rather than quoting a
  component's total.

## 8. Pitfalls that cost the most time here

- **A test fixture using a fake scope is the fixture's bug, not the validator's.**
  `validate_plan` rejecting scope `'h'` is correct; use a real in-scope host from
  the corpus and keep the assertion.
- **A hand-rolled stub of an authority-boundary store is not a test fixture.**
  A class with `__getattr__` returning a canned dict makes the real
  `create_investigation` reject every input, and the suite reports
  "0 compared, 0 differing" — which looks like a clean negative and is actually
  an empty run. Assert a non-zero comparison count BEFORE trusting a ratio.
- **Copy production before using a throwaway fixture.** The M16 authority
  boundary verifies the signal reference EXISTS, so a fixture with real schema
  but no real rows rejects everything as "signal reference does not exist".
  SQLite's `backup()` into the fixture path makes the real path accept real
  signals.
- **A tolerant JSON loader is part of a measurement tool, not a shortcut.** One
  truncated `metadata` blob aborts the whole pass; return `{}` for unparseable
  rows and count them rather than dropping them silently.
- **`sqlite3.Row` has no `.get()`.** Convert to `dict` at the query boundary or
  every `.get()` raises mid-pass.
- **Count occurrences with a plain substring scan before writing the AST pass.**
  The cheap version finds the answer in one call and tells you whether the
  expensive version is worth building.
- **Never read the count as the verdict.** An all-time rule distribution of
  100% is a finding about the CONSUMER's inputs, and the report must say which
  of the two causes it cannot distinguish.
