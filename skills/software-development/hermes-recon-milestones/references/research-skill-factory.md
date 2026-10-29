# Research → Skill Factory hardening reference

Use this reference when converting persisted research into structured operational
Skills without adding a second runtime, network client, or finding authority. It
is a class-level recipe; it is not a substitute for the milestone brief.

## Procedure

1. **Establish the architecture and baseline before editing.** Read the full
   canonical architecture document found on disk, the sprint architecture, and
   the sprint TODO. If a short or pointer file exists at another path, inspect it
   but do not treat it as canonical without checking its size/content. Record
   alignment and conflicts separately; do not silently resolve an architectural
   fork. Hash every protected Day 1 file and record protected DB counts before the
   first write. Keep production inspection read-only.

2. **Inventory the existing Research subsystem.** Enumerate research
   documents/articles, analyses, pattern memory, feedback/proposal tables,
   writers, readers, statuses, row counts, and foreign keys. Find every path
   that writes a Skill. Choose one canonical registry. If a legacy table must
   remain, make it an explicitly documented compatibility/read projection and
   keep its old statuses from acquiring approval semantics. Do not create two
   canonical registries with different truth rules.

3. **Use vertical TDD slices.** For each behavior, write one focused failing
   test and run it to see the expected failure, implement the smallest change,
   then run the focused test and the cumulative suite. Add a hostile or malformed
   case for every boundary; a clean-input test alone does not prove a detector.
   A test that cannot fail is not verification. Keep test fixtures inert and use
   a frozen database copy for persistence checks.

4. **Define the candidate contract and validation split.** Require identity,
   hypothesis, trigger, investigation strategy, and at least one source
   reference. Make technology hints, related CVEs/writeups, target class,
   pattern links, negative indicators, and advanced metadata optional. Missing
   safe evidence or incomplete quality must produce a `REVIEW_REQUIRED` result,
   not a silent reject; unsafe confirmation, exploit, credential, scope, or
   direct-action content must be rejected. Return separate fatal and review
   reasons so callers cannot confuse unsafe data with incomplete knowledge.
   Parse structured output only; never persist raw LLM prose as a Skill.

5. **Separate identity from presentation and metadata.** The canonical key
   should cover vulnerability family, normalized trigger conditions, the core
   investigation strategy, and the relevant target/technology class. Treat title
   as presentation metadata: a title-only change must neither create a duplicate
   nor overwrite the first title. Metadata enrichment may update the same
   Skill; a meaningful change to instruction-bearing content creates an
   append-only version (or a new Skill only when the identity rules genuinely
   say so). Never delete old versions or rewrite history.

6. **Make concurrent writers CAS-safe.** A `SELECT` before the write lock is
   not a compare-and-swap. Start the write transaction, re-read the current row
   inside it, update with the expected version/state predicate, and check the
   affected-row count; retry from the fresh row if a competing writer won. Keep
   the uniqueness constraint on `(skill_id, skill_version)` and prove the race
   with at least five writers. Separately submit the same candidate 20 times
   and assert one Skill identity, no duplicate versions, monotonic version
   numbers, and intact lineage.

7. **Compute confidence from observed evidence.** Use source quality, source
   count, cross-source agreement, actual pattern recurrence, and evidence
   completeness. Do not use a hardcoded recurrence or completeness value merely
   to make a score look nonzero. If inputs are unavailable, use a bounded
   low/unknown result and record the reason. Label confidence as research
   confidence, never vulnerability severity, exploitability, or final finding
   confidence. Test determinism for identical inputs and sensitivity for
   changed evidence.

8. **Use a real Research consumer.** Adapt existing persisted article/analysis
   records in a bounded function, then invoke it from the existing Research
   pipeline or a real consumer seam. Do not add a second scheduler, worker
   pool, queue, fetcher, or LLM dependency. The consumer path must demonstrate
   extraction → validation → dedup → persistence, not only call the storage
   helper in isolation. Persist run-level counters from the transaction or from
   the database; invocation-local counters alone are not durable metrics.

9. **Preserve lineage through deletion of the source row.** Store source type,
   immutable source identifier, and a locator. A source URL is lineage metadata,
   not an instruction to fetch it. If the original row or URL is unavailable,
   retain the stored identifier and mark the limitation; never invent a URL,
   CVE, writeup, or agreement. Reject duplicate source references while keeping
   meaningful version lineage append-only.

10. **Remove legacy auto-activation.** Search all Skill-producing writers, not
    just the newest registry. Automated Research paths terminate at
    `REVIEW_REQUIRED`; no legacy `ACTIVE` or equivalent means approved. Update
    readers/filters with the canonical lifecycle and test that rejected or
    disabled records are not resurrected while review/approved records remain
    readable. Human approval is a separate explicit transition and must not be
    added to an automated factory as a convenience.

11. **Keep the safety boundary structural.** The factory should not import or
    call network, process, shell, port-scanning, or exploitation primitives;
    should not write findings or change scope; and should not create a target
    request from Skill prose. Use AST/call-shape checks or behavioral hostile
    tests rather than raw substring scans that match the factory's own safety
    comments. Reject actionable URLs in candidate prose while retaining URLs or
    identifiers only in lineage fields. Redact credential-shaped values and
    preserve the fact of redaction.

12. **Run offline E2E from real persisted inputs.** Use SQLite's backup API or
    another complete frozen copy, never the live database. Inspect validation
    statuses and record why records qualify or do not qualify; do not fabricate
    research when the corpus is sparse. Prefer a real CVE/analysis/pattern
    record when it contains enough structured evidence, and state a real
    limitation when it does not. After the final code freeze, execute the real
    consumer, reload with a fresh connection, and verify the Skill, version,
    source references, status, and lineage together.

13. **Certify before closing.** Run the required Day 1 core, safety, artifact,
    and protected M14/M16/M17/M18/M24 checks. Run the full regression only after
    the focused blockers are green; preserve a prior baseline and classify every
    failure as `NEW_REGRESSION`, `PRE_EXISTING`, `ENVIRONMENTAL`, `STALE_TEST`,
    `BASELINE_ARTIFACT_MISSING`, or `UNKNOWN` from evidence. Check production
    `quick_check`, `integrity_check`, `foreign_key_check`, schema presence,
    protected row deltas, and unexpected Skill rows before and after. A focused
    green suite is not a completed milestone. If any required gate, offline
    reload, lineage check, or full regression is unfinished, the final result is
    `INCOMPLETE`, with an exact resume list; never write a PASS report early.

## Common failure patterns

- Treating title or a clock value as semantic identity creates duplicate Skills
  or overwrites the first record.
- Computing identity before the transaction lets two writers mint the same next
  version; the uniqueness constraint catches the symptom only after a lost
  update.
- Defaulting optional lists to an empty value and then treating empty as fatal
  turns metadata gaps into silent rejection.
- Scoring confidence with `recurrence=1` or a guessed agreement value creates
  a fabricated signal and makes weak evidence look authoritative.
- Importing the Research module for an audit can run schema initialization; use
  a throwaway DB or read the source before execution.
- A legacy `ACTIVE` writer can survive a new canonical registry and bypass the
  no-auto-approval rule through the old consumer.
- A green API test, synthetic fixture, or partial regression is not evidence of
  a real Research consumer or a completed production-safe milestone.
- A report written before the last verification run carries stale green counts;
  block final status on the machine's completion marker and current artifact.

## Stale background notifications are re-checks, not interruptions

A delayed notification replays the output of an EARLIER run. It can contradict a
result you already published, and the contradiction is not evidence that the later
work was undone.

- Match the notification against the current state before reacting: the suite
  name, the assertion text, and the count should all correspond to code that
  still exists. A failure naming an assertion you have since REPLACED is stale by
  construction.
- Re-run the specific suite in the foreground to confirm, then say in one line
  that it is stale and what the current value is. Do not re-open a closed
  milestone, and do not rewrite a correct report because an old log replayed.
- This also applies in reverse: a notification can be the ONLY evidence that an
  experiment you believed you ran actually executed. When one arrives, re-run the
  cheap check before drawing a conclusion from it.
- Batch command output through a file and grep it, not through a pipe that hides
  the exit status — `cmd | tail` reports the status of `tail`.
- A suite whose run is launched inside an `execute_code` cell cannot be
  backgrounded: that helper has no `background` kwarg. Split the launch and the
  control into separate calls, or use a bounded foreground command.

For the Skill Registry review/approval workflow (context-vs-execution retrieval
split, the human-approval boundary, provenance verification) see the
`hermes-skill-governance` skill.
