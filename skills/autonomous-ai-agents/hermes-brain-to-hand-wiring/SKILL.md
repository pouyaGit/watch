---
name: hermes-brain-to-hand-wiring
category: autonomous-ai-agents
description: Wire a Hermes reasoning stage into the probe path.
---
# Wiring a Hermes reasoning stage into the downstream path

How to make a local reasoning module's output actually reach the consumer that acts
on it, in this repo (`/root/hermes-recon`), without widening any authority.

## Triggers
- A spec says an LLM/assessment stage's output "is ignored" by a downstream probe,
  verifier, or validator.
- Adding an emit/bridge from one module to `lib/poc_verifier.py`,
  `lib/validator_agent.py`, or the `/findings` path.

## The seam, before you write code

Read the CONSUMER's reader, not the producer's schema. `poc_verifier.hunter_output(c,
case_id)` returns None unless BOTH exist:
1. a `case_events` row with `object_type='hypothesis'` for that case, and
2. a `day5_evidence_outcomes` row for that case (it reads `outcome` + `expert_family`).

Then read the consumer's decision function. `final_verdict()` only returns `VERIFIED`
when `verdict_class == 'SUPPORTS'` AND `agreement == 'AGREES'`, and `agreement()` maps
the hunter outcome through `HUNTER_CLASS` (`EVIDENCE_SUPPORTS -> SUPPORTS`,
`EVIDENCE_INCONCLUSIVE -> INCONCLUSIVE`). So the mapping you choose decides whether a
case can be auto-promoted at all.

## Emit only through the sanctioned APIs

- Hypothesis: `investigation.attach_hypothesis(store_mod, case_id, ref_id,
  "HYPOTHESIS", text=...)`. Valid classes come from `HYPOTHESIS_CLASSES`; `OBSERVED`
  additionally requires `evidence_ref`.
- Outcome: `day5_experience.record_outcome(c, candidate_id, hypothesis_id, outcome,
  expert_family=..., case_id=..., reason=..., provenance=..., source=...)`.
- `record_outcome` refuses: an outcome outside `EVIDENCE_OUTCOMES`, an
  `expert_family` outside `expert_hunters.FAMILIES`, any empty
  candidate/hypothesis/reason/provenance, and any text its `_FORBIDDEN` regex matches
  (`https?://`, `curl`, `bash`, `exploit`, `payload`, `bypass`, `executor`, ...). Guard
  the family yourself and COUNT its refusal separately from a module error.
- `attach_hypothesis` is fenced by `investigation_leases`; with no active lease it is
  an administrative call and succeeds (that is how day6 calls it).
- Both are idempotent on content: `attach_hypothesis` returns
  `lineage_id` starting `ce-existing:` on a duplicate, and `record_outcome` uses
  `INSERT OR IGNORE` on a digest of (candidate, hypothesis, outcome, family, skill,
  evidence). Use the `ce-existing:` signal to count a dedupe instead of a new emit.

## Choose the mapping so NO_VULN emits nothing

Emit only for the assessments that make a case probe-eligible. `SUSPECTED_VULN ->
EVIDENCE_SUPPORTS` (a reproducing probe can reach VERIFIED); `NEED_PROBE ->
EVIDENCE_INCONCLUSIVE` (the probe runs but lands NEEDS_HUMAN, never auto-promoted);
`NO_VULN -> nothing`. That gate is the whole safety story: it is what stops the
brain from manufacturing findings.

## Robustness the emit needs

- Wrap the whole emit in try/except and never let it break the producer's loop.
- Persist the producer's own row BEFORE emitting, so a consumer can always read the
  assessment that caused the record.
- Scope-check the host (`scope_guard.check`) and emit nothing off-scope: the probe
  populations are scope-filtered anyway, so an off-scope record is dead weight.
- Counters: `emitted` (new), `emit_dedup`, `emit_refused` (a documented API refusal),
  `emit_skipped` (no-op by design), `emit_errors` (real fault) + a one-line
  `emit_error` reason. Log them in the cycle executor line; without that the wiring is
  invisible in production.

## Verifying it (this is where the milestone is won or lost)

1. `python3 -m py_compile` both files.
2. Snapshot production with SQLite's OWN backup API (`src.backup(dst)`), never `cp`:
   a live WAL DB's main file alone fails `integrity_check`. Set `HERMES_DB` to the
   copy BEFORE the first import so `store.DB` can only be the copy. 1 GB copy takes
   ~3s.
3. The producer's run may assess only a handful of cases per call and can return
   `assessed=0` when the newest eligible cases resolve to no family — do a read-only
   census of eligible-order depth first and pick the limit that actually contains
   emitting cases (measured: 8/20 had a family, hits started at depth 16).
4. Assert the CONSUMER's own reader (`poc_verifier.hunter_output(c, case_id)`) returns
   a non-None dict with a non-empty family, not just that rows exist.
5. Idempotence: the producer's second run usually consumes NEW cases and therefore
   proves nothing about dedupe. Assert it by re-calling the emit DIRECTLY on an
   already-emitted case and requiring the row counts to be unchanged.
6. Non-vacuity: revert only the mapping line (`EO_SUPPORTS if assessment ==
   "SUSPECTED_VULN"` -> `EO_INCONCLUSIVE`), re-run, require the checks that assert
   VERIFIED to go red, then restore and verify the file sha256 is byte-identical.
7. A branch the live sample did not exercise (e.g. no `SUSPECTED_VULN` appeared) is
   proven by a driven fixture on a fresh DB and reported as such — never implied.

## Pitfalls

- `hunt_cases.host` can be EMPTY or a product name ("industrial edge management
  hub", "dd-wrt"); fall back to `target` and treat that population as unsurveyable
  rather than emitting.
- Roughly a quarter of eligible cases resolve to NO family via `recon_dispatch`, so
  they are skipped before the emit and `assessed < eligible`. Report the ratio.
- The daemon is restarted by ci_gate only after a green gate; until then production
  serves the OLD module. Prove the new code is live by the `console_lines` job
  timestamp, the job row (`started_at`/`finished_at`), and above all NEW rows whose
  `source`/provenance the old code could not have written — then check in the same
  pass that the specific `hyp-<hash>` id the new code computes is present.
- `scripts/cycle.py` executor messages are logged only on failure or with
  `HERMES_DEBUG=1`, so a new `emitted=` field in the message is NOT in the log by
  default. Do not claim you saw it.

## Commit/deploy shape

`ci_gate` classifies any `lib/` path HIGH_RISK, runs ~9 suites, then restarts
`hermes-recon.service`. The post-commit hook runs the whole gate, so it can take
several minutes; run the commit in the background and poll `logs/ci_gate.log` for
`DEPLOYED:` vs `BLOCKED:` vs a `Revert` commit. A doc path (`.md`) is classified DOCS
and never triggers the high-risk suite set on its own.
