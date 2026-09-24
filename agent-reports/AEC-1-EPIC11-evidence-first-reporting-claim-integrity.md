# AEC-1 — EPIC11: Evidence-First Reporting & Claim Integrity v1

**Commit:** `e05df35` — includes the runtime gate-row fix
(`backend/research_agents/runtime.py`), the SOC fixture fix
(`tests/test_research_intelligence_soc.py`) and this report
**Branch:** `agent/daily-development`
**Integration base:** `59b4b019` (main); production `6ec6146`, 27 dirty entries (unchanged)
**Status:** EPIC11 promoted to `main` (`817b14c`) on operator APPROVE; this
revision adds the post-promotion defect fix described in §20 (a separate
promotion request covers it)

---

## 1. Implementation summary

A first-class, deterministic claim/evidence integrity layer now sits between
observation and every human-facing artifact. New package:
`backend/research_agents/finding/integrity/`

| module | responsibility |
|---|---|
| `taxonomy.py` | closed evidence vocabulary, normalisation of raw rows, duplicate collapsing, negative evidence (NOT_TESTED vs NOT_OBSERVED), malformed rows that satisfy nothing and never raise |
| `contracts.py` | per-class verification contracts, the XSS stage ladder, `AuthorizationContext`, the closed gate-reason vocabulary |
| `claims.py` | structured claims; `SUPPORTED` only from persisted, non-duplicate evidence of the required types |
| `gate.py` | the Evidence Gate — the only authority on "confirmed vulnerability"; fail-closed |
| `report.py` | evidence-first report contract + the deterministic report validation gate + contradiction detection |
| `projection.py` | re-assessment of persisted records; history is never rewritten |

Wiring/hardening: `finding/models.py` (new `VERIFICATION_PENDING` state +
claim-integrity fields), `finding/store.py` (fail-closed transitions),
`finding/executor.py` (real persisted evidence fed to the gate; case lifecycle
gated on contract + report validation), `capabilities.py`
(`EvidenceRequirements.signal_evidence_any_of`), `runtime.py` (contract
evaluation at case creation + persisted `evidence_gate`/`claim_integrity`
block), `hunt/executor.py` (interim gate rows carry taxonomy fields),
`backend/soc/{findings,candidate_workspace}.py` + `web/templates/soc/finding_detail.html`
(analyst-facing claim/evidence panel).

## 2. Root cause of the previous integrity gap

Three independent defects let an unverified XSS candidate present as verified:

1. **Evidence was counted, not classified.** The runtime gate required
   `min_evidence_refs` + storage `type` + a "high" confidence label. 40
   `xss_parameter_inventory` events across two runs satisfied all three, so
   parameter *inventory* was indistinguishable from verification evidence.
2. **The gate's evidence rows lost their signal.** Both
   `runtime.py::evaluate_case_creation`'s caller and
   `hunt/executor.py::_gate_evidence_rows` passed rows carrying only
   `{id,type,observation_ref,job_id}` — no `signal`. Nothing downstream could
   tell inventory from reflection even in principle.
3. **State transitions were advisory-tolerant.** `VERIFIED` could be persisted
   from a gate record plus any supporting row, with no claim contract and no
   report validation; `READY_FOR_REVIEW` had no integrity precondition at all,
   and the LLM advisory's own `VERIFICATION_PENDING` text was never reconciled
   with the authoritative state.

## 3. Claim / evidence model

Each substantive claim is a record:
`claim_id, claim_type, statement, required_evidence_types,
supporting_evidence_ids, unsupported_reason, status, provenance`.
`status ∈ {SUPPORTED, UNSUPPORTED, CONTRADICTED, NOT_TESTED}`; a claim is
`SUPPORTED` only when non-duplicate persisted evidence of the required types
exists in the authorized scope. `ClaimEvaluation` also carries
`missing_evidence_types`, `missing_evidence` (reason codes),
`malformed_evidence`, `contradictions`, `negative_evidence`, the
claim/evidence matrix and `advisory_only_fields_used: []`.

## 4. XSS verification contract (stage ladder)

| stage | evidence | outcome |
|---|---|---|
| 1 | PARAMETER/URL observed | candidate only |
| 2 | CONTROLLED_INPUT_SENT | unverified |
| 3 | REFLECTION / OUTPUT_CONTEXT / DOM_SINK | potential, further verification required |
| 4 | PAYLOAD_EXECUTION / EXPLOITABILITY (authorized) | eligible for VERIFIED |
| 5 | IMPACT | impact claim supportable |

Confirmation additionally requires authorization lineage. Execution is never
required blindly: stages are declared per class, and a class that cannot
establish stage 3 stays `VERIFICATION_PENDING` rather than being inferred.

## 5. Evidence Gate changes

`missing_reflection_evidence`, `missing_controlled_verification`,
`missing_output_context_evidence`, `missing_dom_sink_evidence`,
`missing_payload_execution_evidence`, `missing_exploitability_evidence`,
`missing_impact_evidence`, `missing_url_observation`,
`missing_parameter_observation`, `missing_authorization_confirmation`,
`no_evidence`, `unclassified_evidence_only`, `duplicate_evidence_only`,
`insufficient_evidence`, `claim_supported` — persisted with the decision and
rendered downstream. Mapping: contract satisfied → `VERIFIED`; contradictions →
`REJECTED`; only authorization missing → `BLOCKED`; otherwise
`VERIFICATION_PENDING`. `xss_parameter_inventory` alone can never reach
`VERIFIED`. Store transitions fail closed on both `evidence_rules_met` and a
SUPPORTED claim-integrity payload (`READY_FOR_REVIEW` additionally needs a
passed report validation).

## 6. Report validation gate

`validate_report()` runs 13 deterministic checks: claim support, confirmation
support, evidence references exist, evidence within authorized scope, no
unsupported claim marked confirmed, state matches the gate, severity matches
authoritative rules, impact claims supported, authorization lineage, historical
advisory not authoritative, limitations preserved, contradictions, well-formed
claims. Any failure → `BLOCKED` with named blockers. A non-VERIFIED finding can
never produce `READY_FOR_REVIEW` (`report_ready_without_verified_state`).

## 7. Contradiction detection

Persisted and reported: `evidence_contradicts_claim`,
`claim_marked_supported_without_evidence`, `executive_conclusion_mismatch`,
`state_mismatch`, `severity_contradicts_evidence`,
`historical_advisory_conflicts_with_current_state`. The louder side is never
chosen; the advisory/latest-text conflict is recorded as non-blocking *and*
shown with provenance, never as authority.

## 8. LLM boundary

Advisory-only, enforced structurally: neither `gate.decide`,
`gate.evaluate_integrity` nor `validate_report` accepts advisor/model/confidence
input (pinned by `test_gate_accepts_no_advisory_input_at_all`). Advisory text is
preserved verbatim and labelled "Historical / Advisory Only" with its recorded
state and timestamp. The real advisory for `cand-7c229c48c455` said
`VERIFICATION_PENDING`; that is now the authoritative outcome too.

## 9. Regression case — `cand-7c229c48c455`

`tests/test_epic11_regression_cand_7c229c48c455.py` (6 tests): the real shape
(40 events, one signal, 20 unique observations re-recorded by
`job-xss-49b9d40fd5` / `job-xss-ffe3afca68`) is reproduced faithfully and proven
**not** to produce VERIFIED XSS; duplicates cannot manufacture support;
projection corrects the persisted claim without rewriting it (history
preserved); a read-only assertion re-runs against the live store when present.

## 10. Adversarial test results (A–P)

`tests/test_epic11_adversarial.py` — 23 tests, all green: A parameter-only;
B +controlled input; C reflection without dangerous context; D reflection +
context, no execution; E authorized execution (the only READY path);
F advisory claims execution; G advisory claims VERIFIED vs gate pending;
H severity HIGH without authoritative rule; I impact claimed without evidence;
J contradictory historical/current states; K duplicate evidence; L evidence from
an unauthorized job / missing authorization; M dangling evidence reference;
N malformed rows and malformed claims; O empty evidence set; P advisory-only
report. Two defects were found by these tests and fixed: malformed rows could
raise into the gate, and evaluation-level contradictions were not blocking.

## 11. Report-integrity battery (§18)

`tests/test_epic11_report_integrity.py` — 13 tests. Across the nine-scenario
matrix, **exactly one** scenario reaches `READY_FOR_REVIEW` (full execution
evidence with authorization) and it has `unsupported_claims == 0`, all checks
true and a SUPPORTED confirmation; every other scenario is BLOCKED with the
exact failed gate, the exact missing evidence types and the exact contradiction.
End-to-end persisted-package tests assert the stored case package obeys the same
contract.

`tests/test_epic11_soc_integrity.py` — 11 tests: pending candidates show exactly
what is missing, verified ones show their evidence basis, contradicted claims are
labelled, a legacy record implies no verdict, malformed payloads never crash.

## 12. Real production validation (§19)

Read-only, against the real persisted state (`/opt/watch/ai_data/research/agent/runtime/`):

- evidence for the regression jobs: **40 rows, all `xss_parameter_inventory`,
  20 unique observations, 20 duplicates**;
- hardened gate verdict: `VERIFICATION_PENDING` / `INCONCLUSIVE` /
  `missing_reflection_evidence` / stage 1 (parameter observed) /
  confirmation `UNSUPPORTED` / `claim_integrity_supported=False`;
- missing evidence types: `DOM_SINK_IDENTIFIED`,
  `EXPLOITABILITY_ESTABLISHED`, `OUTPUT_CONTEXT_IDENTIFIED`,
  `PAYLOAD_EXECUTION`, `REFLECTION_OBSERVED`;
- **unsupported claims reaching a confirmed state: 0**;
- the persisted record (pre-EPIC11, `lifecycle_state=DETECTED`, no
  `claim_integrity`) is reported as "no claim/evidence contract recorded" — no
  verdict is implied by its absence, and nothing was rewritten.

This is the required real case where the hardened gate refuses an unsupported
XSS claim. No execution was manufactured and no finding was promoted.

## 13. AI Ops compatibility

No new scheduler, daemon, service or window. `backend/ai_ops/*` and the systemd
units are untouched (verified by path inspection; the AEC read-only manifest
still reports READ-ONLY VERIFIED). The `Asia/Tehran` window, bounded dispatcher,
leases, recovery and audit model are unchanged; `tests.test_ai_ops_security`,
`tests.test_epic10_operations` and the delivery/policy suites pass (95 tests OK).

## 14. SOC / UI changes

`web/templates/soc/finding_detail.html` gains a **Claim / Evidence Integrity**
panel fed by the workspace read-model: authoritative state + explicit gate
reason, the claim/evidence matrix (SUPPORTED / MISSING / CONTRADICTED with the
supporting evidence ids), the evidence basis of a confirmed finding, the exact
missing evidence types for a pending/blocked one, the report-validation status
and blockers, and the historical advisory kept in its own labelled block.
Observed / Candidate / Verification Pending / Verified / Blocked / Ready for
Review remain distinct; `VERIFIED` is never used as a decorative badge.

## 15. Full regression

- worktree: `Ran 10953 tests … FAILED (failures=244, errors=130, skipped=17)`
- baseline at `HEAD` (`59b4b01`, extracted with `git archive`):
  `Ran 10481 tests … FAILED (failures=252, errors=123, skipped=17)`
- failing entries: **374 (worktree) vs 375 (HEAD baseline)** — no EPIC11 test
  among them; the difference is the same environmental set.
- EPIC11-adjacent modules verified individually green or baseline-identical:
  `test_finding_core`, `test_finding_verification_safety`,
  `test_hunt_planner_safety`, `test_hunt_queue`, `test_research_intelligence_ui`,
  `test_soc_ui_routes` (`backend/soc/campaigns.py`, untouched, fails at HEAD too).
- The one remaining failure in the affected batch is
  `test_finding_verification_safety::test_unknown_model_and_paid_model_are_rejected`
  → `env_model_not_free:nvidia/nemotron-3-ultra-550b-a55b:free`, identical at
  HEAD: an environmental free-model-vocabulary drift, not an implementation
  regression.
- Two real regressions I introduced while wiring were found and fixed rather
  than waived: the finding-gate decision assertion in `test_finding_core`, and
  the case-producing fixture in `test_research_intelligence_soc` (which exposed
  the missing `signal` on the runtime gate rows).

Post-fix affected + EPIC11 batch: **707 tests, 1 pre-existing environmental
error**. New EPIC11 tests: **85, all green** (85 = 32 + 23 + 13 + 6 + 11).

## 16. Security checks

- AEC read-only boundary: `READ-ONLY VERIFIED` (116 pinned files, 0 drift).
- `diff_guard.py`: PASS, 0 findings (no forbidden path/secret/env/system file).
- Credential-shaped scan of every added line: 0 hits; no credential, token or
  API key enters a report, package or generated link.
- Authorization boundaries, scope restrictions, existing fail-closed behaviour,
  secret scanning and auditability all preserved; no guard was weakened.

## 17. Files changed (29)

New (12): `backend/research_agents/finding/integrity/{__init__,taxonomy,contracts,claims,gate,report,projection}.py`;
`tests/test_epic11_{claim_integrity,adversarial,report_integrity,regression_cand_7c229c48c455,soc_integrity}.py`.
Modified (17): `backend/research_agents/{capabilities,runtime}.py`,
`backend/research_agents/finding/{executor,gate,models,store}.py`,
`backend/research_agents/hunt/executor.py`,
`backend/soc/{candidate_workspace,findings}.py`,
`tests/{finding_fixtures,hunt_fixtures,prod_intel_fixtures}.py`,
`tests/test_{finding_core,hunt_planner_core,hunt_planner_failure,research_intelligence_core,research_intelligence_soc}.py`,
`web/templates/soc/finding_detail.html`.

Unrelated in-flight work (EPIC10: `backend/ai_ops/*`,
`backend/research_agents/runtime_store.py`, `api.py`, `command_center*`, …) is
**not** staged: 185 unrelated dirty entries preserved.

## 18. Commit / push / promotion

- Commit: `e05df35 epic11: evidence-first reporting & claim integrity v1`
  (amended with the runtime gate-row fix, the SOC fixture fix and this report).
- Delivery: `report.sh` written and `check.sh` = **READY FOR PROMOTION**
  (BRANCH/COMMIT/TESTS/PATH_GUARD/REPORT/PRODUCTION_UNTOUCHED all PASS);
  `diff_guard.py` PASS, 0 findings.
- Push: `git/push_safe.sh origin agent/daily-development` (fail-closed on
  `check_auth.py`).
- Promotion: `promotion/request.sh` artifact + operator APPROVE, then
  `promotion/promote.sh --yes`. **Never merged here.**

## 20. Post-promotion verification, and the defect it found

Promotion completed as `817b14c` (audit seq 82) after `approve.sh --confirm
APPROVE`; `watch-api.service` was restarted and the promoted code confirmed in
the production tree (`gate rule epic11-integrity-gate-1`, 13 report checks, 36
taxonomy types). Verifying the REAL record through the production read-model
then exposed a presentation defect that the fixture tests had missed:

- `findings._integrity_block` synthesizes a block for every record, so a
  **legacy** record (no `claim_integrity` row) reached the analyst view with
  `recorded: False` but `authoritative_state: VERIFIED` and
  **`confirmed: True`** — the historical pre-contract state presented under the
  Claim / Evidence Integrity heading as if the contract had produced it, with a
  source line claiming "persisted claim-integrity record".
- The existing tests only covered an *absent* `integrity` key, never the
  synthesized-block path that production actually takes.

Fix (fail-closed, §7/§21): without a recorded contract there is **no**
authoritative state — `authoritative_state = not_recorded`, `confirmed` can only
be true for a recorded contract, the historical candidate/verification/case
states are published separately as `persisted_state` and labelled "recorded
before the contract; not an integrity verdict", and the current assessment is
re-derived from the persisted evidence via `projection.project`. The read-model
treats a block as a contract only when the explicit `recorded` flag is true or
real contract content is present (a bare state label or `confirmed` flag is not
a contract).

Verified on the real production record (`cand-7c229c48c455`, fixed code + real
store): block `recorded=False / not_recorded / confirmed=False`,
`persisted_state = VERIFIED / VERIFIED / READY_FOR_REVIEW` preserved and
labelled, `projected = VERIFICATION_PENDING / missing_reflection_evidence /
stage 1` with `DOM_SINK_IDENTIFIED, EXPLOITABILITY_ESTABLISHED,
OUTPUT_CONTEXT_IDENTIFIED, PAYLOAD_EXECUTION, REFLECTION_OBSERVED` still
missing, and the rendered panel shows **no VERIFIED badge**, states the
historical rows are not a verdict, and no longer claims a stored contract.
5 new tests (`TestLegacyRecordCannotShowAnIntegrityBadge`) pin this shape.

## 19. Mandatory final gate

| question | answer |
|---|---|
| Can parameter inventory alone create VERIFIED XSS? | **NO** |
| Can LLM confidence create VERIFIED XSS? | **NO** |
| Can historical advisory text create VERIFIED XSS? | **NO** |
| Can unsupported impact reach READY_FOR_REVIEW? | **NO** |
| Can unsupported severity reach READY_FOR_REVIEW? | **NO** |
| Can a report contain a confirmed claim without supporting evidence? | **NO** |

WAITING FOR EVIDENCE is no longer a failure state, and `VERIFICATION_PENDING`
is a valid success: a smaller number of defensible findings is the point.

VERIFIED FINDINGS: 1 (test-scope only — the synthetic fully-evidenced
scenario in the report-integrity battery; the real production candidate below
remains unverified)

BLOCKED / PENDING FINDINGS: 1 real (`cand-7c229c48c455` →
`VERIFICATION_PENDING` / `missing_reflection_evidence`)

UNSUPPORTED CLAIMS REACHING READY_FOR_REVIEW: **0**

READY TO PUSH: **YES**
