# R56 Human-in-the-Loop Intelligence

## Summary

R56 introduces the explicit human decision boundary between automated
research intelligence and any future controlled execution or reporting:

```
R39–R50 Specialist Research
        ↓
R52 Orchestrator
        ↓
R53 Finding
        ↓
R54 Correlation
        ↓
R55 Prioritization
        ↓
R56 Human Decision Boundary      ← this stage
        ↓
future R57 Continuous Learning
        ↓
future R58 Controlled Execution
```

Core principle: **AI recommends. Human decides.** R56 records explicit
research-workflow decisions on structured findings (approve research,
request more evidence, defer, reject, escalate, needs review) with closed
vocabularies, enforced HUMAN authority, deterministic ids, an audit
representation and full provenance. R56 never executes the selected action,
never confirms a vulnerability, never authorizes exploitation or execution
and never modifies the R53/R54/R55 artifacts.

## Architecture

New modules (pure, offline, deterministic):

| File | Rule version | Role |
|---|---|---|
| `ai/schemas/human_decision.py` | `r56-1` | Decision plan, authority vocabularies, rationale/evidence/escalation/options/audit projections |
| `ai/schemas/human_review.py` | `r56-2` | Review plan, audit entry and review batch contracts |
| `ai/schemas/human_decision_result.py` | `r56-3` | Review result container, statuses, skips, errors, rejection reasons, summary/provenance/governance |
| `ai/knowledge/human_decision_rules.py` | `r56-4` | Ids, fail-closed validation, decision/review construction, transitions, audit and limitations |
| `ai/knowledge/human_review.py` | `r56-5` | Builder/public API: input validation, review assembly, ranking-preserving order, batches |

Public API:

- `create_human_review(prioritization_result, correlation_result=None, decisions=None)`
- `review_finding(finding_id, prioritization_result, correlation_result=None, decision=None)`
- `record_human_decision(finding_id, prioritization_result, correlation_result=None, decision=None, previous_review=None)`
- `create_review_batch(prioritization_result, correlation_result=None, decisions=None, review_order=None)`
- `export_human_review(**kwargs)` — alias

Reuse (never duplicate): R55 priority plans/governance/provenance shapes,
R54 relationship vocabulary and correlation result identity, R53 finding
states/confidence/severity/impact vocabularies and the R53 governance
reference sanitizer, R37 audit states (`VALID`/`INVALID`/`UNKNOWN`), R44/R55
reason strings where they already exist (`EVIDENCE_INCOMPLETE`,
`CONFLICT_PRESENT`, `PROVENANCE_INCOMPLETE`, `GOVERNANCE_UNKNOWN`).

## Human Decision Contract

`HumanDecisionPlan` (`extra="forbid"`) records:

- `decision_id` (`hdc-<16 hex>`, content-derived), `finding_id`
- `decision_type`, `decision_state`
- `decision_source = HUMAN`, `decision_authority = HUMAN`,
  `ai_role = ADVISORY`, `human_authority = True` (all forced/rejected)
- `execution_authorized = False`, `vulnerability_confirmed = False`,
  `exploit_authorized = False`, `confirmation_state = NOT_CONFIRMED`
  (all forced)
- `priority_reference` — immutable R55 recommendation copy
  (`prioritization_id`, `priority_rule_version`, `priority_score`,
  `priority_band`, `ranking_position`, `priority_reasons`)
- `correlation_reference` — `correlation_id`, `correlation_rule_version`,
  `conflict_state`, `conflict_sources`, `relationship_types`,
  `duplicate_present`
- `finding_reference` — `source_kind`, `finding_rule_version`, `category`,
  `agent_id`, `orchestration_id`, `state`, `confidence`,
  `evidence_completeness`, `severity`, `severity_source`, `impact_state`
- `rationale`, `evidence_request`, `escalation`
- `decision_options`, `audit`
- `provenance`, `governance`, `limitations`
- `research_only = True`, `deterministic = True`

## Decision Vocabulary

Closed decision types:

`APPROVE_RESEARCH`, `REQUEST_MORE_EVIDENCE`, `DEFER`, `REJECT`,
`ESCALATE`, `NEEDS_REVIEW`.

These are human decisions about research workflow. They are never
vulnerability confirmation, exploit authorization, execution authorization,
payload authorization or attack authorization — enforced structurally by
forced flags, rejection of malicious keys and the audit `not_authorized`
list (`EXECUTION_NOT_AUTHORIZED`,
`VULNERABILITY_CONFIRMATION_NOT_AUTHORIZED`,
`EXPLOIT_AUTHORIZATION_NOT_AUTHORIZED`, `PAYLOAD_AUTHORIZATION_NOT_AUTHORIZED`,
`ATTACK_PLANNING_NOT_AUTHORIZED`, `AUTOMATED_DECISION_NOT_AUTHORIZED`).

## Authority Boundary

- `decision_source` / `decision_authority` are closed to `HUMAN`; values
  such as `AI`, `AUTOMATED`, `PRIMARY` or `AUTHORITY` are rejected with
  `AUTOMATED_AUTHORITY_REJECTED`.
- `execution_authorized` / `execute` / `execution_allowed` /
  `execution_authorization` truthy → `EXECUTION_AUTHORIZATION_REJECTED`.
- `vulnerability_confirmed` / `confirmed` / `is_vulnerable` /
  `confirmation_state != NOT_CONFIRMED` →
  `VULNERABILITY_CONFIRMATION_REJECTED`.
- `exploit_authorized` / `exploit_authorization` /
  `exploitation_authorized` / `payload_authorized` /
  `payload_authorization` truthy → `EXPLOIT_AUTHORIZATION_REJECTED`.
- Rejected requests are preserved as `invalid_decisions` entries
  (`decision_state = INVALID`) with the rejection reason; they are never
  repaired, applied or deleted.
- Result/review/decision/audit all force `decision_authority = HUMAN`,
  `ai_role = ADVISORY`, `execution_authorized = False`,
  `vulnerability_confirmed = False`, `confirmation_state = NOT_CONFIRMED`.

## Recommendation vs Decision

R55 priority is an automated recommendation and is carried read-only:

- `priority_immutable = True` and `recommendation_preserved = True` on every
  review and batch (schema-enforced), and the batch carries a
  `ranked_snapshot` of the R55 bands/scores/positions.
- A human decision changes workflow direction only. Example verified by
  tests: R55 `CRITICAL` band + human `REQUEST_MORE_EVIDENCE` — the review
  keeps `priority_band = CRITICAL` and records the different decision.
- R55 is never mutated (byte-identical snapshot tests), and the decision
  never rewrites `priority_score`, `priority_band` or `ranking_position`.

## Decision States

Closed states: `PENDING_HUMAN_REVIEW`, `DECIDED`, `EXPIRED`, `INVALID`.

- `PENDING_HUMAN_REVIEW`: review created without a decision.
- `DECIDED`: a validated human decision is recorded.
- `EXPIRED`: the caller explicitly marks the review expired
  (`decision_state = EXPIRED`); no timestamps are used.
- `INVALID`: rejected decision attempts only (never a review state).

A decision is explicitly distinguishable from a recommendation: reviews
carry both the R55 `priority_reference` (recommendation) and the separately
keyed `decision`.

## Decision Rationale

- Closed rationale codes: `EVIDENCE_SUFFICIENT`, `EVIDENCE_INCOMPLETE`,
  `HYPOTHESIS_NEEDS_STRENGTHENING`, `CONFLICT_REQUIRES_RESOLUTION`,
  `DUPLICATE_RESEARCH_OVERLAP`, `FAILS_RESEARCH_SCOPE`,
  `RESEARCH_VALUE_LOW`, `ESCALATION_REQUIRED`,
  `GOVERNANCE_REVIEW_REQUIRED`, `PROVENANCE_INCOMPLETE`,
  `SEVERITY_CONTEXT_REQUIRED`, `PRIORITY_CONTEXT_ACKNOWLEDGED`, `OTHER`,
  `RATIONALE_NOT_PROVIDED`.
- An optional bounded human note (max 240 chars, control characters
  stripped, whitespace collapsed) is preserved as text.
- No rationale is invented: absent rationale becomes
  `rationale_state = RATIONALE_NOT_PROVIDED` with the explicit code and
  limitation.
- Human notes are treated strictly as data and never interpreted as
  executable instructions (static tests forbid `eval`/`exec`/`compile`, and
  output key scans show no command/payload/script fields).

## Evidence Requests

`REQUEST_MORE_EVIDENCE` records a structured `HumanEvidenceRequestPlan`:

- `requested_evidence_type` (closed: observation confirmation, context
  completion, hypothesis strengthening, conflict resolution, provenance
  completion, severity context, impact context, other, unknown)
- `source_finding_id` (stable finding id, validated)
- `reason` (rationale code or `REASON_NOT_SPECIFIED`)
- `priority` (closed confidence levels)
- `originating_reference` (bounded hypothesis/evidence reference)

R56 only records the human request: nothing is collected, sent or scanned.
A missing request becomes explicit `EVIDENCE_UNKNOWN` /
`REASON_NOT_SPECIFIED`; a malformed one fails closed with
`MALFORMED_EVIDENCE_REFERENCE`. Limitation
`EVIDENCE_REQUEST_RECORDED_ONLY` is added.

## Escalation

`ESCALATE` records a structured `HumanEscalationPlan`:

- `escalation_target` (closed: `HUMAN_ANALYST_REVIEW`,
  `RESEARCH_LEAD_REVIEW`, `GOVERNANCE_REVIEW`, `SECURITY_REVIEW_BOARD`,
  `ESCALATION_UNKNOWN`)
- `reason` (closed escalation reasons)
- `finding_id`, `priority_band` (R55 context), `evidence_context`
- `provenance` (`prioritization_id`, `correlation_id`,
  `finding_rule_version`, `priority_rule_version`, `orchestration_id`)

No notification is sent, no person or system is contacted and no external
communication integration exists. Limitation
`ESCALATION_RECORDED_ONLY` is added.

## Conflict Handling

If R54 identifies conflicting findings, R56 makes the conflict visible in
the review `correlation_reference` (`conflict_state = CONFLICT_PRESENT`,
`conflict_sources`) and in `batch.conflict_finding_ids`; both reviews stay
independently addressable and both findings remain preserved. A human may
choose `REQUEST_MORE_EVIDENCE`, `ESCALATE`, `DEFER` (or any other decision)
per side — R56 never silently resolves the conflict, never selects a side
and never discards either finding.

## Duplicate Handling

If R54 identifies duplicates, both findings are reviewed and preserved:
`correlation_reference.duplicate_present` is true and
`batch.duplicate_finding_ids` lists both. R55's duplicate-representative
information remains recommendation context inside the immutable
`priority_reference`; no finding is silently deleted and no merge occurs.

## Priority Preservation

R55 priority is immutable in R56: `priority_immutable = True`,
`recommendation_preserved = True`, the `ranked_snapshot` in the batch and
the per-review `priority_reference` are read-only copies. Human decisions
never mutate `priority_score`, `priority_band` or `ranking_position`
(byte-identical R55 input snapshots before/after).

## Governance

Every review preserves the R53 governance reference
(`rule_version`, `ready`, `provenance_state`, `trace_state`, `audit_state`,
`explanation_state`, `reference_state`) via the reused R53 sanitizer. The
result carries the aggregated governance summary
(`CONSISTENT_REFERENCED` / `MIXED` / `UNKNOWN`) over all reviewed findings,
and unknown governance is visible in the limitations. R56 never invents
governance records and never claims execution governance (audit
`not_authorized` always lists execution and confirmation as unauthorized).

## Provenance

Preserved without fabrication (per review and container level):

- finding id, R53 finding rule version, R54 correlation rule version,
  R55 priority rule version and R55 prioritization id
- R54 correlation id (when the correlation result is supplied)
- R52 orchestration id, specialist/agent id and category, source kind and
  source stages
- R56 decision rule version, review rule version and result rule version
- `decision_source = HUMAN`, `deterministic = True`,
  `research_only = True`

## Audit Trail

Every review carries a deterministic `HumanDecisionAuditEntryPlan` with
`audit_id = hda-<16 hex>` answering:

- what finding was reviewed (`finding_id`)
- what automated recommendation existed
  (`automated_recommendation`: band, score, reasons)
- what the human decided (`human_decision_type`, `human_decision_state`)
- why (`decision_rationale_state`, `decision_rationale_codes`)
- what evidence was referenced (`evidence_references`)
- what governance state existed (`governance_state`)
- what remains unconfirmed (`confirmation_state = NOT_CONFIRMED`)
- what is explicitly NOT authorized (`not_authorized` list)
- audit validity (`VALID` when decided, `UNKNOWN` while pending, reusing
  the R37 audit vocabulary)

No external audit system is connected.

## Decision Transitions

Closed transition table (schema vocabulary + rules matrix):

| From | Allowed to |
|---|---|
| `PENDING_HUMAN_REVIEW` | `DECIDED`, `EXPIRED` |
| `DECIDED` | `DECIDED` (supersession) |
| `EXPIRED` | (terminal) |
| `INVALID` | (terminal) |

Transition reasons: `INITIAL_DECISION`, `DECISION_SUPERSEDED`,
`REVIEW_EXPIRED`, `TRANSITION_REJECTED`. Invalid transitions fail closed
(rejection `INVALID_TRANSITION`, structured error, review left pending) and
are never invented dynamically. Supersession preserves
`previous_decision` and `decision_history`.

## Review Batches

`HumanReviewBatchPlan` (`hrb-<16 hex>`) preserves:

- `prioritization_id`, `finding_ids` (stable sorted), `review_order`
  (R55 ranking by default; an explicit order must be an exact permutation
  or `INVALID_REVIEW_ORDER` is reported and the canonical order restored)
- `ranked_snapshot` (immutable R55 band/score/position copies)
- `decisions_by_finding` (decision id/type/state per finding)
- `conflict_finding_ids`, `duplicate_finding_ids`
- `priority_immutable = True`

List position is never used as identity; R55 is never mutated.

## R53 Integration

R56 preserves R53 references through the R55 plan: `finding_rule_version`
(`r53-6`), finding state/confidence/evidence/severity/impact context and the
R53 governance reference shape. R53 artifacts themselves are never imported
or modified; upstream immutability is tested.

## R54 Integration

The optional R54 correlation result (`r54-2`) is validated fail-closed and
contributes the correlation id and rule version, while conflict and
duplicate context comes from the immutable R55 plans. R54 relationships are
sanitized through the R54 sanitizer; endpoints outside the review set are
reported as structured `CORRELATION_MISMATCH` errors. R54 input is never
mutated.

## R55 Integration

The primary input is the R55 prioritization result (`r55-2`): every ranked
and deferred finding becomes a review plan preserving the R55 recommendation
verbatim. R55 requirements are validated (rule version, list shapes,
finding ids, supported categories) and malformed plans are skipped with
structured reasons. No parallel prioritization system exists.

## Safety Boundary

- **No execution**: no commands, HTTP requests, DNS resolution, scanners,
  subprocesses, payloads, browsers, databases or LLM calls exist in R56; a
  decision is recorded only.
- **Fail closed**: unknown decisions, missing finding ids, missing source
  priority, malformed evidence references, invalid provenance/governance,
  automated authority and authorization attempts are rejected or skipped
  with structured reasons and preserved as invalid records.
- **Never confirmed**: every review, decision and audit keeps
  `confirmation_state = NOT_CONFIRMED`; `APPROVE_RESEARCH` is a research
  workflow approval and never a vulnerability confirmation. `ESCALATE`,
  `REQUEST_MORE_EVIDENCE`, `DEFER` and `REJECT` likewise never confirm.
- **Execution placeholder**: the only execution-related option is
  `OPTION_EXECUTION_PLACEHOLDER`, schema-forced `enabled = False` with
  `EXECUTION_NEVER_AUTHORIZED_RESEARCH_ONLY`.
- **Human notes are data**: bounded, sanitized, never executed or
  interpreted as instructions.
- AST static tests forbid network, subprocess, shell, browser, scanner,
  database, LLM provider, dynamic loading, randomness and wall-clock
  imports/calls and all forbidden claim markers.

## Determinism

- Content-derived ids only: `hdc-` (decision), `hrv-` (review), `hda-`
  (audit), `hrb-` (batch), `hrr-` (result) with 16 hex digits from SHA-256.
- No timestamps, UUIDs, pids, randomness or external state; AST tests
  forbid `random`, `uuid`, `time` and `datetime`.
- Stable ordering by stable finding ids; shuffled decision inputs produce
  byte-identical output; repeated calls are byte-identical.

## Tests

Focused R56 tests (all offline, `unittest` style):

```
python -m pytest tests/test_human_decision.py -q -p no:cacheprovider
72 passed

python -m pytest tests/test_human_review.py -q -p no:cacheprovider
66 passed

python -m pytest tests/test_human_decision_safety.py -q -p no:cacheprovider
22 passed

combined: 160 passed
```

Coverage includes every decision state and type, HUMAN authority and
ADVISORY AI enforcement, `execution_authorized=False`,
`vulnerability_confirmed=False`, the `NOT_CONFIRMED` invariant,
recommendation/decision separation, rationale preservation and absence,
evidence request creation, escalation representation, conflict review,
duplicate review, priority immutability, provenance and governance
preservation, decision history, valid and invalid transitions, review
batches, stable ids, deterministic and shuffled-input output, malformed/
unsupported/empty/minimal inputs, invalid authority, execution/confirmation/
exploit authorization rejection, input immutability, R53/R54/R55 → R56
integration and AST static safety checks.

## Full Suite

```
python -m pytest tests/ -q -p no:cacheprovider
5416 passed, 40 failed, 1 warning, 376 subtests passed in 54.91s
```

Baseline (R55): `5256 passed, 40 failed, 376 subtests`.

- passed growth: `5416 - 5256 = 160` — exactly the 160 new R56 tests;
- failed count unchanged at 40; subtests unchanged at 376;
- the sorted failure list is byte-identical to the R55 baseline set.

Relevant regression (all passed):

```
R42/R43/R44/R52/R53/R54/R55 + finding/priority suite:
  tests/test_research_priority*.py, tests/test_finding_*.py,
  tests/test_agent_evaluation_*.py, tests/test_agent_orchestrator*.py,
  tests/test_collaboration_*.py, tests/test_hypothesis_correlator.py,
  tests/test_learning_*.py, tests/test_multi_agent_collaboration_*.py,
  tests/test_research_feedback_event.py
  632 passed

AI safety (knowledge_store/xss_researcher/xss_llm_researcher/openrouter):
  96 passed
```

## Changed Files

Added (8 implementation/test files + this report):

```
ai/schemas/human_decision.py
ai/schemas/human_review.py
ai/schemas/human_decision_result.py
ai/knowledge/human_decision_rules.py
ai/knowledge/human_review.py
tests/test_human_decision.py
tests/test_human_review.py
tests/test_human_decision_safety.py
agent-reports/stage-r56-human-in-the-loop.md
```

Modified: **none**. No existing tracked file was modified.

## Git Commit

- Subject: `feat(human-loop): add r56 human decision boundary`
- Parent: `1af71e5` (R55 Research Prioritization)
- One local commit only; no push, no amend, no squash.
- Exact commit hash is reported in the final task response (a commit cannot
  embed its own hash; this report is part of that single R56 commit).

## Verification

- Focused R56: `160 passed`.
- Full suite: `5416 passed, 40 failed, 376 subtests`.
- `git diff --check`: clean.
- `git status --short`: only the new R56 files; the pre-existing unrelated
  worktree items (` D utils.zip`, `?? watch.zip`,
  `?? agent-reports/R31-final-github-audit.md`,
  `?? agent-reports/stage-r31-5-planning-audit.md`) remain untouched and
  outside the commit.
- R38–R55 modifications: **NONE**.
- Backend/infrastructure modifications: **NONE** (backend does not import
  R56; no Docker/systemd/VPS/deployment/VM changes).
- Network/execution capability: **NONE**.
- Human authority boundary: **PASS** (HUMAN authority, ADVISORY AI, never
  confirmed, never authorized).
- Safety: **PASS** (fail-closed rejection, invalid records preserved, no
  execution capability).
- Determinism: **PASS** (content-derived ids, byte-identical output,
  shuffled-input equivalence).

## Known Pre-existing Failures

The full suite retains exactly the same 40 pre-existing failures as the
R45–R55 baselines (money-score / economics corpus drift, dashboard render,
product API, research sessions/outcomes/UI, router lookup, daily research
workflow diff). They are unrelated to R56 and were not modified or fixed.
