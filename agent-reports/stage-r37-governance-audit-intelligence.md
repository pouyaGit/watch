# Stage R37 — Research Governance & Audit Intelligence Layer

Local WSL implementation. **Governance/audit only.** R37 creates deterministic
governance, provenance, decision-trace and audit intelligence. It does NOT
execute anything: no execution runtime, workers, task dispatch, scheduler,
crawling, scanning, Nuclei, fuzzing, exploit validation, HTTP, subprocess,
shell, browser automation, Mongo persistence, external network, LLM calls,
embeddings, VM changes or deployment changes. No R29/Money/CVE or R31–R36
semantics were modified.

## 1. Architecture

Deterministic pipeline over the existing R34/R35/R36 exports:

```
R34 Strategy Export + R35 Orchestration Export + R36 Authorization Export
        ↓
R37.1 Decision Provenance              (r37-1)
        ↓
R37.2 Governance Rule Trace            (r37-2)
        ↓
R37.3 Audit Event Model                (r37-3)
        ↓
R37.4 Explainability Planner           (r37-4)
        ↓
R37.5 Governance Export                (r37-5)
```

Every module is pure, stateless, JSON-serializable, pydantic-validated and
`research_only=True`. Inputs are consumed read-only and never mutated. No
wall-clock time, randomness, environment, filesystem or global state is used.
No persistence and no database ids exist.

## 2. Provenance Model (R37.1)

`DecisionProvenancePlan` fields: `rule_version`, `decision_id`,
`source_strategy`, `source_orchestration`, `source_authorization`,
`contributing_signals[]`, `provenance_state`, `research_only`.

- **Deterministic id**: `dp-<sha256[:16]>` computed from bounded closed inputs
  (strategy type, primary role, authorization decision, policy, risk level,
  approval state, boundary state); no clock, no persistence, no database id.
  Identical inputs always produce the identical id.
- **Closed signals**: `STRATEGY`, `ORCHESTRATION`, `AUTHORIZATION`, `POLICY`,
  `RISK`, `APPROVAL`, `BOUNDARY` (only valid sources are listed, fixed order).
- **States**: `COMPLETE` (strategy + orchestration + authorization all valid),
  `PARTIAL` (at least one of the three), `UNKNOWN` (none). Malformed sources
  degrade to bounded sanitized snapshots, never invented provenance.

## 3. Rule Trace Model (R37.2)

`GovernanceRuleTracePlan` fields: `rule_version`, `applied_rules[]`,
`rejected_rules[]`, `precedence_order[]`, `trace_state`, `research_only`.

- **Closed rule vocabulary** (12): `CONTEXT_VALIDATION_FIRST`,
  `POLICY_BLOCK_TERMINAL`, `HUMAN_APPROVAL_MANDATORY`, `RESEARCH_ONLY_LIMIT`,
  `PASSIVE_ONLY_LIMIT`, `ACTIVE_ALLOWED_VALID`, `SCOPE_GATE`,
  `SCOPE_UNKNOWN_CONSERVATIVE`, `APPROVAL_GATE`, `RISK_NOT_PERMISSION`,
  `BOUNDARY_PRECEDENCE`, `UNKNOWN_CONTEXT`.
- **Explicit precedence** always emitted: context validation → policy block →
  human approval → research-only limit → passive-only limit → active allowed
  → scope gate → approval gate → risk-not-permission → boundary.
- **Applied/rejected mapping** is a closed per-decision table: BLOCK applies
  `POLICY_BLOCK_TERMINAL`, REQUIRE_HUMAN_APPROVAL applies
  `HUMAN_APPROVAL_MANDATORY` + `APPROVAL_GATE`, limited decisions apply the
  research/passive limit + `SCOPE_GATE`, ALLOW applies `ACTIVE_ALLOWED_VALID`.
  An unknown scope prepends `SCOPE_UNKNOWN_CONSERVATIVE`. No hidden logic.
- **States**: `COMPLETE` (valid policy + valid decision), `PARTIAL` (one),
  `UNKNOWN` (neither).

## 4. Audit Event Model (R37.3)

`ResearchAuditEventPlan` fields: `rule_version`, `event_type`,
`event_source`, `event_summary`, `related_strategy`,
`related_authorization`, `audit_state`, `research_only`.

- **Event types** (6): `STRATEGY_CREATED`, `WORKFLOW_CREATED`,
  `AUTHORIZATION_DECIDED`, `APPROVAL_REQUIRED`, `BLOCK_APPLIED`, `UNKNOWN`.
- **Sources** (5): `STRATEGY`, `ORCHESTRATION`, `AUTHORIZATION`,
  `GOVERNANCE`, `UNKNOWN`; **summaries** are closed static codes.
- **Derivation**: known decisions first (BLOCK / human approval / decided),
  then workflow, then strategy, else `UNKNOWN`.
- **Audit states**: `VALID` for complete/partial provenance with a known
  event; `INVALID` when critical provenance is unknown or the event cannot be
  classified; `UNKNOWN` when no governance input exists.
- **No storage, no runtime timestamps, no external ids**: repeated evaluation
  is byte-identical.

## 5. Explainability Model (R37.4)

`ResearchExplanationPlan` fields: `rule_version`, `summary`, `reasons[]`,
`limitations[]`, `confidence`, `explanation_state`, `research_only`.

- **Summary** (closed): `EXPLANATION_AUTHORIZED`, `EXPLANATION_LIMITED`,
  `EXPLANATION_HUMAN_APPROVAL`, `EXPLANATION_BLOCKED`, `EXPLANATION_UNKNOWN`.
- **Reasons** (closed, 10): policy-level reasons
  (`POLICY_RESEARCH_ONLY`, `POLICY_PASSIVE_ONLY`, `POLICY_ACTIVE_ALLOWED`,
  `POLICY_BLOCKED`, `POLICY_HUMAN_APPROVAL_REQUIRED`), `CONTEXT_INCOMPLETE`,
  `SCOPE_UNKNOWN`, `BOUNDARY_BLOCKED`, `APPROVAL_PENDING`, `RISK_ELEVATED`.
- **Limitations** (closed, 4): `SOURCE_CONTEXT_MISSING`,
  `PARTIAL_PROVENANCE`, `SCOPE_UNKNOWN`, `UNKNOWN_EXPLANATION`.
- **No hallucinated reasons**: the explanation is generated only from the
  strategy/orchestration/authorization/provenance/rule-trace inputs with
  closed codes and static labels; no LLM, no free-form text. Confidence is a
  closed class derived from provenance completeness.
- **States**: `COMPLETE` (provenance + trace complete, decision known),
  `PARTIAL` (some context), `UNKNOWN` (no context).

## 6. Governance Export (R37.5)

`ResearchGovernanceExportPlan` fields: `rule_version`, `ready`, `provenance`,
`rule_trace`, `audit_event`, `explanation`, `limitations[]`, `research_only`.

- **Readiness**: `ready=True` only when provenance and rule trace are
  COMPLETE/PARTIAL, the audit event is VALID and the explanation is
  COMPLETE/PARTIAL. Any UNKNOWN critical state prevents readiness; an INVALID
  audit event prevents readiness.
- **Closed limitations**: `UNKNOWN_PROVENANCE`, `UNKNOWN_RULE_TRACE`,
  `INVALID_AUDIT_EVENT`, `UNKNOWN_AUDIT_EVENT`, `UNKNOWN_EXPLANATION`,
  `MISSING_SOURCES` (single-record partial provenance).
- Embedded plans are bounded sanitized snapshots with no input aliasing.

## 7. Backend Integration

`backend/asset_cve_matching.py` adds only these summary fields plus
rule-version companions:

`decision_provenance_plan`, `governance_rule_trace_plan`,
`research_audit_event_plan`, `research_explanation_plan`,
`research_governance_export_plan`.

The backend diff is +88/−0 (imports and additive projections only). For the
default backend chain the governance export is `ready=True` with a COMPLETE
provenance, COMPLETE trace, VALID audit event and COMPLETE explanation. No
existing field was renamed or changed and no existing behavior was altered.

## 8. Tests

| Suite | Tests |
|---|---|
| `tests.test_decision_provenance` | 20 |
| `tests.test_governance_rule_trace` | 18 |
| `tests.test_research_audit_event` | 19 |
| `tests.test_research_explanation` | 19 |
| `tests.test_research_governance_export` | 17 |
| **Total R37** | **93 (all OK)** |

Coverage: deterministic decision ids, provenance completeness/partial/unknown,
missing source handling, per-decision rule mapping, explicit precedence,
conservative scope rule, every audit event type/source/state, no runtime
timestamps, explanation reasons without hallucination (all closed codes),
limitation and confidence mapping, readiness gating for every component,
malformed/empty inputs, no mutation, snapshot aliasing, JSON serialization,
closed vocabulary + schema rejections, `research_only`, no execution content,
and hermetic backend integration (mocked inventory, no live Mongo, Money
Score canary).

## 9. Regression

```
new R37 suites                                    93 tests   OK
combined R31-R37 + R29/R30 regression             Ran 1609 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
```

Full-suite baseline comparison: before R37 (R36 baseline) **3098 tests / 37
failures / 3 errors**; after R37 **3191 tests / 37 failures / 3 errors**
(+93 new tests). The sorted `FAIL:`/`ERROR:` line sets are byte-identical
(`diff` clean): no new failure is attributable to R37 and no pre-existing
failure was modified.

## 10. Safety Verification

- R37 modules import only stdlib (`re`, `hashlib`), pydantic and
  `ai.schemas`/`ai.knowledge`; a case-insensitive grep found no subprocess,
  shell, network, browser, Nuclei, Mongo or LLM imports (docstring boundary
  statements only).
- No worker queue, scheduler, dispatch, runtime, approval service, database,
  API, UI, notification system or persistence was created.
- No runtime timestamps or external ids exist in any R37 object.
- No VM access, no deployment/systemd/Docker change, no push.

## 11. Git Summary

```
$ git diff --stat      # tracked changes at implementation time
 backend/asset_cve_matching.py | 88 +++++++++++++++++++++++++++++++++++++++++
 1 file changed, 88 insertions(+)

$ git status --short
 D utils.zip
?? agent-reports/R31-final-github-audit.md
?? agent-reports/stage-r31-5-planning-audit.md
?? watch.zip
 + the 17 new R37 files (10 modules, 5 tests, 1 report, backend)
```

The R37 commit contains only R37 files; `utils.zip`, `watch.zip`,
`agent-reports/R31-final-github-audit.md` and
`agent-reports/stage-r31-5-planning-audit.md` remain untouched outside the
commit. No R31–R36 file was modified.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R37
- Role: coding agent
