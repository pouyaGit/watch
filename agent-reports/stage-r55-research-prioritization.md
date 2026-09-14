# R55 Research Prioritization Intelligence

## Summary

R55 adds a deterministic, explainable research-priority layer on top of the
existing R53 finding intelligence and R54 finding correlation:

```
R39–R50 Specialist Research
        ↓
R52 Orchestrator
        ↓
R53 Evidence → Finding
        ↓
R54 Finding Correlation
        ↓
R55 Research Prioritization      ← this stage
        ↓
future R56 Human-in-the-Loop
```

R55 answers: **"Which research finding should be investigated first, and
why?"** It produces a bounded 0–100 priority score, a closed priority band,
explicit factor contributions, structured reason codes and deterministic
rank positions. It is a research-ordering signal only: not vulnerability
confirmation, exploitation, attack planning, payload generation, execution,
severity certification or automated submission.

R55 is implemented additively. No R38–R54 file was modified. Every unsafe
input is preserved in a deferred set with explicit reasons and limitations;
nothing is deleted or merged. Priority never changes confidence, and
correlation never boosts priority.

## Architecture

New modules (pure, offline, deterministic):

| File | Rule version | Role |
|---|---|---|
| `ai/schemas/research_priority.py` | `r55-1` | Priority plan schema, closed vocabularies, factor/reason/limitation sanitizers |
| `ai/schemas/research_priority_result.py` | `r55-2` | Prioritization result container, statuses, skips, errors, summary/provenance/governance projections |
| `ai/knowledge/research_priority_rules.py` | `r55-3` | Pure scoring engine: candidate normalization, contribution tables, caps, reasons, correlation/learning context |
| `ai/knowledge/research_prioritization.py` | `r55-4` | Builder/public API: input validation, safety gate, ranking, container assembly |

Public API:

- `prioritize(finding_intelligence=None, findings=None, correlation_result=None, learning_result=None)`
- `prioritize_finding_intelligence(...)` — R53 result → R55
- `prioritize_findings(...)` — standalone R53 findings → R55
- `prioritize_correlated_findings(...)` — R54 result references → R55
- `export_research_priorities(**kwargs)` — alias

Reuse (never duplication): R53 `sanitize_finding`, R54
`sanitize_finding_relationship`/`sanitize_correlation_cluster`, R43
relationship vocabulary, R44 `sanitize_learning_recommendation`, R42
rating/gate/safety vocabularies, R37 governance reference shape, R53
finding states/confidence/severity/impact vocabularies.

## Priority Contract

`ResearchPriorityPlan` (`extra="forbid"`) preserves the upstream finding
identity and bounded context:

- `finding_id`, `category`, `specialist_name`, `agent_id`
- `state`, `confirmation_state` (forced `NOT_CONFIRMED`)
- `confidence`, `confidence_effect` (forced `NONE`)
- `evidence_state`, `evidence_completeness`, `evidence_origin`
- `severity`, `severity_source`, `impact_state`, `impact_confidence`
- `priority_score`, `priority_band`, `priority_factors`,
  `priority_reasons`
- `correlation_summary`, `conflict_state`, `learning_summary`
- `ranking_position`, `provenance`, `governance`, `limitations`
- `research_only = True`, `deterministic = True`

`ResearchPrioritizationResultPlan` (`extra="forbid"`) carries:

- `rule_version = "r55-2"`, `prioritization_rule_version = "r55-2"`,
  `priority_rule_version = "r55-3"`, `finding_rule_version`,
  `correlation_rule_version`
- `prioritization_id` (`pri-<16 hex>`, content-derived)
- `status` (`COMPLETED` / `PARTIAL` / `NO_FINDINGS` / `FAILED`)
- `ranked_findings`, `deferred_findings`, `skipped_findings`, `errors`
- `summary`, `provenance`, `governance`, `limitations`
- `confidence_effect = NONE`, `research_only = True`, `deterministic = True`

## Priority Bands

Closed vocabulary: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `DEFERRED`.

Deterministic thresholds (`band_for_score`, documented constants):

| Band | Score |
|---|---|
| `CRITICAL` | 80–100 |
| `HIGH` | 65–79 |
| `MEDIUM` | 45–64 |
| `LOW` | 0–44 |
| `DEFERRED` | safety-gate only; score 0, position 0 |

`DEFERRED` is never a low-score side effect: only the safety eligibility gate
(or an R44 safety-boundary learning signal) assigns it, which guarantees
"unsafe output is never boosted" is a structural property, not a threshold
accident.

## Scoring / Ranking Rules

The score is the clamped sum of documented factor contributions plus
explicit negative band-cap adjustments, so `priority_score` always equals
`max(0, min(100, sum(contributions)))` (covered by tests).

Documented contribution tables (fixed constants, not runtime configurable):

| Factor | Value | Contribution |
|---|---|---|
| `EVIDENCE_COMPLETENESS` | COMPLETE / PARTIAL / MISSING / UNKNOWN | +25 / +12 / 0 / 0 |
| `CONTEXT_COMPLETENESS` | CONTEXT_COMPLETE (≥5 facts) / PARTIAL / MISSING | +10 / +5 / 0 |
| `FINDING_STATE` | CONFIRMED_OBSERVED / EVIDENCE_SUPPORTED / RESEARCH_CANDIDATE / NEEDS_MORE_EVIDENCE / CONFLICTED / INSUFFICIENT_EVIDENCE | +20 / +16 / +12 / +10 / +4 / 0 |
| `UPSTREAM_CONFIDENCE` | HIGH / MEDIUM / LOW / UNKNOWN | +12 / +8 / +4 / 0 |
| `IMPACT_SIGNAL` | OBSERVED / POTENTIAL / UNKNOWN | +10 / +6 / 0 |
| `SEVERITY_SIGNAL` | CRITICAL_OBSERVED / HIGH_OBSERVED / MEDIUM_OBSERVED / LOW_OBSERVED / NONE_OBSERVED / UNKNOWN (only with `CVSS_CONTEXT`) | +8 / +6 / +4 / +2 / +1 / 0 |
| `PROVENANCE_COMPLETENESS` | COMPLETE / PARTIAL / INCOMPLETE | +4 / +2 / 0 |
| `CORRELATION_CONTEXT` | CONFLICTING / DUPLICATE_REDUNDANT / DUPLICATE_REPRESENTATIVE / RELATED / INDEPENDENT / UNKNOWN / UNAVAILABLE | −10 / −6 / 0 / 0 / 0 / 0 / 0 |
| `LEARNING_SIGNAL` | REQUIRES_MORE_EVIDENCE / STRENGTHEN_HYPOTHESES / AVOID_DUPLICATION / others | +4 / +4 / −3 / 0 |
| `GOVERNANCE_CONSTRAINT` | BAND_CAP_LOW / BAND_CAP_MEDIUM | negative delta to 44 / 64 |
| `CONFLICT_CONSTRAINT` | BAND_CAP_MEDIUM | negative delta to 64 |
| `LEARNING_CONSTRAINT` | BAND_CAP_MEDIUM | negative delta to 64 |

Ranking order (all keys deterministic; list position never used):

1. safety eligibility (deferred excluded from ranking),
2. priority band rank,
3. priority score,
4. evidence quality rank,
5. upstream confidence rank,
6. impact rank,
7. stable `finding_id` ascending.

`ranking_position` is 1..N for eligible findings and 0 for deferred
findings.

## Evidence Factors

- `evidence_completeness` mirrors the closed R53 state
  (`COMPLETE`/`PARTIAL`/`MISSING`/`UNKNOWN`); R55 never upgrades it.
- `context_fact_count` classifies context completeness (≥5 / 1–4 / 0).
- Missing evidence is explicit: reason `MISSING_EVIDENCE` plus limitation
  `EVIDENCE_INCOMPLETE`; an evidence gap with a structured hypothesis
  (`NEEDS_MORE_EVIDENCE`) receives a meaningful +10 research score because
  additional evidence could resolve it, and the reason says exactly that
  (`NEEDS_MORE_EVIDENCE`) — it is never dressed up as stronger evidence.

## Confidence Handling

Priority is not confidence:

- `confidence_effect` is forced `NONE` at plan, cluster-free result and
  container levels.
- `confirmation_state` is forced `NOT_CONFIRMED` on every ranked and
  deferred plan.
- Upstream confidence is only a bounded +12 factor and is preserved
  verbatim in the plan.
- Multiple agreeing findings (RELATED) contribute 0 priority and never
  increase confidence.
- Tests cover HIGH confidence + LOW priority, LOW confidence + HIGH
  priority, no confidence mutation, and no agreement inflation.

## Severity Handling

Severity is never computed. Only an explicitly structured upstream CVSS
context contributes (`severity_source == CVSS_CONTEXT`); otherwise the
severity factor is `UNKNOWN` with contribution 0 and the reason/limitation
`SEVERITY_NOT_ASSESSED` remains explicit. Category names, priority,
confidence, agent count and correlation count are never converted into
severity.

## Impact Handling

Impact remains `POTENTIAL` unless the upstream structured assessment
explicitly carries `OBSERVED`; both are mirrored, never invented. Business
impact is never asserted (R53 already forces `business_impact_asserted =
False`). Unknown impact contributes 0 and yields `IMPACT_NOT_OBSERVED`.

## Correlation Handling

Correlation is context and penalty only — it never boosts:

- conflicting: −10 and a `MAX_MEDIUM` band cap (score ≤ 64) with
  `CONFLICT_REQUIRES_REVIEW`; conflict source finding ids are preserved;
  neither side is selected as true;
- duplicate: deterministic representative selection (see below); the
  redundant member gets −6 with `DUPLICATE_RESEARCH_REDUCTION`;
- related/independent/unknown: contribution 0 with an explicit reason;
- no R54 result: `CORRELATION_UNAVAILABLE` is explicit, and embedded R43
  conflicts carried by the R53 finding are still honored;
- R54 relationships that reference findings outside the candidate set are
  recorded as structured `CORRELATION_MISMATCH` errors plus a
  `CORRELATION_INCOMPLETE` limitation — never guessed.

## Duplicate Handling

Duplicate findings are never deleted or merged. For each R54 `DUPLICATE`
pair, one deterministic representative is chosen by:

1. strongest available evidence,
2. most complete context,
3. upstream confidence,
4. governance readiness,
5. provenance completeness,
6. lexicographically smaller stable `finding_id` (full tie only).

The representative is not penalized (reason `DUPLICATE_REPRESENTATIVE`); the
other member receives `DUPLICATE_RESEARCH_REDUCTION` (−6) so redundant
research effort is reduced without assuming the first-seen finding is
superior (tested with the weaker finding supplied first).

## Conflict Handling

Conflicting findings are conservative:

- both sides remain independently ranked, addressable and traceable;
- each conflict side gets −10, a `MAX_MEDIUM` band cap and reason
  `CONFLICT_REQUIRES_REVIEW`;
- `conflict_state = CONFLICT_PRESENT`, conflict sources and relationship
  ids are preserved in `correlation_summary`;
- limitation `CONFLICT_PRESENT` is added at plan and container level;
- no silent truth selection or discard occurs (verified by tests).

## Learning Integration

Only existing R44 recommendations are interpreted as advisory context; R55
never modifies learning memory and never invents recommendations.

Mapping of the R44 recommendation vocabulary (used instead of inventing new
signal names):

| R44 recommendation type | R55 factor value | Contribution | Reason |
|---|---|---|---|
| `RESTORE_SAFETY_BOUNDARY` | `LEARNING_SAFETY_BOUNDARY` | 0 | `LEARNING_SIGNAL_SAFETY_BOUNDARY` + deferral |
| `REVIEW_GOVERNANCE_REFERENCES` | `LEARNING_REVIEW_GOVERNANCE` | 0 | `LEARNING_SIGNAL_REVIEW_GOVERNANCE` + cap 64 |
| `PRIORITIZE_EVIDENCE_PLANNING` | `LEARNING_REQUIRE_MORE_EVIDENCE` | +4 | `LEARNING_SIGNAL_REQUIRES_EVIDENCE` |
| `STRENGTHEN_HYPOTHESES` | `LEARNING_STRENGTHEN_HYPOTHESES` | +4 | `LEARNING_SIGNAL_STRENGTHEN_HYPOTHESIS` |
| `DEDUPLICATE_HYPOTHESES` | `LEARNING_AVOID_DUPLICATION` | −3 | `LEARNING_SIGNAL_AVOID_DUPLICATION` |
| `CALIBRATE_CONFIDENCE` | `LEARNING_CALIBRATE_CONFIDENCE` | 0 | `LEARNING_SIGNAL_CALIBRATE_CONFIDENCE` |
| `IMPROVE_CONTEXT_CAPTURE` | `LEARNING_IMPROVE_CONTEXT` | 0 | `LEARNING_SIGNAL_IMPROVE_CONTEXT` |
| `PRESERVE_PROVENANCE` | `LEARNING_REVIEW_PROVENANCE` | 0 | `LEARNING_SIGNAL_REVIEW_PROVENANCE` |
| `PRESERVE_SUCCESSFUL_PATTERN` | `LEARNING_PRESERVE_PATTERN` | 0 | `LEARNING_SIGNAL_PRESERVE_PATTERN` |
| `UNKNOWN` | `LEARNING_UNRECOGNIZED` | 0 | `LEARNING_SIGNAL_UNRECOGNIZED` |

Learning is matched per finding from its own R53 `learning_recommendations`
plus optional container recommendations whose `related_agent` matches.
When no learning context exists, `LEARNING_UNAVAILABLE` is explicitly
represented as factor value, reason and limitation.

## Governance

Per-finding R37 governance reference state is preserved and visible in the
plan `governance` dict, factors, reasons and limitations:

- referenced + ready: no constraint (and never a boost);
- referenced + not ready: score capped at 44 (`BAND_CAP_LOW`) with
  `GOVERNANCE_LIMITATION` / `GOVERNANCE_NOT_READY`;
- unknown: score capped at 64 (`BAND_CAP_MEDIUM`) with
  `GOVERNANCE_LIMITATION` / `GOVERNANCE_UNKNOWN`.

The result carries an aggregated governance summary
(`CONSISTENT_REFERENCED` / `MIXED` / `UNKNOWN`) over ranked and deferred
findings. R55 never claims governed execution.

## Provenance

Preserved without fabrication:

- finding id, R53 finding rule version, R54 correlation rule version,
  R54 priority rule version, R52 orchestration id, specialist/agent id,
  source stages, source kind (`R53_FINDING` / `R54_REFERENCE`);
- R42 reference footprint (`evaluation_rating`, `hard_gate_state`,
  `safety_state`);
- R43 conflict references (conflict count, embedded conflict count,
  conflict source finding ids, R54 relationship ids);
- R44 references (`learning_summary` recommendation types/ids);
- R37 governance reference (`reference_state`, `ready_state`,
  `rule_version`);
- container-level provenance aggregates (source kinds, orchestration ids,
  categories, agent ids) plus `deterministic = True`,
  `research_only = True`.

## Limitations

Closed, ordered limitation vocabulary. Core invariants always present:
`NO_EXECUTION_PERFORMED`, `NO_NETWORK_REQUESTS`,
`NO_VULNERABILITY_CONFIRMATION`, `NO_EXPLOIT_GENERATION`, `RESEARCH_ONLY`,
`PRIORITY_NOT_CONFIDENCE`, `CONFIDENCE_NOT_UPGRADED`, `NOT_CONFIRMED`,
`PRIORITY_RANKING_ONLY`. Conditional codes include `SAFETY_DEFERRED`,
`SEVERITY_NOT_ASSESSED`, `IMPACT_NOT_OBSERVED`, `EVIDENCE_INCOMPLETE`,
`INSUFFICIENT_CONTEXT`, `CORRELATION_UNAVAILABLE`, `CORRELATION_INCOMPLETE`,
`CONFLICT_PRESENT`, `DUPLICATE_RELATIONSHIP`, `GOVERNANCE_UNKNOWN`,
`GOVERNANCE_NOT_READY`, `LEARNING_GOVERNANCE_REVIEW`,
`PROVENANCE_INCOMPLETE`, `LEARNING_UNAVAILABLE`.

## R53 Integration

- `prioritize_finding_intelligence(intelligence, correlation_result=None,
  learning_result=None)` consumes an R53 `r53-6` result (rule version
  validated, fail closed on mismatch).
- Findings are normalized through the R53 `sanitize_finding` contract; the
  R53 input is never mutated (byte-identical snapshot tests).
- Standalone R53 findings are accepted via `prioritize_findings`.
- Tested end-to-end: `orchestrate_research` → `build_finding_intelligence`
  → `prioritize_finding_intelligence`.

## R54 Integration

- `prioritize(...)` and `prioritize_findings(...)` accept an optional R54
  `r54-2` correlation result; the rule version is validated (fail closed).
- `prioritize_correlated_findings(correlation_result)` builds priority plans
  directly from R54 finding references (severity/impact stay explicitly
  `UNKNOWN`/`NOT_ASSESSED`).
- Relationships and clusters are consumed through R54 sanitizers; R54 input
  is never mutated and no parallel correlation system exists.
- Tested end-to-end: `correlate` / `correlate_findings` → R55, including
  duplicate, related, conflicting, independent, unknown and mismatch cases.

## Safety Boundary

Safety-first behavior:

- unsafe findings are **deferred, never deleted**: non-research-only,
  unsafe confirmation (`!= NOT_CONFIRMED`), `safety_state = FAILED`,
  `hard_gate_state = FAIL_SAFETY`, forbidden claim tokens in text channels,
  invalid-provenance/invalid-governance diagnostics, and R44 safety-boundary
  signals;
- deferred plans have score 0, band `DEFERRED`, position 0, only the
  `SAFETY_ELIGIBILITY`/`SAFETY_DEFERRED` factor, and explicit
  `SAFETY_DEFERRED` reasons/limitations;
- fail-closed handling for malformed/ambiguous inputs, wrong rule
  versions, both finding sources supplied, malformed correlation/learning
  shapes; malformed entries are skipped with structured reasons;
- no HTTP/network/DNS/subprocess/browser/scanner/DB/LLM capability exists in
  the R55 modules (AST static tests).

## Determinism

- No timestamps, UUIDs, pids, randomness, wall-clock or external state.
- Stable canonical ordering by stable finding ids; shuffled input produces
  byte-identical ranked output (tested).
- `prioritization_id` is a SHA-256 content token (`pri-<16 hex>`);
  `rule_version`s are fixed constants.
- AST tests forbid `random`, `uuid`, `time`, `datetime` imports and calls.
- Byte-identical output over repeated calls is tested.

## Tests

Focused R55 tests (all offline, `unittest` style):

```
python -m pytest tests/test_research_priority_rules.py -q -p no:cacheprovider
52 passed

python -m pytest tests/test_research_priority.py -q -p no:cacheprovider
83 passed

python -m pytest tests/test_research_prioritization_safety.py -q -p no:cacheprovider
19 passed

combined: 154 passed
```

Coverage includes every priority band, score bounds and sum invariant,
factor calculation, reason generation, deterministic ranking, stable
tie-breaking, priority ≠ confidence, no confidence inflation, NOT_CONFIRMED
invariant, complete/partial/missing evidence, high-confidence/low-priority
and low-confidence/high-priority, impact and severity handling, duplicate /
related / conflicting / independent / unknown correlation, duplicate
research reduction, conflict-aware prioritization, evidence-gap
prioritization, R44 learning signals and learning unavailable, governance
constraints, provenance preservation, limitations, unsafe/deferred findings,
malformed/empty/minimal/unsupported input, input immutability, R53→R55 and
R54→R55 integration, deterministic byte-identical output, shuffled-input
equivalence and AST static safety checks.

## Full Suite

```
python -m pytest tests/ -q -p no:cacheprovider
5256 passed, 40 failed, 1 warning, 376 subtests passed in 53.29s
```

Baseline (R54): `5102 passed, 40 failed, 376 subtests`.

- passed growth: `5256 - 5102 = 154` — exactly the 154 new R55 tests;
- failed count unchanged at 40; subtests unchanged at 376;
- none of the 40 failures references R55.

Relevant regression (all passed):

```
R42/R43/R44/R52/R53/R54 + finding suite:
  tests/test_agent_evaluation_*.py, tests/test_agent_orchestrator*.py,
  tests/test_collaboration_*.py, tests/test_finding_*.py,
  tests/test_hypothesis_correlator.py, tests/test_learning_*.py,
  tests/test_multi_agent_collaboration_*.py, tests/test_research_feedback_event.py
  553 passed

AI safety (knowledge_store/xss_researcher/xss_llm_researcher/openrouter):
  ai/test_knowledge_store.py ai/test_xss_researcher.py
  ai/test_xss_llm_researcher.py ai/test_openrouter.py
  96 passed
```

## Changed Files

Added (7 implementation/test files + this report):

```
ai/schemas/research_priority.py
ai/schemas/research_priority_result.py
ai/knowledge/research_priority_rules.py
ai/knowledge/research_prioritization.py
tests/test_research_priority_rules.py
tests/test_research_priority.py
tests/test_research_prioritization_safety.py
agent-reports/stage-r55-research-prioritization.md
```

Modified: **none**. No existing tracked file was modified.

## Git Commit

- Subject: `feat(priority): add r55 research prioritization intelligence`
- Parent: `de3e063` (R54 Finding Correlation)
- One local commit only; no push, no amend, no squash.
- Exact commit hash is reported in the final task response (a commit cannot
  embed its own hash; this report is part of that single R55 commit).

## Verification

- Focused R55: `154 passed`.
- Full suite: `5256 passed, 40 failed, 376 subtests`.
- `git diff --check`: clean.
- `git status --short`: only the new R55 files; the pre-existing unrelated
  worktree items (` D utils.zip`, `?? watch.zip`,
  `?? agent-reports/R31-final-github-audit.md`,
  `?? agent-reports/stage-r31-5-planning-audit.md`) remain untouched and
  outside the commit.
- R38–R54 modifications: **NONE**.
- Backend/infrastructure modifications: **NONE** (backend does not import
  R55; no Docker/systemd/VPS/deployment/VM changes).
- Network/execution capability: **NONE** (`NO_NETWORK_REQUESTS`,
  `NO_EXECUTION_PERFORMED`; AST static tests pass).
- Priority ≠ confidence: enforced by schema validators and tests.
- Safety: **PASS** — unsafe findings deferred, never dropped or boosted.
- Determinism: **PASS** — byte-identical output, shuffled input
  equivalence.

## Known Pre-existing Failures

The full suite retains exactly the same 40 pre-existing failures as the
R45–R54 baselines (money-score / economics corpus drift, dashboard render,
product API, research sessions/outcomes/UI, router lookup, daily research
workflow diff). They are unrelated to R55 and were not modified or fixed.
