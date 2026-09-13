# Stage R43 — Multi-Agent Research Collaboration Layer

A deterministic, research-only collaboration layer for multiple security
specialist agents. R43 combines already-structured specialist results (and
optionally their R42 evaluation results) into one coherent research view. It
is not an execution orchestrator, does not run agents, and does not perform
security testing.

- Stage: R43
- Rule versions: `r43-1` … `r43-6`
- Commit: `feat(research): add r43 multi-agent collaboration layer` (local
  only, not pushed; hash reported in the final response)

## 1. Objective

Answer: **"How do multiple structured security research results relate,
support, overlap or conflict?"** — while preserving attribution, safety,
governance and provenance. R43 does NOT answer whether a vulnerability is
real, exploitable or should be attacked.

## 2. Architecture

```
Specialist Results (R38 contract, R39/R40/R41 + future)
        ↓
R43.1 Collaboration input      ai/schemas|knowledge/multi_agent_collaboration_input.py
        ↓
R43.2 Shared context           ai/schemas|knowledge/shared_research_context.py
        ↓
R43.3 Hypothesis correlation   ai/schemas|knowledge/hypothesis_correlation.py
        ↓                                             hypothesis_correlator.py
R43.4 Evidence merge           ai/schemas|knowledge/collaboration_evidence.py
        ↓                                             collaboration_evidence_merger.py
R43.4 Conflict analysis        ai/schemas|knowledge/collaboration_conflict.py
        ↓                                             collaboration_conflict_analyzer.py
R43.5 Ranking + unified result ai/schemas|knowledge/multi_agent_collaboration_result.py
                                                      multi_agent_collaboration_export.py
```

All components are deterministic, pure/offline, stateless, JSON
serializable and pydantic validated (`extra="forbid"`, forced rule versions,
`research_only=True`).

## 3. Collaboration input contract

`MultiAgentCollaborationInputPlan` (`r43-1`): `rule_version`,
`collaboration_rule_version`, `collaboration_id`, `participating_agents`,
`specialist_results`, `evaluation_results`, `shared_context`,
`collaboration_diagnostics`, `research_only`.

- Attribution per agent: `agent_id`, `agent_category`, `agent_rule_version`,
  `result_rule_version`, `research_only`, `provenance`.
- `collaboration_id` is a deterministic content token
  (`collab-<16 hex>`, SHA-256 over the sorted agent keys and shared-context
  digest) or a caller-supplied validated token. No timestamps, UUID
  generation, randomness or runtime ids.
- Results are normalized through the R42 evaluation input projection; no
  specialist-specific branches exist. A generic wrapper
  (`{"specialist_result": ..., "agent_id": ..., "agent_category": ...}`)
  supplies attribution for result contracts without identity (R39).
- Malformed results are preserved with structural flags and structured
  diagnostics: `MALFORMED_SPECIALIST_RESULT`, `MISSING_AGENT_IDENTITY`,
  `DUPLICATE_AGENT_ID`, `UNKNOWN_AGENT_CATEGORY`, `MISSING_PROVENANCE`,
  `INVALID_EVALUATION_RESULT`, `EVALUATION_AGENT_MISMATCH`,
  `MISSING_SPECIALIST_RESULTS`, `NON_DETERMINISTIC_INPUT`. Nothing is
  silently discarded.

## 4. Shared context contract

`SharedResearchContextPlan` (`r43-2`): `asset_reference`,
`application_context`, `technology_context`, `input_surface_context`,
`observed_behavior_context`, `existing_research_context`, `source_layers`,
`authorization_context`, `governance_context`, `research_only`.

- Bounded flat blocks with secret-like value redaction; closed
  `SOURCE_LAYERS` vocabulary (`REASONING`, `MEMORY`, `LEARNING`, `STRATEGY`,
  `ORCHESTRATION`, `AUTHORIZATION`, `GOVERNANCE`) — references only, never
  implemented here.
- Deterministic merge: first non-empty value wins in input order, lists are
  unioned preserving first-seen order, source layers are emitted in
  canonical order. Inputs are never mutated.
- `shared_context_summary()` reports blocks present, fact count and source
  layers for the unified result.

## 5. Hypothesis correlation model

`HypothesisGroupPlan` (`r43-3`): `correlation_id`, `correlation_type`,
`hypothesis_references`, `participating_agents`, `shared_signals`,
`confidence_summary`, `member_count`.

Closed correlation types: `DUPLICATE`, `RELATED`, `INDEPENDENT`,
`CONFLICTING`, `UNKNOWN`. Deterministic pairwise rules over structured data
only (agent category, hypothesis type, supporting signals, normalized
subject reference):

- same category + same type + equal signals + equal subject → DUPLICATE;
- same category + same type + subset signals → RELATED;
- same category + same type + overlapping-but-incomparable signals →
  CONFLICTING;
- different categories sharing ≥1 signal or with the same type → RELATED
  (different vulnerability classes may be related without being duplicates);
- otherwise INDEPENDENT; unclassifiable/unknown-type pairs remain UNKNOWN
  (never merged).

Merge policy: DUPLICATE and CONFLICTING pairs always group; RELATED pairs
merge only while both sides are still singleton clusters, preventing one
generic signal from chaining unrelated specialists into a giant group.
Group type precedence: CONFLICTING > DUPLICATE > RELATED > INDEPENDENT >
UNKNOWN. Confidence summaries: `AGREE` / `DIVERGENT` / `CONFLICT` /
`UNKNOWN` (band distance ≥ 2 = CONFLICT).

## 6. Fingerprint/deduplication model

`hypothesis_fingerprint()` = `fp-<sha256[0:16]>` over normalized
`agent_category | hypothesis_type | sorted(signals) | subject_reference`.
Only structured data is used — no timestamps, random values, runtime ids or
memory addresses. Duplicates are grouped, never deleted: every original
hypothesis stays referenced with agent id, category, hypothesis index,
type, signals, confidence, priority, limitations and fingerprint.

## 7. Evidence merge model

`CollaborationEvidencePlan` (`r43-4`): `evidence_items`,
`evidence_state`, `confidence`, `limitations`, `research_only`. Each merged
item preserves `evidence_category`, `requirement_state` (`REQUIRED` /
`CONSIDERED` / `UNKNOWN`), `source_agents`, `hypothesis_references` (agent,
index, type) and `source_count`.

Equivalence-based deduplication: items merge only on the exact normalized
evidence category; distinct categories stay separate in first-appearance
order. Merged state is `COMPLETE` only when every source plan is complete,
`PARTIAL` otherwise, `UNKNOWN` when nothing can be planned. Every plan
records `NO_COLLECTION_PERFORMED`, `NO_NETWORK_REQUESTS`,
`NO_DATABASE_ACCESS`, `EVIDENCE_REQUIRED` (plus `INSUFFICIENT_CONTEXT` when
unknown). No evidence is collected.

## 8. Conflict model

`CollaborationConflictRecordPlan` (`r43-5`): `conflict_id`,
`conflict_type`, `subjects`, `conflicting_fields`, `resolution_state`,
`message`, `evidence_references`.

Closed conflict types: `CONFIDENCE_CONFLICT`, `CONTEXT_CONFLICT`,
`HYPOTHESIS_CONFLICT`, `EVIDENCE_STATE_CONFLICT`, `GOVERNANCE_CONFLICT`,
`PROVENANCE_CONFLICT`, `SAFETY_CONFLICT`, `UNKNOWN`. Resolution states:
`CONSISTENT`, `RECONCILABLE`, `UNRESOLVED`, `UNKNOWN`.

Deterministic detection over structured data (pairwise, both sides
preserved):

- confidence band distance ≥ 2 → confidence conflict; `RECONCILABLE` when
  one side has a substantially richer context, `UNKNOWN` when data is
  insufficient, else `UNRESOLVED`;
- same-category context divergence on a shared key → `UNRESOLVED`;
  three or more one-sided keys → `RECONCILABLE`;
- evidence-state distance ≥ 2 → `RECONCILABLE` when both sides planned
  items, `UNRESOLVED` when only one did;
- governance divergence (`REFERENCED` vs `UNKNOWN`) → `RECONCILABLE` for a
  valid R37 reference, otherwise `UNRESOLVED`;
- provenance divergence → `RECONCILABLE`/`UNKNOWN` by band;
- conflicting hypothesis groups and divergent duplicate confidences →
  hypothesis conflict;
- mixed `research_only` state or forbidden execution/confirmation claims →
  `SAFETY_CONFLICT` `UNRESOLVED`, with the offending agents preserved.

## 9. Evaluation-aware ranking

`CollaborationRankingPlan` (`r43-6`): `agent_id`, `agent_category`,
`priority_score`, `priority_rating`, `rank`, `factors`, `safety_state`,
`safety_bucket`, `evaluation_present`.

R42 evaluation results are consumed as structured signals only — never
recomputed, never interpreted as vulnerability probability, severity or
exploitability. Missing evaluation stays visible (`evaluation_present=False`
with a neutral-low evaluation factor). Invalid evaluations produce
diagnostics and never replace supplied data.

The priority score is a bounded 0–100 research/collaboration priority:

```
factors = confidence, best hypothesis priority, evaluation quality,
          evidence completeness, provenance completeness, governance
          state, safety state
```

Rankings are ordered by safety bucket first (SAFE, DEGRADED, FAILED), then
score, then agent id — so a critically unsafe result can never outrank a
safe research result regardless of numerical confidence. Safety caps:
FAILED → ≤ 39; DEGRADED → ≤ 74.

## 10. Fixed weights

```
SPECIALIST_CONFIDENCE     20%
HYPOTHESIS_PRIORITY       20%
EVALUATION_QUALITY        25%
EVIDENCE_COMPLETENESS     10%
PROVENANCE_COMPLETENESS    5%
GOVERNANCE_STATE           5%
SAFETY_STATE              15%
Total                    100%
```

Component maps: confidence/priority HIGH 100 / MEDIUM 70 / LOW 40 /
UNKNOWN 20; evidence COMPLETE 100 / PARTIAL 60 / UNKNOWN 20; provenance
COMPLETE 100 / PARTIAL 70 / UNKNOWN 20; governance referenced-ready 100 /
referenced-not-ready 70 / unknown 30; safety PASS 100 / DEGRADED 50 /
FAILED 0; missing evaluation 40. Weights are module constants, never
runtime-configurable.

## 11. Safety boundaries

- R43 modules import only `__future__`, `re`, `hashlib`, `json`, `pydantic`
  and `ai.schemas`/`ai.knowledge`. No network client, DNS, socket,
  subprocess, shell, browser automation, SQL/database client,
  sqlmap/nuclei, LLM, embedding, filesystem state, persistence, worker or
  scheduler.
- Inputs are only combined; no agent is executed. Forbidden
  execution/confirmation claims are preserved with attribution and surfaced
  as `SAFETY_CONFLICT`; they are never normalized into safe claims, and the
  result never asserts `vulnerability_confirmed`, `exploit_success`,
  `target_compromised` or `attack_executed`.

## 12. Governance behavior

`governance_summary` reports `referenced_agents`, `unknown_agents`,
`ready_agents`, `not_ready_agents` and state `CONSISTENT_REFERENCED` /
`MIXED` / `UNKNOWN`. UNKNOWN governance is never upgraded to ready, and
governance states are never invented. Conflicting governance states remain
visible and are surfaced by the conflict analyzer.

## 13. Provenance behavior

`provenance_summary` reports the union of declared source layers (canonical
layer order), complete/partial/unknown agents and state `COMPLETE` /
`PARTIAL` / `UNKNOWN`. Namespace layers outside the closed set are dropped,
never invented; provenance from one agent is never silently merged into
another agent's provenance. Agent-level provenance is preserved in
`participating_agents`.

## 14. R38 integration

R43 consumes valid R38-compatible structured results through the R42
evaluation input projection (which itself uses the R38 vocabularies for
categories and statuses). R38 itself was not modified, and R43 contains no
specialist-specific branches.

## 15. R42 integration

`evaluation_results` accepts R42 results via the R42 result sanitizer.
R42 scoring rules are not duplicated or recomputed; only `overall_score`,
`safety_state`, `hard_gate_state`, structural/safety dimension scores and
provenance/evaluation presence feed the ranking and safety bucket.

## 16. R35 boundary

R35 remains the orchestration-intelligence layer, answering "How should
research work be orchestrated?" R43 is the collaboration/result-synthesis
layer, answering "How do multiple research results relate and combine?"
R43 does not schedule, dispatch, or execute anything and does not modify
R35.

## 17. R39/R40/R41 participation

Verified in tests: XSS (R39, via the attribution wrapper), SSRF (R40) and
SQLi (R41) participate in the same collaboration with correct categories,
attribution, hypothesis groups, merged evidence and rankings. The mixed
rich collaboration evaluates all three with intact provenance/governance
summaries. R39's contract has no identity field and its rich result lacks
provenance, so the collaboration surfaces the related diagnostics while
preserving the result.

## 18. Backend integration decision

Decision: **standalone collaboration layer; no backend integration.** No
existing production consumer requires collaboration output, and the prompt
prefers standalone initially. `backend/asset_cve_matching.py` was not
modified (`git diff` clean); a test asserts the backend does not import or
call the collaboration layer, documenting the decision.

## 19. AST safety tests

`tests/test_multi_agent_collaboration_result.py` parses all 12 R43 modules
with `ast` and rejects forbidden imports (`subprocess`, `socket`, `http`,
`urllib`, `requests`, `httpx`, `aiohttp`, `asyncio`, `threading`,
`multiprocessing`, `concurrent`, `importlib`, `ctypes`, `shutil`, `ssl`,
`os`, `dns`, `selenium`, `playwright`, `pyppeteer`, `paramiko`, `sqlite3`,
`sqlalchemy`, `psycopg`, `psycopg2`, `pymysql`, `MySQLdb`, `sqlmap`,
`nuclei`, `curl`, `pycurl`) and forbidden calls (`__import__`, `eval`,
`exec`, `compile`, `open`, and dotted prefixes for subprocess/os/importlib/
socket/urllib/requests/httpx/database clients).

## 20. Determinism tests

`test_determinism` runs the mixed R39/R40/R41 collaboration three times and
asserts byte-identical JSON, plus absence of `timestamp`, `uuid` and
`runtime_id`. Additional tests assert deterministic collaboration ids,
fingerprints, group ordering, conflict ordering, evidence ordering and
input normalization. No runtime identity or wall-clock time exists anywhere
in R43.

## 21. Focused tests

| Suite | Tests |
|---|---|
| `tests/test_multi_agent_collaboration_input.py` (R43.1) | 19 |
| `tests/test_shared_research_context.py` (R43.2) | 14 |
| `tests/test_hypothesis_correlator.py` (R43.3) | 15 |
| `tests/test_collaboration_evidence_merger.py` (R43.4) | 12 |
| `tests/test_collaboration_conflict_analyzer.py` (R43.4) | 18 |
| `tests/test_multi_agent_collaboration_result.py` (R43.5) | 24 |
| **R43 total** | **102 passed** |

Coverage includes valid/malformed input, extra-field rejection,
deterministic ids, attribution, shared-context normalization, provenance
preservation, duplicate/related/independent/conflicting detection,
fingerprinting, grouping without deletion, evidence merge/dedup/attribution,
confidence/context/governance/safety/provenance conflicts,
evaluation-aware ranking, fixed weights, the ranking safety boundary,
R39/R40/R41 participation, missing/invalid evaluations, unknown
category/governance, deterministic serialization and repeated-run equality,
unsafe-input preservation and forbidden-claim detection.

## 22. Regression tests

```
R43 focused suites                                        102 passed
R38 suites                                                132 passed
R39 suites                                                100 passed
R40 suites                                                122 passed
R41 suites                                                131 passed
R42 suites                                                 91 passed
All tests referencing r31- … r42- (76 files)  1958 passed, 27 subtests
tests/test_asset_cve_matching.py               79 passed, 13 subtests
```

## 23. Full-suite results

```
python -m pytest tests/ -q
R42 baseline:  3727 passed, 40 failed, 376 subtests passed
R43 result:    3829 passed, 40 failed, 376 subtests passed
```

The +102 equals exactly the new R43 tests. R43 modifies no existing module,
so no stash comparison is required; `git diff` shows no tracked change.

## 24. Existing failure comparison

The sorted `FAILED` line sets before and after R43 are byte-identical
(`diff` clean). The 40 pre-existing failures are the money-score/economics
corpus-drift failures present since before R40; none was modified or
"fixed".

## 25. Git commit hash

Commit message: `feat(research): add r43 multi-agent collaboration layer`.
Hash is reported in the final response after the local commit (the report is
part of the same commit; no amend and no push).

## 26. Git status

Unrelated pre-existing worktree items remain outside the R43 commit and were
not modified: ` D utils.zip`, `?? watch.zip`,
`?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`. No tracked file is
modified by R43; `git diff --check` is clean.

## 27. Known limitations

- R43 correlates structural contracts; it cannot judge whether two
  differently-typed hypotheses are semantically equivalent beyond the
  declared structured attributes.
- Hypothesis grouping is intentionally conservative: RELATED merges only
  singletons, so large mixed collaborations usually produce several small
  groups rather than one cluster.
- The priority score ranks research direction quality/urgency for
  collaboration; it must not be used as severity, exploitability or
  vulnerability likelihood.
- Evidence merging is category-level; item-to-hypothesis mapping is
  preserved only as far as the source result supplies it.
- Governance/provenance summaries describe supplied references; they do not
  validate the truth of those references.

## 28. No-execution statement

Explicitly: R43 contains no execution capability of any kind. There is no
agent execution, subprocess, shell, HTTP/network request, DNS resolution,
database connection, SQL execution, JavaScript execution, payload
generation or execution, sqlmap/nuclei invocation, browser automation,
external API call, LLM call, persistence, worker or scheduler anywhere in
R43. The collaboration layer reads structured artifacts, correlates them
deterministically, and emits a unified research view.

## Agent / Model

- Model: deepseek-v4.1-flash
- Stage: R43
- Role: coding agent
