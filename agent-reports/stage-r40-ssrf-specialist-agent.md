# Stage R40 — SSRF Specialist Agent

The first second specialist security agent built on the Watch AI Core: a
deterministic, research-only SSRF intelligence agent. It classifies bounded
SSRF context, plans review hypotheses and evidence, and produces an
R38-compatible result with R37 governance and R31–R37 provenance references.

R40 executes nothing. There are no HTTP/network requests, DNS resolution,
localhost/private-IP connections, port scans, URL probes, payload execution,
metadata access, redirect following, sockets, subprocesses, shells, browser
automation, external APIs, LLM calls, persistence, workers or schedulers.

- Stage: R40
- Rule versions: `r40-1` … `r40-5`
- Commit: `feat(research): add r40 ssrf specialist agent` (local only, not
  pushed; hash reported in the final response)

## 1. Objective

Implement the SSRF specialist agent as a native extension of the R38
framework: use R38 contracts, reuse R31–R37 intelligence/control/governance
boundaries, accept structured SSRF research context, and emit a bounded,
deterministic, explainable result — without executing any SSRF activity.
R40 does not blindly copy R39/XSS semantics; it introduces SSRF-specific
vocabularies, a fetch-observation safety cap, and SSRF review hypotheses.

## 2. Architecture

```
SSRF Agent Identity (r40-1)            ai/schemas|knowledge/ssrf_agent_identity.py
        ↓
SSRF Context Analyzer (r40-2)          ai/schemas|knowledge/ssrf_context_analysis.py
        ↓                                                    ssrf_context_analyzer.py
SSRF Hypothesis Planner (r40-3)        ai/schemas|knowledge/ssrf_hypothesis.py
        ↓                                                    ssrf_hypothesis_planner.py
SSRF Evidence Planner (r40-4)          ai/schemas|knowledge/ssrf_evidence_plan.py
        ↓                                                    ssrf_evidence_planner.py
SSRF Specialist Result (r40-5)         ai/schemas|knowledge/ssrf_agent_result.py
        ↓                                                    ssrf_agent_result_export.py
R38-compatible result + R37 governance reference + R31–R37 provenance
```

All components are deterministic, pure/offline, stateless, JSON
serializable, pydantic validated (`extra="forbid"`, forced rule versions,
`research_only=True`).

## 3. Files created

```
ai/schemas/ssrf_agent_identity.py
ai/schemas/ssrf_context_analysis.py
ai/schemas/ssrf_hypothesis.py
ai/schemas/ssrf_evidence_plan.py
ai/schemas/ssrf_agent_result.py
ai/knowledge/ssrf_agent_identity.py
ai/knowledge/ssrf_context_analyzer.py
ai/knowledge/ssrf_hypothesis_planner.py
ai/knowledge/ssrf_evidence_planner.py
ai/knowledge/ssrf_agent_result_export.py
tests/test_ssrf_agent_identity.py
tests/test_ssrf_context_analyzer.py
tests/test_ssrf_hypothesis_planner.py
tests/test_ssrf_evidence_planner.py
tests/test_ssrf_agent_result.py
agent-reports/stage-r40-ssrf-specialist-agent.md
```

## 4. Files modified

```
backend/asset_cve_matching.py   (+14 lines, additive only)
```

No R31–R39 file was modified.

## 5. SSRF context vocabulary

`SSRFContextAnalysisPlan` fields and closed vocabularies:

- `input_location`: `QUERY`, `BODY`, `HEADER`, `COOKIE`, `PATH`,
  `UNKNOWN`
- `url_handling`: `FULL_URL`, `HOST_ONLY`, `PATH_OR_URL`,
  `REDIRECT_TARGET`, `WEBHOOK_TARGET`, `RESOURCE_URL`, `UNKNOWN`
- `server_side_fetch`: `OBSERVED`, `NOT_OBSERVED`, `UNKNOWN`
- `protocol_context`: `HTTP`, `HTTPS`, `FILE`, `FTP`, `GOPHER`, `OTHER`,
  `UNKNOWN`
- `redirect_behavior`: `FOLLOWED`, `NOT_FOLLOWED`, `UNKNOWN`
- `hostname_validation` / `ip_validation` / `allowlist_behavior`:
  `PRESENT`, `ABSENT`, `UNKNOWN`
- `encoding_behavior`: `NORMALIZED`, `ENCODED`, `PARTIAL`, `UNKNOWN`
- `context_confidence`: shared `HIGH`/`MEDIUM`/`LOW`/`UNKNOWN`

Malformed or missing observations degrade to `UNKNOWN`; nothing is promoted.

## 6. Confidence logic

Confidence is a pure function of supplied facts with a hard SSRF safety cap:

- base by known-fact count: ≥8 → HIGH, 5–7 → MEDIUM, 2–4 → LOW, 0–1 →
  UNKNOWN;
- **unless `server_side_fetch == OBSERVED`, confidence can never exceed
  LOW.**

Consequences, verified by tests:

- A lone URL parameter (`input_location` + `url_handling`) yields LOW, and
  `server_side_fetch_confirmed()` is False while `ssrf_input_possible()` is
  True. Possible SSRF-relevant input is never equated with a confirmed
  server-side fetch.
- `NOT_OBSERVED` and `UNKNOWN` fetch states are capped at LOW.
- Only a fully specified context with an observed fetch can reach HIGH.

`ssrf_context_confidence_of()` recomputes confidence from bounded
observations so partial context dicts supplied directly to downstream
planners receive the correct, capped value.

## 7. Hypothesis types

`SSRFHypothesisPlan`: `rule_version`, `hypothesis_type`,
`supporting_signals[]`, `confidence`, `priority`, `limitations`,
`research_only`.

Types (closed): `SERVER_SIDE_FETCH_ANALYSIS`, `URL_VALIDATION_REVIEW`,
`IP_VALIDATION_REVIEW`, `REDIRECT_HANDLING_REVIEW`,
`PROTOCOL_HANDLING_REVIEW`, `DNS_REBINDING_REVIEW`,
`INTERNAL_ADDRESS_RESTRICTION_REVIEW`, `CLOUD_METADATA_BOUNDARY_REVIEW`,
`WEBHOOK_FETCH_REVIEW`, `UNKNOWN`.

Deterministic mapping highlights:

- observed fetch → `SERVER_SIDE_FETCH_ANALYSIS` HIGH/MEDIUM; a URL
  parameter without observed fetch → same review at LOW only;
- absent hostname/IP/allowlist validation → validation review hypotheses;
- redirect targets / followed redirects → redirect review;
- non-HTTP schemes (`FILE`, `FTP`, `GOPHER`, `OTHER`) → protocol review;
- hostname check missing with IP check present → DNS rebinding review;
- both checks missing → internal address restriction review;
- both checks missing plus observed fetch and no allowlist → cloud metadata
  boundary review (a review hypothesis only — no endpoints, no URLs);
- webhook targets → webhook fetch review.

Every hypothesis explicitly carries `NO_EXPLOIT_CLAIM`,
`NO_VULNERABILITY_CONFIRMATION`, `HYPOTHESIS_ONLY`, `EVIDENCE_REQUIRED`
(and `INSUFFICIENT_CONTEXT` when unknown). Priority mirrors confidence. No
payload, endpoint, IP address, or exploitation instruction is ever emitted.

## 8. Evidence categories

`SSRFEvidencePlan`: `rule_version`, `evidence_items[]`, `evidence_state`,
`confidence`, `limitations`, `research_only`.

Categories (closed): `SERVER_FETCH_BEHAVIOR`, `URL_PARSING_CONTEXT`,
`HOST_VALIDATION`, `IP_RANGE_VALIDATION`, `REDIRECT_POLICY`,
`PROTOCOL_RESTRICTION`, `DNS_RESOLUTION_BEHAVIOR`,
`DESTINATION_RESTRICTION`, `APPLICATION_BEHAVIOR`,
`CLOUD_BOUNDARY_CONTEXT`, `UNKNOWN`.

Planning only:

- per-hypothesis fixed mappings produce an ordered, deduplicated required
  category list; hypotheses are derived when omitted;
- `COMPLETE` only for a fully specified observed-fetch context with no
  `UNKNOWN` hypothesis; `PARTIAL` otherwise; `UNKNOWN` when nothing can be
  planned;
- every plan records `NO_COLLECTION_PERFORMED`, `NO_NETWORK_REQUESTS`,
  `NO_DNS_RESOLUTION`, `EVIDENCE_REQUIRED`. No evidence is collected.

## 9. R38 integration

- **Identity**: uses R38 `CATEGORY_SSRF`, `AGENT_ID_RE` and the R38
  content-token id function. `supported_capabilities` are restricted to the
  R38 analysis-only vocabulary — prohibited execution capabilities are
  rejected by the schema and filtered by the planner. `lifecycle_state` is
  restricted to the identity states `CREATED`/`PLANNED` (no runtime state).
  `ssrf_agent_identity_to_r38()` projects onto a valid R38
  `SecurityAgentIdentityPlan` (verified by constructing the R38 model).
- **Input contract**: `export_ssrf_agent_result(security_agent_input=...)`
  routes context through R38's `validate_security_agent_input`; an R38
  identity block for category `SSRF` is adopted deterministically.
- **Result compatibility**: status/confidence reuse the R38 vocabularies and
  `ssrf_agent_result_to_r38()` maps hypotheses → `HYPOTHESES_RECORDED` and
  the evidence state → the R38 evidence summary through R38's
  `validate_security_agent_result`, producing a valid
  `SecurityAgentResultPlan`.

## 10. R31–R37 integration

- All R31–R37 context enters exclusively through the R38 read-only input
  contract (`research_context`, `memory_context`, `strategy_context`,
  `orchestration_context`, `authorization_context`, `governance_context`);
  no layer is called directly and no layer is mutated.
- R37 governance is consumed through the bounded governance reference
  (section 11).
- The result records which layers were actually supplied
  (`provenance.source_layers`), giving deterministic provenance without
  inventing data. R33 learning is consumed indirectly through the R31
  reasoning / R32 memory contexts, since the R38 input contract has no
  separate learning block.

## 11. Governance/provenance behavior

- `governance_reference`: fixed keys `rule_version`, `ready`,
  `provenance_state`, `trace_state`, `audit_state`, `explanation_state`,
  `reference_state`. A reference is `REFERENCED` only for a real R37 export
  (`r37-5` plus all four component records); missing, malformed, foreign or
  component-less plans degrade to `UNKNOWN` with `ready=False` and force the
  `GOVERNANCE_UNKNOWN` limitation. Component states are validated against
  the closed R37 vocabularies.
- `provenance`: fixed keys `rule_version`, `source_layers`,
  `provenance_state`, `research_only`; state `COMPLETE` when all six layers
  were supplied, `PARTIAL` when some, `UNKNOWN` when none.

## 12. Backend integration

Additive change only in `backend/asset_cve_matching.py` (14 lines: one
import, two summary fields, comment), following the exact R39 pattern:

```python
summary["ssrf_agent_plan"] = export_ssrf_agent_result()
summary["ssrf_agent_plan_rule_version"] = (
    SSRF_AGENT_RESULT_EXPORTER_RULE_VERSION
)
```

No existing field was renamed, removed or reordered; R38/R39 fields remain
intact and no R31–R39 logic was touched. Live check through `build_matches`
returns `status="CREATED"`, `rule_version="r40-5"`, `research_only=True`,
`NO_NETWORK_REQUESTS`/`NO_DNS_RESOLUTION` limitations and an `UNKNOWN`
governance reference.

## 13. Safety boundary

- R40 modules import only `__future__`, `re`, `pydantic` and
  `ai.schemas`/`ai.knowledge`. No network client, DNS library, socket,
  subprocess, shell, browser automation, LLM, embedding, Mongo or
  filesystem state.
- An AST test rejects forbidden imports (`subprocess`, `socket`, `http`,
  `urllib`, `requests`, `httpx`, `aiohttp`, `asyncio`, `dns`, `importlib`,
  `ctypes`, `ssl`, `selenium`, `playwright`, `curl`, `os`, …) and forbidden
  calls (`__import__`, `eval`, `exec`, `compile`, `open`,
  `subprocess.*`, `os.system`, `os.popen`, `socket.*`, `urllib.*`,
  `requests.*`, `httpx.*`, `dns.*`) across all 10 R40 modules.
- Not implemented (by design): HTTP/network requests, DNS resolution,
  localhost/private-IP connection, port scanning, URL probing, SSRF payload
  execution or generation, auth bypass, cloud metadata access, internal
  service access, redirect following, curl/wget/httpx/requests/browser
  automation, subprocess/shell, sockets, external APIs, LLM calls,
  persistence, workers, schedulers, autonomous execution.
- No systemd, Docker, deployment or VM configuration was created or
  modified. Nothing was pushed.

## 14. Tests

| Suite | Tests |
|---|---|
| `tests/test_ssrf_agent_identity.py` (R40.1) | 19 |
| `tests/test_ssrf_context_analyzer.py` (R40.2) | 24 |
| `tests/test_ssrf_hypothesis_planner.py` (R40.3) | 25 |
| `tests/test_ssrf_evidence_planner.py` (R40.4) | 25 |
| `tests/test_ssrf_agent_result.py` (R40.5) | 29 |
| **R40 total** | **122 passed** |

Coverage includes: deterministic identity; R38 category/id conformance;
capability restrictions (prohibited codes rejected/filtered); lifecycle
restriction; valid R38 input contract; deterministic context
classification; confidence calculation including the observed-fetch cap and
the possible-input vs confirmed-fetch distinction; hypothesis generation
and ordering; safety flags; evidence planning and states; governance
handling; provenance preservation; result contract compliance and R38
projection; limitation preservation; unknown/invalid input behavior;
backend additive integration; and the safety AST scan.

## 15. Regression results

```
R40 focused suites                                        122 passed
R38 suites                                                132 passed
All tests referencing r31- … r39- (60 files)  1613 passed, 27 subtests
tests/test_asset_cve_matching.py               79 passed, 13 subtests
```

## 16. Full-suite results

```
python -m pytest tests/ -q
R39 baseline:  3383 passed, 40 failed, 376 subtests passed
R40 result:    3505 passed, 40 failed, 376 subtests passed
```

The +122 equals exactly the new R40 tests, and the sorted `FAILED` line
sets are byte-identical (`diff` clean): no new failure and no existing
failure was altered. Re-running the full suite with the R40 backend diff
stashed yields 3504 passed / 41 failed, where the single extra failure is
`tests/test_ssrf_agent_result.py::test_backend_additive_integration` —
proving the backend change is additive and that existing behavior is
unaffected. The 40 pre-existing failures are the money-score/economics
corpus-drift failures present since before R40.

## 17. Git commit hash

Commit message: `feat(research): add r40 ssrf specialist agent`. Hash is
reported in the final response after the local commit (the report is part
of the same commit; no amend and no push).

## 18. Git status

Unrelated pre-existing worktree items remain outside the R40 commit and
were not modified: ` D utils.zip`, `?? watch.zip`,
`?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`.

## 19. Known limitations

- R40 is a research/planning model only: it does not observe real traffic,
  fetch URLs, resolve DNS, or validate any hypothesis. Evidence categories
  are plans, not collected evidence.
- Confidence describes context completeness under the observed-fetch cap,
  not the likelihood that SSRF exists.
- Cloud metadata boundary review is a review hypothesis only; no endpoint,
  address or payload is ever emitted.
- The result is deterministic given bounded inputs; it does not model
  application-specific URL parsers beyond the declared vocabularies.
- `COMPLETED` means the evidence plan is fully specified for a fully
  specified observed context; it is not a vulnerability confirmation.

## 20. No network/exploit execution statement

Explicitly: R40 contains no network capability and no exploit capability.
There is no HTTP/network request, DNS resolution, socket usage, localhost or
private-IP connection, port scan, URL probe, payload generation or
execution, metadata access, redirect following, subprocess/shell, browser
automation, external API call, LLM call, persistence, worker or scheduler
anywhere in R40. The agent analyzes structured context, plans hypotheses
and evidence, and emits a structured research result.

## Agent / Model

- Model: deepseek-v4.1-flash
- Stage: R40
- Role: coding agent
