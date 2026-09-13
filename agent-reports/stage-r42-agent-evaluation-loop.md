# Stage R42 — Agent Evaluation Loop

A deterministic, research-only evaluation layer for structured security
agent outputs. R42 judges the quality, completeness, safety and consistency
of results produced by R38/R39/R40/R41 (and future specialists). It does not
execute agents, does not perform security testing, and does not answer
whether a vulnerability is real or exploitable.

- Stage: R42
- Rule versions: `r42-1` … `r42-5`
- Commit: `feat(research): add r42 agent evaluation loop` (local only, not
  pushed; hash reported in the final response)

## 1. Objective

Introduce an evaluation layer that answers:

- Is the agent output structurally valid?
- Is the context analysis complete enough?
- Are hypotheses supported by supplied signals?
- Is the evidence plan sufficient?
- Is confidence appropriately calibrated?
- Are safety boundaries preserved?
- Is provenance present?
- Is governance state visible?
- Is the output deterministic?
- Are unsupported claims avoided?

R42 is generic across specialists: the same rules evaluate XSS, SSRF, SQLi
and future agent categories through the common result contract.

## 2. Architecture

```
Agent result (R38/R39/R40/R41, generic contract)
        ↓
R42.1 Evaluation input        ai/schemas|knowledge/agent_evaluation_input.py
        ↓
R42.2 Evaluation rules        ai/schemas|knowledge/agent_evaluation_rule.py
        ↓                                             agent_evaluation_rules.py
R42.3 Dimension scores        ai/schemas|knowledge/agent_evaluation_score.py
        ↓                                             agent_evaluation_scorer.py
R42.4 Diagnostics             ai/schemas|knowledge/agent_evaluation_diagnostic.py
        ↓                                             agent_evaluation_diagnostics.py
R42.5 Evaluation result       ai/schemas|knowledge/agent_evaluation_result.py
                                                      agent_evaluation_export.py
```

All components are deterministic, pure/offline, stateless, JSON
serializable and pydantic validated (`extra="forbid"`, forced rule versions,
`research_only=True` on the evaluation result).

## 3. Evaluation input contract

`AgentEvaluationInputPlan` (r42-1) is a bounded, read-only projection:

- `agent_id`, `agent_category`, `agent_rule_version`,
  `result_rule_version`, `result_status`, `result_confidence`
- `context_analysis`, `hypotheses`, `evidence_plan`, `limitations`
- `provenance`, `governance_reference`
- `research_only` (preserved as supplied, including `False`)
- `structural_flags` (closed set of deterministic quality flags)

`build_agent_evaluation_input()` accepts a plain R38-compatible result or a
specialist result and records structural flags for missing fields, invalid
rule versions, invalid enums, unknown categories, malformed hypotheses,
evidence plans, provenance, governance, limitations, invented provenance
layers and non-deterministic markers (for example `timestamp`, `created_at`,
`runtime_id`, `uuid`). Malformed input never silently becomes valid.
Explicit `agent_id`/`agent_category` overrides are supported for result
contracts that do not expose an identity (R39).

## 4. Evaluation dimensions

| Dimension | What it evaluates |
|---|---|
| STRUCTURAL_VALIDITY | required fields, valid enums/rule versions, well-formed hypotheses/evidence, known category |
| CONTEXT_COMPLETENESS | how many structured context facts were preserved (not vulnerability presence) |
| HYPOTHESIS_SUPPORT | supporting signals exist, type/confidence consistency, per-hypothesis safety limitations |
| EVIDENCE_COMPLETENESS | evidence requirements planned, `EVIDENCE_REQUIRED` preserved, state/confidence consistent |
| CONFIDENCE_CALIBRATION | confidence compatible with context completeness in both directions |
| SAFETY_COMPLIANCE | `research_only`, required non-execution limitations, no execution claim, no vulnerability confirmation claim |
| PROVENANCE_COMPLETENESS | provenance present, state/layers consistent, no invented layers |
| GOVERNANCE_COMPLETENESS | reference present/visible, no false ready state, no invented governance |
| DETERMINISM | no non-deterministic markers, rule versions present |
| LIMITATION_DISCLOSURE | limitations disclosed, non-execution boundary stated |

## 5. Rule vocabulary

32 closed rule codes across the ten dimensions (for example
`REQUIRED_FIELDS_PRESENT`, `SIGNALS_PRESENT`, `EVIDENCE_ITEMS_PRESENT`,
`CONFIDENCE_MATCHES_CONTEXT`, `RESEARCH_ONLY`, `NO_EXECUTION_CLAIMS`,
`NO_VULNERABILITY_CONFIRMATION`, `OUTPUT_DETERMINISTIC`,
`NON_EXECUTION_DISCLOSED`). Each dimension outcome carries `score`,
`passed_rules`, `failed_rules`, `reasons` and bounded diagnostic references.
Rule codes are validated against the closed set.

## 6. Score model

Each dimension receives a bounded 0–100 score and a band:

```
90–100  EXCELLENT
75–89   GOOD
60–74   ACCEPTABLE
40–59   WEAK
0–39    CRITICAL
```

The score represents quality of research output only. It is explicitly NOT
a probability of vulnerability, exploitability, severity, CVSS or likelihood
of compromise. Confidence calibration is interpreted as context/research
confidence, never as vulnerability probability.

## 7. Fixed weights

```
STRUCTURAL_VALIDITY       15%
CONTEXT_COMPLETENESS      10%
HYPOTHESIS_SUPPORT        15%
EVIDENCE_COMPLETENESS     10%
CONFIDENCE_CALIBRATION    15%
SAFETY_COMPLIANCE         15%
PROVENANCE_COMPLETENESS    5%
GOVERNANCE_COMPLETENESS    5%
DETERMINISM                5%
LIMITATION_DISCLOSURE      5%
Total                    100%
```

Weights are module constants; they are not configurable at runtime. The
overall score is a deterministic half-up weighted sum, then capped by hard
gates.

## 8. Hard gates

- STRUCTURAL_VALIDITY < 40 → overall capped at WEAK (`CEILING_STRUCTURAL`).
- SAFETY_COMPLIANCE score < 40, `research_only=False`, or a vulnerability
  confirmation claim → safety `FAILED`, overall capped at CRITICAL
  (`FAIL_SAFETY`).
- Execution claim or safety score 40–74 → safety `DEGRADED`, overall capped
  at ACCEPTABLE (`CEILING_SAFETY`).
- `applied_caps` lists every applied gate in deterministic order; multiple
  gates use the lowest cap. `hard_gate_state` follows precedence
  `FAIL_SAFETY` > `CEILING_SAFETY` > `CEILING_STRUCTURAL` > `PASS`.

## 9. Diagnostics

`AgentEvaluationDiagnosticPlan` (r42-4): `diagnostic_code`, `dimension`,
`severity`, `message`, `evidence_reference`, `remediation_hint`. There are 28
closed diagnostic codes (`MISSING_REQUIRED_FIELD`, `CONTEXT_TOO_SPARSE`,
`UNSUPPORTED_HYPOTHESIS`, `CONFIDENCE_OVERSTATED`,
`VULNERABILITY_CONFIRMATION_CLAIM`, `GOVERNANCE_INCONSISTENT`,
`NON_DETERMINISTIC_OUTPUT`, …), five severities (`INFO`, `LOW`, `MEDIUM`,
`HIGH`, `CRITICAL`) and fixed message/remediation text. Unknown codes are
dropped; duplicates are removed; ordering is deterministic (dimension order,
then code, then evidence reference). Diagnostics explain quality problems
only and contain no exploit instructions or payloads.

## 10. Result contract

`AgentEvaluationResultPlan` (r42-5): `rule_version` and
`evaluation_rule_version`, `evaluated_agent_id`,
`evaluated_agent_category`, `evaluated_agent_rule_version`,
`evaluated_result_rule_version`, `overall_score`, `overall_rating`,
`dimension_scores`, `diagnostics`, `hard_gate_state`, `safety_state`,
`applied_caps`, `deterministic`, `research_only`, `limitations`. Result
limitations always include `NO_EXECUTION_PERFORMED`, `NO_NETWORK_REQUESTS`,
`NO_EVIDENCE_COLLECTED`, `NO_VULNERABILITY_CONFIRMATION` and
`QUALITY_EVALUATION_ONLY`. `deterministic` and `research_only` are always
true.

## 11. R38 integration

Evaluation input accepts R38-compatible results and normalizes them without
bypassing validation; malformed fields are flagged, never silently accepted.
The evaluator reuses R38 closed vocabularies (`AGENT_CATEGORIES`,
`AGENT_RESULT_STATUSES`) and the shared confidence vocabulary. R38 itself was
not modified.

## 12. R31–R37 boundary

R42 does not call R31–R37. It evaluates the provenance and governance fields
already present in the structured result, and validates referenced governance
against the R37 export rule version as a generic contract compatibility
check. No reasoning, memory, learning, strategy, orchestration,
authorization or governance logic is duplicated.

## 13. R39 evaluation

`export_xss_agent_result()` results evaluate successfully. Because the R39
result contract does not expose `agent_identity` or `provenance` and omits an
aggregate `EVIDENCE_REQUIRED` limitation, an R39 result evaluated without
overrides reports `UNKNOWN_AGENT_CATEGORY`, `MISSING_REQUIRED_FIELD` and
`PROVENANCE_INCOMPLETE`. With explicit `agent_id`/`agent_category` overrides
the rich XSS result scores 89/GOOD (structural 75, provenance 30,
governance 60/UNKNOWN). This is exactly the kind of contract gap R42 is
designed to surface; R42 contains no XSS-specific logic.

## 14. R40 evaluation

`export_ssrf_agent_result()` rich results evaluate to 95/EXCELLENT, category
`SSRF`, safety PASS, hard gate PASS.

## 15. R41 evaluation

`export_sqli_agent_result()` rich results evaluate to 95/EXCELLENT, category
`SQLI`, safety PASS, hard gate PASS. Parameterized full-context results
report the expected confidence/evidence calibration behavior, since their
context confidence is capped at MEDIUM by the SQLi agent itself.

## 16. Backend integration decision

Decision: **standalone evaluation layer; no backend integration.** Both
backend prompts permit this explicitly. Adding evaluation into
`build_matches` would execute a second full rules pass per summary for every
CVE item without a current consumer, and no production path consumes
evaluation output today. `backend/asset_cve_matching.py` was not modified;
`git diff` shows no tracked change. A test asserts the backend does not
import or call the evaluation layer, documenting the decision.

## 17. Safety boundary

- R42 modules import only `__future__`, `re`, `pydantic` and
  `ai.schemas`/`ai.knowledge`. No network client, socket, subprocess, shell,
  browser automation, SQL/database client, sqlmap/nuclei, LLM, embedding,
  filesystem state, persistence, worker or scheduler.
- Not implemented (by design): HTTP/network requests, DNS resolution,
  database connections, SQL execution, JavaScript execution, payload
  execution or generation, sqlmap/nuclei invocation, curl/wget/httpx/
  requests, subprocess/shell, sockets, browser automation, external APIs,
  LLM calls, runtime state, workers, schedulers, target modification.
- R42 evaluates structured output only; it does not independently perform
  security testing and does not confirm or deny vulnerabilities.

## 18. AST safety tests

`tests/test_agent_evaluation_result.py` parses all 10 R42 modules with `ast`
and rejects forbidden imports (`subprocess`, `socket`, `http`, `urllib`,
`requests`, `httpx`, `aiohttp`, `asyncio`, `threading`, `multiprocessing`,
`concurrent`, `importlib`, `ctypes`, `shutil`, `ssl`, `os`, `dns`,
`selenium`, `playwright`, `pyppeteer`, `paramiko`, `sqlite3`, `sqlalchemy`,
`psycopg`, `psycopg2`, `pymysql`, `MySQLdb`, `sqlmap`, `nuclei`, `curl`,
`pycurl`) and forbidden calls (`__import__`, `eval`, `exec`, `compile`,
`open`, and the corresponding dotted prefixes).

## 19. Determinism tests

`test_determinism_of_full_evaluation` evaluates the exact same R41 rich
result three times and asserts byte-identical JSON, identical scores,
identical diagnostics, identical rating and identical rule version; the
serialized output contains no `timestamp` string. Additional tests assert
deterministic input projection, rule outcomes, diagnostics and scorer
output. No timestamps, randomness or runtime ids exist anywhere in R42.

## 20. Focused tests

| Suite | Tests |
|---|---|
| `tests/test_agent_evaluation_input.py` (R42.1) | 21 |
| `tests/test_agent_evaluation_rules.py` (R42.2) | 20 |
| `tests/test_agent_evaluation_scorer.py` (R42.3) | 15 |
| `tests/test_agent_evaluation_diagnostics.py` (R42.4) | 14 |
| `tests/test_agent_evaluation_result.py` (R42.5) | 21 |
| **R42 total** | **91 passed** |

Coverage includes valid R38/specialist input, malformed input, required
fields, structural validity, context completeness, hypothesis support,
evidence completeness, confidence calibration, safety compliance (including
`research_only=False`, execution claims, confirmation claims), provenance,
governance, determinism, limitation disclosure, score boundaries, overall
score, fixed weights, hard gates, diagnostic generation and ordering,
serialization, R39/R40/R41 evaluation, unknown category, backend decision
and the AST safety scan.

## 21. Regression tests

```
R42 focused suites                                         91 passed
R38 suites                                                132 passed
R39 suites                                                100 passed
R40 suites                                                122 passed
R41 suites                                                131 passed
All tests referencing r31- … r41- (72 files)  1899 passed, 27 subtests
tests/test_asset_cve_matching.py               79 passed, 13 subtests
```

## 22. Full-suite results

```
python -m pytest tests/ -q
R41 baseline:  3636 passed, 40 failed, 376 subtests passed
R42 result:    3727 passed, 40 failed, 376 subtests passed
```

The +91 equals exactly the new R42 tests. R42 modifies no backend or
existing module, so no stash comparison is required; `git diff` shows no
tracked change.

## 23. Existing failure comparison

The sorted `FAILED` line sets before and after R42 are byte-identical
(`diff` clean). The 40 pre-existing failures are the money-score/economics
corpus-drift failures present since before R40; none was modified or
"fixed".

## 24. Git commit hash

Commit message: `feat(research): add r42 agent evaluation loop`. Hash is
reported in the final response after the local commit (the report is part of
the same commit; no amend and no push).

## 25. Git status

Unrelated pre-existing worktree items remain outside the R42 commit and were
not modified: ` D utils.zip`, `?? watch.zip`,
`?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`. No tracked file is
modified by R42; `git diff --check` is clean.

## 26. Known limitations

- R42 evaluates contract-level quality, not ground truth: a well-formed
  result can still be based on incomplete real-world observations.
- Context completeness counts known structured facts; it does not judge
  whether those facts are the right ones for the vulnerability class.
- Hypothesis support checks structural signal presence and consistency; it
  cannot verify specialist semantics without specialist-specific logic,
  which is deliberately excluded from R42.
- Governance scoring treats visible UNKNOWN governance as a quality gap, not
  a failure; a valid-but-not-ready R37 export is referenced without
  inventing readiness.
- Evaluation results are quality artifacts; they must not be used as
  vulnerability verdicts, severity scores or attack decisions.

## 27. No-execution statement

Explicitly: R42 contains no execution capability of any kind. There is no
HTTP or network request, DNS resolution, database connection, SQL execution,
JavaScript execution, payload generation or execution, sqlmap/nuclei
invocation, subprocess/shell, socket, browser automation, external API call,
LLM call, persistence, worker or scheduler anywhere in R42. The evaluation
loop reads structured data, applies deterministic rules, and emits a
structured quality assessment.

## Agent / Model

- Model: deepseek-v4.1-flash
- Stage: R42
- Role: coding agent
