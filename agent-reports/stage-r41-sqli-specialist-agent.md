# Stage R41 — SQLi Specialist Agent

The third specialist security agent built on the Watch AI Core: a
deterministic, research-only SQL Injection intelligence agent. It classifies
bounded SQLi context, plans review hypotheses and evidence, and produces an
R38-compatible result with R37 governance and R31–R37 provenance references.

R41 executes nothing. There is no SQL execution, database connection, SQL
payload generation or storage, HTTP/network request, fuzzing, parameter
brute forcing, sqlmap invocation, subprocess, shell, socket, browser
automation, external API, LLM call, persistence, worker or scheduler.

- Stage: R41
- Rule versions: `r41-1` … `r41-5`
- Commit: `feat(research): add r41 sqli specialist agent` (local only, not
  pushed; hash reported in the final response)

## 1. Objective

Implement the SQL Injection specialist agent as a native extension of the
R38 framework, proving the specialist-agent architecture is reusable across
materially different vulnerability classes. R41 uses its own bounded SQLi
vocabulary and reasoning model — it does not copy XSS or SSRF semantics — and
emits a bounded, deterministic, explainable research result without
executing any SQL or contacting any database.

## 2. Architecture

```
SQLi Agent Identity (r41-1)            ai/schemas|knowledge/sqli_agent_identity.py
        ↓
SQLi Context Analyzer (r41-2)          ai/schemas|knowledge/sqli_context_analysis.py
        ↓                                                    sqli_context_analyzer.py
SQLi Hypothesis Planner (r41-3)        ai/schemas|knowledge/sqli_hypothesis.py
        ↓                                                    sqli_hypothesis_planner.py
SQLi Evidence Planner (r41-4)          ai/schemas|knowledge/sqli_evidence_plan.py
        ↓                                                    sqli_evidence_planner.py
SQLi Specialist Result (r41-5)         ai/schemas|knowledge/sqli_agent_result.py
        ↓                                                    sqli_agent_result_export.py
R38-compatible result + R37 governance reference + R31–R37 provenance
```

All components are deterministic, pure/offline, stateless, JSON
serializable, pydantic validated (`extra="forbid"`, forced rule versions,
`research_only=True`).

## 3. Files created

```
ai/schemas/sqli_agent_identity.py
ai/schemas/sqli_context_analysis.py
ai/schemas/sqli_hypothesis.py
ai/schemas/sqli_evidence_plan.py
ai/schemas/sqli_agent_result.py
ai/knowledge/sqli_agent_identity.py
ai/knowledge/sqli_context_analyzer.py
ai/knowledge/sqli_hypothesis_planner.py
ai/knowledge/sqli_evidence_planner.py
ai/knowledge/sqli_agent_result_export.py
tests/test_sqli_agent_identity.py
tests/test_sqli_context_analyzer.py
tests/test_sqli_hypothesis_planner.py
tests/test_sqli_evidence_planner.py
tests/test_sqli_agent_result.py
agent-reports/stage-r41-sqli-specialist-agent.md
```

## 4. Files modified

```
backend/asset_cve_matching.py   (+14 lines, additive only)
```

No R31–R40 file was modified.

## 5. SQLi context vocabulary

`SQLIContextAnalysisPlan` fields and closed vocabularies:

- `input_location`: `QUERY`, `BODY`, `HEADER`, `COOKIE`, `PATH`,
  `UNKNOWN`
- `parameter_type`: `STRING`, `INTEGER`, `BOOLEAN`, `SORT`, `FILTER`,
  `SEARCH`, `IDENTIFIER`, `UNKNOWN`
- `data_flow`: `DIRECT_QUERY`, `QUERY_BUILDER`, `ORM`, `STORED_PROCEDURE`,
  `RAW_QUERY`, `UNKNOWN`
- `query_context`: `WHERE`, `ORDER_BY`, `LIMIT`, `OFFSET`, `SELECT`,
  `INSERT`, `UPDATE`, `DELETE`, `UNKNOWN`
- `database_context`: `MYSQL`, `POSTGRESQL`, `MSSQL`, `SQLITE`, `ORACLE`,
  `UNKNOWN`
- `input_handling`: `PARAMETERIZED`, `SANITIZED`, `ESCAPED`,
  `CONCATENATED`, `RAW`, `UNKNOWN`
- `type_handling`: `STRONG`, `WEAK`, `CAST`, `NONE_OBSERVED`, `UNKNOWN`
- `error_behavior`: `DATABASE_ERROR_OBSERVED`, `APPLICATION_ERROR_ONLY`,
  `NO_ERROR_OBSERVED`, `UNKNOWN`
- `behavioral_signal`: `DIFFERENTIAL`, `TIMING_RELEVANT`,
  `BOOLEAN_RELEVANT`, `NONE_OBSERVED`, `UNKNOWN`
- `context_confidence`: shared `HIGH`/`MEDIUM`/`LOW`/`UNKNOWN`

Malformed or missing observations degrade to `UNKNOWN`; nothing is promoted.

## 6. Confidence model

Confidence is a pure function of supplied facts with a hard SQLi safety cap:

- base by known-fact count: ≥8 → HIGH, 5–7 → MEDIUM, 2–4 → LOW, 0–1 →
  UNKNOWN;
- **unless unsafe query construction evidence was observed, confidence can
  never exceed MEDIUM.** Unsafe construction evidence means
  `input_handling` of `CONCATENATED`/`RAW` or a `RAW_QUERY` data flow.

Documented meaning: confidence answers "How complete/relevant is the
supplied SQLi research context?" — it does **not** mean "probability that
SQLi exists". No vulnerability is confirmed.

Consequences, verified by tests:

- a parameter alone (e.g. `input_location` + `parameter_type`) is LOW and
  `strong_construction_observed()` is False while `sqli_input_possible()` is
  True;
- a database type alone is UNKNOWN; an ORM alone is UNKNOWN; a search box
  alone is never HIGH;
- a fully specified context with `PARAMETERIZED` or `SANITIZED` handling is
  capped at MEDIUM — even with all nine facts known;
- only observed `CONCATENATED`/`RAW` handling or a `RAW_QUERY` flow (with
  enough facts) can reach HIGH.

`sqli_context_confidence_of()` recomputes confidence from bounded
observations so partial context dicts supplied directly to downstream
planners receive the correct, capped value.

## 7. Hypothesis vocabulary

`SQLIHypothesisPlan`: `rule_version`, `hypothesis_type`,
`supporting_signals[]`, `confidence`, `priority`, `limitations`,
`research_only`.

Types (closed): `QUERY_CONSTRUCTION_REVIEW`, `PARAMETERIZATION_REVIEW`,
`INPUT_HANDLING_REVIEW`, `TYPE_HANDLING_REVIEW`, `ORM_QUERY_REVIEW`,
`RAW_QUERY_REVIEW`, `ERROR_SIGNAL_REVIEW`,
`BOOLEAN_DIFFERENTIAL_REVIEW`, `TIMING_SIGNAL_REVIEW`,
`ORDER_BY_INJECTION_REVIEW`, `IDENTIFIER_HANDLING_REVIEW`,
`STORED_PROCEDURE_REVIEW`, `DATABASE_SPECIFIC_REVIEW`, `UNKNOWN`.

Deterministic mapping highlights:

- `CONCATENATED`/`RAW` handling → construction + parameterization reviews;
  `SANITIZED`/`ESCAPED` → input-handling review; `PARAMETERIZED` →
  low parameterization review;
- `RAW_QUERY` → raw-query review; `ORM` → ORM query review; stored
  procedures → stored-procedure review;
- `ORDER_BY` → order-by injection review; `IDENTIFIER` → identifier
  handling review;
- `WEAK`/`NONE_OBSERVED` type handling → type-handling review; known
  database type → database-specific review;
- `DATABASE_ERROR_OBSERVED` → error-signal review;
  `DIFFERENTIAL`/`BOOLEAN_RELEVANT` → boolean/differential review;
  `TIMING_RELEVANT` → timing review;
- nothing usable degrades to a low parameterization review or `UNKNOWN`.

Hypotheses are emitted in the canonical order of `HYPOTHESIS_TYPES`. Every
hypothesis carries `NO_EXPLOIT_CLAIM`, `NO_VULNERABILITY_CONFIRMATION`,
`HYPOTHESIS_ONLY`, `EVIDENCE_REQUIRED` (and `INSUFFICIENT_CONTEXT` when
unknown). Priority mirrors confidence. No payload, SQL string, statement,
database command, or exploitation instruction is ever emitted.

## 8. Evidence vocabulary

`SQLIEvidencePlan`: `rule_version`, `evidence_items[]`, `evidence_state`,
`confidence`, `limitations`, `research_only`.

Categories (closed): `QUERY_CONSTRUCTION`, `PARAMETERIZATION`,
`INPUT_VALIDATION`, `TYPE_HANDLING`, `ORM_QUERY_CONTEXT`,
`RAW_QUERY_CONTEXT`, `ERROR_BEHAVIOR`, `BOOLEAN_BEHAVIOR`,
`TIMING_BEHAVIOR`, `ORDER_BY_CONTEXT`, `IDENTIFIER_CONTEXT`,
`STORED_PROCEDURE_CONTEXT`, `DATABASE_CONTEXT`, `APPLICATION_BEHAVIOR`,
`UNKNOWN`.

Planning only:

- per-hypothesis fixed mappings produce an ordered, deduplicated required
  category list; hypotheses are derived when omitted;
- `COMPLETE` only for a fully specified unsafe-construction context with no
  `UNKNOWN` hypothesis; `PARTIAL` otherwise; `UNKNOWN` when nothing can be
  planned; a parameterized full context can never be `COMPLETE`;
- every plan records `NO_COLLECTION_PERFORMED`, `NO_SQL_EXECUTION`,
  `NO_NETWORK_REQUESTS`, `NO_PAYLOAD_GENERATION`, `EVIDENCE_REQUIRED`. No
  evidence is collected, no SQL is executed, no database is contacted.

## 9. R38 integration

- **Identity**: uses R38 `CATEGORY_SQLI`, `AGENT_ID_RE` and the R38
  content-token id function. `supported_capabilities` are restricted to the
  R38 analysis-only vocabulary — prohibited execution capabilities are
  rejected by the schema and filtered by the planner. `lifecycle_state` is
  restricted to the identity states `CREATED`/`PLANNED` (no runtime state).
  `sqli_agent_identity_to_r38()` projects onto a valid R38
  `SecurityAgentIdentityPlan` (verified by constructing the R38 model).
- **Input contract**: `export_sqli_agent_result(security_agent_input=...)`
  routes context through R38's `validate_security_agent_input`; an R38
  identity block for category `SQLI` is adopted deterministically. Nothing
  bypasses R38 validation.
- **Result compatibility**: status/confidence reuse the R38 vocabularies and
  `sqli_agent_result_to_r38()` maps hypotheses → `HYPOTHESES_RECORDED` and
  the evidence state → the R38 evidence summary through R38's
  `validate_security_agent_result`, producing a valid
  `SecurityAgentResultPlan`.

## 10. R31–R37 integration

- All R31–R37 context enters exclusively through the R38 read-only input
  contract (`research_context`, `memory_context`, `strategy_context`,
  `orchestration_context`, `authorization_context`, `governance_context`);
  no layer is called directly and no layer is mutated.
- R37 governance is consumed through the bounded governance reference
  (section 11). R33 learning is consumed indirectly through the R31
  reasoning / R32 memory contexts, since the R38 input contract has no
  separate learning block.
- The result records which layers were actually supplied, giving
  deterministic provenance without inventing data.

## 11. Governance behavior

`governance_reference`: fixed keys `rule_version`, `ready`,
`provenance_state`, `trace_state`, `audit_state`, `explanation_state`,
`reference_state`. A reference is `REFERENCED` only for a real R37 export
(`r37-5` plus all four component records); missing, malformed, foreign or
component-less plans degrade to `UNKNOWN` with `ready=False` and force the
`GOVERNANCE_UNKNOWN` limitation. Component states are validated against the
closed R37 vocabularies. Governance uncertainty remains visible in every
result.

## 12. Provenance behavior

`provenance`: fixed keys `rule_version`, `source_layers`,
`provenance_state`, `research_only`. Source layers (`REASONING`, `MEMORY`,
`STRATEGY`, `ORCHESTRATION`, `AUTHORIZATION`, `GOVERNANCE`) are recorded
only when the corresponding R38 input context block was actually supplied
(non-empty); the governance layer is also recorded when a real R37
governance reference was attached. State is `COMPLETE` when all six layers
were supplied, `PARTIAL` when some, `UNKNOWN` when none. No layer is ever
invented.

## 13. Backend integration

Additive change only in `backend/asset_cve_matching.py` (14 lines: one
import, two summary fields, comment), following the exact R39/R40 pattern:

```python
summary["sqli_agent_plan"] = export_sqli_agent_result()
summary["sqli_agent_plan_rule_version"] = (
    SQLI_AGENT_RESULT_EXPORTER_RULE_VERSION
)
```

No existing field was renamed, removed or reordered; R38/R39/R40 fields
remain intact and no R31–R40 logic was touched. Live check through
`build_matches` returns `status="CREATED"`, `rule_version="r41-5"`,
`research_only=True`, `NO_SQL_EXECUTION`/`NO_NETWORK_REQUESTS` limitations
and an `UNKNOWN` governance reference.

## 14. Safety boundary

- R41 modules import only `__future__`, `re`, `pydantic` and
  `ai.schemas`/`ai.knowledge`. No SQL engine, database client, network
  client, socket, subprocess, shell, browser automation, LLM, embedding,
  Mongo or filesystem state.
- Not implemented (by design): SQL execution, database connections, HTTP
  requests, SQL payload execution or generation, execution strings for live
  targets, sqlmap, subprocess/shell, browser automation, network requests,
  sockets, external APIs, LLM calls, target modification, auth bypass,
  database access, automated fuzzing, parameter brute forcing, persistence,
  workers, schedulers.
- No systemd, Docker, deployment or VM configuration was created or
  modified. Nothing was pushed.

## 15. AST safety tests

`tests/test_sqli_agent_result.py` parses all 10 R41 modules with `ast` and
rejects forbidden imports and calls:

- forbidden modules: `subprocess`, `socket`, `http`, `urllib`, `requests`,
  `httpx`, `aiohttp`, `asyncio`, `threading`, `multiprocessing`,
  `concurrent`, `importlib`, `ctypes`, `shutil`, `ssl`, `ftplib`,
  `smtplib`, `telnetlib`, `os`, `dns`, `selenium`, `playwright`,
  `pyppeteer`, `paramiko`, `urllib3`, `curl`, `pycurl`, `sqlite3`,
  `sqlalchemy`, `psycopg`, `psycopg2`, `pymysql`, `MySQLdb`, `cx_Oracle`,
  `pyodbc`, `asyncpg`, `aiosqlite`, `mariadb`, `sqlmap`;
- forbidden calls: `__import__`, `eval`, `exec`, `compile`, `open` and
  dotted prefixes `subprocess.`, `os.system`, `os.popen`, `importlib.`,
  `socket.`, `urllib.`, `requests.`, `httpx.`, `dns.`, `sqlite3.`,
  `sqlalchemy.`, `psycopg2.`, `pymysql.`, `sqlmap.`.

Additional tests assert output contains no SQL payload content
(`select `, `union `, `drop table`, ` or 1=1`, `sleep(`, `waitfor delay`,
`sqlmap`, database client names). The schemas describe database context but
never connect to a database.

## 16. Focused tests

| Suite | Tests |
|---|---|
| `tests/test_sqli_agent_identity.py` (R41.1) | 19 |
| `tests/test_sqli_context_analyzer.py` (R41.2) | 31 |
| `tests/test_sqli_hypothesis_planner.py` (R41.3) | 26 |
| `tests/test_sqli_evidence_planner.py` (R41.4) | 26 |
| `tests/test_sqli_agent_result.py` (R41.5) | 29 |
| **R41 total** | **131 passed** |

Coverage includes: deterministic identity; R38 category/id conformance;
capability restrictions including prohibited codes; lifecycle restriction;
R38 input validation; deterministic context classification and confidence
model (parameter-only, database-only, ORM-only, parameterized cap, unsafe
construction requirement); hypothesis generation and canonical ordering;
safety flags; evidence planning, deduplication and ordering; governance
handling; provenance; result contract and R38 projection; limitation
preservation; unknown/invalid input; backend additive integration; and the
AST safety scan.

## 17. Regression tests

```
R41 focused suites                                        131 passed
R38 suites                                                132 passed
R39 suites                                                100 passed
R40 suites                                                122 passed
All tests referencing r31- … r40- (65 files)  1735 passed, 27 subtests
tests/test_asset_cve_matching.py               79 passed, 13 subtests
```

## 18. Full-suite results

```
python -m pytest tests/ -q
R40 baseline:  3505 passed, 40 failed, 376 subtests passed
R41 result:    3636 passed, 40 failed, 376 subtests passed
```

The +131 equals exactly the new R41 tests, and the sorted `FAILED` line
sets are byte-identical (`diff` clean): no new failure and no existing
failure was altered. Re-running the full suite with the R41 backend diff
stashed yields 3635 passed / 41 failed, where the single extra failure is
`tests/test_sqli_agent_result.py::TestSQLIAgentResult::test_backend_additive_integration`
— proving the backend change is additive and behavior-neutral.

## 19. Existing failure comparison

The 40 pre-existing failures are the money-score/economics corpus-drift
failures present since before R40 (product API, sessions, economics
projection/API, opportunities, outcomes, hunt/opportunity queues, page
render, research UI, routers). The sorted failure sets before and after
R41 are byte-identical; none was modified or "fixed".

## 20. Git commit hash

Commit message: `feat(research): add r41 sqli specialist agent`. Hash is
reported in the final response after the local commit (the report is part
of the same commit; no amend and no push).

## 21. Git status

Unrelated pre-existing worktree items remain outside the R41 commit and
were not modified: ` D utils.zip`, `?? watch.zip`,
`?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`.

## 22. Known limitations

- R41 is a research/planning model only: it does not execute SQL, connect
  to databases, or validate any hypothesis. Evidence categories are plans,
  not collected evidence.
- Confidence describes SQLi context completeness under the
  unsafe-construction cap, not the likelihood that SQLi exists.
- Database-specific reviews are generic schema-level reviews; no
  database-specific payload, syntax, or version behavior is modeled.
- The result is deterministic given bounded inputs; application-specific
  query builders or ORMs beyond the declared vocabularies are not modeled.
- `COMPLETED` means the evidence plan is fully specified for a fully
  specified unsafe-construction context; it is not a vulnerability
  confirmation.

## 23. No-execution statement

Explicitly: R41 contains no SQL or execution capability. There is no SQL
execution, database connection, SQL payload generation or storage, HTTP or
network request, socket usage, fuzzing, parameter brute forcing, sqlmap
invocation, subprocess/shell, browser automation, external API call, LLM
call, persistence, worker or scheduler anywhere in R41. The agent analyzes
structured context, plans hypotheses and evidence, and emits a structured
research result.

## Agent / Model

- Model: deepseek-v4.1-flash
- Stage: R41
- Role: coding agent
