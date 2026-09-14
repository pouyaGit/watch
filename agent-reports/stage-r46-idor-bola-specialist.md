# Stage R46 — IDOR / BOLA Specialist Agent

The next real security Specialist Agent in the R38 framework. R46 analyzes
supplied application/security context and produces structured research
artifacts only: identity, context analysis, hypotheses, evidence
requirements and a research result. It does not test, request, browse, scan,
bypass or exploit anything.

- Stage: R46
- Rule versions: `r46-1` … `r46-5`
- Commit message: `feat(research): add r46 idor bola specialist agent`
  (local only, not pushed; hash reported in the final response)

## 1. Objective

Answer: **"What object-level authorization research context was supplied,
which IDOR/BOLA research hypotheses follow, and which evidence would be
required?"** — while making explicit that R46 does NOT answer "is this
target vulnerable?", "how do we bypass authorization?", "what request do we
send?" or "which object do we access?".

IDOR (Insecure Direct Object Reference) and BOLA (Broken Object Level
Authorization) are treated as related object-level authorization research
concepts, not automatically identical findings. R46 only reasons about
object-level authorization boundaries, identifier-controlled object access,
ownership/context relationships and authorization evidence requirements.

## 2. Architecture

```
R38 contract
   ↓
Identity            ai/schemas|knowledge/idor_bola_agent_identity.py   (r46-1)
   ↓
Context Analysis    ai/schemas|knowledge/idor_bola_context_analysis.py (r46-2)
   ↓                                              idor_bola_context_analyzer.py
Hypothesis Planning ai/schemas|knowledge/idor_bola_hypothesis.py       (r46-3)
   ↓                                              idor_bola_hypothesis_planner.py
Evidence Planning   ai/schemas|knowledge/idor_bola_evidence_plan.py    (r46-4)
   ↓                                              idor_bola_evidence_planner.py
Research Result     ai/schemas|knowledge/idor_bola_agent_result.py     (r46-5)
                                                  idor_bola_agent_result_export.py
```

The established R39/R40/R41 separation is preserved (five schema components
and five knowledge components). Two optional facades aggregate the
components for discoverability:

- `ai/schemas/idor_bola_agent.py`
- `ai/knowledge/idor_bola_agent.py` (also exposes `run_idor_bola_agent`)

Output is consumed unchanged by R42 evaluation, R43 collaboration, R44
feedback learning and R45 advisory through their generic contracts. No
R38/R42/R43/R44/R45 contract file was modified.

## 3. Specialist identity

`IDORBOLAAgentIdentityPlan` (`r46-1`): `agent_id`, `agent_name`, `category`,
`version`, `maturity`, `supported_contexts`, `supported_capabilities`,
`lifecycle_state`, `limitations`, `research_only`.

- `agent_name`: `idor-bola-specialist`
- `agent_id`: deterministic R38 content token `sa-<16 hex>`
  (`compute_idor_bola_agent_id`, no clock/UUID/randomness)
- `category`: the canonical R38 closed category `IDOR`
  (`CATEGORY_IDOR`). R38 already reserves `IDOR` in `AGENT_CATEGORIES`;
  `IDOR_BOLA` is exposed as the descriptive research label
  (`IDOR_BOLA_RESEARCH_LABEL`), not as a new R38 category. This is a
  deliberate contract-conformance decision: adding `IDOR_BOLA` to the R38
  category vocabulary would modify the R38 contract and would make R42/R43
  degrade the agent to `UNKNOWN`.
- `supported_contexts`: bounded object reference locations (path, query,
  body, header, cookie; `UNKNOWN` is the declarable degrade value)
- `supported_capabilities`: R38 analysis-only capabilities only; prohibited
  execution capabilities are always dropped
- `lifecycle_state`: identity states `CREATED`/`PLANNED` only
- `limitations`: `NO_EXECUTION_CAPABILITY`, `NO_AUTHORIZATION_BYPASS`,
  `NO_NETWORK_REQUESTS`, `NO_PAYLOAD_GENERATION`,
  `NO_VULNERABILITY_CONFIRMATION`, plus `SCOPE_UNKNOWN` when no context
  survives

## 4. Context model

`IDORBOLAContextAnalysisPlan` (`r46-2`) with closed vocabularies:

- `object_reference`: `NONE_OBSERVED`, `PATH_PARAMETER`,
  `QUERY_PARAMETER`, `BODY_FIELD`, `HEADER_VALUE`, `COOKIE_VALUE`,
  `UNKNOWN`
- `resource_type`: `DOCUMENT`, `RECORD`, `PROFILE`, `ORDER`, `FILE`,
  `MESSAGE`, `TRANSACTION`, `INVOICE`, `NONE_OBSERVED`, `UNKNOWN`
- `identifier_type`: `OPAQUE_ID`, `SEQUENTIAL_INTEGER`, `UUID`, `SLUG`,
  `COMPOSITE_KEY`, `NONE_OBSERVED`, `UNKNOWN`
- `ownership_relationship`: `OWNER_RECORDED`, `OWNER_NOT_RECORDED`,
  `UNKNOWN`
- `tenant_boundary`: `TENANT_RECORDED`, `TENANT_NOT_RECORDED`, `UNKNOWN`
- `role_boundary`: `ROLE_RECORDED`, `ROLE_NOT_RECORDED`, `UNKNOWN`
- `authorization_control`: `POLICY_ENFORCEMENT_PRESENT`,
  `OWNERSHIP_CHECK_PRESENT`, `TENANT_AUTHORIZATION_PRESENT`,
  `ROLE_AUTHORIZATION_PRESENT`, `ACCESS_CONTROL_MIDDLEWARE_PRESENT`,
  `SERVER_SIDE_AUTHORIZATION_PRESENT`, `AUTHORIZATION_ABSENT`, `UNKNOWN`
- `authorization_location`: `SERVER_SIDE`, `CLIENT_SIDE_ONLY`, `MIXED`,
  `NONE_OBSERVED`, `UNKNOWN`
- `object_lookup`: `LOOKUP_BY_IDENTIFIER`, `LOOKUP_BY_OWNED_SCOPE`,
  `LOOKUP_BY_TENANT_SCOPE`, `NONE_OBSERVED`, `UNKNOWN`
- `authorization_behavior` (observed behavior, preserved only when
  explicitly supplied): `CROSS_USER_ACCESS_OBSERVED`,
  `CROSS_TENANT_ACCESS_OBSERVED`, `OWN_OBJECT_ONLY_OBSERVED`,
  `ACCESS_DENIED_OBSERVED`, `NO_BEHAVIOR_OBSERVED`, `UNKNOWN`
- `route_context`: `RESOURCE_ROUTE`, `COLLECTION_ROUTE`, `ADMIN_ROUTE`,
  `INTERNAL_ROUTE`, `NONE_OBSERVED`, `UNKNOWN`

The analyzer distinguishes the five required categories: object identifier
exposure, authorization control evidence, ownership/context evidence,
observed authorization behavior and missing evidence. "Identifier present"
and "object lookup exists" never imply broken authorization. Naive
`/users/{id}`-style context alone can never produce HIGH confidence.

## 5. Hypothesis model

`IDORBOLAHypothesisPlan` (`r46-3`). Closed type vocabulary:

`OBJECT_LEVEL_AUTHORIZATION_GAP`, `OWNERSHIP_BOUNDARY_GAP`,
`TENANT_ISOLATION_GAP`, `ROLE_BOUNDARY_GAP`, `DIRECT_OBJECT_REFERENCE`,
`MISSING_AUTHORIZATION_CONTEXT`, `AUTHORIZATION_CONTROL_PRESENT`,
`UNKNOWN`.

Closed supporting-signal vocabulary (reference location, resource presence,
identifier type, ownership/tenant/role recording, lookup pattern,
authorization control presence/absence/unknown, server-side/client-side
location, observed behavior, route context, context unknown).

Deterministic rules:

- identifier + direct object lookup + missing authorization evidence →
  `OBJECT_LEVEL_AUTHORIZATION_GAP`
- object identifier + ownership relationship → `OWNERSHIP_BOUNDARY_GAP`
- tenant identifier/object + missing tenant authorization evidence →
  `TENANT_ISOLATION_GAP`
- role-sensitive resource + missing role authorization evidence →
  `ROLE_BOUNDARY_GAP`
- direct object reference with unknown authorization state →
  `DIRECT_OBJECT_REFERENCE`
- no authorization or boundary evidence → `MISSING_AUTHORIZATION_CONTEXT`
- explicit authorization control → `AUTHORIZATION_CONTROL_PRESENT`
- nothing usable → `UNKNOWN`

Negative signals reduce priority but never erase the hypothesis: when a
matching control is present the boundary/gap hypothesis is still emitted at
`LOW` priority with the control signal attached, and
`AUTHORIZATION_CONTROL_PRESENT` explains that the supplied context contains
authorization evidence. Priority is a bounded closed value
(HIGH/MEDIUM/LOW/UNKNOWN) that means "how useful is further research of this
authorization hypothesis?" — never severity, exploitability, CVSS,
vulnerability probability or confirmation. Explicitly supplied cross-context
behavior raises a gap hypothesis to at least MEDIUM; it never fabricates
behavior.

## 6. Evidence planner

`IDORBOLAEvidencePlan` (`r46-4`) with closed evidence categories:

- `OBJECT_LEVEL_AUTHORIZATION_GAP`: authorization control evidence,
  ownership relationship evidence, object lookup context, cross-context
  access behavior (if already observed)
- `OWNERSHIP_BOUNDARY_GAP`: ownership relationship, authorization control,
  server-side authorization evidence, observed authorization behavior
- `TENANT_ISOLATION_GAP`: tenant boundary evidence, object identifier
  context, server-side authorization evidence, cross-context behavior
- `ROLE_BOUNDARY_GAP`: role definition, route/controller context,
  server-side authorization evidence, observed authorization behavior
- `DIRECT_OBJECT_REFERENCE`: object identifier context, authorization
  control, object lookup context
- `MISSING_AUTHORIZATION_CONTEXT`: authorization control, access-control
  policy, route/controller context
- `AUTHORIZATION_CONTROL_PRESENT`: authorization control, policy/middleware
  evidence, ownership check evidence

Planning state is `UNKNOWN` when nothing can be planned, `COMPLETE` only
when the supplied context is HIGH confidence and no `UNKNOWN` hypothesis
remains, `PARTIAL` otherwise. Evidence planning describes what would be
relevant; it never collects evidence, never contacts a target and never
generates bypass content. Limitations include `NO_COLLECTION_PERFORMED`,
`NO_AUTHORIZATION_BYPASS`, `NO_NETWORK_REQUESTS`,
`NO_PAYLOAD_GENERATION`, `EVIDENCE_REQUIRED`.

## 7. Confidence calibration

Context confidence follows the R42 calibration philosophy and is a pure
function of supplied facts:

- `HIGH`: strong structured object-level authorization context — a supplied
  object reference plus a positive authorization control plus server-side
  authorization location plus boundary context.
- `MEDIUM`: relevant object/resource context with incomplete authorization
  evidence, or an authorization control whose enforcement location is not
  server-side, or explicit/unknown authorization absence.
- `LOW`: only weak object-reference signals.
- `UNKNOWN`: insufficient structured context (no supplied object reference).

Hard caps: without an object reference the confidence is `UNKNOWN`; without
a positive, server-side authorization control the confidence can never
exceed `MEDIUM`. HIGH confidence is never produced merely because an id
exists, an endpoint has an object parameter, a numeric ID appears, an object
is user-controlled, a route contains an id, or a resource lookup exists.
Hypothesis confidence mirrors bounded priority and is never a vulnerability
probability.

## 8. Result contract

`IDORBOLAAgentResultPlan` (`r46-5`), R38-compatible, canonical field names
matching R39/R40/R41: `rule_version`, `agent_name`, `agent_identity`,
`status`, `context_analysis`, `hypotheses`, `evidence_plan`, `confidence`,
`limitations`, `governance_reference`, `provenance`, `research_only`.

- status: complete evidence plan → `COMPLETED`; partial plan or partially
  known context → `ANALYZING`; fully unknown context → `CREATED`
- confidence equals the evidence-plan confidence
- limitations: `NO_EXECUTION_PERFORMED`, `NO_NETWORK_REQUESTS`,
  `NO_AUTHORIZATION_BYPASS`, `NO_PAYLOAD_GENERATION`,
  `NO_VULNERABILITY_CONFIRMATION`, `NO_TARGET_MODIFICATION`,
  `HYPOTHESIS_ONLY`, `EVIDENCE_REQUIRED`, plus `INSUFFICIENT_CONTEXT`,
  `GOVERNANCE_UNKNOWN` and `RESULT_UNKNOWN` when applicable
- `idor_bola_agent_result_to_r38` projects the result onto a valid R38
  result plan (hypotheses → `HYPOTHESES_RECORDED`, evidence state → R38
  evidence summary)

## 9. R42 compatibility

R42 was not modified. The R46 result is evaluated through the generic R42
contract: `evaluate_agent_result(r46_result)` resolves
`evaluated_agent_category = IDOR`, `evaluated_result_rule_version = r46-5`,
produces a bounded overall score/rating, hard-gate and safety states, and
the result projects onto the R38 result vocabulary. Focused tests assert
category, rule version, rating/gate/safety membership, score range and
explicit identity agreement.

## 10. R43 compatibility

R43 was not modified. A mixed collaboration was built with R39 XSS, R40
SSRF, R41 SQLi and R46 IDOR results. Tests verify: four participating
agents, categories `{XSS, SSRF, SQLI, IDOR}`, IDOR attribution with
`result_rule_version = r46-5`, non-empty hypothesis grouping, merged
evidence presence, governance/provenance summaries and four collaboration
rankings. No IDOR-specific branch was added to R43.

## 11. R44 compatibility

R44 was not modified. R42 evaluations of R46 results produce feedback
events with `source_category = IDOR`; classification and learning signals
are generated generically. Focused tests cover the required examples:

- high confidence + weak authorization evidence:
  `CONFIDENCE_CALIBRATION` → `REDUCE_CONFIDENCE`
- missing provenance: `PROVENANCE_ISSUE` → `REVIEW_PROVENANCE`
- authorization-control-present success pattern: R46 emits
  `AUTHORIZATION_CONTROL_PRESENT`; a safe success observation classifies as
  `SUCCESS_PATTERN` → `PRESERVE_SUCCESS_PATTERN`

## 12. R45 compatibility

R45 was not modified and no real LLM connection is involved. R42
evaluations of R46 results plus the derived R44 learning signals are
accepted by the R45 advisory input and export: the advisory result passes
validation, preserves source references (`R42`, and `R44` when signals are
supplied) and remains research-only. No IDOR-specific branch was added to
R45.

## 13. Provenance/governance behavior

- `provenance` records only R31-R37 input layers actually supplied through
  the R38 read-only input contract (`REASONING`, `MEMORY`, `STRATEGY`,
  `ORCHESTRATION`, `AUTHORIZATION`, `GOVERNANCE`); no layer is invented.
  Unknown provenance stays `UNKNOWN` with empty layers.
- `governance_reference` is `REFERENCED` only when the R37 governance export
  rule version and all four component records are present; missing,
  malformed, foreign or component-less plans degrade to `UNKNOWN` with
  `ready=False`, which is never treated as authorization readiness. Unknown
  governance records the `GOVERNANCE_UNKNOWN` limitation.

## 14. Safety boundary

R46 contains no network request, DNS resolution, socket, database
connection, SQL execution, JavaScript execution, target browsing, browser,
nuclei, sqlmap, scanner, subprocess, shell command, payload, attack command,
authorization bypass, target-state modification, external API, LLM call,
filesystem/runtime persistence, worker or scheduler. It only analyzes
already-supplied structured context. `backend/asset_cve_matching.py` was
not modified.

## 15. AST safety tests

Each of the five R46 test files AST-parses all twelve R46 modules and
rejects:

- imports: `subprocess`, `socket`, `http`, `urllib`, `requests`, `httpx`,
  `aiohttp`, `asyncio`, `threading`, `multiprocessing`, `concurrent`,
  `importlib`, `ctypes`, `shutil`, `ssl`, `os`, `dns`, `selenium`,
  `playwright`, `pyppeteer`, `paramiko`, `sqlite3`, `sqlalchemy`,
  `psycopg`, `psycopg2`, `pymysql`, `MySQLdb`, `sqlmap`, `nuclei`, `curl`,
  `pycurl`, and LLM/provider SDKs (`openai`, `ollama`, `litellm`,
  `anthropic`, `openrouter`)
- calls: `__import__`, `eval`, `exec`, `compile`, `open`, and forbidden
  call prefixes (`subprocess.`, `os.system`, `os.popen`, `importlib.`,
  `socket.`, `urllib.`, `requests.`, `httpx.`, SQL clients, `openai.`)

A forbidden-output test additionally scans the serialized result for
payload/attack tokens (`payload:`, `<script`, `union select`, `or 1=1`,
`execute this`, `run this command`, `bypass authentication`, `attack plan`,
`attack sequence`, `exploit the target`, `send this payload`) and
credential tokens; none are present.

## 16. Determinism tests

Repeated runs are byte-identical for identity, context analysis,
hypotheses, evidence plans and results; the agent id is a deterministic
content token; canonical ordering is asserted for hypotheses, evidence items
and source layers; serialized output contains no `timestamp`, `uuid` or
`runtime_id`. Repeated-execution equality is asserted for the full result.

## 17. Focused test results

| Suite | Tests |
|---|---|
| `tests/test_idor_bola_agent_identity.py` (R46.1) | 16 |
| `tests/test_idor_bola_context_analyzer.py` (R46.2) | 16 |
| `tests/test_idor_bola_hypothesis_planner.py` (R46.3) | 18 |
| `tests/test_idor_bola_evidence_planner.py` (R46.4) | 16 |
| `tests/test_idor_bola_agent_result.py` (R46.5) | 31 |
| **R46 total** | **97 passed** |

Coverage includes all required behaviors: identity, valid/malformed input,
extra-field rejection, deterministic normalization, direct object reference
detection, missing authorization evidence, ownership/tenant/role boundary
hypotheses, authorization-control-present, negative authorization signals,
insufficient context, confidence calibration and safety caps, hypothesis
priority, evidence planning, observed behavior preservation, no fabricated
behavior, provenance/governance preservation, R42/R43/R44/R45 compatibility,
deterministic serialization, repeated execution equality, AST safety,
forbidden imports and forbidden payload/attack output.

## 18. Regression results

```
R46 focused suites (5 files)                               97 passed
R38 suites (SECURITY AGENT)                               132 passed
R39 suites (XSS)                                          100 passed
R40 suites (SSRF)                                         122 passed
R41 suites (SQLi)                                         131 passed
R42 suites (evaluation)                                    91 passed
R43 suites (collaboration, incl. shared context)          102 passed
R44 suites (learning)                                      81 passed
R45 suites (advisory)                                     107 passed
All tests referencing r31- … r45- (91 files)  2234 passed, 27 subtests
Backend test (tests/test_asset_cve_matching.py) 79 passed, 13 subtests
AI safety tests (knowledge_store/xss_researcher/
  xss_llm_researcher/openrouter)                           96 passed
```

## 19. Full-suite result

```
python -m pytest tests/ -q -p no:cacheprovider
4114 passed, 40 failed, 1 warning, 376 subtests passed in 56.29s
```

The growth from the R45 full-suite baseline (4015 passed) is exactly the 97
new R46 tests plus the two R45 validator tests added after that baseline
run (105 → 107): no previously passing test changed state.

## 20. Existing failure comparison

Failure set comparison against the R45 baseline:
`diff` of the sorted `FAILED` lines is empty (`0` differences; 40 entries
in both). The 40 failures are the pre-existing money-score/economics
corpus-drift failures (`test_hunt_queue`, `test_product_api`,
`test_research_economics_*`, `test_research_opportunities`,
`test_research_outcomes`, `test_research_sessions`, `test_page_render`,
`test_daily_research_workflow`, `test_opportunity_action_queue`,
`test_research_ui`, `test_routers_fixes`). No failure references
`idor_bola` or IDOR, and none was modified or "fixed".

Environment note: the R41 SQLi suite contains a pre-existing backend
integration test (`test_backend_additive_integration`) that connects to the
external MongoDB used by `database/db.py`. One run of that test took 38.5 s
while the connection was cold; it then passed. This variance is an
environment dependency, not an R46 change.

## 21. Git status

Only new R46 files are added. Pre-existing unrelated worktree items remain
untouched and outside the commit: ` D utils.zip`, `?? watch.zip`,
`?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`. `git diff --check` is
clean. No VM, Docker, systemd, deployment, shell or unrelated file is
modified. `backend/asset_cve_matching.py` is not modified. No push is
performed.

Files added:

```
ai/schemas/idor_bola_agent_identity.py
ai/schemas/idor_bola_context_analysis.py
ai/schemas/idor_bola_hypothesis.py
ai/schemas/idor_bola_evidence_plan.py
ai/schemas/idor_bola_agent_result.py
ai/schemas/idor_bola_agent.py
ai/knowledge/idor_bola_agent_identity.py
ai/knowledge/idor_bola_context_analyzer.py
ai/knowledge/idor_bola_hypothesis_planner.py
ai/knowledge/idor_bola_evidence_planner.py
ai/knowledge/idor_bola_agent_result_export.py
ai/knowledge/idor_bola_agent.py
tests/test_idor_bola_agent_identity.py
tests/test_idor_bola_context_analyzer.py
tests/test_idor_bola_hypothesis_planner.py
tests/test_idor_bola_evidence_planner.py
tests/test_idor_bola_agent_result.py
agent-reports/stage-r46-idor-bola-specialist.md
```

## 22. Commit hash

Commit message: `feat(research): add r46 idor bola specialist agent`. The
hash is reported in the final response after the local commit (the report is
part of the same commit; no amend and no push).

## 23. Limitations

- The canonical R38 category is `IDOR`; `IDOR_BOLA` is a descriptive
  research label. This is deliberate contract conformance (R38/R42/R43
  vocabularies are closed and were not modified).
- R46 analyzes only structured indicators already supplied; it cannot infer
  authorization behavior from unrepresented context.
- Hypothesis priority and context confidence are fixed deterministic design
  choices, not statistical estimates.
- Observed behavior is only as reliable as the supplied context; R46 never
  validates or collects it.
- Evidence planning lists relevant categories; it does not measure
  sufficiency or collect anything.
- The full-suite metric includes the 40 pre-existing corpus-drift failures
  unchanged from earlier baselines.

## 24. Explicit no-execution statement

Explicitly: R46 contains no execution capability of any kind. There is no
HTTP request, DNS resolution, socket, database connection, SQL execution,
JavaScript execution, browser, object access, authorization bypass, scanner,
nuclei, sqlmap, subprocess, shell command, payload generation or execution,
target-state modification, external API call, LLM call, filesystem or
runtime persistence, worker or scheduler anywhere in R46. The agent reads
already-supplied structured context, classifies it deterministically, and
emits hypotheses, evidence requirements and an R38-compatible research
result.

## Agent / Model

- Model: deepseek-v4.1-flash
- Stage: R46
- Role: coding agent
