# Stage R49 — API Security Specialist Agent

| | |
|---|---|
| Date | 2026-09-14 |
| Stage | R49 |
| Scope | Research-only API-level security posture specialist agent |
| Follows | R38 / R39 / R40 / R41 / R42 / R43 / R44 / R45 / R46 / R47 / R48 |
| Commit message | `feat(research): add r49 api security specialist agent` |
| Push status | **Not pushed** (local commit only) |
| Focused tests | 156 passed |
| Full suite | 4556 passed, 40 failed (unchanged baseline), 376 subtests |

## 1. Objective

Add the R49 API security specialist research agent. The agent analyzes
**already-supplied structured API security context** and produces:

1. API security specialist identity,
2. API context analysis,
3. API security hypotheses,
4. evidence requirements,
5. a structured specialist result.

R49 is research-only: it never calls an API, probes an endpoint, fuzzes,
executes a scanner, sends a payload or contacts any target, browser,
database, network or external service. Technology presence (REST/GraphQL/
RPC APIs, endpoint metadata, schemas, pagination, CORS metadata, API keys,
webhooks) is context only and can never, by itself, produce a
HIGH-confidence finding.

The implementation follows the established R38–R48 specialist pattern
(`ai/schemas/*` contracts, `ai/knowledge/*` pure engines, thin facades,
`tests/test_api_security_*.py` focused suites).

## 2. Architecture

```
ai/schemas/
  api_security_agent_identity.py       R49.1 identity contract
  api_security_context_analysis.py     R49.2 context contract
  api_security_hypothesis.py           R49.3 hypothesis contract
  api_security_evidence_plan.py        R49.4 evidence contract
  api_security_agent_result.py         R49.5 result contract
  api_security_agent.py                schema facade

ai/knowledge/
  api_security_agent_identity.py       deterministic identity planner
  api_security_context_analyzer.py     deterministic context analyzer
  api_security_hypothesis_planner.py   deterministic hypothesis planner
  api_security_evidence_planner.py     deterministic evidence planner
  api_security_agent_result_export.py  result exporter (R38 projection)
  api_security_agent.py                knowledge facade / aggregate entry

tests/
  test_api_security_agent_identity.py
  test_api_security_context_analyzer.py
  test_api_security_hypothesis_planner.py
  test_api_security_evidence_planner.py
  test_api_security_agent_result.py
```

Pipeline (`export_api_security_agent_result`):

```
supplied structured API context
  -> identity planner        (R38-conformant identity, category = RECON)
  -> context analyzer        (descriptive closed-vocabulary analysis)
  -> hypothesis planner      (closed hypothesis mapping)
  -> evidence planner        (required evidence categories, planning state)
  -> result exporter         (R38 result projection + R37 governance
                              reference + R31-R37 provenance)
```

All layers are pure functions of bounded inputs: no I/O, no network, no
API call, no LLM, no Mongo, no wall-clock time, no randomness, no input
mutation. Facade modules only re-export canonical components and expose
`run_api_security_agent` as an alias of the result exporter.

## 3. Specialist identity

- `API_SECURITY_CATEGORY = CATEGORY_RECON = "RECON"` — an **existing**
  canonical R38 category imported from
  `ai/schemas/security_agent_identity.py`. R38 defines no API-specific
  canonical category (the closed set is XSS, SSRF, SQLI, IDOR, JWT,
  OAUTH, CVE_RESEARCH, RECON, UNKNOWN), modifying R38 is forbidden, and
  `RECON` is the only existing non-vulnerability-class umbrella and is
  unused by any other specialist. **R38 was not modified.**
- `API_SECURITY` is a descriptive research label only, never a canonical
  category, and is not registered in R38.
- `agent_id` uses the R38 content-token format (`compute_agent_id`);
  default name `api-security-specialist`, version `1.0`.
- `supported_contexts` is the closed set of known API types (`REST`,
  `GRAPHQL`, `RPC`, `JSON_API`, `XML_API`, `WEBHOOK`); an empty scope
  degrades to `UNKNOWN` with `SCOPE_UNKNOWN`.
- `supported_capabilities` is restricted to the R38 analysis-only
  vocabulary (`ANALYZE_CONTEXT`, `ANALYZE_PATTERN`, `CREATE_HYPOTHESIS`,
  `REQUEST_EVIDENCE`, `GENERATE_EXPLANATION`, `RANK_FINDINGS`); R38
  prohibited execution capabilities can never be declared.
- lifecycle is restricted to identity states `CREATED` / `PLANNED`; the
  identity projects onto a valid `SecurityAgentIdentityPlan`.

## 4. API responsibility boundaries

- **R46** remains the primary object-level authorization / IDOR / BOLA
  specialist. R49 records `object_authorization_context` as API context
  but never creates an IDOR/BOLA hypothesis.
- **R47** remains the primary JWT / authentication / token-validation
  specialist. R49 treats `JWT_BEARER` only as an authentication
  mechanism label.
- **R48** remains the primary OAuth protocol / authorization-flow
  specialist. R49 treats OAuth context only as an API authentication
  mechanism.
- **R49** covers the API-level posture: API type/surface, API
  authentication enforcement, endpoint/function/tenant authorization,
  request/parameter/schema validation, mass assignment, HTTP method
  controls, versioning, response/sensitive-field exposure, error/debug
  disclosure, rate/resource limits, pagination, batch operations,
  upload/download, GraphQL controls, CORS, API keys and webhooks.
- A test asserts that R49 output contains no R46/R47/R48 hypothesis
  types (`BOLA`, `IDOR`, `OBJECT_LEVEL_AUTHORIZATION_GAP`,
  `JWT_VALIDATION_GAP`, `SIGNATURE_VERIFICATION_GAP`,
  `REDIRECT_URI_VALIDATION_GAP`, `PKCE_ENFORCEMENT_GAP`) and that mixed
  R43 collaboration preserves each specialist's category and provenance.

## 5. Context model

Closed observable fields (all malformed/unsupplied values degrade to
`UNKNOWN`/`NOT_PROVIDED`, never promoted):

- API type (6 known types), API versioning (`VERSIONED_OBSERVED`,
  `UNVERSIONED_OBSERVED`, `DEPRECATED_VERSION_OBSERVED`), content type
  (JSON / form / XML / multipart);
- authentication mechanism (bearer, JWT, cookie/session, OAuth2, API key,
  basic, mutual TLS);
- API surface presence: object-authorization context, endpoint metadata,
  request/response schema, pagination, batch, upload, download, nested
  resources, GraphQL batching, webhook context;
- exposure observations: resource exposure (excessive data), sensitive
  field exposure (sensitive fields / internal identifiers), error detail
  (generic / detailed / stack trace), debug information, GraphQL
  introspection (enabled / disabled);
- 32 validation/control states with the shared four-state vocabulary
  (`ENFORCED_OBSERVED`, `ABSENT_OBSERVED`, `NOT_PROVIDED`, `UNKNOWN`):
  API authentication, endpoint authorization, function/role
  authorization, tenant isolation, schema validation, parameter
  validation, unknown-field handling, content-type validation, HTTP
  method restrictions, method-override control, rate-limit control,
  request-size limit, pagination limit, query-complexity limit, batch
  limit, upload limit, download control, error-detail control, debug-mode
  control, sensitive-field control, CORS origin policy, CORS credentials
  policy, GraphQL field authorization, GraphQL mutation authorization,
  GraphQL depth limit, GraphQL complexity limit, GraphQL introspection
  control, API key rotation, API key revocation, webhook signature
  validation, webhook replay protection, webhook source validation.

The analyzer distinguishes **OBSERVED** facts, **INFERRED/CONTEXT**
technology metadata and **UNKNOWN / NOT PROVIDED** information.
Determinism: repeated identical input produces byte-identical analysis.
Privacy: no URLs, endpoints, keys, tokens or payloads are stored — only
closed presence/validation labels.

## 6. Hypothesis vocabulary

Closed deterministic vocabulary (32 types, canonical order):

```
API_AUTHENTICATION_GAP               API_AUTHORIZATION_GAP
FUNCTION_LEVEL_AUTHORIZATION_GAP     TENANT_ISOLATION_GAP
INPUT_VALIDATION_GAP                 SCHEMA_VALIDATION_GAP
MASS_ASSIGNMENT_RISK                 HTTP_METHOD_CONTROL_GAP
METHOD_OVERRIDE_RISK                 API_VERSIONING_RISK
RESOURCE_EXPOSURE_RISK               SENSITIVE_FIELD_EXPOSURE_RISK
ERROR_INFORMATION_DISCLOSURE         DEBUG_INFORMATION_EXPOSURE
RATE_LIMIT_CONTROL_GAP               RESOURCE_LIMIT_CONTROL_GAP
PAGINATION_CONTROL_GAP               QUERY_COMPLEXITY_CONTROL_GAP
BATCH_OPERATION_CONTROL_GAP          FILE_UPLOAD_CONTROL_GAP
FILE_DOWNLOAD_CONTROL_GAP            CORS_CONTROL_GAP
GRAPHQL_INTROSPECTION_RISK           GRAPHQL_AUTHORIZATION_GAP
GRAPHQL_QUERY_COMPLEXITY_GAP         API_KEY_CONTROL_GAP
WEBHOOK_SIGNATURE_CONTROL_GAP        WEBHOOK_REPLAY_CONTROL_GAP
CONTENT_TYPE_CONTROL_GAP             API_SECURITY_CONTROL_PRESENT
MISSING_API_CONTEXT                  UNKNOWN
```

Closed hypothesis states: `WEAKNESS_OBSERVED`,
`CONTROL_PRESENT_OBSERVED`, `NEEDS_EVIDENCE`, `NOT_OBSERVED` (available
vocabulary), `UNKNOWN`.

Mapping rules (deterministic; priority is research usefulness only, never
severity/exploitability/CVSS):

- explicit absent authentication / endpoint authorization /
  function-role authorization / tenant isolation / schema / parameter /
  method / rate-limit / request-size / pagination / query-complexity /
  batch / upload / download / CORS / GraphQL authorization / GraphQL
  complexity / webhook signature / webhook replay control → matching gap
  with `WEAKNESS_OBSERVED` and HIGH priority (softer controls use
  MEDIUM);
- not-provided control information → matching gap with `NEEDS_EVIDENCE`
  at LOW priority;
- method override, API key rotation/revocation, CORS, content type,
  consent-like softer controls → MEDIUM weakness on explicit absence;
- deprecated API version, excessive response data, sensitive/internal
  identifier exposure, detailed/stack-trace errors, debug information →
  MEDIUM risk (LOW for deprecated versions and introspection);
- GraphQL introspection enabled alone → LOW risk signal only;
- explicit `GENERIC_MESSAGE_OBSERVED` errors, `NONE_OBSERVED` debug
  information and introspection-disabled observations are control
  signals, not findings;
- explicit observed enforcement → `API_SECURITY_CONTROL_PRESENT`
  (`CONTROL_PRESENT_OBSERVED`) and no gap for that control;
- technology presence alone (API type, endpoint metadata, schemas,
  pagination, CORS metadata, API keys, webhooks) produces no gap
  hypothesis;
- nothing usable → `UNKNOWN`; usable but non-hypothesizable context →
  `MISSING_API_CONTEXT` (`NEEDS_EVIDENCE`, LOW).

Duplicate hypotheses are merged in canonical order; every hypothesis
carries closed supporting signals, rationale and research limitations
(`NO_EXPLOIT_CLAIM`, `NO_VULNERABILITY_CONFIRMATION`,
`NO_API_ATTACK_CLAIM`, `NO_AUTH_BYPASS_CLAIM`, `NO_IDOR_EXPLOIT_CLAIM`,
`NO_INJECTION_EXPLOIT_CLAIM`, `HYPOTHESIS_ONLY`, `EVIDENCE_REQUIRED`,
plus `INSUFFICIENT_CONTEXT` where applicable).

## 7. Evidence planner

Closed evidence vocabulary (40 categories) covering API authentication
configuration/enforcement, endpoint authorization policy, authorization
enforcement behavior, function/role authorization policy, tenant
isolation policy, input validation implementation, request schema
definition, unknown-field handling, writable field policy,
HTTP method and override configuration, API versioning policy, response
field policy, sensitive field policy, error handling and debug
configuration, rate-limit, request-size, pagination, query-complexity,
batch, upload and download policies, CORS origin/credential policy,
GraphQL field/mutation authorization, depth/complexity limit and
introspection policy, API key rotation/revocation/scope policy, webhook
signature/replay/source validation, content-type validation policy and
API security configuration.

- Required categories are the ordered union of the per-hypothesis
  mappings; the planner never collects evidence.
- Planning state: `UNKNOWN` when nothing can be planned; `COMPLETE` only
  when the context is HIGH confidence, no `UNKNOWN` hypothesis remains
  and at least one substantive (non-missing-context) hypothesis is
  present; otherwise `PARTIAL`.
- A context that only degrades to `MISSING_API_CONTEXT` can never be
  `COMPLETE`.
- Confidence: UNKNOWN / LOW / HIGH mirrors the state.

## 8. Confidence calibration

| Layer | Rule |
|---|---|
| Context analyzer | UNKNOWN when nothing usable; HIGH only for explicit observed weakness inside an API context; MEDIUM for explicit observed control; otherwise LOW |
| Hypothesis | Priority derived per mapping above; technology presence → no weakness hypothesis; not-provided → NEEDS_EVIDENCE/LOW |
| Evidence plan | COMPLETE/HIGH only with a HIGH context, no UNKNOWN hypothesis and at least one substantive hypothesis; otherwise PARTIAL/LOW |
| Result | Confidence = evidence-plan confidence; status COMPLETED only for COMPLETE evidence, ANALYZING for PARTIAL or known context, CREATED for fully unknown |

Conservative examples (verified by tests):

- `api_type="REST"` alone → context LOW, NEEDS_EVIDENCE hypotheses,
  result `ANALYZING`/LOW.
- `pagination_context="OBSERVED"` or `api_versioning=
  "DEPRECATED_VERSION_OBSERVED"` alone → context LOW, no
  `WEAKNESS_OBSERVED`.
- `graphql_introspection="INTROSPECTION_ENABLED_OBSERVED"` alone →
  context LOW; `GRAPHQL_INTROSPECTION_RISK` LOW only.
- isolated `sensitive_field_exposure`, `error_detail=STACK_TRACE`,
  `debug_information=OBSERVED`, `rate_limit_control=ABSENT_OBSERVED`
  without an API context → context LOW, `MISSING_API_CONTEXT`,
  `ANALYZING`/LOW.
- explicit `api_authentication="ABSENT_OBSERVED"` with an API context →
  `API_AUTHENTICATION_GAP` HIGH/`WEAKNESS_OBSERVED`, result
  `COMPLETED`/HIGH — an observed control weakness, still only a research
  finding (no API call, fuzzing or exploitation is claimed or performed).
- explicit `webhook_signature_validation="ABSENT_OBSERVED"` →
  `WEBHOOK_SIGNATURE_CONTROL_GAP` HIGH research finding.

R42's confidence-calibration dimension does not flag the conservative
cases as `CONFIDENCE_OVERSTATED` (asserted by test).

## 9. Result contract

`APISecurityAgentResultPlan` (rule version `r49-5`) with the exact key
set:

```
rule_version, agent_name, agent_identity, status,
context_analysis, hypotheses, evidence_plan, confidence,
limitations, governance_reference, provenance, research_only
```

- `status` ∈ R38 result statuses; `confidence` ∈ shared
  evidence-confidence levels; `research_only=True` is enforced.
- `governance_reference` is a bounded R37 reference: `REFERENCED` only
  for the genuine R37 governance export carrying all four component
  records, otherwise `UNKNOWN` with `ready=False` and the
  `GOVERNANCE_UNKNOWN` limitation.
- `provenance` records only the R31–R37 layers actually supplied
  (`REASONING`, `MEMORY`, `STRATEGY`, `ORCHESTRATION`, `AUTHORIZATION`,
  `GOVERNANCE`); no layer is invented.
- Observed evidence is preserved exactly; weakness/secret/exploitation
  material is never fabricated.
- `api_security_agent_result_to_r38` projects the result onto a valid
  `SecurityAgentResultPlan` (`HYPOTHESES_RECORDED` findings summary,
  evidence summary, conservative status rules).

## 10. R42 compatibility

Verified through the generic `evaluate_agent_result` loop without
modifying R42:

- structural validity, enum/rule-version validity, research-only and
  safety compliance all pass;
- `evaluated_agent_category = "RECON"`, `evaluated_result_rule_version =
  "r49-5"`;
- dimension scores include STRUCTURAL_VALIDITY, CONTEXT_COMPLETENESS,
  HYPOTHESIS_SUPPORT, EVIDENCE_COMPLETENESS, CONFIDENCE_CALIBRATION,
  SAFETY_COMPLIANCE, PROVENANCE_COMPLETENESS, GOVERNANCE_COMPLETENESS;
- no `RESEARCH_ONLY_FALSE`, `EXECUTION_CLAIM_DETECTED` or
  `CONFIDENCE_OVERSTATED` diagnostics for conservative cases;
- hard gate and safety states are always in their closed vocabularies,
  `deterministic=True`, `research_only=True`.

Known generic-integration characteristic (not R49-specific, R42 not
modified): the R42 evaluation input sanitizer keeps only generic context
keys, so specialist-specific context fields are reduced for the generic
fact-count rule. This affects R39–R48 specialist schemas equally; R49
still evaluates with PASS hard gate and PASS safety state.

## 11. R43 compatibility

Verified through the unmodified R43 `export_multi_agent_collaboration`
API with the R49 result as a participant:

- R39 + R49 (XSS wrapped with its identity),
- R40 + R49 (SSRF),
- R41 + R49 (SQLI),
- R46 + R49 (IDOR/BOLA),
- R47 + R49 (JWT/authentication),
- R48 + R49 (OAuth).

Each collaboration yields both participating categories, collaboration
rankings for both agents, hypothesis groups, merged evidence and
provenance per participant; repeated R46/R47/R48 collaborations are
byte-identical. Conflict handling, evidence merge and safety ranking are
exercised by the shared R43 pipeline without changes to R43.

## 12. R44 compatibility

Verified without modifying R44:

- `build_research_feedback_event(evaluation_result=...)` from an R49
  evaluation produces a valid event with `source_category="RECON"`;
- `classify_research_feedback_events` and `extract_learning_signals`
  consume it;
- direct feedback events (missing provenance / weak evidence) are
  classified as `PROVENANCE_ISSUE` and produce
  `REQUIRE_MORE_EVIDENCE` signals.

## 13. R45 compatibility

Verified without modifying R45 and without adding any LLM provider:

- `export_llm_advisory(evaluation_result=..., learning_signals=...)`
  consumes an R49-derived evaluation + signals:
  `validation_state="PASS"`, `safety_state="PASS"`,
  `research_only=True`, non-empty advisory summary and `source_refs`
  containing the R42 reference.
- R49 contains no OpenAI/OpenRouter/Ollama/Anthropic call; the LLM
  remains advisory only.

## 14. R46 / R47 / R48 interoperability

- R46 keeps object-level authorization; R49 records only
  `object_authorization_context` as API context.
- R47 keeps JWT signature/claim validation; R49's
  `API_AUTHENTICATION_GAP` is enforcement-level only and references no
  JWT claim validation.
- R48 keeps OAuth protocol flow; R49 references OAuth only as an API
  authentication mechanism.
- R49's own hypotheses are API-level postures; a responsibility-boundary
  test asserts no R46/R47/R48 hypothesis types appear, and R43 mixed
  collaborations preserve originating specialist categories and
  provenance.

## 15. Safety boundary

R49 remains strictly research-only. There is no HTTP/HTTPS request, no
API call, no endpoint probing, no API fuzzing, no network connection, no
socket, no DNS, no browser/Selenium/Playwright, no curl execution, no
scanner execution (nuclei/ffuf/sqlmap), no database connection or SQL, no
subprocess/shell, no credential testing, no authentication/
authorization bypass, no BOLA/IDOR/SSRF/SQLi/XSS exploitation, no token
manipulation, no OAuth flow execution, no payload or exploit generation,
no secret extraction, no external API or LLM call, no persistence,
worker or scheduler anywhere in the R49 sources. The agent reasons only
over structured data already supplied; API parameters are context labels
only. No backend file was modified (including
`backend/asset_cve_matching.py`).

## 16. AST safety tests

Every R49 test module contains an AST scan over all 12 R49 modules
(including both facades) rejecting:

- imports: `subprocess`, `socket`, `http`, `urllib`, `urllib3`,
  `requests`, `httpx`, `aiohttp`, `asyncio`, `threading`,
  `multiprocessing`, `concurrent`, `importlib`, `ctypes`, `shutil`,
  `ssl`, `os`, `dns`, `selenium`, `playwright`, `pyppeteer`, `paramiko`,
  `sqlite3`, `sqlalchemy`, `psycopg`, `psycopg2`, `pymysql`, `MySQLdb`,
  `sqlmap`, `nuclei`, `ffuf`, `curl`, `pycurl`, LLM/provider SDKs
  (`openai`, `ollama`, `litellm`, `anthropic`, `openrouter`), JWT
  libraries (`jwt`, `pyjwt`, `jose`), OAuth libraries (`oauthlib`,
  `authlib`, `oauth2`, `oauth2client`, `requests_oauthlib`, `msal`,
  `google`) and API/client libraries (`gql`, `graphql`, `openapi`,
  `swagger`, `grpc`);
- calls: `__import__`, `eval`, `exec`, `compile`, `open`, plus forbidden
  call prefixes (`subprocess.`, `os.system`, `os.popen`, `importlib.`,
  `socket.`, `urllib.`, `requests.`, `httpx.`, `urllib3.`, SQL clients,
  `openai.`, `oauthlib.`, `authlib.`, `msal.`, `grpc.`).

A forbidden-output test scans serialized results for payload/attack/
secret tokens (`payload:`, `<script`, `union select`, `or 1=1`,
`execute this`, `run this command`, `api bypassed`, `fuzz instructions`,
`dos attack`, `denial of service payload`, `idor exploit`,
`bola exploit`, `sql injection payload`, `ssrf payload`, `xss payload`,
`steal token`, `forge token`, `credential stuffing`, `secret key is`,
`api_key=`, `brute force password`, etc.); none are present, and no
access-token/API-key values appear. A standalone-backend test asserts
`backend/asset_cve_matching.py` contains no R49 references.

## 17. Determinism tests

Repeated runs are byte-identical for identity, context analysis,
hypotheses, evidence plans and results; the agent id is a deterministic
content token; canonical ordering is asserted for hypotheses, evidence
items and source layers; serialized output contains no `timestamp`,
`uuid` or `runtime_id`. Repeated-execution equality is asserted for the
full result, and identical input yields the same result across separate
processes and `PYTHONHASHSEED` values.

## 18. Focused test results

```
tests/test_api_security_agent_identity.py       16 passed
tests/test_api_security_context_analyzer.py     37 passed
tests/test_api_security_hypothesis_planner.py   35 passed
tests/test_api_security_evidence_planner.py     29 passed
tests/test_api_security_agent_result.py         39 passed
R49 total                                      156 passed
```

Coverage includes identity, canonical category, REST/GraphQL/RPC context,
authentication, authorization, function-level authorization, tenant
isolation, input validation, schema validation, mass assignment, HTTP
method controls, method override, API versioning, resource exposure,
sensitive field exposure, error disclosure, debug exposure, rate
limiting, resource limits, pagination, batch operations, file
upload/download, GraphQL introspection/field authorization/query
complexity, CORS, API key controls, webhook signature/replay,
content-type controls, missing-context handling, confidence calibration,
evidence planning, result schema, R42/R43/R44/R45 compatibility,
R46/R47/R48 interoperability, determinism, AST safety and
negative/speculation/technology-presence/observed-control/
observed-weakness cases.

## 19. Regression results

```
R49 focused suites (5 files)                             156 passed
R38 core suites (7 files)                                132 passed
R39 suites (XSS, 5 files)                                100 passed
R40 suites (SSRF, 5 files)                               122 passed
R41 suites (SQLi, 5 files)                               131 passed
R42 suites (evaluation, 5 files)                          91 passed
R43 suites (collaboration, 5 files)                       88 passed
R44 suites (feedback/learning, 4 files)                   68 passed
R45 suites (advisory + provider, 5 files)                 92 passed
R46 suites (IDOR/BOLA, 5 files)                           97 passed
R47 suites (JWT/authentication, 5 files)                 136 passed
R48 suites (OAuth, 5 files)                              150 passed
Backend test (tests/test_asset_cve_matching.py)           79 passed, 13 subtests
AI safety tests (knowledge_store/xss_researcher/
  xss_llm_researcher/openrouter)                          96 passed
```

No existing test was modified, weakened or fixed. `R40`/`R41` emit the
project's pre-existing warnings only.

## 20. Full-suite result

```
python -m pytest tests/ -q -p no:cacheprovider
4556 passed, 40 failed, 1 warning, 376 subtests passed in 53.51s
```

## 21. Existing failure comparison

Baseline (R48 report): `4400 passed, 40 failed, 376 subtests`.

- passed growth: `4556 - 4400 = 156` — exactly the 156 new R49 tests;
- failed count unchanged at 40; subtests unchanged at 376;
- the 40 failures are the pre-existing money-score/economics corpus-drift
  failures in `test_hunt_queue`, `test_product_api`,
  `test_research_economics_api`, `test_research_economics_calibration`,
  `test_research_economics_projection`, `test_research_opportunities`,
  `test_research_outcomes`, `test_research_sessions`, `test_page_render`,
  `test_daily_research_workflow`, `test_opportunity_action_queue`,
  `test_research_ui`, `test_routers_fixes`.

No failure references `api_security` or `API_SECURITY`, and none was
modified or "fixed".

Environment note: the external MongoDB used by the backend integration
test timed out once on a cold connection (documented in the R41–R48
baselines); an immediate retry passed in 4.5 s. This is environment
variance, not an R49 change.

## 22. Git status

Only new R49 files (12 sources, 5 tests, this report) are added.
Pre-existing unrelated worktree items remain untouched and outside the
commit: ` D utils.zip`, `?? watch.zip`,
`?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`. `git diff --check` is
clean. No unrelated file, deployment unit, shell or backend file is
modified. No push is performed.

Files added:

```
ai/schemas/api_security_agent_identity.py
ai/schemas/api_security_context_analysis.py
ai/schemas/api_security_hypothesis.py
ai/schemas/api_security_evidence_plan.py
ai/schemas/api_security_agent_result.py
ai/schemas/api_security_agent.py
ai/knowledge/api_security_agent_identity.py
ai/knowledge/api_security_context_analyzer.py
ai/knowledge/api_security_hypothesis_planner.py
ai/knowledge/api_security_evidence_planner.py
ai/knowledge/api_security_agent_result_export.py
ai/knowledge/api_security_agent.py
tests/test_api_security_agent_identity.py
tests/test_api_security_context_analyzer.py
tests/test_api_security_hypothesis_planner.py
tests/test_api_security_evidence_planner.py
tests/test_api_security_agent_result.py
agent-reports/stage-r49-api-security-specialist.md
```

## 23. Commit hash

Commit message: `feat(research): add r49 api security specialist agent`.
The hash is reported in the final response after the local commit (the
report is part of the same commit; no amend and no push).

## 24. Limitations

- The canonical R38 category is `RECON`; R38 has no API-specific
  category and was not modified. `API_SECURITY` is a descriptive research
  label. This is deliberate contract conformance (R38/R42/R43
  vocabularies are closed).
- R49 analyzes only structured indicators already supplied; it cannot
  infer API behavior from unrepresented context and does not store URLs,
  endpoints, keys, tokens or payloads.
- Hypothesis priority and context confidence are deterministic design
  choices, not statistical estimates; priority means research
  usefulness, not vulnerability probability.
- API technology presence is never a vulnerability; explicit observed
  control absence is required for `WEAKNESS_OBSERVED`.
- GraphQL introspection and deprecated API versions are conservative
  risk signals only.
- Observed weaknesses are research findings only; no API call,
  endpoint probe, fuzz, payload or exploitation was performed and no
  vulnerability is confirmed.
- Evidence planning lists relevant categories; it neither measures
  sufficiency nor collects anything.
- The R42 generic evaluator reduces specialist-specific context fields
  (systemic across specialist schemas); its fact-count-based calibration
  dimension scores HIGH-confidence specialist results conservatively
  while structure/safety/provenance/governance dimensions pass.
- The full-suite metric includes the same 40 pre-existing corpus-drift
  failures as the R45–R48 baselines.

## 25. Explicit no-execution statement

Explicitly: R49 contains no execution capability of any kind. There is no
HTTP request, API call, endpoint probing, API fuzzing, scanner execution
(nuclei/ffuf/sqlmap), curl execution, network connection, socket, DNS,
database connection, SQL execution, browser automation, credential
testing, authentication/authorization bypass, BOLA/IDOR exploitation,
SSRF/SQLi/XSS exploitation, token manipulation, OAuth flow execution,
payload generation, exploit generation, secret extraction, target-state
modification, external API call, LLM call, filesystem or runtime
persistence, worker or scheduler anywhere in R49. The agent reads
supplied structured context and returns deterministic research
hypotheses and evidence requirements only.

## Agent / Model

Implemented by opencode (model: deepseek-v4.1-flash) on 2026-09-14.
