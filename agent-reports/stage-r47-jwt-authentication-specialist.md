# Stage R47 — JWT / Authentication Specialist Agent

| | |
|---|---|
| Date | 2026-09-14 |
| Stage | R47 |
| Scope | Research-only JWT / authentication specialist agent |
| Follows | R38 / R39 / R40 / R41 / R42 / R43 / R44 / R45 / R46 |
| Commit message | `feat(research): add r47 jwt authentication specialist agent` |
| Push status | **Not pushed** (local commit only) |
| Focused tests | 136 passed |
| Full suite | 4250 passed, 40 failed (unchanged baseline), 376 subtests |

## 1. Objective

Add the R47 JWT / authentication specialist research agent. The agent
analyzes **already-supplied structured authentication/JWT context** and
produces:

1. authentication identity,
2. authentication context analysis,
3. authentication/JWT hypotheses,
4. evidence requirements,
5. a structured specialist result.

R47 is research-only: it never contacts a target, never decodes/forges
tokens, never tests credentials and never executes anything. Technology
presence (JWT, bearer tokens, cookies, algorithm metadata) is treated as
context only and can never, by itself, produce a HIGH-confidence finding.

The implementation follows the established R38–R46 specialist pattern:
`ai/schemas/*` for the contract layer and `ai/knowledge/*` for the pure
deterministic engine layer, with a thin facade module per layer.

## 2. Architecture

```
ai/schemas/
  jwt_authentication_agent_identity.py    R47.1 identity contract
  jwt_authentication_context_analysis.py  R47.2 context contract
  jwt_authentication_hypothesis.py        R47.3 hypothesis contract
  jwt_authentication_evidence_plan.py     R47.4 evidence contract
  jwt_authentication_agent_result.py      R47.5 result contract
  jwt_authentication_agent.py             schema facade

ai/knowledge/
  jwt_authentication_agent_identity.py    deterministic identity planner
  jwt_authentication_context_analyzer.py  deterministic context analyzer
  jwt_authentication_hypothesis_planner.py deterministic hypothesis planner
  jwt_authentication_evidence_planner.py  deterministic evidence planner
  jwt_authentication_agent_result_export.py result exporter (R38 projection)
  jwt_authentication_agent.py             knowledge facade / aggregate entry

tests/
  test_jwt_authentication_agent_identity.py
  test_jwt_authentication_context_analyzer.py
  test_jwt_authentication_hypothesis_planner.py
  test_jwt_authentication_evidence_planner.py
  test_jwt_authentication_agent_result.py
```

Pipeline (`export_jwt_authentication_agent_result`):

```
supplied structured auth context
  -> identity planner        (R38-conformant identity, category = JWT)
  -> context analyzer        (descriptive closed-vocabulary analysis)
  -> hypothesis planner      (closed hypothesis mapping)
  -> evidence planner        (required evidence categories, planning state)
  -> result exporter         (R38 result projection + R37 governance
                              reference + R31-R37 provenance)
```

All layers are pure functions of bounded inputs: no I/O, no network, no
LLM, no Mongo, no wall-clock time, no randomness, no input mutation.
Facade modules only re-export the canonical components and expose
`run_jwt_authentication_agent` as an alias of the result exporter.

## 3. Specialist identity

- `JWT_AUTHENTICATION_CATEGORY = CATEGORY_JWT = "JWT"` — the canonical R38
  category imported from `ai/schemas/security_agent_identity.py`. R38
  already defined `CATEGORY_JWT` (line 40) and its registry references it;
  **R38 was not modified**.
- `JWT_AUTHENTICATION` is a descriptive research label only, never a
  canonical category.
- `agent_id` uses the R38 content-token format (`compute_agent_id`);
  default name `jwt-authentication-specialist`, version `1.0`.
- `supported_contexts` is the closed set of known authentication
  mechanisms (`BEARER_TOKEN`, `JWT_BEARER`, `COOKIE_SESSION`, `OAUTH2`,
  `API_KEY`, `BASIC`, `MUTUAL_TLS`); an empty scope degrades to `UNKNOWN`
  with the `SCOPE_UNKNOWN` limitation.
- `supported_capabilities` is restricted to the R38 analysis-only
  vocabulary (`ANALYZE_CONTEXT`, `ANALYZE_PATTERN`, `CREATE_HYPOTHESIS`,
  `REQUEST_EVIDENCE`, `GENERATE_EXPLANATION`, `RANK_FINDINGS`); R38
  prohibited execution capabilities can never be declared.
- lifecycle is restricted to identity states `CREATED` / `PLANNED`; the
  identity projects onto a valid `SecurityAgentIdentityPlan`.

## 4. Context model

Closed observable fields (all malformed/unsupplied values degrade to
`UNKNOWN`/`NOT_PROVIDED`, never promoted):

- authentication mechanism, token mechanism, token format,
- signing algorithm, signing method,
- signature / algorithm / issuer / audience / expiration / not-before /
  claim validation states (`ENFORCED_OBSERVED`, `ABSENT_OBSERVED`,
  `NOT_PROVIDED`, `UNKNOWN`),
- key management, key rotation,
- token lifetime, refresh token presence, refresh control,
- revocation control,
- session lifecycle (server-side / client-side / stateless token),
- token storage (server-side / memory-only / cookie / localStorage /
  sessionStorage) and cookie attributes (Secure, HttpOnly, SameSite
  variants),
- token exposure (URL / log / response body / client storage),
- authorization boundary, authentication flow, authentication control.

The analyzer distinguishes:

- **OBSERVED** — explicit structured observations (`*_OBSERVED` states,
  enforced/absent controls, exposure/storage facts);
- **INFERRED/CONTEXT** — technology and configuration metadata (JWT
  present, algorithm family, cookie use, session architecture);
- **UNKNOWN / NOT PROVIDED** — absent information.

Determinism: repeated identical input produces byte-identical analysis.
Confidence limitations:

- HIGH requires an explicit observed validation/control weakness **inside
  an authentication context** (mechanism, token, JWT metadata, observed
  authentication control/flow, or observed session lifecycle).
- Isolated lifetime, storage, exposure, key-management, rotation or
  authorization-boundary metadata without any authentication context is
  context only and cannot be promoted to HIGH.
- A stateless-token session is only an observed weakness when explicit
  revocation-control absence is supplied alongside it.
- MEDIUM requires explicit observed control evidence; otherwise LOW;
  nothing usable is UNKNOWN.

## 5. Hypothesis model

Closed vocabulary (18 types, canonical order):

```
JWT_VALIDATION_GAP                SIGNATURE_VERIFICATION_GAP
ALGORITHM_VALIDATION_GAP          CLAIM_VALIDATION_GAP
ISSUER_VALIDATION_GAP             AUDIENCE_VALIDATION_GAP
EXPIRATION_VALIDATION_GAP         NOT_BEFORE_VALIDATION_GAP
KEY_MANAGEMENT_GAP                TOKEN_LIFETIME_RISK
TOKEN_STORAGE_RISK                TOKEN_REVOCATION_GAP
REFRESH_TOKEN_CONTROL_GAP         SESSION_MANAGEMENT_GAP
AUTHENTICATION_FLOW_GAP           AUTHENTICATION_CONTROL_PRESENT
MISSING_AUTHENTICATION_CONTEXT    UNKNOWN
```

Closed hypothesis states: `WEAKNESS_OBSERVED`,
`CONTROL_PRESENT_OBSERVED`, `NEEDS_EVIDENCE`, `NOT_OBSERVED` (available
vocabulary), `UNKNOWN`.

Mapping rules (deterministic, priority = research usefulness only, never
severity/exploitability/CVSS):

- JWT present → per-control gap hypotheses for signature, algorithm,
  claim, issuer, audience, expiration, not-before, plus the umbrella
  `JWT_VALIDATION_GAP` when ≥2 validation states are missing and none is
  observed absent.
- Token present → expiration and revocation gap hypotheses.
- Explicit observed absence → matching gap with `WEAKNESS_OBSERVED` and
  the design priority; not-provided/missing info → `NEEDS_EVIDENCE` at LOW.
- Explicit observed enforcement → no gap for that control, and
  `AUTHENTICATION_CONTROL_PRESENT` (`CONTROL_PRESENT_OBSERVED`) collects
  all enforced control signals.
- Key management: static/embedded → MEDIUM weakness; absent → HIGH
  weakness; configured rotation counts as control.
- Lifetime: long → LOW risk, unbounded → MEDIUM risk.
- Client storage / incomplete cookie attributes / exposure → token
  storage risk (MEDIUM, `WEAKNESS_OBSERVED`).
- Refresh tokens present but refresh control absent → HIGH weakness;
  not provided → NEEDS_EVIDENCE.
- Session: client-side → MEDIUM weakness; stateless → `NEEDS_EVIDENCE`
  unless revocation absence is explicit (then HIGH weakness).
- Authentication control absent → HIGH `AUTHENTICATION_FLOW_GAP`;
  not provided → LOW `NEEDS_EVIDENCE`.
- Observed authentication control/flow/session context itself counts as
  authentication context, so these fields are never silently dropped.
- Nothing usable → `UNKNOWN`; usable but non-hypothesizable context →
  `MISSING_AUTHENTICATION_CONTEXT` (`NEEDS_EVIDENCE`, LOW).
- Technology presence alone (JWT, bearer, cookies, algorithm/claim
  metadata) never produces a gap hypothesis; duplicate hypotheses are
  merged with the first (canonical) determination preserved.

Every hypothesis carries closed supporting signals, rationale and
research limitations (`NO_EXPLOIT_CLAIM`, `NO_VULNERABILITY_CONFIRMATION`,
`NO_SIGNATURE_BYPASS_CLAIM`, `NO_AUTHENTICATION_BYPASS_CLAIM`,
`HYPOTHESIS_ONLY`, `EVIDENCE_REQUIRED`, and `INSUFFICIENT_CONTEXT` where
applicable).

## 6. Evidence planner

Closed evidence vocabulary (25 categories) covering, among others:
signature verification configuration/behavior, algorithm
acceptance/validation behavior, issuer configuration/rules, audience
configuration/rules, expiration policy/behavior, not-before
policy/behavior, claim rules, key management/rotation policy, token
lifetime policy, token storage mechanism, cookie security attributes,
refresh control configuration, revocation configuration, session
lifecycle configuration, authentication flow configuration,
authentication control evidence and validation implementation evidence.

- Required categories are the ordered union of the per-hypothesis
  mappings; the planner never collects evidence.
- Planning state: `UNKNOWN` when nothing can be planned; `COMPLETE` only
  when the context is HIGH confidence, no `UNKNOWN` hypothesis remains
  **and at least one substantive (non-missing-context) hypothesis is
  present**; otherwise `PARTIAL`.
- A context that only degrades to `MISSING_AUTHENTICATION_CONTEXT` can
  never be reported `COMPLETE`, so an isolated weakness signal without an
  authentication context cannot be presented as a completed assessment.
- Confidence: UNKNOWN / LOW / HIGH mirrors the state (`COMPLETE` → HIGH).

## 7. Confidence calibration

| Layer | Rule |
|---|---|
| Context analyzer | UNKNOWN when nothing usable; HIGH only for explicit observed weakness inside an authentication context; MEDIUM for explicit observed control; otherwise LOW |
| Hypothesis | Priority derived per mapping above; technology presence → no weakness hypothesis; not-provided → NEEDS_EVIDENCE/LOW |
| Evidence plan | COMPLETE/HIGH only with a HIGH context, no UNKNOWN hypothesis and at least one substantive hypothesis; otherwise PARTIAL/LOW |
| Result | Confidence = evidence-plan confidence; status COMPLETED only for COMPLETE evidence, ANALYZING for PARTIAL or known context, CREATED for fully unknown |

Conservative examples (verified by tests):

- `token_mechanism="JWT"` alone → context LOW, hypotheses NEEDS_EVIDENCE,
  evidence PARTIAL/LOW, result `ANALYZING`/LOW.
- `token_lifetime="LONG_OBSERVED"` or `token_storage=LOCAL_STORAGE` with
  no authentication context → context LOW, evidence PARTIAL/LOW,
  `ANALYZING`/LOW; no `WEAKNESS_OBSERVED` is emitted.
- `session_lifecycle="STATELESS_TOKEN_OBSERVED"` alone → LOW.
- `signature_verification="ABSENT_OBSERVED"` with JWT present → context
  HIGH, `SIGNATURE_VERIFICATION_GAP` HIGH/`WEAKNESS_OBSERVED`, result
  `COMPLETED`/HIGH (observed control weakness, still only a research
  finding — no exploitation is claimed or performed).
- `authentication_control="ABSENT_OBSERVED"` alone →
  `AUTHENTICATION_FLOW_GAP` HIGH/`WEAKNESS_OBSERVED` (explicit
  authentication-control failure evidence).

R42's confidence-calibration dimension does not flag the conservative
cases as `CONFIDENCE_OVERSTATED` (asserted by test).

## 8. Result contract

`JWTAuthenticationAgentResultPlan` (rule version `r47-5`) with the exact
key set:

```
rule_version, agent_name, agent_identity, status,
context_analysis, hypotheses, evidence_plan, confidence,
limitations, governance_reference, provenance, research_only
```

- `status` ∈ R38 result statuses (`CREATED`, `ANALYZING`, `COMPLETED`,
  `FAILED`, `UNKNOWN`); `confidence` ∈ shared evidence-confidence levels;
  `research_only=True` is enforced.
- `governance_reference` is a bounded R37 reference: `REFERENCED` only
  for the genuine R37 governance export carrying all four component
  records, otherwise `UNKNOWN` with `ready=False` and the
  `GOVERNANCE_UNKNOWN` limitation (unknown governance is never readiness).
- `provenance` records only the R31–R37 layers actually supplied
  (`REASONING`, `MEMORY`, `STRATEGY`, `ORCHESTRATION`, `AUTHORIZATION`,
  `GOVERNANCE`); no layer is invented.
- Observed evidence is preserved exactly; weakness/secret/exploitation
  material is never fabricated.
- `jwt_authentication_agent_result_to_r38` projects the result onto a
  valid `SecurityAgentResultPlan` (`HYPOTHESES_RECORDED` findings
  summary, evidence summary, conservative status rules).

## 9. R42 compatibility

Verified through the generic `evaluate_agent_result` loop without
modifying R42:

- structural validity, enum/rule-version validity, research-only and
  safety compliance all pass;
- `evaluated_agent_category = "JWT"`, `evaluated_result_rule_version =
  "r47-5"`;
- dimension scores include STRUCTURAL_VALIDITY, CONTEXT_COMPLETENESS,
  HYPOTHESIS_SUPPORT, EVIDENCE_COMPLETENESS, CONFIDENCE_CALIBRATION,
  SAFETY_COMPLIANCE, PROVENANCE_COMPLETENESS, GOVERNANCE_COMPLETENESS;
- no `RESEARCH_ONLY_FALSE`, `EXECUTION_CLAIM_DETECTED` or
  `CONFIDENCE_OVERSTATED` diagnostics for the conservative cases;
- hard gate and safety states are always in their closed vocabularies,
  `deterministic=True`, `research_only=True`.

Known generic-integration characteristic (not R47-specific, R42 not
modified): the R42 evaluation input sanitizer keeps only generic context
keys, so specialist-specific context fields are reduced for the
generic fact-count rule. This affects R39–R46 specialist schemas equally;
R47 still evaluates with PASS hard gate and PASS safety state.

## 10. R43 compatibility

Verified through the unmodified R43 `export_multi_agent_collaboration`
API with the R47 result as a participant:

- R39 + R47 (XSS wrapped with its identity),
- R40 + R47 (SSRF),
- R41 + R47 (SQLI),
- R46 + R47 (IDOR).

Each collaboration yields both participating categories, collaboration
rankings for both agents, hypothesis groups, merged evidence and
provenance per participant; the R46 pairing additionally proves
byte-identical repeated collaboration output. Conflict handling,
evidence merge and safety ranking are exercised by the shared R43
pipeline without changes to R43.

## 11. R44 compatibility

Verified without modifying R44:

- `build_research_feedback_event(evaluation_result=...)` from an R47
  evaluation produces a valid event with `source_category="JWT"`;
- `classify_research_feedback_events` and `extract_learning_signals`
  consume it;
- direct JWT feedback events (missing provenance / weak evidence) are
  classified as `PROVENANCE_ISSUE` and produce
  `REQUIRE_MORE_EVIDENCE` signals.

## 12. R45 compatibility

Verified without modifying R45 and without adding any LLM provider:

- `export_llm_advisory(evaluation_result=..., learning_signals=...)`
  consumes an R47-derived evaluation + signals: `validation_state="PASS"`,
  `safety_state="PASS"`, `research_only=True`, non-empty advisory summary
  and `source_refs` containing the R42 reference.
- R47 contains no OpenAI/OpenRouter/Ollama/LLM SDK call; the LLM remains
  advisory only.

## 13. Provenance and governance behavior

- Default result: provenance `UNKNOWN` with empty `source_layers`,
  governance `UNKNOWN` with `ready=False`.
- Supplied R38 input layers are preserved in canonical order
  (`REASONING`, `MEMORY`, `STRATEGY`, `ORCHESTRATION`, `AUTHORIZATION`,
  `GOVERNANCE`); all six gives `COMPLETE`.
- A genuine R37 governance export attaches as `REFERENCED` (`r37-5`) and
  records the `GOVERNANCE` provenance layer; malformed, foreign or
  component-less governance degrades safely to `UNKNOWN`.
- R38 input is validated through `validate_security_agent_input`
  (read-only) and the result through `validate_security_agent_result`.

## 14. Safety boundary

R47 remains strictly research-only. There is no HTTP/HTTPS request, no
DNS resolution, no socket, no browser/Selenium/Playwright, no database
connection or query, no subprocess/shell, no token decoding or
manipulation, no token forging, no signature bypass, no authentication
bypass, no brute force or credential testing, no token replay, no payload
or exploit generation, no attack execution, no secret extraction, no
external API or LLM call, no persistence, worker or scheduler anywhere in
the R47 sources. The agent reasons only over structured data already
supplied to it; token metadata is research context only. No backend file
was modified (including `backend/asset_cve_matching.py`).

## 15. AST safety tests

Every R47 test module contains an AST scan over all 12 R47 modules
(including both facades) rejecting:

- imports: `subprocess`, `socket`, `http`, `urllib`, `requests`, `httpx`,
  `aiohttp`, `asyncio`, `threading`, `multiprocessing`, `concurrent`,
  `importlib`, `ctypes`, `shutil`, `ssl`, `os`, `dns`, `selenium`,
  `playwright`, `pyppeteer`, `paramiko`, `sqlite3`, `sqlalchemy`,
  `psycopg`, `psycopg2`, `pymysql`, `MySQLdb`, `sqlmap`, `nuclei`,
  `curl`, `pycurl`, LLM/provider SDKs (`openai`, `ollama`, `litellm`,
  `anthropic`, `openrouter`) and JWT libraries (`jwt`, `pyjwt`, `jose`);
- calls: `__import__`, `eval`, `exec`, `compile`, `open`, plus forbidden
  call prefixes (`subprocess.`, `os.system`, `os.popen`, `importlib.`,
  `socket.`, `urllib.`, `requests.`, `httpx.`, SQL clients, `openai.`).

A forbidden-output test scans serialized results for payload/attack
tokens (`payload:`, `<script`, `union select`, `execute this`,
`run this command`, `signature bypassed`, `authentication bypassed`,
`forge token`, `steal token`, `secret key is`, `brute force password`,
etc.); none are present. A standalone-backend test asserts
`backend/asset_cve_matching.py` contains no R47 references.

## 16. Determinism tests

Repeated runs are byte-identical for identity, context analysis,
hypotheses, evidence plans and results; the agent id is a deterministic
content token; canonical ordering is asserted for hypotheses, evidence
items and source layers; serialized output contains no `timestamp`,
`uuid` or `runtime_id`. Repeated-execution equality is asserted for the
full result, and identical input yields the same result across separate
processes and `PYTHONHASHSEED` values.

## 17. Focused test results

```
tests/test_jwt_authentication_agent_identity.py      16 passed
tests/test_jwt_authentication_context_analyzer.py    30 passed
tests/test_jwt_authentication_hypothesis_planner.py  28 passed
tests/test_jwt_authentication_evidence_planner.py    25 passed
tests/test_jwt_authentication_agent_result.py        37 passed
R47 total                                           136 passed
```

Coverage includes identity, context analysis, JWT detection,
authentication-mechanism detection, signature/algorithm/issuer/audience/
expiration/not-before/claim reasoning, key-management reasoning, token
storage reasoning, refresh-token reasoning, revocation/session
reasoning, missing-context handling, confidence calibration, evidence
planning, result schema, R42/R43/R44/R45 compatibility, determinism, AST
safety and negative/speculation cases.

## 18. Regression results

```
R47 focused suites (5 files)                             136 passed
R38 core suites (7 files)                                132 passed
R38 agent planning (coordination + role, 2 files)         40 passed
R39 suites (XSS, 5 files)                                100 passed
R40 suites (SSRF, 5 files)                               122 passed
R41 suites (SQLi, 5 files)                               131 passed
R42 suites (evaluation, 5 files)                          91 passed
R43 suites (collaboration, 5 files)                       88 passed
R44 suites (feedback/learning, 4 files)                   68 passed
R45 suites (advisory + provider, 5 files)                 92 passed
R46 suites (IDOR/BOLA, 5 files)                           97 passed
Backend test (tests/test_asset_cve_matching.py)           79 passed, 13 subtests
AI safety tests (knowledge_store/xss_researcher/
  xss_llm_researcher/openrouter)                          96 passed
```

No existing test was modified, weakened or fixed. `R40`/`R41` emit the
project's pre-existing warnings only.

## 19. Full-suite result

```
python -m pytest tests/ -q -p no:cacheprovider
4250 passed, 40 failed, 1 warning, 376 subtests passed in 45.87s
```

## 20. Existing failure comparison

Baseline (R46 report): `4114 passed, 40 failed`.

- passed growth: `4250 - 4114 = 136` — exactly the 136 new R47 tests;
- failed count unchanged at 40;
- the 40 failures are the pre-existing money-score/economics corpus-drift
  failures in `test_hunt_queue`, `test_product_api`,
  `test_research_economics_api`, `test_research_economics_calibration`,
  `test_research_economics_projection`, `test_research_opportunities`,
  `test_research_outcomes`, `test_research_sessions`, `test_page_render`,
  `test_daily_research_workflow`, `test_opportunity_action_queue`,
  `test_research_ui`, `test_routers_fixes`.

No failure references `jwt_authentication` or `JWT`, and none was
modified or "fixed".

Environment note: one run of the backend integration test
(`tests/test_asset_cve_matching.py`) timed out while the external MongoDB
connection was cold; an immediate retry passed in 4.5 s. This is the
same environment variance documented in the R41/R46 baselines, not an R47
change.

## 21. Git status

Only new R47 files (12 sources, 5 tests, this report) are added.
Pre-existing unrelated worktree items remain untouched and outside the
commit: ` D utils.zip`, `?? watch.zip`,
`?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`. `git diff --check` is
clean. No unrelated file, deployment unit, shell or backend file is
modified. No push is performed.

Files added:

```
ai/schemas/jwt_authentication_agent_identity.py
ai/schemas/jwt_authentication_context_analysis.py
ai/schemas/jwt_authentication_hypothesis.py
ai/schemas/jwt_authentication_evidence_plan.py
ai/schemas/jwt_authentication_agent_result.py
ai/schemas/jwt_authentication_agent.py
ai/knowledge/jwt_authentication_agent_identity.py
ai/knowledge/jwt_authentication_context_analyzer.py
ai/knowledge/jwt_authentication_hypothesis_planner.py
ai/knowledge/jwt_authentication_evidence_planner.py
ai/knowledge/jwt_authentication_agent_result_export.py
ai/knowledge/jwt_authentication_agent.py
tests/test_jwt_authentication_agent_identity.py
tests/test_jwt_authentication_context_analyzer.py
tests/test_jwt_authentication_hypothesis_planner.py
tests/test_jwt_authentication_evidence_planner.py
tests/test_jwt_authentication_agent_result.py
agent-reports/stage-r47-jwt-authentication-specialist.md
```

## 22. Commit hash

Commit message: `feat(research): add r47 jwt authentication specialist agent`.
The hash is reported in the final response after the local commit (the
report is part of the same commit; no amend and no push).

## 23. Limitations

- The canonical R38 category is `JWT`; `JWT_AUTHENTICATION` is a
  descriptive research label. R38/R39–R46 vocabularies were not modified.
- R47 analyzes only structured indicators already supplied; it cannot
  infer authentication or token behavior from unrepresented context.
- Hypothesis priority and context confidence are deterministic design
  choices, not statistical estimates; they mean research usefulness, not
  vulnerability probability.
- No token content is decoded, parsed or validated; "JWT present" is a
  context label, never a vulnerability.
- Observed weaknesses are research findings only; no exploitation is
  performed and no vulnerability is confirmed.
- Evidence planning lists relevant categories; it neither measures
  sufficiency nor collects anything.
- The R42 generic evaluator reduces specialist-specific context fields
  (systemic across specialist schemas); its fact-count-based calibration
  dimension therefore scores HIGH-confidence specialist results
  conservatively while structure/safety/provenance/governance
  dimensions pass.
- The full-suite metric includes the same 40 pre-existing corpus-drift
  failures as the R45/R46 baselines.

## 24. Explicit no-execution statement

Explicitly: R47 contains no execution capability of any kind. There is no
HTTP request, DNS resolution, socket, database connection, SQL execution,
browser, token decoding/manipulation, token forging, signature bypass,
authentication bypass, credential testing, brute force, token replay,
payload generation, scanner, subprocess, shell command, secret
extraction, target-state modification, external API call, LLM call,
filesystem or runtime persistence, worker or scheduler anywhere in R47.
The agent reads supplied structured context and returns deterministic
research hypotheses and evidence requirements only.

## Agent / Model

Implemented by opencode (model: deepseek-v4.1-flash) on 2026-09-14.
