# Stage R48 — OAuth Specialist Agent

| | |
|---|---|
| Date | 2026-09-14 |
| Stage | R48 |
| Scope | Research-only OAuth protocol / authorization-flow specialist agent |
| Follows | R38 / R39 / R40 / R41 / R42 / R43 / R44 / R45 / R46 / R47 |
| Commit message | `feat(research): add r48 oauth specialist agent` |
| Push status | **Not pushed** (local commit only) |
| Focused tests | 150 passed |
| Full suite | 4400 passed, 40 failed (unchanged baseline), 376 subtests |

## 1. Objective

Add the R48 OAuth specialist research agent. The agent analyzes
**already-supplied structured OAuth protocol context** and produces:

1. OAuth specialist identity,
2. OAuth context analysis,
3. OAuth hypotheses,
4. evidence requirements,
5. a structured specialist result.

R48 is research-only: it never contacts a target, OAuth provider,
authorization server, callback or token endpoint; it never follows
redirects, exchanges tokens, replays codes, manipulates state/nonce/PKCE
or tests credentials. Technology presence (OAuth, redirect_uri, state,
nonce, PKCE, scopes, client ids, authorization codes, refresh tokens) is
context only and can never, by itself, produce a HIGH-confidence finding.

The implementation follows the established R38–R47 specialist pattern
(`ai/schemas/*` contracts, `ai/knowledge/*` pure engines, thin facades,
`tests/test_oauth_*.py` focused suites). R46 (IDOR/BOLA) and R47
(JWT/authentication) were not modified; overlapping responsibilities stay
with their primary specialist.

## 2. Architecture

```
ai/schemas/
  oauth_agent_identity.py       R48.1 identity contract
  oauth_context_analysis.py     R48.2 context contract
  oauth_hypothesis.py           R48.3 hypothesis contract
  oauth_evidence_plan.py        R48.4 evidence contract
  oauth_agent_result.py         R48.5 result contract
  oauth_agent.py                schema facade

ai/knowledge/
  oauth_agent_identity.py       deterministic identity planner
  oauth_context_analyzer.py     deterministic context analyzer
  oauth_hypothesis_planner.py   deterministic hypothesis planner
  oauth_evidence_planner.py     deterministic evidence planner
  oauth_agent_result_export.py  result exporter (R38 projection)
  oauth_agent.py                knowledge facade / aggregate entry

tests/
  test_oauth_agent_identity.py
  test_oauth_context_analyzer.py
  test_oauth_hypothesis_planner.py
  test_oauth_evidence_planner.py
  test_oauth_agent_result.py
```

Pipeline (`export_oauth_agent_result`):

```
supplied structured OAuth context
  -> identity planner        (R38-conformant identity, category = OAUTH)
  -> context analyzer        (descriptive closed-vocabulary analysis)
  -> hypothesis planner      (closed hypothesis mapping)
  -> evidence planner        (required evidence categories, planning state)
  -> result exporter         (R38 result projection + R37 governance
                              reference + R31-R37 provenance)
```

All layers are pure functions of bounded inputs: no I/O, no network, no
LLM, no Mongo, no wall-clock time, no randomness, no input mutation.
Facade modules only re-export canonical components and expose
`run_oauth_agent` as an alias of the result exporter.

## 3. Specialist identity

- `OAUTH_CATEGORY = CATEGORY_OAUTH = "OAUTH"` — the canonical R38 closed
  category imported from `ai/schemas/security_agent_identity.py` (line
  41). R38 already mapped `CATEGORY_OAUTH` in the capability table and
  registry; **R38 was not modified**.
- `OAUTH_FLOW` is a descriptive research label only, never a canonical
  category.
- `agent_id` uses the R38 content-token format (`compute_agent_id`);
  default name `oauth-specialist`, version `1.0`.
- `supported_contexts` is the closed set of known OAuth flows
  (`AUTHORIZATION_CODE`, `AUTHORIZATION_CODE_PKCE`, `IMPLICIT`,
  `CLIENT_CREDENTIALS`, `DEVICE_AUTHORIZATION`, `REFRESH_TOKEN`,
  `HYBRID`); an empty scope degrades to `UNKNOWN` with
  `SCOPE_UNKNOWN`.
- `supported_capabilities` is restricted to the R38 analysis-only
  vocabulary (`ANALYZE_CONTEXT`, `ANALYZE_PATTERN`, `CREATE_HYPOTHESIS`,
  `REQUEST_EVIDENCE`, `GENERATE_EXPLANATION`, `RANK_FINDINGS`); R38
  prohibited execution capabilities can never be declared.
- lifecycle is restricted to identity states `CREATED` / `PLANNED`; the
  identity projects onto a valid `SecurityAgentIdentityPlan`.

## 4. Context model

Closed observable fields (all malformed/unsupplied values degrade to
`UNKNOWN`/`NOT_PROVIDED`, never promoted):

- OAuth version (`OAUTH2`, `OAUTH2_1`), flow (7 flows), client type
  (`PUBLIC_CLIENT`, `CONFIDENTIAL_CLIENT`);
- actor/endpoint context: authorization server, resource server,
  authorization endpoint, token endpoint, `redirect_uri`, `client_id`,
  `response_type`, `grant_type`, scope context, `state`, `nonce`, PKCE
  challenge (presence observations only, never values);
- 20 validation/control states with the shared four-state vocabulary
  (`ENFORCED_OBSERVED`, `ABSENT_OBSERVED`, `NOT_PROVIDED`, `UNKNOWN`):
  redirect URI validation, exact redirect matching, state validation,
  state/session binding, nonce validation, PKCE enforcement, PKCE
  verifier validation, authorization-code binding, code reuse control,
  client authentication, scope validation, resource/audience validation,
  issuer validation, token validation, refresh-token rotation,
  refresh-token revocation, consent control, CSRF protection, login CSRF
  protection, redirect handling;
- client configuration: redirect URI registration (`EXACT_REGISTERED`,
  `WILDCARD_REGISTERED`), authorization-code lifetime, token endpoint
  authentication method, client secret usage;
- refresh-token presence, authorization boundary, session integration,
  token exposure (URL / browser storage / response body / log / referrer
  / client storage).

The analyzer distinguishes **OBSERVED** facts, **INFERRED/CONTEXT**
technology metadata and **UNKNOWN / NOT PROVIDED** information.

Determinism: repeated identical input produces byte-identical analysis.
Privacy: no URLs, secrets, tokens, codes or verifiers are stored — only
closed presence/validation labels.

## 5. Hypothesis model

Closed deterministic vocabulary (26 types, canonical order):

```
REDIRECT_URI_VALIDATION_GAP        STATE_VALIDATION_GAP
NONCE_VALIDATION_GAP               PKCE_ENFORCEMENT_GAP
PKCE_VERIFIER_VALIDATION_GAP       AUTHORIZATION_CODE_VALIDATION_GAP
AUTHORIZATION_CODE_REUSE_GAP       AUTHORIZATION_CODE_LIFETIME_RISK
CLIENT_AUTHENTICATION_GAP          CLIENT_CONFIGURATION_GAP
SCOPE_VALIDATION_GAP               RESOURCE_AUDIENCE_VALIDATION_GAP
ISSUER_VALIDATION_GAP              TOKEN_VALIDATION_GAP
REFRESH_TOKEN_ROTATION_GAP         REFRESH_TOKEN_REVOCATION_GAP
CONSENT_CONTROL_GAP                CSRF_PROTECTION_GAP
LOGIN_CSRF_GAP                     REDIRECT_HANDLING_RISK
IMPLICIT_FLOW_RISK                 TOKEN_EXPOSURE_RISK
AUTHORIZATION_FLOW_GAP             AUTHENTICATION_CONTROL_PRESENT
MISSING_OAUTH_CONTEXT              UNKNOWN
```

Closed hypothesis states: `WEAKNESS_OBSERVED`,
`CONTROL_PRESENT_OBSERVED`, `NEEDS_EVIDENCE`, `NOT_OBSERVED` (available
vocabulary), `UNKNOWN`.

Mapping rules (deterministic; priority is research usefulness only, never
severity/exploitability/CVSS):

- Redirect URI: explicit absent validation → `REDIRECT_URI_VALIDATION_GAP`
  HIGH/`WEAKNESS_OBSERVED`; not provided where relevant → NEEDS_EVIDENCE;
  exact-matching absence and wildcard registration are additional
  supported signals; nothing is called an open redirect.
- State: explicit absent validation → `STATE_VALIDATION_GAP` HIGH;
  presence alone never a gap.
- Nonce: only when the supplied flow/context makes nonce relevant
  (nonce observed or implicit/hybrid); explicit absence → HIGH.
- PKCE: required for public clients / PKCE flows / observed challenge;
  explicit absent enforcement → `PKCE_ENFORCEMENT_GAP` HIGH; verifier
  validation absence → `PKCE_VERIFIER_VALIDATION_GAP` HIGH.
- Authorization code: binding absence → `AUTHORIZATION_CODE_VALIDATION_GAP`
  HIGH; reusable codes → `AUTHORIZATION_CODE_REUSE_GAP` HIGH; long
  lifetime → LOW risk, unbounded → MEDIUM risk.
- Client authentication: required for confidential clients or observed
  token endpoint auth method; explicit absence (including explicit
  `NONE_OBSERVED` auth method on a confidential client) → HIGH; public
  clients are never penalized for not authenticating.
- Client configuration: wildcard registered redirect URIs or
  not-required client secrets on a confidential client → MEDIUM risk.
- Scope: explicit absent validation → `SCOPE_VALIDATION_GAP` HIGH; broad
  scope names alone are context only.
- Resource/audience, issuer and token validation: explicit absence →
  HIGH; not provided → NEEDS_EVIDENCE.
- Refresh tokens: present token with explicit absent rotation/revocation
  → HIGH; not provided → NEEDS_EVIDENCE; token presence alone is not a
  hypothesis of weakness.
- Consent: explicit absence → MEDIUM risk; not provided → NEEDS_EVIDENCE
  for interactive flows.
- CSRF / login CSRF: interactive-flow gated; explicit absence → HIGH;
  not provided → NEEDS_EVIDENCE; never claimed merely because state is
  not mentioned.
- Redirect handling: explicit absence → `REDIRECT_HANDLING_RISK` HIGH.
- Implicit flow: `IMPLICIT_FLOW_RISK` LOW/`WEAKNESS_OBSERVED` as a risk
  signal only — explicitly not a confirmed vulnerability.
- Token exposure: observed exposure → `TOKEN_EXPOSURE_RISK` MEDIUM.
- Authorization boundary: client-side-only → `AUTHORIZATION_FLOW_GAP`
  MEDIUM; mixed → NEEDS_EVIDENCE; server-side → control signal.
- Explicit observed enforcement → `AUTHENTICATION_CONTROL_PRESENT`
  (`CONTROL_PRESENT_OBSERVED`) and no gap for that control.
- Nothing usable → `UNKNOWN`; usable but non-hypothesizable context →
  `MISSING_OAUTH_CONTEXT` (`NEEDS_EVIDENCE`, LOW).

Duplicate hypotheses are merged in canonical order; every hypothesis
carries closed supporting signals, rationale and research limitations
(`NO_EXPLOIT_CLAIM`, `NO_VULNERABILITY_CONFIRMATION`,
`NO_OAUTH_BYPASS_CLAIM`, `NO_REDIRECT_URI_EXPLOIT_CLAIM`,
`NO_TOKEN_EXCHANGE_CLAIM`, `NO_CSRF_EXPLOIT_CLAIM`, `HYPOTHESIS_ONLY`,
`EVIDENCE_REQUIRED`, plus `INSUFFICIENT_CONTEXT` where applicable).

## 6. Evidence planner

Closed evidence vocabulary (36 categories) covering redirect URI
registration/matching/validation behavior, state generation/session
binding/validation behavior, nonce validation behavior, PKCE enforcement
policy/challenge method/verifier validation, authorization-code
lifetime/one-time-use/binding/replay controls, client type/authentication
method/registration configuration, requested/granted scopes and scope
validation policy, resource indicator/audience validation, issuer and
token validation configuration, refresh rotation/revocation/reuse
detection, consent configuration, CSRF and login-CSRF request binding,
redirect handling configuration, authorization flow configuration,
token storage/exposure context and authorization server configuration.

- Required categories are the ordered union of the per-hypothesis
  mappings; the planner never collects evidence.
- Planning state: `UNKNOWN` when nothing can be planned; `COMPLETE` only
  when the context is HIGH confidence, no `UNKNOWN` hypothesis remains
  and at least one substantive (non-missing-context) hypothesis is
  present; otherwise `PARTIAL`.
- A context that only degrades to `MISSING_OAUTH_CONTEXT` can never be
  `COMPLETE`, so isolated risk metadata cannot be presented as a
  completed assessment.
- Confidence: UNKNOWN / LOW / HIGH mirrors the state.

## 7. Confidence calibration

| Layer | Rule |
|---|---|
| Context analyzer | UNKNOWN when nothing usable; HIGH only for explicit observed weakness inside an OAuth protocol context; MEDIUM for explicit observed control; otherwise LOW |
| Hypothesis | Priority derived per mapping above; technology presence → no weakness hypothesis; not-provided → NEEDS_EVIDENCE/LOW |
| Evidence plan | COMPLETE/HIGH only with a HIGH context, no UNKNOWN hypothesis and at least one substantive hypothesis; otherwise PARTIAL/LOW |
| Result | Confidence = evidence-plan confidence; status COMPLETED only for COMPLETE evidence, ANALYZING for PARTIAL or known context, CREATED for fully unknown |

Conservative examples (verified by tests):

- `oauth_version="OAUTH2"` alone → context LOW, `MISSING_OAUTH_CONTEXT`
  NEEDS_EVIDENCE, result `ANALYZING`/LOW.
- `flow="AUTHORIZATION_CODE"` alone → all validation gaps
  NEEDS_EVIDENCE/LOW.
- `redirect_uri`, `state`, `nonce`, PKCE challenge or scope presence
  alone → context LOW, no `WEAKNESS_OBSERVED`.
- implicit flow metadata → `IMPLICIT_FLOW_RISK` LOW only.
- isolated exposure/session/boundary/validation-absence metadata without
  an OAuth protocol context → context LOW, `MISSING_OAUTH_CONTEXT`,
  `ANALYZING`/LOW.
- explicit `redirect_uri_validation="ABSENT_OBSERVED"` with OAuth context
  → REDIRECT_URI_VALIDATION_GAP HIGH/`WEAKNESS_OBSERVED`, result
  `COMPLETED`/HIGH — an observed control weakness, still only a research
  finding (no exploitation is claimed or performed).
- explicit `authorization_code_reuse_control("code_reuse_control")
  ="ABSENT_OBSERVED"` → `AUTHORIZATION_CODE_REUSE_GAP`
  HIGH/`WEAKNESS_OBSERVED`.
- explicit refresh rotation/revocation absence → HIGH research findings.

R42's confidence-calibration dimension does not flag the conservative
cases as `CONFIDENCE_OVERSTATED` (asserted by test).

## 8. Result contract

`OAuthAgentResultPlan` (rule version `r48-5`) with the exact key set:

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
- `oauth_agent_result_to_r38` projects the result onto a valid
  `SecurityAgentResultPlan` (`HYPOTHESES_RECORDED` findings summary,
  evidence summary, conservative status rules).

## 9. R42 compatibility

Verified through the generic `evaluate_agent_result` loop without
modifying R42:

- structural validity, enum/rule-version validity, research-only and
  safety compliance all pass;
- `evaluated_agent_category = "OAUTH"`, `evaluated_result_rule_version =
  "r48-5"`;
- dimension scores include STRUCTURAL_VALIDITY, CONTEXT_COMPLETENESS,
  HYPOTHESIS_SUPPORT, EVIDENCE_COMPLETENESS, CONFIDENCE_CALIBRATION,
  SAFETY_COMPLIANCE, PROVENANCE_COMPLETENESS, GOVERNANCE_COMPLETENESS;
- no `RESEARCH_ONLY_FALSE`, `EXECUTION_CLAIM_DETECTED` or
  `CONFIDENCE_OVERSTATED` diagnostics for conservative cases;
- hard gate and safety states are always in their closed vocabularies,
  `deterministic=True`, `research_only=True`.

Known generic-integration characteristic (not R48-specific, R42 not
modified): the R42 evaluation input sanitizer keeps only generic context
keys, so specialist-specific context fields are reduced for the generic
fact-count rule. This affects R39–R47 specialist schemas equally; R48
still evaluates with PASS hard gate and PASS safety state.

## 10. R43 compatibility

Verified through the unmodified R43 `export_multi_agent_collaboration`
API with the R48 result as a participant:

- R39 + R48 (XSS wrapped with its identity),
- R40 + R48 (SSRF),
- R41 + R48 (SQLI),
- R46 + R48 (IDOR/BOLA),
- R47 + R48 (JWT/authentication).

Each collaboration yields both participating categories, collaboration
rankings for both agents, hypothesis groups, merged evidence and
provenance per participant; repeated R46 and R47 collaborations are
byte-identical. Conflict handling, evidence merge and safety ranking are
exercised by the shared R43 pipeline without changes to R43.

## 11. R44 compatibility

Verified without modifying R44:

- `build_research_feedback_event(evaluation_result=...)` from an R48
  evaluation produces a valid event with `source_category="OAUTH"`;
- `classify_research_feedback_events` and `extract_learning_signals`
  consume it;
- direct OAuth feedback events (missing provenance / weak evidence) are
  classified as `PROVENANCE_ISSUE` and produce
  `REQUIRE_MORE_EVIDENCE` signals.

## 12. R45 compatibility

Verified without modifying R45 and without adding any LLM provider:

- `export_llm_advisory(evaluation_result=..., learning_signals=...)`
  consumes an R48-derived evaluation + signals:
  `validation_state="PASS"`, `safety_state="PASS"`,
  `research_only=True`, non-empty advisory summary and `source_refs`
  containing the R42 reference.
- R48 contains no OpenAI/OpenRouter/Ollama/Anthropic call; the LLM
  remains advisory only.

## 13. R46 / R47 interoperability

- R46 remains the primary IDOR/BOLA object-authorization specialist;
  R48 does not model object ownership or per-object authorization.
- R47 remains the primary JWT signature/claim-validation specialist; R48
  covers the OAuth protocol and authorization-flow side (redirect URI,
  state, nonce, PKCE, code, client authentication, scopes, refresh
  tokens) and only identifies OAuth-side validation requirements.
- R48 participates with both in R43 collaboration (tests above) without
  modifying either specialist or duplicating their hypotheses.

## 14. Provenance and governance behavior

- Default result: provenance `UNKNOWN` with empty `source_layers`,
  governance `UNKNOWN` with `ready=False`.
- Supplied R38 input layers are preserved in canonical order; all six
  gives `COMPLETE`.
- A genuine R37 governance export attaches as `REFERENCED` (`r37-5`) and
  records the `GOVERNANCE` provenance layer; malformed, foreign or
  component-less governance degrades safely to `UNKNOWN`.
- R38 input is validated through `validate_security_agent_input`
  (read-only) and the result through `validate_security_agent_result`.

## 15. Safety boundary

R48 remains strictly research-only. There is no HTTP/HTTPS request, no
OAuth authorization request, no token endpoint request, no callback
request, no redirect following, no browser/Selenium/Playwright, no DNS
resolution, no socket, no database connection or SQL, no
subprocess/shell, no token exchange (authorization-code or refresh), no
token replay or forgery, no state/nonce/PKCE manipulation, no CSRF or
redirect_uri exploitation, no OAuth/authentication/authorization bypass,
no credential testing, no payload or exploit generation, no secret
extraction, no external API or LLM call, no persistence, worker or
scheduler anywhere in the R48 sources. The agent reasons only over
structured data already supplied; OAuth parameters are context labels
only. No backend file was modified (including
`backend/asset_cve_matching.py`).

## 16. AST safety tests

Every R48 test module contains an AST scan over all 12 R48 modules
(including both facades) rejecting:

- imports: `subprocess`, `socket`, `http`, `urllib`, `requests`, `httpx`,
  `aiohttp`, `asyncio`, `threading`, `multiprocessing`, `concurrent`,
  `importlib`, `ctypes`, `shutil`, `ssl`, `os`, `dns`, `selenium`,
  `playwright`, `pyppeteer`, `paramiko`, `sqlite3`, `sqlalchemy`,
  `psycopg`, `psycopg2`, `pymysql`, `MySQLdb`, `sqlmap`, `nuclei`,
  `curl`, `pycurl`, LLM/provider SDKs (`openai`, `ollama`, `litellm`,
  `anthropic`, `openrouter`), JWT libraries (`jwt`, `pyjwt`, `jose`) and
  OAuth/identity client libraries (`oauthlib`, `authlib`, `oauth2`,
  `oauth2client`, `requests_oauthlib`, `msal`, `google`);
- calls: `__import__`, `eval`, `exec`, `compile`, `open`, plus forbidden
  call prefixes (`subprocess.`, `os.system`, `os.popen`, `importlib.`,
  `socket.`, `urllib.`, `requests.`, `httpx.`, SQL clients, `openai.`,
  `oauthlib.`, `authlib.`, `msal.`).

A forbidden-output test scans serialized results for payload/attack/secret
tokens (`payload:`, `<script`, `union select`, `execute this`,
`run this command`, `oauth bypassed`, `exchange the code`,
`replay the code`, `replay the token`, `forge token`, `steal token`,
`redirect chaining`, `csrf payload`, `secret key is`, `client_secret=`,
`brute force password`, etc.); none are present, and no
`code_verifier`/secret values appear. A standalone-backend test asserts
`backend/asset_cve_matching.py` contains no R48 references.

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
tests/test_oauth_agent_identity.py       16 passed
tests/test_oauth_context_analyzer.py     34 passed
tests/test_oauth_hypothesis_planner.py   32 passed
tests/test_oauth_evidence_planner.py     30 passed
tests/test_oauth_agent_result.py         38 passed
R48 total                               150 passed
```

Coverage includes identity, canonical category, OAuth version/flow/
client-type detection, redirect URI, state, nonce, PKCE, authorization
code (binding/reuse/lifetime), client authentication, client
configuration, scope, resource/audience, issuer, token validation,
refresh-token, consent, CSRF, login-CSRF, implicit-flow, token exposure,
missing-context handling, confidence calibration, evidence planning,
result schema, R42/R43/R44/R45 compatibility, R46/R47 interoperability,
determinism, AST safety and negative/speculation/technology-presence/
observed-control/observed-weakness cases.

## 19. Regression results

```
R48 focused suites (5 files)                             150 passed
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
Backend test (tests/test_asset_cve_matching.py)           79 passed, 13 subtests
AI safety tests (knowledge_store/xss_researcher/
  xss_llm_researcher/openrouter)                          96 passed
```

No existing test was modified, weakened or fixed. `R40`/`R41` emit the
project's pre-existing warnings only.

## 20. Full-suite result

```
python -m pytest tests/ -q -p no:cacheprovider
4400 passed, 40 failed, 1 warning, 376 subtests passed in 45.26s
```

## 21. Existing failure comparison

Baseline (R47 report): `4250 passed, 40 failed, 376 subtests`.

- passed growth: `4400 - 4250 = 150` — exactly the 150 new R48 tests;
- failed count unchanged at 40; subtests unchanged at 376;
- the 40 failures are the pre-existing money-score/economics corpus-drift
  failures in `test_hunt_queue`, `test_product_api`,
  `test_research_economics_api`, `test_research_economics_calibration`,
  `test_research_economics_projection`, `test_research_opportunities`,
  `test_research_outcomes`, `test_research_sessions`, `test_page_render`,
  `test_daily_research_workflow`, `test_opportunity_action_queue`,
  `test_research_ui`, `test_routers_fixes`.

No failure references `oauth_agent` or `OAUTH`, and none was modified or
"fixed".

Environment note: the external MongoDB used by the backend integration
test can time out on a cold connection (documented in the R41–R47
baselines); an immediate retry passed in 4.4 s. This is environment
variance, not an R48 change.

## 22. Git status

Only new R48 files (12 sources, 5 tests, this report) are added.
Pre-existing unrelated worktree items remain untouched and outside the
commit: ` D utils.zip`, `?? watch.zip`,
`?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`. `git diff --check` is
clean. No unrelated file, deployment unit, shell or backend file is
modified. No push is performed.

Files added:

```
ai/schemas/oauth_agent_identity.py
ai/schemas/oauth_context_analysis.py
ai/schemas/oauth_hypothesis.py
ai/schemas/oauth_evidence_plan.py
ai/schemas/oauth_agent_result.py
ai/schemas/oauth_agent.py
ai/knowledge/oauth_agent_identity.py
ai/knowledge/oauth_context_analyzer.py
ai/knowledge/oauth_hypothesis_planner.py
ai/knowledge/oauth_evidence_planner.py
ai/knowledge/oauth_agent_result_export.py
ai/knowledge/oauth_agent.py
tests/test_oauth_agent_identity.py
tests/test_oauth_context_analyzer.py
tests/test_oauth_hypothesis_planner.py
tests/test_oauth_evidence_planner.py
tests/test_oauth_agent_result.py
agent-reports/stage-r48-oauth-specialist.md
```

## 23. Commit hash

Commit message: `feat(research): add r48 oauth specialist agent`. The
hash is reported in the final response after the local commit (the report
is part of the same commit; no amend and no push).

## 24. Limitations

- The canonical R38 category is `OAUTH`; `OAUTH_FLOW` is a descriptive
  research label. R38/R39–R47 vocabularies were not modified.
- R48 analyzes only structured indicators already supplied; it cannot
  infer OAuth behavior from unrepresented context and does not store
  URLs, client secrets, tokens, codes or verifiers.
- Hypothesis priority and context confidence are deterministic design
  choices, not statistical estimates; priority means research
  usefulness, not vulnerability probability.
- OAuth parameter presence is never a vulnerability; explicit observed
  control absence is required for `WEAKNESS_OBSERVED`.
- Implicit flow is treated as a conservative risk signal only.
- Observed weaknesses are research findings only; no OAuth flow, token
  exchange, redirect, CSRF or replay was performed and no vulnerability
  is confirmed.
- Evidence planning lists relevant categories; it neither measures
  sufficiency nor collects anything.
- The R42 generic evaluator reduces specialist-specific context fields
  (systemic across specialist schemas); its fact-count-based calibration
  dimension scores HIGH-confidence specialist results conservatively
  while structure/safety/provenance/governance dimensions pass.
- The full-suite metric includes the same 40 pre-existing corpus-drift
  failures as the R45–R47 baselines.

## 25. Explicit no-execution statement

Explicitly: R48 contains no execution capability of any kind. There is no
HTTP request, OAuth authorization/token/callback request, redirect
following, DNS resolution, socket, database connection, SQL execution,
browser, token decoding/exchange, authorization-code exchange,
refresh-token exchange, token replay, token forging, state/nonce/PKCE
manipulation, CSRF exploitation, redirect_uri exploitation, open-redirect
exploitation, OAuth/authentication/authorization bypass, credential
testing, payload generation, scanner, subprocess, shell command, secret
extraction, target-state modification, external API call, LLM call,
filesystem or runtime persistence, worker or scheduler anywhere in R48.
The agent reads supplied structured context and returns deterministic
research hypotheses and evidence requirements only.

## Agent / Model

Implemented by opencode (model: deepseek-v4.1-flash) on 2026-09-14.
