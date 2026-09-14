# Stage R45 — LLM Advisory Layer

An optional, deterministic intelligence-assistance layer that consumes
structured research artifacts and produces human-readable advisory output.
R45 is an **advisor only**: it does not execute anything, does not test
security, does not confirm vulnerabilities, does not generate payloads and
does not modify agents, rules, strategy or governance. Version 1 is
contract + governance + mock provider only; no real LLM connection exists.

- Stage: R45
- Rule versions: `r45-1` … `r45-6`
- Commit message: `feat(research): add r45 llm advisory layer` (local only,
  not pushed; hash reported in the final response)

## 1. Objective

Answer: **"How can structured security research intelligence be explained to
a human?"** — while making explicit that R45 does NOT answer "How do we
exploit the target?", "What payload should we send?", "Is the vulnerability
confirmed?" or "How do we execute an attack?".

The core principle is preserved:

```
Deterministic Intelligence        LLM Decision
        |                              |
        v                              v
   LLM Advisory          NOT       Execution
        |                              |
        v                              v
 Human Explanation             Security Decision
```

R42 owns evaluation, R43 owns collaboration, R44 owns learning signals. R45
only explains their already-computed outputs and never recomputes them.

## 2. Architecture

```
R42 evaluation   R43 collaboration   R44 learning signals
        \               |               /
         v              v              v
R45.1 Advisory input contract     ai/schemas|knowledge/llm_advisory_input.py
         v
R45.2 Advisory policy / governance ai/schemas|knowledge/llm_advisory_policy.py
         v
R45.4 Advisory request builder     ai/knowledge/llm_advisory_request_builder.py
         v
R45.3 Provider abstraction        ai/schemas|knowledge/llm_provider.py
         v   (MockLLMProvider only in version 1; no network, no SDK)
R45.6 Advisory validation layer    ai/knowledge/llm_advisory_validator.py
         v
R45.5 Advisory response contract   ai/schemas/llm_advisory_result.py
                                   ai/knowledge/llm_advisory_export.py
         v
Human-readable advisory result
```

All components are deterministic, pure/offline, stateless, JSON serializable
and pydantic validated (`extra="forbid"`, forced rule versions,
`research_only=True`, `deterministic=True`).

## 3. Advisory boundary

R45 version 1 contains:

- no network requests, no external API calls, no HTTP client
- no OpenAI / OpenRouter / Ollama / local-model runtime or SDK import
- no subprocess, shell command, browser or filesystem access
- no database or scanner invocation, no nuclei/sqlmap
- no exploit payload, attack instruction or confirmation capability
- no agent, rule, strategy or governance modification
- no uncontrolled persistence

The provider interface is the only extension point. Future kinds are
declared (`OPENAI`, `OPENROUTER`, `OLLAMA`, `LOCAL`) and rejected as
unsupported in version 1 rather than silently ignored.

## 4. Input contract (R45.1)

`LLMAdvisoryInputPlan` (`r45-1`), `extra="forbid"`:

`advisory_id`, `source_layer`, `research_context`, `evaluation_summary`,
`collaboration_summary`, `learning_signals`, `governance_state`,
`safety_state`, `limitations`, `research_only`, `structural_flags`.

- `advisory_id` is a deterministic content token (`adv-<16 hex>`) derived by
  SHA-256 over the canonical bounded content, or a caller-supplied validated
  token. No timestamps, UUIDs, randomness or runtime ids.
- `source_layer` is closed (`R42`, `R43`, `R44`, `MULTI`, `UNKNOWN`),
  derived from which artifacts are present.
- `evaluation_summary`, `collaboration_summary` and `learning_signals` are
  bounded projections of R42/R43/R44 sanitized artifacts; no R42/R43/R44
  logic is recomputed. Non-artifact inputs are flagged
  (`MALFORMED_EVALUATION_SUMMARY`, `MALFORMED_COLLABORATION_SUMMARY`,
  `MALFORMED_LEARNING_SIGNALS`) and treated as absent.
- Non-deterministic keys (`timestamp`, `uuid`, `runtime_id`, …) inside raw
  inputs are detected and flagged (`NON_DETERMINISTIC_INPUT`).
- `research_only` is required and forced true; `research_only=False` raises.

## 5. Policy model (R45.2)

`LLMAdvisoryPolicyPlan` (`r45-2`) with fixed, non-configurable vocabularies:

- Allowed modes: `SUMMARY`, `EXPLANATION`, `RESEARCH_PRIORITY`,
  `CONFLICT_EXPLANATION`, `LEARNING_SUMMARY`.
- Forbidden modes: `EXPLOITATION`, `EXECUTION`, `PAYLOAD_GENERATION`,
  `VULNERABILITY_CONFIRMATION`, `ATTACK_PLANNING`.
- Fixed limits (8 insights, 8 recommendations) and fixed advisory
  limitations (`NO_EXECUTION_PERFORMED`, `NO_NETWORK_REQUESTS`,
  `NO_VULNERABILITY_CONFIRMATION`, `NO_EXPLOIT_GENERATION`, `ADVISORY_ONLY`).

Deterministic mode selection precedence (`select_advisory_mode`):
conflicts present → `CONFLICT_EXPLANATION`; learning signals present →
`LEARNING_SUMMARY`; collaboration present → `RESEARCH_PRIORITY`; evaluation
present → `EXPLANATION`; otherwise `SUMMARY`. Requesting a forbidden mode
raises `ForbiddenAdvisoryModeError` with preserved diagnostics
(`policy_state=FORBIDDEN`, allowed/forbidden sets); unknown modes raise
`AdvisoryPolicyError`.

## 6. Provider abstraction (R45.3)

`AdvisoryProvider` is an abstract, offline interface (`complete(request)`)
with no API keys, no network code, no SDK imports and no HTTP clients.
`MockLLMProvider` returns deterministic, mode-specific, research-only text
(for example `LEARNING_SUMMARY`: "Research confidence should remain limited
until additional evidence requirements are satisfied."). Responses carry
bounded insights and recommendations with source references to R42/R43/R44.
`get_advisory_provider` returns the mock provider; future/unknown kinds raise
`UnsupportedProviderError` with a diagnostic that states
`network_access=false` and `credentials_used=false`.

## 7. Request builder (R45.4)

`build_llm_advisory_request` normalizes the bounded input, applies the
policy, selects or validates the advisory mode, validates the provider kind
and produces a deterministic `LLMProviderRequestPlan` (`r45-3`) containing:
`advisory_id`, `advisory_mode`, `provider_kind`, `source_layer`, a fixed
mode instruction, the six bounded sections, preserved source references,
limitations and forced `research_only`/`deterministic` flags. Instructions
are closed advisory text ("explain/summarize … do not confirm
vulnerabilities") — no exploitation prompt, no credential, no target secret
and no raw runtime data. `serialize_advisory_request` canonicalizes the
request and `advisory_request_fingerprint` returns a stable content token.

## 8. Response contract (R45.5)

`LLMAdvisoryResultPlan` (`r45-5`) fields: `rule_version`,
`advisory_rule_version`, `advisory_id`, `advisory_mode`, `summary`,
`insights`, `recommendations`, `source_refs`, `provenance`, `governance`,
`validation_state`, `validation_diagnostics`, `safety_state`,
`limitations`, `research_only`, `deterministic`.

The export pipeline (`export_llm_advisory`, alias `run_llm_advisory`)
builds the input, request, mock/provider response and validation, and then:

- on `PASS`, includes the validated summary/insights/recommendations;
- on `REJECTED`, excludes all unsafe content (`summary=""`, empty lists) and
  preserves the validator diagnostics; safety state becomes `FAILED`.

Source references, provenance (`source_layers`, `COMPLETE`/`PARTIAL`/
`UNKNOWN`) and governance visibility (`governance_state`,
`reference_present`) are preserved from the deterministic layers.

## 9. Validator (R45.6)

`validate_advisory_response` / `validate_advisory_result` check required
fields, allowed modes, forbidden modes, `research_only`/`deterministic`
enforcement, mode/identity agreement with the request, source-reference
provenance, bounded text and non-deterministic output tokens. Forbidden
output categories are rejected — never sanitized — with preserved
diagnostics:

- vulnerability confirmation (`VULNERABILITY_CONFIRMATION_CLAIM`)
- exploitation success (`EXPLOIT_CONFIRMATION_CLAIM`)
- execution instructions (`EXECUTION_INSTRUCTION`)
- payload content (`PAYLOAD_CONTENT`)
- attack planning / auth bypass / privilege escalation (`ATTACK_PLANNING`)
- exploit/payload generation guidance (`EXPLOITATION_GUIDANCE`)

`require_valid_advisory_response` raises `AdvisoryValidationError` carrying
the full validation record. `advisory_safety_state` derives `FAILED` for
rejections and propagates `DEGRADED`/`FAILED` input safety states.

## 10. R42 integration

R45 consumes R42 evaluation results through the R42 result sanitizer:
overall score/rating, hard-gate state, safety state, diagnostic codes (up to
16) and agent category. R42 is never recomputed and its scoring rules are
not duplicated. Evaluation presence drives `EXPLANATION` mode and, when
combined with other layers, `MULTI` provenance. The mock `EVALUATION_STATE`
insight reports the supplied rating/safety state as a research-output
quality signal only.

## 11. R43 integration

R45 consumes R43 collaboration results through the R43 result sanitizer:
participant count, hypothesis-group count, conflict count and types, merged
evidence state, governance state and provenance state. R43 correlation and
conflict logic is not duplicated. Conflicting collaborations select
`CONFLICT_EXPLANATION`; non-conflicting collaborations select
`RESEARCH_PRIORITY`; conflict insight text is still research-level ("they
remain research-level divergences").

## 12. R44 integration

R45 consumes R44 learning signals through the R44 signal sanitizer
(`signal_type`, `subject`, `source_agent`, `source_classification`,
`recommendation`, `confidence`), deduplicated and bounded to 8. Learning
signals select `LEARNING_SUMMARY`; the mock emits a `LEARNING_STATE` insight
listing signal types and an `APPLY_LEARNING_AS_ADVISORY` recommendation.
Learning signals remain advisory records; nothing is applied or executed.

## 13. Safety model

- Reject, never sanitize: unsafe provider output is excluded entirely and
  the validator diagnostics are preserved in the result.
- The LLM cannot cause execution, scanning, confirmation or persistence:
  there is no such capability in the code path, and the AST safety scan
  verifies no runtime/network/database capability is imported or called.
- No credentials: the provider takes no credential material; tests assert
  that provider/builder sources and serialized requests contain no
  `api_key`/`authorization`/`bearer`/password/private-key tokens.
- Provider output is structurally validated before consumption; malformed
  or unsafe output is rejected rather than consumed.
- `research_only` and `deterministic` are forced true on input, request,
  response and result.

## 14. Tests

| Suite | Tests |
|---|---|
| `tests/test_llm_advisory_input.py` (R45.1) | 19 |
| `tests/test_llm_advisory_policy.py` (R45.2) | 16 |
| `tests/test_llm_provider.py` (R45.3) | 17 |
| `tests/test_llm_request_builder.py` (R45.4) | 15 |
| `tests/test_llm_advisory_validator.py` (R45.6) | 23 |
| `tests/test_llm_advisory_result.py` (R45.5) | 17 |
| **R45 total** | **107 passed** |

Coverage includes valid advisory input, malformed input, extra-field
rejection, `research_only` enforcement, allowed/forbidden modes, forbidden
mode rejection with diagnostics, deterministic request generation and
fingerprints, mock provider behavior per mode, response validation,
forbidden claim detection, exploit-language rejection, execution-instruction
rejection, payload-content rejection, exploitation-guidance rejection,
attack-planning rejection, reject-without-sanitizing, R42/R43/R44
integration, multi-layer provenance, governance visibility, deterministic
serialization, repeated execution equality, rejection-excludes-content and
the R45 AST safety scan.

The AST safety scan in every R45 test file parses all ten R45 modules and
rejects `subprocess`, `socket`, `http`, `urllib`, `requests`, `httpx`,
`aiohttp`, `selenium`, `playwright`, `pyppeteer`, database clients
(`sqlite3`, `sqlalchemy`, `psycopg*`, `pymysql`, `MySQLdb`), `sqlmap`,
`nuclei`, LLM SDKs (`openai`, `ollama`, `litellm`, `anthropic`,
`openrouter`, `curl`, `pycurl`), and the calls `__import__`, `eval`, `exec`,
`compile`, `open` plus forbidden call prefixes.

## 15. Regression results

```
R45 focused suites (6 files)                              107 passed
R38 suites                                                132 passed
R39 suites                                                100 passed
R40 suites                                                122 passed
R41 suites                                                131 passed
R42 suites                                                 91 passed
R43 suites (incl. shared research context)                102 passed
R44 suites                                                 81 passed
All tests referencing r31- … r44- (89 files)  2185 passed, 27 subtests
Backend test (tests/test_asset_cve_matching.py) 79 passed, 13 subtests
AI safety tests (knowledge_store/xss_researcher/
  xss_llm_researcher/openrouter)                           96 passed
Full suite (pytest tests/ -q)         4015 passed, 40 failed,
                                      376 subtests passed
```

The 40 full-suite failures are the pre-existing money-score/economics
corpus-drift failures already documented in the R43/R44 baselines
(`test_hunt_queue`, `test_product_api`, `test_research_economics_*`,
`test_research_opportunities`, `test_research_outcomes`,
`test_research_sessions`, `test_page_render`, `test_daily_research_workflow`,
`test_opportunity_action_queue`, `test_research_ui`, `test_routers_fixes`).
No failure references `llm_advisory`, `llm_provider` or `llm_request`, and
none was modified or "fixed". The external MongoDB used by
`database/db.py` was reachable in this session, so the full suite completed
(4015 passed); the pre-existing failure set is unchanged at 40.

## 16. Limitations

- Version 1 is contract, governance and mock provider only; it does not
  connect to any real model and deliberately cannot.
- The mock provider produces fixed advisory text derived from closed
  vocabularies and counts; it does not perform language understanding.
- R45 explains only what the deterministic layers already represent;
  unrepresented context cannot be explained.
- The advisory validator uses deterministic pattern rules for forbidden
  output categories; pattern-based rejection can be evaded in principle by
  real free-text models, which is one reason no real provider is enabled in
  version 1.
- `source_layer` derivation and mode precedence are fixed design choices.
- The full-suite metric includes the pre-existing corpus-drift failures
  documented in earlier stages.

## 17. Git status

Only new R45 files are added. Pre-existing unrelated worktree items remain
untouched and outside the commit: ` D utils.zip`, `?? watch.zip`,
`?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`. `git diff --check` is
clean. No push is performed. No VM, Docker, systemd, deployment or unrelated
file is modified. `backend/asset_cve_matching.py` is not modified.

## 18. Commit hash

Commit message: `feat(research): add r45 llm advisory layer`. The hash is
reported in the final response after the local commit (the report is part of
the same commit; no amend and no push).

## 19. Explicit no-execution statement

Explicitly: R45 contains no execution capability of any kind. There is no
agent execution, security testing, network request, DNS resolution, database
connection, SQL execution, JavaScript execution, payload generation or
execution, nuclei/sqlmap invocation, scanner, external API call, real LLM
call, rule/agent/strategy/governance modification, self-update, uncontrolled
persistence, worker or scheduler anywhere in R45. The advisory layer reads
structured deterministic artifacts, validates them, and emits bounded
human-readable explanations through a deterministic offline mock provider.

## Agent / Model

- Model: deepseek-v4.1-flash
- Stage: R45
- Role: coding agent
