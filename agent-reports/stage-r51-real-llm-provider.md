# Stage R51 — Real LLM Provider Layer

| | |
|---|---|
| Date | 2026-09-14 |
| Stage | R51 |
| Scope | Real advisory provider layer behind the existing R45 contract |
| Follows | R38 / R39 / R40 / R41 / R42 / R43 / R44 / R45 / R46 / R47 / R48 / R49 / R50 |
| Commit message | `feat(infrastructure): add r51 real llm provider layer` |
| Push status | **Not pushed** (local commit only) |
| Focused tests | 94 passed |
| Full suite | 4775 passed, 40 failed (unchanged baseline), 376 subtests |
| Real API calls during testing | **None** (all transports mocked; guard test asserts the stdlib transport is never invoked) |

## 1. Implementation summary

R51 implements the real remote provider layer behind the R45 LLM
advisory contract: an explicit, fail-closed provider registry with a
generic adapter interface, real OpenRouter and OpenAI adapters over a
bounded stdlib HTTP transport, a strict outbound context allowlist with
data minimization, deterministic bounded prompt construction, strict
provider-response parsing into the R45 response contract, a structured
secret-free error contract, safe telemetry, and an advisory bridge that
runs provider output through the **unmodified R45 validator and result
assembly**.

The LLM remains advisory only. No provider output becomes a security
finding, triggers execution, confirms vulnerabilities, generates
payloads or plans attacks. R52 orchestration is deliberately not
implemented: the bridge handles one advisory request and never dispatches
specialists.

## 2. Architecture

```
R45 advisory contract (unchanged shape and validation)
  ai/schemas/llm_advisory_input.py     bounded advisory input
  ai/schemas/llm_advisory_policy.py    allowed/forbidden advisory modes
  ai/schemas/llm_provider.py           provider request/response contract
  ai/knowledge/llm_advisory_request_builder.py
  ai/knowledge/llm_advisory_validator.py   R45.6 reject-not-sanitize
  ai/knowledge/llm_advisory_export.py      R45 result assembly
  ai/knowledge/llm_provider.py         R45 interface + deterministic mock

R51 real provider layer (new)
  ai/schemas/llm_provider_config.py    secret-free provider configuration
  ai/schemas/llm_provider_error.py     11-category error contract
  ai/schemas/llm_provider_telemetry.py safe telemetry contract
  ai/providers/provider_errors.py      structured provider exceptions
  ai/providers/http_transport.py       bounded stdlib HTTP transport*
  ai/providers/context_allowlist.py    allowlist + sensitive rejection
  ai/providers/prompt_builder.py       deterministic prompt + strict parse
  ai/providers/real_provider.py        real adapter base (retry/timeout)
  ai/providers/openrouter_provider.py  OpenRouter adapter
  ai/providers/openai_provider.py      OpenAI adapter
  ai/providers/provider_registry.py    explicit fail-closed selection
  ai/providers/advisory_bridge.py      R45 pipeline integration
```

\* the only R51 module that imports network primitives.

Flow per bridge invocation:

```
R45 advisory input -> R45 request (explicit provider kind)
  -> R51 explicit selection (fail closed; no fallback)
  -> context allowlist (reject sensitive/structural violations)
  -> deterministic bounded prompt
  -> bounded HTTP transport (timeout, bounded deterministic retries)
  -> strict JSON parse into the R45 response contract
  -> export_llm_advisory (R45 validator + assembly; one provider call)
  -> structured R51 envelope (bounded error/telemetry; no prompts/bodies)
```

## 3. Provider interface

- `AdvisoryProvider` (R45) remains the interface. Real adapters subclass
  it through `RealAdvisoryProvider` and expose `complete(request)`; they
  additionally expose `complete_with_status(request)` returning the
  bounded outcome `{response, error, telemetry}` for structured error
  handling.
- All providers (mock, OpenRouter, OpenAI, and any future adapter) are
  selected through `ai.providers.provider_registry.select_provider`. The
  rest of Watch never sees provider-specific response formats.
- `describe()` exposes only bounded boundary metadata (kind,
  model-configured, base URL, timeout/retry/token bounds, network and
  credential flags, limitations). The credential value is never part of
  any structure.
- Selection is explicit and closed: `MOCK`, `OPENROUTER`, `OPENAI`.
  `OLLAMA`/`LOCAL` remain declared future kinds; unknown, missing or
  future kinds raise a structured `CONFIGURATION_ERROR`
  (`CONFIG_UNSUPPORTED_KIND`). There is no default provider in the
  registry and no silent fallback to mock or to another provider.

## 4. OpenRouter implementation

`ai/providers/openrouter_provider.py`:

- endpoint `https://openrouter.ai/api/v1/chat/completions`
  (base URL configurable via argument or `OPENROUTER_BASE_URL`);
- model from the `OPENROUTER_MODEL` environment variable or an explicit
  argument; **no model is hardcoded** and no model is the only supported
  one;
- credential from `OPENROUTER_API_KEY` or an explicit in-memory
  constructor argument; used only in the transport authorization header;
- OpenAI-compatible bounded body
  (`model`, `messages`, `max_tokens`, `temperature=0`);
- response content extracted from `choices[0].message.content` with
  strict type/empty checks.

## 5. OpenAI implementation

`ai/providers/openai_provider.py`:

- endpoint `https://api.openai.com/v1/chat/completions`
  (`OPENAI_BASE_URL` override);
- model from `OPENAI_MODEL` or explicit argument; no hardcoded model;
- credential from `OPENAI_API_KEY` or explicit argument;
- the same provider interface, request/response contract, error mapping,
  retry policy, parsing and safety pipeline as OpenRouter;
- OpenAI-specific credentials are never used for OpenRouter and vice
  versa (tests assert no cross-provider credential use and no fallback).
- No OpenAI SDK is imported; the adapter uses the same isolated bounded
  transport, so no provider-specific objects can leak.

## 6. Configuration

`ai/schemas/llm_provider_config.py` (`r51-1`) defines the secret-free
configuration contract:

- `provider_kind`, `model`, `base_url`, `api_key_env` (environment
  variable **name** only), `timeout_seconds`, `max_retries`,
  `retry_backoff_seconds`, `max_tokens`, `max_response_bytes`,
  `credentials_configured` (boolean), `research_only`.
- Bounds: timeout 1–120 s (default 30), retries 0–3 (default 2), backoff
  0–10 s (default 0), max tokens 1–8192 (default 2048), response size
  1 KiB–256 KiB (default 64 KiB).
- `base_url` must be HTTPS; model identifiers and environment-variable
  names are validated; credential-like model values are rejected.
- Fail closed: invalid configuration raises a structured
  `CONFIGURATION_ERROR`/`CONFIG_INVALID_PARAMETER`; missing credentials
  or model raise `CONFIG_MISSING_CREDENTIAL` / `CONFIG_MISSING_MODEL`
  before any transport call, and no response is fabricated.

## 7. Security boundary

- The LLM stays advisory: R45's forbidden modes (`EXPLOITATION`,
  `EXECUTION`, `PAYLOAD_GENERATION`, `VULNERABILITY_CONFIRMATION`,
  `ATTACK_PLANNING`) are rejected by the unmodified R45 policy before any
  provider call.
- Provider output is fed through the unmodified R45 validator through
  `export_llm_advisory`. Unsafe content is **rejected, never sanitized**:
  the advisory result carries empty content, `validation_state=REJECTED`,
  `safety_state=FAILED` and preserved diagnostics; the envelope reports
  `provider_state=REJECTED` with `SAFETY_VALIDATION_ERROR` /
  `UNSAFE_OUTPUT_REJECTED`.
- Provider errors are infrastructure-only: the envelope contains a
  bounded error plan, no findings, no hypotheses and no advisory content.
- Provider output cannot trigger execution: the provider layer contains
  no `eval`/`exec`/`compile`/`__import__`/`open`/`subprocess`/`os.system`
  calls (AST tests), and the bridge returns bounded data structures only.
- Exactly one provider exchange happens per bridge invocation; the R45
  assembly pass replays the already-obtained response through a
  single-response adapter with advisory identity/mode verification.
- Network access is isolated to `ai/providers/http_transport.py`; tests
  assert no other R51 module imports network primitives and that
  R38–R50 specialist modules neither import network modules nor the R51
  provider layer.

## 8. Context allowlist

`ai/providers/context_allowlist.py` (`r51-context-allowlist`):

- Explicit allowlists: request keys, section names and section keys,
  learning-signal item keys and source-reference keys. Projection is
  built by picking approved keys — arbitrary objects/dicts are never
  serialized.
- Reject, never rewrite: unknown request keys, unknown section names,
  unknown section keys, malformed types, invalid advisory identity/mode/
  source layer and oversized contexts are rejected with
  `CONFIGURATION_ERROR`/`CONFIG_INVALID_PARAMETER`; sensitive content is
  rejected with `SAFETY_VALIDATION_ERROR`/`UNSAFE_CONTEXT_REJECTED`
  before any provider call.
- The projection returns `crossing_fields`, the explicit documentation of
  what crosses the provider boundary (advisory id/mode/source layer/
  instruction, each approved section, source references, limitations).

## 9. Data minimization

`detect_sensitive_content` scans only the allowlisted projection for
reason codes (no matched values are returned): credential-like `sk-`
strings, `Authorization:`/bearer tokens, cookies, session/access/refresh/
generic token assignments, password/secret assignments, private-key
blocks, URLs, payload markers and control characters. Approved research
metadata crossing the boundary is limited to: advisory identity and mode,
source layer, the bounded request instruction, the bounded research
context, evaluation summary, collaboration summary, learning signals,
governance state, safety state, source references and limitations.
Secrets, credentials, authentication material, provider credentials, raw
tokens, payloads and arbitrary URLs never cross.

## 10. Retry / timeout behavior

- Explicit timeout per attempt (default 30 s, bounded 1–120 s).
- Bounded retries: `max_retries` 0–3 (default 2 → at most 3 attempts);
  deterministic retry count; no infinite retries.
- Retry only transient failures: HTTP 429 (rate limit), HTTP 408,
  transport timeouts/network failures and HTTP 500/502/503/504. Client
  errors, authentication/authorization failures, malformed/empty
  responses and safety rejections are never retried.
- Bounded response size: the transport reads at most
  `max_response_bytes + 1` and fails with `INVALID_RESPONSE` if exceeded.
- Redirects are never followed (the default transport refuses them and
  surfaces the status for deterministic mapping).
- Telemetry makes external variability explicit:
  `content_deterministic=False` for real providers and bounded
  `attempt_count`/`retry_count`.

## 11. Error contract

`ai/schemas/llm_provider_error.py` (`r51-2`) defines 11 closed categories:
`CONFIGURATION_ERROR`, `AUTHENTICATION_ERROR`, `AUTHORIZATION_ERROR`,
`RATE_LIMIT_ERROR`, `TIMEOUT_ERROR`, `NETWORK_ERROR`, `PROVIDER_ERROR`,
`INVALID_RESPONSE`, `EMPTY_RESPONSE`, `SAFETY_VALIDATION_ERROR`,
`UNKNOWN_ERROR`, plus 19 closed error codes (missing credential/model,
invalid base URL/parameter, unsupported kind, unsafe context, invalid
credentials, forbidden, rate limited, timeout, connection failed,
transport error, HTTP error, transient error, invalid/empty provider
response, unsafe output, unknown).

Every error plan is bounded (provider kind, model, category, code,
optional status, retryable flag, attempts, safe message) and
credential-safe: `safe_error_message` blanks messages containing
credential/authorization-like material. HTTP mapping is deterministic
(401→authentication, 403→authorization, 408→timeout, 429→rate limit,
5xx→transient/non-transient provider error, other 4xx/3xx→provider
error).

## 12. Observability

`ai/schemas/llm_provider_telemetry.py` (`r51-3`) defines bounded safe
telemetry: provider kind, model, advisory id/mode, attempt/retry counts,
success flag, error category, validation state (`NOT_RUN`/`PASS`/
`REJECTED`), response character count, external-provider/network/
credentials-used flags, `content_deterministic`, research-only and
deterministic flags.

Telemetry never contains credentials, authorization headers, cookies,
session tokens, prompts, raw provider bodies or raw responses. No logging
infrastructure was added or used: the provider layer contains no
`logging` import and no `print` calls (AST/static test), and telemetry is
returned as a structure rather than persisted.

## 13. R45 validation preservation

- R45 validation rules, forbidden-claim detection, mode policy,
  provenance checks and reject-not-sanitize semantics are unchanged. The
  only R45 change is an **additive** provider-kind vocabulary extension:
  `SUPPORTED_PROVIDER_KINDS = (MOCK, OPENROUTER, OPENAI)` and
  `FUTURE_PROVIDER_KINDS = (OLLAMA, LOCAL)` plus four additive
  real-provider limitation labels allowed in the response contract. The
  mock provider's request/response behavior is byte-identical (it still
  uses the original limitation tuple).
- R45's pure factory `get_advisory_provider` remains mock-only and now
  raises a structured `UnsupportedProviderError` naming the R51
  implementation layer for real kinds, so nothing silently constructs a
  network provider from the pure layer.
- Five existing R45 test assertions were updated to the extended closed
  vocabulary (no test was deleted, skipped or weakened; no safety
  assertion changed):
  - `tests/test_llm_provider.py`: supported/future kind sets; unsupported
    schema kind now uses `OLLAMA`.
  - `tests/test_llm_request_builder.py`: unsupported-kind loop no longer
    lists supported kinds; schema rejection uses `OLLAMA`.
  - `tests/test_llm_advisory_validator.py`: unsupported-kind violation
    now uses `OLLAMA`.

## 14. Tests

Focused R51 suites (94 tests):

```
tests/test_llm_provider_interface.py      23 passed
tests/test_llm_openrouter_provider.py     24 passed
tests/test_llm_openai_provider.py         12 passed
tests/test_llm_provider_safety.py         17 passed
tests/test_llm_provider_integration.py    18 passed
R51 total                                 94 passed
```

Coverage includes: provider interface and boundary description; explicit
selection and fail-closed behavior; OpenRouter/OpenAI configuration and
environment resolution; missing key and missing model; invalid
configuration; successful response mapping; malformed/empty/non-string
provider responses; authentication/authorization/rate-limit/timeout/
network mapping; transient retry and bounded retry counts; safety
validation of unsafe output; forbidden advisory modes; secret
redaction/rejection; context allowlisting; data minimization;
deterministic request construction; deterministic error mapping; mock
provider compatibility; R45 compatibility; R42/R43/R44 inputs;
specialist interoperability (R46–R50); provider isolation and AST
safety.

All network interactions in tests use injected fake transports. A guard
test replaces `UrllibHttpTransport.send` with a failing stub and runs the
bridge to prove no real transport is invoked.

Regression suites (all passed, no existing failure introduced):

```
R45 suites (6 files)                              107 passed
R38 core suites (7 files)                         132 passed
R39 suites (XSS, 5 files)                         100 passed
R40 suites (SSRF, 5 files)                        122 passed
R41 suites (SQLi, 5 files)                        131 passed
R42 suites (evaluation, 5 files)                   91 passed
R43 suites (collaboration, 5 files)                88 passed
R44 suites (feedback/learning, 4 files)            68 passed
R46 suites (IDOR/BOLA, 5 files)                    97 passed
R47 suites (JWT/authentication, 5 files)          136 passed
R48 suites (OAuth, 5 files)                       150 passed
R49 suites (API security, 5 files)                156 passed
R50 suites (CVE research, 5 files)                125 passed
Backend (tests/test_asset_cve_matching.py)         79 passed, 13 subtests
AI safety (knowledge_store/xss_researcher/
  xss_llm_researcher/openrouter)                   96 passed
```

## 15. Full-suite result and baseline comparison

```
python -m pytest tests/ -q -p no:cacheprovider
4775 passed, 40 failed, 1 warning, 376 subtests passed in 54.48s
```

Baseline (R50): `4681 passed, 40 failed, 376 subtests`.

- passed growth: `4775 - 4681 = 94` — exactly the 94 new R51 tests;
- failed count unchanged at 40; subtests unchanged at 376; failure
  identities unchanged (the same pre-existing money-score/economics
  corpus-drift failures);
- no failure references the provider layer.

## 16. Changed files

Modified (5):

```
ai/schemas/llm_provider.py            additive provider-kind/limitation extension
ai/knowledge/llm_provider.py          real-kind diagnostic + docstring
tests/test_llm_provider.py            2 vocabulary-expectation updates
tests/test_llm_request_builder.py     2 vocabulary-expectation updates
tests/test_llm_advisory_validator.py  1 vocabulary-expectation update
```

Added (19):

```
ai/schemas/llm_provider_config.py
ai/schemas/llm_provider_error.py
ai/schemas/llm_provider_telemetry.py
ai/providers/__init__.py
ai/providers/provider_errors.py
ai/providers/http_transport.py
ai/providers/context_allowlist.py
ai/providers/prompt_builder.py
ai/providers/real_provider.py
ai/providers/openrouter_provider.py
ai/providers/openai_provider.py
ai/providers/provider_registry.py
ai/providers/advisory_bridge.py
tests/test_llm_provider_interface.py
tests/test_llm_openrouter_provider.py
tests/test_llm_openai_provider.py
tests/test_llm_provider_safety.py
tests/test_llm_provider_integration.py
agent-reports/stage-r51-real-llm-provider.md
```

No Docker/systemd/VPS/deployment configuration was modified. No
specialist (R39–R50) behavior was modified. No canonical R38 category was
modified.

## 17. Limitations

- R51 is the provider layer only; there is no orchestrator and no
  automatic specialist dispatch (R52 owns orchestration).
- Real provider content is inherently external and variable; the R45
  response contract's deterministic flag describes the bounded contract
  shape, while R51 telemetry records `content_deterministic=False` and the
  R45 validator still rejects unsafe or non-deterministic-key content.
- Providers are exercised only through mocked transports in this stage;
  no live endpoint was contacted, so live provider behavior (model
  availability, provider-side JSON strictness) is not yet observed.
- Ollama/local models remain unsupported; the adapter interface is
  generic enough to add them without touching the R45 contract.
- The R45 provider-kind vocabulary extension is additive but does change
  the closed supported set; five R45 test expectations were updated
  accordingly (no safety assertion changed).
- The full-suite metric includes the same 40 pre-existing corpus-drift
  failures as the R45–R50 baselines.

## 18. Git

Commit message: `feat(infrastructure): add r51 real llm provider layer`.
The hash is reported in the final response after the local commit (no
amend and no push). Unrelated worktree items (` D utils.zip`,
`?? watch.zip`, `?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`) remain untouched and
outside the commit.

## Agent / Model

Implemented by opencode (model: deepseek-v4.1-flash) on 2026-09-14.
