# Stage R10 — LLM Provider Abstraction & Research Pipeline Hardening

## Outcome

DONE — small, scoped stage. The existing LLM provider abstraction was
audited end-to-end and found fundamentally sound: provider-specific
behavior is already isolated behind `LLMProvider`, configuration is
already environment-driven, and the R9.3 content-hash trust boundary is
already enforced in code and pinned by tests.

Two concrete abstraction defects were found and fixed (both are
boundary-integrity defects, not refactoring):

1. **Hidden SDK-level retries.** `OpenRouterProvider` never set
   `max_retries`, so the OpenAI SDK silently retried HTTP
   408/409/429/5xx up to 2 extra times per invocation. One
   `generate()` call could therefore make up to 3 provider HTTP
   calls — violating the R10 contract "one invocation = one provider
   call" and burning free-tier rate-limit budget on 429 (exactly the
   R9.5 Gemma failure mode). Fixed with `max_retries=0` at client
   construction. Proof: a new regression test counted **3** HTTP calls
   on a 429 before the fix, **1** after.

2. **Malformed-response normalization gaps.** `_extract_content`
   checked truthiness only. A non-list `choices` (e.g. dict) leaked a
   raw `KeyError` past the provider boundary, and a non-string
   `message.content` (e.g. OpenRouter content-part arrays) was
   returned as-is, so `LLMResult.content` violated its `str` contract
   and the failure surfaced downstream as an `AttributeError`, which
   `ai/researcher/provider_errors.py` misclassifies as a
   non-transient *programming error* instead of a clean provider
   failure. Both shapes now normalize into `OpenRouterProviderError`.

Provider failures remain normalized into clean application errors;
no retries, no fallback routing, no new providers, no schema changes;
`.env` untouched; no secrets in code, tests, or this report; no
commit/push.

## Current Architecture

The provider boundary is three layers, each with a single job:

```
ai/llm/base.py                     LLMProvider (ABC)
  - generate(prompt) -> str        abstract: the only thing a provider must implement
  - complete(prompt) -> LLMResult  default wrapper: generate -> LLMResult(content)
  - LLMResult(content, request_id, model)  frozen dataclass

ai/llm/openrouter.py               OpenRouterProvider(LLMProvider)
  - ONLY place that talks to OpenRouter (openai SDK chat.completions)
  - env-driven config: OPENROUTER_API_KEY, OPENROUTER_MODEL,
    OPENROUTER_MAX_TOKENS (+ optional explicit ctor overrides)
  - http transport injectable via http_client (test seam)
  - normalizes APIStatusError / APIConnectionError / any other
    exception into OpenRouterProviderError (RuntimeError subclass)
  - never logs/echoes the API key; no application-level retries

ai/researcher/provider_errors.py   fail-soft classification
  - classifies provider failures into transient (402/429/5xx,
    network/timeout) vs programming errors; produces public_message
    with no secrets; feeds outage telemetry buckets

ai/researcher/xss_llm_assistant.py XSSLLMResearchAssistant
  - consumes ONLY LLMProvider.complete() (duck-typed in tests)
  - retrieval before LLM: loads KB evidence from KnowledgeStore first
  - builds bounded/minimized prompt; validates model output structurally
  - enforces all authority invariants; rejects violations closed

ai/research_cli.py                 CLI entry (run_xss_llm_research)
  - exit 1 + clean ERROR line on provider failure; no partial writes
```

Swapping providers/models happens through configuration
(`OPENROUTER_MODEL`) or dependency injection (any `LLMProvider`
implementing `generate`, or duck-typed `complete`) — the XSS research
layer never sees provider specifics.

## Provider Boundary Audit

Verified invariants (all confirmed by reading source + tests):

- **Isolation:** only `ai/llm/openrouter.py` imports the openai SDK
  and touches the network. `XSSLLMResearchAssistant` depends on
  `ai.llm.base.LLMProvider` only.
- **Interface contract:** `base.LLMProvider.complete()` default wraps
  abstract `generate()`; providers with real metadata override
  `complete()`. Both halves of the contract are now test-pinned
  (existing `StubLLM`/`MetadataStubLLM` for `complete`; new
  `GenerateOnlyLLM` test proves a generate-only provider works
  end-to-end through the assistant).
- **Config:** all credentials/model/budget from environment with
  explicit ctor override precedence; missing key/model fails loudly at
  construction (`OpenRouterProviderError`); invalid
  `OPENROUTER_MAX_TOKENS` fails loudly instead of being clamped.
- **No secret leakage:** error messages contain only
  `type(exc).__name__` and numeric status codes — never provider
  response bodies, headers, or keys (test-pinned).
- **Defects found** (fixed, see Changes): hidden SDK retries
  (`max_retries` unset) and two malformed-response shapes escaping
  normalization (non-list `choices`, non-string `content`).
- **Known limitation (documented, not changed):** `DEFAULT_MODEL` is
  still `minimax/minimax-m3:free` — a slug known dead since R9. Env
  override (`OPENROUTER_MODEL`) still works, so this does not block
  provider/model swapping; changing the default would either
  hard-code another model or require the env var (a behavior change
  beyond this stage's "prefer no change" mandate). See
  Recommendations.
- **Known limitation (documented, not changed):**
  `response_format={"type": "json_object"}` is hard-coded in the
  request body. It lives inside the provider (correct place), but a
  model that rejects JSON mode cannot be swapped in without a code
  change. See Recommendations.

## Changes

Exactly three code edits, all in the provider boundary + tests:

1. `ai/llm/openrouter.py`
   - Added `"max_retries": 0` to the OpenAI client kwargs (with
     explanatory comment) and updated the class docstring: ONE
     invocation = exactly ONE provider HTTP call.
   - `_extract_content` hardening:
     - `choices` must be a non-empty list/tuple, else clean
       `OpenRouterProviderError("OpenRouter response has no choices")`
       (previously a dict `choices` leaked `KeyError`).
     - `message.content` must be a `str`, else clean
       `OpenRouterProviderError("OpenRouter response content is not
       a string: <TypeName>")` (previously returned non-str content,
       violating `LLMResult.content: str`).

2. `ai/test_openrouter.py` — new
   `OpenRouterProviderFailureNormalizationTests` class (7 tests, see
   Tests).

3. `ai/test_xss_llm_assistant.py` — new `GenerateOnlyLLM`
   (generate-only `LLMProvider`) + provider-swap regression test
   through the full research-assistant path.

No other application code, schemas, prompts, validators, CLI,
backend, web, execution, database, `.env`, or `ns/`/`crawl/` paths
were touched.

## Failure Normalization

Post-fix, the complete required failure-mode matrix is handled and
test-pinned:

| Failure mode | Real-world case | Behavior after fix | Test |
| --- | --- | --- | --- |
| HTTP 4xx (404) | R9 Minimax discontinued slug | `OpenRouterProviderError`, message keeps `HTTP 404` for downstream classification | `test_404_discontinued_slug_normalized_with_status`, `test_http_4xx_raises_provider_error` |
| HTTP 4xx (401) | auth failure | `OpenRouterProviderError` (no key in message/cause) | `test_http_4xx_raises_provider_error`, `test_api_key_not_in_provider_errors` |
| HTTP 429 | R9.5 Gemma rate limit | `OpenRouterProviderError` with `HTTP 429`; exactly ONE HTTP call (no SDK retry) | `test_429_rate_limit_normalized_with_status`, `test_no_automatic_retry_on_429` |
| HTTP 5xx | provider outage | `OpenRouterProviderError`; exactly ONE HTTP call | `test_http_5xx_raises_provider_error`, `test_no_automatic_retry_on_5xx` |
| Empty choices | R9.4 Nemotron HTTP 200, empty choices | `OpenRouterProviderError("...no choices")` | `test_missing_choices_raises`, plus non-list-choices shape |
| Empty/missing content | provider returns blank | `OpenRouterProviderError("...no message content")` | `test_empty_message_content_raises` |
| Malformed response (non-list `choices`) | broken/garbled provider payload | clean `OpenRouterProviderError` (was raw `KeyError` leak) | `test_non_list_choices_rejected` |
| Malformed response (non-string `content`) | content-part arrays | clean `OpenRouterProviderError` naming the type (was silent pass-through → downstream `AttributeError` misclassified as programming error) | `test_non_string_message_content_rejected` |
| Auth/config failure at construction | missing env | `OpenRouterProviderError` before any network I/O | `test_missing_api_key_raises` |
| Timeout/network | transport failure | `OpenRouterProviderError` ("connection error: APITimeoutError") | `test_timeout_normalized_to_connection_error`, `test_api_key_not_in_connection_error` |

Downstream, `ai/researcher/provider_errors.py` keeps classifying
these into transient vs non-transient with sanitized public messages;
that classifier was NOT modified (it already consumed the
provider-normalized shape, including the `HTTP <code>` text this
stage now test-pins).

## Content Hash Trust Boundary

Preserved exactly (R9.3 semantics, verified in source + tests):

- `XSSLLMResearchAssistant.research()` computes the candidate
  `content_hash` via `_candidate_content_hash()` (SHA-256 over the
  deterministic candidate payload, excluding any pre-existing
  `content_hash` field) — verifier-computed, never model-supplied.
- `build_research_assistant_result()` pops any model-supplied
  `content_hash` from `llm_data` before validation (discarded, never
  compared, never trusted) and stamps the deterministic value from
  trusted local state after validation.
- The prompt never asks for the hash and the candidate projection
  never includes it (`test_prompt_hides_hash_and_does_not_ask_for_it`).
- Existing regression tests kept passing:
  `test_model_supplied_wrong_content_hash_ignored`,
  `test_model_supplied_correct_content_hash_also_ignored`,
  `test_r9_failure_mode_impossible`.
- No model output was persisted in this stage (no provider calls
  made); nothing in this stage alters what would be persisted.

## Security Boundary

- XSS LLM authority rules unchanged and re-verified by the existing
  suite: deterministic candidate remains authoritative (status and
  confidence mirrored, never upgraded/downgraded), LLM output is
  research commentary only, `references_used`/EVIDENCE `knowledge_ids`
  constrained to supplied evidence, INFERENCE/UNKNOWN items must not
  carry knowledge_ids, arbitrary URLs rejected, no
  execution/verdict/scan capability anywhere in the LLM path.
- The LLM never retrieves from KnowledgeStore itself; retrieval
  happens before LLM reasoning (`_load_evidence` → fail-closed if no
  evidence, no LLM call).
- EVIDENCE / INFERENCE / UNKNOWN semantics unchanged.
- No API keys, Mongo URIs, authorization headers, response bodies, or
  user identifiers appear in tests or this report. The provider never
  logs the key; error strings carry exception type names and numeric
  status codes only.
- `.env` untouched; no credentials added anywhere.
- No automatic retries or fallback-model routing added — the opposite:
  SDK-level hidden retries were removed.

## Tests

All tests are offline (httpx.MockTransport / stubs); zero real
network/provider calls.

New (9 tests):

- `ai/test_openrouter.py::OpenRouterProviderFailureNormalizationTests`
  1. `test_404_discontinued_slug_normalized_with_status` — R9 mode; message keeps `HTTP 404`; no key leak
  2. `test_429_rate_limit_normalized_with_status` — R9.5 mode; message keeps `HTTP 429`; no key leak
  3. `test_timeout_normalized_to_connection_error` — `APITimeoutError` → clean connection-error shape; no key leak
  4. `test_no_automatic_retry_on_429` — exactly 1 HTTP call on 429 (failed with 3 before the fix)
  5. `test_no_automatic_retry_on_5xx` — exactly 1 HTTP call on 503
  6. `test_non_string_message_content_rejected` — list content → clean provider error
  7. `test_non_list_choices_rejected` — dict choices → clean "no choices" error (no `KeyError`)
- `ai/test_xss_llm_assistant.py`
  8. `test_generate_only_provider_swap_works` — a provider implementing ONLY abstract `generate()` runs the full research-assistant path via the base `complete()` default; `model`/`raw_response_id` stay `None` (never fabricated)

Audit-only conclusion for the remaining required matrix: the
pre-existing suite already covered 4xx/5xx raising, empty
choices/content, missing API key, and key-leak checks
(`OpenRouterProviderRequestTests`, `OpenRouterProviderConfigTests`);
`test_xss_llm_researcher.py` already covered `complete()`-based and
metadata-bearing stubs. No duplicate tests were added for those.

## Regression

Focused + regression suites, all green after the changes:

- `ai.test_openrouter` — 33 tests OK
- `ai.test_xss_llm_assistant`, `ai.test_xss_llm_researcher`,
  `ai.test_provider_fail_soft`, `ai.test_provider_retry`,
  `ai.test_xss_researcher`, `ai.test_knowledge_store` — 137 tests OK
- Full set above plus `ai.test_provider_telemetry`,
  `ai.test_provider_cache` — 214 tests OK
- Baseline before changes: same suites already OK (137/214 minus the
  9 new tests), so no regression was introduced.
- The mandated XSS/knowledge-layer regression set
  (`ai.test_knowledge_store`, `ai.test_xss_researcher`,
  `ai.test_xss_llm_researcher`, `ai.test_openrouter`) all pass.
  (`ai.test_xss_llm_assistant` additionally passes.)

## Diff/Stat

```
 ai/llm/openrouter.py    |  24 +++++++-
 ai/test_openrouter.py   | 173 ++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 194 insertions(+), 3 deletions(-)
```

- `ai/llm/openrouter.py`: +22/−2 (docstring, `max_retries=0` block,
  two isinstance guards in `_extract_content`)
- `ai/test_openrouter.py`: +172/−1 (new failure-normalization test
  class; 33 test functions total in file)
- `ai/test_xss_llm_assistant.py`: untracked pre-existing file from
  R7 (not in `git diff`); this stage added ~45 lines (import,
  `GenerateOnlyLLM`, swap test; 28 test functions total in file)
- `git diff --check`: clean (no whitespace errors)

## Unchanged Areas

- `ai/llm/base.py` — interface contract already correct.
- `ai/researcher/xss_llm_assistant.py`,
  `ai/researcher/xss_llm_researcher.py` — research semantics,
  authority checks, prompts, persistence untouched.
- `ai/researcher/provider_errors.py` — classification untouched.
- `ai/research_cli.py`, `ai/schemas/` — untouched.
- `ai/researcher/xss_agent.py` and the deterministic XSS candidate
  authority — untouched.
- Production execution, 5B–5J, live validation, Nuclei, Mongo
  schemas, dashboard/backend/web — untouched.
- `ns/`, `crawl/`, `database/` — untouched.
- `.env` — untouched. No new dependencies, no new providers, no
  retry/queue/orchestration machinery. No commit/push.

## Recommendations

1. **Default model slug (future stage):** `DEFAULT_MODEL` still points
   at the dead `minimax/minimax-m3:free` slug. Consider either
   requiring `OPENROUTER_MODEL` explicitly (fail fast at construction
   with a clear message) or a `check`-command warning when the
   configured/default slug is known-dead. Both are behavior changes,
   so they were left out of this stage deliberately.
2. **JSON-mode knob (future stage):** `response_format={"type":
   "json_object"}` is hard-coded inside the provider. If a future
   model rejects JSON mode, consider an env knob (e.g.
   `OPENROUTER_JSON_MODE=false`) — a provider-local request-shape
   option, not an orchestration feature.
3. **Orchestration layer (explicitly out of scope here):** when it
   exists, it should own retries/fallback-model routing and consume
   `provider_errors.classify_provider_failure` so there remains
   exactly one classification system.
4. No further free-model probing is needed for the abstraction itself:
   every observed R9-family failure shape now has a pinned, offline
   regression test.

## Agent / Model

- Model: GLM (Z.ai), via the Cline coding agent
- Stage: R10
- Role: LLM Provider Abstraction / Hardening


