# Stage R24.11 — LLM Reliability & Safe Failover

**GO.** The R24 LLM path now deterministically classifies failures, keeps all
safety invariants, and fails soft to `RESEARCH_PARTIAL` with deterministic
evidence preserved. Defaults are unchanged (no fallback, no retries, discovery
still disabled).

No project source was changed outside the additive LLM-reliability layer. No R23
behavior changed, `database/db.py` untouched, no commit/push/reset.

## 1. Exact files changed

| File | Change |
|---|---|
| `ai/research_agent/llm_reliability.py` | **New.** Failure vocabulary, classification, secret-free sanitising, one-attempt `call_llm`, fallback/retry eligibility. |
| `ai/research_agent/llm_loop.py` | Budget-bounded primary→fallback→retry sequence; `llm_failure_kind` on round/result; `consume_llm(n)`. |
| `ai/research_agent/discovery_runner.py` | Passes `llm_fallback` / `llm_max_retries` through to the loop. |
| `ai/research_agent/scheduler.py` | Additive config: `llm_model`, `llm_fallback_model`, `llm_max_retries`, `llm_response_format`. |
| `ai/research_cli.py` | `_build_discovery_llm_provider`; discovery agent wires primary/fallback/retries. R23 `_build_llm_provider` unchanged. |
| `ai/llm/openrouter.py` | Additive `response_format_json: bool = True` (default preserves existing behavior). |
| `tests/test_research_agent_r24_11.py` | **New.** 19 tests. |

## 2. Failure classification

`classify_llm_error` maps a failure (message shape only) to a closed vocabulary:

| Kind | Trigger examples |
|---|---|
| `SUCCESS` | non-empty string content |
| `EMPTY_CHOICES` | “no choices”, “no message content”, empty/blank content |
| `MALFORMED_RESPONSE` | “content is not a string”, invalid/undecodable JSON |
| `TIMEOUT` | `APITimeoutError`, “timeout”/“timed out” |
| `HTTP_ERROR` | other HTTP 4xx/5xx provider errors |
| `RATE_LIMIT` | HTTP 429, “rate limit”, “too many requests” |
| `AUTH_CONFIG_ERROR` | 401/403, “is not configured”, “no api key”, “unauthorized” |
| `UNKNOWN_ERROR` | anything else |

`sanitize_llm_error` is single-line, ≤200 chars, and redacts `sk-…`,
`Bearer …`, and `Authorization`/`api-key` values. No API keys, Authorization
headers or secrets are ever surfaced (unit-tested).

## 3. Fallback behavior

- Fallback is **disabled unless explicitly configured**
  (`WATCH_RESEARCH_LLM_FALLBACK_MODEL`, default empty).
- `is_fallback_eligible` excludes `AUTH_CONFIG_ERROR`; fallback runs only for
  `EMPTY_CHOICES`, `MALFORMED_RESPONSE`, `TIMEOUT`, `HTTP_ERROR`, `RATE_LIMIT`,
  `UNKNOWN_ERROR`.
- No automatic paid-model escalation: the fallback model is operator-configured;
  the default introduces no additional cost.
- Every attempt (primary, fallback, retry) consumes the **same** llm-call
  budget: `max_llm_calls=1` means exactly **one** attempt total (tested).

## 4. Retry behavior

- Default `WATCH_RESEARCH_LLM_MAX_RETRIES=0` (no retries).
- Retries, when configured, consume the same per-plan/per-run budget and are
  bounded by the existing deadline; `is_retry_eligible` excludes auth/config.
- Never retries authentication/configuration errors (tested), and rate-limit
  retries cannot exceed budget/deadline because the attempt loop stops when
  `budget_remaining` is reached.

## 5. Call-budget enforcement

`_attempt_llm_sequence` walks `primary → fallback` (each with up to
`max_retries` retries) while `attempts < budget_remaining`, where
`budget_remaining = min(per_plan_remaining, tracker.llm_calls_remaining())`.
`BudgetTracker.consume_llm(n)` adds the exact number of attempts. Outcomes:

- `max_llm_calls=1`, primary fails → 1 call, no fallback/retry;
- `max_llm_calls=2`, fallback configured → primary + fallback;
- `max_llm_calls=2`, `max_retries=1` → primary + retry.

## 6. Response-format handling

`OpenRouterProvider` gained an additive `response_format_json` flag (default
`True`, preserving R23/R24 behavior exactly; the existing `ai.test_openrouter`
assertion still passes). Operators can set
`WATCH_RESEARCH_LLM_RESPONSE_FORMAT=text` for models that reject
`{"type":"json_object"}`; the response is still parsed by `parse_llm_analysis`
and passed through the full attribution/sanitisation pipeline. If structured
output cannot be obtained, the LLM is marked failed/partial and no claims are
invented. If the provider rejects `response_format`, it surfaces as
`HTTP_ERROR` → fail-soft (reflected in `llm_failure_kind`).

## 7. Tests

New `tests/test_research_agent_r24_11.py` (19): classification table;
fallback/retry eligibility; secret redaction; `call_llm` outcomes; fallback
disabled/configured; `max_llm_calls=1` prevents a second call; retry default 0
and budget-bounded retry success; auth error never retried/failed over;
`response_format` incompatibility fail-soft; deterministic evidence survives
**every** failure kind; attribution + forbidden-verdict filtering unchanged;
target-token exclusion unchanged; no secrets in errors; `discovery=false`
unchanged; OpenRouter `response_format` toggle; scheduler LLM config defaults
and env overrides.

Regression:

| Suite | Tests |
|---|---|
| `tests.test_research_agent` | 92 |
| `tests.test_research_agent_r24_1` | 43 |
| `tests.test_research_agent_r24_2` | 50 |
| `tests.test_research_agent_r24_3` | 80 |
| `tests.test_research_agent_r24_4` | 71 |
| `tests.test_research_agent_r24_5` | 38 |
| `tests.test_research_agent_r24_6` | 49 |
| `tests.test_research_agent_r24_8` | 31 |
| `tests.test_research_agent_r24_10` | 14 |
| `tests.test_research_agent_r24_11` | 19 |
| **Combined** | **Ran 487 tests … OK** |

`ai.test_openrouter` → 33 OK (unchanged). `git diff --check` → **clean (rc=0)**.

## 8. Real smoke result

One controlled real OpenRouter run through the scheduler path
(`--force`, discovery enabled only for the invocation, fresh agent dir),
`WATCH_RESEARCH_LLM_MAX_RETRIES=0`, no fallback configured, budget 1 query /
1 fetch / 1 LLM call, ≤120 s.

- **Model:** `nvidia/nemotron-3-ultra-550b-a55b:free` (configured; unchanged).
- **Exact number of LLM calls: 1** (instrumented counter; no retry, no fallback).
- **Runtime:** 65.56 s (≤120 s).
- **Outcome:** the free model timed out →
  `llm_status="failed"`, `llm_failure_kind="TIMEOUT"`,
  `llm_error="OpenRouter connection error: APITimeoutError"` (key-free).
- **Fail-soft proven:** plan `RESEARCH_PARTIAL`; deterministic evidence
  preserved (`de-4a331f12b5611e84`, `nvd_cve`/TRUSTED, hash
  `12e789ee4ca7…`, provider/query/template + redirect chain intact);
  `production_finding=false`, `public_research_only=true`; no finding, no alert.
- Artifact scan: no secrets, no target tokens.

## 9. Safety confirmations

- LLM cannot create evidence; claims require valid attribution; invented
  source/evidence IDs, invented URLs and forbidden verdicts are rejected
  (unchanged).
- Target/program/asset exclusion unchanged (`dell` absent from the LLM context).
- No target URL/host/IP, no exploitation, no PoC, no Nuclei, no browser, no
  verifier, no 5B–5J.
- `production_finding=false`; `public_research_only=true`.
- `WATCH_RESEARCH_DISCOVERY=false` default before and after the smoke; no
  persistent environment change.
- No secrets persisted or logged.

## 10. Remaining limitations

1. The configured **free** model is intermittently unreliable (timeouts / empty
   choices). Failover is available but disabled by default; a stable model or an
   explicit `WATCH_RESEARCH_LLM_FALLBACK_MODEL` is recommended for unattended
   runs.
2. Fallback uses the same OpenRouter account/key; it does not mitigate an
   account-level/rate-limit outage.
3. Retries are budget-bounded by design, but the per-attempt provider timeout is
   the existing fixed 60 s; the loop has no mid-attempt interrupt beyond that.
4. Response parsing remains the existing lenient `parse_llm_json` + strict
   `LLMAnalysis` validation; no semantic claim verification is added.

## 11. GO / NO-GO

- **GO** — deterministic failure classification, secret-free errors, safe
  opt-in fallback, budget-bounded retries, response-format compatibility and
  proven fail-soft evidence preservation are implemented and tested (487 OK).
- Deployment default remains **discovery disabled**; enabling discovery or a
  fallback model is an explicit operator decision.

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R24.11
- Role: LLM Reliability & Safe Failover
