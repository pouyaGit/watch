# Stage R9.1 — Fix Provider Error Handling

## Summary

Fixed ONLY the R9 defect: `run_xss_llm_research` caught
`XSSLLMResearchError` but not `OpenRouterProviderError`, so an
in-flight provider failure escaped as a raw traceback whose chained
cause exposed OpenRouter account metadata (`user_id`). The handler now
catches both exception types and emits the existing clean
`ERROR: <type>: <message>` + exit 1. No successful-path behavior
changed; nothing is persisted on failure.

## Root cause

Location: `ai/research_cli.py::run_xss_llm_research`.

`assistant.research(...)` calls `self.llm.complete(prompt)` in-flight.
On a provider failure `OpenRouterProvider.complete` raises
`OpenRouterProviderError` (a `RuntimeError` subclass, defined in
`ai/llm/openrouter.py`), which is NOT an `XSSLLMResearchError`. The
`try` around `assistant.research(...) + persist_research(...)` caught
only `XSSLLMResearchError`, so the provider error propagated uncaught.
Python then printed the full traceback chain to stderr — including the
`__cause__` (the raw `openai` error whose body carries the OpenRouter
`user_id`), which is exactly the R9 leak. Provider-construction
failures were already handled by a separate broad `except Exception`
earlier in the function; only the in-flight path was exposed.

A negative control reproduced the mechanism: raising the same
`OpenRouterProviderError` with a chained cause under the old
`except XSSLLMResearchError`-only handler prints the chain
(`ValueError: response body: {'user_id': ...}`) to stderr.

## Exact fix

`ai/research_cli.py`, `run_xss_llm_research` only (7 added lines,
1 modified line):

1. Lazy import alongside the existing lazy imports (same convention as
   the existing lazy `OpenRouterProvider` import; provider stays
   injected, module stays import-light):
   `from ai.llm.openrouter import OpenRouterProviderError`
2. Widened the existing handler:
   `except (XSSLLMResearchError, OpenRouterProviderError) as exc:`
   keeping the identical clean-error body:
   `print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)` +
   `return 1`.

Why this is safe against metadata leakage: `OpenRouterProvider`
builds wrapper messages from status code + exception type name only
(`OpenRouter returned HTTP 404: NotFoundError`,
`OpenRouter connection error: ...`, `OpenRouter request failed: ...`)
— never response bodies, keys, or account ids. Printing only
`str(exc)` of the wrapper (and never the traceback chain) therefore
cannot emit the `user_id`, API key, Mongo URI, or env secrets.

Not changed: `OpenRouterProvider` behavior untouched; schemas
untouched; deterministic XSS agent untouched; dashboard untouched;
execution / 5B–5J / live validation untouched; no packages added;
success path (research → persist → `LLM-RESEARCH`/`SAVED`/`MODE`
output, return 0) byte-identical.

## Regression test

Added to `ai/test_xss_llm_assistant.py`:
`test_cli_inflight_provider_failure_clean_error_no_leak`. It injects a
mock LLM raising `OpenRouterProviderError("OpenRouter returned HTTP
404: NotFoundError")` with a chained cause carrying a fake
`user_id`/`sk-or-` key (mirroring the R9 leak), plus a sentinel
`OPENROUTER_API_KEY` in the environment, then captures stderr and
verifies: exit code 1; `ERROR:` + `OpenRouterProviderError` present;
no `Traceback`; no sentinel user_id; no `user_id`; no sentinel API
key; no `OPENROUTER_API_KEY`/`WATCH_MONGO_URI`; no persisted
`llm/<candidate>.json`. Uses no model slug (no discontinued model).

## Exact test counts

Required suites, one run, all `OK`:

| Suite | Tests |
| --- | --- |
| ai.test_xss_llm_assistant (incl. 1 new regression test) | 21 |
| ai.test_research_cli | 6 |
| ai.test_xss_agent | 21 |
| ai.test_xss_researcher | 12 |
| ai.test_knowledge_store | 15 |
| ai.test_openrouter | 26 |
| **Total** | **101** |

`git diff --check` → clean.

## Confirmation of no traceback/metadata leakage

- New regression test asserts absence of `Traceback`, `user_id`,
  sentinel key material, and env-secret names in stderr — passes.
- Wrapper message content audited in `ai/llm/openrouter.py::complete`:
  status-code + type-name only, no bodies/credentials.
- No successful-path behavior changed: `test_cli_success_path_persists`
  passes unmodified; the fix only widens the failure handler's caught
  types, leaving the `try` body and all success output untouched.
- No partial persistence on failure: `persist_research` is never
  reached (exception precedes it); asserted absent on disk.

## Agent / Model

- Model: muse-spark-1.3-contributor (Muse Spark)
- Stage: R9.1
- Role: Bug Fix
