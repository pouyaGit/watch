# Stage R9 — First Real LLM XSS Research Run

## Outcome: STOPPED — provider failure exposed an implementation defect

The single real LLM research call was attempted and failed at the
provider (configured OpenRouter model discontinued → HTTP 404). The
failure surfaced an implementation defect in the R7 CLI error handling:
a provider error propagated as a raw traceback (leaking an OpenRouter
account `user_id`) instead of the designed clean `ERROR` + exit 1.
Per the stage instructions ("If anything fails because of an
implementation defect: STOP and report the defect. Do not patch it in
this stage"), the run was NOT completed, NO patch was made, and the
LLM output-quality evaluation could not be performed.

## Exact command used

```
venv/bin/python -m ai.research_cli xss llm-research xss-488f639165085224
```

One call only. Exit code 1. Nothing was persisted.

## Target candidate (pre-run snapshot)

Exact id: `xss-488f639165085224`

| Field | Value |
| --- | --- |
| candidate file SHA-256 | `599c14f39402f8baf4e10172c7355e77423d4520f60d07f652407a09a4fa056f` |
| status | `INSUFFICIENT_EVIDENCE` (expected per deterministic authority) |
| confidence | `0.35` (expected per deterministic authority) |
| content_hash (R7) | `bbdc0d5f7d26d497acb9397d76c8909485f602acb5f865c1c6b75bac1418f7b6` |
| query | `reflected XSS wordpress plugin parameter` |
| references | `['kb-0958da2bb9935000', 'kb-59a0bec7d50e6054', 'kb-609f38e9c57c0592']` |
| source_evidence | 3 entries: seed `kb-0958da2bb9935000` (score 6, xss_type exact), seed `kb-59a0bec7d50e6054` (score 6, xss_type exact), ingested `kb-609f38e9c57c0592` (score 3, keyword-only) |
| llm dir / record | absent (no LLM research existed before the run) |

## Provider configuration

- `AI_PROVIDER=openrouter`, `OPENROUTER_MODEL=minimax/minimax-m3:free`,
  `OPENROUTER_MAX_TOKENS=8192`, `OPENROUTER_API_KEY` set.
- "Currently configured model" = `minimax/minimax-m3:free`.

## KB evidence used (pre-check 3)

- Loaded via `KnowledgeStore.get_by_id` for each referenced id.
- Resolved: **1 document** — `kb-609f38e9c57c0592` ("WP Responsive
  Images plugin <=1.0 unauthenticated path traversal via 'src'
  parameter").
- NOT resolved in the persisted store (seed fixtures, by design — R7
  consumes store-resolved KB evidence only): `kb-0958da2bb9935000`,
  `kb-59a0bec7d50e6054`. Consistent with R7's real-data validation
  (1 store doc). No fabrication; the prompt's "SUPPLIED KB EVIDENCE"
  section contains only the resolved doc.

## Pre-checks (all completed before the call)

1. Candidate exists — yes (`ai_data/research/xss/xss-488f639165085224.json`).
2. Candidate unchanged from snapshot — yes (snapshot taken immediately
   prior; file hash `599c14f3…`).
3. Referenced KB evidence — `kb-609f38e9c57c0592` exists in store; the
   two seed ids are fixtures outside the store (noted above, not a
   failure).
4. No API key printed — prompt contains no `api_key`/`OPENROUTER`
   material; the CLI/provider never echoed the key. (The traceback
   leaked an OpenRouter `user_id`, not a credential — see defect.)
5. Prompt within R7 bound — built read-only: **6053 chars** ≤ 20,000
   deterministic bound.
6. No execution/Nuclei/subprocess path — R7 tests enforce AST-level
   import safety; the only network call is the provider completion.

## Provider call result

- Failure: `openai.NotFoundError`, HTTP 404 from OpenRouter:
  > "This model is unavailable for free. The paid version is available
  > now - use this slug instead: minimax/minimax-m3"
- This is an external provider condition (the free model endpoint was
  discontinued), not an implementation defect in the provider layer:
  `OpenRouterProvider.complete` correctly wrapped it as
  `OpenRouterProviderError("OpenRouter returned HTTP 404: NotFoundError")`.

## DEFECT (STOP-and-report, NOT patched)

Location: `ai/research_cli.py` → `run_xss_llm_research`.

`assistant.research(...)` is wrapped in `try/except XSSLLMResearchError`
only. A provider failure raises `OpenRouterProviderError` (a
`RuntimeError` subclass) from `self.llm.complete(...)`, which is NOT an
`XSSLLMResearchError` → it propagates uncaught. Result on the real run:

- A full Python traceback was printed to stderr instead of the R7-
  designed clean `ERROR: OpenRouterProviderError: OpenRouter returned
  HTTP 404: NotFoundError` + exit 1.
- The raw `openai.NotFoundError` body included an OpenRouter account
  identifier (`user_id: user_3ILyt5fM0cgJ0IBgXK4CJ5mJMtK`), leaking
  account-identifying provider metadata to stderr. Not the API key
  (verified absent), but contrary to the R7 "no secrets/metadata in
  error paths" intent and the clean-error design contract.

This also means the R7 CLI provider-failure path was never covered by a
test: `test_cli_provider_failure_exits_nonzero_no_partial` mocks
*provider construction* (caught), and the assistant-level provider
tests assert the raw exception propagates rather than the CLI handling
it. The real call is the first to exercise an in-flight provider error.

Per instructions: no code was changed. The fix (catching
`OpenRouterProviderError` alongside `XSSLLMResearchError` in
`run_xss_llm_research`, plus a regression test) is a follow-up task.

## Post-failure verification (fail-closed held on persistence)

- `ai_data/research/xss/llm/xss-488f639165085224.json` does NOT exist
  (no partial output persisted).
- `ai_data/research/xss/llm/` does NOT exist.
- Deterministic candidate file byte-identical to snapshot
  (`599c14f3…`).
- No API key/credential material in the traceback output.

## Post-run authority / content_hash / integrity verification

- status/confidence/content_hash verification of a generated record:
  **not applicable** — no record was generated (call failed before any
  persistence; `build_research_assistant_result` was never reached).
- Deterministic candidate byte-integrity: **verified** (hash matches
  pre-run snapshot exactly).

## API verification

`GET /api/xss/candidates/xss-488f639165085224/llm-research` →
**404** `{"detail":"llm research not found"}`. Correct absence behavior;
does NOT invoke the provider (read-only layer, no `ai.llm` imports —
R8-verified).

## Dashboard verification

`/ui/xss/xss-488f639165085224` → 200. With no LLM record, the R8 panel
renders the neutral **"LLM research not generated."** state; the
deterministic candidate remains visually authoritative
(`RESEARCH CANDIDATE — NOT A PRODUCTION FINDING` banner, confidence
0.35 present). No raw HTML/script, no production-finding language, no
provider invocation from the page. "Real LLM result displayed" is **not
applicable** — no result exists to display.

## Manual quality assessment (1–8)

Not performed — no LLM output was produced (provider failure). Each
category 1–8 is moot until a successful run on a working model slug.

## Concerning behavior observed

1. **Configured model discontinued**: `minimax/minimax-m3:free` no
   longer exists on OpenRouter (404). The config (`OPENROUTER_MODEL`)
   must be updated to a valid slug (provider suggests
   `minimax/minimax-m3`, paid) before any real run — a config change,
   out of scope for this no-code-change stage.
2. **Uncaught provider error → traceback + account-id leak** (the
   defect above).

## Exact command used (repeated)

```
venv/bin/python -m ai.research_cli xss llm-research xss-488f639165085224
```

## No-code-change confirmation

No production code was modified. `ai/researcher/`, `ai/schemas/`,
`backend/`, `web/`, 5B–5J, execution, verification, live validation,
the deterministic candidate, authentication, and database schema are
untouched. No packages added. No `.env`/config changes. No commit, no
push. `git diff --check` unchanged (clean). The only writes attempted
by the toolchain were none — the run persisted nothing.

## Agent / Model

- Model: deepseek-v4-flash (agent). Provider model: **not obtained** —
  the configured `minimax/minimax-m3:free` returned HTTP 404 before any
  completion; no provider model identifier was returned.
- Stage: R9
- Role: Real LLM Validation