# Stage R9.5 — Real LLM XSS Research Run with a Different Free Model

## Outcome

STOPPED — provider rate limit. Exactly ONE real provider call was made
with a different free model (`google/gemma-4-31b-it:free`). OpenRouter
returned HTTP 429 (`RateLimitError`), surfaced through the designed clean
`ERROR: <type>: <message>` path with exit 1. Per the strict single-call
budget ("Do not retry with another model in the same stage"), no retry was
attempted, no second call was made, and no code was changed. Nothing was
persisted. No validation was reached.

## Provider Model

- Actual OpenRouter model used: `google/gemma-4-31b-it:free`
- Selection method: queried the live OpenRouter catalog
  (`GET https://openrouter.ai/api/v1/models`, metadata only — not an LLM
  call) immediately before the run. The catalog listed 431 models, 18 with
  a `:free` suffix. Nemotron (`nvidia/nemotron-3-ultra-550b-a55b:free`,
  the R9.4 model) was explicitly excluded per instructions.
- Why this slug: explicit stable slug (not `openrouter/free` random
  routing); instruction-tuned dense text-output model from a major lab
  (Google DeepMind "Gemma 4 31B Instruct", 256K context); catalog
  description confirms text input/output. Rejected alternatives:
  same-family Nemotron variants (shared failure-mode risk after R9.4's
  empty-choices result), `nemotron-3.5-content-safety` (a safety
  classifier, not a research model), code-specialist slugs
  (`poolside/*`, `cohere/north-mini-code`), and lesser-known preview
  slugs. The slug was taken verbatim from the live catalog — not
  invented.
- Configuration mechanism: process-environment override only
  (`OPENROUTER_MODEL=google/gemma-4-31b-it:free` prefixing the single
  command). `.env` untouched (still
  `nvidia/nemotron-3-ultra-550b-a55b:free`). No application code, schema,
  prompt, validator, dashboard, API, or persistence logic modified.

## Candidate

Exactly: `xss-488f639165085224`. No other candidate run. Nemotron NOT
retried in this stage.

## Pre-call Snapshot (recorded before the provider call)

| Field | Value |
| --- | --- |
| candidate file SHA-256 | `599c14f39402f8baf4e10172c7355e77423d4520f60d07f652407a09a4fa056f` |
| deterministic content_hash (recomputed) | `bbdc0d5f7d26d497acb9397d76c8909485f602acb5f865c1c6b75bac1418f7b6` |
| matches expected hash | True (exact) |
| status | `INSUFFICIENT_EVIDENCE` (as expected) |
| confidence | `0.35` (as expected) |
| query | `reflected XSS wordpress plugin parameter` |
| references | `['kb-0958da2bb9935000', 'kb-59a0bec7d50e6054', 'kb-609f38e9c57c0592']` |
| source_evidence | 3 entries: `kb-0958da2bb9935000` (score 6), `kb-59a0bec7d50e6054` (score 6), `kb-609f38e9c57c0592` (score 3) |
| llm record before run | absent (`ai_data/research/xss/llm/` did not exist) |

## Preflight (all completed before the call, offline, no provider involved)

- Candidate exists — yes (2118 bytes).
- Candidate hash matches expected `bbdc0d5f…` — yes, exact.
- Prompt does not expose content_hash — verified by offline prompt build:
  hash value absent.
- Prompt does not ask the model to generate content_hash — verified: the
  token `content_hash` appears nowhere in the built prompt (R9.3 fix
  confirmed on the prompt path).
- No API key or Mongo URI in prompt — none of `OPENROUTER_API_KEY`,
  `sk-or-`, `WATCH_MONGO_URI`, `MONGODB` present.
- No Nuclei / target / subprocess execution — module imports only
  `hashlib`, `json`, `re`, `pathlib`, `typing`, `pydantic`,
  `ai.llm.base` (interface), parser helper, schemas (R7-AST-verified,
  unchanged since).
- Prompt within existing bounds — **6006 chars** ≤ 20000.
- Referenced KB evidence loadable — 1 doc resolved via
  `KnowledgeStore.get_by_id`: `kb-609f38e9c57c0592`; two seed ids are
  fixtures outside the store, by design (same as R9/R9.4).

## Exact Command (run exactly once)

```
OPENROUTER_MODEL=google/gemma-4-31b-it:free venv/bin/python -m ai.research_cli xss llm-research xss-488f639165085224
```

The `OPENROUTER_MODEL=` prefix is the ONLY configuration change, scoped
to this single process invocation.

## Provider Result

- Exit code: **1**.
- Full stderr (exact, clean, single line, no traceback):

  ```
  ERROR: OpenRouterProviderError: OpenRouter returned HTTP 429: RateLimitError
  ```

- Meaning: the request reached OpenRouter and the slug was accepted (no
  404 unknown-model error), but the account/model was rate-limited at call
  time — a transient provider-side capacity condition on the free tier,
  not a client, slug, validation, or content_hash defect. Error hygiene
  held (R9.1 path): no traceback, no response body, no `user_id`, no key
  material.
- No validation failure occurred: validation was never reached (no model
  output existed to validate).

## Persisted File

- `ai_data/research/xss/llm/xss-488f639165085224.json`: **does NOT exist**.
- `ai_data/research/xss/llm/`: **does NOT exist** (no directory created).
- All persisted-field verifications (candidate_id, status, confidence,
  verifier-stamped content_hash, evidence kinds, attribution,
  references_used, URLs, exploitation/execution claims, model/
  raw_response_id metadata, authority changes): **not applicable** — no
  record was generated.

## Content Hash Verification

- Expected verifier hash `bbdc0d5f…` recomputed pre-call and confirmed.
- No generated record to compare against (none exists). The R9.3
  stub-provider proof (hash-less body succeeds with verifier-stamped hash)
  remains the only executed verification of the fix; this real run
  neither confirms nor contradicts it.

## Candidate Byte Integrity

- Post-failure `sha256sum`: `599c14f3…` — **byte-identical** to the
  pre-call snapshot. The deterministic candidate was untouched.

## API Verification

- Not applicable — no LLM record exists. No API call made in this stage.
  Expected absence behavior (R9-observed):
  `GET /api/xss/candidates/xss-488f639165085224/llm-research` → 404
  `{"detail":"llm research not found"}` via the read-only layer, which
  never invokes the provider.

## Dashboard Verification

- Not applicable — no LLM record exists, so no research panel to inspect.
  No dashboard request issued. Expected (R8/R9): neutral "LLM research
  not generated." state with the deterministic candidate remaining
  visually authoritative; nothing in this stage could have altered that.

## Manual Quality Assessment

Not performed — no model output was produced. All eight categories are
moot until a run yields a persisted record:

1. Evidence accuracy — N/A. 2. Evidence vs inference — N/A.
3. Uncertainty — N/A. 4. Security reasoning — N/A. 5. Attack surface —
   N/A. 6. Missing evidence — N/A. 7. Test idea — N/A.
8. Hallucination resistance — N/A (nothing generated to hallucinate with).

## Overall Quality Score

N/A (1–10 moot — no completion returned). This is a rate-limit outcome,
not a model-quality signal.

## Hallucination Findings

None — no content was generated; no URLs, technologies, sinks, sources,
vulnerabilities, versions, or exploitation claims were emitted by any
component.

## Useful Insights

- The newly selected slug is currently a *valid, routable* free model
  (accepted by OpenRouter — no 404), unlike Minimax in R9. The 429 is a
  capacity/quota signal, so this slug remains a viable candidate for a
  future single-call stage; nothing about this outcome impugns the model.
- Failure-mode contrast across real attempts is now three distinct,
  cleanly-handled provider behaviors: 404 discontinued slug (R9/Minimax),
  200-with-empty-choices (R9.4/Nemotron), 429 rate limit (R9.5/Gemma).
  All three exited through the same clean `ERROR` + exit-1 path with no
  leakage and no partial persistence — the R9.1 error-handling fix is
  holding across every observed failure shape.

## Comparison Against Previous Real-Model Attempts

| Attempt | Provider model | Result | Quality score |
| --- | --- | --- | --- |
| R9 (Minimax) | `minimax/minimax-m3:free` | HTTP 404, slug discontinued/unavailable for free | N/A (no output) |
| R9.4 (Nemotron) | `nvidia/nemotron-3-ultra-550b-a55b:free` | HTTP 200 but empty `choices`, no completion | N/A (no output) |
| R9.5 (this stage) | `google/gemma-4-31b-it:free` | HTTP 429 `RateLimitError`, no completion | N/A (no output) |

No output has yet been produced by any real provider call, so no
model-vs-model research-quality comparison is possible. (Coding-agent
performance in R7–R9.3 is unrelated to LLM research quality and is not
scored here.)

## Call Budget

- Exactly ONE provider call made in this stage (the command above). The
  catalog metadata fetch (`GET /v1/models`) is not a completion call and
  consumed no call budget.
- No retries, automatic or manual. No second model attempted in-stage.
- Nemotron not retried. No other candidates run.

## Code Changes

- NONE. No application code, schemas, prompts, validators, CLI, backend,
  web, execution, or database paths modified. `.env` unmodified. The only
  filesystem write in this stage is this report. No commit, no push.

## Agent / Model

- Model: muse-spark-1.3-contributor-free (Muse Spark)
- Provider Model: google/gemma-4-31b-it:free
- Stage: R9.5
- Role: Real LLM Validation
