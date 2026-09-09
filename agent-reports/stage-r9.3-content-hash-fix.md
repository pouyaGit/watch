# Stage R9.3 — Fix Verifier-Derived content_hash Binding

## Summary

Fixed the R7 content_hash design defect diagnosed in R9.2. The binding
hash is now derived and stamped by the verifier from trusted local
state; the LLM is never asked to generate, copy, or validate it. A real
model response without `content_hash` now succeeds (the R9.2-identified
failure mode is structurally impossible), while the persisted record
still carries the verifier-derived `content_hash` for candidate-version
binding. Minimal targeted fix: one module (`xss_llm_assistant.py`) plus
its test file. No schema, provider, agent, dashboard, or execution
changes. No real provider call was made.

## Root cause (from R9.2)

- `XSSLLMResearchAssistantResult.content_hash` (persisted schema)
  required the field, but `_candidate_projection` deliberately strips
  `content_hash` from the prompt, so the model could never know the
  value.
- `build_research_assistant_result` did `payload.update(llm_data)`,
  letting model output overwrite the deterministic binding, then
  `_check_authority` compared the model's (necessarily invented) string
  against the verifier hash → every real response failed
  "mismatched content_hash" with ~2^-256 success probability.
- Test blind spot: `_valid_llm_body` injected the hash out-of-band, so
  mocks passed while the real path was deterministically broken.

## Exact implementation

`ai/researcher/xss_llm_assistant.py` (3 edits):

1. **Prompt schema** (`_build_prompt`): removed the
   `"content_hash": "string (exactly as given)"` line from the
   model-visible JSON schema. The LLM is now asked to produce research
   content only. Verified: the token `content_hash` no longer appears
   anywhere in the built prompt (asserted by test).

2. **Result construction** (`build_research_assistant_result`): the
   model-supplied dict is copied and `content_hash` is popped from it
   (`llm_data.pop("content_hash", None)`) — explicitly discarded, never
   trusted, never compared. The deterministic payload still seeds
   `content_hash` from `candidate["content_hash"]` (the verifier hash
   computed in `research()`), and `payload.update(llm_data)` can no
   longer overwrite it because the key has been removed from untrusted
   input. `payload.update(llm_data)` can therefore never override the
   deterministic binding.

3. **Authority check** (`_check_authority`): replaced the
   model-echo comparison with a binding assertion over verifier-stamped
   state: requires `candidate["content_hash"]` to exist (else error),
   then asserts `result.content_hash == det_hash` with the message
   `content_hash binding mismatch (verifier-stamped value only)`. Since
   the result's hash is stamped from the candidate's verifier hash, this
   is a defense-in-depth invariant, not a model capability test. The
   genuinely model-echoable authority fields (`candidate_id`, `status`,
   `confidence`) remain enforced exactly as before.

`ai/schemas/xss.py`: UNCHANGED — `XSSLLMResearchAssistantResult`
retains required `content_hash: str` because the persisted record still
contains the binding (see § Schema behavior). No schema migration.

`ai/research_cli.py`: UNCHANGED (R9.1 already fixed the provider-error
path).

`ai/test_xss_llm_assistant.py`: `_valid_llm_body` no longer contains
`content_hash`; added 6 tests (see § Test coverage).

## Old vs new trust boundary

| Aspect | Before (R7) | After (R9.3) |
| --- | --- | --- |
| who produces content_hash | LLM (impossible: value withheld) | verifier derives from deterministic candidate |
| prompt asks for content_hash | yes ("string (exactly as given)") | no |
| prompt exposes the hash | no | no |
| model-supplied content_hash | overwrote binding via `payload.update` | popped/discarded before validation |
| authority check | compares model string vs verifier hash | asserts verifier-stamped binding only |
| persisted record contains content_hash | yes | yes (unchanged) |
| status/confidence/candidate_id authority | enforced | enforced (unchanged) |

## Schema behavior

- Model-visible schema (prompt JSON): no `content_hash`.
- Persisted schema (`XSSLLMResearchAssistantResult`): still requires
  `content_hash`; the verifier stamps it after validation. A raw model
  body without `content_hash` correctly fails `model_validate` (it is
  not a complete result until stamped) — asserted by
  `test_result_schema_round_trip`.
- Backward compatibility: existing persisted LLM research records (with
  `content_hash`) read normally — the persisted schema is byte-identical
  to R7's. No migration, no rewrite of existing records. (The real tree
  currently has no `ai_data/research/xss/llm/` records.)

## Test coverage (A–L)

New/modified in `ai/test_xss_llm_assistant.py`:

- A `test_valid_response_without_content_hash_succeeds` — content_hash-
  less body succeeds; hash is stamped.
- B same test asserts `result.content_hash == candidate["content_hash"]`
  and `test_r9_failure_mode_impossible` asserts the persisted file
  carries the verifier hash.
- C/D `test_model_supplied_wrong_content_hash_ignored` (wrong 64-hex)
  and `test_model_supplied_correct_content_hash_also_ignored` (even an
  exact echo is discarded) — model can never override.
- E/F `test_prompt_hides_hash_and_does_not_ask_for_it` — the candidate
  hash value and the `content_hash` token are both absent from the
  prompt.
- G `test_changed_candidate_different_content_hash` — altering the
  candidate payload yields a different hash (canonical algorithm
  unchanged).
- H existing `test_insufficient_cannot_upgrade_to_candidate`,
  `test_status_downgrade_rejected`, `test_confidence_cannot_be_overridden`,
  `test_deterministic_candidate_authority_status_unchanged` — status/
  confidence authority unchanged.
- I existing `test_authoritative_candidate_unchanged_after_llm_research`
  + `test_persistence_idempotent_and_candidate_unchanged` — candidate
  file byte-identical.
- J existing `test_persistence_idempotent_and_candidate_unchanged`
  (atomic replace, single record, byte-identical repeat).
- K existing R9.1 `test_cli_inflight_provider_failure_clean_error_no_leak`
  + `test_cli_provider_failure_exits_nonzero_no_partial`.
- L `test_r9_failure_mode_impossible` — full CLI pipeline with a
  content_hash-less body exits 0 and persists the stamped binding
  (this is the test that would have caught R9).

## Exact test counts

Required suites, one run, all `OK`:

| Suite | Tests |
| --- | --- |
| ai.test_xss_llm_assistant (incl. 6 new R9.3 tests) | 27 |
| ai.test_research_cli | 6 |
| ai.test_xss_agent | 21 |
| ai.test_xss_researcher | 12 |
| ai.test_knowledge_store | 15 |
| ai.test_openrouter | 26 |
| ai.test_research_kb_xss_e2e | 6 |
| ai.test_reports_renderer | 14 |
| **AI total** | **127** |

Backend/UI regression (persisted record shape shared with readers):
`tests.test_xss_llm_dashboard` + `tests.test_research_api` +
`tests.test_research_ui` → **82 tests, all pass**.

`git diff --check` → clean.

## Real provider test

NO real provider call was made in this stage (per §10). Verification of
the fixed behavior used a stub `LLMProvider` against the real persisted
candidate `xss-488f639165085224` (loaded from disk, no `content_hash`
key) and the real KnowledgeStore: result status `INSUFFICIENT_EVIDENCE`,
confidence `0.35`, stamped `content_hash == bbdc0d5f…` (verifier-derived
`_candidate_content_hash`), prompt neither exposes the hash nor asks for
it, persisted record carries the verifier hash. The next stage performs
the real model call.

## Security review

- content_hash is verifier-derived: computed via the existing canonical
  `_candidate_content_hash` (SHA-256 of the canonical candidate payload
  excluding `content_hash`, `sort_keys`, compact separators —
  algorithm/serialization unchanged) and stamped after validation.
- Model cannot override it: any model-supplied value is popped before
  `payload.update`; `_check_authority` asserts the stamped binding only.
- status/confidence remain authoritative (enforced, unchanged).
- No evidence laundering: attribution/URL/references checks unchanged.
- No secret leakage: prompt/redaction tests unchanged and passing.
- No new execution: only the existing `LLMProvider` abstraction
  (R7) is called; no subprocess, no target execution, no Nuclei.
- No network except the injected provider abstraction; no new
  dependencies; no production finding; no alert; no auth changes;
  no dashboard changes.

## Backward compatibility

Persisted schema and record shape unchanged (`content_hash` retained);
existing records (none currently on disk) would read normally; no
automatic migration/rewrite. The deterministic candidate JSON is never
written by the LLM layer (unchanged, byte-integrity tested).

## Confirmation

No real provider call made. Files changed: `ai/researcher/xss_llm_assistant.py`,
`ai/test_xss_llm_assistant.py`. All other paths untouched (schemas,
CLI, agent, backend, web, execution, 5B–5J, live validation, database,
auth). No packages added. No Git operations (no commit/push).

## Agent / Model

- Model: deepseek-v4-flash
- Stage: R9.3
- Role: Security-Sensitive Bug Fix