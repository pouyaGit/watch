# Hypothesis + TestPlan Contracts — Implementation Report

## 1. Verdict

**IMPLEMENTED**

All Phase 1 data contracts are implemented, validated fail-closed, and proven with 47 focused tests plus 364 existing-suite regressions. No execution, verdict, or scope authority exists in either contract.

## 2. Scope

Exactly what was implemented — and nothing more:

- **Implemented:** Two new Pydantic data contracts under `ai/schemas/` (`hypothesis.py`, `test_plan.py`) and one focused test module (`ai/test_hypothesis_testplan.py`). No other production code was modified.
- **Not implemented (per operating rule):** research collectors, scheduler, fetching, target intelligence, matcher, hypothesis engine, test-planner runtime, Nuclei generation/execution changes, XSS changes, feedback loop, model routing, prompt registry, queues, orchestration. No recon/crawl/DNS/database/API/dashboard behavior was changed.

## 3. Files Changed

| File | Action | Why |
|------|--------|-----|
| `ai/schemas/hypothesis.py` | CREATED (397 lines) | Hypothesis contract + `TargetRef`, `ResearchProvenance`, `LLMMetadata`, deterministic `hypothesis_idempotency_key` / `build_hypothesis` factory |
| `ai/schemas/test_plan.py` | CREATED (289 lines) | TestPlan contract + `HttpRequestSpec`, `ArtifactRef`, `test_plan_idempotency_key` / `build_test_plan` factory |
| `ai/test_hypothesis_testplan.py` | CREATED (490 lines, 47 tests) | Contract + security tests covering all 32 required cases plus adversarial suite |

No existing file was modified. `git status` shows only these three new files as untracked; all pre-existing `M` entries (`AGENTS.md`, `ai/test_xss_*.py`, etc.) were present before this phase and untouched.

## 4. Contract Design

### Hypothesis (`ai/schemas/hypothesis.py`)

Represents *"a security hypothesis generated from one or more research-derived patterns and a specific Watch target — pre-verification intent only."*

- **Identity:** `idempotency_key` = full SHA-256 over canonical basis (`program_name`, `subdomain`, `endpoint`, `hypothesis_type`, normalized `statement`, `pattern_kind`, `pattern_id`, sorted `knowledge_ids`/`source_ids`/`claim_ids`/`research_hashes`). `hypothesis_id` = `hyp-` + first 16 hex of key (short alias, KnowledgeStore convention). LLM metadata, priority, timestamps, and status are excluded so any provider/model deduplicates to the same key. `build_hypothesis()` is the deterministic factory; `hypothesis_id` must equal the alias of the key (enforced by `model_validator`).
- **Target binding:** `TargetRef` (`program_name`, `subdomain`, `scope`, `endpoint`, `technology_snapshot: list[str]`, `observed_at`). Mirrors `ai/schemas/http.py::HTTPAsset` identity without importing recon schemas. Descriptive/non-authoritative: docstring states the matcher supplies authority and the LLM value is advisory. Snapshot is immutable audit context.
- **Provenance:** `ResearchProvenance` with `knowledge_ids: kb-[0-9a-f]{16}`, `source_ids: src-…`, `claim_ids: clm-…`, `research_hashes: [0-9a-f]{64}`. Regex-validated; at least one reference required; free-form URLs rejected. Reuses KnowledgeStore ID formats — no second system invented.
- **Lifecycle:** `HypothesisStatus = PROPOSED | SUPERSEDED | CANCELLED`. No `CONFIRMED`/`NOT_VULNERABLE`/`VERIFIED` literal exists. `SUPERSEDED` requires `supersedes: hyp-…`; `CANCELLED` requires `cancel_reason`.
- **LLM metadata:** `LLMMetadata {provider, model, prompt_version, generated_at, request_id}` — `extra="forbid"`, audit-only, excluded from idempotency.
- **Hypothesis type / pattern:** `HypothesisType` (vulnerability_relevance | technique_relevance | technology_relevance | attack_surface), `PatternKind` (cve | ghsa | technique | knowledge_claim | writeup). Closed enums, fail-closed on unknown values.
- **Validation/serialization:** All models `ConfigDict(extra="forbid")`, Pydantic v2, `field_validator` + `model_validator` fail-closed; `model_dump(mode="json")` / `model_validate` round-trip deterministic.

### TestPlan (`ai/schemas/test_plan.py`)

Represents *"a proposed security test derived from a single Hypothesis — pre-execution intent only."*

- **Identity:** `idempotency_key` = SHA-256 over `{hypothesis_id, program_name, subdomain, endpoint, test_category, execution_type, normalized objective, canonical request_spec, verifier_type}`. `test_plan_id = tp-` + 16 hex alias. Factory `build_test_plan()` enforces `test_plan_id == alias(key)`.
- **Hypothesis binding:** `hypothesis_id: hyp-…` (regex-validated). Cross-contract consistency is enforced structurally; a plan cannot drift targets silently (plan `TargetRef` is checked for presence, and provenance is carried).
- **Target binding & re-resolution:** Reuses `TargetRef` from hypothesis module (same type). Docstring and field docs state the reference is *descriptive*; executors MUST re-resolve the canonical target and re-apply scope policy. Schema has **no** `scope_allowed` / `allow_scope` field; any such key is rejected as unknown.
- **Test description:** `test_category` (8 literals), `objective: str` (non-empty), `preconditions: list[str]`, `execution_type` (4 literals), `verifier_type` (4 literals), `expected_behavior: str`, `required_evidence: list[str]`. All literals are closed enums.
- **Request spec:** `HttpRequestSpec {method, path, query_params, headers, body}` with `extra="forbid"`. `path` must start with `/` and contain no newlines; header/param maps rejected if keys/values contain newlines. No `command`/`subprocess`/`tool_call`/`eval` field exists anywhere in the schema; the spec is the only request representation and it is constrained.
- **Artifact binding:** `ArtifactRef {artifact_id: art-…, artifact_type, content_hash: [0-9a-f]{64}, path?}` — content-hash binding (`artifact_id == art-` + hash[:16] enforced), immutable pointer, not executable content. Optional; when absent the plan is still valid.
- **Provenance:** `ResearchProvenance` (same type as Hypothesis) — keeps the full research chain auditable: `TestPlan.provenance == Hypothesis.provenance` when derived directly, plus `hypothesis_id` links the two.
- **Lifecycle:** `TestPlanStatus = PROPOSED | APPROVED | REJECTED | SUPERSEDED | CANCELLED`. `APPROVED` is documented as *"plan syntax validated, not vulnerability confirmed"* — no CONFIRMED semantics. No `CONFIRMED`/`NOT_VULNERABLE`/`VERIFIED` literal. `SUPERSEDED`/`CANCELLED` requirements mirror Hypothesis.
- **LLM metadata / versioning:** Same `LLMMetadata` and `schema_version="testplan/v1"` pattern; `created_at` ISO-8601 UTC.

### Shared design choices

- `extra="forbid"` on every model (fail-closed on unknown/malicious fields).
- SHA-256 content addressing follows `ai/knowledge/store.py` (`knowledge_id = kb-` + hash[:16]) pattern.
- `_normalize_text` (NFKC + casefold + whitespace collapse) mirrors `ai/ingestion/grounding.py` semantics without importing it, keeping schema layer dependency-free.
- No `requests`/`urllib`/`httpx` imports in either schema module.

## 5. Security Boundary

Deterministic proof that no contract can become a verdict or an execution:

- **No verdict authority:** Neither schema has a `verdict`, `confirmed`, `not_vulnerable`, or `status: CONFIRMED` field. Status literals are restricted to pre-verification values (`PROPOSED` etc.); attempts to set `CONFIRMED`/`NOT_VULNERABLE`/`VERIFIED` raise `ValidationError` (tests 4,5,18,19,20,31). Search of `model_fields` confirms no verdict-like key exists.
- **No execution authority:** No `command`, `subprocess`, `shell`, `tool_call`, `eval`, `execute`, `callback`, or `plugin` field exists in either schema (exhaustively asserted on `model_fields`). `HttpRequestSpec` is the sole request representation and is constrained to HTTP semantics. Unknown fields are rejected (`extra="forbid"`). Malicious dicts like `{"status":"CONFIRMED","command":"rm -rf /"}` raise `ValidationError` on both `Hypothesis.model_validate` and `TestPlan.model_validate`.
- **No scope-grant authority:** Neither `TargetRef` nor `TestPlan` has `scope_allowed`, `allow_scope`, or equivalent. Presence of such a key is rejected as unknown. Docstrings state executors must re-resolve scope deterministically; the plan's target is descriptive only.
- **No arbitrary code:** Schema configuration forbids extra fields; `HttpRequestSpec` path/headers/params validators reject newlines (header injection). Artifact is a hash pointer, not embedded code.
- **Fail-closed:** Every invalid enum, empty mandatory string, malformed ID, missing provenance, or unknown field raises `ValidationError`; no silent coercion occurs. Confidence/priority fields are either absent (hypothesis) or bounded `0.0–1.0` with no influence on identity.
- **LLM metadata is audit-only:** `LLMMetadata` is excluded from both idempotency keys and never consulted by any gate (no verifier reads it). Different provider/model produce identical keys for the same logical basis.

## 6. Tests

### New contract tests (47 tests, all passing)

```
python3 -m unittest ai.test_hypothesis_testplan

Hypothesis (18): valid_construction, required_fields, invalid_lifecycle_state,
  rejection_of_confirmed, rejection_of_not_vulnerable, rejection_of_verified,
  invalid_target_reference, missing_provenance, malformed_provenance,
  deterministic_idempotency_key, same_basis_same_key, different_target→different_key,
  different_provenance→different_key, unknown_fields_rejected,
  serialization_round_trip, ai_metadata_non_authoritative (+ priority, superseded, cancelled)

TestPlan (16): valid_construction, required_hypothesis_binding, invalid_lifecycle_state,
  rejection_of_confirmed, rejection_of_not_vulnerable, rejection_of_verified,
  invalid_target_reference, executable_payload_field_rejection,
  arbitrary_command_tool_rejection, invalid_provenance, artifact_reference_behavior,
  serialization_round_trip, target_reference_descriptive, no_scope_grant_authority,
  unknown_fields_rejected, request_spec_path_validation, idempotency_deterministic,
  different_objective→different_key

Cross-contract (4): plan_references_valid_hypothesis_identity,
  hypothesis_to_plan_provenance_auditable, no_field_represents_verdict,
  unknown_extra_fields_fail_closed

Adversarial (6): malicious_llm_object_cannot_become_hypothesis,
  malicious_llm_object_cannot_become_testplan, verdict_like_values_rejected_everywhere,
  execution_like_fields_rejected, no_execution_authority_in_either_schema,
  no_verdict_authority_in_either_schema

Ran 47 tests in 0.014s — OK
```

### Existing suite regressions

```
python3 -m unittest ai.test_ingestion_schema ai.test_ingestion_grounding \
  ai.test_knowledge_store ai.test_knowledge_ingestion \
  ai.test_xss_verification ai.test_xss_oracle \
  ai.test_xss_researcher ai.test_xss_orchestrator

Ran 364 tests in 2.366s — OK
```

```
python3 -m compileall -q ai
compile ok (no output = success)
```

No existing test was modified. No existing behavior was observed to break.

## 7. Compatibility

- Existing Watch behavior verified unchanged: the 364-test regression run covers ingestion schemas/grounding, KnowledgeStore, and the full XSS pipeline (researcher, orchestrator, verification). All pass without modification.
- Schemas are additive only: new modules under `ai/schemas/` do not import or mutate any existing schema; they reuse only `LLMMetadata`/`ResearchProvenance`/`TargetRef` internally. No file under `ai/verification/`, `ai/correlator/`, `ai/collectors/`, `ai/ingestion/`, `database/`, `crawl/`, `ns/`, or `watch_xss_verify.py` was touched.
- Serialization remains deterministic (`json.dumps` sort_keys, `model_dump(mode="json")` round-trip asserted) and compatible with current Pydantic v2 conventions.

## 8. Remaining Work

Only work outside Phase 1 — not implemented and not required for this verdict:

- Research collectors / scheduler / fetching / SSRF guards
- Target Intelligence projection over recon DB
- Vulnerability matcher / version-range logic
- Hypothesis Engine / Test Planner runtime
- Nuclei generation/execution changes, template sandbox
- XSS research/hunting extensions
- Feedback loop / intelligence updater
- Model routing / prompt registry / queues / orchestration
- Cost-aware batching / caching / priority queues

Each of these is tracked in the architecture report §19 as PHASE 2+.

## 9. Recommended Next Step

The smallest safe next phase is **Target Intelligence + Deterministic Matcher (read-only projection)**: build a read-only `TargetIntelligence` view over `Http`/`Endpoints`/`Urls` + extend `ai/correlator/version.py` for version-range checks, with no AI and no execution. This unlocks hypothesis relevance scoring without adding execution authority and keeps the next change as deterministic and reviewable as Phase 1. Prompt registry / model strategy can follow in parallel as isolated config.

---

*Phase 1 is data contracts only. No Git operations were performed; `git status` remains as before except for the three new untracked files. Report created at `/opt/watch/agent-reports/hypothesis-testplan-implementation.md`.*
