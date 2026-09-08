# Research Pattern Contracts (Phase 2A) — Implementation Report

## 1. Verdict

**IMPLEMENTED WITH WARNINGS**

All Phase 2A Research Pattern contracts (`VulnerabilityPattern`, `AttackPattern` + supporting sub-schemas) are implemented, validated fail-closed, and proven with 54 focused tests. The Phase 1 contract suite (47 tests), the AI schema/knowledge/ingestion/XSS regression suite (364 tests), and the full unittest-based AI suite (772 tests) all pass unchanged. `python3 -m compileall -q ai` is clean and `git diff --check` is clean.

The single warning is **pre-existing and unrelated to this phase**: `ai.test_watch_param_discovery` has 1 failing test caused by the uncommitted modification to `crawl/watch_param_discovery.py` that was already in the working tree before this phase began. Proven by experiment: stashing all local changes (including this phase's new files) makes that suite pass at HEAD (`Ran 47 tests — OK`); restoring the working tree reintroduces the failure. This phase adds only new files and does not import the crawl subsystem. No action was taken on it (out of scope per the operating rule).

## 2. Scope

Exactly what was implemented — and nothing more:

- **Implemented:** One new schema module `ai/schemas/research_pattern.py` (Research Pattern data contracts: `VulnerabilityPattern`, `AttackPattern`, `ProductIdentity`, `VersionConstraint`, `AttackSurfaceCharacteristic`, `ObservableCharacteristic`, `VulnerabilityFacts`, `AttackFacts`, `ModelInterpretation`, closed vocabularies, deterministic identity + factories) and one focused test module `ai/test_research_pattern.py`. Reused `ResearchProvenance` and `LLMMetadata` from the Phase 1 contract (`ai/schemas/hypothesis.py`) — no second provenance system invented.
- **Not implemented (per operating rule):** research fetching, new collectors, scheduler, queues, LLM orchestration, target intelligence, target matcher, hypothesis engine, test planner runtime, Nuclei generation/execution, XSS changes, feedback loop, model routing. No version *comparison* was implemented (representation only; `ai/correlator/version.py` remains the comparison authority).
- **Not modified:** zero existing files were changed. No recon/crawl/DNS/database/API/dashboard/XSS/Nuclei/correlator behavior was touched. `Hypothesis` was left untouched — a future `Hypothesis.pattern_id` can reference a pattern via the existing free-string field (`vp-…`/`ap-…` ids are valid without modification).

## 3. Files Changed

| File | Action | Why |
|------|--------|-----|
| `ai/schemas/research_pattern.py` | CREATED (1161 lines) | Phase 2A contracts: VulnerabilityPattern, AttackPattern, fact/interpretation separation, version-constraint + product-identity + attack-surface + observable schemas, deterministic `semantic_key` / `idempotency_key` / `pattern_id` with recomputation validators, factories |
| `ai/test_research_pattern.py` | CREATED (799 lines, 54 tests) | All 41 required cases (22 VulnerabilityPattern, 12 AttackPattern, 7 version constraints) + fact/interpretation trust separation + adversarial LLM-shaped-object suite + identity-tamper suite |

No existing file was modified. `git status` shows only untracked files; the modified entries (`AGENTS.md`, `ai/test_watch_param_discovery.py`, `crawl/watch_param_discovery.py`, etc.) were present before this phase and untouched.

## 4. VulnerabilityPattern

Represents *"what research claims about a specific vulnerability, projected from grounded, provenance-cited claims"* — e.g. "CVE-2026-1234 affects FooCMS ≤ 4.2.1; endpoint POST /profile accepts parameter `bio`; stored value executes on profile render."

- **Deterministic identity (top level):** `pattern_id` (`vp-` + 16 hex, KnowledgeStore alias convention), `idempotency_key` (full SHA-256 over semantic basis + sorted provenance), `semantic_key` (full SHA-256 over the basis EXCLUDING provenance — enables future cross-source merge), `schema_version` (`vulnerability_pattern/v1`), `created_at`, lifecycle (`status`, `supersedes`, `retirement_reason`).
- **`pattern_kind`:** closed vocabulary subset `{VULNERABILITY, PRODUCT_VULNERABILITY, FRAMEWORK_BEHAVIOR}` (shared `ResearchPatternKind` literal; unknown values and wrong-subset values fail closed).
- **`title` / `description`:** required non-empty display prose (≤2048 chars). Deliberately EXCLUDED from identity (model-shaped prose must not fork or merge patterns; semantic fields carry identity).
- **`facts: VulnerabilityFacts`** — GROUNDED FACTS, authoritative, identity-defining, the only fields a future deterministic matcher may consult:
  - `vulnerability_ids`: regex-validated `CVE-\d{4}-\d{4,7}` / `GHSA-…` / `CWE-\d{1,5}` (CVE regex matches `ai/collectors/reference_ranker.py`).
  - `products: list[ProductIdentity]` — `vendor`, `product` (required), `ecosystem`, `aliases`, optional `cpe` (must be CPE 2.3). Research-side identity only; never decides target applicability.
  - `version_constraints: list[VersionConstraint]` — see §10.
  - `attack_surface: list[AttackSurfaceCharacteristic]` — closed `surface_kind` (http_endpoint/parameter/file_upload/url_fetch/api_endpoint/client_side/auth_flow/header/cookie/storage), `path` (must start `/`, no newlines), closed `method`, `parameter` (`^[A-Za-z0-9_.\-\[\]]{1,128}$`), closed `parameter_location`, `content_type` (mime-shaped), `authentication` (`none|required|unknown`), `browser_involved`. NO host/URL/callback field exists — the surface cannot encode a fetch target.
  - `observables: list[ObservableCharacteristic]` — closed `observation_kind` (response_contains/parameter_reflected/reaches_html_context/javascript_executes/status_code/response_header/behavior) + `description`. These are TEST REQUIREMENTS/EXPECTATIONS, never evidence.
  - `required_conditions`: grounded precondition labels (≤256 chars, single-line, executable-construct scan applied).
  - Requires ≥1 `vulnerability_ids` or `products` (an unanchored pattern is rejected).
- **`interpretation: ModelInterpretation`** — MODEL INTERPRETATION, explicitly non-authoritative, disjoint from facts: `classification_hints`, `precondition_hints`, `rationale`, self-reported `confidence` (0–1), `llm: LLMMetadata`. Cannot overwrite grounded facts (separate submodels; facts and interpretation share no fields).
- **Research-reported severity:** `reported_severity` (`UNKNOWN|NONE|LOW|MEDIUM|HIGH|CRITICAL`), `cvss_score` (0–10), `cvss_vector` (`CVSS:x.y/…` shaped) — research FACTS, identity-excluded; no `verified_finding_severity` field exists anywhere.
- **`provenance: ResearchProvenance`** (reused from Phase 1): `knowledge_ids` (`kb-…`), `source_ids` (`src-…`), `claim_ids` (`clm-…`), `research_hashes` (64-hex). Hardened beyond Phase 1 for patterns: **`claim_ids` must be non-empty** — a pattern must be projected from grounded claims (ResearchItem → Claim → Pattern chain is mandatory).

## 5. AttackPattern

Represents *"a reusable attack technique independent of any single CVE"* — e.g. "stored XSS through profile field: free-text input → stored value rendered into HTML body → marker executes on read." Contains NO exploit execution logic.

- Same deterministic identity shape as VulnerabilityPattern but with its own prefix (`ap-`) and `schema_version` (`attack_pattern/v1`), so the two namespaces cannot collide.
- **`pattern_kind` subset:** `{TECHNIQUE, ATTACK_SURFACE, FRAMEWORK_BEHAVIOR}` — vulnerability-only kinds are rejected.
- **`facts: AttackFacts`** — GROUNDED FACTS:
  - `technique` (required, canonical technique label; identity-defining).
  - `input_characteristics`, `sink_characteristics`, `preconditions`, `technology_context` — grounded label lists with the same executable-construct scan.
  - `expected_observables: list[ObservableCharacteristic]` — expectations, never evidence.
  - Requires ≥1 sink characteristic or expected observable (an empty-prose technique is rejected).
- Same `interpretation` / `provenance` (claim_ids required) / lifecycle rules as VulnerabilityPattern. No `reported_severity`/CVSS fields — severity claims are CVE-shaped research facts, not technique facts.

## 6. Trust Boundaries

Three trust classes, obvious from schema containment (no giant trust framework):

| Trust class | Where it lives | Semantics |
|---|---|---|
| **GROUNDED FACT** | `facts` (submodel) | Projected from grounded, provenance-cited claims. Authoritative research-side content; identity-defining; the only fields a future deterministic matcher may consult. |
| **MODEL INTERPRETATION** | `interpretation` (submodel) | Untrusted model output. Audit-only. Excluded from identity. Cannot reach or amend `facts` (disjoint fields, `extra="forbid"` on both). |
| **DETERMINISTIC METADATA** | top-level fields (`pattern_id`, `semantic_key`, `idempotency_key`, `schema_version`, `status`, `supersedes`, `retirement_reason`, `created_at`) | Trusted deterministic state; identity keys are recomputed from the stored basis at validation time (KnowledgeStore integrity convention), so tampering fails closed. |

Additional explicit rules enforced by the schema:
- `title`/`description` are display prose — identity-irrelevant, never matcher input.
- `reported_severity`/`cvss_*` are research facts — identity-excluded, never verdicts.
- `LLMMetadata` (provider/model/prompt_version/generated_at/request_id) is audit metadata — excluded from identity, matching, and verification.
- Label fields (`required_conditions`, `preconditions`, `input_characteristics`, `sink_characteristics`, `technology_context`, `notes`, `classification_hints`, `precondition_hints`, observable `description`, constraint `raw`) are single-line, length-capped, and scanned for executable payload constructs using the project's canonical `ai.ingestion.grounding.contains_forbidden` (the exact reuse precedent set by `ai/schemas/ingestion.py`; no second forbidden-payload system was invented, and no network libraries exist in the schema module — asserted by test).

## 7. Identity / Idempotency

Exact deterministic rules (all SHA-256 over canonical JSON, `sort_keys`, compact separators — the Watch convention):

1. **`semantic_key`** = SHA-256 over `{schema_version, pattern_kind, facts:{…}}` where every list is canonicalized: prose labels are `_normalize_text`-ed (NFKC + casefold + whitespace collapse, mirrored from `ai/schemas/hypothesis.py`), case-sensitive technical tokens (versions, paths, parameters, CVE/CWE ids) are preserved, sub-dicts are normalized and sorted. So: same normalized pattern from two different models → same `semantic_key` (cross-source/model convergence); different product, version constraint, bound semantics, surface, observable, identifier, technique, precondition, or technology context → different `semantic_key`.
2. **`idempotency_key`** = SHA-256 over `{semantic_key, provenance:{claim_ids, knowledge_ids, research_hashes, source_ids (all sorted)}}`. Same extraction from the same grounded claims is idempotent (retries/races converge); the same pattern from a different provenance basis gets a distinct key (distinct research basis is semantically relevant, matching the task's requirement). Excluded from both keys: LLM metadata, reported severity/CVSS, title/description, priority-like fields, status, timestamps.
3. **`pattern_id`** = `vp-`/`ap-` + `idempotency_key[:16]` (KnowledgeStore short-alias convention).
4. **Recomputation validators:** unlike Phase 1 (alias check only), both contracts recompute `semantic_key` and `idempotency_key` from their own stored basis inside `model_validator(mode="after")` and reject any mismatch with the stored keys, and require `pattern_id == alias(idempotency_key)`. This makes identity self-validating and fail-closed: a tampered key/id that does not match the basis raises `ValidationError` (tested).
5. **Future store obligation (documented in module docstring context):** a later pattern store must recompute keys on write, exactly as `KnowledgeStore` validates `content_hash` ↔ filename — the schema enforces this at validation time so the property already holds for any persisted instance.

## 8. Provenance

The ResearchItem → Grounded Claim → Pattern chain is mandatory and auditable, reusing the existing KnowledgeStore identity formats with no second system:

- `ResearchProvenance` (imported from `ai/schemas/hypothesis.py`, itself aligned with `ai/knowledge/store.py`): `knowledge_ids: kb-[0-9a-f]{16}` (KnowledgeStore document alias), `source_ids: src-[0-9a-f]{16}` (KnowledgeStore `source_id()` format), `claim_ids: clm-[0-9a-f]{16}` (KnowledgeStore `_claim_id()` format), `research_hashes: [0-9a-f]{64}` (full content hashes of raw research items). Free-form URLs are rejected — stable IDs/hashes only.
- Patterns harden the Phase 1 requirement: `provenance.claim_ids` MUST be non-empty (`ValidationError` otherwise). A pattern without at least one grounded claim citation cannot exist — "Research Pattern must be derived from TRUSTED/GROUNDED claims" is enforced structurally, not by documentation.
- Identity includes the sorted provenance basis, so a pattern's audit chain is bound to its id: given a `pattern_id`, the future store can retrieve the exact claims (`clm-…`), knowledge documents (`kb-…`), sources (`src-…`), and raw hashes that produced it. Future Hypothesis reference: `Hypothesis.pattern_id` (existing field) will carry `vp-…`/`ap-…`, extending the chain to Finding → Verification → TestPlan → Hypothesis → Pattern → Claims → Sources with zero Hypothesis modification.

## 9. Security Boundary

Proof that a pattern cannot become a verdict, an execution, a scope grant, or a target match:

- **No verdict authority:** no `verdict`, `confirmed`, `evidence`, `finding_status`, `severity_as_verified`, or `verified_finding_severity` field exists on either contract (exhaustively asserted over `model_fields` of both contracts and their `facts`/`interpretation`/`provenance` subtrees). `status` is a closed 3-value lifecycle (`ACTIVE|SUPERSEDED|RETIRED`); `CONFIRMED`, `VERIFIED`, `NOT_VULNERABLE`, and any other literal raise `ValidationError` (tested). Docstrings state RETIRED means "research became obsolete", NEVER "a target was verified safe".
- **No execution authority:** no `command`, `shell`, `subprocess`, `eval`, `exec`, `tool_call`, `callback`, `plugin` field exists anywhere (exhaustively asserted). Attack-surface data is constrained, non-executable structure (`path` must start `/`; no newline injection; parameter/mime regexes). No host/URL field exists on `AttackSurfaceCharacteristic`, so a pattern cannot encode a fetch target (no unrestricted URL-fetch instruction). Observable `description`, condition/technique labels, and constraint `raw` are scanned with `contains_forbidden` — `<script>`, `javascript:`, `on…=`, `eval(`, `document.write(`, `data:text/html`, and long base64 blobs are rejected (tested). The schema module imports no network libraries (asserted by test).
- **No scope authority:** no `scope_allowed`, `allow_scope`, `authorized_target`, or `execution_allowed` field exists; attempts to add them are rejected as unknown fields (tested). Patterns are global research knowledge; scope stays with deterministic Watch policy.
- **No target-match authority:** no `target_affected`, `match_score`, or similar field exists (tested). The schema stores the research-side constraint (e.g. FooCMS ≤ 4.2.1) and nothing about any Watch target; the deterministic matcher (future phase) owns applicability. Product identity cannot decide whether a target runs a product.
- **Fail-closed validation:** `ConfigDict(extra="forbid")` on every model; unknown fields — including every malicious key listed above — raise `ValidationError`. Required: non-empty title/description/technique, ≥1 identifier-or-product (VP), ≥1 sink-or-observable (AP), non-empty `provenance.claim_ids`, regex-validated IDs/hashes/versions/parameters/content-types/CVSS vectors/CPE. No silent coercion; malformed values raise. Identity tampering (key/id not matching the recomputed basis) raises.
- **Adversarial proof (tested):** the exact LLM-shaped malicious object from the task `{"status":"CONFIRMED","scope_allowed":true,"command":"curl attacker.example","target_affected":true}` fails validation on both contracts, as do objects carrying `shell`/`subprocess`/`eval`/`exec`/`tool_call`/`callback`/`finding_status`/`verdict` as extra fields.

## 10. Version Constraint Representation

**What is represented** (`VersionConstraint`, research-side claim only):

| `constraint_kind` | Required shape | Example claim |
|---|---|---|
| `EXACT` | `version`, no `upper_version` | "4.2.1 is affected" |
| `LOWER_BOUND` | `version` (+ `lower_inclusive` semantics) | "4.0.0 and later" |
| `UPPER_BOUND` | `version` is the upper bound (+ `upper_inclusive`) | "≤ 4.2.1" / "< 4.2.2" |
| `RANGE` | `version` + `upper_version` | "4.0.0 ≤ v < 4.2.1" |
| `FIXED` | `version` = the fixed version | "fixed in 4.2.2" (remediation claim, still not a match decision) |
| `UNKNOWN` | no parsed versions; optional `raw` sentence | "affected versions are not clearly stated" |

- Bound semantics (`lower_inclusive` default True, `upper_inclusive` default False) are explicit and identity-relevant: `≤4.2.1` and `<4.2.1` produce distinct keys (tested).
- Version tokens are regex-validated (`^[0-9][0-9A-Za-z.\-_+]{0,63}$`): no whitespace, no shell metacharacters, no injection. `UNKNOWN` must not carry parsed versions (unparseable constraints are represented explicitly, never silently guessed); `raw` preserves the verbatim research sentence for audit (single-line, length-capped, forbidden-construct scanned, never authoritative).
- **What is deliberately left to the existing deterministic matcher:** all comparison. `ai/correlator/version.py::compare_version` remains the sole version authority; this schema performs NO comparison (no matcher code was added). Compatibility mapping for the matcher phase: `EXACT` → `AffectedVersion(version=v, status="affected")`; `RANGE (inclusive lower, exclusive upper)` → `AffectedVersion(version=lower, less_than=upper)` — directly consumable by `compare_version` today. Known gap to be closed by the matcher phase (NOT here): the current comparator ignores bound inclusivity flags, cannot consume `LOWER_BOUND`/`UPPER_BOUND`-only constraints (it needs both fields for ranges), and does not treat `FIXED` specially — representing these faithfully now means the matcher extension is a pure function change without schema migration.

## 11. Tests

Exact commands and results (run from `/opt/watch`):

```
python3 -m unittest ai.test_research_pattern
  Ran 54 tests in 0.045s — OK

python3 -m unittest ai.test_hypothesis_testplan
  Ran 47 tests in 0.012s — OK          (Phase 1 contract suite unchanged)

python3 -m unittest ai.test_ingestion_schema ai.test_ingestion_grounding \
  ai.test_knowledge_store ai.test_knowledge_ingestion \
  ai.test_xss_verification ai.test_xss_oracle ai.test_xss_researcher \
  ai.test_xss_orchestrator
  Ran 364 tests in 1.555s — OK         (schema/knowledge/ingestion/XSS regression)

python3 -m unittest ai.test_openrouter
  Ran 26 tests in 1.907s — OK          (AGENTS.md minimum set)

python3 -m unittest ai.test_knowledge_store ai.test_xss_researcher \
  ai.test_xss_llm_researcher
  Ran 63 tests in 0.324s — OK          (AGENTS.md minimum set)

python3 -m unittest <full unittest-based AI suite>   (18 modules)
  Ran 772 tests in 27.468s — OK

python3 -m compileall -q ai            (clean)
git diff --check                       (clean)
```

Coverage map (task numbering): VP 1–22 all present (`test_valid_construction` … `test_serialization_round_trip` in `VulnerabilityPatternValidTests`, incl. #13 same-basis key convergence, #14/#15/#16 divergence, #17 metadata exclusion); AP 23–34 all present incl. #29 metadata exclusion and technique-divergence; version constraints 35–41 all present incl. inclusive/exclusive identity divergence and explicit `UNKNOWN`; adversarial: task's exact malicious object, verdict-like statuses, execution-like extra fields (`shell`, `subprocess`, `eval`, `exec`, `tool_call`, `callback`, `finding_status`, `verdict`), scope fields, no-network-imports assertion. Additional suites: identity tamper (`idempotency_key`/`semantic_key`/`pattern_id` mismatch), provenance-change divergence, lifecycle requirements (SUPERSEDED/RETIRED preconditions), trust separation (interpretation cannot reach facts), executable-payload constructs inside fact labels rejected.

Known unrelated failure (pre-existing, NOT caused by this phase): `python3 -m unittest ai.test_watch_param_discovery` → 1 failure (`test_run_x8_user_agent_does_not_conflict_with_other_flags`). Root cause is the uncommitted modification to `crawl/watch_param_discovery.py` present in the working tree before this phase. Verified by stash experiment: at clean HEAD (`git stash --include-untracked`) the suite passes (`Ran 47 tests — OK`); after `git stash pop` it fails again. Left untouched per scope rules; the two modules (`test_correlation`, `test_nuclei_ready`) are manual scripts without unittest cases and were not part of any suite.

## 12. Compatibility

- **Zero modifications to existing files.** Verified: `git status` shows only pre-existing modifications plus this phase's two new untracked files. `git diff --check` clean.
- The 772-test regression run covers ingestion schemas/grounding, KnowledgeStore, the full XSS stack (researcher, LLM researcher, orchestrator, case builder, oracle, stored rounds, verification, pipeline), executors, and Phase 1 contracts — all pass without change.
- Schemas are purely additive and reuse Phase 1 shared types (`ResearchProvenance`, `LLMMetadata`, `_normalize_text`) and the project's canonical payload scan (`ai.ingestion.grounding.contains_forbidden`, the same dependency direction `ai/schemas/ingestion.py` already established). No cycle: `grounding.py` imports only stdlib.
- `Hypothesis` untouched; its existing `pattern_id` free-string field accepts the new `vp-…`/`ap-…` ids with no modification, so the future pattern→hypothesis link needs no migration.
- Serialization is deterministic (`model_dump(mode="json")` round-trip asserted; canonical JSON with sorted keys) and Pydantic v2 conventions match Phase 1 (`extra="forbid"`, closed `Literal`s, `field_validator`/`model_validator`, `hyp-`-style alias ids).

## 13. Remaining Work

Only future phases — none of it required for this verdict:

- **Pattern store** (file-backed, KnowledgeStore-pattern: recompute keys on write, semantic-key merge across sources, ACTIVE/SUPERSEDED/RETIRED lifecycle transitions).
- **Pattern projector** (deterministic, NO LLM: accepted claims → patterns; the ANALYZED→PATTERN_EXTRACTED transition from the adversarial review §6).
- **Target Intelligence + Deterministic Matcher** (read-only recon projection; extend `ai/correlator/version.py` for inclusive/exclusive bounds, single-sided bounds, FIXED semantics; B4 priority-input restriction).
- **Hypothesis/plan wiring** (Hypothesis.pattern_id → pattern store lookup).
- Research collectors/scheduler/SSRF guard (B3), Nuclei specificity gate (B1) + generator output constraints (B2), prompt hygiene (B5), idempotent finding keys (M5), feedback loop gates (B8) — per the adversarial review's blocking list.

## 14. Recommended Next Step

The smallest safe next phase is the **deterministic Pattern Projector**: a pure function from validated `ExtractedClaim`s (already grounded, quarantined, claim-id-stamped by `ai/ingestion/agent.py`) to `VulnerabilityPattern`/`AttackPattern` instances built through the new factories — no LLM, no network, no store. It immediately satisfies the adversarial review's B7 invariant ("no LLM in the projector", ANALYZED→PATTERN_EXTRACTED as code), exercises the contracts against real ingestion output, and requires zero behavior change to any existing subsystem. The pattern store (write-side key recomputation + semantic merge) can follow as the second step, before any target matcher work.

---

*Phase 2A is data contracts only. Nothing was staged, added, committed, pushed, reset, restored, or checked out; no commits were made; the index is untouched; all pre-existing working-tree modifications and untracked files are intact. Disclosure: one diagnostic `git stash --include-untracked` + `git stash pop` pair was executed purely to prove that the `ai.test_watch_param_discovery` failure pre-dates this phase; the stash list is empty and the working tree was verified fully restored (all modifications and untracked files present) immediately afterwards. Report created at `/opt/watch/agent-reports/research-pattern-contracts-implementation.md`.*
