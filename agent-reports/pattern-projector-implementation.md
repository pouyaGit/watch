# Deterministic Pattern Projector (Phase 2B) — Implementation Report

## 1. Verdict

**IMPLEMENTED**

A pure, deterministic projector from already grounded claims to
Phase 2A research patterns is implemented in one new module,
proven by 54 focused tests, with all required regression suites
passing unchanged and no existing file modified.

## 2. Repository Findings

The actual grounded-claim representation in HEAD differs from the
task brief's assumed field names. What exists:

- **`ai/schemas/ingestion.py::ExtractedClaim`** — the validated
  claim type produced by the ingestion layer. Fields:
  `evidence_class` (`EXPLICIT` / `STRONGLY_IMPLIED` /
  `MODEL_INFERENCE`), `rationale`, `evidence_snippets`,
  `title`, `summary`, `technologies`, `xss_types`, `contexts`,
  `wafs`, `techniques`, `payload_patterns`,
  `verification_patterns`, `tags`, `evidence_quality`,
  `confidence`, `forbidden_values`, `strict_payloads`.
  Confidence bands are enforced per evidence class
  (`EXPLICIT` 0.80–1.00, `STRONGLY_IMPLIED` 0.55–0.79,
  `MODEL_INFERENCE` 0.00–0.54).
- **Grounding boundary** (`ai/ingestion/agent.py`): a claim is
  accepted only if at least one evidence snippet is grounded in the
  source content AND every populated metadata value is grounded
  (`claim_values_grounded`), AND no executable payload construct
  survives (`contains_forbidden` re-scan). `MODEL_INFERENCE`
  claims are quarantined and never persisted.
- **Stable claim IDs** (`ai/knowledge/store.py`): the store stamps
  `claim_id = clm-` + 16 hex (SHA-256 over the canonical claim),
  `source_id = src-` + 16 hex, `knowledge_id = kb-` + 16 hex,
  and full 64-hex `content_hash` (the research hash). Persisted
  claims live as `KnowledgeSourceClaims`
  (`ai/schemas/knowledge.py`) with `evidence_quality`
  `HIGH_CONFIDENCE` (from `EXPLICIT`) / `SECONDARY` (from
  `STRONGLY_IMPLIED`).
- **`ai/schemas/source.py::ResearchDocument`** (vendor/products/
  cpes/cwes/affected_versions/CVSS) is RAW collector output that
  has NOT crossed any grounding boundary and is therefore NOT an
  accepted projector input.

Consequences: there is NO `cve_id`, `product`,
`affected_version`, `endpoint`, `parameter`, `sink`,
`preconditions`, `claim_id`, `knowledge_id`, `source_id`, or
`research_hash` field on any claim type. The brief's example
mapping table is therefore mostly unsupported (documented in §4).
No second Claim model was invented: the projector wraps the two
existing claim types verbatim in a thin `GroundedClaim` provenance
envelope and reuses the Phase 2A factories
(`build_vulnerability_pattern` / `build_attack_pattern`) with no
validation bypass.

## 3. Projection API

Module: `ai/researcher/pattern_projector.py` (pure; imports only
stdlib + `pydantic.ValidationError` + existing schema/grounding
helpers). Public surface:

```python
@dataclass(frozen=True)
class GroundedClaim:
    claim: ExtractedClaim | KnowledgeSourceClaims
    claim_id: str            # clm-... (required)
    knowledge_id: str | None # kb-...
    source_id: str | None    # src-...
    research_hash: str | None  # 64-hex content hash

@dataclass(frozen=True)
class ProjectionSkip:
    claim_id: str
    reason: SkipReason  # ungrounded_evidence_class |
                        # missing_provenance | insufficient_information |
                        # validation_failed | forbidden_content |
                        # unsupported_claim
    detail: str

@dataclass(frozen=True)
class ProjectionResult:
    patterns: tuple[Pattern, ...]
    skipped: tuple[ProjectionSkip, ...]

def project_claim(claim: object) -> list[VulnerabilityPattern | AttackPattern]
def project_claims(claims: Sequence[object]) -> ProjectionResult
```

`project_claim` returns 0+ typed pattern objects (empty = safely
skipped); `ValueError` propagates on forbidden content or pattern
validation failure (fail closed). Anything that is not a
`GroundedClaim` (raw `str`/`dict`, `SourceDocument`,
`ResearchDocument`) raises `TypeError` — raw research text has no
code path into pattern facts. `project_claims` sorts inputs by
claim fingerprint, merges equal-`semantic_key` patterns over the
union provenance, dedupes identical claims, and records per-claim
skip reasons so one bad claim never poisons the batch. No
database, network, LLM, or subprocess dependency; unit-testable in
isolation.

## 4. Claim → Pattern Mapping

Concrete mapping based on actual repository fields:

| Claim field | Pattern field |
|---|---|
| `technologies[]` | `VulnerabilityFacts.products[]` (one `ProductIdentity` per distinct technology) and `AttackFacts.technology_context[]` |
| `techniques[]` | `AttackFacts.technique` (one `AttackPattern` per distinct label) |
| `contexts[]` | `AttackFacts.sink_characteristics[]` |
| `payload_patterns[]` | `AttackFacts.input_characteristics[]` |
| `verification_patterns[]` | `expected_observables[]` / `observables[]` as `observation_kind="behavior"` expectations (never evidence) |
| `title` / `summary` | pattern `title` / `description` (display prose, identity-excluded) |
| `rationale` / `confidence` | `Pattern.interpretation` (audit-only) |
| `xss_types[]` / `wafs[]` / `tags[]` / `evidence_class` | `interpretation.classification_hints` (preserved audit-only, never facts) |
| wrapper `claim_id` / `knowledge_id` / `source_id` / `research_hash` | `ResearchProvenance` |

Explicitly unsupported (`UNMAPPED_FIELDS` in code — never guessed):
`cve_id`, `affected_version`, `endpoint`, `parameter`,
`observation`, `sink`, `preconditions`. There are therefore no
vulnerability identifiers, no version constraints, no attack-surface
endpoints/paths/methods/parameters, no required conditions, and no
severity/CVSS on projected patterns. Products carry no vendor/CPE
(the claim model has none). Version-like technology strings
(e.g. `"FooCMS 4.2.1"`) are preserved verbatim as product labels;
no version is ever parsed, compared, or inferred.

## 5. VulnerabilityPattern Projection

Rule: emit exactly one `VulnerabilityPattern`
(`pattern_kind="PRODUCT_VULNERABILITY"`) iff the claim carries ≥ 1
distinct technology label; otherwise skip (`insufficient_information`).
Every technology label must pass the executable-construct/newline
scan or the claim fails closed (`forbidden_content`). Observables
are attached only from grounded `verification_patterns[]`.
Construction goes exclusively through `build_vulnerability_pattern`;
any `ValidationError` fails the projection. Limitations: patterns
are product-anchored only (no CVE/GHSA/CWE, no version constraints,
no attack surface) until the ingestion schema gains CVE/version/
endpoint fields — a deliberate, documented gap, not a silent
default (no `UNKNOWN` constraint is fabricated from absent data).

## 6. AttackPattern Projection

Rule: emit one `AttackPattern` (`pattern_kind="TECHNIQUE"`) per
distinct technique label iff the claim also carries ≥ 1 sink
characteristic (`contexts[]`) or expected observable
(`verification_patterns[]`); a bare technique with neither is
skipped per the Phase 2A minimum. All contributing labels are
scanned; one unsafe label fails that claim closed without affecting
sibling claims. No sink, observable, precondition, or input
characteristic is ever fabricated: empty claim lists stay empty,
and `preconditions`/`required_conditions` remain empty because the
claim model has no such field. Limitations: technique granularity
is whatever the upstream extractor produced; multi-technique claims
yield one pattern per technique rather than an invented merge.

## 7. Trust Boundary

Trust is preserved, never created, by three structural facts:

1. **Entry gate** — `GroundedClaim.__post_init__` rejects
   `MODEL_INFERENCE` / snippet-less `ExtractedClaim`s and
   `UNVERIFIED`/`UNKNOWN` `KnowledgeSourceClaims` with
   `ValueError`. The projector cannot express "trust this
   ungrounded text": there is no parameter, flag, or second
   constructor to bypass the gate (proven by construction-failure
   tests).
2. **Disjoint sinks** — grounded lists flow only into `facts`;
   `rationale`/`confidence`/unprojectable metadata flow only into
   `interpretation` (identity-excluded, matcher-invisible by
   contract). Tests assert verbatim that rationale strings and
   confidence values appear in `interpretation` and nowhere in
   `facts` serialization, and that verdict-flavored summary wording
   ("confirmed … verified …") leaves `status == "ACTIVE"` with no
   verdict field.
3. **No escalation path** — the module contains no LLM client, no
   fetcher, and no grounding logic of its own; it reuses
   `contains_forbidden` (the canonical scan) purely as a
   rejection filter. Downgrade is the only direction metadata can
   move (grounded-but-unprojectable `xss_types`/`wafs`/`tags`
   become audit-only hints).

## 8. Determinism

- Same `GroundedClaim` → same `pattern_id`/`idempotency_key`/
  `semantic_key` (tested by double-projection equality).
- Input order independence: `project_claims` sorts by claim
  fingerprint before projecting and sorts output by `pattern_id`;
  `[A, B]` and `[B, A]` produce identical outputs (tested),
  as do claims whose internal lists are permuted (case-insensitive
  dedupe + sorted canonical form).
- Duplicates: identical claims merge to one pattern with one
  `claim_ids` entry (set-union provenance); same semantic content
  from different claims merges to one pattern over the union
  provenance (same `semantic_key`, new provenance-bound
  `idempotency_key`/`pattern_id` — matching the Phase 2A identity
  rule, which was NOT modified).
- No timestamps, UUIDs, randomness, model calls, or network state
  influence output (`created_at` is schema-default audit metadata,
  excluded from identity).

## 9. Security Boundary

Proven by architecture and tests:

- **No LLM** — module namespace contains no provider/client/
  completion symbol; projection runs with `socket.socket`
  disabled (test).
- **No network** — no `requests`/`urllib`/`httpx`/`socket`
  symbol in the module.
- **No execution** — no `subprocess`/`os`/`sys`/`eval`/`exec`
  symbol; the only request-adjacent data (product/observable
  labels) is string data inside constrained schema fields.
- **No scope authority** — no `scope_allowed`/`allow_scope`
  field on either contract output (asserted over serialized
  patterns).
- **No target-match authority** — no `target_affected`/
  `match_score` field; version-like strings are inert labels and
  `ai/correlator/version.py` is untouched and unimported.
- **No finding/verdict authority** — no `verdict`/`confirmed`/
  `evidence`/status-escalation field; `status` is always the
  factory default `ACTIVE`.
- **Fail closed** — unknown input types (`TypeError`),
  forbidden/newline content (`ValueError` → `forbidden_content`
  skip), insufficient content (`insufficient_information` skip),
  and factory `ValidationError`s (propagated, never swallowed).
  Malicious suite covers `<script>`, `javascript:`, `eval(`,
  event-handler, newline, absolute-URL/callback labels, and
  inert security words (`confirmed`, `scope_allowed`,
  `tool_call`, …) — the former are rejected, the latter carry
  zero authority.

## 10. Tests

Exact commands and results (from `/opt/watch`):

```
python3 -m unittest ai.test_pattern_projector
  Ran 54 tests in 0.036s — OK

python3 -m unittest ai.test_research_pattern ai.test_hypothesis_testplan \
  ai.test_ingestion_schema ai.test_ingestion_grounding \
  ai.test_knowledge_store ai.test_knowledge_ingestion
  Ran 233 tests in 1.452s — OK

python3 -m unittest ai.test_openrouter ai.test_xss_researcher \
  ai.test_xss_llm_researcher ai.test_xss_orchestrator \
  ai.test_xss_verification ai.test_xss_oracle
  Ran 294 tests in 2.500s — OK

python3 -m compileall -q ai   (clean)
```

The 54 new tests cover: no-LLM/network/execution/version-comparator
imports; network-disabled projection; raw-text/`SourceDocument`/
`ResearchDocument` rejection; `MODEL_INFERENCE`/`UNVERIFIED`/
`UNKNOWN`/missing-snippet/malformed-ID rejection; VP/AP basic
projection; multi-technique fan-out; insufficiency skips; store-claim
form; full provenance preservation + optional absence + duplicate
normalization + multi-claim merge + semantic-convergence key
behavior; determinism/order-independence/no-duplicate suites;
batch poisoning isolation; rationale/confidence/metadata trust
separation; verdict-wording non-escalation; no invented versions +
verbatim version-like labels; empty attack surface; newline/URL
handling; the malicious matrix; factory fail-closed propagation;
identity-tamper rejection; empty batch.

## 11. Files Changed

| File | Action | Why |
|---|---|---|
| `ai/researcher/pattern_projector.py` | CREATED (~600 lines) | Deterministic projector: `GroundedClaim` envelope, `project_claim`/`project_claims`, merge logic, mapping + fail-closed policy |
| `ai/test_pattern_projector.py` | CREATED (54 tests) | Security + determinism + trust test matrix |
| `agent-reports/pattern-projector-implementation.md` | CREATED | This report |

No existing file was created, modified, or renamed. No Git
operation was performed.

## 12. Compatibility

Additive only: the projector imports existing schemas and the
canonical `contains_forbidden` scan (the same dependency direction
`ai/schemas/ingestion.py` and `research_pattern.py` already use)
without altering them. Phase 2A identity rules, factories, and
validators are consumed as-is. Regression evidence: the 47-test
Phase 1 suite, the 54-test Phase 2A suite, the ingestion/
grounding/knowledge suites, and the XSS/orchestrator/verification/
oracle suites all pass unmodified; `compileall` is clean. The
pre-existing `crawl/watch_param_discovery.py` working-tree state
was not touched or evaluated (out of scope).

## 13. Limitations

1. Current ingestion claims carry no CVE/GHSA/CWE identifiers, so
   projected `VulnerabilityPattern`s are product-anchored only and
   carry no `vulnerability_ids`.
2. Claims carry no version statements, so `version_constraints`
   is always empty (no `UNKNOWN` placeholder is fabricated).
3. Claims carry no endpoint/path/method/parameter structure, so
   `attack_surface` is always empty and parameter-level patterns
   (e.g. "`bio` reflected in HTML") cannot project yet.
4. Claims carry no preconditions/severity/CVSS, so those pattern
   fields stay at their safe defaults.
5. Technique granularity is inherited from upstream extraction;
   the projector does not split, merge, or normalize technique
   semantics beyond deterministic label dedupe.
6. Multi-claim merge combines provenance and audit-only
   interpretation; `title`/`description` follow the deterministically
   first contributor (identity-excluded display prose).

## 14. Recommended Next Step

The smallest safe next phase is the **file-backed Pattern Store**
(KnowledgeStore-pattern: recompute `semantic_key`/
`idempotency_key` on write, `semantic_key` merge across sources,
`ACTIVE`/`SUPERSEDED`/`RETIRED` lifecycle) — it needs no schema
change, exercises projector output against real ingestion claims,
and still grants no matching, execution, or verdict authority.
Extending `ExtractedClaim` with CVE/version/endpoint structure
(CVE IDs, version statements, HTTP method/path/parameter) is the
parallel prerequisite that would unlock identifier-anchored
`VulnerabilityPattern`s and populated attack surfaces.

---

*Phase 2B ends at Grounded Claim → Deterministic Pattern. No Git
operations were performed; the index is untouched. Report created
at `/opt/watch/agent-reports/pattern-projector-implementation.md`.*
