# Deterministic Hypothesis Engine (Phase 4A) — Implementation Report

## 1. Verdict

**IMPLEMENTED**

A deterministic Hypothesis Engine converting eligible
TargetPatternMatch records into Phase 1 Hypothesis objects is
implemented in one new module, proven by 61 focused tests
(adversarial matrix A–AI plus a pure in-memory integration
chain), with every required regression suite passing unchanged.
One minimal additive extension to `ai/schemas/hypothesis.py` was
objectively required for match/snapshot binding; all pre-existing
identity keys reproduce byte-for-byte.

## 2. Actual Repository Findings

Authority was the worktree code, not prior reports. Confirmed:

- **Hypothesis contract** (`ai/schemas/hypothesis.py`): `Hypothesis`
  with `hypothesis_id` (`hyp-` alias of full-SHA-256
  `idempotency_key`), `TargetRef` (program/subdomain/scope/
  endpoint/technology_snapshot/observed_at, descriptive only),
  closed `HypothesisType` (vulnerability_relevance,
  technique_relevance, technology_relevance, attack_surface),
  closed `PatternKind` (cve, ghsa, technique, knowledge_claim,
  writeup), `ResearchProvenance` (kb-/src-/clm- IDs + 64-hex
  hashes, at least one required), neutral `priority` (default
  0.0), `LLMMetadata` audit-only, lifecycle PROPOSED →
  SUPERSEDED/CANCELLED. Critically, the model validates only the
  id alias and lifecycle — it does NOT recompute the key from
  the basis — and the pre-4A basis (target + type + statement +
  pattern + provenance) contains NO match or snapshot binding.
  Two matches of one pattern against two snapshots would
  otherwise be distinguishable only inside free text.
- **Match contract** (`ai/schemas/target_match.py` + matcher):
  `TargetPatternMatch` carries `match_id` (`tm-`), `pattern_id`,
  `pattern_type`, `target_key`, `snapshot_hash`, program/
  subdomain, closed `match_kind`, sorted criteria lists,
  explainable score, single-line explanation. Matcher is pure
  (typed objects, no lookup) with MATCH/PARTIAL_MATCH vs
  NO_MATCH/INCONCLUSIVE semantics and MATCH ≠ VULNERABLE.
- **Patterns/TI**: `VulnerabilityPattern` facts (ids, products,
  version constraints, attack surface, observables, required
  conditions) and `AttackPattern` facts (technique, sinks,
  preconditions, observables, technology_context); TI carries
  `target_key`, `snapshot_hash`, technologies, endpoint/url
  observations, descriptive `scope_snapshot`, `observed_at`.
  Interpretation/severity/CVSS are identity-excluded and
  matcher-invisible — the engine preserves that boundary.
- **Projector/store/knowledge**: `GroundedClaim` envelope,
  `project_claim(s)`, file-backed `PatternStore`; no changes
  needed or made. `scope_policy.py` exists and was deliberately
  NOT imported.

## 3. Files Changed

| File | Action | Why |
|---|---|---|
| `ai/researcher/hypothesis_engine.py` | CREATED (~380 lines) | Deterministic engine: `build_hypothesis_from_match`, `build_hypotheses_from_matches`, `EngineResult`, closed eligibility, deterministic statement/type/priority/provenance rules |
| `ai/test_hypothesis_engine.py` | CREATED (61 tests) | Matrix A–AI + pure integration chain |
| `ai/schemas/hypothesis.py` | MINIMAL ADDITIVE EXTENSION | Optional `match_id`/`snapshot_hash` fields + optional key-basis params + factory passthrough (see §5); all existing keys byte-identical |
| `agent-reports/hypothesis-engine-implementation.md` | CREATED | This report (written from scratch; no prior file existed) |

No other file was created, modified, or renamed. Target
Matcher, Target Intelligence, Pattern Store, Pattern Projector,
Nuclei/XSS pipelines, collectors, crawler, and database models
are untouched.

## 4. Exact Contract Implemented

Engine input/output (typed objects only; raw dicts/strings/IDs
→ `TypeError`, never coerced):

```python
build_hypothesis_from_match(
    match: TargetPatternMatch,
    pattern: VulnerabilityPattern | AttackPattern,
    target_intelligence: TargetIntelligence,
) -> EngineResult  # CREATED | SKIPPED | REJECTED

build_hypotheses_from_matches(
    matches: list[TargetPatternMatch] | tuple,
    pattern_resolver: Callable[[str], Pattern | None],
    target_resolver: Callable[[str], TargetIntelligence | None],
) -> tuple[EngineResult, ...]  # sorted by match_id, deduped
```

`EngineResult` (frozen): `outcome`, `hypothesis` (Hypothesis on
CREATED, else None), deterministic `reason`, `match_id`.
Binding gates (all fail closed as REJECTED):
`match.pattern_id == pattern.pattern_id` (no substitution);
`pattern_type` ↔ pattern class agreement; four-field target
agreement (`target_key`, `snapshot_hash`, `program_name`,
`subdomain`) — identity is never inferred from hostnames,
domains, URLs, or pattern metadata. Eligibility: MATCH and
PARTIAL_MATCH → CREATED; NO_MATCH and INCONCLUSIVE → SKIPPED
(never silently a hypothesis). Created hypotheses are PROPOSED
with neutral `priority=0.0`, closed derived types, deterministic
statements from structured fields only, verbatim provenance, and
the re-resolution invariant encoded in text and snapshot
fields. Resolvers are read-only DI callables receiving string
IDs only; unresolvable/wrong-typed resolutions → per-item
REJECTED with full batch isolation.

## 5. Hypothesis Identity / Idempotency Design

Smallest justified extension, backward compatible by
construction:

- `Hypothesis` gains `match_id: str | None = None`
  (`^tm-[0-9a-f]{16}$`) and `snapshot_hash: str | None = None`
  (64-hex). Both default None, so every pre-4A construction
  validates unchanged.
- `hypothesis_idempotency_key` gains optional
  `match_id=""` / `snapshot_hash=""`, included in the canonical
  basis ONLY when non-empty. Proven by test: legacy calls
  reproduce legacy keys byte-for-byte (`test_legacy_key_
  reproduces_without_binding`); bound calls diverge
  (`test_binding_changes_identity`).
- `build_hypothesis` passes both through; the engine always
  sets both.

Resulting guarantees (all tested): same pattern + same target +
same snapshot + same match → identical identity (modulo
audit-only `created_at`); same pattern + different target,
different snapshot, or different pattern → distinct identities;
reordered observations converge (projection sorts; key sorts);
duplicate batch matches dedupe by `match_id`. Statement text
additionally embeds `match_id` + `snapshot_hash`, giving triple
binding (basis fields + statement + stored fields).

## 6. Match Binding Design

`Hypothesis.pattern_id` exactly equals the bound pattern's id
(gate-enforced, never substituted); `Hypothesis.match_id`
equals the source match's `tm-` alias; pattern `ResearchProvenance`
is copied verbatim via re-validation (never manufactured, never
edited). Type agreement is enforced both directions
(vulnerability↔VulnerabilityPattern, attack↔AttackPattern).
`pattern_kind` derives from structured facts only: AttackPattern
→ `technique`; any `CVE-` id → `cve`; any `GHSA-` id → `ghsa`;
otherwise `knowledge_claim`. `hypothesis_type` derives from the
contract: vulnerability → `vulnerability_relevance`, attack →
`technique_relevance`. No new types invented; no severity/CVSS/
urgency prose consulted (B4).

## 7. Snapshot Binding Design

`Hypothesis.snapshot_hash` equals the bound TI's hash;
`target.technology_snapshot` records the sorted observed tech
labels and `observed_at` the TI timestamp (both descriptive);
`target.endpoint` records the smallest matched surface path or
"" (descriptive); `target.scope` copies the TI subdomain scope
as observed data. The statement names the snapshot hash and
declares that future testing must re-resolve the canonical
target and scope. Proven: snapshot change → different
`hypothesis_id`; `target_key`/`snapshot_hash`/`program_name`/
`subdomain` mismatches each → REJECTED; cross-program and
cross-subdomain batches keep distinct identities with no
merging.

## 8. Security Boundary

Proven by construction and tests:

- **No LLM** — AST import scan finds no provider/completion/
  embedding/model/agent import; hostile "CRITICAL / EXPLOIT
  NOW" interpretation + severity 10.0 + CVSS vector change
  neither priority (stays 0.0, neutral basis) nor kind.
- **No network** — no requests/httpx/urllib/socket import; full
  single + batch builds run with `socket.socket` disabled.
- **No subprocess** — no subprocess/shutil/multiprocessing/os/
  sys import.
- **No database** — no database/mongo/store import; engine
  takes objects, never IDs; resolvers are caller-owned.
- **No scope authority** — scope policy absent from the import
  graph; no `scope_allowed`/`execution_allowed`/`authorized`
  field exists; scope travels only as descriptive TI data.
- **No verdict authority** — no `verdict`/`confirmed`/
  `finding_status`/`evidence`/`target_affected` field; status
  PROPOSED only (`CONFIRMED` rejected by the Literal);
  MATCH/PARTIAL statements contain no "target is vulnerable",
  "confirmed", "verified", "exploitable", or "in scope" claim.
- **No execution authority** — no command/shell/request/
  browser/Nuclei/payload/callback field; shell-like pattern
  labels and "CONFIRMED"-shaped prose stay inert (never
  interpolated — statements use IDs/kinds/criteria only).
- Fail closed: wrong types → `TypeError`; mismatches →
  REJECTED; ineligible kinds → SKIPPED; empty identity →
  REJECTED.

## 9. Adversarial Tests

61 tests; matrix coverage: A–E binding mismatches → REJECTED;
F–G matched pairs → CREATED; H–I crossed types (forged
`pattern_type`) → REJECTED; J–K NO_MATCH/INCONCLUSIVE →
SKIPPED with `hypothesis=None`; L–M MATCH/PARTIAL → PROPOSED
hypothesis only (verdict-literal scan, forbidden-claim scan,
kind distinction in text); N–S idempotency/provenance/snapshot
rules; T–U hostile priority/severity neutrality + no-authority
field scan; V shell-like labels inert; W "CONFIRMED"-shaped
prose yields PROPOSED with clean statement; X–Z raw-dict/wrong-
type/empty-identity fail-closed; AA–AE import scans +
network-disabled run + scope-absence proofs; AF cross-program
isolation; AG batch order-independence; AH match-binding audit
(fields + statement); AI snapshot-collision prevention.
Integration: GroundedClaim → projector → PatternStore-free
patterns → TI projection → matcher → engine → Hypothesis,
asserting every CREATED artifact is PROPOSED relevance-only and
every other outcome is SKIPPED with no hypothesis.

## 10. Regression Test Results

From `/opt/watch`:

```
python3 -m unittest ai.test_hypothesis_engine
  Ran 61 tests — OK
python3 -m unittest ai.test_research_pattern ai.test_hypothesis_testplan \
  ai.test_pattern_projector ai.test_pattern_store \
  ai.test_target_intelligence ai.test_target_matcher
  Ran 343 tests — OK
python3 -m unittest ai.test_ingestion_schema ai.test_ingestion_grounding \
  ai.test_knowledge_store ai.test_knowledge_ingestion
  Ran 132 tests — OK
python3 -m unittest ai.test_openrouter ai.test_xss_researcher \
  ai.test_xss_llm_researcher ai.test_xss_orchestrator \
  ai.test_xss_verification ai.test_xss_oracle
  Ran 294 tests — OK
python3 -m compileall -q ai   (clean)
```

No unrelated pre-existing failures encountered in any run
suite. Correlator `test_correlation/candidate/assessment/
shortlist` modules are manual live scripts (MongoDB + network,
0 unittest cases) and were not runnable here; they are
unaffected (no correlator code touched).

## 11. Limitations

1. `created_at` remains audit-only wall-clock metadata excluded
   from identity (same convention as all prior phases);
   whole-model equality therefore differs across runs while
   identity content is stable — tests compare accordingly.
2. Statements deliberately exclude pattern prose (titles,
   technique labels) so hostile text cannot reach even inert
   prose fields; human readability of *why* beyond criteria
   lives in the bound match explanation, reachable via
   `match_id`.
3. `target.endpoint` records only the smallest matched surface
   path; multi-path relevance detail stays in the match record.
4. Batch resolvers are trusted only as fetchers: every
   returned object is re-validated through the full single-
   match binding gates, but resolver freshness/consistency
   (TOCTOU between resolve and build) is the caller's
   responsibility.
5. Priority is uniformly neutral; any future scheduler must
   derive its own deterministic ordering — `priority` on these
   hypotheses must never be treated as execution authority.
6. Hypotheses reference matches by alias only; match-record
   retention/expiry policy is a future store concern.

## 12. Git Confirmation

**No Git operation was performed.** No `git status`, `diff`,
`add`, `commit`, `checkout`, `restore`, `reset`, `merge`,
`branch`, `stash`, or any other git command was run. Unrelated
working-tree state was not inspected, staged, or modified.

## 13. Recommended Next Safe Phase

The smallest safe next phase is **deterministic TestPlan
construction from a single bound Hypothesis** (Hypothesis →
TestPlan intent only, Phase 1 `build_test_plan` contract):
derive `test_category`/`execution_type`/`verifier_type` from the
closed hypothesis type + matched criteria, bind
`hypothesis_id` + snapshot target description, keep the
detection/request spec minimal and validator-gated, and prove
by fixture tests that plans carry no scope, execution, or
verdict authority. Do NOT build LLM proposal, executors,
schedulers, queues, Nuclei/XSS runtimes, feedback loops, or
findings until plan records exist with those proofs.

---

*Phase 4A ends at TargetPatternMatch + Research Pattern +
Target Intelligence Snapshot → Deterministic Hypothesis.
No Git operations were performed; the index is untouched.
Report created at
`/opt/watch/agent-reports/hypothesis-engine-implementation.md`.*
