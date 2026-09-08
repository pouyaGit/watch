# Deterministic Target Matcher (Phase 3B) — Implementation Report

## 1. Verdict

**IMPLEMENTED**

A deterministic, read-only relevance matcher joining research
patterns with target intelligence is implemented in two new modules
(contract + matcher), proven by 96 focused tests, with every
required regression suite passing and one minimal additive
extension to `ai/correlator/version.py`. No existing behavior was
modified: `compare_version` is byte-identical, no schema, store,
projector, scope, database, or network code was touched, and no Git
operation was performed.

## 2. Repository Findings

Actual conventions found in code (reports were not trusted blindly):

- **Product identity** (`ai/correlator/technology.py`): `normalize`
  strips version suffixes (`nginx:1.30.4` → `nginx`) and
  separators; `match_technology(technology, vendor, product,
  cpes)` applies exact normalized identity → generic-technology
  blocklist (`python`, `php`, …) → explicit small alias map →
  token-set equality → vendor+product subset → CPE fallback. No
  substring matching. Confidence values are correlator-internal
  and are NOT propagated into the match result.
- **Version comparison** (`ai/correlator/version.py`): the existing
  `compare_version(detected, affected_versions)` supports ONLY
  exact (`version` set, `less_than` unset) and half-open ranges
  (`version <= detected < less_than`). It ignores inclusivity
  flags, cannot consume single-sided `LOWER_BOUND`/`UPPER_BOUND`
  constraints, and has no `FIXED` semantics. `normalize_version`
  (packaging-based) is the parsing authority. Callers
  (`assessment.py`, `watch_targets.py`) use `compare_version`
  unchanged.
- **Pattern identity** (`ai/schemas/research_pattern.py`):
  `VulnerabilityPattern` facts = `vulnerability_ids`, `products[]`
  (vendor/product/ecosystem/aliases/cpe), `version_constraints[]`
  (`EXACT|RANGE|LOWER_BOUND|UPPER_BOUND|FIXED|UNKNOWN` with
  `version`/`upper_version`/`lower_inclusive`/`upper_inclusive`),
  `attack_surface[]` (surface_kind/path/method/parameter/
  parameter_location/…), `observables[]`, `required_conditions`;
  `AttackPattern` facts = `technique`, `input/sink/preconditions`,
  `expected_observables`, `technology_context`. Interpretation,
  severity, CVSS, and prose are identity-excluded and
  matcher-invisible by contract.
- **Target identity** (`ai/schemas/target_intelligence.py` +
  `ai/researcher/target_intelligence.py`): `TargetIntelligence`
  carries `target_key` (program+subdomain), `snapshot_hash`
  (observation state), `technologies[]` (name/observed_version/
  raw_label from `http_tech`), `endpoint_observations[]`
  (path/params/param_details with method ∈ {GET,POST,PUT,PATCH},
  location ∈ {query,body}), `url_observations[]`
  (scheme/host/path/params), and a non-authoritative
  `scope_snapshot`. Scope authority stays with
  `ai/correlator/scope_policy.py`.
- **Projector reality** (Phase 2B): current `ExtractedClaim`
  objects carry no CVE IDs, versions, endpoints, methods, or
  parameters, so projector-built patterns are product-anchored
  only (empty `version_constraints`/`attack_surface`). The matcher
  therefore treats absent constraint families as not-applicable
  (excluded from every criteria list), never fabricates `UNKNOWN`
  placeholders, and documents unrepresentable present content as
  unknown uncertainty.

## 3. Match Contract

New schema `ai/schemas/target_match.py`
(`MATCHER_VERSION = "target_matcher/v1"`, all models
`extra="forbid"`):

- **TargetPatternMatch**: `match_id` (`tm-` + 16 hex),
  `pattern_id` (`vp-`/`ap-`), `pattern_type`
  (`vulnerability`|`attack`), `target_key` (64-hex),
  `snapshot_hash` (64-hex, binds the observation state),
  `program_name`, `subdomain`, `match_kind`
  (`MATCH|PARTIAL_MATCH|NO_MATCH|INCONCLUSIVE`),
  `matched_criteria[]`, `unmatched_criteria[]`,
  `unknown_criteria[]` (closed `MatchCriterion` vocabulary,
  sorted, duplicate-free — enforced by validators),
  `deterministic_score` (0–1), `explanation` (single-line,
  ≤4096 chars, derived deterministically from the criteria),
  `matcher_version`.
- `match_id_for(...)` = `tm-` + SHA-256 over the canonical basis
  (matcher version + pattern id + target key + snapshot hash +
  sorted criteria). `deterministic_score_for(...)` = rounded
  `matched / (matched + unmatched + unknown)` (0.0 when nothing
  evaluated).
- No `verdict`, `confirmed`, `target_affected`, `scope_allowed`,
  `execution_allowed`, `command`, `match_score`, `evidence`, or
  status field of any kind exists (asserted by unknown-field
  rejection tests); `match_kind` rejects every verdict-valued
  literal.

## 4. Match Algorithm

New module `ai/researcher/target_matcher.py` (stdlib + existing
correlator/schema imports only). Public API:

```python
match_pattern_to_target(pattern, target) -> TargetPatternMatch
match_patterns_to_target(patterns, target) -> list[TargetPatternMatch]
```

Typed in/out; non-pattern/non-TI inputs (including raw dicts)
raise `TypeError` — no silent coercion. Batch matching evaluates
each pattern independently and returns results sorted by
`pattern_id`; no cross-pattern inference, no global score.

Evaluation order per (pattern, target) pair:

1. Product (vulnerability only): every product name + alias via
   `match_technology` against every observed technology
   (`raw_label`, vendor, optional CPE). Any hit → `product`
   matched (observed versions of hits become the version
   candidates); none → `product` unmatched.
2. Version (vulnerability only): every constraint × every
   candidate version via `evaluate_version_constraint`. Any MATCH
   → `version` matched; else any INCONCLUSIVE → unknown; else
   unmatched. No constraints → not applicable. No product anchor
   or no observed versions → unknown (never guessed).
3. Attack surface (vulnerability only): `path`/`method`/
   `parameter`/`parameter_location` by exact equality against
   endpoint+url paths, per-path/all observed methods, endpoint/
   url params, and param-detail locations. A field no surface
   entry specifies is not applicable. Locations outside the
   target `{query, body}` vocabulary are unknown. Empty target
   inventory for a specified field → unknown, not mismatch.
4. Technology context (attack only): every context label via
   `match_technology` (vendor empty, no CPE) against observed
   technologies. Technique/sink/precondition/observable content
   has no target representation → recorded as unknown markers.
5. Kind decision table: `product` unmatched → NO_MATCH;
   `version` unmatched → NO_MATCH; nothing matched +
   something unmatched → NO_MATCH; nothing matched +
   nothing unmatched → INCONCLUSIVE; all evaluated matched →
   MATCH; product-only matched with `version` unknown and no
   other signal → INCONCLUSIVE (the spec's FooCMS/unknown-version
   case); otherwise PARTIAL_MATCH.

## 5. Product Matching

No second algorithm: matching calls `match_technology`
verbatim, inheriting exact normalized identity, the explicit
alias map, token equality, vendor+product composition, CPE
fallback, the generic-technology blocklist, and the
no-substring rule. `ProductIdentity.aliases` are tried as
alternative names for the same product. The correlator
`confidence` is recorded in explanation detail text
(`exact_identity` etc. as match-type labels) but never enters
the score. Proven: case normalization (`FooCMS`/`foocms`),
alias (`Apache` → `Apache:2.4.59`), multi-technology targets,
duplicate observations, unrelated products, generic-technology
non-overmatch (`Python` × `GitPython`), and no-substring
(`Foo` × `FooCMS`).

## 6. Version Matching

Exact use of `ai/correlator/version.py`: the matcher calls the
NEW `evaluate_version_constraint` authority (see below) and never
compares versions itself. All `VersionConstraint` kinds:

| Kind | Semantics implemented |
|---|---|
| EXACT | `detected == version`, else MISMATCH |
| LOWER_BOUND | `detected >= version` (or `>` when exclusive) |
| UPPER_BOUND | `detected <= version` (or `<` when exclusive) |
| RANGE | lower check + upper check, each honoring its flag |
| FIXED | `detected >= fixed` → MISMATCH; older → INCONCLUSIVE (affected lower bound unstated; never MATCH) |
| UNKNOWN | always INCONCLUSIVE |

Missing/unparseable versions on either side → INCONCLUSIVE.
`≤ 4.2.1` vs `< 4.2.1` are distinguished exactly (tested both
directions at the boundary). Proven: FooCMS ≤4.2.1 × 4.1.0 →
MATCH; × 4.5.0 → NO_MATCH; × version unknown → INCONCLUSIVE;
product mismatch + version match → NO_MATCH with `version` never
matched; constraints without a product anchor → unknown.

**Comparator change (minimal, additive):** `compare_version` was
left byte-identical (both existing callers preserved). Added one
pure function `evaluate_version_constraint(detected_version, *,
constraint_kind, version, upper_version, lower_inclusive,
upper_inclusive) -> ConstraintEvaluation(MATCH|MISMATCH|
INCONCLUSIVE, reason)` reusing `normalize_version` as the sole
parsing authority. This was objectively required: the existing
comparator cannot represent single-sided bounds, inclusive flags,
or FIXED, while the task's normative examples (e.g. `<= 4.2.1` ×
4.1.0 → MATCH) demand them; the alternative — returning
INCONCLUSIVE for every bounded pattern — would contradict the
spec. Regression: all existing correlator callers untouched; 15
new unit tests cover every kind, both inclusivities at the
boundary, FIXED both directions, UNKNOWN, missing/malformed
inputs on both sides, and unknown kinds.

## 7. Attack Surface Matching

Supported fields (exact deterministic equality only):
`path` (surface path vs endpoint+url paths), `method` (vs
param-detail methods for the same path, or all observed methods
when the entry has no path), `parameter` (vs endpoint params,
param-detail names, url params), `parameter_location` (vs
param-detail locations for the same parameter name, or any
location when the entry names none). No fetching, no probing, no
DNS; target URLs are data. Proven: path/method/parameter/
location match and mismatch, unrepresentable (`cookie`)
location → unknown, endpoint mismatch with product anchor →
PARTIAL_MATCH, multi-endpoint selection, url-row contribution.
Attack patterns carry no surface structure, so only
`technology_context` is matchable there; technique relevance caps
at PARTIAL_MATCH by construction.

## 8. Result Semantics

Proof that MATCH ≠ VULNERABLE: the contract contains no verdict
field (unknown-field rejection over `verdict`, `confirmed`,
`target_affected`, `scope_allowed`, `execution_allowed`,
`command`, `match_score`); `match_kind` rejects `CONFIRMED`,
`VERIFIED`, `NOT_VULNERABLE`, `EXPLOITED`; every MATCH
explanation ends with the literal marker "relevance only, not a
vulnerability verdict"; serialized MATCH payloads are asserted
free of `CONFIRMED/VERIFIED/NOT_VULNERABLE/EXPLOITED/
target_affected`. `MATCH` for a product-only pattern means "the
only deterministic criterion (product identity) matched the
observed inventory" — the report documents that current
projector output makes this the common case until CVE/version/
endpoint claim fields exist.

## 9. Determinism

Same inputs → structurally identical outputs (tested by
equality, not just kind): sorted criteria lists (schema-enforced
sorted+unique), sorted explanation details, canonical-JSON
`match_id` with no timestamps/randomness/UUIDs/process state.
Input-order independence: shuffled technologies, shuffled
endpoints, shuffled pattern lists, and reversed subdomain
projections all produce identical results. Duplicates (repeated
technologies, repeated observations, repeated patterns) converge
without changing kind. Batch output is sorted by `pattern_id`.

## 10. Security Boundary

Proven by construction and tests:

- **No LLM** — AST import scan of the matcher finds no
  provider/model/completion/embedding import; priority,
  interpretation, severity, and CVSS inputs are proven ignored
  (identical kind+score with hostile "CRITICAL, test
  immediately" metadata) per B4.
- **No network** — no requests/httpx/urllib/socket import; full
  matching (vulnerability + attack, with endpoints/urls) runs
  with `socket.socket` disabled; hostile and metadata-IP URLs
  are parsed as data, never fetched.
- **No subprocess** — no subprocess/os/sys import.
- **No DB writes** — no database/mongo/store import; matcher
  takes objects, never ids; write-trap unnecessary (nothing to
  trap — there is no write path).
- **No scope authority** — scope policy never imported; no
  `scope_allowed`/`execution_allowed`/`authorized` key exists;
  scope strings travel only inside the input TI.
- **No execution authority** — no command/shell/callback
  semantics; adversarial product names and command strings are
  inert data (non-matching → NO_MATCH).
- **No finding/verdict authority** — see §8; no `evidence`,
  `finding_status`, or status-escalation path.
- Malformed input fails closed: wrong types → `TypeError`,
  empty target identity → `TargetMatchError`, hostile version
  strings → INCONCLUSIVE, newline-carrying labels rejected at
  the schema/projector boundary before the matcher ever sees
  them.

## 11. Cross-Program Isolation

Isolation is structural: the matcher performs no lookup and
attaches rows by nothing — it copies the input TI's canonical
`program_name`/`subdomain`/`target_key` into the result. Same
pattern × different program/subdomain TIs yields results bound
to distinct `target_key`s and distinct `match_id`s (tested both
directions); no hostname similarity or registrable-domain
guessing exists anywhere in the path. Snapshot changes move
`match_id` (tested), so stale matches cannot be mistaken for
fresh statements.

## 12. Files Changed

| File | Action | Why |
|---|---|---|
| `ai/schemas/target_match.py` | CREATED (~250 lines) | Match contract: `TargetPatternMatch`, `MatchKind`, closed criteria, deterministic `match_id_for`/`deterministic_score_for`, `MATCHER_VERSION` |
| `ai/researcher/target_matcher.py` | CREATED (~560 lines) | Pure matcher: product/version/surface/context evaluators, kind decision table, deterministic explanations, batch API |
| `ai/test_target_matcher.py` | CREATED (96 tests) | Full §13 matrix |
| `ai/correlator/version.py` | ADDITIVE ONLY (+~190 lines) | New pure `evaluate_version_constraint` + `ConstraintEvaluation`; `compare_version` and all existing code untouched |
| `agent-reports/target-matcher-implementation.md` | CREATED | This report |

No existing file was modified except the additive version.py
extension. No Git operation was performed (per the absolute Git
rule; not even status/diff commands were run).

## 13. Tests

Exact commands and results (from `/opt/watch`):

```
python3 -m unittest ai.test_target_matcher
  Ran 96 tests — OK
python3 -m unittest ai.test_research_pattern ai.test_hypothesis_testplan \
  ai.test_pattern_projector ai.test_pattern_store ai.test_target_intelligence
  Ran 247 tests — OK
python3 -m unittest ai.test_ingestion_schema ai.test_ingestion_grounding \
  ai.test_knowledge_store ai.test_knowledge_ingestion
  Ran 132 tests — OK
python3 -m unittest ai.test_openrouter ai.test_xss_researcher \
  ai.test_xss_llm_researcher
  Ran 74 tests — OK
python3 -m compileall -q ai   (clean)
```

The 96 new tests map to the required matrix: contract 1–6,
product 7–11 (+ generic/substring guards), version 12–22 unit
(15 evaluator cases) + matcher wiring (exact/bounds/range/
inclusivity/FIXED/UNKNOWN/unknown-target/malformed/
product-mismatch/unanchored), surface 23–28, semantics 29–34
(incl. MATCH≠CONFIRMED proof and B4 priority-ignored proof),
security 35–43 (AST import scans, network-disabled run,
authority-field absence, hostile URL/command inertness),
isolation 44–46 (+ snapshot-identity test), determinism 47–49
(+ batch-order and pattern-independence tests), integration
50–52 (GroundedClaim → project → PatternStore → match;
TI projection → match; full-criteria MATCH). Correlator
`test_correlation/candidate/assessment/shortlist` modules are
manual live scripts (MongoDB + network; 0 unittest cases) and
were not runnable here; the version.py change is purely additive
with `compare_version` untouched, so they are unaffected by
construction.

## 14. Compatibility

Purely additive except the version.py append: the matcher
consumes Phase 2A factories/identity and Phase 3A projection
output as-is; `match_technology` and the scope policy are
unmodified and the latter unimported. Regression evidence: 247
Phase 1/2A/2B/2C/3A tests, 132 ingestion/grounding/knowledge
tests, and 74 provider/XSS tests pass unmodified; `compileall`
is clean. The pre-existing `crawl/watch_param_discovery.py`
working-tree state was not touched or evaluated (out of scope).

## 15. Limitations

1. Current projector output is product-anchored only (no CVE
   IDs, versions, endpoints — Phase 2B gap), so most live
   matches today are product-relevance MATCHes; version/surface
   criteria engage only for hand-built or future
   identifier-anchored patterns.
2. `FIXED` with an older observed version is INCONCLUSIVE by
   design (affected lower bound unstated) — a deliberate
   under-match, never a guess.
3. Surface absence in inventory yields PARTIAL_MATCH (not
   NO_MATCH) when a product anchor matched, because recon
   crawls may be incomplete; consumers must re-match against
   fresh snapshots (snapshot_hash binding) rather than treat
   PARTIAL as stable.
4. Attack patterns cap at PARTIAL_MATCH (technique has no
   target-side representation); full MATCH is reachable only
   for vulnerability patterns whose every present criterion
   matched.
5. Parameter comparison is exact (case-sensitive); path
   comparison is exact string equality between pattern paths and
   write-time-normalized inventory paths.
6. The score is a criteria proportion, not a ranking signal for
   scheduling/execution (B4); any scheduler must re-derive
   priority from its own deterministic inputs.

## 16. Recommended Next Step

The smallest safe next phase is the **Hypothesis Engine
(contract-level, no execution)**: consume `TargetPatternMatch`
records (MATCH/PARTIAL_MATCH) plus their bound pattern and TI
snapshot into Phase 1 `Hypothesis` objects via
`Hypothesis.pattern_id` (`vp-`/`ap-`) with content-hash
idempotency keys — deterministic record binding first, LLM
proposal layer only after, with the adversarial review's
transition allowlist and target re-resolution rules as code
invariants. Do not build test planning, execution, Nuclei/XSS
runtimes, or scheduling until hypothesis records exist with
fixture tests proving they carry no verdict, scope, or
execution authority.

---

*Phase 3B ends at VulnerabilityPattern / AttackPattern +
TargetIntelligence → Deterministic Match → RELEVANCE ONLY. No
Git operations were performed; the index is untouched. Report
created at `/opt/watch/agent-reports/target-matcher-implementation.md`.*
