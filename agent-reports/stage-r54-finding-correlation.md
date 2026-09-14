# R54 Finding Correlation Intelligence

| | |
|---|---|
| Date | 2026-09-14 |
| Stage | R54 |
| Scope | Deterministic correlation of R53 research finding candidates |
| Follows | R38 / R39 / R40 / R41 / R42 / R43 / R44 / R45 / R46 / R47 / R48 / R49 / R50 / R51 / R52 / R53 |
| Commit message | `feat(correlation): add r54 finding correlation intelligence` |
| Push status | **Not pushed** (local commit only) |
| Focused tests | 101 passed |
| Full suite | 5102 passed, 40 failed (unchanged baseline), 376 subtests |
| Real provider calls during testing | **None** (R54 is offline by construction) |

## Summary

R54 consumes structured R53 Finding Intelligence output and classifies
deterministic relationships between research finding candidates:

- `DUPLICATE`, `RELATED`, `INDEPENDENT`, `CONFLICTING`, `UNKNOWN` (the
  existing R43 correlation vocabulary, reused by value);
- stable finding ids are always the correlation identity — list position is
  never used;
- every original finding, evidence reference, hypothesis reference,
  provenance reference, governance reference and limitation is preserved;
  nothing is merged, rewritten or deleted;
- correlation never changes finding confidence (forced
  `confidence_effect = NONE` everywhere), never confirms a vulnerability and
  never produces a finding;
- the result is fully deterministic: identical findings produce byte-identical
  output, stable relationship/cluster/content ids, and no timestamps,
  UUIDs, pids or randomness.

## Architecture

```
ai/schemas/finding_correlation.py          r54-1  relationship + signals + references
ai/schemas/finding_correlation_result.py   r54-2  clusters + correlation result
ai/knowledge/finding_correlation_rules.py  r54-3  deterministic rules engine
ai/knowledge/finding_correlation.py        r54-4  builder + public APIs
```

Flow:

```
R52 orchestration result
  -> R53 finding intelligence (existing structured API)
  -> R54 normalize findings (R53 sanitizer; stable finding ids)
  -> bounded finding references + comparison facts
  -> pairwise relationship classification (R54.3 rules)
  -> deterministic clusters (R43 clustering semantics)
  -> provenance / governance summary / limitations
  -> finding correlation result (r54-2)
```

Reused upstream contracts: R53 `sanitize_finding`, `FINDING_RESULT_RULE_VERSION`,
finding/assessment/evidence state vocabularies and `NOT_CONFIRMED`; R43
`CORRELATION_TYPES`, conflict-type vocabulary, `EVIDENCE_BANDS` and
confidence bands, `GOVERNANCE_*` summary codes. No R38–R53 file was modified.

## Correlation Contract

`FindingRelationshipPlan` (r54-1): `relationship_id` (`fcr-<16 hex>`),
`relationship_type`, `source_finding_id`, `target_finding_id`,
`source_agent_id`, `target_agent_id`, `signals`, `score`,
`shared_context_values`, `shared_hypothesis_types`,
`shared_hypothesis_signals`, `shared_evidence_requirements`,
`shared_component_name`, `shared_endpoint_reference`, `conflict_details`,
`confidence_effect` (forced `NONE`), `limitations`, `research_only`.

`FindingCorrelationClusterPlan` (r54-2): `cluster_id` (`fcg-<16 hex>`),
`relationship_type`, `member_finding_ids`, `cluster_size`, `signals`,
shared context/hypothesis/evidence summaries, `confidence_effect` (forced
`NONE`), `limitations`, `research_only`.

`FindingCorrelationResultPlan` (r54-2): `rule_version`,
`correlation_rule_version`, `relationship_rule_version`, `correlation_id`
(`fci-<16 hex>`), `status`, `finding_references`, `relationships`,
`clusters`, `skipped_findings`, `errors`, `provenance`,
`governance_summary`, `limitations`, `confidence_effect` (forced `NONE`),
`research_only`, `deterministic`.

## Correlation Vocabulary

- Relationship types: R43's closed `CORRELATION_TYPES` — `DUPLICATE`,
  `RELATED`, `INDEPENDENT`, `CONFLICTING`, `UNKNOWN`. R54 defines no
  incompatible value.
- Signals (closed, 21 codes): identical finding id, same category, same
  agent, same orchestration (informational, weight 0), shared hypothesis
  fingerprint/type/signal, shared evidence requirement, shared context
  value, shared component, shared endpoint, category family, R43 related
  group, R43 material conflict, context conflict, evidence-state
  conflict/divergence, confidence conflict/divergence, insufficient
  structure, no shared signal.
- Scores are bounded (0–100) and derived only from documented per-signal
  weights; classification uses the closed rule set, never a threshold.

## Duplicate Detection

Deterministic duplicate signals (classification precedence:
`CONFLICTING` > `DUPLICATE` > `RELATED` > `UNKNOWN` > `INDEPENDENT`):

- identical stable `finding_id`;
- same canonical category and same specialist agent id;
- an explicit R43 `DUPLICATE` correlation group;
- shared non-empty hypothesis fingerprints with same category or shared
  component/endpoint;
- same category with identical non-empty hypothesis-type sets, identical
  non-empty evidence-requirement sets and identical context signatures.

Duplicates are never deleted: both findings remain in
`finding_references`, the relationship is explicit (`DUPLICATE`) and the
cluster preserves all member finding ids.

## Related Detection

Related relationships are derived from structured overlap only: shared
component, shared endpoint reference, shared non-generic context values,
shared hypothesis types, shared hypothesis signals, shared evidence
requirements or an explicit R43 `RELATED` group. The fixed
authorization/authentication/API family (`IDOR`, `JWT`, `OAUTH`, `RECON`)
is a supporting signal only and never creates a relationship by itself.
Generic signals (`input_location`/`context_confidence` context keys,
`INPUT_*` hypothesis signals, `*_UNKNOWN` markers, generic technology
values) are filtered and cannot force relatedness. Findings from the same
orchestration run are not correlated unless a structured signal exists.

## Conflict Detection

Material conflicts:

- contradictory shared non-generic context key values (direct structured
  contradiction, e.g. `issuer_validation` `PRESENT` vs `ABSENT`);
- explicit R43 material conflicts: `CONTEXT_CONFLICT` and `SAFETY_CONFLICT`
  always; `CONFIDENCE_CONFLICT`, `HYPOTHESIS_CONFLICT` and
  `EVIDENCE_STATE_CONFLICT` only with an `UNRESOLVED` R43 resolution;
- evidence-state distance ≥ 2 with scope overlap (same category or shared
  evidence/context).

Conservative constraints: confidence disagreement alone is never a
conflict; R43 `RECONCILABLE`/`UNKNOWN` confidence and provenance/governance
conflicts are divergence signals only; no conflict is manufactured. All
underlying conflict records are preserved in `conflict_details`
(type, resolution state, conflicting fields).

## Independent / Unknown

Findings with no shared signal, no conflict and comparable structure are
`INDEPENDENT`. When either side lacks comparable structure (no non-generic
context, hypothesis types, evidence requirements or component/endpoint),
the pair is `UNKNOWN` — R54 never guesses. Unrelated findings are never
artificially correlated.

## Clustering

Clusters use R43 clustering semantics: `DUPLICATE` and `CONFLICTING` pairs
unite always; `RELATED` pairs merge only while both clusters are
singletons (preventing generic-signal chaining); `INDEPENDENT`/`UNKNOWN`
pairs never cluster. Every cluster carries a stable content id, its single
relationship type, sorted member finding ids, union signals, shared
summaries, `confidence_effect = NONE` and limitations. Original findings
remain independently addressable; clusters never collapse them.
Cluster/relationship ordering is canonical (precedence, then ids).

## Evidence Preservation

R54 never rewrites or discards evidence: `finding_references` preserve
`evidence_state`, `evidence_completeness`, `evidence_origin`,
`evidence_requirement_count` and the finding's own evidence requirements;
relationships and clusters record shared evidence requirements explicitly
rather than duplicating or mutating evidence. `EVIDENCE_INCOMPLETE` is
disclosed when any correlated finding's evidence completeness is not
`COMPLETE`.

## Hypothesis Preservation

`finding_references` preserve `hypothesis_count`; comparison facts use the
original hypothesis types, supporting signals and fingerprints without
inventing, reclassifying or merging hypotheses. Shared hypothesis signals
are reported as relationship signals, never altered upstream.

## Confidence Rules

Correlation never increases confidence: the relationship, cluster and
container all force `confidence_effect = NONE`, every result carries
`CONFIDENCE_NOT_UPGRADED`, and inputs are read-only (tests assert exact
upstream confidence values before and after). Agreement between findings is
represented only as a correlation signal; conflicting evidence is surfaced
as `CONFLICTED`/divergence and constrains interpretation. The R53
`confirmation_state = NOT_CONFIRMED` invariant is re-enforced at the schema
and builder layers.

## Provenance

Per finding: stable id, category, specialist name, agent id, state,
confidence, evidence summary, component/endpoint, orchestration id,
governance state and finding rule version. Container provenance aggregates
`finding_rule_version`, `orchestration_ids`, finding/relationship/cluster
counts, source categories and source agent ids. Nothing is fabricated;
unavailable provenance is disclosed via `PROVENANCE_UNAVAILABLE`.

## Governance

`governance_summary` preserves per-finding governance reference states and
aggregates them with the R43 summary vocabulary
(`CONSISTENT_REFERENCED`/`MIXED`/`UNKNOWN`), including ready/not-ready
finding ids. Unknown governance is disclosed via `GOVERNANCE_UNKNOWN`; R54
never invents a governance record and never claims governed execution.

## Limitations

Closed vocabulary: `NO_EXECUTION_PERFORMED`, `NO_NETWORK_REQUESTS`,
`NO_VULNERABILITY_CONFIRMATION`, `NOT_CONFIRMED`, `RESEARCH_ONLY`,
`CONFIDENCE_NOT_UPGRADED`, `INSUFFICIENT_CONTEXT`,
`CORRELATION_UNAVAILABLE`, `CONFLICT_PRESENT`, `DUPLICATE_RELATIONSHIP`,
`SHARED_CONTEXT`, `EVIDENCE_INCOMPLETE`, `PROVENANCE_UNAVAILABLE`,
`GOVERNANCE_UNKNOWN`. Limitations are emitted at relationship, cluster and
container level from actual conditions only.

## R53 Integration

`correlate_finding_intelligence(finding_intelligence)` consumes the R53
result through its structured Python API (normalizing findings through
`sanitize_finding`). `correlate_findings(findings)` accepts standalone R53
findings. Supplying both inputs, a non-mapping/intelligence input, a foreign
rule version or a non-list `findings` value fails closed with
`INVALID_INPUT`. R53 inputs are never mutated. R53 output remains unchanged
and contains no R54 keys.

## R43 Compatibility

R54 reuses R43's correlation vocabulary and conflict semantics without
modifying R43: relationship types are imported from
`ai.schemas.hypothesis_correlation`; conflict types, evidence bands and
confidence bands are imported from the R43 module; clustering mirrors R43's
duplicate/conflicting union and singleton-related merge. R43 test suites
pass unchanged, and static tests assert the imports exist (no redefined
vocabulary).

## Safety Boundary

AST/static tests over all four R54 modules verify: no
`requests`/`httpx`/`urllib`/`socket`/`ssl`/`dns`/`http`/`aiohttp`/`urllib3`/
`pycurl`/`paramiko`, no `subprocess`/`os`/shell, no browser automation, no
`nuclei`/`sqlmap`, no database clients, no `importlib`/`pkgutil`/
`stevedore`, no `__import__`/`eval`/`exec`/`compile`/`open`, no LLM SDKs
(`openai`/`anthropic`/`litellm`/`ollama`), no `ai.providers` import, no
URLs and no forbidden claim markers. R54 does not import specialists, the
R52 orchestrator or the R53 builder. The public API has no
credential/provider parameters; unsafe findings
(`NON_RESEARCH_ONLY`/`UNSAFE_CONFIRMATION`) never reach relationships.

## Determinism

- canonical ordering: finding references sorted by finding id, relationships
  by (precedence, source id, target id), clusters by (precedence, cluster
  id);
- stable content ids (`fcr-`, `fcg-`, `fci-`) derived from structured
  content only;
- no timestamps, UUIDs, pids, nonces, randomness or external state;
- tests assert byte-identical output for repeated runs and for shuffled
  input order.

## Tests

Focused R54 suites (101 tests):

```
tests/test_finding_correlation_rules.py    40 passed
tests/test_finding_correlation.py          44 passed
tests/test_finding_correlation_safety.py   17 passed
R54 total                                 101 passed
```

Coverage includes: every relationship type; duplicate detection and
preservation; cluster formation and R43 singleton-merge semantics; stable
finding ids; deterministic ordering/output/ids; shared component, endpoint,
context, evidence and hypothesis relations; related
authentication/authorization findings; conflicting evidence; contradictory
structured observations; conservative conflict semantics (confidence-only
disagreement is not a conflict); insufficient context; minimal/empty input;
malformed/unsupported/unsafe input; duplicate identity; finding limit;
provenance/governance/limitation/evidence/hypothesis preservation; no
confidence inflation; `NOT_CONFIRMED` invariant; no R52/R53 mutation; R53 →
R54 integration; R43 compatibility; static safety; backend
non-integration.

## Full Suite

```
python -m pytest tests/ -q -p no:cacheprovider
5102 passed, 40 failed, 1 warning, 376 subtests passed in 50.78s
```

Baseline (R53): `5001 passed, 40 failed, 376 subtests`.

- passed growth: `5102 - 5001 = 101` — exactly the 101 new R54 tests;
- failed count unchanged at 40; subtests unchanged at 376;
- the 40 failures are byte-identical to the R53 baseline set (sorted diff)
  and none references R54.

Per-stage regression (all passed):

```
R38 132 | R39 100 | R40 122 | R41 131 | R42 91 | R43 102 | R44 68
R45 90  | R46 97  | R47 136 | R48 150 | R49 156 | R50 125 | R51 111
R52 101 | R53 125
Backend (tests/test_asset_cve_matching.py)  79 passed, 13 subtests
AI safety (knowledge_store/xss_researcher/
  xss_llm_researcher/openrouter)            96 passed
```

## Changed Files

Added (8 — 4 implementation modules + 3 test files + this report):

```
ai/schemas/finding_correlation.py
ai/schemas/finding_correlation_result.py
ai/knowledge/finding_correlation_rules.py
ai/knowledge/finding_correlation.py
tests/test_finding_correlation_rules.py
tests/test_finding_correlation.py
tests/test_finding_correlation_safety.py
agent-reports/stage-r54-finding-correlation.md
```

Modified: **none**. No existing R38–R53 file was modified. No backend,
crawl, ns, database, Docker, systemd, deployment, scheduler or VPS file was
touched. The pre-existing worktree items (` D utils.zip`, `?? watch.zip`,
`?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`) remain untouched and
outside the commit. No network/execution capability was introduced.

## Git Commit

Commit message: `feat(correlation): add r54 finding correlation
intelligence`. Parent: `a7e942a` (R53). Exactly one local commit was
created; nothing was pushed and nothing was amended or squashed. The exact
commit hash is reported in the final task response (a commit cannot embed
its own hash; this report is part of that single R54 commit).

## Verification

- `git diff --check` clean; staged diff check clean.
- `git status --short` shows only new untracked R54 files plus the
  pre-existing unrelated items.
- `git log --oneline <parent>..HEAD` shows exactly one R54 commit.
- No existing tracked file modified.
- R54 output key set is exact and contains no confirmed/execution claims.
- No secrets, credentials or bearer tokens in R54 source.

## Known Pre-existing Failures

The full suite retains exactly the same 40 pre-existing failures as the
R45–R53 baselines (money-score / economics corpus drift, dashboard render,
product API, research sessions/outcomes/UI, router lookup). They are
unrelated to R54 and were not modified or fixed.
