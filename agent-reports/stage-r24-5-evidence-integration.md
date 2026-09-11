# Stage R24.5 — Evidence Integration

**Status: PASS.**

Integrated ranked + deduplicated R24 `DiscoveredSource` records into a grounded,
deterministic, additive `DiscoveryBlock`. R23 behavior is unchanged, R24.1–R24.4
are untouched, and `WATCH_RESEARCH_DISCOVERY` remains unset/off. No scheduler,
systemd, timer, database, target, LLM, or 5B–5J surface was modified.

---

## 1. Exact files changed

| File | Change |
|---|---|
| `ai/research_agent/evidence.py` | **New.** Lifecycle engine, `DiscoveryEvidence`/`DiscoveryInference`/`DiscoverySourceRecord`/`DiscoveryBlock` models, pure `build_evidence`, `integrate_discovery`, `attach_discovery_block`. |
| `ai/research_agent/storage.py` | **Additive only** (+65 lines, 0 deletions): `discovery_path`, `store_discovery`, `load_discovery` and their `__all__` entries. No existing function altered. |
| `tests/test_research_agent_r24_5.py` | **New.** 38 focused R24.5 tests. |
| `agent-reports/stage-r24-5-evidence-integration.md` | This report. |

`git diff --check` → clean (rc=0). `storage.py` diff is `1 file changed, 65
insertions(+)`.

---

## 2. Additive schema changes

New Pydantic models in `evidence.py` (R23 models are **not** touched):

- `DiscoveryEvidence` — one grounded claim: `evidence_id`, `source_id`,
  `source_url`, `canonical_url`, `final_url`, `content_hash`,
  `source_category`, `trust_tier`, `source_quality`, `lifecycle` (forced
  `EVIDENCE`), `claim`, `quote`, `confidence`, `extraction_method`,
  `discovery_provider/query/template_id`, `redirect_chain`, `aliases`,
  `production_finding=False`.
- `DiscoveryInference` — `inference_id`, `statement`, `basis`, `source_ids`,
  `evidence_ids`, `model_generated`, `production_finding=False`.
- `DiscoverySourceRecord` — deterministic per-source lifecycle + provenance
  summary (canonical URL, final URL, status, category, tier, quality, hash,
  provider/query/template, redirect chain, aliases, `eligible`,
  `ineligible_reason`, `evidence_id`).
- `DiscoveryBlock` — the additive block: `rule_version="r24-1"`,
  `discovery_enabled`, `plan_id`, `result_id`, counts
  (`discovered_sources`, `fetched_sources`, `relevant_sources`,
  `evidence_count`, `unknown_count`, `inference_count`, `ineligible_count`),
  `providers`, `evidence[]`, `sources[]`, `unknowns[]`, `inferences[]`,
  `production_finding=False`.

The block is stored/presented **separately** (see §9), so the R23
`ResearchAgentResult` schema and all existing R23 result files are byte-for-byte
unchanged. `attach_discovery_block(result, block)` returns a new combined dict
for downstream consumers without mutating the R23 result.

---

## 3. Lifecycle implementation

Deterministic, validated transitions (`evidence.py`):

```
DISCOVERED_SOURCE → FETCHED_SOURCE → RELEVANT_SOURCE → EVIDENCE
any non-terminal  → UNKNOWN | INFERENCE      (terminal)
```

- `LIFECYCLE_ORDER` fixes the forward ordering;
  `TERMINAL_LIFECYCLES = {UNKNOWN, INFERENCE}`.
- `is_valid_lifecycle_transition` allows identity, one-step forward moves, and
  any non-terminal → terminal move; rejects backward moves, skipped-forward
  moves, and any out-of-terminal move.
- `transition_lifecycle` raises `LifecycleError` on illegal moves;
  `with_lifecycle` returns a validated copy.
- `next_lifecycle_for(source, content_present, eligible)` is a pure derivation:
  no hash/no content → `DISCOVERED_SOURCE`; hash or content only →
  `FETCHED_SOURCE`; content + hash but ineligible → `RELEVANT_SOURCE`; content +
  hash + eligible → `EVIDENCE`.
- Lifecycle never implies target validation; the closed `Lifecycle` enum has no
  `VULNERABLE`/`VERIFIED`/`EXPLOITED`/`FINDING` value.

---

## 4. Evidence eligibility

`evidence.py` **reuses** `ai.research_agent.ranking.is_evidence_eligible` — the
predicate is not re-implemented. Evidence requires a trusted `content_hash`,
`source_quality >= 0.45` (`EVIDENCE_FLOOR`), and tier `TRUSTED`/`SEMI_TRUSTED`.
A `DISCOVERY_ONLY` `detection_rule` qualifies only with an explicit
authoritative advisory reference (supplied via
`advisory_reference_by_source_id`, or detected from the source text by the
R24.4 predicate). `GENERIC` can never become evidence alone. The predicate is
pure and creates/persists nothing.

---

## 5. Grounding guarantees

`build_evidence`/`integrate_discovery` are pure grounded transformations:

- evidence text comes **only** from already-materialized content passed in via
  `content_by_source_id`; nothing is fetched, and no provider/LLM is called;
- with an explicit `claim`, the normalized claim must appear verbatim in the
  normalized content, else no evidence is produced;
- without a claim, a deterministic bounded excerpt (`MAX_EXCERPT_CHARS=500`) of
  the normalized content is used and `extraction_method` is recorded;
- a source with no trusted `content_hash` or no supplied content cannot become
  evidence — it is recorded with a deterministic `ineligible_reason` and, when
  relevant, an `unknowns[]` entry;
- the evidence `content_hash` is copied from the source (never recomputed from a
  URL) and the `claim`/`quote` are substrings of the supplied content. No
  fabricated URLs, hashes, or claims.

---

## 6. Provenance preservation

Every `DiscoveryEvidence` carries, copied from its source: `source_id`,
`source_url`, `canonical_url`, `final_url`, `content_hash`, category, tier,
quality, provider, query, template id, extraction method, `redirect_chain`,
`aliases`. Every evidence object references exactly one known source; an
evidence list entry is only created for a source present in the integrated set.

Redirect provenance (R24.3 fields `discovered_url` / `final_url` /
`redirect_chain`) is preserved on both the evidence and the source record, and
is **not** revalidated, re-resolved, or re-fetched here.

---

## 7. Ranking / dedup integration

`integrate_discovery` consumes the R24.4 output directly:

- no second ranking or canonicalization algorithm is implemented;
- duplicate sources (same `source_id` or canonical URL) are skipped so a
  duplicate cannot create duplicate evidence; `seen_evidence` also guards
  evidence ids;
- only the canonical deduplicated source becomes evidence — aliases stay
  attached to the canonical record/evidence;
- a full-pipeline test (`rank_sources` → `dedup_discovered_sources` →
  `integrate_discovery`) collapses URL/content duplicates to one source and one
  evidence item, with `providers` aggregated.

---

## 8. Storage behavior

Additive, R23-compatible, atomic, idempotent:

- `discovery_path(plan_id, rule_version, base)` → `<plan>.<rule>.discovery.json`;
- `store_discovery(block, base=..., overwrite=False)` writes atomically
  (temp file + `os.replace`) and is idempotent (an existing block is left
  untouched unless `overwrite=True`);
- `load_discovery(plan_id, rule_version, base)` returns the block dict or
  `None` when absent/unreadable.

No new database dependency, no findings, no alerts. The existing R23
`store_result`/`load_result`/`write_report`/`store_run` paths are unchanged
(diff is +65/−0).

---

## 9. Explicit confirmation — ZERO NETWORK

R24.5 performs **no** HTTP, **no** DNS, **no** socket, **no** provider call,
**no** LLM call, **no** re-fetch, and **no** URL-derived hashing. Evidence is a
pure function of already-materialized source records plus caller-supplied
content. Verified by (a) AST import-boundary scan and (b) a runtime test that
patches `socket.socket` to raise during integration.

## 10. R23 compatibility

- No R23 model or function was changed. Old R23 results
  (`ai_data/research/agent/r22-*.r23-1.json`) still load via `storage.load_result`
  and `ResearchAgentResult.model_validate` exactly as before, with no
  `discovery` key injected.
- `attach_discovery_block` never mutates the input and the combined dict keeps
  all R23 fields.
- A new R23 result written through `store_result` contains no `discovery` key
  (tested).

## 11. R24.1 / R24.2 / R24.3 / R24.4 compatibility

No R24.1–R24.4 file was edited; R24.5 imports and reuses their vocabulary and
helpers (`DiscoveredSource`, `Lifecycle`, `SourceCategory`, `TrustTier`,
`canonical_url`, `is_evidence_eligible`, `EVIDENCE_FLOOR`, `make_discovered_source`,
`netguard`). All four suites still pass unchanged.

## 12. No scheduler/systemd changes

`watch-research.service` / `watch-research.timer` untouched; no scheduler
default changed; `WATCH_RESEARCH_DISCOVERY` still unset (off); the R23 scheduler
path is byte-for-byte unchanged.

## 13. No target interaction / no 5B–5J

No target/program/asset contacted. No Nuclei, PoC, browser, verifier, finding,
alert, execution, or 5B–5J path imported or invoked. `production_finding`
remains `False` on every model.

---

## 14. Tests (exact results)

Per-suite:

| Suite | Result |
|---|---|
| `tests.test_research_agent` | **92 OK** |
| `tests.test_research_agent_r24_1` | **43 OK** |
| `tests.test_research_agent_r24_2` | **50 OK** |
| `tests.test_research_agent_r24_3` | **80 OK** |
| `tests.test_research_agent_r24_4` | **71 OK** |
| `tests.test_research_agent_r24_5` | **38 OK** |

Combined regression:

```
python3 -m unittest \
  tests.test_research_agent \
  tests.test_research_agent_r24_1 \
  tests.test_research_agent_r24_2 \
  tests.test_research_agent_r24_3 \
  tests.test_research_agent_r24_4 \
  tests.test_research_agent_r24_5
→ Ran 374 tests ... OK
```

`git diff --check` → clean (rc=0).

New R24.5 coverage: schema (old R23 load, block round-trip, optional block,
`production_finding=False`, forbidden states), lifecycle (happy path, terminal
states, invalid transitions, ordering, deterministic `with_lifecycle`,
`next_lifecycle_for`), eligibility (trusted/semi/generic/below-floor/detection
rule ± advisory), evidence (provenance preservation, grounded claim, no
fabrication, deterministic ids), grounding (missing content → UNKNOWN, no
network), dedup integration (canonical-only evidence, aliases, no duplicate
evidence, full pipeline), inferences (kept when grounded, dropped when unknown),
safety (field/import/text scans), storage (store/load/idempotent, R23 result
untouched), compatibility.

---

## 15. Known limitations deferred to R24.6+

- **Claim extraction is structural, not semantic.** R24.5 grounds claims as
  verbatim/bounded content excerpts; richer claim extraction/summarization is
  R24.6 (LLM research loop), which must remain attribution-checked.
- **No automatic inference generation.** `DiscoveryInference` objects are
  caller-supplied and validated against known sources/evidence; the bounded
  multi-round loop that derives them is R24.6.
- **Integration is not yet wired into `ResearchAgent.run_plan`.** R24.5 provides
  the pure contract + additive storage; R24.6/R24.8 will consume it under the
  (still off) discovery flag.
- **`advisory_reference` provenance** is caller/text-derived; a persisted
  advisory linkage should be threaded from provider provenance in R24.6.
- **Confidence** is a preserved/defaulted field (default `LOW`); R24.5 does not
  compute confidence from source tier to avoid fabricating a strength signal.

## 16. Next-stage recommendation

Proceed to **R24.6 — LLM Research Loop** (bounded, 2 rounds), consuming the
`DiscoveryBlock`/`is_evidence_eligible` contract: discover → rank → dedup →
integrate → analyze → identify gaps → optionally one bounded second round. Keep
`WATCH_RESEARCH_DISCOVERY` off until R24.7/R24.8, and keep all LLM output
attribution-checked against supplied, hash-verified evidence.

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R24.5
- Role: Evidence Integration
