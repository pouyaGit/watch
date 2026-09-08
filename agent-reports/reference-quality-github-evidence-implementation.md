# Implementation: Reference Quality GitHub Evidence Retention

Status: ONE focused implementation stage of the approved design in
`agent-reports/reference-quality-github-evidence-design.md` (approach
D-hybrid with a frozen gate). No redesign. No LLM calls, network
requests, Nuclei runs, Mongo access, live execution, or git operations
were performed. `ai/test_real_research.py` (live Mongo/network script)
and `ai/test_researcher.py` (stale manual script) were deliberately not
executed.

## 1. Summary

Directly-discovered GitHub technical evidence (`/blob/`, `/commit/`,
`/issues/`, `/pull/`) whose fetched page contains no CVE identifier is
now retained as one bounded verbatim source slice instead of being
emitted empty and dropped by Quality Gate Rule 4. Repository roots and
boilerplate still yield `[]` and are still rejected; foreign-CVE-only
content is still rejected by the unchanged Rule 3. The gate file is
untouched, schemas and telemetry are untouched, and all pre-existing
quality/parity/cache suites pass unmodified (zero assertion rewrites).

## 2. Files changed

| File | Change |
| --- | --- |
| `ai/collectors/reference_ranker.py` | Added `TECHNICAL_GITHUB_SOURCE_TYPES`, `TECHNICAL_GITHUB_PATH_SEGMENTS`, `CVE_CORRELATED_DISCOVERY_TAGS` class constants; added private `_technical_github_fallback(...)`; narrative branch calls it ONLY when `_narrative_context` returns `[]`; class docstring documents the fallback + verbatim guarantee. |
| `ai/researcher/research_context.py` | `build_research_contexts` forwards ephemeral `discovery_tags`/`discovery_query` onto the ranker input object; docstring added. Emitted dict shape unchanged (keys stripped). |
| `ai/collectors/discovery_fetch.py` | `fetch_discovered_sources` adds `discovery_tags=list(source.tags)` + `discovery_query=source.query` to each document dict. Covers `research_cli`, `batch_v3`, `retry_v3` (all consume this helper). |
| `ai/researcher/cve_batch.py` | Inline `discovered_documents` loop in `_make_cached_research_fn` adds the same two keys (this site does not use the helper). |
| `ai/test_reference_ranker_technical_fallback.py` | NEW: 28 offline deterministic tests (covers spec A–T). |
| Explicitly UNCHANGED | `ai/researcher/reference_quality.py` (never edited), `ai/schemas/*`, telemetry histograms, `ai/collectors/discovery.py`, `ai/collectors/reference.py`, `ai/researcher/reference_cache.py`, `ai/research_cli.py` (covered via helper, no edit needed), `ai/researcher/batch_v3.py`, `ai/researcher/retry_v3.py` (covered via helper, no edit needed). |

## 3. Exact behavior implemented

`ReferenceRanker.build`, narrative branch, previously ended with
`contexts = _narrative_context(...)` (possibly `[]`) → `ReferenceContext(...,
exact_record=None, context_chunks=[])`. Now, ONLY when that result is
empty, `_technical_github_fallback` runs (full predicate in Section 5).
On success it returns exactly one chunk; `exact_record` remains `None`
(the call site does not touch it). When narrative extraction already
succeeded, behavior is byte-identical to before (fallback never runs).

Content derivation on predicate pass: existing `_fallback_context(text,
keywords)` first (keyword-anchored window, preserving vendor-tolerance
behavior); if that yields `[]` (pure code with no keyword), exactly one
head slice `normalize(text)[:FALLBACK_CONTEXT_SIZE]` (5000, reused
constant; at most one chunk per `MAX_CONTEXT_CHUNKS`). Whitespace-only
text yields `[]`. The slice is source text only — no CVE ids, severity,
exploit/remediation claims, prefixes, or trust markers are added
(pinned by test R).

## 4. Provenance flow

```
DiscoveredSource.tags/query
  → discovered_documents{discovery_tags, discovery_query}   # discovery_fetch.py + cve_batch.py
  → SimpleDocument.discovery_tags/discovery_query           # research_context.py (getattr-safe)
  → ReferenceRanker._technical_github_fallback              # consumed
  → contexts_raw dicts WITHOUT those keys                   # stripped (output shape frozen)
  → gate → ReferenceContext (no provenance fields)          # schemas frozen
```

- Distinct names (`discovery_tags`/`discovery_query`) never collide with
  `ReferenceDocument.tags` (collector-side, always `[]`) — pinned by a
  dedicated forwarding test.
- Safe default: documents lacking the keys (legacy `researcher/batch.py`,
  hand-built test dicts, cache-test helpers) expose `None` via
  `document.get(...)` / `getattr(...)` → helper returns `[]` → legacy
  outputs exactly (pinned by test I).
- In-memory only: keys never enter `ReferenceContext`, artifacts, or
  telemetry (output-key-set test pins the exact six keys).

## 5. Fallback predicate

Conjunctive, fail-closed, evaluated in this order inside
`_technical_github_fallback`:

1. `source_type.lower() ∈ {github, github_issue, github_research}`.
2. `cve_id` non-blank after strip (else `[]`).
3. URL is a non-blank string; `urlsplit` in try/except; `parts.hostname
   == "github.com"` exactly (`www.github.com`, enterprise/GHE, raw,
   gist, other hosts, ports aside, malformed → `[]`).
4. Lowercased path segments: `len ≥ 4` AND `segments[2] ∈ {blob, commit,
   issues, pull}` (i.e. `/<owner>/<repo>/<kind>/...` with segment
   boundaries — a repo literally named `blob-store` does not match;
   roots `/org/repo`, `/org`, `/search`, `/topics`, `/tree/...`,
   `/security/advisories` do not match).
5. Provenance for THIS CVE (case-insensitive, whitespace-normalized):
   (`nvd_reference ∈ tags ∧ query == cve_id`) OR (`cve_id ⊆ query ∧
   tags ∩ {cve_in_title, cve_in_body, cve_in_repo_name} ≠ ∅`).
   `priority`, `confidence`, `security_research_signal` alone confer
   nothing. Anything else → `[]`.
6. Content: keyword fallback, else bounded head slice, else `[]`.

Only new import: `urllib.parse.urlsplit` (stdlib, function-local, same
family already used by `reference_cache.py` / `reference.py`).

## 6. Security guarantees

- Gate Rules 1/2/3/5 fully authoritative and unmodified; the fallback
  only authorizes *producing* a slice, never *keeping* text — Rule 3
  scans every new slice (foreign-only → dropped, pinned end-to-end by
  test M).
- Empty entries cannot smuggle foreign-CVE text (Rule 3 vacuous on
  empty); new slices are verbatim source bytes with original URL/title
  intact, `exact_record=None`, no authority marking — research stays
  non-authoritative.
- `known_urls` membership and canonical dedup operate on URLs exactly as
  before (no code path touched).
- No LLM trust decision anywhere; all predicates are deterministic
  functions of discovery facts + URL shape + pre-existing emptiness.
- Fail-closed on every ambiguity (unparseable URL, missing/blank
  provenance, query mismatch, empty text, unknown source type).
- Adversarial shaping (`/blob/` path on a hostile repo) still requires
  NVD listing or CVE-tagged search correlation for THIS CVE, and content
  passes verbatim with its URL visible — never elevated to exact record.

## 7. Tests added/changed

- ADDED `ai/test_reference_ranker_technical_fallback.py` (28 tests, all
  offline/socket-blocked): A blob/commit/issues/pull retention; E root
  (×3 shapes) still Rule-4-dropped; F search/topics/profile/tree/
  security-advisories excluded; repo-named-`blob-store` boundary; G five
  non-github hosts denied; H malformed URLs (no raise); non-github
  source types denied; I missing provenance = legacy; J query mismatch;
  K product-only tags denied; L three CVE-tag variants allowed;
  signal-only tags denied; case-insensitive query/tags; M foreign-only
  slice produced upstream but Rule-3-rejected end-to-end; N zero-CVE kept;
  narrative-success path unchanged; O keyword preference; P bound
  enforcement on a 5000×-line body; Q determinism; R seven forbidden
  claim-strings absent; S URL/title/type preserved; T `ReferenceContext`
  conversion; whitespace-only content; provenance forwarded-but-stripped
  (exact six output keys); fetch-layer forwarding incl. tags-namespace
  guard.
- CHANGED existing tests: NONE. Zero assertion rewrites — no existing
  fixture exercises NVD-provenance GitHub technical URLs (they use
  `example.test` URLs or `vendor` types), so all counts are stable.

## 8. Test results

| Suite | Result |
| --- | --- |
| `ai.test_reference_ranker_technical_fallback` (new, 28) | PASS |
| `ai.test_reference_quality_gate` (27) | PASS unmodified |
| `ai.test_reference_quality_decision_boundary` (20) | PASS unmodified |
| `ai.test_batch_reference_quality_parity` (21) | PASS unmodified |
| `ai.test_single_cve_quality_parity` (21) | PASS unmodified |
| `ai.test_reference_cache` (24) | PASS unmodified |
| `ai.test_cve_batch` (15) | PASS unmodified |
| `ai.test_research_cli` (6) | PASS unmodified |
| `ai.test_reference_url_canonicalization` (33) | PASS unmodified |
| `py_compile` on all touched files | OK |

Not run (out of scope by instruction): `ai/test_real_research.py` (live
Mongo/network script, hardcoded credentials — not a unit suite),
`ai/test_researcher.py` (stale manual script calling removed
`research(title=, content=)` signature — pre-existing breakage, verified
it imports none of the touched modules; left untouched per instructions).

## 9. Investigated CVE fixture results

Offline replay with representative fixture content (no fetching; shapes
per the prior investigation):

- CVE-2026-78203: `views.py` blob (CVE-less handler code) → 1 chunk,
  KEPT; fix-commit diff → 1 chunk, KEPT; repository root → 0 chunks,
  REJECTED (Rule 4). Aggregate `rejected=True` solely due to the root —
  correct boolean semantics (≥1 dropped).
- CVE-2026-78205: `uri.py` blob (CVE-less guard code) → KEPT; issue
  #5644 PoC body → KEPT; repository root → REJECTED. All retained
  entries have `exact_record=None` (no fabrication).
- Previously-lost primary evidence (vulnerable handler, fix diff, guard
  condition, first-hand PoC comparison) now reaches `SecurityResearcher`;
  boilerplate roots still do not.

## 10. Reference Quality Gate invariance proof

- `ai/researcher/reference_quality.py` was never opened for editing in
  this stage (only read for verification); its Rules 1–5 logic,
  docstring contract, import surface (no network/LLM/subprocess), and
  fail-closed postures are intact.
- Behavioral proof: all 27 gate unit tests + 20 decision-boundary tests
  + 21 batch-parity + 21 single-parity tests pass UNMODIFIED, including
  `test_empty_content_rejected`, unknown-URL rejection, foreign-CVE
  rejection, cross-CVE isolation, dedup, order-preservation, and the AST
  no-network-surface test.
- Targeted end-to-end pins in the new suite re-prove the interactions:
  foreign-only fallback slice → Rule 3 drop (M); zero-CVE slice → kept
  by tolerance (N); roots → Rule 4 drop (E); known-URL membership still
  enforced (all `_gate` calls use per-entry known sets).

## 11. Parity/cache verification

- Parity: single (`research_cli` via `fetch_discovered_sources`) and
  batch (`cve_batch` inline loop) receive identical provenance keys from
  identical `DiscoveredSource` fields through the shared
  `build_research_contexts` + unchanged gate; `batch_v3`/`retry_v3`
  inherit via the same helper with no edits. Parity suites pass
  unmodified. Ungated legacy lanes gain the same fallback slices (more
  grounding, no filtering change — consistent direction).
- Cache: `BatchReferenceCache` stores pre-ranking `ReferenceDocument`s
  keyed by canonical URL; ranking (and fallback) runs post-fetch per
  CVE, so shared bytes re-rank per CVE id. All 24 cache tests pass
  unmodified; no poisoning vector introduced (provenance travels in
  per-CVE document dicts, never in cached values).

## 12. Any deviations from the approved design

Two immaterial tightenings (both in the conservative direction):

1. `source_type` eligibility uses the explicit set
   `{github, github_issue, github_research}` (new
   `TECHNICAL_GITHUB_SOURCE_TYPES`) rather than a `startswith("github")`
   prefix test — identical coverage of real discovery outputs, but
   immune to hypothetical future `github_*` types silently inheriting
   the fallback.
2. The `urlsplit` import is function-local inside the helper (matching
   the gate module's lazy-import style) rather than module-top — zero
   import-time surface change for the collector package.

No spec item was weakened: host exactness, segment boundaries with
`/<owner>/<repo>/<kind>/...` depth, provenance disjuncts (priority/
confidence/signal excluded), keyword-first-then-head content derivation,
single bounded chunk, `exact_record=None`, no-claims-injected, gate
frozen, schemas/telemetry frozen.

## 13. Remaining limitations

- Untagged product-only search hits (`product_in_title` without any CVE
  tag, score ≥80) are still dropped — deliberate residual FN, flagged in
  the design; escalation belongs in discovery thresholds, not the gate.
- Head slices of large/minified blobs can be low-signal (license
  headers); bounded noise accepted as the cost of recall.
- `/compare/`, `/tree/`, `/releases/`, `/security/advisories/`,
  `raw.githubusercontent.com`, gists remain out of scope (design
  decision; extend on observed FNs only).
- Line-fragment (`#L275-L315`) targeting is not used for windowing;
  keyword/head slices suffice for stage one.
- Per-CVE `reference_quality` booleans still cannot attribute drops to
  rules — a future counts-only per-rule histogram is compatible but out
  of scope.

---

## Acceptance Table

| Check | Result |
| --- | --- |
| Gate unchanged | PASS (file never edited; 27+20+21+21 gate/boundary/parity tests green unmodified) |
| Schemas unchanged | PASS (no edits under `ai/schemas/`) |
| Telemetry unchanged | PASS (histogram shapes frozen; zero count-assertion rewrites needed) |
| Foreign-CVE rejection | PASS (Rule 3 end-to-end pin, test M) |
| Repo-root rejection | PASS (Rule 4 pins, test E incl. trailing-slash/bare-owner shapes) |
| Technical GitHub retention | PASS (blob/commit/issues/pull pins A–D + CVE replay §9) |
| Single/Batch parity | PASS (shared code path; parity suites green unmodified) |
| Cache safety | PASS (24 cache tests green unmodified; post-fetch per-CVE ranking preserved) |
| Tests | PASS (28 new + 165 existing across 8 suites, all green) |
