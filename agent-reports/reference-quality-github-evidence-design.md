# Design: Retaining Directly-Discovered GitHub Technical Evidence in the Reference Quality Gate

Status: DESIGN / IMPACT ANALYSIS ONLY. No production code, tests, schemas,
or telemetry were modified. No LLM calls, network requests, Nuclei runs,
or Mongo access were performed. Findings are from offline code inspection
of the files listed in Section 2 plus the prior read-only investigation
report (`agent-reports/reference-quality-rejection-78203-78205-investigation.md`).

## 1. Executive Summary

The Reference Quality Gate (`ai/researcher/reference_quality.py::gate_reference_contexts`)
is working as specified, but its interaction with `ReferenceRanker`
(`ai/collectors/reference_ranker.py`) systematically discards a specific
class of first-party technical evidence: GitHub blob / commit / issue URLs
whose fetched page does not contain the CVE identifier string. The ranker
classifies every `github*` `source_type` as narrative, emits
`exact_record=None` and `context_chunks=[]` when the CVE string is absent,
and the gate's Rule 4 (`exact is None and no non-empty chunk → drop`)
then removes the entry. This is correct for repository roots and
boilerplate, but it dropped primary evidence in the investigated batch
(`views.py` L275–L315 for CVE-2026-78203; `uri.py` L89–L96 and possibly
issue #5644 for CVE-2026-78205). Kept advisories mitigated the loss; the
gate should still stop discarding directly-discovered technical evidence.

The recommended design (Section 10, approach D-hybrid with a frozen gate)
is: thread the already-existing, deterministic discovery provenance
(`DiscoveredSource.tags` + `DiscoveredSource.query`, today computed and
then dropped) through `build_research_contexts` into the ranker as
ephemeral in-memory fields only, and add one narrowly-scoped ranker
fallback that emits a single bounded verbatim text slice for entries that
satisfy ALL of (a) known-URL membership is satisfiable downstream,
(b) direct-discovery provenance for the current CVE, and (c) a
conservative GitHub technical-URL shape (`/blob/`, `/commit/`,
`/issues/`, `/pull/` on a github.com host; repository roots never
qualify). The gate itself is left byte-for-byte unchanged: Rules 1, 2, 3,
5 keep enforcing exactly as today (Rule 3 still drops foreign-CVE-only
chunks, including any produced by the new fallback), and Rule 4 passes
naturally because the entry is no longer empty. No new persistent schema,
no telemetry change, no LLM judgment, no fabricated CVE claims.

Why this placement matters: keeping an empty entry at the gate without a
ranker chunk would hand `SecurityResearcher` a URL with zero text — a
useless shell that fixes no evidence loss. The evidence loss happens in
the ranker (empty output), not in the gate (correct filtering of empty
input). So the fix belongs at the point of loss (ranker fallback,
provenance-gated), with the gate remaining the unchanged safety net.

## 2. Current Data Flow

End-to-end reference path for the gated lanes (batch and single-CVE share
it verbatim):

```
CVECollector.get_by_ids
  → ReferenceDiscovery.discover(cve, limit=5)          # ai/collectors/discovery.py
  → BatchReferenceCache.fetch / ReferenceCollector.fetch  # per-URL fetch
  → discovered_documents: list[dict]                   # ai/researcher/cve_batch.py ~L163-178,
                                                       # ai/collectors/discovery_fetch.py,
                                                       # ai/research_cli.py ~L185-187
  → build_research_contexts(documents, cve_id, keywords)  # ai/researcher/research_context.py
  → ReferenceRanker.build(document, cve_id, keywords)     # per document
  → contexts_raw: list[dict{url, source_type, title, priority, exact_record, context_chunks}]
  → gate_reference_contexts(contexts_raw, cve_id, known_urls)  # filter-only
  → ReferenceContext(...)                               # ai/schemas/reference.py
  → SecurityResearcher.research(..., reference_contexts, discovered_sources)
```

Field-level provenance ledger (what survives each hop):

| Stage | Fields present | Provenance survived? |
| --- | --- | --- |
| `DiscoveredSource` | `url, source_type, title, query, priority, confidence, tags` | Full. `query` = `cve.title` for NVD refs; `'"CVE"'` / `'"CVE" "product"'` for GitHub search. `tags` vocabulary below. |
| `ReferenceDocument` (fetch result) | `url` (post-redirect final), `source_type` (collector's own `classify_source`), `title, content, status_code, content_hash, tags=[]` | Collector re-derives `source_type` from host only; its `tags` are always `[]`. |
| `discovered_documents` (batch + `fetch_discovered_sources`) | `url=document.url`, `source_type=source.source_type` (discovery wins; collector's value discarded), `title=document.title or source.title`, `priority=source.priority`, `tags=source.tags`, `content=document.content` | `source_type`, `priority`, `tags` preserved. **`query` and `confidence` dropped here.** |
| `build_research_contexts` input `SimpleDocument` | `url, source_type, title, content` | **`tags` (and `priority`) dropped here.** Ranker never sees them. |
| `contexts_raw` dict | `url, source_type, title, priority, exact_record, context_chunks` | No `tags`/`query`. Gate sees URL + source_type + texts only. |

Discovery source-type and tag assignment (deterministic, offline-verified):

- `from_existing_references` (NVD references): any URL containing
  `github.com` → `source_type="github"`, priority 90,
  `tags=["nvd_reference","github"]`, `query=cve.title`. Only
  oracle/microsoft/google/redhat become `"vendor"`; everything else
  (including VulnCheck) becomes `"other"`. **All NVD GitHub blob/commit
  URLs therefore enter the ranker's narrative path.**
- `discover_github_repositories` (API search `'"CVE"'`): passing hits get
  `source_type="github"`, score-derived priority/confidence, and tags from
  `_relevance_score`: `cve_in_title` (+70), `cve_in_body` (+20),
  `product_in_title` (+35), `vendor_in_title` (+20),
  `security_research_signal` (exploit/PoC/proof-of-concept/reproducer),
  `cve_in_repo_name` (+40). `_is_relevant` thresholds: ≥60 for
  CVE-in-title/repo-name or product-in-title+CVE-in-body, else ≥80.
- `discover_github_issues` (API search `'"CVE" "product"'`): passing hits
  get `source_type="github_research"` iff `security_research_signal` is
  present, else `"github_issue"`, with the same tag vocabulary.
- `discover` dedups by exact URL string, sorts by
  `(priority, confidence)` descending, truncates to `limit` (5 in the
  gated lanes).

Ranker dispatch (`ReferenceRanker.build`):

- `source_type ∈ {vendor, advisory, security_advisory}` → structured:
  `_find_exact_record(content, cve_id)`; on hit returns
  `{exact_record, chunks=[exact_record]}`; on miss falls through to the
  generic fallback (keyword window, may yield a zero-CVE chunk that the
  gate tolerantly keeps).
- `source_type ∈ {github, github_issue, github_research,
  security_research, bug_bounty, blog, writeup, research}` → narrative:
  `exact_record=None` ALWAYS; `_extract_github_body` (chrome trim; falls
  back to full text if the CVE string would be lost); then
  `_narrative_context`, which returns `[]` unless the (possibly trimmed)
  text contains the CVE id, windowing `[-1200, +5000]` around the LAST
  match, capped to one chunk (`MAX_CONTEXT_CHUNKS=1` is structural — only
  one chunk is ever produced).
- Otherwise (`other`, …) → generic: exact record on CVE hit, else
  `_fallback_context` — first keyword hit (CVE id, vendor, products, plus
  caller-specific extras in ungated lanes) windows
  `±FALLBACK_CONTEXT_SIZE/2` (5000) and returns one chunk, possibly with
  zero CVE ids.

Gate (`gate_reference_contexts`, rules in code order 1→5):

1. dict + non-empty `url`; `url ∈ known_urls` (both gated callers build
   `known_urls={item["url"] for item in discovered_documents}` from the
   identical list, so Rule 1 passes by construction absent a
   redirect-rewrite divergence between `DiscoveredSource.url` and
   `document.url`).
2. `exact_record` non-None ⇒ must contain current CVE (case-insensitive).
   Narrative entries have `exact=None`: Rule 2 is vacuous for them.
3. Scoped text (`exact` + non-empty chunks): if any `CVE_PATTERN`
   (`\bCVE-\d{4}-\d{4,7}\b`, case-insensitive) hit exists and the current
   CVE is not among them ⇒ drop. **Vacuous on empty entries** (`found`
   is empty ⇒ keep-or rather, fall through to Rule 4). Multi-CVE text
   containing the current CVE passes (this is why the VulnCheck advisory
   mentioning predecessor CVE-2025-54381 survived).
4. `exact is None and not non_empty` ⇒ drop. **This is the sole killer of
   the CVE-less GitHub entries.**
5. Canonical-URL dedup (`canonicalize_reference_url`: strip, drop
   fragment, drop only `utm_*`/`gclid`/`fbclid` params; fragment `#L275`
   therefore does not split lines) keeps the first occurrence.

Ungated callers of the same `build_research_contexts` (no gate at all):
legacy `ai/researcher/batch.py::build_reference_contexts`,
`ai/researcher/batch_v3.py` (~L265), `ai/researcher/retry_v3.py` (~L116).
They use different keyword sets (batch_v3/retry_v3 append
`"exploit","PoC",…`), and their output flows straight into
`ReferenceContext`s. Any ranker change propagates to them as well (more
grounding, no gate interaction — see Section 7).

## 3. Root Cause

Three individually-reasonable behaviors compose into systematic evidence
loss for one URL class:

1. **Discovery flattens role to host.** `from_existing_references` maps
   every `github.com` URL — repo root, `/blob/` source file, `/commit/`
   diff, `/issues/` PoC — to the single `source_type="github"` with tags
   `["nvd_reference","github"]`. The URL path (which distinguishes a
   pinpointed file/commit from a repository landing page) is never parsed;
   the NVD-listing fact (strongest provenance: a human curator attached
   this URL to this CVE) is recorded in `tags`/`query` but:
2. **Context-building drops the provenance.** `build_research_contexts`
   copies only `{url, source_type, title, content}` into the ranker's
   input and emits only
   `{url, source_type, title, priority, exact_record, context_chunks}`.
   By gate time the only remaining signals are coarse `source_type`
   (`"github"` = root and blob alike) and the extracted texts.
3. **Narrative extraction is CVE-string-gated, and Rule 4 finishes the
   job.** Source files and diffs rarely contain their CVE identifier, so
   `_narrative_context` returns `[]`, `exact_record` is `None` by
   construction for the narrative path, and Rule 4 drops the entry —
   correctly for boilerplate, incorrectly for pinpointed technical
   material.

Net effect (investigated batch): the entries most likely to ground
code-level claims (vulnerable file at a tag, fix commit, pre-assignment
issue body) are exactly the entries most likely to lack a CVE string and
hence be dropped, while keyword-bearing advisories survive. The LLM then
reasons about code it can no longer see, leaning on second-hand
restatements. Decisions stayed conservative in the observed batch, but the
margin came from advisory redundancy, not from the gate preserving the
best evidence.

Separately noted (telemetry gap, not a correctness bug): per-CVE
`reference_quality={checked:1, rejected:0|1}` records THAT ≥1 entry was
dropped, never WHICH rule or HOW many. The investigation's per-URL
attribution required code-plus-artifact reconstruction. Any future
per-rule histogram must remain counts-only (no URLs/contents) to preserve
the existing telemetry privacy property asserted in tests
(`test_telemetry_has_no_urls_or_ids`).

## 4. Candidate Designs A-D

### Approach A — Relax Rule 4 in the gate

Shape: add a keep-exception to Rule 4 inside `gate_reference_contexts`
(e.g. keep `exact=None`/empty-chunk entries when `source_type` is a
GitHub type, or when the URL looks technical). Ranker untouched.

- Files/functions: `ai/researcher/reference_quality.py::gate_reference_contexts`
  (+ docstring contract); tests in `ai/test_reference_quality_gate.py`,
  `ai/test_reference_quality_decision_boundary.py`,
  `ai/test_batch_reference_quality_parity.py`,
  `ai/test_single_cve_quality_parity.py`.
- Data-flow impact: gate gains URL-parsing and/or source-type-based keep
  logic. Every downstream consumer of gated contexts (single + batch
  `SecurityResearcher` inputs) receives entries that may carry **zero
  text** (`ReferenceContext` with `exact_record=None, context_chunks=[]`)
  unless paired with a chunk-producing change — a keep-without-content
  shell is useless to the LLM and risks confusing grounding ("cited URL
  with nothing behind it"). To be useful, A must be paired with B anyway.
- Security/false-positives: any exception keyed only on
  `source_type ∈ github*` keeps ALL CVE-less GitHub material including
  repo roots, user profiles, search pages — directly violating constraint
  4/5. Keying on URL shape inside the gate is deterministic and safer,
  but puts URL semantics in the filter layer, which today is deliberately
  URL-agnostic (it only tests membership + canonical equality).
- Foreign-CVE contamination: cannot occur through THESE entries (empty
  scoped text ⇒ Rule 3 vacuous, nothing to contaminate). The real risk is
  misattribution-by-proximity: unscoped code adjacent to the current CVE's
  other contexts may be read by the LLM as belonging to it. Bounded by
  keeping the entry's own URL/title intact (provenance travels with the
  entry) — but A alone provides no content anchor at all.
- Rules 1/2/3/5: Rule 4 is weakened by definition; Rules 1 (membership),
  2 (exact identity), 3 (foreign-only), 5 (dedup) can stay intact IF the
  exception is placed strictly after Rule 3 and before Rule 5. Ordering
  discipline required and must be tested.
- Ranker semantics: unchanged globally (a plus), but the ranker's empty
  output becomes load-bearing "keep me" signal — inverting the current
  meaning of emptiness.
- Parity/cache/telemetry: parity preserved (shared gate); cache
  unaffected (pre-ranking); telemetry schema unchanged but `rejected`
  counts drop — count-asserting tests need updates.
- Required tests: Rule-4 exception matrix (technical shapes kept; roots
  dropped; non-GitHub empty still dropped; foreign-only non-empty still
  dropped; ordering vs Rules 1/2/3/5; empty-shell handling downstream).
- Backward-compat risk: MEDIUM-HIGH. The gate is the most
  contract-pinned component in the suite (filter-only, never-mutates,
  AST no-network test, cross-CVE isolation tests). Touching Rule 4
  invalidates the crispest existing guarantee ("empty ⇒ dropped") and
  every test that encodes it (`test_empty_content_rejected` et al.).

Verdict: viable only as URL-shape-scoped exception AND paired with a
chunk source; otherwise it keeps either too much (source-type key) or
nothing useful (empty shells). As a standalone, NOT recommended.

### Approach B — Ranker emits fallback context for GitHub technical references without a CVE string

Shape: extend the narrative branch (or add a post-narrative fallback) so
that when `_narrative_context` yields `[]`, the ranker produces one
bounded verbatim slice (e.g. keyword-anchored window, else head slice of
normalized text) instead of `[]`. Gate untouched.

- Files/functions: `ai/collectors/reference_ranker.py::ReferenceRanker.build`
  (+ `_narrative_context` / new `_technical_fallback`), possibly
  `FALLBACK_CONTEXT_SIZE` reuse; `ai/researcher/research_context.py`
  unchanged (same dict shape, now non-empty more often).
- Data-flow impact: every `build_research_contexts` caller gains chunks —
  INCLUDING the three ungated lanes (legacy batch, batch_v3, retry_v3).
  That is strictly more grounding everywhere, but it is a global semantic
  change to a shared extractor, and keyword sets differ per caller
  (ungated lanes append "exploit"/"PoC"/…), so fallback content would vary
  by caller for the same document. Deterministic per caller, but not
  caller-invariant — must be documented, not fixed.
- Critical sub-flaw if unscoped: the generic `_fallback_context` is
  keyword-anchored (CVE → vendor → products). A source blob containing
  none of those words (pure code, minified JS) STILL yields `[]` — B
  implemented as "reuse keyword fallback for github" does not reliably fix
  blobs. A reliable B needs a keyword-independent terminal fallback
  (head slice of normalized text, bounded, verbatim). That is a new
  content-selection semantic: the head of a large file (license header,
  imports) is low-signal but harmless; the alternative (no chunk) is the
  current loss. Cap MUST reuse existing bounds (`FALLBACK_CONTEXT_SIZE`,
  one chunk) to bound LLM token growth.
- Security/false-positives: unscoped B keeps repo roots too (a root page
  contains vendor/product words ⇒ keyword fallback fires ⇒ zero-CVE chunk
  ⇒ gate tolerance keeps it) — violates constraint 5 unless B is
  shape/provenance-scoped, at which point it IS approach D implemented in
  the ranker. Foreign-only risk is handled downstream: any fallback chunk
  containing only foreign CVE ids is still dropped by Rule 3 (gate
  unchanged). Zero-CVE chunks are kept by tolerance — intended.
- Rules 1/2/3/5: untouched (gate frozen). Rules 1/5 operate on URLs,
  unaffected by chunk content. Rule 2 unaffected (fallback sets
  `exact_record=None`, never fabricates an exact record — mandatory).
- Ranker semantics: changed globally by definition — the blast radius is
  the concern (all lanes, all source types if not scoped).
- Parity: single/batch parity preserved trivially (shared ranker).
  Gated/ungated outputs BOTH gain chunks (consistent direction).
- Cache: unaffected (ranking happens after cache fetch, per CVE).
- Telemetry: schema unchanged; `rejected` decreases; count tests updated.
- Required tests: fallback matrix per source class (blob/commit/issues
  without CVE ⇒ one bounded verbatim chunk; root ⇒ still `[]`;
  foreign-only content ⇒ chunk produced but gate drops it end-to-end;
  determinism; bound enforcement; no `exact_record` fabrication; keyword
  sets documented).
- Backward-compat risk: MEDIUM unscoped (roots get kept downstream via
  tolerance — a behavior regression the suite does not currently pin for
  ranker outputs); LOW if scoped to technical shapes + provenance (→ D).

Verdict: the right MECHANISM (produce a chunk where loss occurs) but the
wrong SCOPE if unscoped. Scoped B + provenance (C) = the recommended D.

### Approach C — Propagate deterministic provenance; gate decides

Shape: thread `DiscoveredSource.tags` (+`query`) through
`discovered_documents` (already present) → `build_research_contexts`
(new ephemeral fields) → `contexts_raw` (ephemeral) → gate allowlist
(e.g. keep iff `nvd_reference ∈ tags ∧ query == cve_id`, or GitHub-search
tags with `query` containing the CVE). No ranker change, no content
change.

- Files/functions: `ai/researcher/research_context.py::build_research_contexts`
  (accept/forward `tags`/`query`), `ai/researcher/cve_batch.py` +
  `ai/research_cli.py` (+ `ai/collectors/discovery_fetch.py`,
  `ai/researcher/batch_v3.py`, `ai/researcher/retry_v3.py` for
  consistency) to supply them; `ai/researcher/reference_quality.py` to
  consume them; `ReferenceContext` conversion stays as-is (provenance
  MUST NOT flow into the LLM-facing schema — filter signal only).
- Data-flow impact: plumbing only. Provenance is in-memory, per-entry,
  per-CVE (re-derived per CVE at ranking time — no cross-CVE bleed; the
  cache stores documents, not provenance application).
- Security: provenance is curator-derived (NVD listing) or
  query-derived (API search for THIS CVE string), never LLM-derived —
  satisfies constraint 2. But C ALONE retains nothing: the gate would
  keep entries that are still empty (shell problem, as in A) unless the
  keep-exception fabricates context (forbidden) or is paired with B's
  chunk production. C is necessary infrastructure, insufficient alone.
- Foreign-CVE: provenance must NEVER override Rule 3. A
  `nvd_reference`-tagged page whose text names only a foreign CVE (stale
  NVD link, reused advisory URL) must still drop. The allowlist must be
  conjunctive with Rules 2/3 passing, never a bypass. Tests must pin an
  NVD-tagged foreign-only entry ⇒ dropped.
- Rules 1/2/3/5: preserved if the provenance check is an additional
  conjunct evaluated with (not instead of) Rules 1–3/5. `known_urls` and
  dedup untouched.
- Ranker semantics: unchanged.
- Parity: preserved IF all `build_research_contexts` call sites forward
  provenance (batch, single, batch_v3, retry_v3, legacy batch, cache-test
  helpers). Missed call sites silently get "no provenance" ⇒ old behavior
  (safe default: unprovenanced entries gate exactly as today — fail-safe
  direction, but creates lane inconsistency to document).
- Cache: unaffected (provenance applied post-fetch per CVE; cached
  `ReferenceDocument.tags` are collector-side `[]` and must NOT be
  confused with discovery tags — name the forwarded field distinctly,
  e.g. `discovery_tags`/`discovery_query`, to prevent exactly this mixup).
- Telemetry: unchanged schema; counts shift.
- Required tests: forwarding tests per call site (tags/query survive to
  `contexts_raw`, absent ⇒ legacy behavior); gate allowlist matrix;
  NVD-tagged foreign-only ⇒ dropped; query-mismatch ⇒ no exception.
- Backward-compat risk: LOW-MEDIUM as pure plumbing with safe-default
  (absent provenance ⇒ today's behavior). Risk concentrates in field
  naming (collision with `ReferenceDocument.tags`) and in callers that
  construct `documents` dicts by hand (tests, `_make_research_fn`
  helpers).

Verdict: required ENABLER, not a standalone fix. Every viable D contains
C's plumbing with C's safeguards (conjunctive, safe-default, distinct
field names).

### Approach D — Hybrid (RECOMMENDED, gate frozen)

Shape: C's provenance plumbing (ephemeral only) + B's fallback NARROWLY
scoped to directly-discovered technical GitHub evidence. Gate UNCHANGED.

Precise predicate (all conjuncts, evaluated in the ranker fallback):

1. `source_type` is a GitHub narrative type AND the host is github.com
   (defense against `source_type` spoofing via hand-built dicts; parse
   with stdlib `urlsplit`, lowercase host compare — the same stdlib
   family already used by `reference_cache` and `reference.py`).
2. URL path matches the technical allowlist (case-sensitive path,
   lowercased copy for matching): contains `/{owner}/{repo}/blob/`,
   `/commit/`, `/issues/`, `/pull/` (initial set; see open questions for
   `/compare/`, `/tree/`, `/releases/`, `/security/advisories/`,
   `raw.githubusercontent.com`, gists). Repository roots
   (`^/[^/]+/[^/]+/?$`), user profiles, `/search`, `/topics`,
   `/marketplace`, `/sponsors`, and any non-matching path ⇒ NO fallback
   (today's `[]` preserved ⇒ Rule 4 still drops them).
3. Direct-discovery provenance for THIS CVE: (`nvd_reference ∈
   discovery_tags ∧ discovery_query == cve_id`) OR (`discovery_query`
   contains `cve_id` as a quoted token AND `discovery_tags ∩
   {cve_in_title, cve_in_body, cve_in_repo_name} ≠ ∅`). Priority,
   confidence, and `security_research_signal` alone confer NOTHING
   (ranking ≠ trust).
4. `_narrative_context` yielded `[]` (CVE string absent — the loss case).
   If narrative produced a chunk, return it unchanged (no behavior change
   on today's kept paths).

Fallback output on predicate pass: `exact_record=None` (NEVER fabricate),
`context_chunks=[one verbatim slice]` derived as: first try the existing
keyword-anchored `_fallback_context` (preserves today's vendor-tolerance
behavior where applicable); if that yields `[]` (pure code), emit the
head slice of `_normalize(content)` capped at `FALLBACK_CONTEXT_SIZE`
with `MAX_CONTEXT_CHUNKS=1`. Verbatim means verbatim: no CVE-ID
insertion, no "this fixes CVE-…" prefix, no severity/exploit/payload
claims, no trust marking. URL + title + source_type continue to the LLM
unchanged, which is the entire provenance signal the model receives.

Gate behavior on the new chunks (no code change): Rule 1 (membership) and
Rule 5 (dedup) operate on URLs as before; Rule 2 vacuous (`exact=None`);
Rule 3 scans the new chunk — foreign-only ⇒ dropped (desired, tested);
zero-CVE ⇒ kept by tolerance (the intended retention); current-CVE ⇒
kept. Rule 4 passes (non-empty). The gate remains the unchanged safety
net; its contract, docstring, and AST surface are untouched.

Worked expectations on the investigated evidence:

- `.../Ghostwriter/blob/v7.1.1/.../views.py#L275-L315` (NVD `github` tag,
  technical shape, no CVE string) ⇒ head/keyword slice kept; Rule 3 scans
  code (no CVE ids ⇒ tolerance keep). Primary evidence restored.
- Fix commit `.../commit/5b2a4a…` ⇒ same. (If its message names the CVE,
  narrative already kept it; fallback never fires.)
- `.../BentoML/blob/v1.4.39/.../uri.py#L89-L96` ⇒ same.
- `.../BentoML/issues/5644`: if NVD-listed ⇒ kept via slice even
  pre-assignment; if search-found with `cve_in_body` ⇒ kept; if
  search-found WITHOUT any CVE tag (pure product match scoring ≥80) ⇒
  still dropped — accepted residual FN (see Section 6), narrow and
  principled: the gate keeps refusing to trust query-correlated-but-
  CVE-unmentioned material beyond NVD curation.
- Repo roots (`github.com/GhostManager/Ghostwriter`,
  `github.com/bentoml/BentoML`) ⇒ shape fails ⇒ `[]` ⇒ Rule 4 drops as
  today. Constraint 5 satisfied structurally, not by judgment.

## 5. Security Analysis

- **No LLM trust decision (constraint 2):** all retention predicates are
  deterministic functions of (discovery tags/query, URL host+path,
  pre-existing ranker emptiness). No model output influences keep/drop.
- **No fabrication (constraint 3):** the new chunk is a verbatim slice of
  fetched content; `exact_record` stays `None`; no CVE id, severity,
  exploit, or remediation text is added. The LLM receives strictly more
  *source* text, zero new *claims*. `ReferenceContext` gains no
  authority/verified fields (constraint 10).
- **Foreign-CVE isolation (constraint 6):** preserved by keeping Rule 3
  authoritative over ALL text including new slices. Threat cases:
  (i) NVD-tagged URL whose content names only a foreign CVE (stale/moved
  link) ⇒ Rule 3 drops — MUST be a pinned test; (ii) blob at a tag whose
  file header references another CVE ⇒ same; (iii) shared canonical URL
  across CVEs in one batch ⇒ per-CVE ranking + per-CVE gating re-evaluate
  the same bytes under each CVE id (existing `test_shared_document_reused…`
  pattern extends directly). Provenance NEVER bypasses Rules 2/3 — it only
  authorizes *producing* a slice, never *keeping* foreign-scoped text.
- **Source integrity (constraint 7):** `known_urls` construction and
  membership test untouched; redirect-rewrite edge (document.url ≠
  source.url) behaves exactly as today. Retain the existing fail-closed
  posture for missing/empty `cve_id`.
- **Dedup (constraint 8):** untouched; line fragments (`#L275`) remain
  key-invisible as today, so blob + line-link duplicates still collapse —
  desired.
- **New attack surface introduced:** minimal — a stdlib URL-shape matcher
  in the ranker ( Frankfurt-level parsing bugs bounded by: host allowlist
  first, `urlsplit` in try/except with fail-closed `[]` on parse error,
  path matching on lowercased copy, no regex backtracking risk if
  implemented with segment checks). Malformed URLs ⇒ no fallback ⇒
  today's drop. An adversary who controls a linked repo could shape paths
  (`/blob/…`) — but inclusion still requires NVD listing or CVE-tagged
  search correlation for THIS CVE, and content is passed verbatim with its
  URL visible, never as an exact record or trusted claim.
- **Misattribution-by-proximity (residual):** unscoped code slices sit
  beside CVE-scoped advisory chunks in the LLM prompt. Mitigations:
  verbatim-only content, original URL/title preserved (model sees the file
  path), single bounded chunk, no exact-record elevation. The researcher
  prompt's existing evidence conventions (advisory-grounded vs
  model-surfaced) continue to apply; no prompt change is proposed in this
  stage.
- **DoS/token cost:** at most one extra `FALLBACK_CONTEXT_SIZE`-bounded
  chunk per qualifying entry (previously zero), only for the technical
  class. Worst case per CVE is bounded by the discovery limit (5) —
  negligible and deterministic.

## 6. False Positive / False Negative Analysis

Definitions: FP = kept entry with no security value for this CVE (noise
the LLM must ignore); FN = dropped entry that carried first-party value.

| Situation | Today | Under D |
| --- | --- | --- |
| NVD-listed blob/commit without CVE string (the investigated loss) | FN (dropped, Rule 4) | Kept with verbatim slice (FN fixed) |
| NVD-listed issue without CVE string in body | FN (likely) | Kept (FN fixed) |
| NVD-listed blob whose text names ONLY a foreign CVE | Dropped (Rule 3 if non-empty; Rule 4 if empty — either way dropped) | Still dropped (Rule 3 on the new slice). No regression. |
| Repo root / profile / search page (any provenance) | Dropped (Rule 4) | Still dropped (shape gate). No FP added. |
| Search-found technical URL, CVE-tagged (`cve_in_title/body/repo_name`) | Dropped if body lacks CVE at fetch | Kept (bounded slice). Small FP risk (title-matched but body-irrelevant) — accepted: search required the CVE string + relevance threshold ≥60, slice is verbatim, Rule 3 still filters foreign-only. |
| Search-found technical URL, product-only match (no CVE tag, score ≥80) | Dropped | Still dropped. Accepted residual FN (rare; deliberately conservative). |
| Non-GitHub `other`/vendor material | Today's behavior (exact / keyword fallback / tolerance) | Unchanged (predicate requires github host + github type). |
| Minified/large blob, head slice is license header | N/A (dropped) | Kept low-signal chunk (mild FP). Bounded, verbatim, URL-visible; acceptable cost of a recall fix. Keyword-anchored attempt first mitigates it when vendor words exist. |
| Adversarial repo path shaped as `/blob/` | N/A | Still needs NVD/search provenance for THIS CVE + passes Rule 3; content verbatim. Threat negligible. |

Overall: D converts the two observed high-value FNs to keeps, adds no
root/boilerplate FPs by construction, and holds the foreign-CVE line via
the unchanged Rule 3. The only accepted regressions-in-principle are
low-signal head slices (bounded noise) and the deliberate residual FN for
untagged product-only search hits.

## 7. Batch vs Single-CVE Impact

- Gated lanes (`_make_cached_research_fn` in `cve_batch.py`, `_research_single_cve`
  in `research_cli.py`) call the IDENTICAL `build_research_contexts` +
  `gate_reference_contexts` sequence with identically-built `known_urls`.
  A ranker-scoped fallback + shared provenance plumbing therefore affects
  both lanes identically — parity (constraint 9) is structural, and the
  existing parity suites (`test_batch_reference_quality_parity.py`,
  `test_single_cve_quality_parity.py`) extend without redesign.
- Ungated lanes (legacy `researcher/batch.py`, `researcher/batch_v3.py`,
  `researcher/retry_v3.py`) call `build_research_contexts` with NO gate.
  They automatically gain the same fallback slices (more grounding, no
  filtering change). Direction is consistent (never less context), and no
  gate semantics leak into them. Note for implementers: batch_v3/retry_v3
  use richer keyword sets, so keyword-anchored slices may differ there —
  deterministic and acceptable; document it in the ranker docstring.
- `test_real_research.py` (live-shape inspection) and decision-boundary
  tests gain kept technical contexts; assertions on exact kept/dropped
  sets for GitHub fixtures will need targeted updates (Section 9), not
  rewrites.

## 8. Cache Impact

None beyond today (explicitly verified against `reference_cache.py`):

- `BatchReferenceCache` stores `ReferenceDocument`s (pre-ranking bytes)
  keyed by canonical URL; ranking (and the new fallback) runs AFTER fetch,
  PER CVE. The same cached bytes re-ranked under different CVE ids yield
  different slices — no cross-CVE conclusion sharing (existing invariant,
  plus the `test_shared_document_reused…` pattern).
- Provenance MUST travel in the per-CVE `discovered_documents` dicts
  (new `discovery_tags`/`discovery_query` keys), NOT in the cached
  document (whose `tags` are collector-side `[]`). Field naming must keep
  these namespaces distinct — a named trap for implementers (Section 10).
- Canonicalization, hit semantics, hard-miss non-caching, and the
  counts-only `reference_cache` histogram are untouched.

## 9. Test Impact

No test changes in THIS stage (design only). For the implementation stage,
required suites (all offline, socket/subprocess-blocked per existing
conventions):

1. Ranker unit (new/extended — no dedicated ranker test file exists
   today; nearest homes: extend via `test_reference_quality_gate.py`
   helpers or a new `ai/test_reference_ranker_technical_fallback.py`):
   blob/commit/issues/pull URLs + NVD provenance + CVE-less code body ⇒
   exactly one bounded verbatim chunk, `exact_record is None`; same URLs
   with repo-root shape ⇒ `[]`; non-github host with `/blob/` path ⇒
   `[]`; malformed URL ⇒ `[]` (no raise); head-slice bound
   (≤ `FALLBACK_CONTEXT_SIZE` chars post-normalize); determinism (same
   bytes ⇒ same slice); keyword-anchored preference when vendor words
   present.
2. Provenance plumbing: `build_research_contexts` forwards
   `discovery_tags`/`discovery_query` (and ignores their absence →
   legacy behavior); all call sites (`cve_batch`, `research_cli`,
   `discovery_fetch`, `batch_v3`, `retry_v3`) supply them; hand-built
   dicts without them behave exactly as today (safe default).
3. Gate invariance: gate file untouched — existing gate suites MUST pass
   unmodified, PLUS new end-to-end pins: NVD-tagged foreign-only slice ⇒
   dropped (Rule 3); query-mismatch ⇒ no fallback occurred upstream
   (entry still drops under Rule 4); untagged product-only search hit ⇒
   still drops; kept technical slice ⇒ `ReferenceContext` converts
   cleanly with original URL/title.
4. Parity: single-vs-batch gated outputs identical for shared fixtures
   (extend `SingleBatchParityTests` pattern); updated `checked/rejected`
   counts where fixtures now keep technical entries (aggregate + per-CVE
   assertions recompensed, schema unchanged).
5. Boundaries preserved: gate AST no-network test, filter-only/order
   tests, dedup tests, `test_telemetry_has_no_urls_or_ids`-style privacy
   pins all remain green; new slices contain no invented CVE ids
   (assert `CVE_PATTERN` absence unless source contained them).
6. Cache: existing `test_reference_cache.py` green unmodified (proves no
   poisoning); one new test that shared-URL + per-CVE provenance yields
   per-CVE slices.

## 10. Recommended Design

**D-hybrid with a frozen gate** (C plumbing + scoped-B fallback), for the
reasons in Sections 4–6: smallest trust-relevant change, clearest
provenance (reuse of curator/query facts already computed), gate contract
and its extensive test pinning fully preserved, no schema/telemetry
changes.

Concrete specification for the implementing agent:

1. **Provenance carriage (ephemeral only).**
   - In `cve_batch._make_cached_research_fn.research_fn`,
     `research_cli._research_single_cve`, `discovery_fetch.fetch_discovered_sources`,
     `batch_v3`, `retry_v3`: include per-document
     `discovery_tags=list(source.tags)` and `discovery_query=source.query`
     in the `discovered_documents` dicts.
   - In `research_context.build_research_contexts`: accept these keys,
     copy them onto the ranker input object (extend `SimpleDocument`
     attributes; do NOT add them to `ReferenceDocument` /
     `ReferenceContext` schemas), and (optionally, for debuggability)
     strip them from the emitted `contexts_raw` dicts so the gate input
     shape is unchanged. If stripped, the ranker's decision is already
     baked into `exact_record`/`context_chunks` — the gate needs no new
     fields at all. (Preferred: strip. Then the gate file is literally
     untouched, and no gate-input-shape test can break.)
   - Absent keys ⇒ legacy behavior exactly (safe default for hand-built
     callers/tests).
2. **Scoped technical fallback in
   `ReferenceRanker`** (new private helper, e.g.
   `_technical_github_fallback(url, discovery_tags, discovery_query,
   text, cve_id, keywords) -> list[str]`, invoked ONLY when
   `source_type` is a GitHub narrative type AND `_narrative_context`
   returned `[]`):
   - Host check: `urlsplit(url)` in try/except; host lowercased; require
     `host == "github.com"` (exact; allow `www.github.com` only if the
     team confirms NVD emits it — default deny). Parse failure ⇒ `[]`.
   - Shape check on lowercased path segments: allow iff path contains
     `/blob/` or `/commit/` or `/issues/` or `/pull/` as full segments
     (`/blob` as a repo name must NOT match — segment-boundary check,
     not substring). Everything else ⇒ `[]`.
   - Provenance check: `(nvd_reference ∈ tags ∧ query == cve_id)` ∨
     (`cve_id` appears as a case-insensitive token in `query` ∧ `tags ∩
     {cve_in_title, cve_in_body, cve_in_repo_name} ≠ ∅`). Comparison
     case-insensitive, whitespace-stripped. Anything else ⇒ `[]`.
   - Emission: try existing `_fallback_context(text, keywords)` first;
     if `[]`, emit `[normalize(text)[:FALLBACK_CONTEXT_SIZE]]` (strip;
     empty ⇒ `[]`). Return at most one chunk. NEVER set `exact_record`.
3. **Gate: no change.** Verify by running the full quality suites
   unmodified. Rules 1/2/3/5 continue to dispose of foreign-only,
   synthetic, and duplicate entries including any produced by (2).
4. **Docs:** one-paragraph docstring updates in `reference_ranker.py`
   (fallback scope + verbatim guarantee) and `research_context.py`
   (ephemeral provenance keys, stripped before gate). No telemetry,
   schema, or contract-doc changes (gate docstring frozen).

## 11. Exact Production Files/Functions That Would Change

| File | Function/area | Change (next stage) |
| --- | --- | --- |
| `ai/collectors/reference_ranker.py` | `ReferenceRanker.build` + new `_technical_github_fallback`; class docstring | Scoped fallback per Section 10.2; reuse `FALLBACK_CONTEXT_SIZE`, `_normalize`, `_fallback_context`. No changes to `CVE_PATTERN`, source-type sets, `_narrative_context`, `_extract_github_body`, `_find_exact_record`. |
| `ai/researcher/research_context.py` | `build_research_contexts` | Forward ephemeral `discovery_tags`/`discovery_query` to ranker input; strip from emitted dicts (preferred). |
| `ai/researcher/cve_batch.py` | `_make_cached_research_fn.research_fn` (~L163–184) | Add the two ephemeral keys to `discovered_documents`. |
| `ai/research_cli.py` | `_research_single_cve` discovery→documents block | Same two keys (direct dict build or via `fetch_discovered_sources` return). |
| `ai/collectors/discovery_fetch.py` | `fetch_discovered_sources` | Include `discovery_tags`/`discovery_query` from `source` in returned dicts (covers single-CVE + batch_v3 + retry_v3 paths at once). |
| `ai/researcher/batch_v3.py`, `ai/researcher/retry_v3.py` | context-building call sites | Only if they build document dicts outside `fetch_discovered_sources` — align to the same keys; no logic change. |
| Explicitly UNCHANGED | `ai/researcher/reference_quality.py` (entire file), `ai/schemas/reference.py`, `ai/schemas/discovery.py`, `ai/researcher/reference_cache.py`, telemetry (`empty_reference_quality_histogram`, per-CVE/aggregate shapes), `ai/collectors/discovery.py`, `ai/collectors/reference.py` | Frozen by design. |

## 12. Explicit Non-Goals

- No gate Rule 1/2/3/5 relaxation; no Rule 4 text change (gate file
  frozen).
- No `ReferenceDocument` / `ReferenceContext` / `DiscoveredSource` schema
  changes; no new persistent store; no provenance persisted to artifacts.
- No telemetry-shape changes (counts shift; keys and privacy properties
  fixed).
- No LLM involvement in keep/drop; no prompt changes; no
  exploit/severity/impact claim generation in the fallback.
- No "keep every GitHub URL"; repo roots, profiles, search/topic pages
  stay rejectable by construction.
- No title-based evidence invention (content-only fallback); no CVE-id
  insertion; no trust/authority marking.
- No redirect resolution, no host normalization beyond the exact-match
  allowlist, no new URL parser (stdlib `urlsplit` only).
- No Nuclei, network, Mongo, or live-execution surface changes; research
  stays non-authoritative (`authoritative=False` throughout).

## 13. Implementation Plan for the NEXT Stage

One focused stage, estimated small (single PR, no migrations):

1. Add ephemeral provenance keys through `discovery_fetch` +
   `cve_batch` + `research_cli` (+ align `batch_v3`/`retry_v3`) and
   `build_research_contexts` forwarding/stripping (Section 10.1).
   Test: forwarding + safe-default (absent keys ⇒ legacy outputs).
2. Implement `_technical_github_fallback` in `ReferenceRanker` per
   Section 10.2 with segment-boundary shape checks and the provenance
   predicate. Test: matrix in Section 9.1 (kept shapes, dropped roots,
   non-github, malformed, bounds, determinism, keyword-preference, no
   `exact_record`).
3. Run FULL existing quality/parity/cache/boundary suites unmodified;
   update ONLY count assertions where fixtures legitimately keep more
   (document each delta as recall-fix, not regression).
4. Add the three end-to-end pins (Section 9.3): NVD-tagged foreign-only ⇒
   dropped; query-mismatch ⇒ dropped; technical-keep converts to
   `ReferenceContext` with original URL/title.
5. Re-run the two investigated CVEs' offline fixtures (stored shapes, no
   network) to demonstrate: blob/commit/issue slices retained, roots
   still rejected, `checked` unchanged, `rejected` decreased for the
   right reason. Report artifact deltas in the implementation report.
6. Docstrings only (ranker + context builder). No gate/contract edits; no
   telemetry/schema edits. Implementation report under `agent-reports/`
   per repo convention.

Acceptance bar: gate file byte-identical; all pre-existing quality tests
green unmodified except documented count deltas; new tests green;
`ReferenceContext` outputs for previously-kept entries byte-identical;
no new imports beyond stdlib (`urllib.parse`); no network/LLM/subprocess
surface (AST test stays green).

## 14. Open Questions / Remaining Uncertainty

1. **Allowlist breadth:** are `/compare/`, `/tree/`, `/releases/`,
   `/security/advisories/`, `raw.githubusercontent.com`, and gists
   in-scope for the first iteration? Recommendation: NO — ship
   blob/commit/issues/pull only; extend on observed FNs. A too-wide
   initial set is the easiest way to reintroduce boilerplate keeps.
2. **Line-fragment utilization:** blob URLs carry `#L275-L315`. Current
   cache key drops fragments (dedup benefit). Should the fallback window
   center on the fragment's line range instead of keyword/head? Higher
   fidelity, but requires mapping rendered-text offsets to source lines —
   fragile across collectors. Defer; head/keyword slice is sufficient for
   stage one.
3. **Title signal:** PoC issues often name the CVE in the GitHub issue
   title while the fetched body omits it. The ranker is content-only
   today. Using title as fallback anchor is tempting but expands
   invention surface (titles are short, often boilerplate). Defer;
   NVD-provenance already covers NVD-listed issues regardless of body.
4. **Untagged product-only search hits:** deliberately still dropped.
   If future batches show this as a live FN source, the principled
   escalation is discovery-threshold tuning (in `discovery.py`), not gate
   weakening — keep the layers' responsibilities separate.
5. **`www.github.com` and enterprise hosts:** default-deny recommended
   until NVD data shows such URLs; GHE hosts must never qualify via the
   public-github predicate.
6. **Slice quality for minified blobs:** head slices of minified JS are
   noise. Bounded and harmless, but a future refinement could prefer
   slices containing path-relevant tokens (filename/function names from
   the URL path). Explicitly out of scope for stage one.
7. **Per-rule telemetry:** the boolean-per-CVE histogram cannot attribute
   drops to rules. A future counts-only per-rule histogram (no URLs) is
   compatible with this design (fallback keeps would move mass from
   "rule4" to "kept") but is NOT part of the recommended stage.

---

## Recommendation Table

| Approach | Safety | Evidence Retention | Complexity | Recommendation |
| --- | --- | --- | --- | --- |
| A) Relax Rule 4 in gate | Low–Medium (risks keeping roots if keyed on source_type; keeps empty shells if unpaired with chunk production; touches the most-pinned contract) | Medium (retains entries but WITHOUT content unless paired with B — shells, not evidence) | Low code, high assurance cost (gate suites + contract rewrite) | NOT recommended standalone; only as shape-scoped exception AND paired with chunk production — at which point D dominates it |
| B) Unscoped ranker fallback for GitHub | Low (repo roots gain keepable chunks via tolerance; global semantic change across gated + ungated lanes; keyword-dependence fails pure-code blobs without head-slice) | High recall, low precision (fixes FNs, adds boilerplate FPs) | Medium (new fallback semantics, caller-dependent keywords) | NOT recommended unscoped; becomes D when scoped + provenanced |
| C) Provenance plumbing only | High (plumbing with safe defaults; no keep/drop change alone) | None alone (enabler, not a fix) | Low–Medium (touch all document-building call sites; field-naming discipline) | REQUIRED ENABLER, insufficient alone — include its plumbing inside D |
| D) Hybrid: provenance + scoped technical fallback, gate frozen | High (conjunctive predicates; Rule 3/1/2/5 fully authoritative; roots structurally excluded; verbatim-only slices; fail-closed defaults everywhere) | High precision recall (fixes exactly the observed FN class: NVD/search-correlated blob/commit/issues/pull; deliberate residual FN only for untagged product-only hits) | Medium-low (one new private ranker helper + ephemeral key forwarding; gate byte-identical; no schema/telemetry changes) | **RECOMMENDED — implement in one focused stage per Sections 10–13** |
