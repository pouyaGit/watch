# Reference-quality rejections: CVE-2026-78203 / CVE-2026-78205 (read-only investigation)

Scope: read-only. No production code changed. No LLM calls, no network
calls, no Mongo writes, no Nuclei execution made by this investigation.
Gate replay used only local pure functions (`build_research_contexts`,
`gate_reference_contexts`, `ReferenceRanker.CVE_PATTERN`) plus stored
artifacts. No git operations performed.

## 1. Batch anchor

Two stored aggregates match `reference_quality checked=3 rejected=2`:

- `ai_data/research/batch-2026-09-07T070741.096002Z.json`
  (1557 failed on LLM `ResearchResult` ValidationError; 78203 + 78205
  completed, each `reference_quality = {checked:1, rejected:1}`).
- `ai_data/research/batch-2026-09-07T072603.424405Z.json`
  (all 3 completed; 1557 `{checked:1, rejected:0}`, 78203 `{checked:1,
  rejected:1}`, 78205 `{checked:1, rejected:1}`; aggregate
  `{checked:3, rejected:2}`).

This report anchors on the latest successful batch
(`batch-2026-09-07T072603.424405Z.json`, report
`agent-reports/cve-batch-run-2026-09-07T072603.424405Z.md`). The quality
outcome is identical in both batches, so the analysis applies to either.

Per-CVE batch items carry only counts (`checked`/`rejected`), never URLs
or contents, by design (`cve_batch._per_cve_reference_quality`,
`reference_quality.py` contract). There is therefore **no persisted
per-URL rejection log** in the batch artifacts. The tables below
reconstruct the gate inputs from (a) the batch/single flow source code,
(b) stored CLI metadata + `research.references`, and (c) offline replay
of the exact ranker + gate code. Reconstruction confidence is stated per
row; nothing below invents fetched page bodies.

## 2. Batch flow traced (code points)

Batch wrapper (`ai/researcher/cve_batch.py::_make_cached_research_fn`,
lines ~155-218; single-CVE mirror in `ai/research_cli.py::_research_single_cve`,
lines ~185-210):

1. `discovered = discovery.discover(cve, limit=5)` — NVD references via
   `from_existing_references` plus GitHub repo/issue search; sorted by
   priority, truncated to 5.
2. `discovered_documents` — per-URL `reference_cache.fetch(source.url)`;
   hard misses (`None`) skipped, never cached. Each entry keeps
   `url = document.url` (post-redirect final URL), `source_type` from the
   `DiscoveredSource` (NOT from the fetched document), `title`, `priority`,
   `tags`, `content`.
3. `contexts_raw = build_research_contexts(documents=discovered_documents,
   cve_id=cve.title, keywords=[cve.title, *cve.vendor, *cve.products])`
   (`ai/researcher/research_context.py`). One raw dict per fetched
   document, preserving discovery order: `{url, source_type, title,
   priority, exact_record, context_chunks}` via `ReferenceRanker.build`.
4. `gate_result = gate_reference_contexts(contexts_raw, cve_id=cve.title,
   known_urls={item["url"] for item in discovered_documents})`
   (`ai/researcher/reference_quality.py::gate_reference_contexts`).
   `known_urls` is built from the **same** `discovered_documents` list in
   both the batch and single flows, so a URL mismatch (Rule 1) can only
   arise from a redirect-rewritten `document.url` differing from the
   `DiscoveredSource.url` — not observed here (see section 4).
5. `quality_sink.append(bool(gate_result.rejected))`; per-CVE
   `reference_quality = {checked:1, rejected:1|0}` copied verbatim onto
   the result item; aggregate = `{checked: len(events), rejected: sum}`.
   `rejected=True` means "≥1 entry dropped from a non-empty list", NOT a
   count of dropped entries.

`ReferenceRanker.CVE_PATTERN` (reused verbatim by the gate):
`\bCVE-\d{4}-\d{4,7}\b`, case-insensitive. Both target IDs match it
(4-digit year + 5-digit sequence).

`ReferenceRanker.build` behavior that matters here:

- `source_type in {vendor, advisory, security_advisory}` → structured:
  `exact_record = _find_exact_record(content, cve_id)`; if found, chunks =
  `[exact_record]`; else falls through to generic fallback.
- `source_type in {github, github_issue, github_research,
  security_research, bug_bounty, blog, writeup, research}` → narrative:
  `exact_record=None` always; chunks = `_narrative_context(...)` which
  returns `[]` when the page body contains **no** occurrence of the
  current CVE id (GitHub chrome handling + last-occurrence windowing).
- Otherwise (`other`, the type `from_existing_references` assigns to all
  non-github/non-big-vendor NVD references, including VulnCheck) →
  generic: exact record if the CVE string occurs, else
  `_fallback_context` keyed on keywords (CVE id, vendor, products) —
  a vendor/product word hit yields a chunk that may contain **zero** CVE ids.
- `from_existing_references` mapping (offline code read, no network):
  any `github.com` URL → `source_type="github"` (priority 90);
  oracle/microsoft/google/redhat → `"vendor"` (100); everything else
  (incl. VulnCheck) → `"other"` (30). GitHub issue-search hits become
  `"github_issue"`/`"github_research"`. So every `github.com/.../blob/...`,
  repo root, and fix-commit URL in these batches takes the **narrative**
  path, while VulnCheck advisories take the **generic** path.

Gate rules (numbered as in the module docstring):

1. dict + non-empty `url`; when `known_urls` is provided, `url` must be a
   member (source integrity).
2. `exact_record`, when not None, must be a non-empty string containing
   the current CVE id (case-insensitive) — else drop (CVE identity).
3. Scoped text (`exact_record` + all non-empty chunks): if ≥1 CVE id is
   found anywhere and the current CVE id is not among them → drop
   (foreign-only). Entries with **zero** CVE ids anywhere are kept
   (fallback tolerance for keyword-scoped vendor material).
4. `exact_record is None` **and** no non-empty chunk → drop (empty
   reference content).
5. Duplicate canonical URL (`canonicalize_reference_url`: strip, drop
   fragment, drop only `utm_*`/`gclid`/`fbclid` params) keeps first
   occurrence only (dedup), original URL preserved.

## 3. Stored evidence used for reconstruction

| CVE | discovered / fetched / contexts (CLI metadata) | `research.references` in stored CLI JSON (order as returned by LLM, not discovery order) |
| --- | --- | --- |
| 78203 (`CVE-2026-78203.cli.json`, pre-gate run: no `reference_quality` field, `reference_context_count: 5`) | 5 / 5 / 5 | `https://github.com/GhostManager/Ghostwriter` (repo root) · `.../blob/v7.1.1/ghostwriter/reporting/views.py#L275-L315` (vulnerable code) · `.../commit/5b2a4a297e44c823c16f65b1ba101c742791cd0b` (fix commit) · `https://github.com/geo-chen/oss/blob/main/Ghostwriter.md` (public PoC) · `https://www.vulncheck.com/advisories/ghostwriter-before-cross-client-report-template-disclosure-via-unauthorized-template-swap` (advisory) |
| 78205 (`CVE-2026-78205.cli.json`, gated run: `reference_quality {checked:1, rejected:1}`, `reference_context_count: 1`) | 4 / 4 / **1 kept** | `https://www.vulncheck.com/advisories/bentoml-through-server-side-request-forgery-via-unfiltered-rfc-6598-shared-address-space` · `https://github.com/bentoml/BentoML` (repo root) · `.../blob/v1.4.39/src/bentoml/_internal/utils/uri.py#L89-L96` (vulnerable guard) · `.../issues/5644` (reporter PoC issue) |

Counts match exactly (5 URLs ↔ 5 discovered/fetched; 4 URLs ↔ 4
discovered/fetched), so `research.references` is a reliable proxy for the
discovery URL set. Discovery order is not persisted; table order below is
by URL role, not claimed discovery order. Fetched page bodies are **not**
persisted anywhere, so `exact_record`/chunk contents below are
mechanism-level determinations from offline replay of the exact code, not
byte-level quotes of the live pages (explicitly marked inferred vs
replayed).

Offline replay performed (no network, `/tmp`-only, nothing written to the
repo): (i) github blob content with no CVE string + `source_type=github`
→ `build_research_contexts` returns `{exact_record: None,
context_chunks: []}` → gate drops via **Rule 4**; (ii) `source_type=other`
advisory content containing the current CVE → `{exact_record:
"<CVE> ...", chunks: [same]}` → gate keeps; (iii) `other` content with
only a foreign CVE + vendor keyword → fallback chunk with
`CVE ids found = [foreign]` → gate drops via **Rule 3**; (iv) `other`
content with vendor keyword and zero CVE ids → fallback chunk, `found =
{}` → gate **keeps** (tolerance); (v) `github_issue` content containing
the current CVE → narrative chunk → keeps; (vi) `known_urls` missing the
entry URL → drops via **Rule 1**. Existing suite `ai.test_reference_quality_gate`
(27 tests) re-ran green, confirming the contract above.

## 4. Rejection tables

Conventions: `exact_record status` / `chunk status` describe what
`ReferenceRanker.build` yields for that URL class; `CVE ids found` is what
`ReferenceRanker.CVE_PATTERN` finds in the scoped text; `known_url check`
is membership of the entry URL in the same-run `discovered_documents` URL
set; `rejected rule` is the first gate rule that drops the entry
(rules evaluated in code order 1→5).

### CVE-2026-78203 (batch: `rejected=1`; ≥1 of ~5 entries dropped)

| URL | exact_record status | chunk status | CVE ids found | known_url check | rejected rule | assessment |
| --- | --- | --- | --- | --- | --- | --- |
| `https://github.com/GhostManager/Ghostwriter` (repo root; `source_type=github`) | None (narrative path never sets exact) — replayed | `[]`: repo landing content does not contain the CVE string (no per-CVE record on a repo root) — inferred + replayed mechanism | `{}` in scoped text (no text at all) | pass (URL comes from discovery set) | **Rule 4** (empty reference content) | Expected under current contract (Rule 4 fires on any narrative entry without a CVE mention). Aggressiveness: low-loss here — a repo root carries no per-CVE evidence; nothing of value lost. |
| `https://github.com/GhostManager/Ghostwriter/blob/v7.1.1/ghostwriter/reporting/views.py#L275-L315` (vulnerable source file; `source_type=github`) | None — replayed | `[]`: source code at a tag contains no CVE string — inferred + replayed mechanism | `{}` (empty scoped text) | pass | **Rule 4** | Expected under the contract, but **overly aggressive in effect**: this is primary code-level evidence (the `ReportTemplateSwap` handler the LLM later cites at L275–L315). Valid security evidence is lost from the LLM input (the exact vulnerable code). Mitigation in practice: the kept PoC/advisory quote the same lines, so grounding survived indirectly (stored research still cites the file/lines and the queryset-vs-endpoint distinction). |
| `https://github.com/GhostManager/Ghostwriter/commit/5b2a4a297e44c823c16f65b1ba101c742791cd0b` (fix commit; `source_type=github`) | None — replayed | `[]` unless the commit message body contains the CVE string (commit `5b2a4a2` message is a code fix message; CVE-string presence unconfirmed; most likely absent) — inferred, lower confidence | `{}` if absent (if the message did contain `CVE-2026-78203`, this row would instead be kept via Rule 3-pass) | pass | **Rule 4** (probable; Rule 2/3 cannot fire since exact is None and chunks are empty) | Expected under the contract given the likely content. If the CVE string is absent, dropping the fix diff is a second instance of Rule-4 evidence loss (patch semantics: `can_apply_to_report`, queryset restriction, GraphQL guard). Same indirect-mitigation note as above (kept contexts describe the patch). If the commit message does contain the CVE, this entry was kept and the batch's single `rejected` flag comes from the other rows — the per-CVE boolean cannot distinguish these cases, which is itself a finding about telemetry granularity. |
| `https://github.com/geo-chen/oss/blob/main/Ghostwriter.md` (public PoC; `source_type=github`) | None — replayed | `[narrative chunk]`: PoC title/body names the CVE and the swap endpoint — inferred kept (this is the "CVE in body" case the ranker's `_extract_github_body` fallback is built for) | `{CVE-2026-78203}` | pass | **kept** (no rule fires) | Expected keep. No loss; this is the highest-value kept context (curl commands, expected JSON, `leaked.docx` markers). |
| `https://www.vulncheck.com/advisories/ghostwriter-before-cross-client-report-template-disclosure-via-unauthorized-template-swap` (`source_type=other`) | `"<CVE-2026-78203> ..."` via `_find_exact_record` (advisory names the CVE) — replayed mechanism | `[exact_record]` — replayed mechanism | `{CVE-2026-78203}` | pass | **kept** (Rules 2+3 pass) | Expected keep. No loss; secondary corroboration retained. |

Net for 78203: `rejected=1` is the per-CVE boolean for "≥1 dropped"; the
dropped entries are the CVE-less github code pages via **Rule 4** (repo
root + vulnerable blob, and probably the fix commit). No Rule 1
(known-URL), Rule 2 (exact-record identity), Rule 3 (foreign-only), or
Rule 5 (dedup) involvement is indicated: entry URLs come from the same
`discovered_documents` set (Rule 1 passes by construction absent a
redirect rewrite), narrative entries have `exact=None` (Rule 2
inapplicable), and no second CVE id is documented in these pages
(Rule 3 needs a *found* foreign id — empty scoped text cannot trigger
it). Dedup (Rule 5) would require two canonical-equal URLs; the five URLs
are canonically distinct.

### CVE-2026-78205 (batch: `rejected=1`; CLI metadata proves 4 fetched → 1 kept, i.e. 3 dropped)

| URL | exact_record status | chunk status | CVE ids found | known_url check | rejected rule | assessment |
| --- | --- | --- | --- | --- | --- | --- |
| `https://github.com/bentoml/BentoML` (repo root; `source_type=github`) | None — replayed | `[]` (no CVE string on repo landing) — inferred + replayed | `{}` | pass | **Rule 4** | Expected under contract; negligible loss (no per-CVE evidence on a repo root). |
| `https://github.com/bentoml/BentoML/blob/v1.4.39/src/bentoml/_internal/utils/uri.py#L89-L96` (vulnerable guard; `source_type=github`) | None — replayed | `[]` (source file contains `is_private/is_loopback/is_link_local` guard, not a CVE string) — inferred + replayed | `{}` | pass | **Rule 4** | Expected under contract but **overly aggressive in effect**: the exact guard lines (`uri.py` L89–96) the advisory and stored research cite are removed from LLM input. Valid security evidence lost (code ground truth for the CGNAT bypass claim). Indirect mitigation: the kept advisory restates the guard condition. |
| `https://github.com/bentoml/BentoML/issues/5644` (reporter PoC issue; `source_type=github_issue` or `github_research` depending on `security_research_signal` tag) | None — replayed | Depends on whether the issue body at fetch time contained a `CVE-####-#####` string: (a) if it named `CVE-2026-78205` → narrative chunk kept; (b) if filed pre-assignment (CVE ids only in title metadata, not body) → `[]` → dropped. Stored research quotes the issue PoC (`100.64.1.1` bypass vs `192.168.0.1` block) AND the CLI shows only 1 kept context, so either (b) dropped it and the detail survived via the VulnCheck restatement, or (a) the issue IS the single kept context and the VulnCheck page was one of the dropped ones — the persisted booleans cannot resolve this. Both branches assessed. | (a) `{CVE-2026-78205}` → kept; (b) `{}` → dropped | pass | **Rule 4** under branch (b); **kept** under branch (a) | Expected under either branch per the contract. Under branch (b): aggressive — the primary PoC (httpx.ConnectTimeout vs "Connection blocked" comparison, entry points `MultipartSerde.ensure_file`/`JSONSerde.parse_request`) is first-hand evidence lost from LLM input, surviving only second-hand via VulnCheck. This is the largest single evidence-loss candidate in the batch. Under branch (a): no loss for the issue; the 3 drops are then repo root + blob + one redundant advisory copy. Either way ≥2 of the 3 drops are Rule-4 code/root pages. |
| `https://www.vulncheck.com/advisories/bentoml-through-server-side-request-forgery-via-unfiltered-rfc-6598-shared-address-space` (`source_type=other`) | `"<CVE-2026-78205> ..."` (advisory names the CVE; also names the incomplete-fix predecessor `CVE-2025-54381`) — replayed mechanism | `[exact_record]`; scoped CVE set = `{CVE-2026-78205, CVE-2025-54381}` — current id present so Rule 3 passes | `{CVE-2026-78205, CVE-2025-54381}` | pass | **kept** (Rules 2+3 pass; multi-CVE mention is fine when the current id is among them) | Expected keep. No loss. Note this row is why Rule 3 did NOT misfire on the predecessor-CVE mention — the gate's `cve_upper not in found` test correctly tolerates related-CVE context. |

Net for 78205: the 3 drops are Rule-4 empty-content drops of CVE-less
github pages (certain: repo root + source blob; probable: pre-assignment
issue body under branch (b)). No Rule 1/2/5 involvement for the same
structural reasons as 78203. Rule 3 is affirmatively *not* the cause for
the kept advisory despite its `CVE-2025-54381` mention — verified by
replay. The `reference_context_count: 1` in the stored CLI JSON is the
post-gate kept count, consistent with exactly one surviving advisory/issue
context reaching `SecurityResearcher`.

## 5. Per-rejection verdicts (as required)

- CVE-2026-78203 / repo root → **Rule 4**. Rejection expected per current
  gate contract: yes. Overly aggressive: no. Valid evidence lost: no.
- CVE-2026-78203 / vulnerable-code blob (`views.py` L275–L315) →
  **Rule 4**. Expected per contract: yes (narrative path + no CVE string
  ⇒ empty ⇒ drop). Overly aggressive: **yes in effect** — the rule cannot
  distinguish "chrome/boilerplate with no signal" from "vulnerable source
  file that never names its CVE". Valid evidence lost: **yes** (primary
  code evidence; indirectly mitigated by kept PoC/advisory quotations).
- CVE-2026-78203 / fix commit `5b2a4a2` → **Rule 4 (probable)**.
  Expected per contract: yes conditional on the commit message lacking the
  CVE string. Overly aggressive: yes in the same sense as the blob row.
  Valid evidence lost: patch diff semantics (partially mitigated via kept
  advisory/PoC descriptions). Confidence: medium (commit body not
  persisted; if it names the CVE the entry was kept instead).
- CVE-2026-78203 / geo-chen PoC → **kept**. N/A (no rejection).
- CVE-2026-78203 / VulnCheck advisory → **kept**. N/A.
- CVE-2026-78205 / repo root → **Rule 4**. Expected: yes. Aggressive: no.
  Lost: no.
- CVE-2026-78205 / vulnerable-guard blob (`uri.py` L89–96) → **Rule 4**.
  Expected: yes. Aggressive: **yes in effect**. Lost: **yes** (exact guard
  condition grounding; mitigated via advisory restatement).
- CVE-2026-78205 / issue #5644 → **Rule 4 under branch (b), else kept**.
  Expected under either branch: yes. Aggressive under branch (b): **yes —
  the most material candidate loss** (first-hand PoC comparison). Lost
  under (b): **yes, partially** (survives second-hand via VulnCheck, which
  the stored evidence itself labels SECONDARY). Telemetry cannot resolve
  branch (a) vs (b) — flagged as an observability gap, not a gate
  correctness claim.
- CVE-2026-78205 / VulnCheck advisory → **kept** (multi-CVE tolerant).
  N/A.
- Rule 1 (known-URL), Rule 2 (exact-record identity), Rule 5 (dedup):
  **no involvement indicated for any row in either CVE** — `known_urls` is
  derived from the identical document list, narrative entries carry
  `exact=None`, and the URL sets are canonically distinct.

## 6. Is `checked=3 rejected=2` healthy/expected?

Yes — healthy and expected for this batch composition, with one
telemetry-granularity caveat:

- `checked=3`: one gate evaluation per requested CVE (first occurrences;
  no duplicates in this batch), matching the documented
  `quality_events` semantics.
- `rejected=2`: exactly the two fresh CVEs whose NVD reference sets
  include CVE-less github code/root pages (78203: 5 URLs incl. repo root +
  two code/commit pages; 78205: 4 URLs incl. repo root + source blob (+
  possibly pre-assignment issue)). The anchor CVE-2026-1557
  (`rejected=0`) kept all its contexts because its material names its CVE.
  Zero provider outages/retries and zero reference-cache hits in the same
  aggregate confirm the rejections are gate-identity/content drops, not
  fetch failures or cross-CVE contamination.
- The LLM outcomes corroborate health: both CVEs completed (not
  degraded), decisions stayed conservative (`POSSIBLE` / `NOT_APPLICABLE`,
  `nuclei_candidate=false` with sound reasons), and evidence still cites
  file/line-level detail via the kept advisory/PoC contexts. Nothing
  indicates gate-induced hallucination or gate-induced decision flip.
- Caveat: the boolean-per-CVE telemetry records *that* ≥1 entry was
  dropped but not *which rule* or *how many*, so `rejected=2` alone cannot
  distinguish "dropped two boilerplate roots" from "dropped primary code
  + PoC". That distinction required this code-plus-artifact reconstruction
  and remains the reason a per-rule histogram (counts only, no URLs) would
  be worth considering — stated here as an observation only; **no fix is
  proposed or implemented per instructions**.

## 7. Method, limits, and reproducibility

- Files read: `ai/researcher/reference_quality.py` (gate contract +
  implementation), `ai/researcher/research_context.py`,
  `ai/collectors/reference_ranker.py` (`CVE_PATTERN`, narrative vs
  structured vs fallback paths), `ai/collectors/discovery.py`
  (`from_existing_references` source-type mapping),
  `ai/collectors/discovery_fetch.py`, `ai/researcher/cve_batch.py`
  (`_make_cached_research_fn`, `known_urls` construction, telemetry),
  `ai/research_cli.py` (single-CVE mirror),
  `ai/researcher/reference_cache.py` (canonicalization/dedup key),
  `ai/test_reference_quality_gate.py` + `ai/test_batch_reference_quality_parity.py`
  (contract tests; gate suite re-run green), stored artifacts
  `ai_data/research/batch-2026-09-07T072603.424405Z.json`,
  `batch-2026-09-07T070741.096002Z.json`, `CVE-2026-78203.cli.json`,
  `CVE-2026-78205.cli.json`, `CVE-2026-78207.cli.json`, and
  `agent-reports/cve-batch-quality-run-2026-09-06.md` (URL universe +
  fetch counts).
- Not available offline (no network/Mongo/LLM by instruction): live NVD
  reference lists, fetched page bodies at batch time, discovery ordering,
  and redirect-resolved `document.url` values. URL-role rows above are
  therefore mechanism determinations (exact code replayed against the
  URL's source-type class) rather than byte-level replays of the live
  pages; confidence is marked per row. No production file was modified;
  the diagnostic replay ran in-process with synthetic strings and left no
  artifacts in the repo.
- No fix proposed or implemented, per instructions.
