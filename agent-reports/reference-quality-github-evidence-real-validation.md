# Reference Quality GitHub Evidence Retention — Real Research-Only Validation

Validation stage only. No production code, tests, schemas, or telemetry
were modified. No git operations performed. No Nuclei runs against
targets. No target-side HTTP probing. No authoritative findings. No
5J/materialization/alerts/notifications.

## 1. Run metadata

- Validation date (UTC): 2026-09-07
- Feature under validation: provenance-gated technical GitHub fallback
  in `ai/collectors/reference_ranker.py`
  (`_technical_github_fallback`, `TECHNICAL_GITHUB_PATH_SEGMENTS`,
  `CVE_CORRELATED_DISCOVERY_TAGS`), fed by ephemeral discovery
  provenance forwarded in `ai/researcher/research_context.py`, gated by
  the unchanged `gate_reference_contexts` in
  `ai/researcher/reference_quality.py`.
- BEFORE baseline: `ai_data/research/batch-2026-09-07T072603.424405Z.json`
  (+ `agent-reports/cve-batch-run-2026-09-07T072603.424405Z.md`),
  generated 2026-09-07T07:26:03Z.
- AFTER run (this validation):
  `ai_data/research/batch-2026-09-07T103348.083192Z.json`
  (+ `agent-reports/cve-batch-run-2026-09-07T103348.083192Z.md`),
  generated 2026-09-07T10:33:48Z.
- Code-timing note (filesystem mtimes, no git used):
  `ai/collectors/reference_ranker.py`,
  `ai/researcher/research_context.py`, and `ai/researcher/cve_batch.py`
  were all modified between the two batch timestamps, while
  `ai/researcher/reference_quality.py` is unchanged since 2026-09-06.
  The BEFORE batch therefore ran without the retention fallback; the
  AFTER batch ran with it. Both runs used the same quality gate.
- BEFORE per-CVE context-count caveat: the batch flow persists only
  counts-only `reference_quality` per CVE, not full research payloads,
  so BEFORE `reference_context_count` values below are *inferred by
  static code-path analysis* (old ranker: a fetched GitHub page whose
  text contains no CVE id yields zero narrative chunks, and the gate
  drops chunk-less entries as empty), not read from a persisted
  artifact. AFTER counts are *measured* by a read-only replay of the
  deterministic discovery → fetch → rank → gate pipeline (no LLM, no
  repo writes; scratch scripts in `/tmp` only).

## 2. Exact command

`/tmp/cve-batch-3.txt` already existed with exactly the required CVEs
(verified before the run; no edit needed):

```text
CVE-2026-1557
CVE-2026-78203
CVE-2026-78205
```

Command executed (working directory `/opt/watch`):

```bash
python3 -m ai.research_cli batch --file /tmp/cve-batch-3.txt
```

Stdout:

```text
CVE-2026-1557: completed
CVE-2026-78203: completed
CVE-2026-78205: completed
BATCH DONE: processed=3 failed=0
AGGREGATE: ai_data/research/batch-2026-09-07T103348.083192Z.json
REPORT: agent-reports/cve-batch-run-2026-09-07T103348.083192Z.md
MODE: research-only (authoritative=False, no live execution)
```

## 3. Batch result

AFTER aggregate (`batch-2026-09-07T103348.083192Z.json`):

| CVE | research_status | nuclei_candidate | decision | confidence | template_generated | error |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2026-1557 | completed | False | GOOD_CANDIDATE | 0.95 | True | — |
| CVE-2026-78203 | completed | False | NOT_APPLICABLE | 0.95 | False | — |
| CVE-2026-78205 | completed | False | NOT_APPLICABLE | 0.95 | False | — |

Batch completion status: **3 requested, 3 processed, 3 completed,
0 completed_degraded, 0 failed.** No per-CVE errors; both 7820x
`nuclei_error` fields carry the same pre-existing informational string
as BEFORE (`no source template for <CVE>: decision only, no
generation`) — unchanged behavior, not a failure.

## 4. Aggregate telemetry

| Signal | BEFORE (072603) | AFTER (103348) | Delta |
| --- | --- | --- | --- |
| completed / processed / failed | 3 / 3 / 0 | 3 / 3 / 0 | none |
| completed_degraded | 0 | 0 | none |
| provider_outages http_402 / http_429 / http_5xx / network | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | none |
| provider_retries attempted / succeeded / exhausted | 0 / 0 / 0 | 0 / 0 / 0 | none |
| provider_cache hits | 0 | 0 | none |
| reference_cache hits | 0 | 0 | none (expected: the three CVEs share no reference URLs) |
| reference_quality checked / rejected | 3 / 2 | 3 / 2 | none (counts identical; *meaning* changed — see §6) |

Per-CVE `reference_quality`: `{checked:1, rejected:0}` for 1557 and
`{checked:1, rejected:1}` for each of 78203/78205 — byte-identical to
BEFORE in all three cases.

## 5. Per-CVE comparison: BEFORE vs AFTER

`*` = inferred for BEFORE (see §1 caveat); all AFTER values measured.

| CVE | Before contexts | After contexts | Before rejected | After rejected | Decision Before | Decision After | Evidence improved? | Regression? |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2026-1557 | 5 | 5 | 0 | 0 | GOOD_CANDIDATE 0.95 (candidate=True) | GOOD_CANDIDATE 0.95 (candidate=False) | n/a — unchanged | No (§9) |
| CVE-2026-78203 | 1* (advisory only) | 4 | 1 | 1 | POSSIBLE 0.80 | NOT_APPLICABLE 0.95 | Yes (§7) | Decision label changed — observation, not pipeline failure (§10) |
| CVE-2026-78205 | 1* (advisory only) | 2 | 1 | 1 | NOT_APPLICABLE 0.95 | NOT_APPLICABLE 0.95 | Yes (§8) | No |

## 6. Reference context retention analysis

Measured AFTER state via read-only deterministic replay
(discovery limit 5, real fetch, rank, gate):

- **CVE-2026-1557**: discovered 5 (GitHub code-search results keyed on
  `cve_in_title`/`cve_in_body` tags), fetched 5, raw 5, kept 5,
  rejected=False. All five kept contexts are CVE-anchored narrative
  slices (chrome-free, 2812–6213 chars) that mention CVE-2026-1557.
  Identical shape to BEFORE — the retention fallback was never needed
  here and changed nothing.
- **CVE-2026-78203**: discovered 5 (4× `nvd_reference`-tagged GitHub
  URLs + VulnCheck advisory), fetched 5, raw 5, kept 4,
  rejected=True. Kept: vulnerable-source blob, fix commit, researcher
  PoC write-up, VulnCheck advisory (exact record). Dropped: repository
  root only (zero chunks → gate rule 4).
- **CVE-2026-78205**: discovered 4 (3× `nvd_reference`-tagged GitHub
  URLs + VulnCheck advisory), fetched 4, raw 4, kept 2,
  rejected=True. Kept: vulnerable-guard blob, VulnCheck advisory
  (exact record). Dropped: repository root (zero chunks) and issue
  #5644 (foreign-CVE-only → gate rule 3; see §8).

Why identical `rejected` counts still mean improvement: BEFORE,
`rejected=1` meant "the only GitHub evidence was lost and the LLM saw
just the advisory". AFTER, `rejected=1` means "only the repository
root (78203) / root + foreign-scoped issue (78205) was excluded while
all provenance-qualified technical evidence was retained". The count
hides a qualitative inversion from evidence-loss to evidence-retention.

A higher `reference_context_count` was NOT treated as automatically
better: every additional retained context was inspected for technical
substance (§7, §8, §11). All retained GitHub URLs are NVD-referenced
for the exact CVE under research; slices are verbatim source text with
`exact_record=None` (no CVE id, severity, exploit, remediation, or
trust claim fabricated); repository roots yield zero chunks and stay
excluded.

## 7. CVE-78203 evidence analysis

- **Ghostwriter vulnerable source evidence retained: YES.**
  `.../Ghostwriter/blob/v7.1.1/ghostwriter/reporting/views.py#L275-L315`
  (NVD-referenced, `nvd_reference` tag, query == CVE id) is retained
  with a 2555-char verbatim slice. Content characterization (honest):
  the slice carries file identity/version metadata (repo, tag v7.1.1,
  `views.py`, 1036 lines / 38.3 KB) plus page chrome and the line-number
  gutter — the anchored lines 275–315 themselves are NOT reached
  because the fetcher returns rendered GitHub HTML and the
  keyword-anchored fallback found no vendor/product keyword hit, so the
  head slice was kept. Provenance-correct file pointer; code content
  partial. No code identifiers (`ReportTemplateSwap`, `user_can_edit`)
  in this slice.
- **Fix commit evidence retained: YES, with substance.**
  `.../Ghostwriter/commit/5b2a4a297e44c823c16f65b1ba101c742791cd0b`
  is retained (2539 chars); the slice contains real diff tokens
  (`docx_template`, `pptx_template`) and the commit title ("Restricted
  templates swaps on reports").
- **Researcher PoC retained: YES, with substance.**
  `.../geo-chen/oss/blob/main/Ghostwriter.md` is retained (3293
  chars) with `ReportTemplateSwap`, `user_can_edit`, `docx_template`,
  `pptx_template` all present.
- **Repository root excluded: YES.**
  `https://github.com/GhostManager/Ghostwriter` yields zero chunks
  (boilerplate only) and is dropped by the gate — the single
  `rejected=1` for this CVE.
- **Advisory unchanged:** VulnCheck exact record scoped to
  CVE-2026-78203 retained as before.

## 8. CVE-78205 evidence analysis

- **BentoML `uri.py` vulnerable guard evidence retained: YES, with
  substance.** `.../BentoML/blob/v1.4.39/src/bentoml/_internal/utils/uri.py#L89-L96`
  is retained (2499 chars). Because `uri.py` is small (117 lines),
  the bounded slice reaches genuine source: imports
  (`ipaddress`, `urlparse`, …), `uri_to_path`, `encode_path_for_uri`,
  `is_http_url`, and surrounding helpers. File/version metadata
  (tag v1.4.39, 3.16 KB) also present.
- **Issue #5644: correctly NOT retained — its provenance does not
  qualify.** The fetched issue page text mentions **CVE-2025-54381**
  and does **not** mention CVE-2026-78205 anywhere in its full text,
  so the gate's CVE-identity rule drops it as foreign-CVE-only. The
  ranker's provenance gate (NVD tag + query == CVE) let it *reach*
  the gate, but content scoping failed closed exactly as designed.
  This is the feature working, not a gap: retaining it would have
  attached another CVE's issue thread to this CVE's research.
- **Repository root excluded: YES.**
  `https://github.com/bentoml/BentoML` yields zero chunks and is
  dropped — same as BEFORE.
- **Advisory unchanged and correctly scoped:** VulnCheck exact record
  for CVE-2026-78205 retained; the advisory page also references
  CVE-2025-54381 and issue #5644 as *references*, but the extracted
  exact record is scoped to CVE-2026-78205 and the kept chunk carries
  `make_safe_connect`, `100.64`, `CGNAT`, `RFC 6598`, `SSRF`.

## 9. CVE-1557 regression analysis

Known-good behavior intact:

- `research_status=completed`, decision `GOOD_CANDIDATE` at 0.95,
  `template_generated=True`, `semantic_validation.valid=True`,
  `reference_quality={checked:1, rejected:0}` — all identical to
  BEFORE.
- All 5 reference contexts retained before and after (CVE-anchored
  narrative slices; the three crowdsec roundup issues legitimately
  list CVE-2026-1557 among many CVEs, so they are kept by design —
  they are not foreign-only).
- One cosmetic flag delta: `nuclei_candidate` True → False while the
  decision, confidence, template generation, and semantic validation
  are unchanged. This flag is the LLM-side candidacy judgment, not a
  pipeline outcome; it had zero material effect (template still
  generated, same decision). Documented as LLM variance, not a
  regression. No re-run was triggered to chase a flag with no
  downstream effect.

## 10. Nuclei decision comparison

| CVE | BEFORE | AFTER | Material change? |
| --- | --- | --- | --- |
| CVE-2026-1557 | GOOD_CANDIDATE, template generated | GOOD_CANDIDATE, template generated | No (candidate flag flip only, §9) |
| CVE-2026-78203 | POSSIBLE 0.80, no template | NOT_APPLICABLE 0.95, no template | Label changed; generation outcome identical (no template either run) |
| CVE-2026-78205 | NOT_APPLICABLE 0.95, no template | NOT_APPLICABLE 0.95, no template | No |

On the CVE-2026-78203 `POSSIBLE → NOT_APPLICABLE` change: no pipeline
error, no provider outage, no degraded status, and no schema/LLM
failure accompanies it — both runs are clean `completed` outcomes, so
this is distinguished from a pipeline regression. Plausible
contributors are (a) LLM judgment variance across runs and/or (b) the
newly retained evidence (end-to-end PoC plus the v7.1.2 fix commit
framing the bug as an authenticated, multi-client template-scope
issue with no black-box signature). Causality cannot be proven from
batch artifacts because the BEFORE run's context list was not
persisted. The generation-relevant outcome is unchanged (no source
template either run), and the retained evidence itself is verified
sound (§7), so this is recorded as an observation to monitor, not a
blocker.

## 11. False-positive inspection

Question: was any irrelevant GitHub material accidentally retained?

- **No.** Every retained GitHub URL in the AFTER run is an
  NVD-supplied reference for the exact CVE under research
  (`nvd_reference` tag with discovery query == CVE id in all six
  7820x GitHub cases).
- Segment-boundary path check holds: only `blob`/`commit`/`issues`
  pages with `/<owner>/<repo>/<kind>/...` depth were retained; both
  repository roots produced zero chunks and were dropped.
- CVE-less retained slices contain **zero** CVE ids in their full
  scoped text (verified over the complete chunk text, not just
  heads), so no foreign-CVE attribution could leak through them, and
  `exact_record` remains `None` for all of them (no identity claim
  fabricated).
- Chrome boilerplate is present in retained slices (fetcher returns
  rendered GitHub HTML) — noise, not misinformation: it carries no
  CVE, severity, exploit, or remediation claim. Improvement candidate
  for the fetcher/ranker, documented without code changes.

## 12. False-negative inspection

Question: was any qualifying technical evidence lost?

- **CVE-2026-78203**: all three technical GitHub references (vuln
  source blob, fix commit, PoC write-up) retained. Nothing
  qualifying dropped.
- **CVE-2026-78205**: `uri.py` blob retained; issue #5644 dropped
  only because its page content is scoped to CVE-2025-54381 (see
  §8) — correct exclusion, not a false negative.
- **CVE-2026-1557**: all five CVE-mentioning contexts retained, as
  before.
- Residual limitation (not a regression): for large files, the
  bounded head slice may not reach the anchored lines (views.py
  L275–L315). Small files (uri.py) and diff/issue/prose pages retain
  substantive content. No CVE-less page that contained the current
  CVE id was dropped; no qualifying page was observed missing.

## 13. Provider/cache behavior

- **Provider outages: none** in either run
  (`http_402=0, http_429=0, http_5xx=0, network=0`).
- **Provider retries: none attempted** in either run
  (`attempted=0, succeeded=0, exhausted=0`); no 429/5xx path
  exercised, so retry behavior is unvalidated by this batch (neutral,
  not negative).
- **Provider cache hits: 0; reference cache hits: 0** in both runs.
  Zero reference-cache hits is expected: the three CVEs share no
  reference URLs, and each URL is fetched once.
- **No LLM/schema/provider failure occurred**: all three CVEs
  `completed` (zero `completed_degraded`), no `llm_error`, no
  exception payloads, no fail-soft artifacts in the AFTER aggregate.

## 14. Security boundary verification

- Batch mode `research-only`, `authoritative=False` on the aggregate
  and every per-CVE result — confirmed in the persisted artifact.
- No SealedFinding / 5J / CONFIRMED materialization exists in this
  lane; the only Nuclei artifact touched is the pre-existing
  offline-generated `CVE-2026-1557` template path with
  `candidate_count=0`, zero targets, zero run results, zero findings.
- No Watch asset contacted: offline selection empty, no
  fingerprinting (`fingerprint_performed=False`), no subprocess
  (`nuclei -validate` skipped by design with warnings recorded).
- HTTP traffic in this validation was limited to public reference
  reads (NVD API, GitHub reference pages, VulnCheck advisories) via
  the existing research-only collectors — no target-side probing.
- **Explicit statements:**
  - No repository root was retained for any CVE (both roots yield
    zero chunks and are gate-dropped).
  - No foreign-CVE-only context survived (issue #5644 correctly
    dropped; every kept context mentions the current CVE or no CVE
    at all).
  - No non-GitHub context changed unexpectedly (VulnCheck advisory
    exact records retained identically; 1557's GitHub-search
    contexts byte-comparable in shape to BEFORE).
  - No LLM/schema/provider failure occurred (§13).

## 15. Final verdict

**GO WITH OBSERVATION**

- The retention feature does what it claims on real data: 78203 went
  from ~1 to 4 contexts (vuln-source blob, fix commit, PoC, advisory)
  and 78205 from ~1 to 2 (guard-source blob, advisory), while both
  repository roots stayed excluded, the foreign-scoped issue #5644
  stayed excluded, and the known-good 1557 flow is byte-for-byte
  equivalent in every material outcome.
- Observations (no code changes made; documenting only):
  1. CVE-2026-78203's LLM decision label moved `POSSIBLE (0.80)` →
     `NOT_APPLICABLE (0.95)` with identical generation outcomes.
     Clean pipeline both runs; treat as LLM-variance watch item and
     compare again on the next batch rather than blocking on it.
  2. Retained blob slices for large files are chrome-prefixed head
     slices that may not reach the anchored lines (views.py case);
     the provenance pointer and version metadata are correct but a
     future fetcher/ranker pass could anchor slices on the referenced
     line range or strip UI chrome. Small-file/diff/prose evidence
     already retains substantive content.
  3. `nuclei_candidate` for CVE-2026-1557 flipped True → False with
     no downstream effect (same decision, template still generated).
     Cosmetic LLM variance; no action.
