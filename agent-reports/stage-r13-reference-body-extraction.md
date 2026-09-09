# Stage R13 — Reference Body Extraction (Implementation Report)

## Summary

Stage R13 adds bounded, deterministic body extraction (HTML / Markdown /
PDF / plain text) with normalization, SHA-256 content hashing, and full
extraction provenance to the existing research reference pipeline. The
extracted bodies persist in the reference archives
(`ai_data/research/<CVE>.references.json`), flow into the Knowledge Base
via `kb ingest`, and widen the text the R12 deterministic intelligence
rules run over — with zero changes to R12 rule semantics. Verified live
against CVE-2024-5376 and regression-checked across all five staged CVEs.

## Scope of Changes

| File | Change |
|---|---|
| `ai/collectors/body_extraction.py` | New module. Limits + rule version (`BODY_EXTRACTION_RULE_VERSION="r13-1"`, `MAX_DOWNLOAD_BYTES=2MB`, `MAX_EXTRACTED_CHARS=200k`, `MAX_PDF_PAGES=60`, `MAX_PDF_BYTES=5MB`); statuses `ok`/`failed`/`empty`; `HTMLTextExtractor` (stdlib `HTMLParser`, skips script/style/noscript/svg/iframe/nav/footer/header, captures title); `ExtractedBody` dataclass; `sha256_text`; `normalize_text`; URL-suffix helpers; `sniff_content_type` (PDF magic → header → NUL-byte binary rejection → octet-stream/missing-header URL-suffix fallback); `extract_html`, `extract_markdown`, `extract_plain_text`, `extract_pdf` (pypdf, page-ordered, fail-soft), `extract_body` dispatcher. |
| `ai/schemas/reference.py` | Additive optional fields: `raw_content_hash`, `extraction_format`, `extraction_status`. `content_hash` documented as SHA-256 of the normalized persisted text; `None` on failure (never fabricated). Legacy records remain valid. |
| `ai/collectors/reference.py` | `HTMLTextExtractor` re-exported from `body_extraction.py` (single source of truth). `fetch()` rewritten: bounded read, content-type sniffing, extraction + hash + status. GitHub `blob`/`raw` → `raw.githubusercontent.com` rewrite (deterministic, exact-path, percent-encoding preserved; only for PDF-looking GitHub URLs; one raw fetch, no retries; original URL preserved as provenance). `_failed_document()` fail-soft path. `collect()` skips failed/empty extractions (hard misses) and dedupes by content hash. |
| `ai/collectors/discovery_fetch.py` | `fetch_discovered_sources` forwards `content_hash`, `raw_content_hash`, `extraction_format`, `extraction_status` and drops failed/empty extractions (hard misses). |
| `ai/research_cli.py` | `write_reference_archive` persists `body` + provenance per record (additive keys; archive version unchanged). New `refresh_reference_archive()` + `references refresh --cve <CVE>` CLI subcommand: re-fetches archived source URLs once each, updates body/provenance in place, atomic deterministic write, fail-soft on unreachable/unparseable sources (body cleared, `content_hash=None`, metadata preserved). |
| `ai/knowledge/ingestion.py` | `build_reference_documents` includes the record `body` (after title, before context chunks) in KB document content. Legacy body-less records unchanged. |
| `ai/knowledge/intelligence.py` | `_reference_sources` includes the record `body` (bounded by `MAX_INTELLIGENCE_TEXT_CHARS`) as explicit reference evidence. R12 rules untouched. |
| `ai/test_body_extraction.py` | New: 14 tests (extraction, hashing, fail-soft PDF, sniffing, hard-miss forwarding, archive body, refresh fail-soft, ingestion backward-compat, GitHub rewrite). |
| `ai/test_reference_ranker_technical_fallback.py` | Existing provenance-forwarding test extended for the R13 fields. |

## Hard Constraints Honored

- Research-only: no LLM/OpenRouter, no OCR, no browser, no subprocess, no
  crawler, no retries (each URL fetched at most once per refresh).
- `content_hash` is always the SHA-256 of the exact normalized persisted
  body text; never fabricated on failure (`None` records stay valid).
- Failed extractions remain hard misses in `discovery_fetch`,
  `write_reference_archive` provenance, and `collect()`.
- Original reference URLs are preserved verbatim (including
  percent-encoding); no URL corruption, no rewriting to the raw host.
- R12 rules unchanged; no forced XSS classification (see live result).


## Live Verification — CVE-2024-5376

Command: `python3 -m ai.research_cli references refresh --cve CVE-2024-5376`
→ `records: 1  bodies-updated: 1`.

- Archive record: the GitHub blob URL is preserved verbatim;
  `extraction_format=application/pdf`, `extraction_status=ok`;
  `content_hash=fa7a7caa66afb0ec…`; `raw_content_hash=a1d749203b85af70…`;
  body length 708 chars, extracted page-ordered by pypdf.
- Bounded body snippet (only this, per policy): *"XSS injection
  vulnerability exists in id parameter of view_each_faculty.php file of
  College Management System …"*.
- `kb ingest --cve CVE-2024-5376`: first run created
  `kb-43e8d2bf60dcbfed` (the body-bearing reference document); second run
  reports both documents `present` — ingest is idempotent and
  deterministic.

### R12 deterministic intelligence over the extracted body

- `vulnerability_types`: `['xss']` — now also evidenced directly from the
  extracted PDF body (evidence window includes
  `…exists in id parameter of view_each_faculty.php file of College
  Management Sy…`).
- `xss_types`: `[]` — the PDF states no reflected/stored/DOM phrasing
  meeting R12's strict rules; not forced.
- `parameters`: `[]` — the body's "id parameter of view_each_faculty.php"
  construction does not match the strict "the <name> parameter" /
  request-qualified patterns; not forced.
- This is the intended conservative outcome: the deterministic pipeline
  stays INSUFFICIENT_EVIDENCE for classification it cannot prove.

## Regression — 5-CVE Set

`references refresh` + `kb ingest` re-run for CVE-2024-27956,
CVE-2024-42327, CVE-2024-5376, CVE-2025-3102, CVE-2025-4893:

| CVE | records | hash_ok | hash_null | corrupt | ingest |
|---|---|---|---|---|---|
| CVE-2024-27956 | 5 | 5 | 0 | 0 | idempotent |
| CVE-2024-42327 | 2 | 2 | 0 | 0 | idempotent |
| CVE-2024-5376 | 1 | 1 | 0 | 0 | idempotent |
| CVE-2025-3102 | 0 | — | — | — | idempotent |
| CVE-2025-4893 | 1 | 1 | 0 | 0 | idempotent |

`hash_ok` means `sha256(body) == content_hash`; `corrupt` also checks URL
integrity (no `%0x`-mangled or space-containing URLs). All pass.

## Test Results

```
python3 -m unittest ai.test_body_extraction ai.test_reference_quality_gate \
  ai.test_reference_url_canonicalization ai.test_reference_cache \
  ai.test_reference_ranker_technical_fallback \
  ai.test_reference_quality_decision_boundary \
  ai.test_batch_reference_quality_parity ai.test_research_ingestion \
  ai.test_intelligence ai.test_knowledge_store ai.test_xss_researcher \
  ai.test_xss_llm_researcher ai.test_openrouter
Ran 318 tests in 1.737s — OK
```

`git diff --check`: clean. No commit/push performed.

## Security Notes

- PDF parsing is pypdf text-layer only: no OCR, no link handling, no
  embedded-content execution; page and byte caps bound worst-case work.
- Binary content (NUL bytes) is rejected before decode; decodes use
  `errors="replace"` — no crashes on hostile encodings.
- The refresh path uses dependency-injected collectors in tests; no
  test performs network I/O.
- No secrets touched or logged.

## Known Limitations

- `content_type` header is used for sniffing but not persisted on the
  schema (sniff result `extraction_format` is persisted instead).
- Scanned-image-only PDFs yield `empty` / `pdf_no_extractable_text` and
  stay hard misses — by design (no OCR).
- CVE-2025-3102's archive has 0 reference records; refresh is a no-op.

## Agent / Model

- Stage: R13
- Role: Reference Body Extraction
- Agent: Cline (Claude)
