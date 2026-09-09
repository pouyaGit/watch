# Stage R4 — Research-to-Knowledge Ingestion: Implementation Report

## 1. Architecture

One focused module plus additive CLI/tests:

- `ai/knowledge/ingestion.py` (new) — pure builders plus thin
  store-writing passes. No network, no LLM, no subprocess, no Nuclei.
- `ai/research_cli.py` (`kb ingest`, append-only) — `run_kb_ingest`
  with `store`/`research_dir` overrides for offline tests.
- `ai/test_research_ingestion.py` (new) — 19 focused tests.

It reuses the existing `KnowledgeStore.ingest` API for all writes, so
content addressing, deterministic `knowledge_id`s and merge semantics
are inherited, not reimplemented. The R3 seed pool is untouched
(`seed KB ∪ persisted KnowledgeStore` with `knowledge_id` dedup
already in `xss_agent._pool_documents`).

## 2. Input/output

Input: `ai_data/research/<CVE>.cli.json` (required) and
`<CVE>.references.json` (optional, fail-soft with a note).
Output per CVE: one synthesis document (title/summary/root cause/
evidence/etc. copied verbatim in fixed section order) plus one
document per reference record (title + `context_chunks` + persisted
`content_hash` line). Only explicitly present fields are copied;
missing fields stay `UNKNOWN`/`0.0`/`None`; the CVE travels in tags
(`cve:<ID>`) and prose since `KnowledgeDocument` has no CVE field.

## 3. Provenance model

Every document answers "where did this come from": synthesis docs use
`source_url = local://<artifact path>`, `source_type = research`;
reference docs keep the record's real `source_url`/`source_type`.
Records without a source URL are skipped (no provenance → no
document). No stronger claim than the input supports:
`evidence_quality = UNKNOWN`, `confidence = 0.0`.

## 4. Deterministic ID/hash strategy

Identity is `sha256(content)` → `knowledge_id = kb-<16>`, computed by
the store's own `content_hash`. Builders are pure: same payload bytes
→ same `content` string (verified by test). `indexed_at` wall-clock
never leaks into identity.

## 5. Idempotency behavior

Re-ingest converges: first run `created=[...]`, rerun `created=[]`,
`existing=[...]`, identical ids and identical stored documents
(`model_dump` equality asserted). Duplicates are impossible by content
addressing; same-content re-ingest merges to the same aggregate.
`--dry-run` previews `would-create`/`present` via read-only
`get_by_hash` and writes nothing (index file asserted absent).

## 6. CLI examples

```bash
python3 -m ai.research_cli kb ingest --cve CVE-2026-1557 --dry-run
python3 -m ai.research_cli kb ingest --cve CVE-2026-1557
python3 -m ai.research_cli kb ingest --cve CVE-2026-1557 --references-only  # archive path
```

Dry-run output for the real artifact: `kb-609f38e9c57c0592
would-create`, note `references: archive not present`, exit 0, and no
`ai_data/knowledge/` created.

## 7. Sample ingestion result (CVE-2026-1557, temp KB)

Pipeline demonstrated end to end with only local data:

1. research → KB: `ingest_research('CVE-2026-1557', store)` created
   `kb-609f38e9c57c0592` ("WP Responsive Images plugin <=1.0 …").
2. KB search: `retrieve(tags=['cve:CVE-2026-1557'])` returns it.
3. XSS search: query "wordpress plugin src parameter traversal" ranks
   the ingested doc top (score 3, keyword reasons) above seed docs.
4. candidate: query "reflected xss in wordpress plugin parameter" →
   `INSUFFICIENT_EVIDENCE` with references
   `[kb-0958da…, kb-59a0be…, kb-609f38…]` — the ingested doc pools with
   seed naturally. A non-XSS query against the traversal CVE honestly
   yields `REJECTED` (no XSS signals), proving the agent does not
   launder non-XSS research into XSS candidates.

## 8. Exact test counts

- New `ai.test_research_ingestion`: **19 tests, all pass** (CVE +
  archive ingestion, deterministic IDs/hashes, provenance, idempotent
  rerun, duplicates, missing/malformed/empty input, sourceless-record
  skip, dry-run no-writes, import scan + blocked-module execution, XSS
  visibility, seed/store dedup, CLI ingest/dry-run/failure/parser).
- Regression (venv): ingestion + knowledge store + knowledge ingestion
  + XSS researcher + XSS LLM researcher + XSS agent + research CLI +
  reports renderer → **159 tests, all pass** (`Ran 159 ... OK`).
- Full-suite leftovers are pre-existing/environmental; not attempted.

## 9. Changed files

Added: `ai/knowledge/ingestion.py`, `ai/test_research_ingestion.py`.
Modified (append-only, 0 removed lines each): `ai/research_cli.py`
(`kb ingest` parser + `run_kb_ingest` + dispatch),
`ai/schemas/xss.py` was R3 (untouched here). `git diff --check` clean.

## 10. Known limitations

- No `<CVE>.references.json` exists yet, so reference-doc output is
  covered by synthetic archives in tests only.
- The real `ai_data/knowledge/` store is still empty; the demo ran in
  a temp KB, so the repo ships capability, not populated knowledge.
- `technologies` copies artifact values verbatim (no taxonomy
  mapping); `xss_types`/`contexts` are never inferred, so ingested
  non-XSS research matches XSS queries by keyword only.
- CVE lives in tags/prose (schema has no CVE field) — consumers must
  query `tags=['cve:<ID>']`.

## 11. Production/live-validation confirmation

Confirmed untouched: nothing under `ns/`, `crawl/`, `database/`,
nuclei/CVE logic, `ai/live_validation/`, `ai/execution/`,
`ai/finding/`, `ai/verification/`, or 5B–5J was modified, and the
ingestion module imports none of them (test-enforced). No live target
testing, no exploitation, no Nuclei execution, no alerts/findings/
materialization. Pre-existing dirt (`M database/db.py`, deleted
`Zone.Identifier`) left alone. No commit, no push.

```
Report generated:
agent-reports/stage-r4-research-to-knowledge.md
```
