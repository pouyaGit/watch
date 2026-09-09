# Stage R6 — Research Pipeline → Knowledge Base → XSS Agent Integration

## Summary

Audit + integration-verification stage over the R1–R5 chain
(research artifact → `kb ingest` → XSS agent → persisted candidate
JSON → read-only dashboard). Every link was exercised against the real
persisted CVE-2026-1557 artifacts with zero production-code changes
required: ingestion is deterministic and idempotent, the archive-absent
path is fail-soft and explicit, the XSS agent already pools real KB
documents with seed fixtures, evidence quality tiers stay distinct, and
the CLI workflow runs end to end offline. The stage deliverable is a
new deterministic E2E test (`ai/test_research_kb_xss_e2e.py`, 6 tests)
that proves the full chain on an isolated copy of the real artifact,
including double-ingestion idempotency and byte-identical candidate
reproduction of the real persisted candidates.

## Exact files changed

- Added: `ai/test_research_kb_xss_e2e.py` (6 tests, see § E2E test).
- Modified production code: **none** (zero lines). `ai/research_cli.py`,
  `ai/knowledge/ingestion.py`, `ai/researcher/xss_agent.py`,
  `ai/knowledge/store.py`, schemas, dashboard, and API are untouched.
- Modified existing tests: none.
- This report: `agent-reports/stage-r6-research-kb-xss-integration.md`.

## Architecture / data-flow changes

None — the audit confirmed the existing data flow is already correct:

```
ai_data/research/<CVE>.cli.json   (source of truth, required)
        │  (+ <CVE>.references.json, optional, fail-soft)
        ▼
kb ingest  →  KnowledgeStore (content-addressed, kb-<16>)
        │
        ▼
xss search / xss research  →  pool = seed ∪ store (dedup by knowledge_id)
        │  (fixed scoring: type+4 / context+4 / tech+2 / technique+1 /
        │   keyword+1 capped at 3; stable sort score↓, id↑)
        ▼
ai_data/research/xss/xss-<16>.json  →  read-only dashboard display
```

No new modules, no new packages, no workers/queues, no scheduler/daemon,
no architecture introduced.

## 1. Research → Knowledge Base audit (`kb ingest` path)

Code: `ai/knowledge/ingestion.py::ingest_cve_research` via
`ai/research_cli.py::run_kb_ingest`. Verified properties:

- Research JSON is the source of truth: one synthesis document per CVE,
  explicit fields copied verbatim in fixed section order; missing fields
  stay `UNKNOWN`/`0.0`/`None`; CVE travels in tags (`cve:<ID>`) + prose.
- Reference archive optional: absent archive → exit 0 with explicit note
  `references: archive not present (CVE-2026-1557.references.json)`
  (observed live). Present-but-sourceless records (no `source_url`) are
  skipped; URL-only records with no title/chunks/hash yield empty content
  and are skipped — no fake KB documents, no fabricated bodies.
- Deterministic IDs/hashes stable: identity is `sha256(content)` →
  `kb-<16>` via the store's own `content_hash`; `indexed_at` never leaks
  into identity; builders pure.
- Provenance preserved: synthesis docs use
  `source_url=local://<artifact path>`, `source_type=research`;
  reference docs keep the record's real URL/type.
- Idempotent: rerun converges (`created=[]`, `existing=[...]`, identical
  stored documents); duplicates impossible by content addressing.
- Failures fail-soft and explicit: missing/malformed CVE → `ERROR:
  ResearchIngestionError` on stderr, exit 1; corrupt store readback →
  `XSSAgentError`, exit 1. No tracebacks, no partial writes (atomic
  temp+rename).

## 2. Real CVE-2026-1557 verification

- Research artifact exists: `ai_data/research/CVE-2026-1557.cli.json`
  (WP Responsive Images path traversal, CVSS 7.5, `src` parameter).
- References archive behavior correct: no
  `CVE-2026-1557.references.json` on disk (R1 backfill gone, R5
  concurred) → ingestion records the absence honestly and creates no
  reference documents. Nothing fabricated.
- Live run `kb ingest --cve CVE-2026-1557` → `INGESTED`, single line
  `kb-609f38e9c57c0592 present` (already stored), plus the archive note,
  exit 0.
- Before/after KB document counts: **1 → 1** (no duplicates, no drift).
  Real store still holds exactly `kb-609f38e9c57c0592`;
  `ai_data/knowledge/index.json` untouched by this stage's testing
  (E2E snapshot guard enforces it).
- Provenance/source URLs correct: `source_type=research`,
  `source_url=local://ai_data/research/CVE-2026-1557.cli.json`, tags
  `cve:CVE-2026-1557` + `research`, `evidence_quality=UNKNOWN`,
  `confidence=0.0` (verified via CLI `kb show` readback and the E2E test).

## 3. XSS agent over real KB

No change needed — `xss_agent._pool_documents` already unions bundled
seed fixtures (`ai/researcher/xss_seed/`, deterministic baseline, always
available) with `KnowledgeStore.retrieve()`, deduped by `knowledge_id`.
Live `xss search --query "reflected XSS wordpress plugin parameter"`
over the real store:

- `kb-0958da2bb9935000` score 6 (xss_type exact + keywords) — seed,
- `kb-59a0bec7d50e6054` score 6 — seed,
- `kb-609f38e9c57c0592` score 3 (keyword-only) — real ingested CVE doc.

Ranking deterministic (score desc, id asc); exact type/context matches
remain strongest; no LLM/network required; nothing executed; no
production finding created; legacy `XssFindings` never imported or
queried (AST + grep verified).

## 4. XSS evidence quality

Inspected persisted candidates `xss-488f639165085224`
(`INSUFFICIENT_EVIDENCE`, 0.35) and `xss-0df931af429249e4` (`REJECTED`,
0.0), plus live rebuilds:

- KB references traceable: `references` lists every matched
  `knowledge_id`; `source_evidence` carries per-match id/title/score/
  human-readable reasons (e.g. `xss_type exact match: reflected`).
- Source evidence preserved through persist/reload round-trip
  (sorted keys, atomic write).
- Statuses deterministic and distinct: type+context exact on top match
  → `RESEARCH_CANDIDATE`; weaker positive match →
  `INSUFFICIENT_EVIDENCE` with unknowns naming the missing exact match;
  no signals/matches → `REJECTED`. Confidence deterministic by formula
  (REJECTED 0.0, insufficient ≤0.35, candidate ≤0.9).
- No evidence upgrade by mere existence: the ingested CVE doc
  contributes keyword reasons only (it carries no `xss_types`/`contexts`,
  so exact-match reasons are impossible for it); the non-XSS traversal
  query honestly yields `REJECTED` with empty evidence/references —
  the agent does not launder non-XSS research into XSS candidates.
- No vulnerability claim invented: every candidate carries the
  research-candidate disclaimer, untested test idea marked never
  executed, and `live reflection: not observed` /
  `exploitability: unconfirmed by design` unknowns.

## 5. CLI workflow

Intended workflow verified working offline, no CLI changes required:

```bash
venv/bin/python -m ai.research_cli kb ingest --cve CVE-2026-1557
venv/bin/python -m ai.research_cli kb search --tag cve:CVE-2026-1557
venv/bin/python -m ai.research_cli xss search --query "reflected XSS wordpress plugin parameter" --limit 5
venv/bin/python -m ai.research_cli xss research --query "..."   # persists candidate, repeat is byte-identical
venv/bin/python -m ai.research_cli xss show <candidate_id>
# → persisted candidate JSON → dashboard read-only display (D2–D5, untouched)
```

Failure paths stay explicit (`ERROR:` + exit 1 on malformed/empty
query, unknown/malformed ids, missing CVE). No scheduler or daemon added.

## 6. Real-data E2E test (`ai/test_research_kb_xss_e2e.py`, 6 tests)

Isolated temp copy of the real `CVE-2026-1557.cli.json` bytes → temp
`KnowledgeStore` → temp XSS dir. Real `ai_data/` is read-only input;
a SHA-256 snapshot guard fails the test on any real-tree write.

1. `test_research_to_kb_to_candidate`: ingest → exactly
   `[kb-609f38e9c57c0592]` created + archive-absent note; second ingest
   → `created=[]`, store holds 1 doc; provenance/tag assertions; XSS
   query → `xss-488f639165085224` / `INSUFFICIENT_EVIDENCE` / 0.35 with
   the ingested doc in evidence (keyword reasons only, no exact-match
   reasons) and in references; persist → reload round-trip; repeat
   persist byte-identical.
2. `test_non_xss_research_is_rejected_not_laundered`: traversal query →
   `xss-0df931af429249e4` / `REJECTED` / 0.0, empty evidence, ingested
   id absent from references.
3. `test_url_list_only_archive_creates_no_reference_documents`:
   R1-backfill-shaped archive (URL, null body) → still exactly 1 doc.
4. `test_cli_workflow_reliable_offline`: `run_kb_ingest` twice + 
...[truncated 3075 chars]
