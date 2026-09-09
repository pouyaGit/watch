# Stage R5 — First End-to-End Local Research Run: Execution Report

Integration only. No architecture changes, no new tests, no code fixes
were required: R1–R4 components composed without defects.

## 1. Exact commands executed

```bash
venv/bin/python -m ai.research_cli check
timeout 100 venv/bin/python -m ai.research_cli research --cve CVE-2026-1557 --skip-llm
venv/bin/python -m ai.research_cli kb ingest --cve CVE-2026-1557          # run twice
venv/bin/python -m ai.research_cli kb search --tag cve:CVE-2026-1557
venv/bin/python -m ai.research_cli kb show kb-609f38e9c57c0592
venv/bin/python -m ai.research_cli xss search --query "reflected XSS wordpress plugin parameter" --limit 5
venv/bin/python -m ai.research_cli xss research --query "WP Responsive Images path traversal src parameter file read"
venv/bin/python -m ai.research_cli xss research --query "reflected XSS wordpress plugin parameter"
venv/bin/python -m ai.research_cli xss show xss-0df931af429249e4
venv/bin/python -m ai.research_cli report --cve CVE-2026-1557            # run twice
venv/bin/python -m unittest ai.test_knowledge_store ai.test_research_ingestion \
  ai.test_xss_researcher ai.test_xss_agent ai.test_research_cli ai.test_reports_renderer
venv/bin/python -m unittest ai.test_knowledge_ingestion ai.test_xss_llm_researcher
```

## 2. Research provider availability

`check` reports MongoDB unreachable (`ServerSelectionTimeoutError`,
connection refused on 127.0.0.1:27017) although `.env` carries
`AI_PROVIDER`/`OPENROUTER_API_KEY`/`OPENROUTER_MODEL`/`WATCH_MONGO_URI`.
The fresh `research --skip-llm` run therefore fails with
`ERROR: ServerSelectionTimeoutError` at asset loading, before any
fetch/write (existing `CVE-2026-1557.cli.json` untouched, mtime still
Sep 6). No data invented. Stage proceeds on the persisted WSL artifact
`ai_data/research/CVE-2026-1557.cli.json` (5509 bytes) as the honest
research input.

## 3. Research artifact status

Existing `CVE-2026-1557.cli.json` used as-is: WP Responsive Images
path traversal, CVSS 7.5, unauthenticated `src` parameter,
4 correlated assets, `authoritative=False`.

## 4. Reference archive status

`ai_data/research/CVE-2026-1557.references.json` does NOT exist (never
persisted; the failed research run wrote nothing). Not fabricated.
Ingestion and report both record this honestly
(`references: archive not present`).

## 5. KB documents created

`kb ingest` created exactly **1** document: `kb-609f38e9c57c0592`
(same id as the R4 temp-store demo — deterministic across stores).
Provenance verified via `kb show`: `source_url=local://ai_data/
research/CVE-2026-1557.cli.json`, `source_type=research`, tags
`cve:CVE-2026-1557`+`research`, `evidence_quality=UNKNOWN`,
`confidence=0.0`. `kb search --tag cve:CVE-2026-1557` → 1 match.

## 6. Idempotent rerun result

Second `kb ingest` → `kb-609f38e9c57c0592 present`, `created=[]`;
store holds exactly 1 document. No duplicates.

## 7. XSS candidate results

- A) XSS-oriented `xss search` ("reflected XSS wordpress plugin
  parameter"): 3 matches; ingested `kb-609f38e9c57c0592` ranks with
  keyword reasons alongside seed docs. Persisted
  `xss-488f639165085224` → `INSUFFICIENT_EVIDENCE` (0.35), references
  include the ingested doc plus seed ids, unknowns list the missing
  exact context match.
- B) non-XSS `xss research` ("WP Responsive Images path traversal src
  parameter file read") → `xss-0df931af429249e4` → `REJECTED`,
  confidence 0.0, no evidence. The CVE's presence in the KB did NOT
  manufacture an XSS candidate.

## 8. Report path

`ai_data/reports/CVE-2026-1557.md` regenerated; §4 now reads
"KB documents checked: 1; matches: 1" (the CVE doc itself), §3 still
states the archive is unavailable, §5 retains the dry-run-only
verdict. Research evidence is never presented as a production finding.

## 9. Deterministic hash check

Two consecutive `report` runs → identical SHA-256
`44987a4e3bde1f3b3be572a07017f09afd08effc3f8992166e2d23717902828d`
(differs from the R2 hash only because the KB section now reflects the
populated store — correct deterministic behavior).

## 10. Safety/integrity checks

- `find -newer` sweep: new files exist ONLY under
  `ai_data/knowledge/`, `ai_data/reports/`, `ai_data/research/xss/`.
- `ai_data/nuclei/{results,findings}` untouched (Aug 27 / Sep 7).
- No production finding creatable (Mongo down; R2/R3/R4 import no
  production modules — test-enforced). No alerts, no live validation
  artifacts, no Nuclei execution. The only network event was the
  refused localhost Mongo connection — no target contacted.

## 11. Exact test counts

- Required six: knowledge store + research ingestion + XSS researcher
  + XSS agent + research CLI + reports renderer → **87 tests, all pass**.
- Adjacent: knowledge ingestion + XSS LLM researcher → **72 tests, all
  pass**. Total **159, OK**. Full-suite leftovers pre-existing,
  untouched per instructions.

## 12. Code changes

None. Zero lines modified or added for this stage.

## 13. Known limitations

- Fresh research impossible without Mongo (and, downstream, NVD/LLM
  reachability); the e2e chain starts from the Sep-6 persisted artifact.
- Reference archive absent → reference-doc ingestion path exercised by
  R4 synthetic tests only, not in this run.
- Real KB holds exactly the 1 ingested doc; seed still carries XSS
  matching weight until XSS research is ingested.

```
Report generated:
agent-reports/stage-r5-first-e2e-research-run.md
```
