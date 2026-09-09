# Stage R3 — XSS Research Agent MVP: Implementation Report

## 1. Architecture

Small deterministic agent, three new pieces plus additive CLI:

- `ai/researcher/xss_seed/*.json` (3 files) — bundled deterministic
  seed KB covering the required categories: `reflected/html_attribute`
  (quoted attribute breakout), `reflected/script` (script-block string
  termination), `dom/javascript` (location.hash → innerHTML). Fixture
  style (`research.example.test` URLs), no live targets.
- `ai/researcher/xss_agent.py` — seed loading (seed JSON validated as
  `KnowledgeDocument`, `knowledge_id`/`content_hash` derived via the
  existing `content_hash` helper), pool = seed ∪ `KnowledgeStore.retrieve()`
  deduped by `knowledge_id`, query-signal parsing, scoring/ranking,
  candidate building, atomic persistence.
- `ai/schemas/xss.py` (append-only) — `XSSCandidateSourceEvidence`,
  `XSSAttributedSink`, `XSSResearchCandidate` (status, evidence, pattern,
  injection context, sinks/sources, preconditions, test idea, confidence,
  unknowns, KB references, exploitability disclaimer).
- `ai/research_cli.py` (append-only) — `xss list|search|research|show`
  following the existing `kb` conventions (`run_xss_*` helpers accept
  `store`/`research_dir` overrides for offline tests).

Candidates persist to `ai_data/research/xss/<candidate_id>.json`
(sorted keys, atomic write, no timestamps).

## 2. Matching/ranking logic

Query signals from fixed keyword tables (types: reflected/stored/dom;
contexts: html_attribute/script/javascript; generic XSS flag), plus
optional explicit `--xss-type`/`--context`/`--technology`/`--technique`
flags. Integer weights: type exact +4, context exact +4, technology
overlap +2 each, technique overlap +1 each, keyword-in-text +1 each
(capped at 3). Ranking is stable: score desc, `knowledge_id` asc. Every
match carries `reasons` (e.g. `xss_type exact match: reflected`).
Sinks/sources come from a fixed vocabulary extracted ONLY when literally
present in matched documents, each attributed with `knowledge_ids`.

Status: both type+context exact on the top match → `RESEARCH_CANDIDATE`;
any weaker positive match → `INSUFFICIENT_EVIDENCE` (unknowns list what
is missing); zero matches or no XSS signals → `REJECTED`. Confidence is
a documented deterministic formula (REJECTED=0.0, insufficient ≤0.35,
candidate ≤0.9) labeled research confidence only. `candidate_id` =
`xss-` + sha256(version|query|signals|id:score…), so repeats are
byte-identical. No exploitability is ever claimed; the disclaimer and
`test_idea` ("Untested idea only — never executed") are baked into every
candidate.

## 3. CLI usage

```bash
python3 -m ai.research_cli xss search --query "reflected attribute" [--json]
python3 -m ai.research_cli xss research --query "..." [--xss-type dom --context javascript] [--output PATH]
python3 -m ai.research_cli xss list
python3 -m ai.research_cli xss show xss-60edf609e21c6b41 [--json]
```

Empty queries and unknown/malformed ids exit 1 with `ERROR:` on stderr.

## 4. Sample candidate

`ai_data/research/xss/xss-60edf609e21c6b41.json`
(query "reflected XSS in HTML attribute via search parameter"):
`RESEARCH_CANDIDATE`, type `reflected`, context `html_attribute`,
confidence 0.9, 3 evidence entries with per-reason attribution
(top: `kb-0958da2bb9935000`, score 11), sinks `inline script`/`innerhtml`
and sources `query parameter`/`location.hash`/`fragment` each with KB
refs, preconditions, untested test idea, unknowns
(`live reflection: not observed`, `exploitability: unconfirmed by
design`). Re-running the same command yields the identical SHA-256
(`59334faf…02183bda1` twice).

## 5. Safety guarantees

- Read-only w.r.t. targets: no sockets/HTTP clients/subprocess/browser
  in top-level imports (test-enforced), and `build_candidate` renders
  correctly with `socket`/`urllib.request`/`requests`/`subprocess`
  blocked from `sys.modules`.
- No LLM (no `ai.llm`/provider imports), no Nuclei, no production
  verifier, no finding materialization, no alerting, no Mongo.
- Agent writes ONLY to `ai_data/research/xss/` (or explicit `--output`).

## 6. Exact test counts

- New `ai/test_xss_agent.py`: **21 tests, all pass** — seed coverage of
  all 3 required categories (+ determinism), per-category research,
  explicit-flag selection, deterministic ranking with reasons,
  tie-break, insufficient-evidence, rejected/irrelevant,
  never-claims-exploitability, malformed/empty input, stable
  serialization with KB references preserved, byte-identical repeat
  persistence, no-network/no-subprocess, store-pool union, CLI
  search/search-json/research/show/list and both CLI failure paths.
- Regression (venv): `test_xss_agent` + `test_knowledge_store` +
  `test_xss_researcher` + `test_xss_llm_researcher` + `test_research_cli`
  + `test_reports_renderer` → **104 tests, all pass** (`Ran 104 ... OK`).
- Full `discover -s ai` failures are pre-existing/environmental and were
  not touched (per instructions, no fix attempted).

## 7. Changed files

Added: `ai/researcher/xss_agent.py`, `ai/researcher/xss_seed/` (3 JSON),
`ai/test_xss_agent.py`, `ai_data/research/xss/xss-60edf609e21c6b41.json`.
Modified (append-only): `ai/schemas/xss.py` (+3 models),
`ai/research_cli.py` (`xss` subparsers + `run_xss*` + dispatch).
`git diff --check` clean.

## 8. Known limitations

- Seed is 3 documents; `stored` and other contexts match only via
  caller-supplied store docs or weak keyword overlap (→ INSUFFICIENT).
- Real `ai_data/knowledge/` store is absent/empty, so CLI results come
  from the seed until KB content is ingested.
- Sink/source extraction is literal-vocabulary only; novel sinks are
  reported under unknowns rather than inferred.
- Confidence is a heuristic ordering signal, not a probability.

## 9. Production/live-validation confirmation

Confirmed untouched: no file under `ns/`, `crawl/`, `database/`,
nuclei/CVE logic, `ai/live_validation/`, `ai/execution/`,
`ai/finding/`, `ai/verification/`, or 5B–5J was modified; the agent
imports none of them. No live network testing, no exploitation, no
Nuclei execution, no alerts/findings/materialization. No commit, no push.

```
Report generated:
agent-reports/stage-r3-xss-agent-mvp.md
```
