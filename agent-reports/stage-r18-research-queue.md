# Stage R18 — Deterministic Research Queue

## 1. Objective

Combine R15 exploitability, R16 research priority, and R17 asset relevance into
a deterministic, explainable research-planning queue answering "which
CVE/program combinations should Watch research first, and why?".

RESEARCH PLANNING ONLY. Items are research attention, never a statement that a
target is vulnerable and never an instruction to exploit anything.

## 2. Exact files changed

- `ai/knowledge/queue.py` — **new**. Pure engine: candidate generation,
  hard gates/blockers, bounded queue score, deterministic ranking,
  `ResearchQueueItem`, content-addressed `queue_id`, and schema projections.
  Reuses R16 priority and R17 relevance (no duplicated intelligence engine).
- `ai/schemas/knowledge.py` — additive standalone `KnowledgeResearchQueueItem`
  (no document field, no R12–R17 field/ID changes, `schema_version` untouched).
- `ai/research_cli.py` — read-only `queue` subcommand (`--cve`, `--limit`,
  `--json`).
- `ai/test_research_queue.py` — **new**, 24 tests.

No other source file changed. `git diff --check` clean.

## 3. Candidate generation

For each CVE with research intelligence, assets are grouped by program and R17
relevance is evaluated per program. A CVE x program item is created only when:

- the CVE carries research intelligence (products / components / technologies /
  vulnerability types); and
- the program exists in the local inventory (assets with a non-empty program);
  and
- the R17 relevance for that program is deterministically positive
  (`LOW` / `MEDIUM` / `HIGH`, score > 0).

`NONE` and `UNKNOWN` relevance never create an item, so a CVE with no
deterministic relationship produces no fake candidate. No program match is
manufactured; candidate generation is strictly per-CVE and per-program.

## 4. Queue score

Transparent, bounded `0–100`, integer deterministic half-up rounding:

```
queue_score = clamp( round(0.60 * priority_score + 0.40 * relevance_score), 0, 100 )
```

Priority contributes up to 60 and relevance up to 40, so relevance can never
fully override priority. Examples: `(80,20) -> 56`, `(100,0) -> 60`,
`(0,100) -> 40`, `(100,100) -> 100`.

## 5. Hard gates / blockers

A candidate is flagged (never silently presented as strong) when applicable:

- `only generic technology match` — the only R17 signal is a technology match
  (e.g. a framework), with no product/component/path match;
- `affected plugin not observed` — the vulnerability names a product, but the
  program's assets have no observed component;
- `asset component not observed` — the vulnerability names a component/path,
  but the assets have no observed component/path;
- `asset version unknown` — the vulnerability declares affected version(s), and
  no asset version is observed (no version applicability is inferred).

Unknowns are preserved verbatim in `unknown_factors`; unknown is never treated
as false.

## 6. Ranking

Fully deterministic, no timestamps or randomness:

1. `queue_score` descending
2. `priority_score` descending
3. `relevance_score` descending
4. `cve` ascending
5. `program` ascending

Ranks are 1-based over the sorted list. `queue_id` is content-addressed
(`rq-` + 16 hex of `rule_version + cve + program`), a stable CVE x program slot
identity.

## 7. Explainability

Every item contains `reasons[]` (priority class label + R16 reasons + R17
reasons), `blockers[]`, `unknown_factors[]`, and bounded `evidence[]`
combining the R16 priority evidence and R17 relevance/asset evidence. Example
(real corpus):

```
#1  CVE-2026-1557 -> dell  queue_score=56
    (priority=CRITICAL_RESEARCH/80, relevance=LOW/20)
reasons:  critical research priority; public proof-of-concept available;
          exploit availability reported; no authentication required; ...
          technology match: wordpress
blockers: only generic technology match; affected plugin not observed;
          asset component not observed; asset version unknown
unknown:  asset component/path not observed; asset plugin/component not observed
```

Items never say "target is vulnerable" or "exploit this target".

## 8. Real corpus results

Evaluated with `python3 -m ai.research_cli queue` against the local program
definitions plus each CVE's persisted research metadata. No matches were
manufactured.

| rank | CVE | program | priority | relevance | queue score | reasons (top) | blockers |
|---:|---|---|---|---|---:|---|---|
| 1 | CVE-2026-1557 | dell | CRITICAL_RESEARCH/80 | LOW/20 | 56 | critical research priority; public PoC; exploit availability; no auth | only generic technology match; affected plugin not observed; asset component not observed; asset version unknown |
| 2 | CVE-2026-1557 | indeed | CRITICAL_RESEARCH/80 | LOW/20 | 56 | critical research priority; public PoC; exploit availability; no auth | only generic technology match; affected plugin not observed; asset component not observed; asset version unknown |

The other five CVEs produce **no queue items** because their local relevance is
`NONE`/`UNKNOWN` (no persisted asset technology inventory) — missing asset
intelligence does not create fake items. CVE-2026-1557 produces the observed
WordPress technology-based candidates for `dell` and `indeed` (tie broken by
program ascending), exactly as expected.

## 9. Test results

- New focused suite `ai.test_research_queue`: **24 tests, OK**.
- Consolidated relevant regression pass (29 modules incl. R12–R17 and the
  mandatory XSS/LLM suites): **773 tests, all OK**.
- `py_compile` clean; `git diff --check` clean.

## 10. Adversarial / mandated scenario results

1. high priority + high relevance ranks first — pass.
2. high priority + low relevance is still visible — pass.
3. low priority + high relevance works — pass.
4. `NONE` relevance creates no fake item — pass.
5. unknown remains visible (`unknown_factors` preserved; `UNKNOWN` relevance
   creates no item) — pass.
6. generic technology match blocked/downgraded (`only generic technology
   match`) — pass.
7. blockers are explicit — pass.
8. queue score bounded 0–100 — pass.
9. deterministic weighting (60/40, integer rounding) — pass.
10. deterministic ordering (score, priority, relevance, CVE, program) — pass.
11. CVE/program isolation — pass.
12. no cross-program contamination — pass.
13. repeated computation byte-identical — pass.
14. no timestamps/randomness (stable `queue_id`) — pass.
15. no network (socket patched to raise) — pass.
16. no subprocess (`Popen` patched to raise) — pass.
17. legacy compatibility (documents without queue fields load; queue item
    schema validates) — pass.
18. adversarial/oversized product names bounded and non-crashing — pass.
19. evidence bounded (≤ 40 records, ≤ 240 chars each) — pass.
20. R15–R17 suites remain green — pass.

## 11. Idempotency

`queue_items_for_vulnerability` / `rank_research_queue` are pure functions of
their inputs; `research_queue_projection` is byte-identical across repeated
computation and independent of asset/evidence ordering. No timestamps,
randomness, or process state enter any result.

## 12. Security boundary

Pure local deterministic computation:

- no HTTP, DNS, Nuclei, browser, subprocess, exploit execution, active
  validation, 5B–5J, findings, alerts, production mutation, LLM, or external
  network (asserted by test);
- no production database access; the CLI reads the local KnowledgeStore, local
  program definitions, and local research JSON only;
- research-planning semantics only; never vulnerable/exploitable/verified/
  confirmed.

## 13. Limitations

- Queue items exist only where a deterministic R17 relevance is positive; with
  the current local inventory only CVE-2026-1557 yields candidates. This is
  honest, not a matching defect.
- Version applicability is never inferred; `asset version unknown` is reported
  whenever the CVE declares versions and no asset version is observed.
- The 60/40 weighting and gates are explicit policy, centralized as constants.
- Program mapping for correlated research assets relies on scope-suffix
  inference from local `programs/*.json`.
- `queue --cve` and `--limit` are read-only and do not persist items.

## 14. Explicit confirmation

- **No network.**
- **No LLM.**
- **No Nuclei.**
- **No active validation.**
- **No production authority chain.**
- **No alerts.**
- **No Git operations** (no add/commit/push).

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R18
- Role: Research Queue Intelligence
