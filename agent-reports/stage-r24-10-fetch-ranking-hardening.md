# Stage R24.10 — Research Source Fetch/Ranking Hardening

Deterministic fetch priority + reserved high-value slot under the tiny fetch
budget. Additive only: R24.4 ranking scores, the R24.8 evidence gate, dedup,
R23 behavior and the default-disabled discovery flag are all unchanged.

## 1. Exact files changed

| File | Change |
|---|---|
| `ai/research_agent/fetch_priority.py` | **New.** Deterministic fetch level/order + reserved high-value slot. |
| `ai/research_agent/llm_loop.py` | Re-order deduplicated sources with `order_for_fetch(...)` before fetching (scores untouched). |
| `tests/test_research_agent_r24_10.py` | **New.** 14 focused tests. |
| `agent-reports/stage-r24-10-fetch-ranking-hardening.md` | This report. |

No other source file modified. `database/db.py` untouched; no commit/push/reset.

## 2. Selection algorithm

The fetch order is a separate, deterministic layer over already-ranked
`DiscoveredSource` records (it never recomputes or changes R24.4 scores):

```
level 0  TRUSTED + advisory category + exact CVE token
level 1  TRUSTED + advisory / structured (NVD/CVE) source
level 2  TRUSTED + other non-generic
level 3  SEMI_TRUSTED + advisory
level 4  SEMI_TRUSTED + other
level 5  DISCOVERY_ONLY detection / exploit / writeup / blog
level 6  other non-generic
level 40 generic search / landing page (any tier)
```

`fetch_priority_key(source)` = `(level, cve_specific, -source_quality,
tier_rank, canonical_url, source_id)` — a total, deterministic order (no clock,
no randomness, no set/dict iteration).

`is_generic_search_source(source)` is a **URL-shape** rule (not provider
special-casing): a `GENERIC`-tier source, or a source whose path contains a
`search` segment or whose query carries `q`/`query`/`pattern`/`search`. This
captures `…/search/…`, `…/update-guide/search`, `search.php`,
`…/SearchResults`, and `?q=`/`?query=` landing pages, while leaving direct
sources (`/rest/json/cves/2.0?cveId=`, `/vuln/detail/`, `/CVERecord?id=`) at
their high-value levels.

`order_for_fetch(sources)` returns ALL sources re-ordered (generic pages last).
`select_for_fetch(sources, max_fetched)` returns at most `max_fetched`, with a
**reserved high-value slot**: when a non-generic TRUSTED source exists it is
guaranteed to be inside the selected set (so generic search pages cannot starve
it even at `max_fetched=1`).

In `llm_loop._run_round` the deduplicated list is passed through
`order_for_fetch(deduped, metadata)` before `_fetch_sources`, so the bounded
fetch budget is spent top-down. Unselected sources still appear in the
discovery block (unfetched), preserving discovery/provenance.

## 3. Before / after behavior

- **Before:** `_fetch_sources` iterated the dedup output ordered by
  `(canonical_url, source_id)`. Generic vendor search pages
  (`access.redhat.com/search/…`) sort before `services.nvd.nist.gov`, so under a
  small cap they consumed fetch slots and the direct NVD/CVE source was not
  fetched (observed in R24.8: `evidence=0` with `max_fetched=2`).
- **After:** generic search/landing pages are level 40; the NVD structured
  source is level 0. NVD is fetched first; generic pages are fetched only if
  budget remains after CVE-specific/structured sources. With `max_fetched=1` the
  NVD source is still fetched (loop-level test asserts exactly one fetch, to
  `services.nvd.nist.gov`).

## 4. Tests

New `tests/test_research_agent_r24_10.py` (14) covers: NVD outranks generic
vendor search; CVE-specific advisory outranks generic; generic-page detection;
preference levels; all sources retained; generic pages cannot starve the trusted
source; reserved slot at `max_fetched=1`; over-budget passthrough;
deterministic ordering; R24.4 scores unchanged (and sources not mutated);
evidence gate unchanged; dedup unchanged; `discovery=false` unchanged; and a
loop-level integration where NVD (not the generic vendor page) is fetched with
`max_fetched=1` and becomes the sole evidence.

Full regression:

| Suite | Tests |
|---|---|
| `tests.test_research_agent` | 92 |
| `tests.test_research_agent_r24_1` | 43 |
| `tests.test_research_agent_r24_2` | 50 |
| `tests.test_research_agent_r24_3` | 80 |
| `tests.test_research_agent_r24_4` | 71 |
| `tests.test_research_agent_r24_5` | 38 |
| `tests.test_research_agent_r24_6` | 49 |
| `tests.test_research_agent_r24_8` | 31 |
| `tests.test_research_agent_r24_10` | 14 |
| **Combined** | **Ran 468 tests … OK** |

Baseline 454 → 468 (all existing suites unchanged). `git diff --check` → **clean
(rc=0)**.

## 5. Confirmation — R23 unchanged

No R23 file (`agent.py`, `scheduler.py`, `sources.py`, `storage.py`, `prompts.py`)
was modified. `tests.test_research_agent` remains 92 OK; the R23 agent path and
`discovery=false` → `ResearchAgent` factory behavior are unchanged (explicitly
tested). No live run, no network, no LLM, no target interaction was performed in
this stage (fakes only).

## 6. Confirmation — default discovery = false

`WATCH_RESEARCH_DISCOVERY` default remains `false`; `SchedulerConfig.from_env({}).discovery`
is `False`; no systemd copy is enabled; no persistent environment change.

## 7. Confirmation — evidence gate unchanged

`required_content_tokens` still gates evidence: a generic vendor page with no
CVE-specific content is not evidence; the same page with the exact CVE token is.
No change to `build_evidence`/`integrate_discovery` logic beyond R24.8.

## 8. Remaining limitations

1. `is_generic_search_source` is a URL-shape heuristic; an unusual direct
   advisory URL containing a `search` path segment could be down-ranked, and a
   search page with a non-standard parameter name could avoid the generic level.
2. The fetch level is a coarse preference; it does not re-score sources, so a
   low-quality TRUSTED source still precedes a high-quality SEMI source (by the
   required preference order).
3. Claim extraction for JSON sources remains a bounded raw-body excerpt.
4. No change to the free-model variance or the scheduler deadline model.

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R24.10
- Role: Research Source Fetch/Ranging Hardening
