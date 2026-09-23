# Production Intelligence & Hunt Operations (EPIC8)

Read-only projection layer that answers operational questions from REAL
persisted Watch state. One authoritative projection feeds both the JSON
API and the AI SOC UI.

## Architecture

```
backend/prod_intel/           READ-ONLY projection package
  semantics.py                metric provenance + honest state vocabulary
  sources.py                  bounded, fail-closed readers over stores
  activity.py                 meaningful-activity taxonomy + right-now state
  overview.py                 production intelligence overview
  targets.py                  target-level intelligence (incl. learning)
  agents_intel.py             per-specialist intelligence + knowledge lineage
  effectiveness.py            hunt/campaign funnel measurement
  learning_signals.py         recurring research patterns (read-only)
  case_intel.py               analyst case/handoff package
  knowledge_usage.py          knowledge usage vs inventory
backend/routers/intel.py      JSON API (12 endpoints, OpenAPI)
                              mounted INSIDE routers/soc.py so api.py
                              (operator-dirty) never changes
web/templates/soc/targets.html  Targets page (+ enriched home, activity,
                                agent detail, case detail, finding detail)
```

Authoritative sources (never duplicated): `runtime_store` (jobs, evidence,
runtime cases, knowledge_use, audit, worker heartbeat), `finding.store`
(candidates, verifications, finding cases), `campaign.store`,
`hunt.store`, `intelligence.memory`, `research_data` KB inventory, Mongo
attack-surface counts, `backend.soc.*` adapters. The projection performs
NO writes (AST-enforced in tests: no transition/add/record/enqueue calls).

## Metric provenance

Every metric dict carries: `source`, `population`, `aggregation`,
`time_range` (when windowed), `rule_version`, `state`, `reason`.
Deterministic: same state -> same output (hours=None windows contain no
wall-clock filter). Reproducible across runs (tested).

## State semantics (exact meanings)

| state | meaning |
|---|---|
| `ok` | source readable; the aggregation ran over the full stated population. A count of `0` under `ok` means the population genuinely contained no rows. |
| `unknown` | there is no persisted record of the subject at all (e.g. no target records exist yet), or runtime state cannot be determined (e.g. no worker heartbeat). NOT a zero. |
| `unavailable` | the source store could not be read (disk, schema, corruption). The payload may contain partial items plus `unavailable_sources`; rates become `null`. Never rendered as `0` or `0%`. |
| `not_observed` | the source was readable but no event/row falls in the requested time window. |
| `insufficient_population` (funnels) | denominator exists but is `0`, or the denominator source is down. `rate` is `null` — never `0%`. |
| `zero` | only under `ok`: a true observed empty population. |
| `blocked` | a hunt objective / verification / case reached an honest terminal-blocked state in the SOURCE system (termination_reason preserved). |
| `rejected` | source system rejected the hypothesis/candidate (REJECTED semantics preserved). |
| `verified` | ONLY the Evidence Gate set it (gate decision `VERIFIED`, `evidence_rules_met`). Projections never promote states; the layer is read-only. |

## Meaningful activity (definition)

An audit event is MEANINGFUL when its type maps to a lifecycle category:
research started/completed/failed/retry, campaign lifecycle, objective
terminal, authorization granted/denied, typed observation produced
(evidence_recorded), candidate created/correlated/deduplicated/triaged,
verification created/authorized/started/completed, case
created/transitioned/handoff-ready, knowledge/memory updates
(knowledge_used, intelligence_memory_learned/retrieved,
intelligence_knowledge_selected, intelligence_lineage_recorded,
intelligence_recommendation_generated), integrity_repair. Everything else
in `audit.jsonl` is excluded from feeds and counts. Failure events are
typed `failure`/`blocked`/`denied` and counted as blockers — never as
successful work.

## Time windows

Default window: 168 h (7 days), `hours=0` allowed (>=0, API cap 2160),
`hours=None` = all history. Windows apply to activity feeds, recent
findings, knowledge use, memory heads, learning signals. Count snapshots
(campaigns, cases, candidates) are current-state (documented per metric
as `current_snapshot`).

## Performance assumptions (no cache, by design)

- Target discovery + full target list builds in ~1.4 s against
  production (jobs/candidates/campaigns/hunt/memory bounded lists;
  Mongo attack-surface counts run once per listed target ~1 s each).
- Audit feed capped at the last 2,000 rows per build; plans/auth walk
  bounded to 200 objectives; learning patterns capped at 50 signals;
  API `limit` bounded 1..200, `offset` >= 0; knowledge usage paginated.
- No cache exists anywhere, so no cache can become a second source of
  truth (spec §15). If query volume grows, add a TTL cache WITH
  `collected_at` provenance rather than background aggregates.

## API (all behind the global API-key middleware)

`GET /api/intel/overview|targets|targets/{t}|agents|agents/{slug}|
activity|now|hunt-effectiveness|learning|cases/{id}|
knowledge-usage|handoff` — 401 without key, 404 unknown ids, 422
out-of-range params, documented in `/openapi.json`.

## Known limitations

- Evidence rows are attributed to a target only through their job's
  recorded subdomain; evidence from jobs no longer in the store cannot
  be attributed (shown honestly as unattributed, not guessed).
- Attack-surface counts require Mongo; without it they read
  `unavailable`, never `0`.
- Learning signals are DERIVED (state `INFERRED` max; original memory
  items keep their own OBSERVED/INFERRED/RESEARCHED/VERIFIED/REJECTED
  states). The projection never writes memory items.
- Candidate lineage shows correlation links + duplicate outcomes;
  it does not claim semantic identity beyond the stored reason codes.
