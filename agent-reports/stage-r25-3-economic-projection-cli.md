# Stage R25.3 — Monetizable Research Queue Projection + CLI

## Status
**IMPLEMENTED (read-only presentation layer).** The deterministic Money Score
is now exposed as a usable researcher queue via one command. No R15–R25.2
logic was modified, no formulas were touched, no persistence was added.

## 1. Implementation files

New:

- `backend/research_economics.py` — read-only composition layer. Gathers
  R18 queue → R21 leads → R22 plans → R15/R16 intelligence → persisted CVE
  research payload → R20 task state → R23 result → R24 loop result, then
  passes each candidate into the existing R25.2
  `ai.knowledge.economics.assess_economic_value`. No scoring logic here.
- `tests/test_research_economics_projection.py` — 33 focused offline tests.

Modified (wiring only — no algorithm changes):

- `ai/research_cli.py` — `run_economics()` + `economics` subparser
  (`--cve`, `--program`, `--limit`, `--json`) + dispatch in `main()`.

Untouched: `ai/knowledge/economics.py`, `ai/schemas/knowledge.py`,
`database/db.py`, all R15–R24 modules, all routers/templates, `ns/`,
`crawl/`, Nuclei/CVE pipelines. No Flask routes, no API endpoints, no
dashboard templates (R25.4 scope).

## 2. Public functions (`backend/research_economics.py`)

- `build_economics() -> list[dict]` — project every R21 lead through the
  R25.2 engine; ordered money DESC, CVE ASC, program ASC.
- `list_research_economics(limit=50, offset=0, cve=None, program=None)`
  → `{total, offset, limit, items, skipped, rule_version, research_only}`.
  `limit` uses the existing `clamp_limit`; `cve` uses `normalize_cve`.
- `get_research_economic_value(lead_id)` — one projection by deterministic
  `rl-…` id; `NotFoundError` on malformed or absent ids.
- `economic_summary()` — `{total, by_priority, top[:3], rule_version,
  research_only}`.

Per-candidate inputs are cached by CVE (intel/payload) and read fail-soft:
a missing payload, missing R23/R24 artifact, or missing task store degrades
to engine-safe defaults (`{}`, `None`) — never fabricated values.

## 3. CLI commands

```
python -m ai.research_cli economics
python -m ai.research_cli economics --limit 10
python -m ai.research_cli economics --cve CVE-2026-1557
python -m ai.research_cli economics --program dell
python -m ai.research_cli economics --json
python -m ai.research_cli economics --cve CVE-2026-1557 --program dell
```

## 4. Real corpus output

`economics --limit 10` (human, concise):

```
MONEY QUEUE

#1  53  P3_MEDIUM
    CVE-2026-1557 → dell
    Confidence: HIGH
    Effort: 1–2 h
    Action: VERIFY_ASSET_MATCH_FIRST

#2  53  P3_MEDIUM
    CVE-2026-1557 → indeed
    Confidence: HIGH
    Effort: 1–2 h
    Action: VERIFY_ASSET_MATCH_FIRST

MONEY QUEUE: 2
```

`economics --json` returns the two full `KnowledgeEconomicValue`-compatible
projections (all 17 required keys: money_score, priority, confidence,
confidence_basis, effort, effort_estimate, asset_match, why_valuable,
blockers→main_blockers, recommended_action, subscores, evidence_summary,
caps_applied, rule_version `r25-1`, research_only `true`, plus ids).

Verification result: **CVE-2026-1557 → dell = 53,
CVE-2026-1557 → indeed = 53 — matches the required corpus values.**
No persisted artifact was modified (verified by directory snapshot test).

## 5. Filtering behavior

- `--cve` validates via the existing `normalize_cve` (malformed → stderr
  `ERROR` + exit 1, same as `leads`/`plan`).
- `--program` strips and exact-matches; `--limit` clamps to `[1, 100]`
  via `clamp_limit`; offset supported in the projection function.
- Ordering is a total order (money DESC, CVE ASC, program ASC), so the
  real-corpus tie (53/53) deterministically breaks `dell` before `indeed`.
- A CVE/program with no queue candidate prints
  `MONEY QUEUE: none (no R18 queue candidates match)` (exit 0).

## 6. Fail-soft behavior

- One malformed lead (non-mapping, missing `cve_id`/`program`, or an engine
  exception) is recorded as a deterministic `skipped` entry
  `{cve_id, program, lead_id, reason}` and never blanks the queue; `skipped`
  is sorted deterministically and filtered alongside `items`.
- A failed lead snapshot degrades to `total 0` with one skip record
  (`lead snapshot unavailable`) instead of raising.
- Missing R15/R16 intel, missing payload, or missing R23/R24 artifacts
  degrade to engine-safe empty inputs (unknown = zero, never negative;
  verified: missing-everything still projects, capped at ≤45).
- Malformed `lead_id` detail lookups raise `NotFoundError`
  (router-mappable to 400/404 in R25.4).

## 7. Test count / results

`tests/test_research_economics_projection.py` — **33 tests, all OK**
(`Ran 33 tests … OK`, ~1.2 s):

- Queue composition (5): real-corpus 53/53 + `P3_MEDIUM`, projection shape
  (17 keys, subscore/evidence keys, bounds), lead→plan mapping
  (`rl-`/`r22-`/`rq-`), R18 blocker propagation, R15 PoC visibility,
  forbidden vocabulary scan.
- Inputs (5): R23 loading (`r23_confidence HIGH`, counts), R24 loading
  (`r24_tier TRUSTED`), missing R23/R24 still projects, R20 `DONE` →
  `COMPLETED`, R20 `IN_PROGRESS` → `CONTINUE` (mocked task store).
- Ordering/filtering (7): total money order, tie-break, determinism,
  CVE/program filters, limit, offset, JSON round-trip.
- Detail lookup (4): by lead id, malformed id → `NotFoundError`, unknown
  id → `NotFoundError`, summary shape.
- Fail-soft (4): malformed items skipped without blanking, empty queue,
  snapshot failure, missing intel/payload (money ≤ 45, `research_only`).
- CLI (5): human output exact lines, JSON output, combined filters,
  empty filter, malformed CVE → exit 1.
- Safety (2): no network/LLM/subprocess/browser import scan, no-persistence
  directory snapshot over `agent/`, `tasks/`, `knowledge/`, `research/`.

## 8. Regression results

- `tests.test_research_economics` (R25.2 engine): **91 tests, OK**
  (~0.01 s) — formulas untouched and green.
- R21/R22 pure-logic classes
  (`TestLeadId`, `TestDeterministicOrdering`, `TestComposition`,
  `TestTaskAssociation`, `TestSafetyScan`, `TestPlanId`,
  `TestCorpusComposition`, `TestRecommendedStart`, `TestStatusSemantics`,
  `TestResearchPlanCli`): **54 tests, OK** (~0.9 s).
- Existing `leads` and `research plan` CLI output verified unchanged.
- `git diff --check` — clean.

Pre-existing environment limitation (unchanged by this stage): the
Mongo-dependent API/UI test classes (`TestLeadsApi`, `TestLeadsUi`,
`TestPlansApi`, `TestPlansUi`) stall in this offline environment both with
and without the R25.3 changes (verified via `git stash` A/B: identical
stall at the same UI test on pristine `HEAD 71fef7c`; single tests pass in
isolation either way). No R25.3 code path is involved.

## 9. Safety verification

- Static source scan of `backend/research_economics.py`: no `socket`,
  `subprocess`, `urllib`, `requests`, `httpx`, `llm`, `openai`, `anthropic`,
  `nuclei`, `urlopen`, `browser`, `Popen` tokens.
- Read-only proof: directory snapshots of `ai_data/research/agent`,
  `ai_data/research/tasks`, `ai_data/knowledge`, `ai_data/research` are
  byte-identical before/after `build_economics` +
  `list_research_economics` + `economic_summary`.
- Output vocabulary scan: no `VULNERABLE`/`VERIFIED`/`EXPLOITED`/`FINDING`
  in any projection; pages/CLI stay research-planning worded.
- Projections always carry `research_only: true` and `rule_version: r25-1`.
- No network/DNS/LLM/subprocess/target/Nuclei/5B-5J code paths added;
  R25.2 formulas byte-untouched (`git diff` on `economics.py`: none).

## 10. Discrepancies

None functional. Notes for R25.4:

- `list_research_economics` carries an additive `skipped` key beyond the
  classic `{total, offset, limit, items}` contract; routers should pass it
  through or drop it — both are JSON-safe.
- Detail lookup currently accepts only `rl-…` ids (plan ids resolve via
  the JSON `plan_id` field); a `plan_id → projection` alias can be added
  in R25.4 if the UI needs it.
- No Git operations performed (no add/commit/push); working tree contains
  only the two new files plus the additive CLI wiring.

## Agent / Model
- Model: Miuz Spark
- Stage: R25.3
- Role: Monetizable Research Queue Projection + CLI
