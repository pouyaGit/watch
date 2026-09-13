# R35.1 Agent Role Planner

Local WSL implementation. Orchestration-planning only: no HTTP requests,
crawling, scanning, Nuclei, fuzzing, exploit validation, browser automation,
Mongo operations, database persistence, LLM calls or external network access.
No autonomous execution, task dispatch, worker queue, scheduler or agent
runtime is created. No VM/deployment change, no R29/Money/CVE-scoring
changes.

## 1. Goal

Determine which conceptual research roles are needed for a given strategy:

    "Which conceptual research roles does this strategy require?"

The planner consumes the R34.1 strategy plan read-only. Roles are planning
labels only; nothing executes.

## 2. Files Changed

- `ai/schemas/agent_role_plan.py` — **new** pydantic schema module (233
  lines): `AgentRolePlan`, closed role/role-reason vocabularies, imported
  confidence vocabulary, bounded validators and sanitizer.
- `ai/knowledge/agent_role_planner.py` — **new** pure module (138 lines,
  `r35-1`): `plan_agent_roles()` and the closed `STRATEGY_ROLES` mapping.
- `backend/asset_cve_matching.py` — **modified additively** (shared R35 diff,
  +55/-0 total): import plus `summary["agent_role_plan"]` and its
  `_rule_version` companion.
- `tests/test_agent_role_planner.py` — **new** focused suite (21 tests, 424
  lines) including hermetic backend integration for R35.1-R35.4.
- `agent-reports/stage-r35-1-agent-role-planner.md` — this report.

## 3. Architecture Decisions

- **Closed strategy → role mapping** (first match, deterministic):

  | strategy | required roles | primary |
  |---|---|---|
  | `IDENTITY_FIRST` | `ASSET_ANALYSIS`, `IDENTITY_ANALYSIS` | `ASSET_ANALYSIS` |
  | `VERSION_FIRST` | `VERSION_ANALYSIS`, `EVIDENCE_ANALYSIS` | `VERSION_ANALYSIS` |
  | `TECHNOLOGY_FIRST` | `TECHNOLOGY_ANALYSIS`, `EVIDENCE_ANALYSIS` | `TECHNOLOGY_ANALYSIS` |
  | `EVIDENCE_FIRST` | `EVIDENCE_ANALYSIS`, `HISTORY_ANALYSIS` | `EVIDENCE_ANALYSIS` |
  | `SCOPE_FIRST` | `ASSET_ANALYSIS`, `EVIDENCE_ANALYSIS` | `ASSET_ANALYSIS` |
  | `HUMAN_REVIEW_FIRST` | `HUMAN_REVIEW` | `HUMAN_REVIEW` |
  | `DEFERRED` | `HUMAN_REVIEW` | `HUMAN_REVIEW` |
  | `UNKNOWN` / malformed | `HISTORY_ANALYSIS` | `HISTORY_ANALYSIS` |

- **`SCOPE_FIRST`, `HUMAN_REVIEW_FIRST` and `UNKNOWN`** are repository-
  convention additions beyond the explicitly listed mappings; all remain
  closed and deterministic.
- **Confidence passthrough** from the strategy (invalid → `UNKNOWN`);
  `primary_role` is always the first required role.
- **No execution.** Roles never schedule, dispatch, enqueue or run anything.

## 4. Plan Shape

```json
{
  "rule_version": "r35-1",
  "required_roles": ["VERSION_ANALYSIS", "EVIDENCE_ANALYSIS"],
  "primary_role": "VERSION_ANALYSIS",
  "role_reason": "VERSION_STRATEGY",
  "confidence_level": "HIGH",
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_agent_role_planner -q
# combined and full-suite runs shared with R35.2-R35.4 (see R35.4 report)
```

Results:

```
tests.test_agent_role_planner                    OK  (21 tests)
combined R31+R32+R33+R34+R35 + R29/R30          Ran 1384 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)         Ran 2966 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2890-test baseline; no new failure
py_compile / git diff --check                   OK / clean
```

Coverage: every strategy → role mapping, deferred human review, confidence
passthrough/default, empty and unrecognized strategies, deterministic output,
no mutation, primary-role invariant, JSON serialization, closed vocabulary +
schema rejections, forced rule version/research_only, no operational
execution content, and hermetic backend tests for all four R35 plans.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- Roles are conceptual planning labels; this stage creates no agent runtime,
  queue, scheduler, dispatch or persistence.
- The backend maps the current candidate's single strategy; multiple
  candidates would each receive an independent role plan.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R35.1
- Role: coding agent
