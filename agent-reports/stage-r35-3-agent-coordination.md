# R35.3 Agent Coordination Planner

Local WSL implementation. Orchestration-planning only: no HTTP requests,
crawling, scanning, Nuclei, fuzzing, exploit validation, browser automation,
Mongo operations, database persistence, LLM calls or external network access.
No autonomous execution, task dispatch, worker queue, scheduler or agent
runtime is created. No VM/deployment change, no R29/Money/CVE-scoring
changes. No real agent communication exists.

## 1. Goal

Describe conceptual coordination between research roles:

    "How would the conceptual research roles coordinate?"

The planner consumes the R34.1 strategy, R35.1 role plan and R34.3 budget
plan read-only. Coordination modes and handoff points are conceptual planning
labels only.

## 2. Files Changed

- `ai/schemas/agent_coordination.py` — **new** pydantic schema module (245
  lines): `AgentCoordinationPlan`, closed coordination-mode vocabulary,
  bounded role/dependency/handoff validators and a filtering sanitizer.
- `ai/knowledge/agent_coordination_planner.py` — **new** pure module (129
  lines, `r35-3`): `plan_agent_coordination()`.
- `backend/asset_cve_matching.py` — **modified additively** (shared R35 diff):
  `summary["agent_coordination_plan"]` and its `_rule_version` companion.
- `tests/test_agent_coordination_planner.py` — **new** focused suite (19
  tests, 269 lines).
- `agent-reports/stage-r35-3-agent-coordination.md` — this report.

## 3. Architecture Decisions

- **Deterministic mode precedence** (first match):
  1. unknown/malformed strategy or empty role sequence → `UNKNOWN`;
  2. `DEFERRED` strategy → `REVIEW_GATE`;
  3. explicit `STOP` budget (without deferral) → `STOPPED`;
  4. otherwise → `SEQUENTIAL`.
- **Deferred wins over the budget stop**, matching the requested rule
  "Deferred: REVIEW_GATE"; `STOPPED` remains reachable for an explicit
  halting budget with a non-deferred valid strategy.
- **Role sequence** comes from the R35.1 `required_roles` (closed, filtered);
  **dependencies** and **handoff_points** are the consecutive role pairs,
  bounded to 4 each.
- **No real agent communication**: the output contains only closed labels and
  conceptual pairs; nothing is dispatched, scheduled or executed.

## 4. Plan Shape

```json
{
  "rule_version": "r35-3",
  "coordination_mode": "SEQUENTIAL",
  "role_sequence": ["VERSION_ANALYSIS", "EVIDENCE_ANALYSIS"],
  "dependencies": [
    {"role": "EVIDENCE_ANALYSIS", "depends_on": "VERSION_ANALYSIS"}
  ],
  "handoff_points": [
    {"from": "VERSION_ANALYSIS", "to": "EVIDENCE_ANALYSIS"}
  ],
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_agent_coordination_planner -q
# combined and full-suite runs shared with R35.1/R35.2/R35.4
```

Results:

```
tests.test_agent_coordination_planner             OK  (19 tests)
combined R31+R32+R33+R34+R35 + R29/R30          Ran 1384 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)         Ran 2966 tests
    37 failures + 3 errors — failure set byte-identical to baseline
py_compile / git diff --check                   OK / clean
```

Coverage: all four modes, review-gate-over-stopped precedence, unknown mode
for missing strategy/roles, dependency/handoff chains, malformed role
filtering, deterministic output, no mutation, JSON serialization, closed
mode vocabulary, schema rejections (invalid mode/roles/pairs, self-pair),
forced rule version/research_only, no operational execution content.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- Coordination is a conceptual label set; there is no runtime, messaging,
  queue, scheduler or persistence.
- `workflow_plan` is accepted for pipeline parity and never changes the mode.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R35.3
- Role: coding agent
