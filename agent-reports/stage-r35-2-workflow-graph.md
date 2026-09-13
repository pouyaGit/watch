# R35.2 Research Workflow Graph

Local WSL implementation. Orchestration-planning only: no HTTP requests,
crawling, scanning, Nuclei, fuzzing, exploit validation, browser automation,
Mongo operations, database persistence, LLM calls or external network access.
No autonomous execution, task dispatch, worker queue, scheduler or agent
runtime is created. No VM/deployment change, no R29/Money/CVE-scoring
changes.

## 1. Goal

Create a deterministic, acyclic, ordered dependency graph for the conceptual
research nodes:

    "In what dependency order should the conceptual research nodes run?"

The builder consumes the R34.1 strategy plan (with the R35.1 role plan as a
strategy fallback via `role_reason`) read-only. This is a planning graph, not
an execution graph.

## 2. Files Changed

- `ai/schemas/research_workflow_graph.py` — **new** pydantic schema module
  (269 lines): `ResearchWorkflowGraphPlan`, closed node vocabulary, bounded
  validators with self-loop/cycle rejection and a filtering sanitizer.
- `ai/knowledge/research_workflow_graph.py` — **new** pure module (148 lines,
  `r35-2`): `build_research_workflow_graph()`, the closed `STRATEGY_WORKFLOW`
  mapping and the `REASON_TO_STRATEGY` decode (derived from the R35.1
  `STRATEGY_ROLES` table).
- `backend/asset_cve_matching.py` — **modified additively** (shared R35 diff):
  `summary["research_workflow_graph_plan"]` and its `_rule_version`
  companion.
- `tests/test_research_workflow_graph.py` — **new** focused suite (18 tests,
  273 lines).
- `agent-reports/stage-r35-2-workflow-graph.md` — this report.

## 3. Architecture Decisions

- **Closed strategy → node chain mapping**:

  | strategy | node chain |
  |---|---|
  | `IDENTITY_FIRST` | `ANALYZE_ASSET` → `ANALYZE_IDENTITY` → `COLLECT_EVIDENCE_PLAN` |
  | `VERSION_FIRST` | `ANALYZE_VERSION` → `COLLECT_EVIDENCE_PLAN` → `REVIEW_HISTORY` |
  | `TECHNOLOGY_FIRST` | `ANALYZE_TECHNOLOGY` → `COLLECT_EVIDENCE_PLAN` → `REVIEW_HISTORY` |
  | `EVIDENCE_FIRST` | `COLLECT_EVIDENCE_PLAN` → `REVIEW_HISTORY` |
  | `SCOPE_FIRST` | `ANALYZE_ASSET` → `COLLECT_EVIDENCE_PLAN` → `REVIEW_HISTORY` |
  | `HUMAN_REVIEW_FIRST` | `HUMAN_REVIEW` |
  | `DEFERRED` | `STOP` |
  | `UNKNOWN` / malformed | `REVIEW_HISTORY` |

- **Edges are generated from consecutive nodes**, so the graph is ordered by
  construction; `entry_nodes`/`terminal_nodes` are the first/last nodes.
  Single-node chains have no edges.
- **Acyclicity is enforced twice**: by construction (linear chains) and by
  the schema validator (Kahn-style topological check that rejects self-loops
  and cycles on direct construction).
- **Role-plan fallback.** When the strategy is absent, the R35.1
  `role_reason` is decoded back to its strategy through
  `REASON_TO_STRATEGY` (derived from the single authoritative R35.1 table).
- **No execution graph.** Nodes are planning labels only.

## 4. Plan Shape

```json
{
  "rule_version": "r35-2",
  "nodes": ["ANALYZE_VERSION", "COLLECT_EVIDENCE_PLAN", "REVIEW_HISTORY"],
  "edges": [
    {"from": "ANALYZE_VERSION", "to": "COLLECT_EVIDENCE_PLAN"},
    {"from": "COLLECT_EVIDENCE_PLAN", "to": "REVIEW_HISTORY"}
  ],
  "entry_nodes": ["ANALYZE_VERSION"],
  "terminal_nodes": ["REVIEW_HISTORY"],
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_workflow_graph -q
# combined and full-suite runs shared with R35.1/R35.3/R35.4
```

Results:

```
tests.test_research_workflow_graph                OK  (18 tests)
combined R31+R32+R33+R34+R35 + R29/R30          Ran 1384 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)         Ran 2966 tests
    37 failures + 3 errors — failure set byte-identical to baseline
py_compile / git diff --check                   OK / clean
```

Coverage: every strategy → node chain, the VERSION_FIRST example ordering,
edge construction and acyclicity for all strategies, STOP-only deferred
graph, role-plan fallback decode completeness, empty/unrecognized strategies,
deterministic output, no mutation, JSON serialization, closed node
vocabulary, self-loop/cycle schema rejection, forced rule
version/research_only, no operational execution content.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- The graph is a linear planning chain per strategy; it does not model
  branching, retries or parallel execution.
- Graph nodes never run, dispatch, schedule or trigger anything.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R35.2
- Role: coding agent
