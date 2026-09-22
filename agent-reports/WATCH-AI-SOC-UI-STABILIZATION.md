# WATCH — AI SOC UI stabilization (Agents 500 + primary navigation)

**Task** — first real browser verification of the live AI SOC exposed two
production defects. Both are fixed here as one coherent stabilization change.

**Production impact** — production was only *inspected* (read-only). No file in
`/opt/watch` was modified; nothing is live until the promotion workflow merges
this branch and the service is reloaded.

---

## Defect 1 — `/ui/soc/agents` returned HTTP 500

### Root cause (server-side, reproduced)

`backend/soc/agents.py::_registry_agents()` did

```python
from backend.research_agents.registry import build_default_registry
```

with **no guard**, and it is the only identity source of the agents page
(reached by `agents_index()`, used by both `/ui/soc/agents` and
`/ui/soc/agents/{slug}`).

`backend.research_agents` is **not part of the deployed tree** — it exists only
in the agent worktree, where it belongs to a different, unpromoted epic. In
production the import therefore raised
`ModuleNotFoundError: No module named 'backend.research_agents'`, which
propagated out of the page helper and became an `Internal Server Error`.

Every other helper in the module (`_service_counts`, `_memory_summary`,
`_kb_documents`, `_case_rows`) was already fail-soft; only the registry import
was unguarded — so the 500 was a single unguarded optional dependency, not a
missing-data condition.

Reproduced deterministically in the deployed module set (imports of
`backend.research_agents` blocked): `agents_index()` raised `ImportError`.

### Fix

Identity sources are now **layered and all optional** — first available real
source wins, nothing is fabricated:

1. the research-agent registry, when that runtime *is* deployed (unchanged
   preferred source — the worktree behaviour is identical);
2. otherwise the engine's own deterministic specialist registry
   (`ai.knowledge.specialist_registry`, shipped with Watch), whose declared
   identities are projected one-to-one:
   * `key` = declared category (e.g. `xss`) — the same key the AEC case
     explorer uses, so agent↔case matching keeps working;
   * `name` / `status` = declared `agent_name` / `lifecycle_state`;
   * `evidence_types` ← declared `supported_contexts`;
   * `strategy` ← declared `supported_capabilities`;
3. otherwise an **explicit empty state** (`{"count": 0, "agents": []}`), never
   an exception.

Additional hardening in the same layer: registry rows that are not mappings are
skipped, entries without a declared name are skipped rather than filled in,
`agents_index()`/`agent_detail()` no longer let an identity-layer failure
escape, and the knowledge projection no longer emits empty strings as
"techniques" or "vulnerability areas".

Templates: `soc/agents.html` renders a deliberate empty state when no registry
is available, `soc/agent_detail.html` states when no description is declared by
the supplying registry instead of printing an empty line.

**Result** — `/ui/soc/agents` renders 200 with a valid key in the deployed
module set, listing real declared specialists; unknown slugs are a safe 404.

---

## Defect 2 — legacy Research section was still primary navigation

### Root cause

`web/templates/base.html` (the single shared sidebar) rendered the AI SOC group
*and* every legacy group — Overview, Discovery, Operations, Changes, **Research**
(Research Cases, Research / CVEs, Research Queue, Research Tasks, Research
Leads, Research Plans, Research Agent), XSS, Knowledge Base, Reports, System —
as flat, equally visible `nav-group` blocks. The `Legacy / Engineering` heading
existed but only as a label above them, so the legacy research surface still
read as primary product navigation.

### Fix

`base.html` now wraps the whole legacy block (heading + all legacy groups) in a
collapsed `<details class="nav-legacy">` disclosure whose summary keeps the
`Legacy / Engineering` label. Consequences:

* primary navigation is the AI SOC group only: Overview, Agents,
  Missions / Activity, Cases, Evidence, Knowledge, Handoff;
* the ten legacy research/technical destinations are no longer primary
  navigation links;
* **nothing is deleted or renamed** — every legacy link keeps its exact href,
  label and markup, stays in the DOM, is keyboard reachable and is identical
  once the disclosure is expanded; no route was touched;
* one shared navigation system, fixed at the source (no page-level hacks).

`web/static/css/soc/soc.css` gains the disclosure styling (collapsed marker,
subordinate indent) on the existing palette.

---

## Handoff finding (no fabrication)

`/ui/soc/handoff` showed "0 shareable read-only investigation packages".
Investigated: the page's source is `backend.investigation_engine.service`
report documents, which is **not deployed** in production, and
`/opt/watch/ai_data/investigations/` contains **no report documents at all**.

So the zero is a *correct* empty state, not a projection bug — and the
projection itself is intact: validated against the real local report source
(144 documents projected without loss) and against a stubbed report list
(job id, target, view URL projection). No package is invented.

It is now **intentional and self-explanatory**: `handoff_index()` reports a
`source_available` flag (purely observational import check), and the page states
plainly that the report source is not deployed and that nothing is fabricated
for display. Packages will appear by themselves once real investigation reports
exist.

---

## Files changed

| File | Change |
| --- | --- |
| `backend/soc/agents.py` | layered optional identity sources + empty-state/robustness guards |
| `backend/soc/handoff.py` | `_source_available()` + `source_available` in the index payload |
| `web/templates/base.html` | legacy block moved behind the `Legacy / Engineering` disclosure |
| `web/templates/soc/agents.html` | explicit empty state (count-aware) |
| `web/templates/soc/agent_detail.html` | explicit "no description declared" state |
| `web/templates/soc/handoff.html` | explicit not-deployed empty state |
| `web/static/css/soc/soc.css` | disclosure styling |
| `tests/test_soc_ui_stabilization.py` | new regression suite (25 tests) |

Untouched by design: `backend/routers/soc.py`, SOC adapters other than the two
above, AEC, `ai/knowledge`, authentication middleware, database schema, runtime
and authorization/evidence systems, `api.py`.

---

## Tests

| Suite | Result |
| --- | --- |
| `tests/test_soc_ui_stabilization.py` (new, deployed module set) | **25 OK** (RED first: 9 failures + 10 errors before the fix) |
| SOC suites (`test_soc_router_mounting`, `test_soc_ui_*`) | **89 OK** |
| AEC regression `discover -p "test_aec_*.py"` | **2149 OK** (baseline unchanged) |
| read-only guard `scripts/check_aec_readonly.py` | **READ-ONLY VERIFIED** (116 pinned, no drift) |
| `test_aec_readonly_guard` + `test_delivery_policy` + `test_delivery_guard` | **100 OK** |
| `test_research_navigation` / `test_page_render` / `test_ui_redesign` | **14 / 7 / 19 OK** |
| mounted-app smoke, deployed module set (SOC pages, agent detail, handoff, auth, legacy pages, nav) | **PASS** |

Regression coverage added: agents page never 500 with valid auth; empty/absent
agent data renders the empty state; SOC pages carry SOC primary navigation;
legacy research links are absent from primary navigation and still present in
the legacy area; legacy routes stay mounted and still render; handoff empty
state is explicit (and the real projection still works when the source is
present); auth constraints unchanged; unknown agent slug is a safe 404.
