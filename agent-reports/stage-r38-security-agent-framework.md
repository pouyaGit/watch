# Stage R38 — Security Agent Framework Core

Deterministic foundation and contracts for future security specialist agents.
This stage creates the Security Agent SDK model layer only. It creates no
vulnerability agents, executes nothing, and contains no runtime, plugin
loader, dynamic import, worker or persistence.

- Stage: R38
- Rule versions: `r38-1` … `r38-7`
- Commit: `feat(research): add r38 security agent framework core` (local only,
  not pushed)

## 1. Architecture Implemented

```
Security Agent Identity      (r38-1)
        ↓
Agent Capability Model       (r38-2)
        ↓
Agent Input Contract         (r38-3)
        ↓
Agent Lifecycle Model        (r38-4)
        ↓
Agent Result Contract        (r38-5)
        ↓
Agent Registry Model         (r38-6)
        ↓
Agent Framework Export       (r38-7)
```

Every component is deterministic, pure, stateless, JSON serializable,
pydantic validated and carries `research_only=True`. Schemas live in
`ai/schemas/security_agent_*.py`; pure engines live in
`ai/knowledge/security_agent_*.py`. No component performs I/O, network, LLM,
DNS, subprocess, browser, Mongo or filesystem mutation.

## 2. Agent Contract Design

The pydantic schema layer owns the closed vocabularies, validators and
sanitizers; the knowledge layer owns deterministic planning/building.

| Model | Schema | Engine | Rule |
|---|---|---|---|
| Identity | `ai/schemas/security_agent_identity.py` | `ai/knowledge/security_agent_identity.py` | r38-1 |
| Capability | `ai/schemas/security_agent_capability.py` | `ai/knowledge/security_agent_capability.py` | r38-2 |
| Input | `ai/schemas/security_agent_input.py` | `ai/knowledge/security_agent_input_validator.py` | r38-3 |
| Lifecycle | `ai/schemas/security_agent_lifecycle.py` | `ai/knowledge/security_agent_lifecycle.py` | r38-4 |
| Result | `ai/schemas/security_agent_result.py` | `ai/knowledge/security_agent_result_validator.py` | r38-5 |
| Registry | `ai/schemas/security_agent_registry.py` | `ai/knowledge/security_agent_registry.py` | r38-6 |
| Export | `ai/schemas/security_agent_framework_export.py` | `ai/knowledge/security_agent_framework_export.py` | r38-7 |

Design rules applied everywhere:

- `extra="forbid"`, `rule_version` is forced to the stage constant and
  `research_only` can never be set false.
- Closed vocabularies reject unknown codes; planner inputs normalize
  case and degrade malformed values to `UNKNOWN` instead of inventing data.
- All outputs use fixed key sets with bounded, redacted text
  (control characters stripped, secret-like pairs and URL userinfo redacted).
- No timestamps, randomness, environment or wall-clock state exist in any
  object, so repeated evaluation is byte-identical.

## 3. Identity Model (R38.1)

`SecurityAgentIdentityPlan`: `rule_version`, `agent_id`, `agent_name`,
`category`, `version`, `maturity`, `description`, `research_only`.

- Categories: `XSS`, `SSRF`, `SQLI`, `IDOR`, `JWT`, `OAUTH`, `CVE_RESEARCH`,
  `RECON`, `UNKNOWN`.
- Maturity: `EXPERIMENTAL`, `RESEARCH`, `STABLE`, `UNKNOWN`.
- Unknown/missing categories always remain `UNKNOWN` and are never promoted;
  unknown maturity remains `UNKNOWN`.
- The agent id is a deterministic content token
  (`sa-<16 hex>`, SHA-256 over bounded identity fields); no runtime metadata
  and no execution capability exists.

## 4. Capability Model (R38.2)

`SecurityAgentCapabilityPlan`: `rule_version`, `agent_category`,
`allowed_capabilities[]`, `prohibited_capabilities[]`, `capability_state`,
`research_only`.

- Allowed (analysis-only): `ANALYZE_CONTEXT`, `ANALYZE_PATTERN`,
  `CREATE_HYPOTHESIS`, `REQUEST_EVIDENCE`, `GENERATE_EXPLANATION`,
  `RANK_FINDINGS`.
- Prohibited: `EXECUTE_EXPLOIT`, `RUN_PAYLOAD`, `BYPASS_AUTH`,
  `MODIFY_TARGET`, `AUTOMATE_ATTACK`.
- Allowed and prohibited vocabularies are disjoint, and the pydantic model
  rejects any overlap.
- Every plan explicitly lists all five prohibited capabilities; unknown
  categories yield `capability_state=UNKNOWN` with an empty allowed set.
  Capability states: `VALID`, `PARTIAL`, `UNKNOWN`.

## 5. Input Contract (R38.3)

`SecurityAgentInputPlan`: `rule_version`, `agent_identity`,
`research_context`, `memory_context`, `strategy_context`,
`orchestration_context`, `authorization_context`, `governance_context`,
`research_only`.

- Read-only: context blocks are projected onto bounded flat key sets and
  caller data is never mutated.
- A missing or malformed `authorization_context` remains an empty (unknown)
  block; it is never defaulted to permissive and no unrestricted assumption
  is materialized.
- Nested objects and non-scalar list items are dropped; scalar/list values
  are bounded (`MAX_CONTEXT_KEYS=24`, `MAX_CONTEXT_LIST=16`,
  `MAX_VALUE_LEN=160`) and secret-like values are redacted.
- No execution context exists: the schema rejects extra fields such as
  `execution_context`.

## 6. Lifecycle Model (R38.4)

`SecurityAgentLifecyclePlan`: `rule_version`, `current_state`,
`previous_state`, `allowed_transitions[]`, `lifecycle_state`, `research_only`.

- States: `CREATED`, `PLANNED`, `ANALYZING`, `WAITING_EVIDENCE`,
  `COMPLETED`, `FAILED` (plus internal `UNKNOWN` for malformed input).
- Transition table: `CREATED→PLANNED`; `PLANNED→{ANALYZING, FAILED}`;
  `ANALYZING→{WAITING_EVIDENCE, COMPLETED, FAILED}`;
  `WAITING_EVIDENCE→{ANALYZING, COMPLETED, FAILED}`; `COMPLETED`, `FAILED`,
  `UNKNOWN` are terminal.
- Validation states: `VALID`, `INVALID`, `UNKNOWN`. Only legal transitions
  validate as `VALID`; illegal transitions from a known previous state
  validate as `INVALID`; malformed states yield `UNKNOWN`.
- Explicit `previous_state="NONE"` is treated identically to an omitted
  previous state (valid start).
- No runtime execution, no timestamps, no persistence.

## 7. Result Contract (R38.5)

`SecurityAgentResultPlan`: `rule_version`, `agent_name`, `status`,
`confidence`, `findings_summary`, `evidence_summary`, `limitations`,
`research_only`.

- Status: `CREATED`, `ANALYZING`, `COMPLETED`, `FAILED`, `UNKNOWN`.
- Confidence reuses the shared closed vocabulary
  (`HIGH`, `MEDIUM`, `LOW`, `UNKNOWN` from `evidence_confidence`).
- Findings summaries: `NO_FINDINGS`, `OBSERVATIONS_RECORDED`,
  `HYPOTHESES_RECORDED`, `UNKNOWN`; evidence summaries:
  `EVIDENCE_NONE`, `EVIDENCE_PARTIAL`, `EVIDENCE_SUFFICIENT`, `UNKNOWN`.
- Overclaim prevention: `UNKNOWN` status forces `UNKNOWN`
  confidence/findings/evidence; `FAILED` downgrades `HIGH`/`MEDIUM` to `LOW`
  and suppresses findings; `CREATED`/`ANALYZING` suppress findings.
- Every result records `NO_EXECUTION_PERFORMED`. Output is descriptive only:
  no exploit output, no payload storage, no execution logs.

## 8. Registry Model (R38.6)

`SecurityAgentRegistryPlan`: `rule_version`, `registered_agents[]`,
`registry_state`, `research_only`; entries expose exactly `agent_id`,
`category`, `maturity`, `capabilities`.

- Closed categories only; capabilities are restricted to the allowed R38.2
  vocabulary and any prohibited code is filtered.
- The default registry is a deterministic static table of the eight
  framework categories with fixed maturity and capability mappings.
- Caller entries are bounded, sanitized and deduplicated: invalid entries are
  skipped and downgrade the state to `PARTIAL`; an empty result is `UNKNOWN`.
- States: `VALID`, `PARTIAL`, `UNKNOWN`. This is static data only: no plugin
  system, no dynamic discovery, no dynamic imports, no runtime.

## 9. Framework Export (R38.7)

`SecurityAgentFrameworkExportPlan`: `rule_version`, `ready`, `identities`,
`capabilities`, `input_contract`, `lifecycle`, `result_contract`, `registry`,
`limitations`, `research_only`.

- `ready=True` only when identities, capabilities, lifecycle and registry are
  all valid. Unknown or malformed critical state prevents readiness.
- Limitations are a closed set (`UNKNOWN_IDENTITY`, `UNKNOWN_CAPABILITY`,
  `UNKNOWN_LIFECYCLE`, `UNKNOWN_REGISTRY`, `NO_REGISTERED_AGENTS`,
  `PLACEHOLDER_TEMPLATES`). The export always records
  `PLACEHOLDER_TEMPLATES` because this stage ships framework contracts, not
  production agents.
- Omitted plans build the deterministic static templates; explicit malformed
  plans (non-dict, empty identity/capability lists, missing registry
  entries) degrade to unknown states and prevent readiness rather than
  silently falling back.

## 10. Backend Integration

Additive change only in `backend/asset_cve_matching.py`:

```python
summary["security_agent_framework_plan"] = export_security_agent_framework()
summary["security_agent_framework_plan_rule_version"] = (
    SECURITY_AGENT_FRAMEWORK_EXPORTER_RULE_VERSION
)
```

16 inserted lines (one import, two additive summary fields, comment). No
existing field was renamed, removed or reordered, and no R31–R37 flow was
touched. Live check through `build_matches` returns `ready=True`,
`rule_version="r38-7"` and 8 identities/capabilities/registry agents.
`tests/test_asset_cve_matching.py` passes (79 tests, 13 subtests).

## 11. Tests

Focused offline tests were added for every R38 component:

| Suite | Tests |
|---|---|
| `tests/test_security_agent_identity.py` (R38.1) | 17 |
| `tests/test_security_agent_capability.py` (R38.2) | 16 |
| `tests/test_security_agent_input.py` (R38.3) | 16 |
| `tests/test_security_agent_lifecycle.py` (R38.4) | 19 |
| `tests/test_security_agent_result.py` (R38.5) | 25 |
| `tests/test_security_agent_registry.py` (R38.6) | 20 |
| `tests/test_security_agent_framework_export.py` (R38.7) | 19 |
| **R38 total** | **132 passed** |

Coverage includes: identity/category/maturity validation; capability and
prohibited-capability enforcement; input immutability and missing
authorization context; lifecycle valid/invalid/terminal transitions; result
validation and confidence mapping; registry validation and downgrades; export
readiness gating; malformed and empty inputs; JSON serialization;
`research_only` always true; no execution vocabulary; and an AST scan proving
no execution-capable imports or calls (`subprocess`, `socket`, network, LLM,
`importlib`, `eval`, `exec`, `open`, …) exist in any of the 14 R38 modules.

Implementation refinements made while locking the contracts under test:

- input sanitizer now drops non-scalar list items (matching its documented
  "nested objects are dropped" contract);
- explicit lifecycle `previous_state="NONE"` now validates as `VALID`,
  identical to an omitted previous state;
- explicit malformed registry plans no longer fall back to the static
  registry during export (they degrade to `UNKNOWN` and block readiness).

## 12. Regression Results

```
R38 suites (7 files)                                       132 passed
R31-R37 stage export suites (7 files)                      134 passed
All tests referencing r31- … r37- (47 files)   1352 passed, 27 subtests
tests/test_asset_cve_matching.py                  79 passed, 13 subtests
Full suite: python -m pytest tests/ -q
    3283 passed, 40 failed, 376 subtests passed
```

Full-suite baseline comparison: the 40 failures are pre-existing
money-score/economics corpus drift failures (product API, sessions,
economics projection/API, opportunities, outcomes, hunt/opportunity queues,
page render, research UI, routers). Re-running the full suite with the R38
backend diff temporarily stashed produces the exact same counts
(3283 passed / 40 failed) and a byte-identical sorted `FAILED` set
(`diff` clean). No failure is attributable to R38 and no pre-existing
failure was modified or fixed.

Failure distribution (all pre-existing):

```
6 test_product_api             5 test_research_sessions
5 test_research_economics_projection
5 test_research_economics_api  4 test_research_opportunities
3 test_research_outcomes       3 test_opportunity_action_queue
3 test_hunt_queue              2 test_page_render
1 each: test_routers_fixes, test_research_ui,
        test_research_economics_calibration, test_daily_research_workflow
```

Note: `python -m unittest discover -s ai` is not runnable in this environment
because `database/db.py` opens a Mongo connection at import time (pre-existing
environment constraint, unrelated to R38). The canonical suite is
`tests/`, which fully includes all R31–R37 stage regressions.

## 13. Safety Verification

- R38 modules import only `__future__`, `hashlib`, `re`, `pydantic` and
  `ai.schemas`/`ai.knowledge`. No subprocess, shell, network, HTTP client,
  browser, Nuclei, LLM, embedding, Mongo or filesystem imports.
- An AST test in `tests/test_security_agent_framework_export.py` rejects
  forbidden imports (`subprocess`, `socket`, `http`, `urllib`, `requests`,
  `httpx`, `aiohttp`, `asyncio`, `threading`, `multiprocessing`,
  `importlib`, `ctypes`, `shutil`, `ssl`, `os`, …) and forbidden calls
  (`__import__`, `eval`, `exec`, `compile`, `open`, `os.system`,
  `os.popen`, `subprocess.*`, `importlib.*`) across all 14 R38 modules.
- Not implemented (by design): vulnerability scanning, HTTP requests,
  crawling, fuzzing, Nuclei execution, payload execution, exploit
  validation, browser automation, subprocess/shell, worker queues,
  schedulers, agent runtime, autonomous loops, tool execution, external
  APIs, LLM calls, embeddings, Mongo persistence, database writes, plugin
  loading, dynamic imports.
- No VM, deployment, systemd, Docker or docker-compose file was created or
  modified. Nothing was pushed.

## 14. Git Summary

New files committed (local only):

```
ai/schemas/security_agent_identity.py
ai/schemas/security_agent_capability.py
ai/schemas/security_agent_input.py
ai/schemas/security_agent_lifecycle.py
ai/schemas/security_agent_result.py
ai/schemas/security_agent_registry.py
ai/schemas/security_agent_framework_export.py
ai/knowledge/security_agent_identity.py
ai/knowledge/security_agent_capability.py
ai/knowledge/security_agent_input_validator.py
ai/knowledge/security_agent_lifecycle.py
ai/knowledge/security_agent_result_validator.py
ai/knowledge/security_agent_registry.py
ai/knowledge/security_agent_framework_export.py
tests/test_security_agent_identity.py
tests/test_security_agent_capability.py
tests/test_security_agent_input.py
tests/test_security_agent_lifecycle.py
tests/test_security_agent_result.py
tests/test_security_agent_registry.py
tests/test_security_agent_framework_export.py
agent-reports/stage-r38-security-agent-framework.md
```

Modified (additive, 16 lines):

```
backend/asset_cve_matching.py
```

Explicitly excluded from the commit: `utils.zip` deletion, `watch.zip`,
`agent-reports/R31-final-github-audit.md` and
`agent-reports/stage-r31-5-planning-audit.md`. No R31–R37 file was modified.

## Agent / Model

- Model: deepseek-v4.1-flash
- Stage: R38
- Role: coding agent
