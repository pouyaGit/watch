# Stage R36 — Execution Safety & Authorization Intelligence Layer

Local WSL implementation. **Planning/authorization only.** R36 is the
architectural boundary between research intelligence/orchestration and any
future execution layer. It never executes anything: no HTTP, crawling,
scanning, fuzzing, Nuclei, exploit validation, browser automation,
subprocess, shell, worker queue, task dispatch, scheduler, autonomous agent,
Mongo persistence, network, LLM/API call, embedding, VM access, deployment,
systemd or Docker change. It creates no execution runtime and does not modify
existing execution behavior.

## 1. Architecture Implemented

Deterministic pipeline over the existing R34/R35 exports:

```
R34 Strategy Export + R35 Orchestration Export
        ↓
R36.1 Execution Policy Model          (r36-1)
        ↓
R36.2 Authorization Decision Planner  (r36-2)
        ↓
R36.3 Scope & Capability Gate         (r36-3)
        ↓
R36.5 Human Approval Gate             (r36-5)
        ↓
R36.4 Execution Risk & Safety Planner (r36-4)
        ↓
R36.6 Execution Boundary Plan         (r36-6)
        ↓
R36.7 Authorization Export            (r36-7)
```

Every module is pure, stateless, JSON-serializable, pydantic-validated and
`research_only=True`. All inputs are consumed read-only and never mutated.
No wall-clock time, randomness, environment, filesystem or global state is
used.

## 2. Exact Files Changed

New schemas (`ai/schemas/`):
`execution_policy.py`, `execution_authorization_plan.py`,
`scope_capability_gate.py`, `execution_risk.py`, `human_approval_gate.py`,
`execution_boundary_plan.py`, `research_execution_authorization_export.py`.

**Naming note:** the R36.2 schema is `execution_authorization_plan.py`
because `ai/schemas/execution_authorization.py` is an existing, actively used
project module (Phase 5B execution-authorization data contract, imported by
`ai/persistence/mongo_authz.py`, `ai/stage2_dryrun.py` and their tests). The
path collision was detected before commit, the original file was restored
byte-identical (its 39 tests in `ai/test_stage2_production_reads.py` pass),
and the R36 schema now lives at the non-colliding path.

New pure planners (`ai/knowledge/`):
`execution_authorization_planner.py` (R36.1 policy resolution + R36.2
authorization), `scope_capability_gate.py`, `execution_risk_planner.py`,
`human_approval_gate.py`, `execution_boundary_planner.py`,
`research_execution_authorization_export.py`.

New tests (`tests/`): `test_execution_policy.py`,
`test_execution_authorization.py`, `test_scope_capability_gate.py`,
`test_execution_risk.py`, `test_human_approval_gate.py`,
`test_execution_boundary.py`,
`test_research_execution_authorization_export.py`.

Additive integration: `backend/asset_cve_matching.py` (+105/-0 only — imports
and new summary fields; no existing behavior changed).

Report: `agent-reports/stage-r36-execution-safety-authorization.md` (this
file). No R31/R32/R33/R34/R35 implementation file was modified.

## 3. Policy Vocabulary (R36.1)

`RESEARCH_ONLY`, `PASSIVE_ONLY`, `ACTIVE_ALLOWED`,
`HUMAN_APPROVAL_REQUIRED`, `BLOCKED`, `UNKNOWN` — closed and exact.

Resolution: an absent explicit policy defaults to the bounded
`RESEARCH_ONLY`; a provided but malformed/unknown policy resolves to
`UNKNOWN` (never permissive). Each policy carries a closed reason and bounded
constraints (`NO_TARGET_INTERACTION`, `PASSIVE_OBSERVATION_ONLY`,
`AUTHORIZED_SCOPE_ONLY`, `HUMAN_APPROVAL_MANDATORY`, `NO_ACTION_PERMITTED`,
`UNKNOWN_NO_ACTION`). No free-form execution permission exists.

## 4. Authorization Precedence (R36.2)

Exact first-match order (documented in code and tests):

1. malformed/unknown policy **or** malformed/empty critical context
   (invalid strategy type or invalid orchestration role/workflow)
   → `UNKNOWN` / `UNKNOWN_POLICY` or `MALFORMED_CONTEXT`;
2. `BLOCKED` → `BLOCK` / `POLICY_BLOCKED` (terminal);
3. `HUMAN_APPROVAL_REQUIRED` → `REQUIRE_HUMAN_APPROVAL` /
   `HUMAN_APPROVAL_REQUIRED`;
4. `RESEARCH_ONLY` / `PASSIVE_ONLY` → `ALLOW_WITH_LIMITS` /
   `RESEARCH_ONLY_LIMITS` or `PASSIVE_ONLY_LIMITS`;
5. `ACTIVE_ALLOWED` with valid context → `ALLOW` / `ACTIVE_ALLOWED_VALID`.

Risk can never override `BLOCK`; a low-risk result can never bypass
`HUMAN_APPROVAL_REQUIRED`; confidence alone never grants authorization.

## 5. Scope / Capability Behavior (R36.3)

Models WHAT (`capability`), WHO (`agent_role`), WHERE (`scope`), WHY
(`source_strategy`) and CONSTRAINTS. Capabilities are the seven conceptual
research capabilities (`ASSET_ANALYSIS`, `IDENTITY_ANALYSIS`,
`TECHNOLOGY_ANALYSIS`, `VERSION_ANALYSIS`, `EVIDENCE_ANALYSIS`,
`HISTORY_ANALYSIS`, `HUMAN_REVIEW`) plus `UNKNOWN`; no operational execution
capability exists.

Scope is `COMPONENT_SCOPED` (HIGH certainty), `AUTHORIZED_RESEARCH_SCOPE` or
`PROGRAM_SCOPED` (MEDIUM), else `UNKNOWN`. A missing, malformed, `GLOBAL`,
`NONE` or unrecognized scope resolves to `UNKNOWN` and `authorized=False` —
it can never become unrestricted scope. There is no `UNRESTRICTED` value in
the vocabulary. `authorized` requires an ALLOW/ALLOW_WITH_LIMITS decision
with both a known capability and a known scope.

## 6. Risk Model (R36.4)

Levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `UNKNOWN`. Base level per
authorization decision: ALLOW→LOW, ALLOW_WITH_LIMITS→MEDIUM,
REQUIRE_HUMAN_APPROVAL→HIGH, BLOCK→CRITICAL, UNKNOWN→UNKNOWN.

Escalation-only factors (each bumps one level, capped at CRITICAL):
`MISSING_SCOPE`, `INVALID_WORKFLOW`, `LOW_CONFIDENCE`; rejected/expired
approvals jump to `CRITICAL`. `authorization_authoritative` is forced `True`
and the schema cannot represent risk as permission.

## 7. Human Approval Model (R36.5)

States: `NOT_REQUIRED`, `PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`,
`UNKNOWN`. Derivation: BLOCKED/BLOCK → `NOT_REQUIRED` (no action permitted);
`HUMAN_APPROVAL_REQUIRED`/`REQUIRE_HUMAN_APPROVAL` → `PENDING` (required),
with a valid caller-supplied explicit state (`PENDING`/`APPROVED`/`REJECTED`/
`EXPIRED`) preserved; research/passive/authorized decisions → `NOT_REQUIRED`;
unknown context → `UNKNOWN`. This is a state/planning model only — no
approval service, database, API, UI, notification or persistence exists.

## 8. Execution Boundary (R36.6)

States: `RESEARCH_ONLY`, `AUTHORIZED`, `HUMAN_REVIEW_REQUIRED`, `BLOCKED`,
`UNKNOWN`. The plan records authorization result, allowed conceptual
capabilities, scope, required human approval, risk, constraints, blocked
conditions, source strategy/orchestration, limitations, and an
`execution_permitted` eligibility flag. `execution_performed` is forced
`False` by the schema (passing `True` raises a validation error) — R36 itself
performs no execution. A satisfied-approval ALLOW with known scope and known
risk is the only path with `execution_permitted=True`.

## 9. Export Readiness Rules (R36.7)

`ready=True` only when every critical component is present and non-UNKNOWN:
policy, authorization decision, scope (+capability), risk, approval and
boundary. Any UNKNOWN critical state prevents readiness. A valid BLOCKed chain
is `ready=True` (with a `BLOCKED` limitation) because the authorization plan
is complete; an UNKNOWN scope prevents readiness even when blocked. Closed
limitations: `UNKNOWN_AUTHORIZATION`, `UNKNOWN_RISK`, `UNKNOWN_SCOPE`,
`UNKNOWN_APPROVAL`, `UNKNOWN_BOUNDARY`, `BLOCKED`,
`HUMAN_APPROVAL_PENDING`, `MISSING_SCOPE`, `INVALID_WORKFLOW`.

## 10. Backend Integration

`backend/asset_cve_matching.py` adds only these summary fields plus
rule-version companions:

`execution_policy_plan`, `execution_authorization_plan`,
`scope_capability_gate_plan`, `execution_risk_plan`,
`human_approval_gate_plan`, `execution_boundary_plan`,
`research_execution_authorization_export_plan`.

Default backend policy is `RESEARCH_ONLY` (no explicit execution policy is
configured), so candidates resolve to `ALLOW_WITH_LIMITS` /
`RESEARCH_ONLY` boundary / `execution_permitted=False`. The R31.5 global
support scope resolves conservatively to `UNKNOWN` in the scope gate, so the
authorization export is not ready for those candidates (`UNKNOWN_SCOPE`,
`MISSING_SCOPE`) — this is the intended conservative behavior. Existing
R29/Money/CVE behavior is untouched.

## 11. Focused Test Counts

| Suite | Tests |
|---|---|
| `tests.test_execution_policy` | 14 |
| `tests.test_execution_authorization` | 25 |
| `tests.test_scope_capability_gate` | 17 |
| `tests.test_execution_risk` | 18 |
| `tests.test_human_approval_gate` | 17 |
| `tests.test_execution_boundary` | 19 |
| `tests.test_research_execution_authorization_export` | 22 |
| **Total R36** | **132 (all OK)** |

Coverage includes: exact closed vocabularies, every policy/decision/boundary
branch, authorization precedence, BLOCK-not-overridable and
approval-not-bypassable behavior, risk-not-permission, conservative scope,
approval state transitions, boundary correctness, readiness gating, malformed
inputs, no mutation, JSON serialization, `research_only`, no operational
execution vocabulary and hermetic backend integration (mocked inventory, no
live Mongo, Money Score canary).

## 12. Regression Results

```
new R36 suites                                     132 tests   OK
combined R31-R36 + R29/R30 regression              Ran 1516 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
```

## 13. Full-Suite Baseline Comparison

Baseline before R36 (`/tmp/opencode/r35_full.txt`): **2966 tests / 37
failures / 3 errors**. After R36: **3098 tests / 37 failures / 3 errors**
(+132 new tests). The sorted `FAIL:`/`ERROR:` line sets are byte-identical
(`diff` clean): no new failure is attributable to R36, and no pre-existing
failure was modified. `py_compile` OK; `git diff --check` clean.

Flakiness note: one intermediate full-suite run under load additionally
failed three `tests.test_research_agent_r24_3.TestHTTPSSeam` tests
(HTTP-seam network timing); they pass standalone (5/5 OK) and the clean
re-run returned the exact baseline failure set. They do not import any R36
module and are unrelated to this stage.

## 14. Safety / Execution-Boundary Verification

- All new modules import only stdlib `re`, pydantic and `ai.schemas`/
  `ai.knowledge`; no `subprocess`, `socket`, `requests`, `urllib`,
  `http.client`, `os.system`, `popen`, browser, Nuclei, Mongo or LLM imports
  exist (a case-insensitive grep matched only docstring boundary statements).
- `ExecutionBoundaryPlan.execution_performed` is schema-forced `False`;
  `ExecutionRiskPlan.authorization_authoritative` is schema-forced `True`.
- No worker queue, scheduler, dispatch, runtime or persistence was created.
- The backend diff is +105/-0: imports and additive projections only.
- Deployment/VM: no systemd, Docker, deployment, `.service` or shell scripts
  touched; no VM access.

## 15. Git Diff / Stat Summary

```
$ git diff --stat      # tracked changes at implementation time
 backend/asset_cve_matching.py | 105 +++++++++++++++++++++++++++++++++++++++++
 1 file changed, 105 insertions(+)

$ git status --short
 D utils.zip
?? agent-reports/R31-final-github-audit.md
?? agent-reports/stage-r31-5-planning-audit.md
?? watch.zip
 + the 21 new R36 files (13 modules, 7 tests, 1 report)
```

R36 commit contains only the R36 files; `utils.zip`, `watch.zip`,
`agent-reports/R31-final-github-audit.md` and
`agent-reports/stage-r31-5-planning-audit.md` remain untouched outside the
commit.

## 16. VM / Deployment Confirmation

No VM access, no deployment change, no systemd change, no Docker change, no
service restart and no remote push occurred. R36 is a planning/authorization
milestone, not an execution milestone.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R36
- Role: coding agent
