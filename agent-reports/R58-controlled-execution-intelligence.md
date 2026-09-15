# R58 Controlled Execution Intelligence

## 1. Summary

R58 adds a deterministic, research-only **controlled execution gate** between
research/learning intelligence and any future execution layer:

```
R53 Finding Intelligence
        ↓
R54 Finding Correlation
        ↓
R55 Research Prioritization
        ↓
R56 Human Decision Boundary
        ↓
R57 Continuous Learning Intelligence
        ↓
R58 Controlled Execution Boundary        ← this stage
        ↓
future actual execution (does not exist in R58)
```

R58 answers exactly one question:

> **"Is a proposed action structurally eligible to enter a controlled
> execution workflow, under explicit human authorization and safety
> constraints?"**

R58 is a **gate, not an executor**. It validates that an explicit human
authorization mirrors one structured execution request exactly — same
action, target, scope, finding and decision — under a deterministic safety
gate, and produces a declarative plan plus an auditable result. It never
sends requests, never resolves DNS, never runs subprocesses or shell
commands, never launches scanners, never automates browsers, never generates
payloads or attack plans, never confirms vulnerabilities and never executes
anything. `execution_performed` and `external_executor_present` are forced
`False` and no `EXECUTED` state exists anywhere in the architecture.

Core principle preserved end to end: **AI can recommend, human can
authorize, R58 validates authorization, and only a future execution layer
may ever execute.**

## 2. Architecture

Four schema layers and two pure engines, all additive:

| File | Rule version | Role |
|---|---|---|
| `ai/schemas/execution_control_result.py` | `r58-4` | Shared gate vocabulary (safety results, control statuses/outcomes, allow/block reasons, error categories, limitations, audit) and result contract |
| `ai/schemas/execution_request.py` | `r58-1` | Execution request contract, closed action vocabulary, scope kinds, rejection codes |
| `ai/schemas/controlled_execution_authorization.py` | `r58-2` | Execution authorization contract, human-only authority, validity, approval constraints |
| `ai/schemas/controlled_execution_plan.py` | `r58-3` | Declarative plan contract, closed step/precondition/safety/stop/rollback vocabularies |
| `ai/knowledge/execution_control_rules.py` | `r58-5` | Pure primitives: deterministic ids, negation-aware safety gate, exact matching, decision resolution, plan content, status derivation, control outcomes |
| `ai/knowledge/execution_control.py` | `r58-6` | Builder/public API and fail-closed input validation |

Public API (never performs execution):

- `build_execution_request(...)` — build one structured request
- `validate_execution_authorization(...)` — validate exact human authorization
- `build_controlled_execution_plan(...)` — build the declarative plan
- `evaluate_execution_control(...)` — run the full gate
- `export_execution_control(...)` — alias for the full gate

Inputs (all optional, validated fail-closed):
`execution_request` (R58 or a raw request dict), `human_review_result`
(R56), `human_decision` (R56.1), explicit `authorization_context`
(source/authority/decision/approved action/scope/target/constraints/validity),
and the context layers `finding_intelligence` (R53), `correlation_result`
(R54), `prioritization_result` (R55) and `learning_result` (R57).

Reuse (never duplication): R53/R54/R55/R56 sanitizers and reference shapes,
R56 decision vocabulary, R57 calibration recommendation vocabulary, R56
governance reference shape (`sanitize_finding_governance`), shared R58
limitation vocabulary.

## 3. Execution request model

`ExecutionRequestPlan` (`r58-1`, `extra="forbid"`):

- `request_id` (`exr-<16 hex>`, content-derived), `finding_id`
- `action_type` (closed), `requested_action_type` (raw claim preserved for
  audit), `action_scope`, `scope_kind`, `target_reference`
- `purpose`, `requested_by`
- `request_state` (`NOT_REQUESTED` / `REQUESTED` / `BLOCKED` / `INVALID`),
  `request_rejection_codes` (closed)
- `human_decision_reference` (bounded R56 reference), `authorization_context`
- `priority_reference`, `correlation_reference`, `finding_reference`
- `safety_context` (closed safety state + safety reasons; every
  execution-capable flag forced `False`)
- `provenance`, `governance`, `limitations`
- `execution_requested`; forced `execution_authorized = False`,
  `vulnerability_confirmed = False`, `exploit_authorized = False`,
  `confirmation_state = NOT_CONFIRMED`, `research_only = True`,
  `deterministic = True`

**Closed action vocabulary (safe research/control actions only):**

`COLLECT_EXISTING_EVIDENCE`, `REVIEW_EXISTING_RESPONSE`, `RECHECK_SCOPE`,
`REASSESS_CONTEXT`, `PREPARE_RESEARCH_STEP`, `REQUEST_HUMAN_REVIEW`.

There is no exploit, payload, attack, scan, browser or execution action, and
there is no way to add one through input: an unsupported action is preserved
verbatim in `requested_action_type`, mapped to `UNSPECIFIED` (never to
another valid action) and rejected with `ACTION_NOT_SUPPORTED`.

Fail-closed rules: missing finding/scope/target/requester/purpose produce
closed rejection codes; wildcard scope/target is blocked; unsafe flags or
forbidden markers block the request; a malformed request is `INVALID`.
`requested_by = AI_ADVISORY` is permitted (AI may recommend) but never
authorizes.

## 4. Authorization model

`ControlledExecutionAuthorizationPlan` (`r58-2`, `extra="forbid"`):

- `authorization_id` (`exa-<16 hex>`), `request_id`, `finding_id`
- `authorization_status` (`NOT_REQUESTED` / `REQUESTED` / `BLOCKED` /
  `AUTHORIZED` / `EXPIRED` / `INVALID`)
- `authorization_source` / `authorization_authority` (`HUMAN`, plus
  claimed `AI` / `SYSTEM` / `UNSPECIFIED` retained as rejection evidence),
  `human_authority`
- `decision_reference`, `decision_type`, `decision_state`
- `approved_action`, `approved_scope`, `approved_target`
- `approval_constraints` (always includes `RESEARCH_ONLY_ACTION`,
  `NO_NETWORK_EXECUTION`, `NO_COMMAND_EXECUTION`, `NO_PAYLOAD_GENERATION`,
  `SINGLE_ACTION`, `SINGLE_TARGET`, `SINGLE_SCOPE`, `NO_SCOPE_EXPANSION`,
  `NO_TARGET_EXPANSION`, `HUMAN_REVIEW_REQUIRED`,
  `FUTURE_EXECUTOR_REQUIRED`, `NO_AUTONOMOUS_AUTHORIZATION`)
- `allow_reasons` / `rejection_codes` (closed), `validity`
- forced `exploit_authorized = False`, `vulnerability_confirmed = False`,
  `confirmation_state = NOT_CONFIRMED`
- `provenance`, `governance`, `limitations`, `research_only`,
  `deterministic`

A model validator makes `AUTHORIZED` structurally impossible without an
explicit `HUMAN` source, `HUMAN` authority, `human_authority = True`,
`execution_authorized = True` and zero rejection codes. AI-originated,
missing, ambiguous, mismatched and expired authorization all produce
`BLOCKED`/`EXPIRED`/`INVALID` records with closed reason codes and can never
become authority.

Closed rejection vocabulary includes `AUTHORIZATION_MISSING`,
`HUMAN_DECISION_REQUIRED`, `HUMAN_DECISION_PENDING`,
`AI_AUTHORIZATION_REJECTED`, `AUTHORIZATION_AMBIGUOUS`, `ACTION_MISMATCH`,
`TARGET_MISMATCH`, `SCOPE_MISMATCH`, `FINDING_MISMATCH`,
`DECISION_MISMATCH`, `DECISION_DOES_NOT_AUTHORIZE`,
`ESCALATION_REVIEW_REQUIRED`, `AUTHORIZATION_EXPIRED`,
`AUTHORIZATION_INVALID`, `EXECUTION_NOT_REQUESTED`, `REQUEST_INVALID`,
`UNSUPPORTED_ACTION_NOT_ALLOWED`, `WILDCARD_SCOPE_NOT_ALLOWED`,
`R57_RECOMMENDATION_REQUIRES_REVIEW`, `RULE_VERSION_MISMATCH`,
`INVALID_INPUT`, `MALFORMED_INPUT`.

**No implicit expansion:** authorization for one action, target, scope,
finding or decision never transfers to another. Scope and target matching is
exact equality after bounded normalization; wildcards are rejected; a
broader approved scope does not authorize a narrower or different request.

**Deterministic validity:** validity is explicit structured metadata only
(`VALID` / `EXPIRED` / `INVALID` / `UNSPECIFIED` with
`EXPLICIT_METADATA` or `DEFAULT_VALID_NO_EXPIRY` basis). No wall clock is
consulted anywhere; omitted validity defaults to currently valid with no
expiry behavior.

## 5. Controlled execution plan

`ControlledExecutionPlan` (`r58-3`, `extra="forbid"`):

- `plan_id` (`exp-<16 hex>`), `request_id`, `finding_id`, `action_type`,
  `action_scope`, `target_reference`
- `ordered_steps` — declarative only. Every step is forced
  `execution_mode = DECLARATIVE_ONLY`, `declarative = True`,
  `performs_network_io = False`, `executes_commands = False`,
  `requires_external_executor = False`
- `target_scope` (exact target/scope/scope-kind, `wildcard`, forced
  `expands_scope = False`)
- `preconditions` — closed codes including `HUMAN_AUTHORIZATION_VALID`,
  `ACTION_EXACT_MATCH`, `TARGET_EXACT_MATCH`, `SCOPE_EXACT_MATCH`,
  `SAFETY_GATE_PASS`, `EXTERNAL_EXECUTOR_ABSENT`
- `authorization_reference` (bounded authorization id/status/decision)
- `safety_checks` — `NO_NETWORK_IO`, `NO_COMMAND_EXECUTION`,
  `NO_PAYLOAD_GENERATION`, `NO_EXPLOIT_AUTHORIZATION`,
  `NO_VULNERABILITY_CONFIRMATION`, `HUMAN_AUTHORITY_EXPLICIT`,
  `SCOPE_EXACT_MATCH`, `TARGET_EXACT_MATCH`, `NO_AUTONOMOUS_AUTHORIZATION`,
  `EXTERNAL_EXECUTOR_ABSENT`
- `stop_conditions` — `AUTHORIZATION_REVOKED`, `SCOPE_CHANGED`,
  `TARGET_CHANGED`, `ACTION_CHANGED`, `FINDING_CHANGED`, `SAFETY_BLOCK`,
  `HUMAN_ESCALATION`, `VALIDITY_EXPIRED`, `UNEXPECTED_STATE`
- `rollback` — `abort_supported = True`, `rollback_supported = False`
  (nothing is executed, so nothing needs rollback),
  `rollback_reason = NO_EXECUTION_PERFORMED`
- `provenance`, `governance`, `limitations`
- `execution_status`; forced `execution_performed = False`,
  `external_executor_present = False`, `external_executor_state = ABSENT`,
  `plan_declarative = True`

Closed step vocabulary (safe research/control steps only):
`LOAD_RECORDED_EVIDENCE`, `REVIEW_STORED_RESPONSE`, `CONFIRM_SCOPE_METADATA`,
`RECONFIRM_CONTEXT_SUMMARY`, `PREPARE_RESEARCH_NOTE`, `REQUEST_HUMAN_REVIEW`,
`VERIFY_HUMAN_AUTHORIZATION`, `ASSERT_SAFETY_CONSTRAINTS`. Each action maps
to a fixed ordered subset ending with authorization verification and safety
assertion. There is no exploit, payload, command, scanner or browser step.

`execution_status` vocabulary: `NOT_REQUESTED`, `REQUESTED`, `BLOCKED`,
`AUTHORIZED`, `READY_FOR_EXTERNAL_EXECUTOR`, `EXPIRED`, `INVALID`.
**There is no `EXECUTED` state.** `READY_FOR_EXTERNAL_EXECUTOR` is a
declarative readiness marker that requires a bound `AUTHORIZED`
authorization; it never claims an executor exists and always carries
`execution_performed = False`.

## 6. Safety gate

The safety gate is deterministic, negation-aware and fail-closed. It scans
every supplied input (request, authorization context, R56 review/decision,
R53/R54/R55/R57 layers, pre-built authorization/plan) for two classes of
violation:

1. **True safety flags** (lowercased key → closed rejection reason):
   `exploit_authorized`, `execute_exploit`, `run_exploit`, `weaponize`,
   `vulnerability_confirmed`, `confirm_vulnerability`, `payload`,
   `payload_generation`, `generate_payload`, `attack_plan`,
   `attack_planning`, `plan_attack`, `command`, `command_execution`,
   `execute_command`, `shell_command`, `run_command`, `arbitrary_code`,
   `code_execution`, `execute_code`, `network_execution`, `network_io`,
   `send_request`, `http_request`, `dns_query`, `scanner_execution`,
   `run_scanner`, `launch_scanner`, `browser_automation`,
   `automate_browser`, `run_browser`, `subprocess`,
   `subprocess_execution`, `spawn_process`, `autonomous_authorization`,
   `auto_authorize`, `auto_execute`, `policy_bypass`, `bypass_policy`,
   `disable_safety`, `disable_governance`, `human_approval_bypass`,
   `bypass_human`, `bypass_approval`, `skip_human_approval`,
   `unsafe_action`.
2. **Free-text markers** (`EXECUTE_EXPLOIT`, `RUN_EXPLOIT`, `WEAPONIZE`,
   `GENERATE_PAYLOAD`, `PAYLOAD_GENERATION`, `ATTACK_PLAN`, `PLAN_ATTACK`,
   `RUN_COMMAND`, `EXECUTE_COMMAND`, `SHELL_EXEC`, `OS_SYSTEM`,
   `ARBITRARY_CODE_EXECUTION`, `EXECUTE_CODE`, `NETWORK_EXECUTION`,
   `SEND_REQUEST`, `DNS_QUERY`, `RUN_SCANNER`, `LAUNCH_SCANNER`,
   `SCANNER_EXECUTION`, `BROWSER_AUTOMATION`, `AUTOMATE_BROWSER`,
   `SUBPROCESS_EXECUTION`, `SPAWN_PROCESS`, `AUTONOMOUS_EXECUTION`,
   `AUTO_EXECUTE`, `DISABLE_SAFETY`, `DISABLE_GOVERNANCE`, `BYPASS_HUMAN`,
   `BYPASS_APPROVAL`, `SKIP_HUMAN_APPROVAL`, `CONFIRM_VULNERABILITY`,
   `VULNERABILITY_CONFIRMED`).

Negation-aware matching makes the legitimate negative codes
(`NO_NETWORK_EXECUTION`, `NO_PAYLOAD_GENERATION`,
`ATTACK_PLANNING_NOT_AUTHORIZED`, `EXECUTION_NOT_AUTHORIZED`, ...) safe, and
closed-code fields (`safety_reasons`, `rejection_codes`, `block_reasons`,
`allow_reasons`, `limitations`, `preconditions`, `safety_checks`,
`stop_conditions`, `approval_constraints`, `decision_options`,
`not_authorized`) are excluded from free-text scanning so that structured
reasons are never self-flagging.

Rejected requests are represented as structured failures with closed reason
codes. Unsafe requests are **never downgraded** into safe requests and an
unsafe action is **never sanitized into another action**. When a request is
already blocked, its structured safety evidence is preserved and re-applied
on every re-evaluation.

## 7. Human authority boundary

R56 remains the source of human decision authority. R58 consumes a valid
R56.3 review result or R56.1 decision; it never reinterprets the decision,
and `APPROVE_RESEARCH` never means "execute anything related to the
finding". Only the explicitly structured research action represented by the
execution request can be authorized, and only when the human has supplied
matching explicit approvals.

| Human decision | R58 handling |
|---|---|
| `APPROVE_RESEARCH` | May precede an authorization, but only an exact explicit approval (action + scope + target + decision) can authorize; approval alone is `AUTHORIZATION_MISSING` |
| `REQUEST_MORE_EVIDENCE` | `BLOCKED` — `DECISION_DOES_NOT_AUTHORIZE` |
| `DEFER` | `BLOCKED` — `DECISION_DOES_NOT_AUTHORIZE` |
| `REJECT` | `BLOCKED` — `DECISION_DOES_NOT_AUTHORIZE` |
| `ESCALATE` | `BLOCKED` — `ESCALATION_REVIEW_REQUIRED` (review required; no implicit authority) |
| `NEEDS_REVIEW` | `BLOCKED` — `DECISION_DOES_NOT_AUTHORIZE` |

Review authority is re-verified (human source, human authority,
`human_authority = True`, falsified execution/confirmation/exploit flags).
AI-originated, system-originated, autonomous and bypassed authority is
rejected with `AI_AUTHORIZATION_REJECTED`. Multiple distinct decisions for
one finding, conflicting context values or a list-valued claim is rejected
as `AUTHORIZATION_AMBIGUOUS`. A pending review is
`HUMAN_DECISION_PENDING`; a missing decision is `AUTHORIZATION_MISSING`.

## 8. Scope matching

Matching is exact on every dimension after deterministic bounded
normalization:

- **action**: closed-vocabulary equality; an unsupported requested action
  can never match any approval;
- **target**: exact equality (target A never authorizes target B);
- **scope**: exact equality (`/api/v1/users` never authorizes `/`, and a
  broader approval never expands to another scope);
- **finding**: validated finding-id equality;
- **decision**: the request's referenced decision id must equal the resolved
  decision (when supplied), and the authorization context's decision
  reference must equal it too;
- **request**: the authorization must reference the same request id.

Wildcards (`*`) in approved or requested scope/target are rejected with
`WILDCARD_SCOPE_NOT_ALLOWED`; there is no wildcard authorization in the
closed policy vocabulary. Expansion attempts surface as
`SCOPE_MISMATCH` / `TARGET_MISMATCH`. No implicit expansion of any kind is
possible.

## 9. R53 integration

R53 finding intelligence is accepted as read-only research context
(`rule_version = r53-6` required when supplied). Finding state,
confidence, evidence and governance are preserved in the request's
`finding_reference`; provenance records the R53 rule version and
orchestration id. **A finding can never authorize execution**: a request
built from finding context alone is `BLOCKED`. A state such as
`CONFIRMED_OBSERVED` is never interpreted as vulnerability confirmation for
exploitation; `vulnerability_confirmed` and `exploit_authorized` remain
`False` and `confirmation_state` remains `NOT_CONFIRMED`, with the
`FINDING_NOT_CONFIRMATION` limitation recorded.

## 10. R54 integration

R54 correlation results are accepted as read-only context
(`rule_version = r54-2`). Correlation ids, rule versions and relationship
facts are preserved in the request/authorization/result provenance.
**Correlation can never authorize execution**: a correlation result alone
produces `BLOCKED` with the `CORRELATION_NOT_AUTHORIZATION` limitation, and
correlation is never treated as causality or as permission.

## 11. R55 integration

R55 prioritization is accepted as read-only context
(`rule_version = r55-2`). Priority score, band, ranking position and reasons
are preserved in the request's `priority_reference`. **Priority does not
equal authorization**: a `CRITICAL` or `HIGH` priority never authorizes
execution by itself; without an exact human authorization the result is
`BLOCKED` with the `PRIORITY_NOT_AUTHORIZATION` limitation.

## 12. R56 integration

R56 is the only authority source. R58 reads `human_review_result`
(`r56-3`) and/or a direct `human_decision` (`r56-1`), preserves
`decision_id`, `decision_type`, `decision_state`, `decision_source`,
`decision_authority`, `human_authority`, rationale and governance, and
never rewrites or supersedes the decision. R56's `execution_authorized =
False`, `vulnerability_confirmed = False` and `NOT_CONFIRMED` invariants are
re-verified; any deviation makes the decision unusable (fail closed).

## 13. R57 integration

R57 recommendations may inform whether additional research review is useful;
they can never authorize execution. The gate inspects
`calibration_recommendations` (`rule_version = r57-4` required when
supplied):

- `REQUEST_MORE_EVIDENCE` → execution remains `BLOCKED`
  (`R57_RECOMMENDATION_REQUIRES_REVIEW`), even with an otherwise valid human
  authorization;
- `REVIEW_SAFETY_BOUNDARY` → execution remains `BLOCKED`
  (`R57_RECOMMENDATION_REQUIRES_REVIEW`);
- `PRESERVE_SUCCESS_PATTERN`, `REVIEW_PRIORITY_ALIGNMENT` and every other
  recommendation → informational only: they neither authorize nor block,
  and without an exact human authorization the result is still `BLOCKED`;
- an R57 result alone (`BLOCKED`, `AUTHORIZATION_MISSING` + the
  `LEARNING_NOT_AUTHORIZATION` limitation) can never authorize anything.

R57 is never an authorization source.

## 14. Auditability

Every controlled execution decision preserves, in a deterministic
`audit` record and in the result container:

- `request_id`, `decision_id`, `authorization_id`, `plan_id`
- `finding_id`, `action_type`, `action_scope`, `target_reference`
- `safety_result` and `safety_reasons`
- `control_outcome`, `authorization_status`, `execution_status`
- `outcome_reasons` — the closed allow/block reasons
- `provenance` (finding/correlation/priority/decision/learning rule versions
  and ids, source stages) and `governance` (R37 reference shape)
- `limitations` (including explicit non-authorization and non-execution
  limitations)

The audit contains no secrets, credentials, tokens or raw network data
(tested). Audit and control ids are content-derived
(`exd-<16 hex>`, `exc-<16 hex>`).

## 15. Determinism

- Content-derived ids only: `exr-` (request), `exa-` (authorization),
  `exp-` (plan), `exc-` (control), `exd-` (audit), all
  `sha256(canonical JSON)[:16]`.
- Canonical ordering for every closed list (allow/block reasons, safety
  reasons, limitations, steps, preconditions, safety checks, stop
  conditions, constraints), independent of input ordering.
- No timestamps, UUIDs, pids, randomness or wall-clock dependence; validity
  is explicit structured metadata, and omitted validity deterministically
  defaults to `DEFAULT_VALID_NO_EXPIRY`.
- Repeated processing of the same request/authorization/plan produces
  byte-identical output (replay consistency tested), including for blocked
  and expired records.
- Inputs are never mutated; upstream artifacts are read-only.

## 16. Static safety

AST/static tests (`tests/test_execution_control_safety.py`) enforce that no
R58 module imports or invokes: `requests`, `httpx`, `urllib`, `socket`,
`http`, `aiohttp`, `urllib3`, `subprocess`, `os`/`os.system`/`os.popen`,
`shutil`, `ssl`, `dns`, browser automation (`selenium`, `playwright`,
`pyppeteer`), scanner frameworks (`nuclei`, `sqlmap`, `curl`), databases,
LLM providers/SDKs, dynamic loading (`importlib`, `ctypes`, `pkgutil`),
`random`, `uuid`, `time`, `datetime`, `eval`, `exec`, `compile`, `open`,
`setattr`, `delattr`, `globals`, `locals`, `__import__` and `sys.modules`.
Hashing utilities (`hashlib`) and `json` are explicitly allowed.

Additional static/behavioral safety checks:

- no URLs (`http://`, `https://`) anywhere in R58 modules;
- no forbidden claim markers (`CONFIRMED_EXPLOIT`, `IS_VULNERABLE`,
  `RUN_PAYLOAD`, ...);
- public API has no dangerous parameters (`command`, `payload`, `script`,
  `url`, `network`, `scanner`, `browser`, `subprocess`, `shell`,
  credentials/tokens);
- no autonomous self-modification helpers (`apply_`, `modify_`,
  `update_agent`, `update_rule`, `set_threshold`, `persist_`, `execute_`,
  `run_command`, `launch_`, `scan_target`);
- output contains no executable keys and never serializes
  `"execution_performed": true`, `"external_executor_present": true`,
  `"exploit_authorized": true`, `"vulnerability_confirmed": true` or
  `"confirmation_state": "CONFIRMED"`;
- a runtime test replaces `socket.socket` and `subprocess.Popen` with
  raising stubs and proves the full gate still completes without touching
  them;
- backend and deployment files contain no reference to R58 modules.

## 17. New files

```
ai/schemas/execution_request.py
ai/schemas/controlled_execution_authorization.py
ai/schemas/controlled_execution_plan.py
ai/schemas/execution_control_result.py
ai/knowledge/execution_control_rules.py
ai/knowledge/execution_control.py
tests/test_execution_request.py
tests/test_controlled_execution_authorization.py
tests/test_controlled_execution.py
tests/test_execution_control_safety.py
agent-reports/R58-controlled-execution-intelligence.md
```

## 18. Existing files modified

**None.** No R38–R57 file, backend file, database file, NS/DNS file,
crawl/parameter-discovery file, Docker/systemd/deployment/VM file or any
tracked file was modified. R58 is purely additive (0 deletions).

**Documented naming deviation (required by existing architecture):** the
task template proposed `ai/schemas/execution_authorization.py` and
`tests/test_execution_authorization.py`, but both paths already exist as the
R36 / Phase 5B execution-authorization subsystem (R36.1–R36.7 and Phase 5B
authorizer). Modifying those files is out of scope and forbidden by the
scope rules, so the R58 authorization schema is named
`ai/schemas/controlled_execution_authorization.py` and its focused test file
`tests/test_controlled_execution_authorization.py`, following the existing
`controlled_execution_*` / `execution_control_*` naming pattern. All other
proposed filenames are used exactly as specified.

## 19. Focused tests

```
python -m pytest tests/test_execution_request.py -q -p no:cacheprovider
26 passed

python -m pytest tests/test_controlled_execution_authorization.py -q -p no:cacheprovider
43 passed

python -m pytest tests/test_controlled_execution.py -q -p no:cacheprovider
39 passed

python -m pytest tests/test_execution_control_safety.py -q -p no:cacheprovider
34 passed

combined focused run: 142 passed
```

Coverage maps to every required case: request schema and closed action
vocabulary; authorization schema and human-only authority; AI, missing,
ambiguous, action, target, scope, finding and decision rejection;
`APPROVE_RESEARCH` handling; `REQUEST_MORE_EVIDENCE`, `DEFER`, `REJECT`,
`ESCALATE`, `NEEDS_REVIEW`; R57 recommendation cannot authorize; R55
priority cannot authorize; R53 finding cannot authorize (including
`CONFIRMED_OBSERVED`); R54 correlation cannot authorize; safety, exploit,
payload, attack-planning, network, subprocess, scanner and browser
rejection; autonomous authorization and human-bypass rejection; declarative
plan generation and status transitions; blocked/authorized/ready plans and
`READY_FOR_EXTERNAL_EXECUTOR` semantics; no `EXECUTED` state; deterministic
ids and byte-identical output; stable ordering under shuffled inputs; input
immutability; provenance/governance/limitation preservation; audit trail;
replay consistency; empty, malformed and unsupported inputs; no
network/subprocess/execution/LLM/autonomous modification.

## 20. Regression tests

Regression is provided by the full existing suite plus explicit R42–R57
integration tests inside the R58 files (full R53→R54→R55→R56→R57→R58 chain,
upstream output immutability, unchanged upstream rule versions `r53-6`,
`r54-2`, `r55-2`, `r56-3`, `r57-4`, and no R58 keys leaking into upstream
artifacts).

## 21. Full-suite results

Final frozen run:

```
python -m pytest tests/ -q -p no:cacheprovider
40 failed, 5688 passed, 1 warning, 376 subtests passed in 55.75s
```

R57 baseline (measured before any R58 change, same environment):

```
40 failed, 5546 passed, 1 warning, 376 subtests passed in 69.01s
```

- passed growth: `5688 - 5546 = 142` — exactly the 142 new focused R58
  tests;
- failed count unchanged at 40; subtests unchanged at 376;
- the sorted failure list is **byte-identical** to the R57 baseline set
  (pre-existing backend/API/corpus/UI failures such as
  `tests/test_product_api.py`, `tests/test_research_economics_*.py`,
  `tests/test_research_sessions.py`, `tests/test_routers_fixes.py`); no
  failure references R58.

## 22. Git diff/stat

```
 ai/schemas/execution_request.py                   |  807 +
 ai/schemas/controlled_execution_authorization.py  |  779 +
 ai/schemas/controlled_execution_plan.py           |  822 +
 ai/schemas/execution_control_result.py            | 1053 +
 ai/knowledge/execution_control_rules.py           | 1175 +
 ai/knowledge/execution_control.py                 | 1987 +
 tests/test_execution_request.py                   |  420 +
 tests/test_controlled_execution_authorization.py  |  730 +
 tests/test_controlled_execution.py                |  735 +
 tests/test_execution_control_safety.py            |  620 +
 agent-reports/R58-controlled-execution-intelligence.md |  596 +
 11 files changed, 9724 insertions(+)
```

All changes are additions (0 deletions), and `git diff --check` (including
the staged diff) is clean.

## 23. Git status

Before the R58 commit (after staging exactly the R58 files):

```
A  ai/schemas/execution_request.py
A  ai/schemas/controlled_execution_authorization.py
A  ai/schemas/controlled_execution_plan.py
A  ai/schemas/execution_control_result.py
A  ai/knowledge/execution_control_rules.py
A  ai/knowledge/execution_control.py
A  tests/test_execution_request.py
A  tests/test_controlled_execution_authorization.py
A  tests/test_controlled_execution.py
A  tests/test_execution_control_safety.py
A  agent-reports/R58-controlled-execution-intelligence.md
 D utils.zip                              (pre-existing, untouched)
?? agent-reports/R31-final-github-audit.md   (pre-existing, untouched)
?? agent-reports/stage-r31-5-planning-audit.md (pre-existing, untouched)
?? watch.zip                             (pre-existing, untouched)
```

The pre-existing unrelated worktree items (` D utils.zip`, `?? watch.zip`,
`?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`) are not part of the R58
commit. No existing tracked file was modified:
`git diff` against `d98a191` contains only additions.

## 24. Commit hash

One local commit was created:

- Subject: `feat(execution): add r58 controlled execution intelligence`
- Parent: `d98a191` (R57 Continuous Learning Intelligence)
- Exact commit hash is reported in the final task response (a commit cannot
  embed its own hash; this report is part of that single R58 commit).

## 25. Push confirmation

**NO push was performed.** Nothing was pushed to GitHub; no remote branch,
tag or remote-tracking state was modified. The commit exists locally only.
No Google VM was accessed or modified and no backend, database, deployment
or infrastructure file was touched.
