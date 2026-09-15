# R60 — Watch Bug Bounty Copilot

## 1. Objective

R60 introduces the first product-level intelligence layer on top of the
existing R31–R59 architecture: a deterministic, advisory **Watch Bug Bounty
Copilot**.

The copilot turns the existing research intelligence and end-to-end workflow
outputs into a structured researcher briefing:

```
Watch → Research Intelligence (R31–R59) → Copilot Briefing → Human Researcher
```

It answers, from existing structured artifacts only:

1. What should I investigate?
2. Why is it interesting?
3. What evidence already exists?
4. What findings are related?
5. How strong is the evidence?
6. What should I do next?
7. What requires human review?
8. What should NOT be executed automatically?

R60 is **advisory only**. It never sends HTTP requests, resolves DNS, runs
subprocesses, launches scanners or browsers, generates payloads, exploits or
confirms vulnerabilities, bypasses R56, bypasses R58 or modifies
authorization state. R56 remains authoritative, R58 remains the final
execution-control boundary and R59 remains the end-to-end workflow layer.
No `EXECUTED` state exists and nothing implies that execution occurred.

## 2. Existing architecture inspected

Before coding, the repository was inspected for equivalent abstractions so
R60 reuses rather than duplicates:

- **R31.10–R31.12 hunt priority / actionability / action planner**
  (`ai/knowledge/hunt_priority.py`, `hunt_actionability.py`,
  `hunt_action_planner.py`). These operate on Asset↔CVE research candidates
  from the historical-memory line and already own an action vocabulary
  (`VERIFY_VERSION`, `COLLECT_HTTP_EVIDENCE`, ...). R60 deliberately does
  **not** create a second hunt actionability concept; its recommendations
  reuse the R59 workflow vocabulary and the R58 safe research/control action
  vocabulary and never name target-verification/network actions.
- **R26 opportunity intelligence** (`ai/schemas/research_opportunity.py`,
  `ai/knowledge/opportunity.py`). `ResearchOpportunity` already exists for
  the lead/economics line, so R60's model is named `CopilotOpportunity`
  (`ai/schemas/copilot_opportunity.py`) and uses distinct ids (`bco-`),
  avoiding a duplicate `research_opportunity` abstraction.
- **R26.3 `daily_research.build_workflow_summary`**. A daily action-queue
  presentation summary over opportunity items already exists; R60's summary
  API is therefore `summarize_copilot_brief` (no duplicate
  `build_workflow_summary`).
- **R35.2 research workflow graph** and **R25.7 research sessions**. A
  planning graph and a time-accounting session record, not a state machine
  over R42–R58 artifacts; not duplicated.
- **R52 agent orchestrator** (`orchestration_result`, `r52-6`) — consumed as
  provenance context; not re-run.
- **R53 finding intelligence** (`r53-6`), **R54 correlation** (`r54-2`),
  **R55 prioritization** (`r55-2`), **R56 human review** (`r56-3`),
  **R57 learning** (`r57-4`), **R58 controlled execution** (`r58-4`),
  **R59 workflow** (`r59-4`) — consumed read-only through their existing
  result contracts.
- **R37 governance export** — projected through the existing
  `build_finding_governance_reference`.
- **R58 safety scanner and R57 blocking-recommendation vocabulary** —
  imported (`safety_reasons_for`, `structured_safety_reasons`,
  `BLOCKING_LEARNING_RECOMMENDATIONS`), never re-implemented.

Reused vocabularies (verbatim): R55 priority bands/scores/reasons, R53
confidence and evidence-completeness levels, R53 finding/impact states, R54
relationship types, R56 rationale codes (for review reasons), R58 safe
actions (`EXECUTION_ACTIONS`), R59 workflow states / safety statuses /
next actions, R37 governance reference.

## 3. Design

Four schema layers and two pure engines, all additive:

| File | Rule version | Role |
|---|---|---|
| `ai/schemas/bug_bounty_copilot.py` | `r60-1` | Copilot input: bounded research context, bounded layer references, closed options |
| `ai/schemas/copilot_opportunity.py` | `r60-2` | Research opportunity + advisory recommendation contract; opportunity classes, review reasons, rationale codes, safety restrictions |
| `ai/schemas/copilot_brief.py` | `r60-3` | Copilot brief: ranked opportunities, evidence summary, confidence + basis, recommended actions, human-review requirements, safety status/restrictions, fixed non-execution boundary |
| `ai/schemas/copilot_result.py` | `r60-4` | Top-level result: status, brief, summary, structured errors, forced advisory/no-execution invariants |
| `ai/knowledge/bug_bounty_copilot_rules.py` | `r60-5` | Pure primitives: ids, safety scan, context facts, correlation index, opportunity composition, confidence, review reasons, brief composition, status |
| `ai/knowledge/bug_bounty_copilot.py` | `r60-6` | Builder/public API and fail-closed validation, R59 public-API composition |

Public API:

- `build_bug_bounty_copilot(...)` — full advisory result
- `build_copilot_brief(...)` — brief only
- `build_copilot_opportunities(...)` — ranked opportunities
- `determine_copilot_priorities(...)` — alias for ranked opportunities
- `summarize_copilot_brief(...)` — deterministic summary
- `export_bug_bounty_copilot(...)` — alias for the builder

Key design decisions:

- **Product layer, not a new orchestrator**: R60 consumes existing outputs;
  when artifacts are supplied without a workflow result it calls R59's
  public API (`build_security_research_workflow`) to resolve the current
  workflow state. It never replaces R52/R56/R58/R59 and never re-derives
  their logic.
- **No new action vocabulary**: recommendations carry a verbatim R59
  `workflow_next_action` and a verbatim R58 `research_action`
  (one of the six safe research/control actions or empty).
- **No LLM**: composition is deterministic; LLM-assisted briefing can be
  layered on later without changing this contract.

## 4. Files added/changed

Added (10 implementation/test files + 1 report):

```
ai/schemas/bug_bounty_copilot.py
ai/schemas/copilot_opportunity.py
ai/schemas/copilot_brief.py
ai/schemas/copilot_result.py
ai/knowledge/bug_bounty_copilot_rules.py
ai/knowledge/bug_bounty_copilot.py
tests/test_copilot_opportunity.py
tests/test_copilot_brief.py
tests/test_bug_bounty_copilot.py
tests/test_bug_bounty_copilot_safety.py
agent-reports/R60-watch-bug-bounty-copilot.md
```

Changed: **none**. No R31–R59 file, backend file, database file, NS/DNS file,
crawl/parameter-discovery file or Docker/systemd/deployment/VM file was
modified. The commit is purely additive.

## 5. Data flow

```
copilot input (target / research context / bounded references / options)
        +
R53 findings ─ R54 correlation ─ R55 prioritization
        + R56 human review + R57 learning + R58 execution control
        │
        ▼
R59 public API (build_security_research_workflow)      ← only when no
        │                                                 workflow result
        ▼                                                 is supplied
workflow facts: state, safety status, next action/reason
        │
        ├── safety scan (R58 scanner reused over every input)
        ├── contradictory-context check (prioritized ids ⊆ finding ids)
        ├── human / learning / execution context facts
        └── correlation index (related ids, conflict, duplicate)
        │
        ▼
opportunity composition (one per ranked/deferred R55 plan, ordered)
        │  class + confidence + review reasons + rationale
        │  + recommendation (R59 action + R58 action)
        ▼
brief composition (evidence summary, confidence, review requirements,
        safety status/restrictions, non-execution boundary, actions)
        │
        ▼
copilot result (status COMPLETED / PARTIAL / NO_CONTEXT / FAILED,
        summary, structured errors) → human researcher
```

Partial context is supported at every level; missing artifacts simply yield
fewer opportunities and a `PARTIAL`/`NO_CONTEXT` status with explicit
errors. Nothing is optimistically authorized.

## 6. Deterministic rules

- **Ids**: content-derived `sha256(canonical JSON)[:16]`:
  `bbc-` (copilot input), `bco-` (opportunity), `bcr-` (recommendation),
  `bcb-` (brief), `bbr-` (result). No timestamps, UUIDs, pids or randomness.
- **Opportunity ordering**: R55 ranked findings in ranking order, then
  deferred findings; deduplicated by finding id; capped by
  `max_opportunities` (default 8, bounded 1–24).
- **Opportunity class** (research attention only, never a vulnerability
  verdict): safety block → `BLOCKED_RESEARCH`; missing/unknown evidence →
  `INSUFFICIENT_EVIDENCE`; `DEFERRED` band → `DEFERRED_RESEARCH`;
  `CRITICAL`/`HIGH` → `HIGH_PRIORITY_RESEARCH`; `MEDIUM` →
  `PRIORITY_RESEARCH`; `LOW` → `STANDARD_RESEARCH`.
- **Confidence** (conservative minimum): `min(upstream confidence,
  evidence completeness)` ranked HIGH/MEDIUM/LOW/UNKNOWN, with a conflict
  cap at LOW and a duplicate cap at MEDIUM; basis codes are explicit
  (`EVIDENCE_COMPLETE`, `CONFLICT_PRESENT`, ...). Brief confidence follows
  the primary (highest-priority) opportunity and is capped by safety /
  workflow blocks and pending decisions.
- **Recommended research action** (verbatim R58 vocabulary):
  blocked → none; human boundary blocker (pending/escalation/needs-review
  decision, blocking learning, blocked execution, blocked workflow) →
  `REQUEST_HUMAN_REVIEW`; insufficient/partial evidence →
  `COLLECT_EXISTING_EVIDENCE`; conflict → `REASSESS_CONTEXT`; duplicate →
  `REVIEW_EXISTING_RESPONSE`; deferred → none; otherwise →
  `PREPARE_RESEARCH_STEP`. `RECHECK_SCOPE` stays reserved and is never
  emitted without an explicit scope signal (no invented gaps).
- **Human-review requirements**: evidence incomplete/missing, conflicts,
  duplicates, conflicted/insufficient finding states, low/unknown
  confidence, missing severity context, incomplete provenance, unknown
  governance, pending/escalated/needs-review decisions, blocking learning
  and blocked execution produce explicit closed reasons; the brief is
  review-required whenever any reason exists.
- **Rationale**: `research_rationale_codes` are the verbatim R55 priority
  reasons (the canonical "why this is interesting"); copilot-specific
  `copilot_rationale_codes` describe briefing composition.
- **Brief safety status**: reuses the R59 workflow safety vocabulary
  (including `CONTROLLED_AUTHORIZATION` and
  `READY_FOR_EXTERNAL_EXECUTOR`), with `SAFETY_BLOCKED`/`HUMAN_REVIEW_REQUIRED`
  taking precedence where imposed by the copilot's own gate.
- **Status**: `NO_CONTEXT` (nothing supplied), `FAILED` (fatal malformed /
  mis-versioned input), `PARTIAL` (structured non-fatal errors such as
  safety blocking, conflicting context or a blocked upstream workflow),
  `COMPLETED` otherwise. Safe failure over optimistic authorization.

## 7. Safety boundaries

- **Advisory only**: no execution, no confirmation, no exploit
  authorization. The result and brief force `execution_performed = False`,
  `external_executor_present = False`, `vulnerability_confirmed = False`,
  `exploit_authorized = False`, `confirmation_state = NOT_CONFIRMED`, and
  every recommendation forces `advisory = True`, `auto_execute = False`.
- **Structural non-execution boundary**: the brief always carries the fixed
  `non_execution_boundary` record (including `r58_gate_required = True` and
  `human_authority_required = True`) plus the full closed safety-restriction
  list (`NO_NETWORK_EXECUTION`, `NO_SCANNER_EXECUTION`,
  `NO_BROWSER_AUTOMATION`, `NO_SUBPROCESS_EXECUTION`,
  `NO_PAYLOAD_GENERATION`, `NO_ATTACK_PLANNING`,
  `NO_EXPLOIT_AUTHORIZATION`, `NO_VULNERABILITY_CONFIRMATION`,
  `HUMAN_AUTHORITY_REQUIRED`, `R58_GATE_REQUIRED`, `RESEARCH_ONLY`).
- **Human authority preserved**: R56 decision fields are never
  reinterpreted; `APPROVE_RESEARCH` is not confirmation, not exploit
  authorization and not execution authorization. Any action crossing into
  execution remains subject to R56 and R58.
- **R58 is the final gate**: the copilot only reports the R58 outcome
  (`CONTROLLED_AUTHORIZATION`, `READY_FOR_EXTERNAL_EXECUTOR`,
  `EXECUTION_BLOCKED`); it never creates or modifies authorization.
- **Fail closed**: malformed, mis-versioned, contradictory or unsafe inputs
  produce structured errors, `FAILED`/`PARTIAL` statuses and explicit human
  review requirements; the R58 safety scanner rejects unsafe flags/markers
  in any input.
- **No new capability**: AST tests forbid network, DNS, subprocess, shell,
  browser, scanner, database, LLM provider, dynamic import, `random`,
  `uuid`, `time`, `datetime`, `eval`, `exec`, `open` and `__import__` in all
  six modules; a runtime test replaces `socket.socket` and
  `subprocess.Popen` with raising stubs and proves the copilot still works.

## 8. Focused tests

```
python -m pytest tests/test_copilot_opportunity.py -q -p no:cacheprovider
22 passed

python -m pytest tests/test_copilot_brief.py -q -p no:cacheprovider
23 passed

python -m pytest tests/test_bug_bounty_copilot.py -q -p no:cacheprovider
50 passed

python -m pytest tests/test_bug_bounty_copilot_safety.py -q -p no:cacheprovider
23 passed

combined focused run: 118 passed
```

Coverage includes: input/brief/result/opportunity/recommendation schemas;
empty, malformed and mis-versioned inputs; deterministic ids and
byte-identical output; replay consistency; upstream immutability;
prioritization ordering and verbatim priority/band/score preservation;
evidence summaries; confidence caps for conflict/duplicate; related findings
and relationship types; recommended-action mapping and deduplication; human
decision handling (approve, request-more-evidence, defer, reject, escalate,
needs review); R57 learning context and review-required blocking; R58
blocked/authorized/ready integration; partial workflows and conflicting
context; safety blocking; options handling; provenance/governance/limitation
preservation; the full R53→R59→R60 chain; no executed state; no
vulnerability confirmation; no exploit authorization; no network,
subprocess, scanner, browser or LLM capability; no autonomous modification.

## 9. Full test suite

```
python -m pytest tests/ -q -p no:cacheprovider
40 failed, 5930 passed, 1 warning, 376 subtests passed in 67.40s
```

## 10. R59 baseline comparison

R59 baseline (measured before any R60 change, same environment):

```
40 failed, 5812 passed, 1 warning, 376 subtests passed in 60.75s
```

- passed growth: `5930 - 5812 = 118` — exactly the 118 new focused R60
  tests;
- failed count unchanged at 40; subtests unchanged at 376;
- the sorted failure list is **byte-identical** to the R59 baseline set
  (pre-existing backend/API/corpus/UI failures); no failure references R60.

## 11. Git commit

One local commit was created:

- Subject: `feat(copilot): add r60 watch bug bounty copilot`
- Parent: `acde1d4` (R59 End-to-End Security Research Workflow)
- Exact commit hash is reported in the final task response (a commit cannot
  embed its own hash; this report is part of that single R60 commit).
- Content: 11 added files (10 implementation/test + this report), only
  additions, `git diff --check` clean.

## 12. Working tree status

Before the commit, after staging exactly the R60 files:

```
A  ai/schemas/bug_bounty_copilot.py
A  ai/schemas/copilot_opportunity.py
A  ai/schemas/copilot_brief.py
A  ai/schemas/copilot_result.py
A  ai/knowledge/bug_bounty_copilot_rules.py
A  ai/knowledge/bug_bounty_copilot.py
A  tests/test_copilot_opportunity.py
A  tests/test_copilot_brief.py
A  tests/test_bug_bounty_copilot.py
A  tests/test_bug_bounty_copilot_safety.py
A  agent-reports/R60-watch-bug-bounty-copilot.md
 D utils.zip                              (pre-existing, untouched)
?? agent-reports/R31-final-github-audit.md   (pre-existing, untouched)
?? agent-reports/stage-r31-5-planning-audit.md (pre-existing, untouched)
?? watch.zip                             (pre-existing, untouched)
```

The pre-existing unrelated worktree items are not part of the R60 commit.
No existing tracked file was modified.

## 13. Remote status

`origin/main` was verified as `acde1d4` (R59) before and after the R60 work.
**NO push was performed**; no remote branch, tag or remote-tracking state was
modified. The R60 commit exists locally only and awaits a manual push.

## 14. Known limitations

- The copilot is prescriptive, not autonomous: it recommends the next
  advisory step and never advances the workflow itself.
- Without R55 prioritization there are no opportunities; without a workflow
  result the copilot composes R59 state from supplied artifacts, and when
  nothing is supplied it reports `NO_CONTEXT`.
- Contradictory context detection is bounded to prioritized finding ids
  versus finding intelligence; other cross-artifact inconsistencies surface
  through R59's own fail-closed validation and are reported as upstream
  workflow errors.
- Cross-source confidence is a conservative minimum of existing signals; the
  copilot never invents new severity, exploitability or payout judgments and
  never re-scores R55 priority.
- The briefing is deterministic structured data. It is intentionally
  LLM-free; a future LLM narration layer can be added without changing the
  contract or the safety boundary.
- `RECHECK_SCOPE` remains reserved: it is not emitted because no explicit
  scope signal exists in the current artifact set; inventing one would
  violate the no-invented-gaps rule.
- The pre-existing 40 full-suite failures are unrelated to R60 and unchanged
  (backend/API/corpus/UI tests).

## 15. Final R60 status: PASS

Delivered: a deterministic, advisory Watch Bug Bounty Copilot that composes
the existing R31–R59 intelligence into a product-level briefing with ranked
opportunities, evidence and confidence reporting, related findings,
recommended next actions, explicit human-review requirements, safety
restrictions and a structural non-execution boundary — with no autonomous
execution, no vulnerability confirmation, no exploit authorization and no
modification to R31–R59 behavior.
