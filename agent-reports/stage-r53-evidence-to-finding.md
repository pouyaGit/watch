# R53 Evidence → Finding Intelligence

| | |
|---|---|
| Date | 2026-09-14 |
| Stage | R53 |
| Scope | Structured research → research finding candidates |
| Follows | R38 / R39 / R40 / R41 / R42 / R43 / R44 / R45 / R46 / R47 / R48 / R49 / R50 / R51 / R52 |
| Commit message | `feat(finding): add r53 evidence to finding intelligence` |
| Push status | **Not pushed** (local commit only) |
| Focused tests | 125 passed |
| Full suite | 5001 passed, 40 failed (unchanged baseline), 376 subtests |
| Real provider calls during testing | **None** (R53 is offline by construction; R52 advisory integration is exercised with the deterministic R45 mock provider) |

## Summary

R53 transforms the structured research outputs produced by the specialist
agents (R39–R50) and the R52 orchestrator into structured **research
finding candidates** suitable for a future bug-bounty workflow.

R53 is not an exploitation or vulnerability-confirmation engine. It:

- creates one deterministic finding candidate per safe specialist result;
- preserves hypotheses, evidence, evaluation/collaboration/feedback
  references, provenance and governance exactly as produced upstream;
- derives a conservative, closed research state and confidence;
- mirrors severity only from observed structured CVSS context;
- states potential impact only, never business impact;
- mirrors remediation only from upstream structured hints;
- forces `confirmation_state = NOT_CONFIRMED` on every finding;
- never executes anything and never contacts the network.

## Architecture

```
ai/schemas/finding_identity.py      r53-1  finding identity
ai/schemas/finding_context.py       r53-2  descriptive context + endpoint/component
ai/schemas/finding_hypothesis.py    r53-3  hypothesis linkage
ai/schemas/finding_evidence.py      r53-4  evidence linkage
ai/schemas/finding_assessment.py    r53-5  state/confidence/severity/impact/remediation
ai/schemas/finding_result.py        r53-6  finding + intelligence result container

ai/knowledge/finding_reasoning.py   r53-2  identity/context/impact/severity/remediation
ai/knowledge/finding_state.py       r53-5  state + confidence derivation
ai/knowledge/finding_builder.py     r53-6  builder + R52 consumption + container
```

Flow:

```
R52 orchestration result (or standalone structured specialist results)
  -> normalize entries (R52-style entries or raw specialist results)
  -> safety filter (research_only / forbidden claims / safety-failed evaluation)
  -> per finding:
       identity (content-addressed fnd-<16hex>)
       context (title/summary/technical/observed facts/endpoint-component)
       hypothesis linkage (preserved, never invented)
       evidence linkage (observed vs planned vs merged, completeness)
       correlation (R43 groups/conflicts attributed per specialist)
       references (R42/R43/R44/R45-R51)
       assessment (state, confidence, severity, impact, remediation, NOT_CONFIRMED)
       provenance + governance + limitations
  -> bounded R53 intelligence result (fni-<16hex>)
```

Reused upstream contracts (no duplication): R38 canonical categories, R42
evaluation result sanitizer, R43 hypothesis-group/conflict/merged-evidence
sanitizers and confidence summary, R44 learning recommendation sanitizer,
R37 governance export rule version. No R38–R52 file was modified.

## Finding Contract

`FindingPlan` (r53-6) keys:

| Key | Content |
|---|---|
| `rule_version` | `r53-6` |
| `finding_id` | `fnd-<16 hex>` content token |
| `state` | closed finding state |
| `identity` | category, specialist name, agent id, fixed labels |
| `context` | title, summary, technical description, observed facts, endpoint/component |
| `hypotheses` | preserved hypothesis references + confidence summary |
| `evidence` | state, completeness, origin, observed/planned/merged separation |
| `assessment` | state, confidence + reasons, severity + source, impact, remediation, confirmation |
| `correlation` | preserved R43 duplicate/related/conflicting groups and conflicts |
| `references` | evaluation / collaboration / feedback / advisory references |
| `learning_recommendations` | preserved R44 recommendations attributed by agent |
| `provenance` | category, specialist, agent id, orchestration id, source stages |
| `governance` | bounded R37 governance reference |
| `limitations` | closed limitation codes |
| `research_only`, `deterministic` | forced `True` |

`FindingIntelligenceResultPlan` (r53-6) keys: `rule_version`,
`intelligence_id` (`fni-<16 hex>`), `orchestration_id`, `status`,
`findings`, `skipped_candidates`, `evaluation_summary`,
`collaboration_reference`, `learning_reference`, `advisory_reference`,
`errors`, `provenance`, `governance`, `limitations`, `research_only`,
`deterministic`.

## Finding States

Closed vocabulary (`ai/schemas/finding_assessment.py`), with conservative
precedence:

| State | Derivation |
|---|---|
| `INSUFFICIENT_EVIDENCE` | no hypotheses, or specialist status `CREATED`/`UNKNOWN`, or nothing observed and nothing planned |
| `CONFLICTED` | at least one R43 conflict references this specialist |
| `NEEDS_MORE_EVIDENCE` | evidence state `PARTIAL`/`UNKNOWN` or completeness `PARTIAL`/`MISSING`/`UNKNOWN` |
| `CONFIRMED_OBSERVED` | complete evidence plan + status `COMPLETED` + evaluation `PASS`/gate `PASS` + no diagnostics + rating `EXCELLENT`/`GOOD` + ≥5 observed facts |
| `EVIDENCE_SUPPORTED` | complete evidence plan + status `COMPLETED` + evaluation `PASS`/gate `PASS` |
| `RESEARCH_CANDIDATE` | hypotheses exist but none of the stronger conditions hold |

`CONFIRMED_OBSERVED` records only that the **structured observation set is
complete and internally consistent** — it is never a vulnerability
confirmation. Every finding additionally forces
`confirmation_state = NOT_CONFIRMED`; the schema rejects any other value.
The complete evidence *plan* is explicitly not collected evidence.

## Evidence Handling

- `observed_context`: known (non-empty, non-`UNKNOWN`) structured context
  facts, deterministically ordered, bounded.
- `planned_requirements`: the specialist's own evidence-state categories
  (requirements, not collected evidence).
- `merged_requirements`: R43 merged requirements attributed to this agent.
- `evidence_state`: mirrored from the specialist plan.
- `evidence_completeness`: derived conservatively (`COMPLETE` only for a
  complete state with items; `PARTIAL`, `MISSING`, `UNKNOWN` otherwise).
- `evidence_origin`: `SPECIALIST_PLAN` / `COLLABORATION_MERGED` / `NONE`.
- `evidence_references`: `<agent_id>:evidence_plan` and
  `collab:<id>:merged_evidence`.
- `assumptions_recorded` is forced `False`; no evidence is ever
  manufactured.

## Hypothesis Handling

Every hypothesis is carried through with its rule version, type,
supporting signals, confidence, priority, safety limitations, subject
reference, rationale and fingerprint, in upstream order, bounded and never
reclassified. An empty hypothesis list stays empty (no invention), and the
linkage confidence summary uses the existing R43 vocabulary
(`AGREE`/`DIVERGENT`/`UNKNOWN`). R53 never promotes a hypothesis into a
vulnerability.

## Confidence Rules

`confidence = min(upstream levels) ∩ explicit caps`:

- upstream meet: specialist result confidence, evidence-plan confidence and
  context confidence (when present), plus upstream status reason;
- caps: evaluation unavailable → `MEDIUM`; safety `DEGRADED` → `LOW`
  (`CEILING_*`/`WEAK`/`CRITICAL`/`CONFIDENCE_OVERSTATED` diagnostics →
  `LOW`; other quality diagnostics → `MEDIUM`; `ACCEPTABLE` → `MEDIUM`);
  incomplete evidence → `MEDIUM`; conflicts → `MEDIUM`;
  `NEEDS_MORE_EVIDENCE`/`INSUFFICIENT_EVIDENCE` → `LOW`;
- agreement/correlation is **not an input**: there is no rule that raises
  confidence, and identical signals with more conflicts never score higher;
- `confidence_reasons` is a closed, ordered list documenting the applied
  constraints; uncertainty is additionally surfaced through the state and
  limitations.

Severity is never computed: it mirrors an observed CVSS context value only
(`severity_source = CVSS_CONTEXT`), otherwise `UNKNOWN` /
`NOT_ASSESSED`. Impact is `POTENTIAL` (with a fixed category-level
statement explicitly disclaiming observed impact) or `UNKNOWN`;
`business_impact_asserted` is forced `False`. Remediation mirrors R42
diagnostic hints as `RESEARCH_QUALITY` items or stays `UNAVAILABLE`.

## Provenance

Per finding: canonical category, specialist name, deterministic agent id,
R52 orchestration id, executed source stages (`SELECTION` … `ADVISORY`,
`FINDING_INTELLIGENCE`), hypothesis and evidence references, evaluation
(`overall_rating`, `safety_state`, `hard_gate_state`, confidence,
diagnostic codes), collaboration (`collaboration_id`), feedback
(`feedback_id`, recommendation ids) and advisory (`advisory_id`,
validation state) references. The container records
`finding_count` and source stages. No provenance is fabricated; references
are `UNKNOWN` unless the corresponding layer really produced an artifact.

## Governance

The caller's R37 governance export is preserved as a bounded reference
(`rule_version`, `ready`, `provenance_state`, `trace_state`,
`audit_state`, `explanation_state`, `reference_state`). A reference is
`REFERENCED` only when the supplied plan carries the R37 rule version and
the four governance components; otherwise it degrades to `UNKNOWN` with a
`GOVERNANCE_UNKNOWN` limitation. R53 never invents a governance record and
never claims governed execution.

## Limitations

Closed limitation vocabulary covers: no execution, no network requests, no
vulnerability confirmation, no exploit generation, no evidence collected,
hypothesis-only, evidence required, insufficient context, governance
unknown, evaluation/collaboration/feedback/advisory unavailable, conflict
present, duplicate correlation present, remediation unavailable, impact not
observed, asset context unavailable, severity not assessed,
research-candidate-only and correlation unavailable. Missing evidence,
conflicting evidence, incomplete context and upstream restrictions remain
visible per finding and at container level.

## R52 Integration

R53 consumes the R52 orchestration result through its structured Python API:
`build_finding_intelligence(orchestration_result=...)` /
`findings_from_orchestration(...)`. R52's selection, safety, ordering and
result contract are untouched (R52 test suite passes unchanged, including
its "no other knowledge module references the orchestrator" static check,
which R53 satisfies by keeping its own governance projection). R53 does not
create a parallel orchestration system: it consumes the R52 result and never
re-runs selection, invocation or evaluation. Standalone structured
specialist results (with optional R42/R43/R44 artifacts) are supported for
direct use; supplying both an orchestration result and standalone inputs
fails closed with `INVALID_INPUT`.

## Safety Boundary

- AST/static tests over all nine R53 modules: no `requests`, `httpx`,
  `urllib`, `socket`, `ssl`, `dns`, `http`, `aiohttp`, `urllib3`, `pycurl`,
  `paramiko`, no `subprocess`/`os`/shell, no browser automation, no scanners
  (`nuclei`, `sqlmap`), no database clients (`sqlite3`, `sqlalchemy`,
  `psycopg2`, `pymysql`), no `importlib`/`__pkgutil__`/`stevedore`, no
  `__import__`/`eval`/`exec`/`compile`/`open`, no LLM SDKs (`openai`,
  `anthropic`, `litellm`, `ollama`), no `ai.providers` import and no
  URLs.
- R53 never imports specialist implementations or the R52 orchestrator
  module; it consumes contracts only.
- Unsafe results never become findings: `research_only != True`,
  forbidden execution/confirmation claims (reusing R42's claim token
  vocabularies), or a safety-failed R42 evaluation cause a structured
  skip (`SAFETY_FAILURE` / `FORBIDDEN_CLAIM`) and an error record.
- Structural guarantees: `confirmation_state` can only be
  `NOT_CONFIRMED`; `business_impact_asserted` can only be `False`;
  `assumptions_recorded` can only be `False`; `OBSERVED` impact is never
  produced by R53.
- The public builder API has no credential/provider parameters.

## Tests

Focused R53 suites (125 tests):

```
tests/test_finding_identity.py     9 passed
tests/test_finding_context.py     18 passed
tests/test_finding_hypothesis.py   9 passed
tests/test_finding_evidence.py    13 passed
tests/test_finding_state.py       26 passed
tests/test_finding_builder.py     33 passed
tests/test_finding_safety.py      17 passed
R53 total                        125 passed
```

Coverage includes: every finding state; state precedence; conservative
confidence (meet, caps, no agreement boost); hypothesis and evidence
preservation; observed/planned/merged evidence separation; evidence
completeness and origin derivation; deterministic identity (stable across
state updates) and byte-identical output; no runtime identifiers; R52 → R53
integration including advisory and governance; duplicate/related/conflicting
correlation preservation without deduplication or isolation loss; per-agent
attribution of correlation; provenance and reference preservation;
limitation disclosure; empty/minimal input; malformed and unsupported
input; unsupported claims rejected; safety-failed and `research_only=False`
results rejected; AST/static isolation; confirmation/impact/assumption
invariants; input immutability; backend non-integration.

No network, no real LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes and no persistence are used by the
R53 tests.

## Full Suite

```
python -m pytest tests/ -q -p no:cacheprovider
5001 passed, 40 failed, 1 warning, 376 subtests passed in 53.13s
```

Baseline (R52): `4876 passed, 40 failed, 376 subtests`.

- passed growth: `5001 - 4876 = 125` — exactly the 125 new R53 tests;
- failed count unchanged at 40; subtests unchanged at 376;
- the 40 failures are byte-identical to the R52 baseline failure set
  (verified with a sorted diff) and none references R53.

Per-stage regression (all passed):

```
R38 132 | R39 100 | R40 122 | R41 131 | R42 91 | R43 102 | R44 68
R45 90  | R46 97  | R47 136 | R48 150 | R49 156 | R50 125 | R51 111
R52 101 (test_agent_orchestrator*)
Backend (tests/test_asset_cve_matching.py)  79 passed, 13 subtests
AI safety (knowledge_store/xss_researcher/
  xss_llm_researcher/openrouter)            96 passed
```

## Changed Files

Added (17 — 16 implementation/test files + this report):

```
ai/schemas/finding_identity.py
ai/schemas/finding_context.py
ai/schemas/finding_hypothesis.py
ai/schemas/finding_evidence.py
ai/schemas/finding_assessment.py
ai/schemas/finding_result.py
ai/knowledge/finding_reasoning.py
ai/knowledge/finding_state.py
ai/knowledge/finding_builder.py
tests/test_finding_identity.py
tests/test_finding_context.py
tests/test_finding_hypothesis.py
tests/test_finding_evidence.py
tests/test_finding_state.py
tests/test_finding_builder.py
tests/test_finding_safety.py
agent-reports/stage-r53-evidence-to-finding.md
```

Modified: **none**. No existing R38–R52 file was modified, no backend,
crawl, ns, database, Docker, systemd, deployment, scheduler or VPS file was
touched. The pre-existing worktree items (` D utils.zip`, `?? watch.zip`,
`?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`) remain untouched and
outside the commit.

## Git Commit

Commit message: `feat(finding): add r53 evidence to finding intelligence`.
Parent: `ddc7a08` (R52, agent orchestrator). Exactly one local commit was
created; nothing was pushed. The exact commit hash is reported in the final
task response (a commit cannot embed its own hash; this report is part of
that single R53 commit).

## Verification

- `git diff --check` clean; staged diff check clean.
- No existing tracked file modified (`git status --short` shows only new
  untracked R53 files plus the pre-existing unrelated items).
- R52's own safety test that no other `ai/knowledge` module references the
  orchestrator passes.
- R52 output for a fixed context is byte-identical after R53 runs (builder
  does not mutate inputs).
- No network/execution capability introduced (AST + behavioral tests).
- No secrets, credentials, bearer tokens or private keys in the R53 source
  (the only literal matching a key-shaped pattern is a synthetic,
  non-functional test fixture used to assert that secrets never appear in
  finding output).

## Known Pre-existing Failures

The full suite retains exactly the same 40 pre-existing failures as the R45–R52
baselines (money-score / economics corpus drift, dashboard render,
product API, research sessions/outcomes/UI, router lookup). They are
unrelated to R53 and were not modified or fixed.
