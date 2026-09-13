# Stage R39 — XSS Specialist Agent v2

The first specialist security agent built on the Watch AI Core: a
deterministic XSS **research** intelligence agent. It analyzes bounded
context, plans hypotheses and evidence, and produces an R38-compatible
result with an R37 governance reference.

R39 is research intelligence only. It executes nothing: no HTTP requests,
payload execution, browser or JavaScript execution, DOM crawling, fuzzing,
exploit confirmation, auth bypass, subprocess, shell, external APIs, LLM
calls, persistence, workers or schedulers.

- Stage: R39
- Rule versions: `r39-1` … `r39-5`
- Commit: `feat(research): add r39 xss specialist agent` (local only, not
  pushed)

## 1. XSS Agent architecture

```
XSS Agent Identity          (r39-1)
        ↓
XSS Context Analyzer        (r39-2)
        ↓
XSS Hypothesis Planner      (r39-3)
        ↓
XSS Evidence Planner        (r39-4)
        ↓
XSS Result Export           (r39-5)
        ↓
R38-compatible agent result + R37 governance reference
```

| Component | Schema | Engine | Rule |
|---|---|---|---|
| Identity | `ai/schemas/xss_agent_identity.py` | `ai/knowledge/xss_agent_identity.py` | r39-1 |
| Context | `ai/schemas/xss_context_analysis.py` | `ai/knowledge/xss_context_analyzer.py` | r39-2 |
| Hypothesis | `ai/schemas/xss_hypothesis.py` | `ai/knowledge/xss_hypothesis_planner.py` | r39-3 |
| Evidence | `ai/schemas/xss_evidence_plan.py` | `ai/knowledge/xss_evidence_planner.py` | r39-4 |
| Result | `ai/schemas/xss_agent_result.py` | `ai/knowledge/xss_agent_result_export.py` | r39-5 |

All components are deterministic, pure, stateless, `research_only=True`,
JSON serializable and pydantic validated (`extra="forbid"`, forced rule
versions).

## 2. R38 integration

- **Identity conformance**: the XSS identity uses R38's `CATEGORY_XSS`,
  `AGENT_ID_RE` (`sa-<16 hex>`) and the R38 content-token id function.
  `xss_agent_identity_to_r38()` projects it onto a valid R38
  `SecurityAgentIdentityPlan` (verified by constructing the R38 model).
- **Input contract**: `export_xss_agent_result(security_agent_input=...)`
  routes all context through R38's `validate_security_agent_input`, so
  R31–R37 context enters only via the framework's read-only bounded
  contract. An R38 identity block for category `XSS` is adopted
  deterministically.
- **Result compatibility**: status/confidence reuse the R38 vocabularies,
  and `xss_agent_result_to_r38()` maps the result (hypotheses →
  `HYPOTHESES_RECORDED`, evidence state → R38 evidence summary) through
  R38's `validate_security_agent_result`, producing a dict that constructs
  a valid `SecurityAgentResultPlan`.

## 3. Context model

`XSSContextAnalysisPlan`: `rule_version`, `input_location`,
`output_context`, `reflection_state`, `encoding_state`,
`framework_context`, `context_confidence`, `research_only`.

- `input_location`: `QUERY`, `BODY`, `HEADER`, `COOKIE`, `UNKNOWN`.
- `output_context`: `HTML`, `ATTRIBUTE`, `JAVASCRIPT`, `DOM`, `UNKNOWN`.
- `reflection_state`: `REFLECTED`, `NOT_OBSERVED`, `UNKNOWN`.
- `encoding_state`: `ENCODED`, `PARTIAL`, `NONE_OBSERVED`, `UNKNOWN`.
- `framework_context`: `NONE_OBSERVED`, `GENERIC`, `REACT`, `VUE`,
  `ANGULAR`, `JQUERY`, `UNKNOWN`.
- Malformed or missing observations degrade to `UNKNOWN`; nothing is
  promoted.
- `context_confidence` is a pure function of known facts: 5 known → HIGH,
  3–4 → MEDIUM, 1–2 → LOW, 0 → UNKNOWN. `context_confidence_of()` recomputes
  it from observations so partial context dicts are handled consistently.
- No payload generation and no execution exist anywhere in the model.

## 4. Hypothesis model

`XSSHypothesisPlan`: `rule_version`, `hypothesis_type`,
`supporting_signals[]`, `confidence`, `priority`, `limitations`,
`research_only`.

- Types: `REFLECTION_ANALYSIS`, `DOM_FLOW_ANALYSIS`,
  `STORAGE_FLOW_ANALYSIS`, `CONTEXT_REVIEW`, `UNKNOWN`.
- Closed signal vocabulary (bounded, deduplicated, never inferred beyond
  observed facts).
- Deterministic mapping:
  - reflected observation → `REFLECTION_ANALYSIS`; confidence HIGH when
    encoding is `NONE_OBSERVED`, MEDIUM when `PARTIAL`, otherwise LOW;
  - no reflection observed from `BODY`/`COOKIE` → low-confidence
    `STORAGE_FLOW_ANALYSIS`;
  - DOM output context adds a `DOM_FLOW_ANALYSIS` hypothesis (MEDIUM only
    when the context is HIGH confidence);
  - unknown everything → `UNKNOWN` with `INSUFFICIENT_CONTEXT`.
- `priority` is a deterministic mirror of confidence.
- Every hypothesis carries `NO_EXPLOIT_CLAIM`,
  `NO_VULNERABILITY_CONFIRMATION`, `HYPOTHESIS_ONLY`, `EVIDENCE_REQUIRED`.
  No exploit claim and no vulnerability confirmation is possible.

## 5. Evidence model

`XSSEvidencePlan`: `rule_version`, `evidence_items[]`, `evidence_state`,
`confidence`, `limitations`, `research_only`.

- Items: `REFLECTION_CONTEXT`, `OUTPUT_ENCODING_CONTEXT`, `SINK_CONTEXT`,
  `SOURCE_CONTEXT`, `APPLICATION_BEHAVIOR`, `UNKNOWN`.
- Fixed per-hypothesis mappings produce an ordered, deduplicated required
  item list. When hypotheses are omitted, the planner derives them itself.
- State: `COMPLETE` only when the context is HIGH confidence and every
  hypothesis is at least MEDIUM and not `UNKNOWN`; `PARTIAL` otherwise;
  `UNKNOWN` when nothing can be planned.
- Every plan records `NO_COLLECTION_PERFORMED` and `EVIDENCE_REQUIRED`:
  this is evidence planning only, nothing is collected.

## 6. Result export

`XSSAgentResultPlan`: `rule_version`, `agent_name`, `status`,
`context_analysis`, `hypotheses`, `evidence_plan`, `confidence`,
`limitations`, `governance_reference`, `research_only`.

- Status/confidence reuse R38 vocabularies; schema limits hypotheses to the
  two the pipeline can emit.
- Conservative status derivation: `COMPLETED` only with a complete evidence
  plan; `ANALYZING` for partial evidence or partially known context;
  `CREATED` when nothing is known. `FAILED` is reserved and never invented.
- Limitations always include `NO_EXECUTION_PERFORMED`,
  `NO_PAYLOAD_GENERATION`, `NO_VULNERABILITY_CONFIRMATION`,
  `HYPOTHESIS_ONLY`; `INSUFFICIENT_CONTEXT` and `GOVERNANCE_UNKNOWN` are
  added when appropriate.
- Explicit agent identity or an R38 input identity controls `agent_name`;
  both paths are bounded and read-only.

## 7. Governance integration

- `governance_reference` is a fixed bounded record:
  `rule_version`, `ready`, `provenance_state`, `trace_state`,
  `audit_state`, `explanation_state`, `reference_state`.
- `build_governance_reference()` accepts only a real R37 governance export
  (rule version `r37-5` plus the four component dicts). Missing, malformed,
  foreign-version or component-less plans degrade to `UNKNOWN` with
  `ready=False` and force the `GOVERNANCE_UNKNOWN` limitation — incomplete
  governance is never treated as valid.
- Component states are validated against the closed R37 vocabularies
  (`COMPLETE`/`PARTIAL`/`UNKNOWN`, `VALID`/`INVALID`/`UNKNOWN`).

## 8. Backend integration

Additive change only in `backend/asset_cve_matching.py` (14 lines: one
import, two summary fields, comment):

```python
summary["xss_agent_plan"] = export_xss_agent_result()
summary["xss_agent_plan_rule_version"] = (
    XSS_AGENT_RESULT_EXPORTER_RULE_VERSION
)
```

No existing field was renamed, removed or reordered; no R31–R38 logic was
touched. Live check through `build_matches` returns `status="CREATED"`,
`rule_version="r39-5"`, `research_only=True` and an `UNKNOWN` governance
reference. `tests/test_asset_cve_matching.py` passes (79 tests, 13
subtests).

## 9. Tests

Focused offline tests were added for every R39 component:

| Suite | Tests |
|---|---|
| `tests/test_xss_agent_identity.py` (R39.1) | 17 |
| `tests/test_xss_context_analyzer.py` (R39.2) | 20 |
| `tests/test_xss_hypothesis_planner.py` (R39.3) | 19 |
| `tests/test_xss_evidence_planner.py` (R39.4) | 21 |
| `tests/test_xss_agent_result.py` (R39.5) | 23 |
| **R39 total** | **100 passed** |

Coverage includes: category/maturity/context validation; reflection and
encoding states; output contexts; malformed input; deterministic output;
confidence and priority mapping; no exploit claims; evidence vocabulary and
incomplete/unknown states; R38 result compatibility (model construction);
R37 governance reference (referenced/unknown/ready states); serialization;
input immutability; status derivation; no payload/execution fields; and an
AST source scan proving none of the 10 R39 modules imports or calls
execution-capable facilities (`subprocess`, `socket`, network, browsers,
`importlib`, `eval`, `exec`, `open`, …).

## 10. Regression

```
R39 suites (5 files)                                        100 passed
R38 suites (7 files)                                        132 passed
All tests referencing r31- … r38- (55 files)   1507 passed, 27 subtests
tests/test_asset_cve_matching.py                  79 passed, 13 subtests
Full suite: python -m pytest tests/ -q
    3383 passed, 40 failed, 376 subtests passed
```

Baseline comparison: before R39 (R38 baseline) the full suite was
**3283 passed / 40 failed**; after R39 it is **3383 passed / 40 failed**
(+100 = exactly the new R39 tests). The sorted `FAILED` line sets are
byte-identical (`diff` clean), and re-running the full suite with the R39
backend diff temporarily stashed produces the same 3383/40 with an
identical failure set. No failure is attributable to R39; the 40 failures
are the pre-existing money-score/economics corpus-drift failures and none
was fixed.

## 11. Safety verification

- R39 modules import only `__future__`, `re`, `hashlib`, `pydantic` and
  `ai.schemas`/`ai.knowledge`. No subprocess, shell, network, HTTP client,
  browser/JS engine, Nuclei, LLM, embedding, Mongo or filesystem imports.
- The AST test in `tests/test_xss_agent_result.py` rejects forbidden
  imports and calls across all 10 R39 modules.
- Not implemented (by design): HTTP requests, payload execution, browser
  automation, JavaScript execution, DOM crawling, fuzzing, exploit
  confirmation, exploitation, authentication bypass, subprocess, shell,
  external APIs, LLM calls, persistence, databases, workers, schedulers,
  attack automation.
- Every object carries `research_only=True`; every result records
  `NO_EXECUTION_PERFORMED` and `NO_PAYLOAD_GENERATION`; every hypothesis
  records `NO_EXPLOIT_CLAIM` and `NO_VULNERABILITY_CONFIRMATION`.
- No VM, deployment, systemd, Docker or docker-compose file was created or
  modified. Nothing was pushed.

## 12. Git summary

New files committed (local only):

```
ai/schemas/xss_agent_identity.py
ai/schemas/xss_context_analysis.py
ai/schemas/xss_hypothesis.py
ai/schemas/xss_evidence_plan.py
ai/schemas/xss_agent_result.py
ai/knowledge/xss_agent_identity.py
ai/knowledge/xss_context_analyzer.py
ai/knowledge/xss_hypothesis_planner.py
ai/knowledge/xss_evidence_planner.py
ai/knowledge/xss_agent_result_export.py
tests/test_xss_agent_identity.py
tests/test_xss_context_analyzer.py
tests/test_xss_hypothesis_planner.py
tests/test_xss_evidence_planner.py
tests/test_xss_agent_result.py
agent-reports/stage-r39-xss-specialist-agent.md
```

Modified (additive, 14 lines):

```
backend/asset_cve_matching.py
```

Explicitly excluded from the commit: `utils.zip` deletion, `watch.zip`,
`agent-reports/R31-final-github-audit.md` and
`agent-reports/stage-r31-5-planning-audit.md`. No R31–R38 file was
modified.

## Agent / Model

- Model: deepseek-v4.1-flash
- Stage: R39
- Role: coding agent
