# Deep Execution Verification (EPIC15)

**Status:** v1 — capability boundary established, fail-closed.

## The question this layer answers

    Did attacker-controlled input actually reach a security-relevant
    execution sink under an authorized, isolated verification environment?

It answers with deterministic evidence, or it says it cannot — it never
fabricates execution.

## Capability audit (code-verified at `main = 76a9c0a5`)

| What | Where | State |
| --- | --- | --- |
| Platform browser/XSS executor (closed spec) | `ai/execution/browser_executor.py` | exists, **closed** |
| Live browser switch | `LIVE_BROWSER` | `False`, literal, non-configurable |
| Boundary requirements | `B1_STATUS`/`B2_STATUS`/`B4_STATUS`/`B5_STATUS` | all `BLOCKED` |
| Browser network/containment boundary | B5 | **pending separate review** |
| Legacy playwright executor | `ai/verification/browser_executor.py` | non-production, no authorization/scope gates, sole caller permanently disabled |
| `playwright` package | interpreter | **not installed** |
| Network-namespace sandbox | `ai/execution/netns_sandbox.py`, `b3_boundary.py` | exists, fails closed (`SANDBOX_UNAVAILABLE`) |
| Frozen ceilings | `ai.limits.ceilings.CEILINGS` | reusable (browser dims included) |
| Read-only DOM trace action | `verification/executors.py` (`TRACE_DOM_SOURCE`/`TRACE_DOM_SINK`) | implemented, **presence-only** before EPIC15 |

**Selected path: PATH C** — a safe live browser/DOM execution capability
cannot exist in this environment. The platform's own rationale is
authoritative: *a real browser is an autonomous network agent (own DNS,
redirect chain, subresources, script-initiated traffic, frames, workers,
prefetch), so `SCOPE-EVALUATED == ACTUALLY-DIALED` cannot be established
without the B5 containment boundary; in-browser hooks are telemetry,
never enforcement.*

## What EPIC15 implements

1. **A lineage-bound served-document DOM source→sink verifier**
   (`verification/deep/dom.py`). It replaces presence-only pattern
   matching with a bounded data-flow check: the observed parameter must be
   read from a DOM source into a variable **and** that variable must reach
   a dangerous sink within a bounded window. A document with
   `location.search` and `.innerHTML` in unrelated places is **not** a DOM
   sink finding.
2. **The execution capability contract** (`deep/capability.py`,
   `deep/execution.py`): every attempt produces one explicit state, and a
   browser/transport failure is never recorded as `EXECUTION_NOT_OBSERVED`.
3. **Isolation, network and redirect policy** (`deep/isolation.py`),
   enforced at every decision point: no localhost, RFC1918, link-local,
   cloud metadata, `file://`, arbitrary protocol or port, no out-of-scope
   redirect, no credential headers.
4. **Authorization at every stage** and **budget reuse** of the frozen
   platform ceilings (`deep/budget.py` — no new ceiling is defined).
5. **The trusted producer** (`deep/producer.py`): a caller cannot submit
   an `evidence_type`; the type is derived from the attempt state and
   attested.
6. **Exploitability kept separate** (`deep/exploitability.py`):
   `PAYLOAD_EXECUTION` never implies `EXPLOITABILITY_ESTABLISHED`.

## Instrumentation honesty

`DOM_INSTRUMENTATION_METHOD = "served_document_static_analysis"`,
`DOM_INSTRUMENTATION_VERSION = "epic15-dom-trace-1"`, persisted on every
observation. This is **bounded variable-name tracking over the served
document and its inline scripts** — not a JavaScript engine, not complete
taint analysis. It establishes a source→sink flow *in the served
material*; it never establishes that the sink executed.

## Execution evidence

Only a deterministic, producer-attested observation may produce
`PAYLOAD_EXECUTION`. Never execution evidence: HTML reflection, script
text in a response, a screenshot, an LLM claim, static source patterns, a
page title, or HTTP 200.

## Failure states (§18)

`EXECUTION_OBSERVED`, `EXECUTION_NOT_OBSERVED`, `DOM_SINK_OBSERVED`,
`DOM_SINK_NOT_OBSERVED`, `BROWSER_UNAVAILABLE`, `BROWSER_START_FAILED`,
`NAVIGATION_BLOCKED`, `REDIRECT_OUT_OF_SCOPE`, `AUTHORIZATION_MISSING`,
`AUTHORIZATION_EXPIRED`, `TIMEOUT`, `BUDGET_EXHAUSTED`,
`INSTRUMENTATION_UNAVAILABLE`, `INCONCLUSIVE`.

Only `EXECUTION_NOT_OBSERVED` and `DOM_SINK_NOT_OBSERVED` may become
negative security evidence, and only when the instrumented run genuinely
reached the relevant point. Every other state is a **refusal**.

## Production activation policy

Live browser execution stays **off**. Nothing in this layer flips
`LIVE_BROWSER`, and the production path refuses before any primitive with
`BROWSER_UNAVAILABLE` / `BROWSER_EXECUTION_BLOCKED`. Offline/injected
validation is labelled as such in every result and is never presented as
real production acquisition. Enabling a live lane requires the B5
containment boundary (separate review) — not a code change here.

**Browser execution evidence is authoritative only when produced by the
trusted, authorized verification producer.**

## Known limitations

* No live execution: the execution lane is `NOT_IMPLEMENTED` here, so
  `PAYLOAD_EXECUTION` and `EXPLOITABILITY_ESTABLISHED` remain unreachable
  in production (fail-closed by construction).
* DOM analysis is static and bounded (8 KiB, `browser_dom_observation_bytes`):
  a flow assembled at runtime (string concatenation, framework templates,
  dynamic imports) is not detected — recorded as not-observed, never as
  absent risk.
* A consistent-shape forgery (a row whose structure matches a trusted
  producer) is not caught by the declared-vs-authoritative mismatch rule;
  it is bounded by the required-evidence rule and by the persistence
  attestation in `record_evidence`.
* CORS/OPEN_REDIRECT inherit `GENERIC` (confirmation requires
  `DOM_SINK_IDENTIFIED` which neither chain produces → unreachable);
  CVE_RESEARCH has no confirmation claim.
