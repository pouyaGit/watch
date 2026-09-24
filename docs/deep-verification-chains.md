# Deep Verification Chains (EPIC12)

**Rule version:** `epic12-verification-1` · **Status:** implemented, XSS is the
reference chain · **Authority:** the EPIC11 claim contract and gate (unchanged)

## 1. Why this exists

Before EPIC12 the runtime could observe a parameter, a header or a redirect and
have no way to say what it had *not* established. The failure mode is specific
and it is a security failure, not a reporting one:

```
parameter exists            -> "XSS"
parameter reflects          -> "XSS"
suspicious URL parameter    -> "SSRF"
CORS header present         -> "exploitable CORS"
redirect parameter present  -> "open redirect"
```

EPIC12 makes the missing work explicit. A finding may only be called confirmed
when the class-specific verification chain has produced the evidence the EPIC11
contract requires — and when it has not, the system says exactly what is
missing:

> Not confirmed — missing reflection evidence.

## 2. Principles (enforced, not aspirational)

1. **Observation is not a vulnerability.** A stage is not a verdict.
2. **LLM output is never authoritative evidence.** The advisory role may only
   name an action the chain already allows; it cannot add evidence, widen scope,
   or confirm anything.
3. **The deterministic gate decides.** The verdict always comes from
   `finding.integrity.gate`; this layer never computes one.
4. **Fail closed.** Missing authorization, missing capability, exhausted budget,
   malformed input → `BLOCKED` / `VERIFICATION_PENDING` / `NOT_CONFIRMED`, with
   the reason recorded.
5. **A failed verification never becomes a positive finding.**
6. **Full lineage.** candidate → hypothesis → verification objective →
   authorization → action → observation → evidence classification → verdict is
   preserved on every record.

## 3. Architecture

```
candidate (EPIC11)
   -> verification chain          backend/research_agents/verification/chains.py
   -> missing evidence            engine.py (stage states, per-stage gaps)
   -> typed verification action   actions.py + planner.py
   -> authorized execution        executors.py (injected transport only)
   -> structured observation      observations.py
   -> EPIC11 evidence classification   finding.integrity.taxonomy  (reused)
   -> claim evaluation            finding.integrity.claims        (reused)
   -> terminal verdict            finding.integrity.gate          (reused)
```

The loop that drives this (`loop.py`) is bounded: at most `max_steps` actions,
one action per step, a budget per resource, and a mandatory progress rule (a
step that produces no new observation terminates the loop).

## 4. The XSS chain (reference implementation)

| # | Stage | Required EPIC11 evidence | Allowed actions | Capability |
|---|-------|--------------------------|-----------------|------------|
| 1 | Parameter / input discovery | `PARAMETER_OBSERVED` | `PARAMETER_INVENTORY`, `SEND_MARKER` | full |
| 2 | Reflection | `REFLECTION_OBSERVED` | `CHECK_REFLECTION`, `SEND_MARKER` | full (recorded material) |
| 3 | Context classification | `OUTPUT_CONTEXT_IDENTIFIED` | `CLASSIFY_REFLECTION_CONTEXT` | full (recorded material) |
| 4 | Sink / execution path | `DOM_SINK_IDENTIFIED` | `TRACE_DOM_SOURCE`, `TRACE_DOM_SINK` | conditional (DOM variant) |
| 5 | Execution | `PAYLOAD_EXECUTION` | `DELIVER_CONTROLLED_PAYLOAD`, `OBSERVE_EXECUTION` | **not available in this runtime** |
| 6 | Exploitability | `EXPLOITABILITY_ESTABLISHED` | `OBSERVE_EXECUTION` | **not available in this runtime** |

Consequences, all of them deliberate:

* `PARAMETER_OBSERVED` only → `VERIFICATION_PENDING`.
* `PARAMETER_OBSERVED` + `REFLECTION_OBSERVED` → still pending (context missing).
* `REFLECTION_OBSERVED` + `OUTPUT_CONTEXT_IDENTIFIED` → still pending
  (execution missing).
* `PAYLOAD_EXECUTION` + applicable confirmation evidence → eligible for
  `VERIFIED` **according to the EPIC11 contract**, which is derived at runtime
  (`chain.confirmation_requires` reads the contract, so the two can never drift).

**Stage 4 is conditional, not skippable.** The sink stage carries
`required_for_confirmation = False` and only becomes `NOT_APPLICABLE` under a
recorded, deterministic rule (`not_applicable_reflected_only`): the context stage
is satisfied by a classified server-side output context, no DOM source/sink
evidence exists, and no DOM negative exists. It is reported as `n/a` with that
reason and never counts as satisfied.

## 5. Reference chains (contract only)

`CORS`, `OPEN_REDIRECT` and `SSRF` have declared stages, required evidence,
allowed actions and limitations, with `capability = CONTRACT_ONLY`: no executor
is wired, so a request against them returns `BLOCKED`
(`capability_contract_only`) with the missing evidence recorded. Their
limitations state the principle in the chain itself — *a CORS header is not
automatically exploitable CORS*, *a URL-shaped parameter is not SSRF*.

Classes with no chain (`IDOR`, `SQLI`, `XXE`, …) report
`capability = NOT_IMPLEMENTED`, an empty stage list and the EPIC11 contract
verdict. No stage list is ever invented.

## 6. Typed verification actions

Every active step is an auditable record:

`action_id · action_type · candidate_id · objective_id · scope_ref · target ·
authorization_id · inputs · safety class · state · result · observation_ids ·
evidence_refs · attempt · timestamps · provenance`

Safety classes: `READ_ONLY` (derives evidence from already-recorded material),
`SAFE_PROBE` (idempotent marker delivery through an injected authorized
transport), `ACTIVE_PAYLOAD` (payload delivery — requires an authorization
reference and is refused without one), `UNAVAILABLE` (no lane in this runtime).

Two independent scope checks: construction refuses a target outside the recorded
scope, and `execute_action` re-checks before handing anything to an executor (a
tampered action is refused with `target_out_of_scope`).

## 7. What can actually execute today

| Executor | Actions | Behaviour |
|----------|---------|-----------|
| `read_only_evidence` | `PARAMETER_INVENTORY`, `CHECK_REFLECTION`, `CLASSIFY_REFLECTION_CONTEXT`, `TRACE_DOM_SOURCE/SINK` | derives evidence from persisted rows, a recorded response body or a recorded document. No socket, no subprocess. |
| `authorized_probe` | `SEND_MARKER` | requires **both** an authorization reference and an injected transport (from the platform's existing authorized execution layer). Otherwise `BLOCKED` (`transport_unavailable` / `authorization_unavailable`). A transport failure is `BLOCKED` (`transport_failed`) — never evidence. |
| `unavailable` | payload delivery, execution observation, all reference-chain actions | always `BLOCKED` with the declared limitation. **No synthetic execution evidence is ever produced.** |

This is the honest answer to "what is genuinely available": the runtime can
derive and check evidence from material it already has, and it can *use* an
authorized live probe the moment the platform provides one — but it cannot
browse, execute JavaScript, or manufacture a payload observation, so the chain
stops at the execution lane and says so.

## 8. Loop termination states

`CONFIRMED` (EPIC11 `VERIFIED`) · `NOT_CONFIRMED` (contradicted) · `BLOCKED`
(authorization / capability) · `VERIFICATION_PENDING` (evidence still missing) ·
`BUDGET_EXHAUSTED` · `ERROR`.

Budget resources: `max_actions`, `max_requests`, `max_payload_attempts` (0 by
default), `max_runtime_seconds`, `max_observations`, `max_retries`. Resources the
EPIC11 finding budget owns (`max_llm_calls`, …) are delegated to it rather than
duplicated in a second ledger. A resource whose limit is `0` is "not available
in this runtime", which is a capability fact, not budget exhaustion.

## 9. The advisory role

`advisor.py` builds a bounded, structural request (≤ 4000 chars, no URLs, no
payloads, no credentials) and validates the response: the suggested action must
be one the current stage already allows, the scope must not change, and any
confirmation/execution claim (`confirmed`, `exploitability`, `alert(`,
`payload_execution`, `cvss`, …) is rejected outright
(`advisor_may_not_confirm`). A rejected or failed advisory leaves the hint empty
and the deterministic planner proceeds. Provider: `openrouter/free` only.

## 10. SOC projection

`projection.py` renders the chain for an analyst: per-stage status glyph
(`✓` satisfied, `·` missing, `?` not tested, `✗` contradicted, `n/a`), the
evidence used with its structured answers, the evidence missing, the negative
results, the actions that ran (with executor and state), the requests, the
authorization state, and *why it is not confirmed*.

The badge rule is the hard part: **a `VERIFIED` badge requires both the EPIC11
verdict and a complete chain.** If the verdict says `VERIFIED` while a required
stage is unsatisfied, the badge is `INCONSISTENT` — never green. Every badge
carries `optimistic: false`.

## 11. Integration

The loop is invoked from inside the promoted finding pass, never from its own
scheduler:

```python
run_findings(..., chain_loop_fn=make_chain_loop_fn(...))
```

The hook runs for an objective the existing authorization boundary already
admitted, using the existing finding budget when supplied, and it can only *add*
structured observations plus the chain state recorded in
`verification.provenance["verification_chain"]`. With `chain_loop_fn=None`
(default) the promoted behaviour is byte-for-byte unchanged (all 90 EPIC11 tests
stay green). The authoritative verdict is recorded next to the chain state, not
merged into it, so a divergence stays visible.

## 12. EPIC11 reuse map

| Reused | How |
|--------|-----|
| Evidence vocabulary, stages, `CONFIRMATION_EVIDENCE` | imported from `finding.integrity.taxonomy`; no second vocabulary exists in this package (asserted by tests) |
| Claim contract, `required_groups`, `min_unique_observations` | `chains.py` derives its confirmation requirement from `contract_for(cls)` at runtime |
| Claim evaluation + verdict | `claims.evaluate_rows` + `gate.decide` — the only source of `ChainState.verdict` |
| Authorization model, scope refs, budgets, stores, job lifecycle | `finding.models.validate_scope_ref`, `FindingBudget` delegation, `FindingStore` base dir + JSONL/flock convention |
| Advisory boundary | `finding.advisor.validate_recommendation` (closed set + scope-expansion check) |

No second Evidence Gate, no second scheduler, no second campaign system, no
duplicated authorization logic, and no modification of any pinned `ai/*` module.

## 13. Known limitation found while building this (reported, not patched)

EPIC11's `classify_row` resolves an evidence class from the row's **signal**,
not from its `type`. A row typed `llm_insight` (or `prior_recommendation`) that
carries an evidence-shaped signal such as `payload_execution` therefore *can*
reach the gate and contribute to a confirmation.

EPIC12 does not silently change EPIC11. Instead:

* the chain view refuses advisory-typed rows
  (`engine.INADMISSIBLE_ROW_TYPES`), so an LLM-derived row can never satisfy a
  chain stage;
* any resulting disagreement between the authoritative verdict and the chain is
  recorded as `ChainState.divergence` and surfaced as an `INCONSISTENT` badge.

Reproduction and the recommended one-line hardening (filter advisory row types
in `classify_row`) are in the EPIC12 report. Today's writers persist advisory
output into `verification.provenance`, not into the evidence store, so the path
is latent rather than active — but it is a real gap against principle 2 and it
is reported rather than hidden.

## 14. Tests

365 tests across 12 modules (`tests/test_epic12_*.py`), all offline and
deterministic: chain model, engine verdicts, actions, executors, planner, loop,
advisor, projection, safety guards, the mandatory
`cand-7c229c48c455` regression, 14 adversarial scenarios, and the
`run_findings` integration.

Rule versions: `epic12-verification-1`, `epic12-verification-chain-1`,
`epic12-verification-action-1`, `epic12-verification-observation-1`,
`epic12-verification-executor-1`, `epic12-verification-planner-1`,
`epic12-verification-loop-1`, `epic12-verification-projection-1`,
`epic12-chain-advisor-1`, `epic12-verification-integration-1`.
