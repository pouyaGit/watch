"""EPIC15 — deep execution verification (the capability boundary).

This package answers one question honestly:

    *Did attacker-controlled input actually reach a security-relevant
    execution sink under an authorized, isolated verification environment?*

and it answers it with deterministic evidence or not at all.

Capability decision (EPIC15 §2/§3, code-verified against the frozen
platform boundary at ``main = 76a9c0a5``): **PATH C**.

A safe live browser/DOM execution capability cannot exist in this
runtime, and that is stated rather than worked around:

* the platform's browser lane is closed by a literal, non-configurable
  switch (``ai.execution.browser_executor.LIVE_BROWSER is False``) and by
  four unimplemented boundary requirements (B1/B2/B4/B5 — B5 is the
  browser network/containment boundary, explicitly pending);
* a real browser is an autonomous network agent (own DNS, redirect
  chain, subresources, script-initiated traffic, frames, workers,
  prefetch), so ``SCOPE-EVALUATED == ACTUALLY-DIALED`` cannot be
  established without that containment boundary;
* a real Linux network namespace cannot be created here (no root /
  ``CAP_SYS_ADMIN``), so the sandbox machinery fails closed
  (``SANDBOX_UNAVAILABLE``);
* the legacy playwright executor (``ai.verification.browser_executor``)
  is non-production, has no authorization/scope gates, and its only
  production entrypoint was permanently disabled; the ``playwright``
  package is not even installed in this interpreter.

What this package *does* implement is the maximum real capability that
is safe here:

* a deterministic, lineage-bound **served-document DOM source→sink
  verifier** (no browser, no network, no execution) that reuses EPIC12's
  read-only DOM action contract and records the exact instrumentation
  method and version;
* the **execution capability contract** with deterministic unavailable
  handling — every attempt fails closed with an explicit state, and a
  browser/transport failure is never recorded as ``EXECUTION_NOT_OBSERVED``;
* the **isolation, network and redirect policy** the future lane would
  have to satisfy, enforced at every decision point;
* **authorization checks at every stage** and budget reuse of the frozen
  platform ceilings;
* the separation of ``PAYLOAD_EXECUTION`` from
  ``EXPLOITABILITY_ESTABLISHED``.

Nothing here creates a browser, a socket, a process, a payload
generator, an evidence taxonomy, a gate, a lifecycle or a provenance
system.  All observations are produced through the trusted EPIC12/EPIC13
observation producer and classified by the EPIC11 taxonomy under the
EPIC14 trust boundary.

**Browser execution evidence is authoritative only when produced by the
trusted, authorized verification producer.**
"""
from __future__ import annotations

from .capability import (  # noqa: F401
    BROWSER_EXECUTION_BLOCKED, DEEP_RULE_VERSION, LANE_ABSENT, LANE_CLOSED,
    LANE_OFFLINE_ONLY, browser_lane, capability_document,
    dom_verification_lane, execution_lane, lane_states)
from .dom import (  # noqa: F401
    DOM_INSTRUMENTATION_METHOD, DOM_INSTRUMENTATION_VERSION, DomTrace,
    trace_dom_flow)
from .execution import (  # noqa: F401
    ATTEMPT_STATES, AUTHORIZATION_EXPIRED, AUTHORIZATION_MISSING,
    BROWSER_START_FAILED, BROWSER_UNAVAILABLE, BUDGET_EXHAUSTED,
    DOM_SINK_NOT_OBSERVED, DOM_SINK_OBSERVED, EXECUTION_NOT_OBSERVED,
    EXECUTION_OBSERVED, EXECUTION_RULE_VERSION, INCONCLUSIVE,
    INSTRUMENTATION_UNAVAILABLE, NAVIGATION_BLOCKED, REDIRECT_OUT_OF_SCOPE,
    TIMEOUT, AttemptResult, attempt_execution, is_negative_security_evidence,
    is_refusal)
from .exploitability import (  # noqa: F401
    ExploitabilityAssessment, assess_exploitability)
from .isolation import (  # noqa: F401
    ISOLATION_VERSION, NAVIGATION_DECISIONS, NavigationDecision,
    IsolationPolicy, check_navigation, check_redirect,
    check_request_headers, isolation_policy)
from .budget import (  # noqa: F401
    BUDGET_VERSION, DeepBudget, budget_from_ceilings)
from .producer import (  # noqa: F401
    DEEP_PRODUCER_VERSION, DeepObservationProducer)
from .service import (  # noqa: F401
    DEEP_BLOCKED, DEEP_CAPABILITY_UNAVAILABLE, DEEP_INCONCLUSIVE,
    DEEP_NOT_OBSERVED, DEEP_NOT_TESTED, DEEP_OBSERVED, DEEP_STAGES,
    DEEP_STATES, DEEP_VERIFICATION_VERSION, DeepVerificationResult,
    deep_stage_for, deep_verify, project_deep)

__all__ = [
    "ATTEMPT_STATES", "AUTHORIZATION_EXPIRED", "AUTHORIZATION_MISSING",
    "BROWSER_START_FAILED", "BROWSER_UNAVAILABLE", "BUDGET_EXHAUSTED",
    "DOM_SINK_NOT_OBSERVED", "DOM_SINK_OBSERVED", "EXECUTION_NOT_OBSERVED",
    "EXECUTION_OBSERVED", "EXECUTION_RULE_VERSION", "INCONCLUSIVE",
    "INSTRUMENTATION_UNAVAILABLE", "NAVIGATION_BLOCKED",
    "REDIRECT_OUT_OF_SCOPE", "TIMEOUT",
    "ATTEMPT_STATES", "AttemptResult", "BROWSER_EXECUTION_BLOCKED",
    "DEEP_BLOCKED", "DEEP_CAPABILITY_UNAVAILABLE", "DEEP_INCONCLUSIVE",
    "DEEP_NOT_OBSERVED", "DEEP_NOT_TESTED", "DEEP_OBSERVED", "DEEP_STAGES",
    "DEEP_STATES", "deep_stage_for", "project_deep",
    "BUDGET_VERSION", "DEEP_PRODUCER_VERSION", "DEEP_RULE_VERSION",
    "DEEP_VERIFICATION_VERSION", "DOM_INSTRUMENTATION_METHOD",
    "DOM_INSTRUMENTATION_VERSION", "DeepBudget", "DeepObservationProducer",
    "DeepVerificationResult", "DomTrace", "ExploitabilityAssessment",
    "ISOLATION_VERSION", "IsolationPolicy", "LANE_ABSENT", "LANE_CLOSED",
    "LANE_OFFLINE_ONLY", "NAVIGATION_DECISIONS", "NavigationDecision",
    "assess_exploitability", "attempt_execution", "browser_lane",
    "budget_from_ceilings", "capability_document", "check_navigation",
    "check_redirect", "check_request_headers", "deep_verify",
    "dom_verification_lane",
    "execution_lane", "is_negative_security_evidence", "is_refusal",
    "isolation_policy", "lane_states", "trace_dom_flow",
]
