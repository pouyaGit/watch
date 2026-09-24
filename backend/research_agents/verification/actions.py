"""EPIC12 — typed, auditable verification actions (§6).

Every active verification step is an explicit, typed action record carrying the
identity, authorization, scope, safety class, inputs, result and the
observations/evidence it produced.  There is no free-form primitive: an action
type that is not declared here cannot be constructed, and an action whose target
is not inside the recorded authorized scope is refused at construction time
(fail closed, never at execution time).

Safety classes
--------------

``READ_ONLY``
    Derives evidence from observations that already exist.  No traffic.
``SAFE_PROBE``
    Idempotent, non-destructive request inside the authorized scope (e.g. a GET
    carrying a marker).  Requires an authorization reference.
``ACTIVE_PAYLOAD``
    Delivers a controlled payload / observes execution.  Requires an
    authorization reference and a wired executor.
``UNAVAILABLE``
    No executor exists in this runtime: the action is declared for the chain
    contract but terminates ``BLOCKED`` — never faked.

Nothing in this module executes anything.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from backend.research_agents.finding.integrity import taxonomy as tx
from backend.research_agents.finding.models import (
    FindingScopeError,
    utcnow,
    validate_scope_ref,
)

ACTION_RULE_VERSION = "epic12-verification-action-1"

# --------------------------------------------------------- safety classes

SAFETY_READ_ONLY = "READ_ONLY"
SAFETY_PROBE = "SAFE_PROBE"
SAFETY_ACTIVE = "ACTIVE_PAYLOAD"
SAFETY_UNAVAILABLE = "UNAVAILABLE"

SAFETY_CLASSES: tuple[str, ...] = (
    SAFETY_READ_ONLY, SAFETY_PROBE, SAFETY_ACTIVE, SAFETY_UNAVAILABLE)

# ------------------------------------------------------------ action states

ACTION_CREATED = "CREATED"
ACTION_AUTHORIZED = "AUTHORIZED"
ACTION_EXECUTING = "EXECUTING"
ACTION_SUCCEEDED = "SUCCEEDED"
ACTION_FAILED = "FAILED"
ACTION_BLOCKED = "BLOCKED"
ACTION_SKIPPED = "SKIPPED"

ACTION_STATES: tuple[str, ...] = (
    ACTION_CREATED, ACTION_AUTHORIZED, ACTION_EXECUTING, ACTION_SUCCEEDED,
    ACTION_FAILED, ACTION_BLOCKED, ACTION_SKIPPED)

ACTION_TERMINAL: frozenset[str] = frozenset(
    {ACTION_SUCCEEDED, ACTION_FAILED, ACTION_BLOCKED, ACTION_SKIPPED})

ACTION_TRANSITIONS: dict[str, frozenset[str]] = {
    ACTION_CREATED: frozenset({ACTION_AUTHORIZED, ACTION_EXECUTING,
                               ACTION_BLOCKED, ACTION_SKIPPED}),
    ACTION_AUTHORIZED: frozenset({ACTION_EXECUTING, ACTION_BLOCKED,
                                  ACTION_SKIPPED}),
    ACTION_EXECUTING: frozenset({ACTION_SUCCEEDED, ACTION_FAILED,
                                 ACTION_BLOCKED}),
    ACTION_SUCCEEDED: frozenset(),
    ACTION_FAILED: frozenset(),
    ACTION_BLOCKED: frozenset(),
    ACTION_SKIPPED: frozenset(),
}

# ----------------------------------------------------------- action types

#: XSS chain actions (§6).
PARAMETER_INVENTORY = "PARAMETER_INVENTORY"
SEND_MARKER = "SEND_MARKER"
CHECK_REFLECTION = "CHECK_REFLECTION"
CLASSIFY_REFLECTION_CONTEXT = "CLASSIFY_REFLECTION_CONTEXT"
TRACE_DOM_SOURCE = "TRACE_DOM_SOURCE"
TRACE_DOM_SINK = "TRACE_DOM_SINK"
DELIVER_CONTROLLED_PAYLOAD = "DELIVER_CONTROLLED_PAYLOAD"
OBSERVE_EXECUTION = "OBSERVE_EXECUTION"

#: reference-chain actions (CORS / open redirect / SSRF — contract only).
SEND_ORIGIN_HEADER = "SEND_ORIGIN_HEADER"
CHECK_CORS_HEADERS = "CHECK_CORS_HEADERS"
CLASSIFY_CORS_ORIGIN_ECHO = "CLASSIFY_CORS_ORIGIN_ECHO"
CHECK_CREDENTIALS_MODE = "CHECK_CREDENTIALS_MODE"
ASSESS_RESPONSE_SENSITIVITY = "ASSESS_RESPONSE_SENSITIVITY"
SEND_REDIRECT_MARKER = "SEND_REDIRECT_MARKER"
CHECK_REDIRECT_LOCATION = "CHECK_REDIRECT_LOCATION"
CLASSIFY_REDIRECT_TARGET = "CLASSIFY_REDIRECT_TARGET"
SEND_CALLBACK_URL = "SEND_CALLBACK_URL"
CHECK_CALLBACK_INTERACTION = "CHECK_CALLBACK_INTERACTION"
OBSERVE_SERVER_RESPONSE = "OBSERVE_SERVER_RESPONSE"
ASSESS_SSRF_IMPACT = "ASSESS_SSRF_IMPACT"


@dataclass(frozen=True)
class ActionSpec:
    """The contract of one action type."""

    action_type: str
    label: str
    safety: str
    produces: tuple[str, ...] = ()
    requires_authorization: bool = True
    requires_network: bool = False
    implemented: bool = False
    limitation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "label": self.label,
            "safety": self.safety,
            "produces": list(self.produces),
            "requires_authorization": self.requires_authorization,
            "requires_network": self.requires_network,
            "implemented": self.implemented,
            "limitation": self.limitation,
            "rule_version": ACTION_RULE_VERSION,
        }


_SPECS: tuple[ActionSpec, ...] = (
    ActionSpec(
        PARAMETER_INVENTORY, "Inventory parameters from persisted observations",
        SAFETY_READ_ONLY, produces=(tx.PARAMETER_OBSERVED,),
        requires_authorization=False, requires_network=False, implemented=True),
    ActionSpec(
        CHECK_REFLECTION, "Check whether a controlled marker is reflected",
        SAFETY_READ_ONLY, produces=(tx.REFLECTION_OBSERVED,),
        requires_authorization=False, requires_network=False, implemented=True,
        limitation="derives from a recorded response; it does not send "
                   "traffic by itself"),
    ActionSpec(
        CLASSIFY_REFLECTION_CONTEXT,
        "Classify the context the reflection lands in",
        SAFETY_READ_ONLY, produces=(tx.OUTPUT_CONTEXT_IDENTIFIED,),
        requires_authorization=False, requires_network=False, implemented=True),
    ActionSpec(
        TRACE_DOM_SOURCE, "Trace a DOM source reachable from controlled input",
        SAFETY_READ_ONLY, produces=(tx.DOM_SINK_IDENTIFIED,),
        requires_authorization=False, requires_network=False, implemented=True,
        limitation="operates on a recorded document; no browser is launched"),
    ActionSpec(
        TRACE_DOM_SINK, "Trace a dangerous DOM sink from a DOM source",
        SAFETY_READ_ONLY, produces=(tx.DOM_SINK_IDENTIFIED,),
        requires_authorization=False, requires_network=False, implemented=True,
        limitation="operates on a recorded document; no browser is launched"),
    ActionSpec(
        SEND_MARKER, "Send a controlled marker to an observed parameter",
        SAFETY_PROBE, produces=(tx.CONTROLLED_INPUT_SENT,
                                tx.REFLECTION_OBSERVED),
        requires_authorization=True, requires_network=True, implemented=False,
        limitation="requires an issued execution authorization and the "
                   "authorized transport; without both the action is BLOCKED"),
    ActionSpec(
        DELIVER_CONTROLLED_PAYLOAD,
        "Deliver a controlled payload into the reflected context",
        SAFETY_ACTIVE, produces=(tx.PAYLOAD_EXECUTION,),
        requires_authorization=True, requires_network=True, implemented=False,
        limitation="payload execution is not available in this runtime: no "
                   "browser/execution lane is wired, so the action is BLOCKED "
                   "and never produces synthetic execution evidence"),
    ActionSpec(
        OBSERVE_EXECUTION, "Observe controlled execution in a browser context",
        SAFETY_ACTIVE, produces=(tx.PAYLOAD_EXECUTION,
                                 tx.EXPLOITABILITY_ESTABLISHED),
        requires_authorization=True, requires_network=True, implemented=False,
        limitation="requires the pinned browser execution lane; not reachable "
                   "from the bounded research worker, so BLOCKED"),
    ActionSpec(
        SEND_ORIGIN_HEADER, "Supply an attacker-controlled Origin header",
        SAFETY_PROBE, produces=(tx.CONTROLLED_INPUT_SENT,),
        requires_authorization=True, requires_network=True, implemented=False,
        limitation="CORS chain is contract-only in EPIC12"),
    ActionSpec(
        CHECK_CORS_HEADERS, "Read the ACAO/ACAC behaviour for that Origin",
        SAFETY_READ_ONLY, produces=(tx.RESPONSE_OBSERVED,),
        requires_authorization=False, requires_network=False, implemented=False,
        limitation="CORS chain is contract-only in EPIC12"),
    ActionSpec(
        CLASSIFY_CORS_ORIGIN_ECHO, "Classify whether the origin was echoed",
        SAFETY_READ_ONLY, produces=(tx.OUTPUT_CONTEXT_IDENTIFIED,),
        requires_authorization=False, requires_network=False, implemented=False,
        limitation="CORS chain is contract-only in EPIC12"),
    ActionSpec(
        CHECK_CREDENTIALS_MODE, "Evaluate Access-Control-Allow-Credentials",
        SAFETY_READ_ONLY, produces=(tx.PAYLOAD_EXECUTION,),
        requires_authorization=False, requires_network=False, implemented=False,
        limitation="CORS chain is contract-only in EPIC12"),
    ActionSpec(
        ASSESS_RESPONSE_SENSITIVITY,
        "Assess whether the credentialed response is sensitive",
        SAFETY_READ_ONLY, produces=(tx.IMPACT_ESTABLISHED,),
        requires_authorization=False, requires_network=False, implemented=False,
        limitation="CORS chain is contract-only in EPIC12"),
    ActionSpec(
        SEND_REDIRECT_MARKER, "Supply a controlled redirect destination",
        SAFETY_PROBE, produces=(tx.CONTROLLED_INPUT_SENT,),
        requires_authorization=True, requires_network=True, implemented=False,
        limitation="open-redirect chain is contract-only in EPIC12"),
    ActionSpec(
        CHECK_REDIRECT_LOCATION, "Observe the Location header/redirect target",
        SAFETY_READ_ONLY, produces=(tx.RESPONSE_OBSERVED,),
        requires_authorization=False, requires_network=False, implemented=False,
        limitation="open-redirect chain is contract-only in EPIC12"),
    ActionSpec(
        CLASSIFY_REDIRECT_TARGET, "Classify the terminal redirect destination",
        SAFETY_READ_ONLY, produces=(tx.PAYLOAD_EXECUTION,),
        requires_authorization=False, requires_network=False, implemented=False,
        limitation="open-redirect chain is contract-only in EPIC12"),
    ActionSpec(
        SEND_CALLBACK_URL, "Submit a controlled callback URL",
        SAFETY_PROBE, produces=(tx.CONTROLLED_INPUT_SENT,),
        requires_authorization=True, requires_network=True, implemented=False,
        limitation="SSRF chain is contract-only in EPIC12"),
    ActionSpec(
        CHECK_CALLBACK_INTERACTION,
        "Check whether the controlled destination was contacted",
        SAFETY_READ_ONLY, produces=(tx.RESPONSE_OBSERVED,),
        requires_authorization=False, requires_network=False, implemented=False,
        limitation="SSRF chain is contract-only in EPIC12"),
    ActionSpec(
        OBSERVE_SERVER_RESPONSE, "Observe server-side behaviour differences",
        SAFETY_READ_ONLY, produces=(tx.PAYLOAD_EXECUTION,),
        requires_authorization=False, requires_network=False, implemented=False,
        limitation="SSRF chain is contract-only in EPIC12"),
    ActionSpec(
        ASSESS_SSRF_IMPACT, "Assess access to internal/privileged resources",
        SAFETY_READ_ONLY, produces=(tx.IMPACT_ESTABLISHED,),
        requires_authorization=False, requires_network=False, implemented=False,
        limitation="SSRF chain is contract-only in EPIC12"),
)

ACTION_SPECS: dict[str, ActionSpec] = {s.action_type: s for s in _SPECS}
ACTION_TYPES: tuple[str, ...] = tuple(sorted(ACTION_SPECS))

#: Actions that need an issued authorization reference to even be created.
AUTHORIZATION_REQUIRED_ACTIONS: frozenset[str] = frozenset(
    t for t, s in ACTION_SPECS.items() if s.requires_authorization)

#: Actions with a wired executor in this runtime.
IMPLEMENTED_ACTIONS: frozenset[str] = frozenset(
    t for t, s in ACTION_SPECS.items() if s.implemented)


def spec_for(action_type: str) -> ActionSpec:
    spec = ACTION_SPECS.get(str(action_type or "").strip().upper())
    if spec is None:
        raise ActionError(f"unknown action type: {action_type!r}")
    return spec


def action_catalog() -> list[dict[str, Any]]:
    return [ACTION_SPECS[t].to_dict() for t in ACTION_TYPES]


class ActionError(ValueError):
    """Raised when an action would violate its own contract."""


def action_id_for(*, candidate_id: str, objective_id: str, action_type: str,
                  attempt: int = 1, salt: str = "") -> str:
    """Deterministic action identity (re-planning is idempotent per attempt)."""
    seed = "|".join([str(candidate_id), str(objective_id),
                     str(action_type).upper(), str(int(attempt)), str(salt)])
    return "act-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]


def target_in_scope(target: str, scope_ref: str) -> bool:
    """Fail-closed scope check: the target host must sit inside the scope ref.

    The rule is exact: the target host must BE the scoped host or a true
    subdomain of it.  ``watch:scope:<program>/<host>`` and
    ``fixture:<name>/<host>`` share it, so a lookalike host can never be
    verified by accident.
    """
    text = str(scope_ref or "").strip()
    host = (urlparse(str(target or "")).hostname or "").lower()
    if not text or not host:
        return False
    if text.startswith("fixture:"):
        body = text[len("fixture:"):]
    elif text.startswith("watch:scope:"):
        body = text[len("watch:scope:"):]
    else:
        return False
    if "/" not in body:
        return False
    _program, subdomain = body.split("/", 1)
    scoped = subdomain.strip().lower().rstrip(".")
    if not scoped:
        return False
    # exact host or a true subdomain of it — never a lookalike suffix
    # (``www.dell.com.evil.test`` must not pass for ``www.dell.com``)
    return host == scoped or host.endswith("." + scoped)


@dataclass
class VerificationAction:
    """One typed, auditable verification action (§6)."""

    action_type: str
    candidate_id: str
    objective_id: str
    scope_ref: str
    target: str = ""
    authorization_id: str = ""
    inputs: dict[str, Any] = field(default_factory=dict)
    state: str = ACTION_CREATED
    action_id: str = ""
    attempt: int = 1
    executor: str = ""
    result: dict[str, Any] = field(default_factory=dict)
    observation_ids: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    error: str = ""
    blocked_reason: str = ""
    safety: str = ""
    created_at: str = ""
    updated_at: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)
    revision: int = 1

    def __post_init__(self) -> None:
        self.action_type = str(self.action_type or "").strip().upper()
        spec = spec_for(self.action_type)          # unknown type -> ActionError
        self.safety = self.safety or spec.safety
        self.scope_ref = validate_scope_ref(self.scope_ref)
        for key in ("candidate_id", "objective_id"):
            if not str(getattr(self, key) or "").strip():
                raise ActionError(f"{key} is required")
        if self.safety not in SAFETY_CLASSES:
            raise ActionError(f"unknown safety class: {self.safety!r}")
        if self.state not in ACTION_STATES:
            raise ActionError(f"unknown action state: {self.state!r}")
        if self.target and not target_in_scope(self.target, self.scope_ref):
            raise FindingScopeError(
                f"action target outside authorized scope: {self.target[:80]}")
        if spec.requires_authorization and not self.authorization_id:
            raise ActionError(
                f"{self.action_type} requires an authorization reference")
        if not isinstance(self.inputs, dict):
            raise ActionError("inputs must be a mapping")
        self.attempt = max(1, int(self.attempt or 1))
        if not self.action_id:
            self.action_id = action_id_for(
                candidate_id=self.candidate_id, objective_id=self.objective_id,
                action_type=self.action_type, attempt=self.attempt)
        if not self.created_at:
            self.created_at = utcnow()
        if not self.updated_at:
            self.updated_at = self.created_at
        self.provenance.setdefault("rule_version", ACTION_RULE_VERSION)

    # ------------------------------------------------------------- helpers

    @property
    def spec(self) -> ActionSpec:
        return ACTION_SPECS[self.action_type]

    @property
    def is_terminal(self) -> bool:
        return self.state in ACTION_TERMINAL

    @property
    def requires_network(self) -> bool:
        return bool(self.spec.requires_network)

    def transition(self, new_state: str, *, reason: str = "",
                   detail: str = "", now: str | None = None) -> None:
        if self.state in ACTION_TERMINAL:
            raise ActionError(
                f"action {self.action_id} is terminal ({self.state})")
        allowed = ACTION_TRANSITIONS.get(self.state, frozenset())
        if new_state not in allowed:
            raise ActionError(
                f"invalid action transition {self.state}->{new_state}")
        if new_state == ACTION_AUTHORIZED and not str(
                self.authorization_id or "").strip():
            raise ActionError(
                "an AUTHORIZED action must carry an authorization reference")
        self.state = new_state
        self.revision += 1
        self.updated_at = now or utcnow()
        if new_state == ACTION_BLOCKED:
            self.blocked_reason = str(reason or "blocked")[:200]
        if new_state in (ACTION_FAILED, ACTION_BLOCKED) and reason:
            self.error = str(reason)[:400]

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "rule_version": ACTION_RULE_VERSION,
            "action_type": self.action_type,
            "label": self.spec.label,
            "safety": self.safety,
            "state": self.state,
            "candidate_id": self.candidate_id,
            "objective_id": self.objective_id,
            "scope_ref": self.scope_ref,
            "target": self.target,
            "authorization_id": self.authorization_id,
            "inputs": dict(self.inputs),
            "executor": self.executor,
            "attempt": self.attempt,
            "result": dict(self.result),
            "observation_ids": list(self.observation_ids),
            "evidence_refs": list(self.evidence_refs),
            "error": self.error,
            "blocked_reason": self.blocked_reason,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "provenance": dict(self.provenance),
            "revision": self.revision,
        }


__all__ = [
    "ACTION_AUTHORIZED", "ACTION_BLOCKED", "ACTION_CREATED", "ACTION_EXECUTING",
    "ACTION_FAILED", "ACTION_SKIPPED", "ACTION_SPECS", "ACTION_STATES",
    "ACTION_SUCCEEDED", "ACTION_TERMINAL", "ACTION_TRANSITIONS", "ACTION_TYPES",
    "ASSESS_RESPONSE_SENSITIVITY", "ASSESS_SSRF_IMPACT",
    "AUTHORIZATION_REQUIRED_ACTIONS", "ActionError", "ActionSpec",
    "CHECK_CALLBACK_INTERACTION", "CHECK_CORS_HEADERS",
    "CHECK_CREDENTIALS_MODE", "CHECK_REDIRECT_LOCATION",
    "CLASSIFY_CORS_ORIGIN_ECHO", "CLASSIFY_REDIRECT_TARGET",
    "CLASSIFY_REFLECTION_CONTEXT", "DELIVER_CONTROLLED_PAYLOAD",
    "IMPLEMENTED_ACTIONS", "OBSERVE_EXECUTION", "OBSERVE_SERVER_RESPONSE",
    "PARAMETER_INVENTORY", "SAFETY_ACTIVE", "SAFETY_CLASSES", "SAFETY_PROBE",
    "SAFETY_READ_ONLY", "SAFETY_UNAVAILABLE", "SEND_CALLBACK_URL",
    "SEND_MARKER", "SEND_ORIGIN_HEADER", "SEND_REDIRECT_MARKER", "TRACE_DOM_SINK",
    "TRACE_DOM_SOURCE", "VerificationAction", "action_catalog", "action_id_for",
    "spec_for", "target_in_scope",
]
