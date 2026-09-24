"""EPIC13 §21 — acquisition capability contracts.

For every vulnerability class the runtime might want to verify actively, this
module states — explicitly and in one place — whether acquisition is
``IMPLEMENTED``, ``LIMITED`` or ``NOT_IMPLEMENTED``, which actions the class
needs, what evidence those actions would produce, and what is *not*
acquirable in this runtime at all.

A capability contract is a statement about the runtime, not a promise about a
target: ``IMPLEMENTED`` means "the machinery exists and would run if the
platform's authorized transport were available", never "this target is
vulnerable".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from backend.research_agents.verification import actions as ac

CAPABILITY_RULE_VERSION = "epic13-capability-1"

IMPLEMENTED = "IMPLEMENTED"
LIMITED = "LIMITED"
NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

CAPABILITY_STATES: tuple[str, ...] = (IMPLEMENTED, LIMITED, NOT_IMPLEMENTED)


@dataclass(frozen=True)
class CapabilityContract:
    """What active acquisition can genuinely do for one class."""

    vulnerability_class: str
    capability: str
    actions: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    not_acquirable: tuple[str, ...] = ()
    limitation: str = ""
    requires_transport: bool = True
    requires_authorization: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "vulnerability_class": self.vulnerability_class,
            "capability": self.capability,
            "actions": list(self.actions),
            "evidence": list(self.evidence),
            "not_acquirable": list(self.not_acquirable),
            "limitation": self.limitation,
            "requires_transport": self.requires_transport,
            "requires_authorization": self.requires_authorization,
            "rule_version": CAPABILITY_RULE_VERSION,
        }


#: the shared reason every network-backed acquisition is blocked today.
_LIVE_GATE = ("requires an authorized transport: the platform's live execution "
              "gate is closed in this runtime (LIVE_TRAFFIC_ENABLED=false, "
              "B1/B2 deferred), so the action is BLOCKED rather than faked")

CONTRACTS: tuple[CapabilityContract, ...] = (
    CapabilityContract(
        vulnerability_class="XSS",
        capability=IMPLEMENTED,
        actions=(ac.SEND_MARKER, ac.CHECK_REFLECTION,
                 ac.CLASSIFY_REFLECTION_CONTEXT, ac.TRACE_DOM_SOURCE,
                 ac.TRACE_DOM_SINK),
        evidence=("REFLECTION_OBSERVED", "OUTPUT_CONTEXT_IDENTIFIED",
                  "DOM_SINK_IDENTIFIED", "NEGATIVE_EVIDENCE"),
        not_acquirable=("PAYLOAD_EXECUTION", "EXPLOITABILITY_ESTABLISHED",
                        "IMPACT_ESTABLISHED"),
        limitation=(_LIVE_GATE + "; DOM source→sink analysis is a read-only "
                    "trace of the served document (EPIC15: no browser is "
                    "launched, no JavaScript runs, so it establishes a "
                    "source→sink flow in the served material and never that "
                    "the sink executed); payload execution is never "
                    "attempted: reflection is evidence of reflection, not of "
                    "execution")),
    CapabilityContract(
        vulnerability_class="CORS",
        capability=NOT_IMPLEMENTED,
        actions=(ac.SEND_ORIGIN_HEADER, ac.CHECK_CORS_HEADERS,
                 ac.CLASSIFY_CORS_ORIGIN_ECHO, ac.CHECK_CREDENTIALS_MODE,
                 ac.ASSESS_RESPONSE_SENSITIVITY),
        evidence=("RESPONSE_OBSERVED",),
        not_acquirable=("AUTHORIZATION_CONFIRMED", "EXPLOITABILITY_ESTABLISHED"),
        limitation=("a controlled Origin header would have to be sent, and this "
                    "layer sends no headers at all (ALLOWED_REQUEST_HEADERS is "
                    "empty): " + _LIVE_GATE)),
    CapabilityContract(
        vulnerability_class="OPEN_REDIRECT",
        capability=LIMITED,
        actions=(ac.SEND_REDIRECT_MARKER, ac.CHECK_REDIRECT_LOCATION,
                 ac.CLASSIFY_REDIRECT_TARGET),
        evidence=("RESPONSE_OBSERVED", "NEGATIVE_EVIDENCE"),
        not_acquirable=("EXPLOITABILITY_ESTABLISHED",),
        limitation=("an already-recorded redirect response can be classified "
                    "read-only and every hop is scope-checked, but sending a "
                    "controlled redirect target needs an authorized transport: "
                    + _LIVE_GATE)),
    CapabilityContract(
        vulnerability_class="SSRF",
        capability=NOT_IMPLEMENTED,
        actions=(ac.SEND_CALLBACK_URL, ac.CHECK_CALLBACK_INTERACTION,
                 ac.OBSERVE_SERVER_RESPONSE, ac.ASSESS_SSRF_IMPACT),
        evidence=("RESPONSE_OBSERVED",),
        not_acquirable=("EXPLOITABILITY_ESTABLISHED",),
        limitation=("server-side interaction evidence needs a callback listener "
                    "and an authorized transport, neither of which exists "
                    "here: " + _LIVE_GATE)),
)


def contract_for(vulnerability_class: str) -> CapabilityContract | None:
    """The capability contract for a class (``None`` when none is declared)."""
    wanted = str(vulnerability_class or "").strip().upper()
    for contract in CONTRACTS:
        if contract.vulnerability_class == wanted:
            return contract
    return None


def capability_matrix() -> list[dict[str, Any]]:
    """Every class's capability state, for the report and the docs."""
    return [c.to_dict() for c in CONTRACTS]


def state_for(vulnerability_class: str) -> str:
    """The acquisition state for a class.

    An unknown class has no acquisition capability at all, so it is reported
    as ``NOT_IMPLEMENTED`` rather than as an empty state that could be read as
    "unknown, therefore allowed".
    """
    contract = contract_for(vulnerability_class)
    return contract.capability if contract else NOT_IMPLEMENTED


def document() -> dict[str, Any]:
    """The capability layer's contract, for docs and reports."""
    return {
        "rule_version": CAPABILITY_RULE_VERSION,
        "states": list(CAPABILITY_STATES),
        "contracts": capability_matrix(),
        "statements": [
            "Active Evidence Acquisition is not a generic scanner: it "
            "acquires one named missing evidence item at a time, inside the "
            "existing authorization, scope and budget model",
            "transport failure is not negative vulnerability evidence",
        ],
        "honesty_rules": [
            "IMPLEMENTED means the machinery exists, never that a target is "
            "vulnerable",
            "an action with no capability is reported, never faked",
            "no class is marked IMPLEMENTED while its transport is closed "
            "without saying so in its limitation",
        ],
    }


__all__ = [
    "CAPABILITY_RULE_VERSION", "CAPABILITY_STATES", "CONTRACTS",
    "CapabilityContract", "IMPLEMENTED", "LIMITED", "NOT_IMPLEMENTED",
    "capability_matrix", "contract_for", "document", "state_for",
]
