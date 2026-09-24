"""EPIC16 §13 — the shared verification framework for vulnerability classes.

One interface, one registry, no second engine.  A specialist declares only
class-specific logic; the authoritative layers stay where they are:

* EPIC11  — the evidence taxonomy and the claim contract (``contracts.py``)
* EPIC12  — the verification chain/engine/actions (``chains.py``)
* EPIC13  — active acquisition (``acquisition/``)
* EPIC14  — provenance and the declared-vs-authoritative boundary
* EPIC15  — deep DOM verification (``deep/``)

A specialist may therefore do exactly three things: declare its class
metadata, classify observed material deterministically, and report honestly
when a capability is unavailable.  It never confirms anything — the EPIC11
gate does, and only through the EPIC12 chain.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from backend.research_agents.verification import chains as ch

CLASS_RULE_VERSION = "epic16-specialist-1"

#: capability vocabulary (EPIC13/EPIC15's, reused — not re-invented)
CAP_IMPLEMENTED = "IMPLEMENTED"
CAP_LIMITED = "LIMITED"
CAP_NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

#: verification outcomes for one class run (§18): the vocabulary distinguishes
#: NOT_TESTED / BLOCKED / NOT_CONFIRMED / INCONCLUSIVE / CAPABILITY_UNAVAILABLE.
CLASS_CONFIRMED_ELIGIBLE = "CONFIRMED_ELIGIBLE"
CLASS_NOT_CONFIRMED = "NOT_CONFIRMED"
CLASS_PENDING = "PENDING"
CLASS_NOT_TESTED = "NOT_TESTED"
CLASS_BLOCKED = "BLOCKED"
CLASS_INCONCLUSIVE = "INCONCLUSIVE"
CLASS_CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"

CLASS_OUTCOMES: tuple[str, ...] = (
    CLASS_CONFIRMED_ELIGIBLE, CLASS_NOT_CONFIRMED, CLASS_PENDING,
    CLASS_NOT_TESTED, CLASS_BLOCKED, CLASS_INCONCLUSIVE,
    CLASS_CAPABILITY_UNAVAILABLE)


@dataclass(frozen=True)
class Specialist:
    """One vulnerability class's declared verification interface (§13)."""

    vulnerability_class: str
    capability: str
    stages: tuple[str, ...] = ()
    required_evidence: tuple[str, ...] = ()
    optional_evidence: tuple[str, ...] = ()
    allowed_actions: tuple[str, ...] = ()
    terminal_conditions: tuple[str, ...] = ()
    confirmation_requirements: tuple[str, ...] = ()
    safety_policy: str = ""
    capability_requirements: tuple[str, ...] = ()
    scanners: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    rule_version: str = CLASS_RULE_VERSION

    @property
    def chain(self) -> Any:
        return ch.chain_for(self.vulnerability_class)

    @property
    def contract(self) -> Any:
        return (self.chain.contract if self.chain is not None else None)

    @property
    def active_verification_capable(self) -> bool:
        """Only a class whose active lane is implemented can send input."""
        return self.capability == CAP_IMPLEMENTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "vulnerability_class": self.vulnerability_class,
            "capability": self.capability,
            "stages": list(self.stages),
            "required_evidence": list(self.required_evidence),
            "optional_evidence": list(self.optional_evidence),
            "allowed_actions": list(self.allowed_actions),
            "terminal_conditions": list(self.terminal_conditions),
            "confirmation_requirements": list(self.confirmation_requirements),
            "safety_policy": self.safety_policy,
            "capability_requirements": list(self.capability_requirements),
            "scanners": list(self.scanners),
            "blockers": list(self.blockers),
            "limitations": list(self.limitations),
            "active_verification_capable": self.active_verification_capable,
            "chain_id": self.chain.chain_id if self.chain is not None else "",
            "rule_version": self.rule_version,
        }


def _stages_of(vulnerability_class: str) -> tuple[str, ...]:
    chain = ch.chain_for(vulnerability_class)
    return tuple(s.key for s in chain.stages) if chain is not None else ()


def _actions_of(vulnerability_class: str) -> tuple[str, ...]:
    chain = ch.chain_for(vulnerability_class)
    if chain is None:
        return ()
    out: list[str] = []
    for stage in chain.stages:
        for action in stage.allowed_actions:
            if action not in out:
                out.append(action)
    return tuple(out)


def _confirmation_of(vulnerability_class: str) -> tuple[str, ...]:
    chain = ch.chain_for(vulnerability_class)
    if chain is None or not ch._has_confirmation_claim(chain):
        return ()
    return tuple("/".join(group) for group in chain.confirmation_requires)


CORS = Specialist(
    vulnerability_class="CORS",
    capability=CAP_LIMITED,
    stages=_stages_of("CORS"),
    required_evidence=("cors_acceptance_evidence",),
    optional_evidence=("cors_acao_observed", "cors_origin_supplied"),
    allowed_actions=_actions_of("CORS"),
    terminal_conditions=("origin_not_accepted", "credentials_not_allowed",
                         "no_sensitive_response"),
    confirmation_requirements=_confirmation_of("CORS"),
    safety_policy=("read-only classification of recorded response headers; "
                   "no live request is issued by this runtime"),
    capability_requirements=("a live request lane able to set the Origin "
                             "header (not available here)",
                             "a browser-relevant cross-origin read "
                             "(EPIC15 PATH C)"),
    scanners=("classify_cors",),
    blockers=("SEND_ORIGIN_HEADER needs a live HTTP lane this runtime does "
              "not have",),
    limitations=("an ACAO value is never automatically exploitable",
                 "credentials-absent CORS is a configuration observation",
                 "confirmation additionally needs browser-relevant "
                 "exploitability, which is unavailable here"),
)

OPEN_REDIRECT = Specialist(
    vulnerability_class="OPEN_REDIRECT",
    capability=CAP_LIMITED,
    stages=_stages_of("OPEN_REDIRECT"),
    required_evidence=("redirect_response_observed",),
    optional_evidence=("redirect_input_identified",),
    allowed_actions=_actions_of("OPEN_REDIRECT"),
    terminal_conditions=("redirect_parameter_ignored",
                         "redirect_destination_normalized",
                         "redirect_relative_only", "redirect_same_origin"),
    confirmation_requirements=_confirmation_of("OPEN_REDIRECT"),
    safety_policy=("read-only classification of a recorded Location header; "
                   "the terminal destination is never followed"),
    capability_requirements=("a live request lane able to supply a "
                             "controlled destination (not available here)",),
    scanners=("classify_redirect",),
    blockers=("SEND_REDIRECT_MARKER needs a live HTTP lane this runtime does "
              "not have",),
    limitations=("a redirect parameter is not an open redirect",
                 "a 302 alone never confirms",
                 "the off-scope destination is never actually reached here"),
)

SSRF = Specialist(
    vulnerability_class="SSRF",
    capability=CAP_LIMITED,
    stages=_stages_of("SSRF"),
    required_evidence=("ssrf_destination_policy_evaluated",),
    optional_evidence=("ssrf_url_parameter",),
    allowed_actions=_actions_of("SSRF"),
    terminal_conditions=("destination_policy_rejected",
                         "no_server_request_observed"),
    confirmation_requirements=_confirmation_of("SSRF"),
    safety_policy=("destination policy evaluation ONLY: internal, loopback, "
                   "metadata, non-http(s) schemes, non-standard ports and "
                   "scope escapes are refused and never probed"),
    capability_requirements=("a controlled callback destination and an "
                             "observable server-side request (not available "
                             "here)",),
    scanners=("classify_ssrf_destination",),
    blockers=("SEND_CALLBACK_URL and CHECK_CALLBACK_INTERACTION need a live "
              "request lane and an authorized callback endpoint",),
    limitations=("no SSRF probing of internal infrastructure is ever "
                 "performed",
                 "a URL-shaped parameter is not SSRF",
                 "no server-side request evidence means no SSRF claim"),
)

IDOR = Specialist(
    vulnerability_class="IDOR",
    capability=CAP_NOT_IMPLEMENTED,
    stages=_stages_of("IDOR"),
    required_evidence=("idor_second_context_available",),
    allowed_actions=_actions_of("IDOR"),
    terminal_conditions=("no_second_context", "access_denied"),
    confirmation_requirements=_confirmation_of("IDOR"),
    safety_policy=("no identity switching and no cross-tenant access "
                   "attempt is performed or simulated"),
    capability_requirements=("a second authorized identity and object "
                             "ownership semantics (absent here)",),
    scanners=("classify_idor_capability",),
    blockers=("this runtime has no second authorized identity, no "
              "identity-switching mechanism and no object-ownership model",),
    limitations=("an object reference is not IDOR",
                 "CHECK_OBJECT_ACCESS refuses: capability unavailable"),
)

CVE_RESEARCH = Specialist(
    vulnerability_class="CVE_RESEARCH",
    capability=CAP_LIMITED,
    stages=_stages_of("CVE_RESEARCH"),
    required_evidence=("cve_applicability_evidence",),
    allowed_actions=_actions_of("CVE_RESEARCH"),
    terminal_conditions=("version_not_affected", "applicability_unresolved"),
    confirmation_requirements=(),
    safety_policy=("research only: product/version correlation against a "
                   "knowledge reference; never exploitability"),
    capability_requirements=("an applicability knowledge source for the "
                             "observed product and version",),
    scanners=("classify_cve_applicability",),
    blockers=(),
    limitations=("a CVE match is not vulnerability confirmation",
                 "the EPIC11 CVE_RESEARCH contract declares no confirmation "
                 "claim, so a CVE can never be confirmed here"),
)

XSS = Specialist(
    vulnerability_class="XSS",
    capability=CAP_IMPLEMENTED,
    stages=_stages_of("XSS"),
    allowed_actions=_actions_of("XSS"),
    confirmation_requirements=_confirmation_of("XSS"),
    safety_policy=("EPIC13 acquisition + EPIC15 deep verification remain "
                   "authoritative; nothing about XSS changes here"),
    capability_requirements=("authorized acquisition lane (EPIC13)",),
    scanners=("epic13_acquisition", "epic15_deep"),
    blockers=(),
    limitations=("unchanged by EPIC16",),
)

SPECIALISTS: dict[str, Specialist] = {
    "XSS": XSS,
    "CORS": CORS,
    "OPEN_REDIRECT": OPEN_REDIRECT,
    "SSRF": SSRF,
    "IDOR": IDOR,
    "CVE_RESEARCH": CVE_RESEARCH,
}


def specialist_for(vulnerability_class: Any) -> Specialist | None:
    """The specialist for a class (``None`` — never a fabricated one)."""
    return SPECIALISTS.get(ch.normalize_class(vulnerability_class))


def capability_matrix() -> list[dict[str, Any]]:
    """The §2/§25 capability matrix, joined with the chain layer."""
    chains = {row["vulnerability_class"]: row for row in ch.capability_matrix()}
    out: list[dict[str, Any]] = []
    for name, spec in sorted(SPECIALISTS.items()):
        chain_row = chains.get(name, {})
        out.append({
            "vulnerability_class": name,
            "specialist_capability": spec.capability,
            "chain_capability": chain_row.get("capability", ""),
            "stages": len(spec.stages),
            "required_evidence": list(spec.required_evidence),
            "active_verification": spec.active_verification_capable,
            "confirmation_requirements": list(spec.confirmation_requirements),
            "blockers": list(spec.blockers),
            "limitations": list(spec.limitations),
        })
    for name, chain_row in sorted(chains.items()):
        if name in SPECIALISTS:
            continue
        out.append({
            "vulnerability_class": name,
            "specialist_capability": CAP_NOT_IMPLEMENTED,
            "chain_capability": chain_row.get("capability", ""),
            "stages": chain_row.get("stages", 0),
            "required_evidence": [],
            "active_verification": False,
            "confirmation_requirements": [],
            "blockers": ["no specialist declared"],
            "limitations": list(chain_row.get("limitations", [])),
        })
    return sorted(out, key=lambda row: row["vulnerability_class"])


def registered_classes() -> tuple[str, ...]:
    return tuple(sorted(SPECIALISTS))


__all__ = [
    "CAP_IMPLEMENTED", "CAP_LIMITED", "CAP_NOT_IMPLEMENTED",
    "CLASS_BLOCKED", "CLASS_CAPABILITY_UNAVAILABLE",
    "CLASS_CONFIRMED_ELIGIBLE", "CLASS_INCONCLUSIVE", "CLASS_NOT_CONFIRMED",
    "CLASS_NOT_TESTED", "CLASS_OUTCOMES", "CLASS_PENDING", "CLASS_RULE_VERSION",
    "CORS", "CVE_RESEARCH", "IDOR", "OPEN_REDIRECT", "SPECIALISTS", "SSRF",
    "Specialist", "XSS", "capability_matrix", "registered_classes",
    "specialist_for",
]
