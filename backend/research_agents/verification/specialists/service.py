"""EPIC16 §17/§18/§24 — one verification service for every vulnerability class.

The loop is shared, not duplicated: candidate -> class -> chain -> missing
evidence -> authorized action -> bounded run -> classification -> re-evaluate
-> terminal state.  This module only dispatches to the class specialist, runs
the deterministic classifier over the observed material, builds the
observations through the trusted producer, and asks the existing EPIC12 engine
(and therefore the EPIC11 gate) for the verdict.

Two rules never bend:

* no observation without an authorized, class-appropriate run (§14/§16);
* an unavailable capability yields CAPABILITY_UNAVAILABLE / NOT_TESTED — never
  a negative and never a confirmation (§18).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from backend.research_agents.finding.integrity import taxonomy as tx
from backend.research_agents.verification import chains as ch
from backend.research_agents.verification import engine as en
from backend.research_agents.verification.specialists import base as sp
from backend.research_agents.verification.specialists import classifiers as cl
from backend.research_agents.verification.specialists import producer as pr

CLASS_VERIFICATION_VERSION = "epic16-class-verification-1"

#: honest outcome vocabulary (§18) — reusing base's, never a second one.
OUTCOME_CONFIRMED = "CONFIRMED_ELIGIBLE"
OUTCOME_NOT_CONFIRMED = "NOT_CONFIRMED"
OUTCOME_PENDING = "PENDING"
OUTCOME_NOT_TESTED = "NOT_TESTED"
OUTCOME_BLOCKED = "BLOCKED"
OUTCOME_INCONCLUSIVE = "INCONCLUSIVE"
OUTCOME_CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
OUTCOME_NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
OUTCOME_UNKNOWN_CLASS = "UNKNOWN_CLASS"

OUTCOME_NEXT_STEP: dict[str, str] = {
    OUTCOME_CONFIRMED: "the EPIC11 gate decided: no further action is implied",
    OUTCOME_NOT_CONFIRMED: "the observation is negative for this surface",
    OUTCOME_PENDING: "more evidence is required by the class contract",
    OUTCOME_NOT_TESTED: "acquire the missing material through the authorized "
                        "acquisition lane first",
    OUTCOME_BLOCKED: "resolve the recorded authorization blocker",
    OUTCOME_INCONCLUSIVE: "re-run with bounded, complete material",
    OUTCOME_CAPABILITY_UNAVAILABLE: "the required capability is unavailable "
                                    "in this runtime",
    OUTCOME_NOT_IMPLEMENTED: "no chain exists for this class",
    OUTCOME_UNKNOWN_CLASS: "the class is not registered",
}


def _authorization_ref(authorization: Any) -> str:
    if isinstance(authorization, Mapping):
        return str(authorization.get("authorization_id") or "")
    return str(getattr(authorization, "authorization_id", "") or "")


def _authorized(authorization: Any) -> bool:
    """Reuses the EPIC15 authorization test on the same object shape."""
    if authorization is None:
        return False
    if isinstance(authorization, Mapping):
        if authorization.get("expired") is True:
            return False
        return bool(authorization.get("authorization_ids")
                    or authorization.get("authorization_id")
                    or authorization.get("scope_ref")
                    or authorization.get("scope"))
    return bool(getattr(authorization, "authorization_ids", None))


@dataclass(frozen=True)
class ClassVerificationResult:
    """One class verification run's honest outcome (§18/§24)."""

    vulnerability_class: str
    outcome: str
    reason: str = ""
    candidate_id: str = ""
    scope_ref: str = ""
    target: str = ""
    parameter: str = ""
    action_id: str = ""
    authorization_id: str = ""
    capability: str = ""
    assessment: dict[str, Any] = field(default_factory=dict)
    observations: tuple[Any, ...] = ()
    evidence_types: tuple[str, ...] = ()
    chain_state: dict[str, Any] = field(default_factory=dict)
    confirmation_requirements: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    next_step: str = ""
    rule_version: str = CLASS_VERIFICATION_VERSION

    @property
    def confirmed(self) -> bool:
        """True only when the EPIC11 gate said so — never from this module."""
        return bool(self.chain_state.get("confirmed")) and \
            self.outcome == OUTCOME_CONFIRMED

    @property
    def produces_confirmation_evidence(self) -> bool:
        return tx.EXPLOITABILITY_ESTABLISHED in self.evidence_types

    def to_dict(self) -> dict[str, Any]:
        return {
            "vulnerability_class": self.vulnerability_class,
            "outcome": self.outcome,
            "reason": self.reason,
            "candidate_id": self.candidate_id,
            "scope_ref": self.scope_ref,
            "target": self.target,
            "parameter": self.parameter,
            "action_id": self.action_id,
            "authorization_id": self.authorization_id,
            "capability": self.capability,
            "assessment": dict(self.assessment),
            "evidence_types": list(self.evidence_types),
            "chain_state": dict(self.chain_state),
            "confirmation_requirements": list(self.confirmation_requirements),
            "blockers": list(self.blockers),
            "next_step": self.next_step,
            "confirmed": self.confirmed,
            "rule_version": self.rule_version,
        }


def _empty(vulnerability_class: str, outcome: str, reason: str, **kw: Any
           ) -> ClassVerificationResult:
    return ClassVerificationResult(
        vulnerability_class=vulnerability_class, outcome=outcome, reason=reason,
        next_step=OUTCOME_NEXT_STEP.get(outcome, ""), **kw)


def _assess(vulnerability_class: str, material: Mapping[str, Any]) -> Any:
    """Run the class's deterministic classifier over observed material."""
    material = dict(material or {})
    if vulnerability_class == "CORS":
        return cl.classify_cors(
            str(material.get("origin") or ""),
            material.get("response_headers") or {},
            credentials_relevant=bool(material.get("credentials_relevant")),
            sensitive_response_declared=bool(
                material.get("sensitive_response_declared")))
    if vulnerability_class == "OPEN_REDIRECT":
        return cl.classify_redirect(
            str(material.get("supplied_destination") or ""),
            material.get("location"),
            request_url=str(material.get("request_url") or ""),
            scope_hosts=tuple(material.get("scope_hosts") or ()))
    if vulnerability_class == "SSRF":
        return cl.classify_ssrf(
            str(material.get("destination") or ""),
            url_parameter_present=bool(material.get("url_parameter_present")),
            server_request_observed=bool(material.get("server_request_observed")),
            destination_interaction=bool(
                material.get("destination_interaction")),
            security_relevant_response=bool(
                material.get("security_relevant_response")),
            callback_capability_available=bool(
                material.get("callback_capability_available")),
            scope_hosts=tuple(material.get("scope_hosts") or ()))
    if vulnerability_class == "IDOR":
        return cl.classify_idor(
            object_reference_present=bool(
                material.get("object_reference_present")),
            authorized_identities=int(material.get("authorized_identities") or 0),
            identity_switching=bool(material.get("identity_switching")),
            ownership_semantics=bool(material.get("ownership_semantics")))
    if vulnerability_class == "CVE_RESEARCH":
        return cl.classify_cve_applicability(
            observable_product=str(material.get("observable_product") or ""),
            observable_version=str(material.get("observable_version") or ""),
            advisory_product=str(material.get("advisory_product") or ""),
            affected_min=str(material.get("affected_min") or ""),
            affected_max=str(material.get("affected_max") or ""))
    raise ValueError(f"no classifier for {vulnerability_class!r}")


def _outcome_for(vulnerability_class: str, assessment: Any,
                 chain_state: Any) -> tuple[str, str]:
    """Map an assessment + chain state onto the §18 outcome vocabulary."""
    if getattr(assessment, "refusal", ""):
        return OUTCOME_NOT_TESTED, str(assessment.refusal)
    if vulnerability_class == "SSRF" and \
            getattr(assessment, "active_verification", "") == \
            "CAPABILITY_UNAVAILABLE":
        return OUTCOME_CAPABILITY_UNAVAILABLE, "no_controlled_callback_capability"
    if vulnerability_class == "IDOR" and \
            not getattr(assessment, "second_context_available", False):
        return OUTCOME_CAPABILITY_UNAVAILABLE, str(
            getattr(assessment, "reason", "") or "no_second_context")

    confirmed = bool(getattr(chain_state, "confirmed", False))
    if confirmed:
        return OUTCOME_CONFIRMED, "epic11_gate_confirmed"

    # §12: a research chain has no confirmation claim, so its terminal state is
    # research-specific — never a confirmation and never a bare "we found
    # nothing".
    if vulnerability_class == "CVE_RESEARCH":
        state = str(getattr(assessment, "state", "") or "")
        if state in (cl.CVE_VERSION_NOT_AFFECTED, cl.CVE_WRONG_PRODUCT):
            return OUTCOME_NOT_CONFIRMED, f"applicability_negative:{state}"
        if state == cl.CVE_APPLICABILITY_CONFIRMED:
            return OUTCOME_INCONCLUSIVE, \
                "research_chain_declares_no_confirmation_claim"
        return OUTCOME_NOT_TESTED, f"applicability_unresolved:{state}"

    missing = tuple(getattr(chain_state, "next_stage_missing_types", ()) or ())
    unproducible = tuple(t for t in missing if t in (
        tx.EXPLOITABILITY_ESTABLISHED, tx.DOM_SINK_IDENTIFIED))

    state = str(getattr(assessment, "exploitable_state", "") or "")
    if state == "NOT_CONFIRMED":
        return OUTCOME_NOT_CONFIRMED, "negative_evidence_recorded"
    if state == "PENDING":
        if unproducible and len(unproducible) == len(missing):
            return OUTCOME_PENDING, (
                "final_stage_capability_unavailable:"
                + ",".join(unproducible))
        return OUTCOME_PENDING, "evidence_incomplete"
    if state == "CAPABILITY_UNAVAILABLE":
        return OUTCOME_CAPABILITY_UNAVAILABLE, "class_capability_unavailable"

    verdict = str(getattr(chain_state, "verdict", "") or "").upper()
    if "CONTRADICT" in verdict or "NEGATIVE" in verdict:
        return OUTCOME_NOT_CONFIRMED, "negative_evidence_recorded"
    if verdict == "BLOCKED":
        return OUTCOME_BLOCKED, "chain_blocked"
    if verdict == "INCONCLUSIVE":
        return OUTCOME_INCONCLUSIVE, "chain_inconclusive"
    if unproducible and len(unproducible) == len(missing):
        return OUTCOME_CAPABILITY_UNAVAILABLE, (
            "stage_capability_unavailable:" + ",".join(unproducible))
    if verdict in ("VERIFICATION_PENDING", "PENDING", ""):
        return OUTCOME_PENDING, "evidence_incomplete"
    return OUTCOME_NOT_CONFIRMED, f"chain_verdict:{verdict or 'unknown'}"


def verify_class(vulnerability_class: str, *,
                 candidate_id: str = "", scope_ref: str = "",
                 target: str = "", parameter: str = "",
                 authorization: Any = None,
                 material: Mapping[str, Any] | None = None,
                 action_id: str = "", objective_id: str = "",
                 where: str = "", marker: str = "",
                 request_ref: str = "", response_ref: str = "",
                 ) -> ClassVerificationResult:
    """Verify one vulnerability class through the shared framework (§17)."""
    normalized = ch.normalize_class(vulnerability_class)
    specialist = sp.specialist_for(normalized)
    base_kw = {"candidate_id": candidate_id, "scope_ref": scope_ref,
               "target": target, "parameter": parameter, "action_id": action_id}

    if specialist is None:
        # A class the platform names but does not implement is NOT_IMPLEMENTED;
        # only a genuinely unknown name is an unknown class.
        declared = (normalized in ch.CHAINS
                    or normalized in getattr(ch, "FUTURE_CLASSES", ()))
        return _empty(normalized or str(vulnerability_class),
                      OUTCOME_NOT_IMPLEMENTED if declared
                      else OUTCOME_UNKNOWN_CLASS,
                      (f"no_specialist_declared_for_class:{normalized}"
                       if declared else
                       f"unregistered_vulnerability_class:{vulnerability_class}"),
                      capability=sp.CAP_NOT_IMPLEMENTED, **base_kw)

    chain = ch.chain_for(normalized)
    capability = (chain.capability if chain is not None
                  else ch.CAPABILITY_NOT_IMPLEMENTED)
    auth_ref = _authorization_ref(authorization)
    result_kw = dict(base_kw, capability=specialist.capability,
                     authorization_id=auth_ref)

    if chain is None or capability == ch.CAPABILITY_NOT_IMPLEMENTED:
        return _empty(normalized, OUTCOME_NOT_IMPLEMENTED,
                      "no_chain_declared_for_class", **result_kw)

    # §14: authorization is checked BEFORE any primitive runs.
    if not _authorized(authorization):
        return _empty(normalized, OUTCOME_BLOCKED, "authorization_missing",
                      blockers=specialist.blockers,
                      confirmation_requirements=specialist.confirmation_requirements,
                      **result_kw)

    if specialist.capability == sp.CAP_NOT_IMPLEMENTED:
        return _empty(normalized, OUTCOME_CAPABILITY_UNAVAILABLE,
                      "specialist_capability_unavailable",
                      blockers=specialist.blockers,
                      confirmation_requirements=specialist.confirmation_requirements,
                      **result_kw)

    if not material:
        return _empty(normalized, OUTCOME_NOT_TESTED, "no_material_supplied",
                      blockers=specialist.blockers,
                      confirmation_requirements=specialist.confirmation_requirements,
                      **result_kw)

    assessment = _assess(normalized, material)
    try:
        producer = pr.producer_for(normalized)
    except ValueError as exc:  # pragma: no cover - defensive
        return _empty(normalized, OUTCOME_NOT_IMPLEMENTED, str(exc), **result_kw)

    effective_action = action_id or f"CLASSIFY_{normalized}"
    effective_objective = objective_id or (
        f"objective:{normalized}:{effective_action}")
    observations = producer.build(
        assessment, action_id=effective_action,
        candidate_id=candidate_id, objective_id=effective_objective,
        scope_ref=scope_ref, where=where, marker=marker,
        request_ref=request_ref, response_ref=response_ref)

    rows = [o.to_dict() for o in observations]
    chain_state = en.evaluate_chain(normalized, rows) if rows else None
    outcome, reason = (OUTCOME_NOT_TESTED, "no_observation_produced") \
        if chain_state is None else _outcome_for(normalized, assessment,
                                                 chain_state)

    evidence_types: list[str] = []
    for row in rows:
        declared = str(row.get("evidence_type") or "")
        if declared and declared not in evidence_types:
            evidence_types.append(declared)

    return ClassVerificationResult(
        vulnerability_class=normalized, outcome=outcome, reason=reason,
        candidate_id=candidate_id, scope_ref=scope_ref, target=target,
        parameter=parameter, action_id=effective_action,
        authorization_id=auth_ref, capability=specialist.capability,
        assessment=assessment.to_dict(),
        observations=observations, evidence_types=tuple(evidence_types),
        chain_state=(chain_state.to_dict() if chain_state is not None else {}),
        confirmation_requirements=specialist.confirmation_requirements,
        blockers=specialist.blockers, next_step=OUTCOME_NEXT_STEP.get(outcome, ""))


def project_class_verification(result: ClassVerificationResult) -> dict[str, Any]:
    """The §24 SOC/UI view — never optimistically confirmed."""
    return {
        "verification_class": result.vulnerability_class,
        "verification_chain": (ch.chain_for(result.vulnerability_class).chain_id
                               if ch.chain_for(result.vulnerability_class)
                               else ""),
        "capability": result.capability,
        "evidence": list(result.evidence_types),
        "observations": len(result.observations),
        "missing": list(result.confirmation_requirements),
        "actions": [result.action_id] if result.action_id else [],
        "authorization": result.authorization_id,
        "result": result.outcome,
        "final_state": _final_state(result),
        "reason": result.reason,
        "blockers": list(result.blockers),
        "next_step": result.next_step,
    }


def _final_state(result: ClassVerificationResult) -> str:
    if result.outcome == OUTCOME_CONFIRMED and result.confirmed:
        return "CONFIRMED"
    return {
        OUTCOME_NOT_CONFIRMED: "NOT_CONFIRMED",
        OUTCOME_PENDING: "PENDING",
        OUTCOME_NOT_TESTED: "NOT_TESTED",
        OUTCOME_BLOCKED: "BLOCKED",
        OUTCOME_INCONCLUSIVE: "INCONCLUSIVE",
        OUTCOME_CAPABILITY_UNAVAILABLE: "CAPABILITY_UNAVAILABLE",
        OUTCOME_NOT_IMPLEMENTED: "CAPABILITY_UNAVAILABLE",
        OUTCOME_UNKNOWN_CLASS: "CAPABILITY_UNAVAILABLE",
    }.get(result.outcome, "INCONCLUSIVE")


__all__ = [
    "CLASS_VERIFICATION_VERSION", "ClassVerificationResult", "OUTCOME_BLOCKED",
    "OUTCOME_CAPABILITY_UNAVAILABLE", "OUTCOME_CONFIRMED",
    "OUTCOME_INCONCLUSIVE", "OUTCOME_NOT_CONFIRMED", "OUTCOME_NOT_IMPLEMENTED",
    "OUTCOME_NOT_TESTED", "OUTCOME_NEXT_STEP", "OUTCOME_PENDING",
    "OUTCOME_UNKNOWN_CLASS", "project_class_verification", "verify_class",
]
