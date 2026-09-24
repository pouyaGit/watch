"""EPIC15 §14/§15 — the trusted deep-observation producer.

Every deep observation is built here, through the EPIC12/EPIC13
observation builders (which themselves enforce the EPIC14 signal↔type
agreement), and carries an attestation: the instrumentation method and
version, the action/observation/session identity and the authorization
reference.

A caller cannot hand this producer an ``evidence_type``: the type is
derived from the *state* the runtime actually observed.  A refusal
(browser unavailable, navigation blocked, expired authorization, timeout,
exhausted budget, missing instrumentation) produces a **NOT_TESTED**
observation — never a negative one — so a failure to run is never
presented as a security result (§18).
"""
from __future__ import annotations

from typing import Any

from backend.research_agents.finding.integrity import taxonomy as tx
from backend.research_agents.verification import observations as ob

from .dom import (DOM_INSTRUMENTATION_METHOD, DOM_INSTRUMENTATION_VERSION,
                  DomTrace)
from .execution import (DOM_SINK_OBSERVED, EXECUTION_OBSERVED,
                        AttemptResult, evidence_type_for, is_observed,
                        is_refusal)
from .exploitability import ExploitabilityAssessment

DEEP_PRODUCER_VERSION = "epic15-producer-1"

#: signals this producer may emit (EPIC11 registry entries, never new ones)
SIGNAL_DOM_SINK_IDENTIFIED = "dom_sink_identified"
SIGNAL_DOM_SINK_NOT_OBSERVED = "dom_sink_not_observed"
SIGNAL_DOM_SINK_NOT_TESTED = "dom_sink_not_tested"
SIGNAL_PAYLOAD_EXECUTION = "payload_execution"
SIGNAL_PAYLOAD_EXECUTION_NOT_OBSERVED = "payload_execution_not_observed"
SIGNAL_PAYLOAD_EXECUTION_NOT_TESTED = "payload_execution_not_tested"
SIGNAL_EXPLOITABILITY_ESTABLISHED = "exploitability_established"
SIGNAL_EXPLOITABILITY_NOT_ESTABLISHED = "exploitability_not_established"


class DeepObservationProducer:
    """Builds attested deep observations from real runtime outcomes."""

    version = DEEP_PRODUCER_VERSION

    def __init__(self, *, action_id: str, candidate_id: str,
                 objective_id: str = "", scope_ref: str = "",
                 job_id: str = "", authorization_id: str = "",
                 where: str = "", category: str = "XSS") -> None:
        self.action_id = action_id
        self.candidate_id = candidate_id
        self.objective_id = objective_id
        self.scope_ref = scope_ref
        self.job_id = job_id
        self.authorization_id = authorization_id
        self.where = where
        self.category = category

    # -- attestation ----------------------------------------------------

    def attestation(self, *, instrumentation_method: str = "",
                    instrumentation_version: str = "",
                    session_id: str = "",
                    extra: dict[str, Any] | None = None
                    ) -> dict[str, Any]:
        payload = {
            "producer": self.version,
            "producer_kind": "trusted_deep_verification",
            "action_id": self.action_id,
            "candidate_id": self.candidate_id,
            "authorization_id": self.authorization_id,
            "instrumentation_method": (instrumentation_method
                                       or DOM_INSTRUMENTATION_METHOD),
            "instrumentation_version": (instrumentation_version
                                        or DOM_INSTRUMENTATION_VERSION),
        }
        if session_id:
            payload["session_id"] = str(session_id)[:64]
        if extra:
            payload.update({k: v for k, v in extra.items() if v is not None})
        return payload

    def _base(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "candidate_id": self.candidate_id,
            "objective_id": self.objective_id,
            "scope_ref": self.scope_ref,
            "job_id": self.job_id,
            "category": self.category,
        }

    # -- DOM (§6/§14) ---------------------------------------------------

    def dom_sink_observation(self, trace: DomTrace, *,
                             material_available: bool = True,
                             marker: str = "") -> ob.VerificationObservation:
        """One DOM observation from a served-document trace."""
        base = self._base()
        where = self.where or ""
        under_input = str(trace.parameter or "")
        provenance = self.attestation(
            instrumentation_method=trace.instrumentation_method,
            instrumentation_version=trace.instrumentation_version,
            extra={"dom": trace.to_dict()})
        if not material_available:
            return ob.not_tested(
                signal=SIGNAL_DOM_SINK_NOT_TESTED, **base,
                not_observed="no served document was available to trace",
                what_happened="DOM source/sink trace requested",
                where=where, context="dom", marker=marker,
                provenance=provenance)
        if trace.produces_dom_sink_evidence:
            return ob.positive(
                signal=SIGNAL_DOM_SINK_IDENTIFIED,
                evidence_type=tx.DOM_SINK_IDENTIFIED, **base,
                observed=(f"DOM flow {trace.evidence} reaches a dangerous "
                          f"sink in the served document"),
                what_happened=("lineage-bound DOM source traced into a "
                               "dangerous sink (static analysis of the "
                               "served document)"),
                where=where, under_input=under_input, context="dom",
                marker=marker, provenance=provenance)
        if trace.flow in ("NO_SOURCE", "NO_SINK", "SOURCE_ONLY", "NO_LINEAGE"):
            return ob.negative(
                signal=SIGNAL_DOM_SINK_NOT_OBSERVED, **base,
                not_observed=(
                    f"served-document trace found no lineage-bound "
                    f"source→sink flow ({trace.reason or trace.flow})"),
                what_happened="DOM source/sink trace completed",
                where=where, under_input=under_input, context="dom",
                marker=marker, provenance=provenance)
        return ob.not_tested(
            signal=SIGNAL_DOM_SINK_NOT_TESTED, **base,
            not_observed=f"DOM trace inconclusive ({trace.reason})",
            what_happened="DOM source/sink trace inconclusive",
            where=where, context="dom", marker=marker, provenance=provenance)

    # -- execution (§18) ------------------------------------------------

    def execution_observation(self, attempt: AttemptResult, *,
                              marker: str = "",
                              sink: str = "",
                              session_id: str = "") -> ob.VerificationObservation:
        """One execution observation from a real attempt outcome."""
        base = self._base()
        provenance = self.attestation(
            instrumentation_method=attempt.instrumentation_method,
            instrumentation_version=attempt.instrumentation_version,
            session_id=session_id or attempt.session_id,
            extra={"attempt": attempt.to_dict()})
        where = self.where or ""
        if attempt.state == EXECUTION_OBSERVED:
            return ob.positive(
                signal=SIGNAL_PAYLOAD_EXECUTION,
                evidence_type=tx.PAYLOAD_EXECUTION, **base,
                observed=(f"controlled marker executed: {attempt.reason}"),
                what_happened=("authorized isolated execution observation "
                               "recorded the controlled marker executing"),
                where=where, context="dom", marker=marker,
                provenance=provenance)
        if attempt.state == DOM_SINK_OBSERVED:
            return ob.positive(
                signal=SIGNAL_DOM_SINK_IDENTIFIED,
                evidence_type=tx.DOM_SINK_IDENTIFIED, **base,
                observed=(f"the instrumented run reached a DOM sink: "
                          f"{attempt.reason}"),
                what_happened=("authorized isolated run observed the "
                               "controlled input reaching a DOM sink; no "
                               "execution was observed"),
                where=where, context="dom", marker=marker,
                provenance={**provenance, "sink": sink,
                            "execution_observed": False})
        if is_observed(attempt.state):
            return ob.negative(
                signal=SIGNAL_PAYLOAD_EXECUTION_NOT_OBSERVED, **base,
                not_observed=("the instrumented run reached the sink but no "
                              "controlled execution was observed"),
                what_happened="execution observed: none",
                where=where, context="dom", marker=marker,
                provenance=provenance)
        if attempt.negative_evidence:
            return ob.negative(
                signal=SIGNAL_PAYLOAD_EXECUTION_NOT_OBSERVED, **base,
                not_observed=(f"instrumented run observed no execution "
                              f"({attempt.reason})"),
                what_happened="execution observation completed",
                where=where, context="dom", marker=marker,
                provenance=provenance)
        if is_refusal(attempt.state):
            return ob.not_tested(
                signal=SIGNAL_PAYLOAD_EXECUTION_NOT_TESTED, **base,
                not_observed=(f"execution was not attempted: {attempt.state} "
                              f"({attempt.reason})"),
                what_happened="execution attempt refused",
                where=where, context="dom", marker=marker,
                provenance=provenance)
        return ob.not_tested(
            signal=SIGNAL_PAYLOAD_EXECUTION_NOT_TESTED, **base,
            not_observed=f"execution inconclusive ({attempt.state})",
            what_happened="execution inconclusive",
            where=where, context="dom", marker=marker, provenance=provenance)

    # -- exploitability (§9) --------------------------------------------

    def exploitability_observation(self, assessment: ExploitabilityAssessment,
                                   *, marker: str = ""
                                   ) -> ob.VerificationObservation:
        base = self._base()
        provenance = self.attestation(
            extra={"exploitability": assessment.to_dict()})
        where = self.where or ""
        if assessment.established:
            return ob.positive(
                signal=SIGNAL_EXPLOITABILITY_ESTABLISHED,
                evidence_type=tx.EXPLOITABILITY_ESTABLISHED, **base,
                observed=(f"controlled input executed in a security-relevant "
                          f"sink ({assessment.sink}) with an established "
                          f"impact condition"),
                what_happened="exploitability conditions satisfied",
                where=where, context="dom", marker=marker,
                provenance=provenance)
        return ob.negative(
            signal=SIGNAL_EXPLOITABILITY_NOT_ESTABLISHED, **base,
            not_observed=(f"exploitability not established "
                          f"({assessment.reason}); missing "
                          f"{','.join(assessment.missing) or 'none'}"),
            what_happened="exploitability assessed",
            where=where, context="dom", marker=marker, provenance=provenance)

    # -- result ---------------------------------------------------------

    @staticmethod
    def evidence_type_of(observation: ob.VerificationObservation) -> str:
        return str(observation.evidence_type or "")


def producer_for(action: Any, *, authorization_id: str = "",
                 where: str = "") -> DeepObservationProducer:
    """The producer bound to one verification action's identity."""
    return DeepObservationProducer(
        action_id=str(getattr(action, "action_id", "") or ""),
        candidate_id=str(getattr(action, "candidate_id", "") or ""),
        objective_id=str(getattr(action, "objective_id", "") or ""),
        scope_ref=str(getattr(action, "scope_ref", "") or ""),
        job_id=str(getattr(action, "job_id", "") or ""),
        authorization_id=authorization_id or str(
            getattr(action, "authorization_id", "") or ""),
        where=where or str(getattr(action, "target", "") or ""),
        category=str(getattr(action, "category", "") or "XSS"))
