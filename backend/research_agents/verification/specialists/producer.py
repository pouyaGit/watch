"""EPIC16 §14/§15 — the trusted observation producer for the new classes.

Every class observation is built here, from a classifier assessment, with
deterministic confidence and an explicit producer provenance stamp.  This is
the EPIC14 trust boundary applied to the new classes: a row can never upgrade
its own evidence type, and a confirmation-capable type may only be emitted
with this producer's attestation.

NOTHING here invents material: an observation exists only if the assessment
carries the corresponding state, and an unavailable lane yields NOT_TESTED —
never a negative and never a positive.
"""
from __future__ import annotations

from typing import Any, Iterable

from backend.research_agents.finding.integrity import taxonomy as tx
from backend.research_agents.verification import chains as chain_registry
from backend.research_agents.verification import observations as obs
from backend.research_agents.verification.specialists import classifiers as cl
from backend.research_agents.verification.specialists import base as sp

CLASS_PRODUCER_VERSION = "epic16-producer-1"

# ------------------------------------------------------------------- signals
SIGNAL_CORS_ORIGIN_NOT_TESTED = "cors_origin_not_tested"
SIGNAL_CORS_SUPPLIED = "cors_origin_supplied"
SIGNAL_CORS_ACAO_OBSERVED = "cors_acao_observed"
SIGNAL_CORS_ACAO_ABSENT = "cors_acao_absent"
SIGNAL_CORS_ARBITRARY_ACCEPTED = "cors_arbitrary_origin_accepted"
SIGNAL_CORS_ORIGIN_NOT_ACCEPTED = "cors_origin_not_accepted"
SIGNAL_CORS_CREDENTIALS_ALLOWED = "cors_credentials_allowed"
SIGNAL_CORS_CREDENTIALS_NOT_ALLOWED = "cors_credentials_not_allowed"
SIGNAL_CORS_SENSITIVE_AVAILABLE = "cors_sensitive_response_available"
SIGNAL_CORS_SENSITIVE_ABSENT = "cors_sensitive_response_absent"

SIGNAL_REDIRECT_INPUT = "redirect_input_identified"
SIGNAL_REDIRECT_RESPONSE = "redirect_response_observed"
SIGNAL_REDIRECT_EXTERNAL_ACCEPTED = "redirect_external_destination_accepted"
SIGNAL_REDIRECT_RELATIVE_ONLY = "redirect_relative_only"
SIGNAL_REDIRECT_OUT_OF_SCOPE = "redirect_external_destination_rejected"
SIGNAL_REDIRECT_UNSAFE_SCHEME = "redirect_unsafe_scheme_rejected"
SIGNAL_REDIRECT_NORMALIZED = "redirect_destination_normalized"
SIGNAL_REDIRECT_IGNORED = "redirect_parameter_ignored"
SIGNAL_REDIRECT_SAME_ORIGIN = "redirect_same_origin"
SIGNAL_REDIRECT_NO_LOCATION = "redirect_no_location_observed"
SIGNAL_REDIRECT_UNSAFE_DESTINATION = "redirect_unsafe_destination_rejected"

SIGNAL_SSRF_URL_PARAMETER = "ssrf_url_parameter"
SIGNAL_SSRF_POLICY = "ssrf_destination_policy_evaluated"
SIGNAL_SSRF_INTERNAL_REJECTED = "ssrf_internal_destination_rejected"
SIGNAL_SSRF_UNSAFE_SCHEME = "ssrf_unsafe_scheme_rejected"
SIGNAL_SSRF_METADATA_REJECTED = "ssrf_metadata_destination_rejected"
SIGNAL_SSRF_NO_REQUEST = "ssrf_server_request_absent"
SIGNAL_SSRF_SERVER_REQUEST = "ssrf_server_side_request_observed"

SIGNAL_IDOR_SECOND_CONTEXT = "idor_second_context_available"
SIGNAL_IDOR_NO_SECOND_CONTEXT = "idor_no_second_context"
SIGNAL_IDOR_ACCESS_DENIED = "idor_object_access_denied"

SIGNAL_CVE_PRODUCT = "cve_product_identified"
SIGNAL_CVE_VERSION = "cve_version_identified"
SIGNAL_CVE_APPLICABILITY = "cve_applicability_evidence"
SIGNAL_CVE_NOT_AFFECTED = "cve_version_not_affected"
SIGNAL_CVE_UNRESOLVED = "cve_applicability_unresolved"


class ClassObservationProducer:
    """Builds the observations for ONE vulnerability class (§14/§15)."""

    def __init__(self, vulnerability_class: str) -> None:
        self.vulnerability_class = str(vulnerability_class)
        self.producer_version = CLASS_PRODUCER_VERSION

    # ------------------------------------------------------------- helpers
    def _provenance(self, assessment: Any, extra: dict[str, Any] | None = None
                    ) -> dict[str, Any]:
        prov = {
            "producer": self.producer_version,
            "vulnerability_class": self.vulnerability_class,
            "classifier": getattr(assessment, "rule_version",
                                  cl.RULE_VERSION),
        }
        prov.update(extra or {})
        return prov

    def _pos(self, signal: str, evidence_type: str, assessment: Any, **kw: Any
             ) -> Any:
        return obs.positive(
            signal=signal, evidence_type=evidence_type,
            category=self.vulnerability_class,
            provenance=self._provenance(assessment, kw.pop("prov_extra", None)),
            **kw)

    def _neg(self, signal: str, assessment: Any, **kw: Any) -> Any:
        return obs.negative(
            signal=signal, category=self.vulnerability_class,
            provenance=self._provenance(assessment, kw.pop("prov_extra", None)),
            **kw)

    def _not_tested(self, signal: str, assessment: Any, **kw: Any) -> Any:
        # obs.not_tested() takes no request/response reference: an untested
        # check has no material to reference.
        for key in ("request_ref", "response_ref"):
            kw.pop(key, None)
        return obs.not_tested(
            signal=signal, category=self.vulnerability_class,
            provenance=self._provenance(assessment, kw.pop("prov_extra", None)),
            **kw)

    # --------------------------------------------------------------- build
    def build(self, assessment: Any, *, action_id: str, candidate_id: str,
              objective_id: str = "", scope_ref: str = "", where: str = "",
              marker: str = "", request_ref: str = "",
              response_ref: str = "") -> tuple[Any, ...]:
        """Deterministically turn an assessment into observations."""
        common = {
            "action_id": action_id, "candidate_id": candidate_id,
            "objective_id": objective_id, "scope_ref": scope_ref, "where": where,
            "marker": marker, "request_ref": request_ref,
            "response_ref": response_ref,
        }
        builder = {
            "CORS": self._build_cors,
            "OPEN_REDIRECT": self._build_redirect,
            "SSRF": self._build_ssrf,
            "IDOR": self._build_idor,
            "CVE_RESEARCH": self._build_cve,
        }.get(self.vulnerability_class)
        if builder is None:
            raise ValueError(
                f"no producer for class {self.vulnerability_class!r}")
        return tuple(builder(assessment, common))

    # ---------------------------------------------------------------- CORS
    def _build_cors(self, a: cl.CorsAssessment, c: dict[str, Any]) -> list[Any]:
        out: list[Any] = []
        detail = (f"acao_class={a.acao_class} acao={a.acao!r} "
                  f"acac={a.acac!r} accepted={a.origin_accepted} "
                  f"reasons={','.join(a.terminal_reasons)}")
        if a.refusal:
            out.append(self._not_tested(
                SIGNAL_CORS_ORIGIN_NOT_TESTED, a, not_observed=a.refusal,
                what_happened=f"no controlled Origin was classified: {a.refusal}",
                context=detail, **c))
            return out
        out.append(self._pos(
            SIGNAL_CORS_SUPPLIED, tx.CONTROLLED_INPUT_SENT, a,
            observed=f"supplied controlled Origin {a.supplied_origin}",
            what_happened="a controlled non-real Origin was supplied for "
                          "classification", under_input=a.supplied_origin,
            context=detail, **c))
        if a.acao_class == cl.ACAO_ABSENT:
            out.append(self._neg(
                SIGNAL_CORS_ACAO_ABSENT, a,
                not_observed="Access-Control-Allow-Origin",
                what_happened="the response carried no ACAO header",
                under_input=a.supplied_origin, context=detail, **c))
        else:
            out.append(self._pos(
                SIGNAL_CORS_ACAO_OBSERVED, tx.RESPONSE_OBSERVED, a,
                observed=f"Access-Control-Allow-Origin: {a.acao}",
                what_happened="a CORS response header was observed",
                under_input=a.supplied_origin, context=detail, **c))
        if a.origin_accepted:
            out.append(self._pos(
                SIGNAL_CORS_ARBITRARY_ACCEPTED, tx.OUTPUT_CONTEXT_IDENTIFIED,
                a, observed=f"origin accepted: {a.acao}",
                what_happened="the origin was accepted by the response",
                under_input=a.supplied_origin, context=detail, **c))
        else:
            out.append(self._neg(
                SIGNAL_CORS_ORIGIN_NOT_ACCEPTED, a,
                not_observed=f"acceptance of {a.supplied_origin}",
                what_happened="the response did not accept the supplied "
                              "origin", under_input=a.supplied_origin,
                context=detail, **c))
        if a.credentials_relevant:
            if a.credentials_allowed:
                out.append(self._pos(
                    SIGNAL_CORS_CREDENTIALS_ALLOWED, tx.PAYLOAD_EXECUTION, a,
                    observed="Access-Control-Allow-Credentials: true with an "
                             "accepted origin",
                    what_happened="the credentialed cross-origin read "
                                  "condition was observed",
                    under_input=a.supplied_origin, context=detail,
                    prov_extra={"stage_semantics":
                                "cors_credentialed_read_not_code_execution"},
                    **c))
            else:
                out.append(self._neg(
                    SIGNAL_CORS_CREDENTIALS_NOT_ALLOWED, a,
                    not_observed="credentialed cross-origin access",
                    what_happened="credentials were not allowed for the "
                                  "supplied origin",
                    under_input=a.supplied_origin, context=detail, **c))
        if a.sensitive_response_declared:
            if a.sensitive_accessible:
                out.append(self._pos(
                    SIGNAL_CORS_SENSITIVE_AVAILABLE, tx.IMPACT_ESTABLISHED, a,
                    observed="a sensitive response was declared accessible",
                    what_happened="the sensitive-response condition was "
                                  "observed", under_input=a.supplied_origin,
                    context=detail,
                    prov_extra={"impact_source": "declared_by_observation"},
                    **c))
            else:
                out.append(self._neg(
                    SIGNAL_CORS_SENSITIVE_ABSENT, a,
                    not_observed="an accessible sensitive response",
                    what_happened="no accessible sensitive response was "
                                  "established", under_input=a.supplied_origin,
                    context=detail, **c))
        return out

    # ------------------------------------------------------- OPEN REDIRECT
    def _build_redirect(self, a: cl.RedirectAssessment,
                        c: dict[str, Any]) -> list[Any]:
        out: list[Any] = []
        detail = (f"classification={a.classification} location={a.location!r} "
                  f"reasons={','.join(a.terminal_reasons)}")
        if a.refusal:
            out.append(self._not_tested(
                SIGNAL_REDIRECT_UNSAFE_DESTINATION, a,
                not_observed=a.refusal,
                what_happened=f"no redirect classification ran: {a.refusal}",
                context=detail, **c))
            return out
        out.append(self._pos(
            SIGNAL_REDIRECT_INPUT, tx.PARAMETER_OBSERVED, a,
            observed="a redirect input with a controlled destination",
            what_happened="a controlled destination was supplied for "
                          "classification", under_input=a.supplied_destination,
            context=detail, **c))
        if a.classification == cl.REDIRECT_NO_LOCATION:
            out.append(self._neg(
                SIGNAL_REDIRECT_NO_LOCATION, a, not_observed="Location header",
                what_happened="no Location header was observed",
                under_input=a.supplied_destination, context=detail, **c))
            return out
        out.append(self._pos(
            SIGNAL_REDIRECT_RESPONSE, tx.RESPONSE_OBSERVED, a,
            observed=f"Location: {a.location}",
            what_happened="a redirect response was observed",
            under_input=a.supplied_destination, context=detail, **c))
        if a.classification == cl.REDIRECT_EXTERNAL_ACCEPTED:
            out.append(self._pos(
                SIGNAL_REDIRECT_EXTERNAL_ACCEPTED, tx.PAYLOAD_EXECUTION, a,
                observed=f"the controlled destination controlled the target: "
                         f"{a.location}",
                what_happened="the controlled destination became the redirect "
                              "target", under_input=a.supplied_destination,
                context=detail, **c))
        elif a.classification == cl.REDIRECT_EXTERNAL_OUT_OF_SCOPE:
            out.append(self._neg(
                SIGNAL_REDIRECT_OUT_OF_SCOPE, a,
                not_observed="a controlled redirect target",
                what_happened="the redirect target was not controlled",
                under_input=a.supplied_destination, context=detail, **c))
        elif a.classification == cl.REDIRECT_UNSAFE_SCHEME:
            out.append(self._neg(
                SIGNAL_REDIRECT_UNSAFE_SCHEME, a,
                not_observed="a safe redirect scheme",
                what_happened="the redirect used an unsafe scheme",
                under_input=a.supplied_destination, context=detail, **c))
        elif a.classification == cl.REDIRECT_PARAMETER_IGNORED:
            out.append(self._neg(
                SIGNAL_REDIRECT_IGNORED, a,
                not_observed="a controlled redirect target",
                what_happened="the redirect input was ignored",
                under_input=a.supplied_destination, context=detail, **c))
        elif a.classification == cl.REDIRECT_DESTINATION_NORMALIZED:
            out.append(self._neg(
                SIGNAL_REDIRECT_NORMALIZED, a,
                not_observed="a controlled redirect target",
                what_happened="the destination was normalized to the same "
                              "origin", under_input=a.supplied_destination,
                context=detail, **c))
        elif a.classification == cl.REDIRECT_SAME_ORIGIN:
            out.append(self._neg(
                SIGNAL_REDIRECT_SAME_ORIGIN, a,
                not_observed="an external redirect target",
                what_happened="the redirect stayed on the same origin",
                under_input=a.supplied_destination, context=detail, **c))
        else:
            out.append(self._neg(
                SIGNAL_REDIRECT_RELATIVE_ONLY, a,
                not_observed="an absolute external redirect target",
                what_happened="the redirect target was relative",
                under_input=a.supplied_destination, context=detail, **c))
        return out

    # ---------------------------------------------------------------- SSRF
    def _build_ssrf(self, a: cl.SsrfAssessment, c: dict[str, Any]) -> list[Any]:
        out: list[Any] = []
        if a.url_parameter_present:
            out.append(self._pos(
                SIGNAL_SSRF_URL_PARAMETER, tx.PARAMETER_OBSERVED, a,
                observed="a URL-shaped parameter was observed",
                what_happened="a URL parameter is a hypothesis, not SSRF",
                **c))
        if a.policy is not None:
            detail = (f"decision={a.policy.decision} "
                      f"reasons={','.join(a.policy.reasons)}")
            out.append(self._pos(
                SIGNAL_SSRF_POLICY, tx.RESPONSE_OBSERVED, a,
                observed=f"destination policy decision {a.policy.decision}",
                what_happened="the destination was evaluated against the "
                              "policy (no probe was performed)",
                under_input=a.destination, context=detail, **c))
            if not a.policy.allowed:
                signal = (SIGNAL_SSRF_METADATA_REJECTED if a.policy.metadata_target
                          else SIGNAL_SSRF_UNSAFE_SCHEME if a.policy.unsafe_scheme
                          else SIGNAL_SSRF_INTERNAL_REJECTED)
                out.append(self._neg(
                    signal, a, not_observed="an allowed destination",
                    what_happened=f"the destination was rejected: "
                                  f"{a.policy.decision}",
                    under_input=a.destination, context=detail, **c))
        if a.active_verification == "CAPABILITY_UNAVAILABLE":
            out.append(self._not_tested(
                SIGNAL_SSRF_NO_REQUEST, a,
                not_observed="server-side request evidence",
                what_happened="no controlled callback capability exists in "
                              "this runtime: server-side request behaviour "
                              "cannot be established",
                under_input=a.destination, **c))
            return out
        if a.server_request_observed:
            out.append(self._pos(
                SIGNAL_SSRF_SERVER_REQUEST, tx.OUTPUT_CONTEXT_IDENTIFIED, a,
                observed="a server-side request reached the controlled "
                         "callback",
                what_happened="the server issued a request to the controlled "
                              "destination", under_input=a.destination, **c))
        else:
            out.append(self._neg(
                SIGNAL_SSRF_NO_REQUEST, a,
                not_observed="server-side request evidence",
                what_happened="no server-side request was observed",
                under_input=a.destination, **c))
        return out

    # ---------------------------------------------------------------- IDOR
    def _build_idor(self, a: cl.IdorCapability, c: dict[str, Any]) -> list[Any]:
        if a.object_reference_present:
            head: list[Any] = [self._pos(
                "idor_object_reference_pattern", tx.PARAMETER_OBSERVED, a,
                observed="an object reference was observed",
                what_happened="an object reference is a hypothesis, not IDOR",
                **c)]
        else:
            head = []
        if a.second_context_available:
            head.append(self._pos(
                SIGNAL_IDOR_SECOND_CONTEXT, tx.CONTROLLED_INPUT_SENT, a,
                observed="a second authorized identity is available",
                what_happened="a second context exists for the object", **c))
            return head
        head.append(self._not_tested(
            SIGNAL_IDOR_NO_SECOND_CONTEXT, a, not_observed=a.reason,
            what_happened="IDOR verification requires a second authorized "
                          "identity and object ownership semantics; this "
                          "runtime has neither, so no access was attempted",
            context=a.reason, **c))
        return head

    # --------------------------------------------------------- CVE research
    def _build_cve(self, a: cl.CveApplicability, c: dict[str, Any]) -> list[Any]:
        out: list[Any] = []
        if a.product_identified:
            out.append(self._pos(
                SIGNAL_CVE_PRODUCT, tx.RESPONSE_OBSERVED, a,
                observed=f"product: {a.observed_product}",
                what_happened="a product was observed", **c))
        if a.version_identified:
            out.append(self._pos(
                SIGNAL_CVE_VERSION, tx.RESPONSE_OBSERVED, a,
                observed=f"version: {a.observed_version}",
                what_happened="a version was observed", **c))
        detail = f"state={a.state} reasons={','.join(a.terminal_reasons)}"
        if a.state == cl.CVE_APPLICABILITY_CONFIRMED:
            out.append(self._pos(
                SIGNAL_CVE_APPLICABILITY, tx.KNOWLEDGE_REFERENCE, a,
                observed="the observed product/version is inside the "
                         "affected range",
                what_happened="applicability was established against a "
                              "declared affected range (a CVE match is not "
                              "exploitability)", context=detail, **c))
        elif a.state in (cl.CVE_VERSION_NOT_AFFECTED, cl.CVE_WRONG_PRODUCT):
            out.append(self._neg(
                SIGNAL_CVE_NOT_AFFECTED, a,
                not_observed="an affected version",
                what_happened=f"applicability was not established: {a.state}",
                context=detail, **c))
        else:
            out.append(self._not_tested(
                SIGNAL_CVE_UNRESOLVED, a, not_observed="applicability evidence",
                what_happened=f"applicability is unresolved: {a.state}",
                context=detail, **c))
        return out


def producer_for(vulnerability_class: str) -> ClassObservationProducer:
    """The producer for a class (an unknown class yields no producer)."""
    normalized = chain_registry.normalize_class(vulnerability_class)
    if normalized not in sp.SPECIALISTS:
        raise ValueError(f"no producer for vulnerability class "
                         f"{vulnerability_class!r}")
    return ClassObservationProducer(normalized)


__all__ = [
    "CLASS_PRODUCER_VERSION", "ClassObservationProducer",
    "SIGNAL_CORS_ACAO_ABSENT", "SIGNAL_CORS_ACAO_OBSERVED",
    "SIGNAL_CORS_ARBITRARY_ACCEPTED", "SIGNAL_CORS_CREDENTIALS_ALLOWED",
    "SIGNAL_CORS_CREDENTIALS_NOT_ALLOWED", "SIGNAL_CORS_ORIGIN_NOT_ACCEPTED",
    "SIGNAL_CORS_ORIGIN_NOT_TESTED", "SIGNAL_CORS_SENSITIVE_ABSENT",
    "SIGNAL_CORS_SENSITIVE_AVAILABLE", "SIGNAL_CORS_SUPPLIED",
    "SIGNAL_CVE_APPLICABILITY", "SIGNAL_CVE_NOT_AFFECTED", "SIGNAL_CVE_PRODUCT",
    "SIGNAL_CVE_UNRESOLVED", "SIGNAL_CVE_VERSION",
    "SIGNAL_IDOR_ACCESS_DENIED", "SIGNAL_IDOR_NO_SECOND_CONTEXT",
    "SIGNAL_IDOR_SECOND_CONTEXT", "SIGNAL_REDIRECT_EXTERNAL_ACCEPTED",
    "SIGNAL_REDIRECT_IGNORED", "SIGNAL_REDIRECT_INPUT",
    "SIGNAL_REDIRECT_NORMALIZED", "SIGNAL_REDIRECT_NO_LOCATION",
    "SIGNAL_REDIRECT_OUT_OF_SCOPE", "SIGNAL_REDIRECT_RELATIVE_ONLY",
    "SIGNAL_REDIRECT_RESPONSE", "SIGNAL_REDIRECT_SAME_ORIGIN",
    "SIGNAL_REDIRECT_UNSAFE_DESTINATION", "SIGNAL_REDIRECT_UNSAFE_SCHEME",
    "SIGNAL_SSRF_INTERNAL_REJECTED", "SIGNAL_SSRF_METADATA_REJECTED",
    "SIGNAL_SSRF_NO_REQUEST", "SIGNAL_SSRF_POLICY",
    "SIGNAL_SSRF_SERVER_REQUEST", "SIGNAL_SSRF_UNSAFE_SCHEME",
    "SIGNAL_SSRF_URL_PARAMETER", "producer_for",
]
