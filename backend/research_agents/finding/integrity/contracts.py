"""Verification evidence contracts (EPIC11 §3, §5, §6, §12, §13).

A contract states, deterministically, which evidence types may support
which claim for a vulnerability class, and which evidence is required
before the class may be called *confirmed*.  Claims and contracts are
plain data: no LLM output, no confidence score and no parameter name can
change what a claim requires.

Design constraints:
- ``confirmation_requires`` always includes stage-4 evidence
  (``PAYLOAD_EXECUTION`` / ``EXPLOITABILITY_ESTABLISHED``) plus an
  authorization confirmation.  Blind payload execution is NOT required to
  *describe* a candidate — it is required to *confirm* one, and no
  observation-only signal produced by the research runtime can ever
  satisfy it.
- Severity and impact are separate claims with their own required
  evidence (``IMPACT_ESTABLISHED``); a vulnerability class alone never
  establishes an impact (§13).
- Classes without a bespoke contract fall back to a conservative
  contract: surface observation may be claimed, confirmation may not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from backend.research_agents.finding.integrity import taxonomy as tx

CONTRACT_RULE_VERSION = "epic11-verification-contract-1"

# ------------------------------------------------------------- reason codes

R_INSUFFICIENT = "insufficient_evidence"
R_NO_EVIDENCE = "no_evidence"
R_UNCLASSIFIED_ONLY = "unclassified_evidence_only"
R_DUPLICATE_ONLY = "duplicate_evidence_only"
R_MISSING_REFLECTION = "missing_reflection_evidence"
R_MISSING_CONTROLLED = "missing_controlled_verification"
R_MISSING_OUTPUT_CONTEXT = "missing_output_context_evidence"
R_MISSING_DOM_SINK = "missing_dom_sink_evidence"
R_MISSING_EXPLOITABILITY = "missing_exploitability_evidence"
R_MISSING_PAYLOAD = "missing_payload_execution_evidence"
R_MISSING_IMPACT = "missing_impact_evidence"
R_MISSING_URL = "missing_url_observation"
R_MISSING_PARAMETER = "missing_parameter_observation"
R_MISSING_AUTHORIZATION = "missing_authorization_confirmation"

# evidence type -> the reason code used when that type is the missing one
_TYPE_REASON: dict[str, str] = {
    tx.REFLECTION_OBSERVED: R_MISSING_REFLECTION,
    tx.OUTPUT_CONTEXT_IDENTIFIED: R_MISSING_OUTPUT_CONTEXT,
    tx.DOM_SINK_IDENTIFIED: R_MISSING_DOM_SINK,
    tx.CONTROLLED_INPUT_SENT: R_MISSING_CONTROLLED,
    tx.PAYLOAD_EXECUTION: R_MISSING_PAYLOAD,
    tx.EXPLOITABILITY_ESTABLISHED: R_MISSING_EXPLOITABILITY,
    tx.IMPACT_ESTABLISHED: R_MISSING_IMPACT,
    tx.URL_OBSERVED: R_MISSING_URL,
    tx.PARAMETER_OBSERVED: R_MISSING_PARAMETER,
    tx.AUTHORIZATION_CONFIRMED: R_MISSING_AUTHORIZATION,
    tx.REQUEST_OBSERVED: R_MISSING_CONTROLLED,
    tx.RESPONSE_OBSERVED: R_MISSING_REFLECTION,
}

GATE_REASONS: tuple[str, ...] = (
    R_INSUFFICIENT, R_NO_EVIDENCE, R_UNCLASSIFIED_ONLY, R_DUPLICATE_ONLY,
    R_MISSING_REFLECTION, R_MISSING_CONTROLLED, R_MISSING_OUTPUT_CONTEXT,
    R_MISSING_DOM_SINK, R_MISSING_EXPLOITABILITY, R_MISSING_PAYLOAD,
    R_MISSING_IMPACT, R_MISSING_URL, R_MISSING_PARAMETER,
    R_MISSING_AUTHORIZATION,
)
# class-scoped aggregates are also legal (``insufficient_xss_evidence``)
GATE_REASON_PREFIX = "insufficient_"
GATE_REASON_SUFFIX = "_evidence"


def reason_for_type(evidence_type: str) -> str:
    return _TYPE_REASON.get(
        str(evidence_type or "").upper(),
        "missing_" + str(evidence_type or "evidence").strip().lower()
        + "_evidence")


def insufficient_reason(vulnerability_class: str) -> str:
    slug = "".join(ch for ch in str(vulnerability_class or "").lower()
                   if ch.isalnum() or ch == "_")
    return f"{GATE_REASON_PREFIX}{slug or 'class'}{GATE_REASON_SUFFIX}"


def is_known_gate_reason(reason: str) -> bool:
    text = str(reason or "")
    if text in GATE_REASONS:
        return True
    return (text.startswith(GATE_REASON_PREFIX)
            and text.endswith(GATE_REASON_SUFFIX))


# ------------------------------------------------------------------- specs

@dataclass(frozen=True)
class ClaimSpec:
    """One substantive security claim and the evidence it requires."""

    claim_type: str
    statement: str
    stage: int
    required_groups: tuple[tuple[str, ...], ...] = ()
    min_unique_observations: int = 1
    requires_authorization: bool = False
    impact_claim: bool = False

    @property
    def claim_id(self) -> str:
        return f"clm-{self.claim_type}"

    @property
    def required_evidence_types(self) -> tuple[str, ...]:
        out: list[str] = []
        for group in self.required_groups:
            for t in group:
                if t not in out:
                    out.append(t)
        return tuple(out)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_type": self.claim_type,
            "statement": self.statement,
            "stage": self.stage,
            "stage_label": tx.STAGE_LABELS.get(self.stage, "auxiliary"),
            "required_evidence_types": list(self.required_evidence_types),
            "required_groups": [list(g) for g in self.required_groups],
            "min_unique_observations": self.min_unique_observations,
            "requires_authorization": self.requires_authorization,
            "impact_claim": self.impact_claim,
        }


@dataclass(frozen=True)
class VulnerabilityContract:
    """The authoritative verification contract for one vulnerability class."""

    vulnerability_class: str
    claims: tuple[ClaimSpec, ...]
    confirmation_types: tuple[str, ...] = (
        tx.PAYLOAD_EXECUTION, tx.EXPLOITABILITY_ESTABLISHED)
    require_authorization_for_confirmation: bool = True
    rule_version: str = CONTRACT_RULE_VERSION
    limitations: tuple[str, ...] = (
        "claim support is derived from persisted evidence types, never "
        "from model confidence, parameter names or historical severity",
        "payload execution is required to CONFIRM; it is never required "
        "to describe an observed candidate",
    )

    @property
    def contract_id(self) -> str:
        return f"contract-{self.vulnerability_class.lower()}"

    def claim(self, claim_type: str) -> ClaimSpec | None:
        for spec in self.claims:
            if spec.claim_type == claim_type:
                return spec
        return None

    @property
    def confirmation_claim(self) -> ClaimSpec:
        spec = self.claim("vulnerability_confirmed")
        if spec is None:                        # pragma: no cover - guarded
            raise KeyError("contract has no confirmation claim")
        return spec

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "rule_version": self.rule_version,
            "vulnerability_class": self.vulnerability_class,
            "confirmation_types": list(self.confirmation_types),
            "require_authorization_for_confirmation":
                self.require_authorization_for_confirmation,
            "claims": [c.to_dict() for c in self.claims],
            "limitations": list(self.limitations),
        }


def _confirmation_spec(*, class_label: str, stage3_group: tuple[str, ...],
                       confirmation_types: tuple[str, ...],
                       include_impact: bool = False) -> ClaimSpec:
    groups: list[tuple[str, ...]] = [stage3_group, tuple(confirmation_types)]
    if include_impact:
        groups.append((tx.IMPACT_ESTABLISHED,))
    return ClaimSpec(
        claim_type="vulnerability_confirmed",
        statement=f"{class_label} confirmed by authorized exploitability "
                  f"evidence.",
        stage=tx.STAGE_EXPLOITABILITY,
        required_groups=tuple(groups),
        min_unique_observations=2,
        requires_authorization=True,
    )


XSS_STAGE3: tuple[str, ...] = (
    tx.REFLECTION_OBSERVED, tx.OUTPUT_CONTEXT_IDENTIFIED,
    tx.DOM_SINK_IDENTIFIED)

XSS = VulnerabilityContract(
    vulnerability_class="XSS",
    claims=(
        ClaimSpec("url_observed", "The target URL was observed.",
                  tx.STAGE_OBSERVED, ((tx.URL_OBSERVED,),)),
        ClaimSpec("parameter_observed",
                  "A parameter was observed on the target URL.",
                  tx.STAGE_OBSERVED, ((tx.PARAMETER_OBSERVED,),)),
        ClaimSpec("controlled_input_tested",
                  "Controlled input was sent to the observed parameter.",
                  tx.STAGE_CONTROLLED, ((tx.CONTROLLED_INPUT_SENT,),)),
        ClaimSpec("reflection_observed",
                  "The controlled input was reflected, or a relevant "
                  "sink/context was identified.",
                  tx.STAGE_REFLECTION, (XSS_STAGE3,)),
        ClaimSpec("output_context_unsafe",
                  "The reflected input lands in an unsafe output context.",
                  tx.STAGE_REFLECTION,
                  ((tx.OUTPUT_CONTEXT_IDENTIFIED, tx.DOM_SINK_IDENTIFIED),)),
        ClaimSpec("payload_execution",
                  "Payload execution was demonstrated within the "
                  "authorized scope.",
                  tx.STAGE_EXPLOITABILITY,
                  ((tx.PAYLOAD_EXECUTION, tx.EXPLOITABILITY_ESTABLISHED),),
                  requires_authorization=True),
        ClaimSpec("impact_established",
                  "An impact attributable to the vulnerability was "
                  "established.",
                  tx.STAGE_IMPACT, ((tx.IMPACT_ESTABLISHED,),),
                  impact_claim=True),
        ClaimSpec("authorized_testing",
                  "Testing occurred inside the recorded authorized scope.",
                  tx.STAGE_AUXILIARY, ((tx.AUTHORIZATION_CONFIRMED,),),
                  requires_authorization=True),
        _confirmation_spec(
            class_label="Reflected XSS",
            stage3_group=XSS_STAGE3,
            confirmation_types=(tx.PAYLOAD_EXECUTION,
                                tx.EXPLOITABILITY_ESTABLISHED),
        ),
    ),
)

SSRF = VulnerabilityContract(
    vulnerability_class="SSRF",
    claims=(
        ClaimSpec("url_observed", "The target URL was observed.",
                  tx.STAGE_OBSERVED, ((tx.URL_OBSERVED,),)),
        ClaimSpec("parameter_observed",
                  "A URL-accepting parameter was observed.",
                  tx.STAGE_OBSERVED, ((tx.PARAMETER_OBSERVED,),)),
        ClaimSpec("controlled_input_tested",
                  "Controlled input was sent to the observed parameter.",
                  tx.STAGE_CONTROLLED, ((tx.CONTROLLED_INPUT_SENT,),)),
        ClaimSpec("server_side_request_observed",
                  "A server-side request caused by controlled input was "
                  "observed.",
                  tx.STAGE_REFLECTION,
                  ((tx.RESPONSE_OBSERVED, tx.REFLECTION_OBSERVED),)),
        ClaimSpec("payload_execution",
                  "Exploitability of the server-side request was "
                  "demonstrated within the authorized scope.",
                  tx.STAGE_EXPLOITABILITY,
                  ((tx.EXPLOITABILITY_ESTABLISHED, tx.PAYLOAD_EXECUTION),),
                  requires_authorization=True),
        ClaimSpec("impact_established",
                  "An impact attributable to the vulnerability was "
                  "established.",
                  tx.STAGE_IMPACT, ((tx.IMPACT_ESTABLISHED,),),
                  impact_claim=True),
        ClaimSpec("authorized_testing",
                  "Testing occurred inside the recorded authorized scope.",
                  tx.STAGE_AUXILIARY, ((tx.AUTHORIZATION_CONFIRMED,),),
                  requires_authorization=True),
        _confirmation_spec(
            class_label="SSRF",
            stage3_group=(tx.RESPONSE_OBSERVED, tx.REFLECTION_OBSERVED),
            confirmation_types=(tx.EXPLOITABILITY_ESTABLISHED,
                                tx.PAYLOAD_EXECUTION),
        ),
    ),
)

SQLI = VulnerabilityContract(
    vulnerability_class="SQLI",
    claims=(
        ClaimSpec("url_observed", "The target URL was observed.",
                  tx.STAGE_OBSERVED, ((tx.URL_OBSERVED,),)),
        ClaimSpec("parameter_observed",
                  "A parameter was observed on the target URL.",
                  tx.STAGE_OBSERVED, ((tx.PARAMETER_OBSERVED,),)),
        ClaimSpec("error_style_response_observed",
                  "An error-style response was observed.",
                  tx.STAGE_OBSERVED, ((tx.RESPONSE_OBSERVED,),)),
        ClaimSpec("controlled_input_tested",
                  "Controlled input was sent to the observed parameter.",
                  tx.STAGE_CONTROLLED, ((tx.CONTROLLED_INPUT_SENT,),)),
        ClaimSpec("injection_confirmed_behavior",
                  "Response behavior consistent with injection was "
                  "observed under controlled input.",
                  tx.STAGE_REFLECTION,
                  ((tx.RESPONSE_OBSERVED, tx.REFLECTION_OBSERVED),)),
        ClaimSpec("payload_execution",
                  "Exploitability of the injection was demonstrated "
                  "within the authorized scope.",
                  tx.STAGE_EXPLOITABILITY,
                  ((tx.EXPLOITABILITY_ESTABLISHED, tx.PAYLOAD_EXECUTION),),
                  requires_authorization=True),
        ClaimSpec("impact_established",
                  "An impact attributable to the vulnerability was "
                  "established.",
                  tx.STAGE_IMPACT, ((tx.IMPACT_ESTABLISHED,),),
                  impact_claim=True),
        ClaimSpec("authorized_testing",
                  "Testing occurred inside the recorded authorized scope.",
                  tx.STAGE_AUXILIARY, ((tx.AUTHORIZATION_CONFIRMED,),),
                  requires_authorization=True),
        _confirmation_spec(
            class_label="SQL injection",
            stage3_group=(tx.RESPONSE_OBSERVED, tx.REFLECTION_OBSERVED),
            confirmation_types=(tx.EXPLOITABILITY_ESTABLISHED,
                                tx.PAYLOAD_EXECUTION),
        ),
    ),
)

IDOR = VulnerabilityContract(
    vulnerability_class="IDOR",
    claims=(
        ClaimSpec("url_observed", "The target URL was observed.",
                  tx.STAGE_OBSERVED, ((tx.URL_OBSERVED,),)),
        ClaimSpec("object_reference_observed",
                  "An object reference was observed on the target.",
                  tx.STAGE_OBSERVED, ((tx.PARAMETER_OBSERVED,),)),
        ClaimSpec("controlled_input_tested",
                  "Controlled input was sent to the observed reference.",
                  tx.STAGE_CONTROLLED, ((tx.CONTROLLED_INPUT_SENT,),)),
        ClaimSpec("cross_object_access_observed",
                  "Access to an object outside the caller's own "
                  "authorization was observed.",
                  tx.STAGE_REFLECTION, ((tx.RESPONSE_OBSERVED,),)),
        ClaimSpec("payload_execution",
                  "Exploitability of the access control gap was "
                  "demonstrated within the authorized scope.",
                  tx.STAGE_EXPLOITABILITY,
                  ((tx.EXPLOITABILITY_ESTABLISHED, tx.PAYLOAD_EXECUTION),),
                  requires_authorization=True),
        ClaimSpec("impact_established",
                  "An impact attributable to the vulnerability was "
                  "established.",
                  tx.STAGE_IMPACT, ((tx.IMPACT_ESTABLISHED,),),
                  impact_claim=True),
        ClaimSpec("authorized_testing",
                  "Testing occurred inside the recorded authorized scope.",
                  tx.STAGE_AUXILIARY, ((tx.AUTHORIZATION_CONFIRMED,),),
                  requires_authorization=True),
        _confirmation_spec(
            class_label="IDOR/BOLA",
            stage3_group=(tx.RESPONSE_OBSERVED,),
            confirmation_types=(tx.EXPLOITABILITY_ESTABLISHED,
                                tx.PAYLOAD_EXECUTION),
        ),
    ),
)

JWT = VulnerabilityContract(
    vulnerability_class="JWT",
    claims=(
        ClaimSpec("url_observed", "The target URL was observed.",
                  tx.STAGE_OBSERVED, ((tx.URL_OBSERVED,),)),
        ClaimSpec("token_structure_observed",
                  "A JWT-shaped token was observed on the target.",
                  tx.STAGE_OBSERVED, ((tx.RESPONSE_OBSERVED,),)),
        ClaimSpec("controlled_input_tested",
                  "Controlled input was sent with a modified token.",
                  tx.STAGE_CONTROLLED, ((tx.CONTROLLED_INPUT_SENT,),)),
        ClaimSpec("token_acceptance_observed",
                  "Acceptance of a modified/forged token was observed.",
                  tx.STAGE_REFLECTION, ((tx.RESPONSE_OBSERVED,),)),
        ClaimSpec("payload_execution",
                  "Exploitability of the token handling was demonstrated "
                  "within the authorized scope.",
                  tx.STAGE_EXPLOITABILITY,
                  ((tx.EXPLOITABILITY_ESTABLISHED, tx.PAYLOAD_EXECUTION),),
                  requires_authorization=True),
        ClaimSpec("impact_established",
                  "An impact attributable to the vulnerability was "
                  "established.",
                  tx.STAGE_IMPACT, ((tx.IMPACT_ESTABLISHED,),),
                  impact_claim=True),
        ClaimSpec("authorized_testing",
                  "Testing occurred inside the recorded authorized scope.",
                  tx.STAGE_AUXILIARY, ((tx.AUTHORIZATION_CONFIRMED,),),
                  requires_authorization=True),
        _confirmation_spec(
            class_label="JWT weakness",
            stage3_group=(tx.RESPONSE_OBSERVED,),
            confirmation_types=(tx.EXPLOITABILITY_ESTABLISHED,
                                tx.PAYLOAD_EXECUTION),
        ),
    ),
)

OAUTH = VulnerabilityContract(
    vulnerability_class="OAUTH",
    claims=(
        ClaimSpec("url_observed", "The target URL was observed.",
                  tx.STAGE_OBSERVED, ((tx.URL_OBSERVED,),)),
        ClaimSpec("authorization_endpoint_observed",
                  "An OAuth-style authorization endpoint was observed.",
                  tx.STAGE_OBSERVED, ((tx.URL_OBSERVED,),)),
        ClaimSpec("controlled_input_tested",
                  "A controlled authorization flow request was performed.",
                  tx.STAGE_CONTROLLED, ((tx.CONTROLLED_INPUT_SENT,),)),
        ClaimSpec("flow_weakness_observed",
                  "Flow behavior inconsistent with the specification was "
                  "observed.",
                  tx.STAGE_REFLECTION, ((tx.RESPONSE_OBSERVED,),)),
        ClaimSpec("payload_execution",
                  "Exploitability of the flow weakness was demonstrated "
                  "within the authorized scope.",
                  tx.STAGE_EXPLOITABILITY,
                  ((tx.EXPLOITABILITY_ESTABLISHED, tx.PAYLOAD_EXECUTION),),
                  requires_authorization=True),
        ClaimSpec("impact_established",
                  "An impact attributable to the vulnerability was "
                  "established.",
                  tx.STAGE_IMPACT, ((tx.IMPACT_ESTABLISHED,),),
                  impact_claim=True),
        ClaimSpec("authorized_testing",
                  "Testing occurred inside the recorded authorized scope.",
                  tx.STAGE_AUXILIARY, ((tx.AUTHORIZATION_CONFIRMED,),),
                  requires_authorization=True),
        _confirmation_spec(
            class_label="OAuth flow weakness",
            stage3_group=(tx.RESPONSE_OBSERVED,),
            confirmation_types=(tx.EXPLOITABILITY_ESTABLISHED,
                                tx.PAYLOAD_EXECUTION),
        ),
    ),
)

RECON = VulnerabilityContract(
    vulnerability_class="RECON",
    claims=(
        ClaimSpec("url_observed", "Surface rows were observed for the "
                  "target.", tx.STAGE_OBSERVED, ((tx.URL_OBSERVED,),)),
        ClaimSpec("authorized_testing",
                  "Collection occurred inside the recorded authorized "
                  "scope.", tx.STAGE_AUXILIARY,
                  ((tx.AUTHORIZATION_CONFIRMED,),),
                  requires_authorization=True),
    ),
    require_authorization_for_confirmation=False,
)

CVE_RESEARCH = VulnerabilityContract(
    vulnerability_class="CVE_RESEARCH",
    claims=(
        ClaimSpec("technology_observed",
                  "A technology fingerprint was observed for the target.",
                  tx.STAGE_OBSERVED, ((tx.RESPONSE_OBSERVED,),)),
        ClaimSpec("knowledge_correlation",
                  "A knowledge-base record was correlated with the "
                  "target.",
                  tx.STAGE_OBSERVED, ((tx.KNOWLEDGE_REFERENCE,),)),
        ClaimSpec("authorized_testing",
                  "Correlation stayed inside the recorded authorized "
                  "scope.", tx.STAGE_AUXILIARY,
                  ((tx.AUTHORIZATION_CONFIRMED,),),
                  requires_authorization=True),
    ),
    require_authorization_for_confirmation=False,
)

# Conservative fallback: an unknown class may be DESCRIBED, never CONFIRMED.
GENERIC = VulnerabilityContract(
    vulnerability_class="GENERIC",
    claims=(
        ClaimSpec("observation_recorded",
                  "An authorized observation was recorded for the target.",
                  tx.STAGE_OBSERVED,
                  ((tx.URL_OBSERVED, tx.PARAMETER_OBSERVED,
                    tx.RESPONSE_OBSERVED, tx.REQUEST_OBSERVED),)),
        ClaimSpec("controlled_input_tested",
                  "Controlled input was sent to the observed surface.",
                  tx.STAGE_CONTROLLED, ((tx.CONTROLLED_INPUT_SENT,),)),
        ClaimSpec("impact_established",
                  "An impact attributable to the vulnerability was "
                  "established.",
                  tx.STAGE_IMPACT, ((tx.IMPACT_ESTABLISHED,),),
                  impact_claim=True),
        ClaimSpec("authorized_testing",
                  "Testing occurred inside the recorded authorized scope.",
                  tx.STAGE_AUXILIARY, ((tx.AUTHORIZATION_CONFIRMED,),),
                  requires_authorization=True),
        _confirmation_spec(
            class_label="Vulnerability",
            stage3_group=(tx.REFLECTION_OBSERVED,
                          tx.OUTPUT_CONTEXT_IDENTIFIED,
                          tx.DOM_SINK_IDENTIFIED, tx.RESPONSE_OBSERVED),
            confirmation_types=(tx.PAYLOAD_EXECUTION,
                                tx.EXPLOITABILITY_ESTABLISHED),
        ),
    ),
)

CONTRACTS: dict[str, VulnerabilityContract] = {
    "XSS": XSS, "SSRF": SSRF, "SQLI": SQLI, "IDOR": IDOR, "JWT": JWT,
    "OAUTH": OAUTH, "RECON": RECON, "CVE_RESEARCH": CVE_RESEARCH,
}


def contract_for(vulnerability_class: Any) -> VulnerabilityContract:
    """Contract lookup — unknown classes get the conservative fallback."""
    key = str(vulnerability_class or "").strip().upper()
    return CONTRACTS.get(key, GENERIC)


def contract_catalog() -> list[dict[str, Any]]:
    out = [CONTRACTS[k].to_dict() for k in sorted(CONTRACTS)]
    out.append(GENERIC.to_dict())
    return out


# --------------------------------------------------- authorization holder

@dataclass(frozen=True)
class AuthorizationContext:
    """Recorded authorization lineage for a candidate/verification."""

    scope_ref: str = ""
    authorization_ref: str = ""
    authorization_ids: tuple[str, ...] = ()
    execution_mode: str = ""
    confirmed: bool = False
    provenance: dict[str, Any] = field(default_factory=dict)
    rule_version: str = CONTRACT_RULE_VERSION

    @property
    def present(self) -> bool:
        return bool(self.scope_ref or self.authorization_ref
                    or self.authorization_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_ref": self.scope_ref,
            "authorization_ref": self.authorization_ref,
            "authorization_ids": list(self.authorization_ids),
            "execution_mode": self.execution_mode,
            "confirmed": self.confirmed,
            "present": self.present,
            "provenance": dict(self.provenance),
            "rule_version": self.rule_version,
        }


__all__ = [
    "AuthorizationContext", "CONTRACTS", "CONTRACT_RULE_VERSION",
    "CVE_RESEARCH", "GATE_REASONS", "GENERIC", "IDOR", "JWT", "OAUTH",
    "RECON", "SQLI", "SSRF", "XSS", "XSS_STAGE3", "ClaimSpec",
    "VulnerabilityContract", "contract_catalog", "contract_for",
    "insufficient_reason", "is_known_gate_reason", "reason_for_type",
]
