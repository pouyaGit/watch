"""backend/research_agents/capabilities.py — Phase 4 specialist capabilities.

One explicit capability definition per registered specialist (the eight
canonical categories declared by the engine's specialist registry in
``ai.knowledge``).  The
runtime refuses to execute a job whose category has no capability here, so
these definitions — not the static registry — are what bounds execution.

Every definition is data, not code: identity, specialization, mission
types, required inputs, allowed observation types, analysis strategy,
evidence requirements, output schema, confidence semantics, case-creation
conditions, knowledge requirements and unsupported operations.  Nothing in
this module executes, contacts a target, or fabricates capability the
deployed system does not have.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CAPABILITIES_RULE_VERSION = "agent-runtime-v1-capabilities"

# The non-negotiable bans from the Epic, in force for every specialist.
UNIVERSAL_UNSUPPORTED: tuple[str, ...] = (
    "arbitrary internet requests",
    "arbitrary HTTP from an LLM",
    "exploit execution",
    "authentication bypass",
    "credential attacks",
    "destructive actions",
    "uncontrolled fuzzing",
    "arbitrary shell execution",
    "arbitrary LLM-generated code execution",
    "direct specialist-to-target HTTP outside the existing execution boundary",
)

CONFIDENCE_SEMANTICS: dict[str, str] = {
    "low": "structural signal only — never sufficient for a case",
    "medium": "corroborated observation pattern — evidence may be recorded, "
              "case still requires the configured evidence threshold",
    "high": "multiple independent authorized observations agree — required "
            "before case creation is even considered",
    "insufficient": "available evidence does not support a finding; the "
                    "result reports blockers instead of a conclusion",
}


@dataclass(frozen=True)
class EvidenceRequirements:
    """What must exist before a case may be created.

    ``signal_evidence_any_of`` (EPIC11) is the claim-grade requirement: at
    least one NON-DUPLICATE evidence row of one of these taxonomy types
    must exist.  It closes the hole where N rows of raw parameter
    inventory satisfied "evidence exists" and were read as proof of a
    vulnerability.  Empty tuple = no claim-grade requirement (only the
    structural checks apply) — never used to *confirm* anything.
    """

    min_evidence_refs: int = 2
    required_types: tuple[str, ...] = ("observation",)
    require_high_confidence: bool = True
    signal_evidence_any_of: tuple[str, ...] = ()


@dataclass(frozen=True)
class SpecialistCapability:
    category: str
    agent_id: str
    agent_name: str
    specialization: str
    mission_types: tuple[str, ...]
    required_inputs: tuple[str, ...]
    allowed_observation_types: tuple[str, ...]
    analysis_strategy: tuple[str, ...]
    evidence_requirements: EvidenceRequirements
    output_schema: tuple[str, ...]
    case_creation_conditions: tuple[str, ...]
    knowledge_requirements: tuple[str, ...]
    unsupported_operations: tuple[str, ...] = field(
        default=UNIVERSAL_UNSUPPORTED
    )
    # Phase 4 edge: extra bounded knowledge/recommendation query hints
    # for the shared intelligence layer (specialist-specific, declared).
    intelligence_hints: tuple[str, ...] = field(default=())

    @property
    def identity(self) -> dict[str, str]:
        return {
            "category": self.category,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_version": CAPABILITIES_RULE_VERSION,
            "identity": dict(self.identity),
            "specialization": self.specialization,
            "mission_types": list(self.mission_types),
            "required_inputs": list(self.required_inputs),
            "allowed_observation_types": list(self.allowed_observation_types),
            "analysis_strategy": list(self.analysis_strategy),
            "evidence_requirements": {
                "min_evidence_refs": self.evidence_requirements.min_evidence_refs,
                "required_types": list(self.evidence_requirements.required_types),
                "require_high_confidence":
                    self.evidence_requirements.require_high_confidence,
            },
            "output_schema": list(self.output_schema),
            "confidence_semantics": dict(CONFIDENCE_SEMANTICS),
            "case_creation_conditions": list(self.case_creation_conditions),
            "knowledge_requirements": list(self.knowledge_requirements),
            "unsupported_operations": list(self.unsupported_operations),
            "intelligence_hints": list(self.intelligence_hints),
        }


OUTPUT_SCHEMA: tuple[str, ...] = (
    "summary",
    "signals",
    "hypotheses",
    "confidence",
    "insufficient_evidence",
    "blockers",
    "evidence_candidates",
)

# --- the eight registered specialists -------------------------------------
# agent_id / agent_name values mirror the engine specialist registry in
# ai.knowledge (probed live); categories mirror CANONICAL_SPECIALIST_ORDER.

_CAPABILITIES: tuple[SpecialistCapability, ...] = (
    SpecialistCapability(
        category="XSS",
        agent_id="sa-c6a83f4938d64172",
        agent_name="xss-agent",
        specialization="reflected/stored cross-site scripting research over "
                       "authorized Watch HTTP observations",
        mission_types=("reflected-input-review", "parameter-inventory"),
        required_inputs=("subdomain", "observation-set"),
        allowed_observation_types=("http-rows", "url-rows", "parameter-rows"),
        analysis_strategy=(
            "inventory parameters from stored HTTP/URL rows",
            "mark reflection-capable inputs as signals only",
            "never send payloads; never execute anything",
        ),
        evidence_requirements=EvidenceRequirements(
            min_evidence_refs=2,
            required_types=("observation",),
            require_high_confidence=True,
            signal_evidence_any_of=("REFLECTION_OBSERVED", "OUTPUT_CONTEXT_IDENTIFIED", "DOM_SINK_IDENTIFIED"),
        ),
        output_schema=OUTPUT_SCHEMA,
        case_creation_conditions=(
            "at least two independent authorized observations",
            "high confidence from corroborated patterns",
            "a hypothesis that names a concrete endpoint and parameter",
        ),
        knowledge_requirements=("XSS", "cross-site scripting", "reflection"),
        intelligence_hints=("reflection", "dom", "stored"),
    ),
    SpecialistCapability(
        category="SSRF",
        agent_id="sa-0f1608cf66b289b0",
        agent_name="ssrf-agent",
        specialization="server-side request forgery surface review over "
                       "authorized Watch endpoint observations",
        mission_types=("url-parameter-review",),
        required_inputs=("subdomain", "observation-set"),
        allowed_observation_types=("http-rows", "endpoint-rows"),
        analysis_strategy=(
            "identify parameters that accept URLs/hosts",
            "map them against stored endpoint rows",
            "no outbound requests of any kind",
        ),
        evidence_requirements=EvidenceRequirements(
            min_evidence_refs=2,
            required_types=("observation",),
            require_high_confidence=True,
            signal_evidence_any_of=("RESPONSE_OBSERVED", "REFLECTION_OBSERVED"),
        ),
        output_schema=OUTPUT_SCHEMA,
        case_creation_conditions=(
            "two or more URL-accepting parameters on distinct endpoints",
            "high confidence",
        ),
        knowledge_requirements=("SSRF", "server-side request forgery"),
    ),
    SpecialistCapability(
        category="SQLI",
        agent_id="sa-3b942dd4051ba515",
        agent_name="sqli-agent",
        specialization="SQL-injection structural review over authorized "
                       "Watch parameter observations",
        mission_types=("parameter-structure-review",),
        required_inputs=("subdomain", "observation-set"),
        allowed_observation_types=("http-rows", "parameter-rows"),
        analysis_strategy=(
            "inventory numeric/identity parameters from stored rows",
            "flag error-style responses recorded in observations",
            "never send injection probes",
        ),
        evidence_requirements=EvidenceRequirements(
            min_evidence_refs=2,
            required_types=("observation",),
            require_high_confidence=True,
            signal_evidence_any_of=("RESPONSE_OBSERVED", "REFLECTION_OBSERVED"),
        ),
        output_schema=OUTPUT_SCHEMA,
        case_creation_conditions=(
            "stored observations show DB-style error signatures",
            "high confidence across two endpoints",
        ),
        knowledge_requirements=("SQL injection", "SQLI"),
    ),
    SpecialistCapability(
        category="IDOR",
        agent_id="sa-b28f17b6cfc6e46d",
        agent_name="idor-bola-specialist",
        specialization="IDOR/BOLA object-reference review over authorized "
                       "Watch endpoint observations",
        mission_types=("object-reference-review",),
        required_inputs=("subdomain", "observation-set"),
        allowed_observation_types=("endpoint-rows", "url-rows"),
        analysis_strategy=(
            "detect id-like path/query segments in stored endpoints",
            "map object references per endpoint; no access attempts",
        ),
        evidence_requirements=EvidenceRequirements(
            min_evidence_refs=2,
            required_types=("observation",),
            require_high_confidence=True,
            signal_evidence_any_of=("RESPONSE_OBSERVED",),
        ),
        output_schema=OUTPUT_SCHEMA,
        case_creation_conditions=(
            "id-pattern endpoints on two or more routes",
            "high confidence",
        ),
        knowledge_requirements=("IDOR", "BOLA", "object-level authorization"),
    ),
    SpecialistCapability(
        category="JWT",
        agent_id="sa-3861adc030feb742",
        agent_name="jwt-authentication-specialist",
        specialization="JWT/authentication structure review over authorized "
                       "Watch observations",
        mission_types=("token-structure-review",),
        required_inputs=("subdomain", "observation-set"),
        allowed_observation_types=("http-rows", "header-rows"),
        analysis_strategy=(
            "detect JWT-shaped tokens recorded in stored observations",
            "never crack, forge, or replay tokens",
        ),
        evidence_requirements=EvidenceRequirements(
            min_evidence_refs=2,
            required_types=("observation",),
            require_high_confidence=True,
            signal_evidence_any_of=("RESPONSE_OBSERVED",),
        ),
        output_schema=OUTPUT_SCHEMA,
        case_creation_conditions=(
            "token structures recorded in two independent observations",
            "high confidence",
        ),
        knowledge_requirements=("JWT", "authentication"),
    ),
    SpecialistCapability(
        category="OAUTH",
        agent_id="sa-5fb80d53098310da",
        agent_name="oauth-specialist",
        specialization="OAuth flow configuration review over authorized "
                       "Watch observations",
        mission_types=("flow-configuration-review",),
        required_inputs=("subdomain", "observation-set"),
        allowed_observation_types=("http-rows", "endpoint-rows"),
        analysis_strategy=(
            "identify OAuth-ish endpoints in stored rows",
            "no redirect following, no flow initiation",
        ),
        evidence_requirements=EvidenceRequirements(
            min_evidence_refs=2,
            required_types=("observation",),
            require_high_confidence=True,
            signal_evidence_any_of=("RESPONSE_OBSERVED",),
        ),
        output_schema=OUTPUT_SCHEMA,
        case_creation_conditions=(
            "oauth endpoints in two independent observations",
            "high confidence",
        ),
        knowledge_requirements=("OAuth", "redirect"),
    ),
    SpecialistCapability(
        category="RECON",
        agent_id="sa-d790ba468bf026dd",
        agent_name="api-security-specialist",
        specialization="API-surface reconnaissance over authorized Watch "
                       "stored recon data",
        mission_types=("api-surface-summary", "fresh-http-review"),
        required_inputs=("program",),
        allowed_observation_types=("http-rows", "endpoint-rows", "url-rows"),
        analysis_strategy=(
            "summarize stored HTTP/endpoint surface for the program",
            "read-only aggregation; no probing",
        ),
        evidence_requirements=EvidenceRequirements(
            min_evidence_refs=1,
            required_types=("observation",),
            require_high_confidence=False,
            signal_evidence_any_of=("URL_OBSERVED",),
        ),
        output_schema=OUTPUT_SCHEMA,
        case_creation_conditions=(
            "surface anomalies recorded in stored rows",
        ),
        knowledge_requirements=("recon", "API security"),
    ),
    SpecialistCapability(
        category="CVE_RESEARCH",
        agent_id="sa-1eaca0a7a4503146",
        agent_name="cve-research-specialist",
        specialization="CVE correlation research against stored technology "
                       "observations and the knowledge base",
        mission_types=("technology-correlation",),
        required_inputs=("observation-set",),
        allowed_observation_types=("http-rows", "kb-rows"),
        analysis_strategy=(
            "match stored technology signals against knowledge-base CVEs",
            "no exploitation, no version probing",
        ),
        evidence_requirements=EvidenceRequirements(
            min_evidence_refs=2,
            required_types=("observation", "knowledge"),
            require_high_confidence=True,
            signal_evidence_any_of=("RESPONSE_OBSERVED",),
        ),
        output_schema=OUTPUT_SCHEMA,
        case_creation_conditions=(
            "technology match plus a knowledge-base CVE reference",
            "high confidence",
        ),
        knowledge_requirements=("CVE", "technology"),
        intelligence_hints=("version", "technology", "correlation"),
    ),
)

CAPABILITIES: dict[str, SpecialistCapability] = {
    cap.category: cap for cap in _CAPABILITIES
}


def capability_for(category: str) -> SpecialistCapability | None:
    """Capability for a canonical category (case-insensitive), or None."""

    return CAPABILITIES.get(str(category or "").strip().upper())


def validate_capabilities() -> list[str]:
    """Structural validation; returns problems (empty list == valid)."""

    problems: list[str] = []
    for cat, cap in CAPABILITIES.items():
        if not cap.agent_id or not cap.agent_name:
            problems.append(f"{cat}: missing identity")
        for name in ("specialization", "output_schema", "mission_types",
                     "required_inputs", "allowed_observation_types",
                     "analysis_strategy", "case_creation_conditions",
                     "knowledge_requirements"):
            value = getattr(cap, name)
            if not value:
                problems.append(f"{cat}: empty {name}")
        if cap.evidence_requirements.min_evidence_refs < 1:
            problems.append(f"{cat}: evidence threshold below 1")
        if any(b in cap.unsupported_operations for b in UNIVERSAL_UNSUPPORTED
               if b not in UNIVERSAL_UNSUPPORTED):
            problems.append(f"{cat}: unsupported_operations corrupted")
        for banned in ("arbitrary shell execution",
                       "exploit execution"):
            if banned not in cap.unsupported_operations:
                problems.append(f"{cat}: missing ban '{banned}'")
        if len(cap.output_schema) != len(set(cap.output_schema)):
            problems.append(f"{cat}: duplicate output schema fields")
    if len(CAPABILITIES) != 8:
        problems.append(f"expected 8 capabilities, found {len(CAPABILITIES)}")
    return problems


__all__ = [
    "CAPABILITIES",
    "CAPABILITIES_RULE_VERSION",
    "CONFIDENCE_SEMANTICS",
    "EvidenceRequirements",
    "SpecialistCapability",
    "UNIVERSAL_UNSUPPORTED",
    "capability_for",
    "validate_capabilities",
]
