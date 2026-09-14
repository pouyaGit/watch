"""Stage R45.5 deterministic LLM advisory exporter (pure engine).

Runs the advisory pipeline over structured deterministic research artifacts:

    R42 evaluation / R43 collaboration / R44 learning signals
        -> advisory input (R45.1)
        -> advisory policy + request (R45.2, R45.4)
        -> provider response (R45.3, mock only)
        -> response validation (R45.6)
        -> advisory result (R45.5)

Hard boundaries encoded here:

- Advisory only: the exporter produces human-readable explanations. It does
  not execute anything, does not confirm vulnerabilities, does not generate
  payloads and does not plan attacks.
- Reject, never sanitize: unsafe provider output is rejected, its content is
  excluded from the result and the validator diagnostics are preserved.
- The deterministic layers stay authoritative: R42/R43/R44 outputs are
  consumed, never recomputed.
- Deterministic: repeated export of the same input is byte-identical.
- Pure and offline: no I/O, no network, no provider call for the mock
  provider, no LLM, no Mongo, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.llm_advisory_input import build_llm_advisory_input
from ai.knowledge.llm_advisory_request_builder import (
    build_llm_advisory_request,
)
from ai.knowledge.llm_advisory_validator import (
    advisory_safety_state,
    validate_advisory_response,
    validate_advisory_result,
)
from ai.knowledge.llm_provider import get_advisory_provider
from ai.schemas.llm_advisory_result import (
    ADVISORY_RESULT_LIMITATIONS,
    PROVENANCE_COMPLETE,
    PROVENANCE_PARTIAL,
    PROVENANCE_UNKNOWN,
    VALIDATION_PASS,
    VALIDATION_REJECTED,
    LLM_ADVISORY_RESULT_RULE_VERSION,
    LLMAdvisoryResultPlan,
    llm_advisory_result_plan_projection,
)
from ai.schemas.llm_provider import PROVIDER_KIND_MOCK

LLM_ADVISORY_EXPORTER_RULE_VERSION = "r45-5"
RULE_VERSION = LLM_ADVISORY_EXPORTER_RULE_VERSION

PROVENANCE_LAYER_ORDER: tuple[str, ...] = ("R42", "R43", "R44")


def build_advisory_provenance(source_refs: object) -> dict:
    """Build deterministic provenance visibility from source references."""

    layers: list[str] = []
    if isinstance(source_refs, (list, tuple)):
        for item in source_refs:
            if not isinstance(item, dict):
                continue
            layer = str(item.get("layer") or "").upper()
            if layer in PROVENANCE_LAYER_ORDER and layer not in layers:
                layers.append(layer)
    ordered = [layer for layer in PROVENANCE_LAYER_ORDER if layer in layers]
    if len(ordered) == len(PROVENANCE_LAYER_ORDER):
        state = PROVENANCE_COMPLETE
    elif ordered:
        state = PROVENANCE_PARTIAL
    else:
        state = PROVENANCE_UNKNOWN
    return {
        "source_layers": ordered,
        "provenance_state": state,
        "research_only": True,
    }


def build_advisory_governance(governance_state: object) -> dict:
    """Build deterministic governance visibility for the result."""

    state = str(governance_state if governance_state is not None else "").strip()
    if not state:
        state = "UNKNOWN"
    return {
        "governance_state": state.upper(),
        "reference_present": state.upper() != "UNKNOWN",
        "research_only": True,
    }


def export_llm_advisory(
    evaluation_result: object = None,
    collaboration_result: object = None,
    learning_signals: object = None,
    research_context: object = None,
    governance_state: object = None,
    safety_state: object = None,
    requested_mode: object = None,
    advisory_id: object = None,
    provider: object = None,
    provider_kind: object = PROVIDER_KIND_MOCK,
) -> dict:
    """Export a deterministic advisory result (read-only).

    The mock provider is the only supported provider in version 1. A caller
    may inject a provider object implementing ``complete(request)``; unsafe
    output from any provider is rejected and preserved as diagnostics.
    """

    advisory_input = build_llm_advisory_input(
        evaluation_result=evaluation_result,
        collaboration_result=collaboration_result,
        learning_signals=learning_signals,
        research_context=research_context,
        governance_state=governance_state,
        safety_state=safety_state,
        advisory_id=advisory_id,
    )

    resolved_kind = provider_kind
    if provider is not None and getattr(provider, "provider_kind", ""):
        resolved_kind = provider.provider_kind

    request = build_llm_advisory_request(
        advisory_input,
        requested_mode=requested_mode,
        provider_kind=resolved_kind,
    )

    active_provider = (
        provider if provider is not None
        else get_advisory_provider(resolved_kind)
    )
    response = active_provider.complete(request)
    validation = validate_advisory_response(response, request)

    if validation["validation_state"] == VALIDATION_PASS:
        summary = str(response.get("summary") or "")
        insights = list(response.get("insights") or [])
        recommendations = list(response.get("recommendations") or [])
    else:
        summary = ""
        insights = []
        recommendations = []

    safety = advisory_safety_state(
        advisory_input.get("safety_state"), validation
    )
    provenance = build_advisory_provenance(request.get("source_refs"))
    governance = build_advisory_governance(
        advisory_input.get("governance_state")
    )

    plan = LLMAdvisoryResultPlan(
        rule_version=LLM_ADVISORY_RESULT_RULE_VERSION,
        advisory_rule_version=LLM_ADVISORY_RESULT_RULE_VERSION,
        advisory_id=request.get("advisory_id") or "",
        advisory_mode=request.get("advisory_mode") or "SUMMARY",
        summary=summary,
        insights=insights,
        recommendations=recommendations,
        source_refs=request.get("source_refs") or [],
        provenance=provenance,
        governance=governance,
        validation_state=validation["validation_state"],
        validation_diagnostics=validation["violations"],
        safety_state=safety,
        limitations=list(ADVISORY_RESULT_LIMITATIONS),
        research_only=True,
        deterministic=True,
    )
    result = llm_advisory_result_plan_projection(plan)
    result["rule_version"] = LLM_ADVISORY_RESULT_RULE_VERSION
    result["advisory_rule_version"] = LLM_ADVISORY_RESULT_RULE_VERSION
    result["advisory_id"] = request.get("advisory_id") or ""

    result_validation = validate_advisory_result(result)
    if result_validation["validation_state"] == VALIDATION_REJECTED:
        rejected = LLMAdvisoryResultPlan(
            rule_version=LLM_ADVISORY_RESULT_RULE_VERSION,
            advisory_rule_version=LLM_ADVISORY_RESULT_RULE_VERSION,
            advisory_id=request.get("advisory_id") or "",
            advisory_mode=request.get("advisory_mode") or "SUMMARY",
            summary="",
            insights=[],
            recommendations=[],
            source_refs=request.get("source_refs") or [],
            provenance=provenance,
            governance=governance,
            validation_state=VALIDATION_REJECTED,
            validation_diagnostics=result_validation["violations"],
            safety_state="FAILED",
            limitations=list(ADVISORY_RESULT_LIMITATIONS),
            research_only=True,
            deterministic=True,
        )
        result = llm_advisory_result_plan_projection(rejected)
        result["rule_version"] = LLM_ADVISORY_RESULT_RULE_VERSION
        result["advisory_rule_version"] = LLM_ADVISORY_RESULT_RULE_VERSION
        result["advisory_id"] = request.get("advisory_id") or ""
    return result


def run_llm_advisory(
    evaluation_result: object = None,
    collaboration_result: object = None,
    learning_signals: object = None,
    research_context: object = None,
    governance_state: object = None,
    safety_state: object = None,
    requested_mode: object = None,
    advisory_id: object = None,
    provider: object = None,
    provider_kind: object = PROVIDER_KIND_MOCK,
) -> dict:
    """Alias for :func:`export_llm_advisory` (project naming pattern)."""

    return export_llm_advisory(
        evaluation_result=evaluation_result,
        collaboration_result=collaboration_result,
        learning_signals=learning_signals,
        research_context=research_context,
        governance_state=governance_state,
        safety_state=safety_state,
        requested_mode=requested_mode,
        advisory_id=advisory_id,
        provider=provider,
        provider_kind=provider_kind,
    )


__all__ = [
    "LLM_ADVISORY_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "PROVENANCE_LAYER_ORDER",
    "build_advisory_provenance",
    "build_advisory_governance",
    "export_llm_advisory",
    "run_llm_advisory",
]
