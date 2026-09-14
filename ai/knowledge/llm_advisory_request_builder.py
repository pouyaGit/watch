"""Stage R45.4 deterministic advisory request builder (pure engine).

Normalizes bounded advisory input, applies the fixed advisory policy, selects
the allowed advisory mode and produces a deterministic request
representation:

    "What bounded advisory request may be sent to a provider?"

Hard boundaries encoded here:

- Advisory only: the request is a structured representation of explanations.
  It contains no exploitation prompt, no execution instruction, no payload,
  no credential and no raw sensitive runtime data.
- Policy first: the advisory mode is selected or validated through the R45.2
  policy engine. Forbidden modes are rejected with preserved diagnostics and
  are never converted into a request.
- Deterministic: the same bounded input produces the same request and the
  same fingerprint.
- No runtime identity: the advisory id is a deterministic content token.
- Pure and offline: no I/O, no network, no provider call, no LLM, no Mongo,
  no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib
import json

from ai.knowledge.llm_advisory_input import derive_llm_advisory_id
from ai.knowledge.llm_advisory_policy import resolve_advisory_mode
from ai.knowledge.llm_provider import get_advisory_provider
from ai.schemas.llm_advisory_policy import (
    MODE_CONFLICT_EXPLANATION,
    MODE_EXPLANATION,
    MODE_LEARNING_SUMMARY,
    MODE_RESEARCH_PRIORITY,
    MODE_SUMMARY,
)
from ai.schemas.llm_provider import (
    LLM_PROVIDER_RULE_VERSION,
    PROVIDER_KIND_MOCK,
    SUPPORTED_PROVIDER_KINDS,
    LLMProviderRequestPlan,
    llm_provider_request_plan_projection,
)
from ai.schemas.llm_advisory_input import (
    ADVISORY_ID_RE,
    ADVISORY_INPUT_LIMITATIONS,
    sanitize_llm_advisory_input,
)

LLM_ADVISORY_REQUEST_BUILDER_RULE_VERSION = "r45-4"
RULE_VERSION = LLM_ADVISORY_REQUEST_BUILDER_RULE_VERSION

ADVISORY_MODE_INSTRUCTIONS: dict[str, str] = {
    MODE_SUMMARY: (
        "Summarize the supplied structured research state using only the "
        "deterministic layer outputs. Do not confirm vulnerabilities."
    ),
    MODE_EXPLANATION: (
        "Explain the supplied evaluation and collaboration outputs. Do not "
        "confirm vulnerabilities and do not provide execution steps."
    ),
    MODE_RESEARCH_PRIORITY: (
        "Explain research priority from the supplied collaboration ranking "
        "outputs. Do not confirm vulnerabilities and do not provide "
        "security-testing guidance."
    ),
    MODE_CONFLICT_EXPLANATION: (
        "Explain the supplied research conflicts as open research questions "
        "that require additional structured evidence. Do not confirm "
        "vulnerabilities."
    ),
    MODE_LEARNING_SUMMARY: (
        "Summarize the supplied learning signals as advisory research "
        "guidance. Do not confirm vulnerabilities."
    ),
}


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def collect_advisory_source_refs(advisory_input: object) -> list[dict]:
    """Collect deterministic source references from the bounded input."""

    value = advisory_input if isinstance(advisory_input, dict) else {}
    evaluation = value.get("evaluation_summary")
    evaluation = evaluation if isinstance(evaluation, dict) else {}
    collaboration = value.get("collaboration_summary")
    collaboration = collaboration if isinstance(collaboration, dict) else {}
    signals = value.get("learning_signals")
    signals = signals if isinstance(signals, (list, tuple)) else ()
    refs: list[dict] = []
    if evaluation.get("present"):
        refs.append(
            {
                "layer": "R42",
                "reference": str(
                    evaluation.get("reference_rule_version") or "r42-5"
                ),
            }
        )
    if collaboration.get("present"):
        refs.append(
            {
                "layer": "R43",
                "reference": str(
                    collaboration.get("reference_rule_version") or "r43-6"
                ),
            }
        )
    if signals:
        refs.append({"layer": "R44", "reference": "r44-3"})
    return refs


def _resolve_provider_kind(provider_kind: object) -> str:
    text = str(
        provider_kind if provider_kind is not None else PROVIDER_KIND_MOCK
    ).strip().upper() or PROVIDER_KIND_MOCK
    if text not in SUPPORTED_PROVIDER_KINDS:
        get_advisory_provider(text)
    return text


def build_llm_advisory_request(
    advisory_input: object = None,
    requested_mode: object = None,
    provider_kind: object = PROVIDER_KIND_MOCK,
) -> dict:
    """Build the deterministic advisory request (read-only).

    The advisory input is normalized, the policy resolves the advisory mode,
    unsupported provider kinds are rejected deterministically and the request
    preserves source references, governance visibility and limitations.
    """

    bounded = sanitize_llm_advisory_input(advisory_input)
    mode = resolve_advisory_mode(bounded, requested_mode=requested_mode)
    resolved_provider = _resolve_provider_kind(provider_kind)

    advisory_id = str(bounded.get("advisory_id") or "")
    if not ADVISORY_ID_RE.match(advisory_id):
        advisory_id = derive_llm_advisory_id(
            {
                "source_layer": bounded.get("source_layer"),
                "research_context": bounded.get("research_context"),
                "evaluation_summary": bounded.get("evaluation_summary"),
                "collaboration_summary": bounded.get(
                    "collaboration_summary"
                ),
                "learning_signals": bounded.get("learning_signals"),
                "governance_state": bounded.get("governance_state"),
                "safety_state": bounded.get("safety_state"),
            }
        )

    limitations = [
        code
        for code in (bounded.get("limitations") or ADVISORY_INPUT_LIMITATIONS)
    ]
    if not limitations:
        limitations = list(ADVISORY_INPUT_LIMITATIONS)

    source_refs = collect_advisory_source_refs(bounded)
    sections = {
        "research_context": bounded.get("research_context"),
        "evaluation_summary": bounded.get("evaluation_summary"),
        "collaboration_summary": bounded.get("collaboration_summary"),
        "learning_signals": bounded.get("learning_signals"),
        "governance_state": bounded.get("governance_state"),
        "safety_state": bounded.get("safety_state"),
    }

    plan = LLMProviderRequestPlan(
        rule_version=LLM_PROVIDER_RULE_VERSION,
        advisory_id=advisory_id,
        advisory_mode=mode,
        provider_kind=resolved_provider,
        source_layer=bounded.get("source_layer"),
        instruction=ADVISORY_MODE_INSTRUCTIONS.get(mode, ""),
        sections=sections,
        source_refs=source_refs,
        limitations=limitations,
        research_only=True,
        deterministic=True,
    )
    request = llm_provider_request_plan_projection(plan)
    request["rule_version"] = LLM_PROVIDER_RULE_VERSION
    return request


def serialize_advisory_request(request: object) -> str:
    """Serialize a request to canonical deterministic JSON."""

    return _canonical_json(request)


def advisory_request_fingerprint(request: object) -> str:
    """Return the deterministic content fingerprint of an advisory request."""

    digest = hashlib.sha256(
        serialize_advisory_request(request).encode("utf-8")
    ).hexdigest()
    return "req-" + digest[:16]


__all__ = [
    "LLM_ADVISORY_REQUEST_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "ADVISORY_MODE_INSTRUCTIONS",
    "build_llm_advisory_request",
    "collect_advisory_source_refs",
    "serialize_advisory_request",
    "advisory_request_fingerprint",
]
