"""Stage R45.3 LLM provider abstraction (pure interface + mock provider).

Defines the advisory provider interface and the deterministic mock provider
used by version 1:

    "Which advisory provider produces the explanation?"

Hard boundaries encoded here:

- Interface and mock only: this pure layer contains no credential
  handling, no network client, no SDK import, no HTTP transport and no
  model runtime. The provider interface is the only extension point.
- Deterministic mock: the mock response is a pure function of the bounded
  request; identical requests produce byte-identical responses.
- No credentials: the provider takes no credential material and never logs
  any.
- Real provider kinds (OPENROUTER, OPENAI) are implemented by the R51
  provider layer under ``ai/providers`` and are never constructed here;
  ollama/local remain unsupported. No kind is silently ignored or
  silently redirected.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ai.schemas.llm_provider import (
    FUTURE_PROVIDER_KINDS,
    LLM_PROVIDER_RULE_VERSION,
    PROVIDER_KIND_MOCK,
    PROVIDER_LIMITATIONS,
    REAL_PROVIDER_KINDS,
    SUPPORTED_PROVIDER_KINDS,
    LLMProviderResponsePlan,
    llm_provider_response_plan_projection,
    sanitize_advisory_source_refs,
    sanitize_provider_request_sections,
)
from ai.schemas.llm_advisory_policy import (
    ADVISORY_MODES,
    DEFAULT_ADVISORY_MODE,
    MODE_CONFLICT_EXPLANATION,
    MODE_EXPLANATION,
    MODE_LEARNING_SUMMARY,
    MODE_RESEARCH_PRIORITY,
    MODE_SUMMARY,
)

LLM_PROVIDER_ENGINE_RULE_VERSION = "r45-3"
RULE_VERSION = LLM_PROVIDER_ENGINE_RULE_VERSION

MOCK_MODE_SUMMARIES: dict[str, str] = {
    MODE_SUMMARY: (
        "Structured research status is summarized from deterministic layer "
        "outputs."
    ),
    MODE_EXPLANATION: (
        "The evaluation and collaboration layers explain the current "
        "research state; no security conclusion is drawn."
    ),
    MODE_RESEARCH_PRIORITY: (
        "Research priority follows the deterministic collaboration ranking, "
        "and confidence remains bounded by the evidence state."
    ),
    MODE_CONFLICT_EXPLANATION: (
        "Conflicting hypotheses are explained as research-level "
        "alternatives that require additional structured evidence."
    ),
    MODE_LEARNING_SUMMARY: (
        "Research confidence should remain limited until additional "
        "evidence requirements are satisfied."
    ),
}

MOCK_INSIGHT_ADVISORY_SCOPE = "ADVISORY_SCOPE"
MOCK_INSIGHT_EVALUATION_STATE = "EVALUATION_STATE"
MOCK_INSIGHT_COLLABORATION_STATE = "COLLABORATION_STATE"
MOCK_INSIGHT_CONFLICT_STATE = "CONFLICT_STATE"
MOCK_INSIGHT_LEARNING_STATE = "LEARNING_STATE"

MOCK_RECOMMENDATION_REQUIRE_EVIDENCE = "REQUIRE_ADDITIONAL_EVIDENCE"
MOCK_RECOMMENDATION_PRESERVE_SAFETY = "PRESERVE_SAFETY_BOUNDARY"
MOCK_RECOMMENDATION_KEEP_CONFLICTS = "KEEP_CONFLICTING_HYPOTHESES"
MOCK_RECOMMENDATION_APPLY_LEARNING = "APPLY_LEARNING_AS_ADVISORY"

MOCK_ADVISORY_TEXT: dict[str, str] = {
    MOCK_INSIGHT_ADVISORY_SCOPE: (
        "Advisory output explains structured layer outputs only and does not "
        "make security decisions."
    ),
    MOCK_RECOMMENDATION_REQUIRE_EVIDENCE: (
        "Require additional structured evidence before increasing research "
        "confidence."
    ),
    MOCK_RECOMMENDATION_PRESERVE_SAFETY: (
        "Preserve the research-only safety boundary and review the safety "
        "diagnostics."
    ),
    MOCK_RECOMMENDATION_KEEP_CONFLICTS: (
        "Keep conflicting hypotheses separate until additional structured "
        "evidence resolves them."
    ),
    MOCK_RECOMMENDATION_APPLY_LEARNING: (
        "Treat learning recommendations as advisory planning input only."
    ),
}


class AdvisoryProviderError(ValueError):
    """Deterministic provider rejection with preserved diagnostics."""

    def __init__(self, message: str, diagnostic: dict | None = None):
        super().__init__(message)
        self.diagnostic = diagnostic or {}


class UnsupportedProviderError(AdvisoryProviderError):
    """Raised when a provider kind is not supported in version 1."""


def _normalize_provider_kind(value: object) -> str:
    return str(value if value is not None else "").strip().upper()


def _normalized_mode(value: object) -> str:
    text = str(value if value is not None else "").strip().upper()
    return text if text in ADVISORY_MODES else DEFAULT_ADVISORY_MODE


class AdvisoryProvider(ABC):
    """Provider-agnostic advisory interface (no network, no SDK)."""

    provider_kind: str = ""

    @abstractmethod
    def complete(self, request: object = None) -> dict:
        """Return a deterministic advisory response for a bounded request."""

        raise NotImplementedError

    def describe(self) -> dict:
        """Return a deterministic description of the provider boundary."""

        return {
            "rule_version": LLM_PROVIDER_ENGINE_RULE_VERSION,
            "provider_kind": self.provider_kind,
            "supported": self.provider_kind in SUPPORTED_PROVIDER_KINDS,
            "network_access": False,
            "credentials_used": False,
            "deterministic": True,
            "research_only": True,
            "limitations": list(PROVIDER_LIMITATIONS),
        }


class MockLLMProvider(AdvisoryProvider):
    """Deterministic offline mock provider (version 1)."""

    provider_kind = PROVIDER_KIND_MOCK

    def complete(self, request: object = None) -> dict:
        raw = request if isinstance(request, dict) else {}
        mode = _normalized_mode(raw.get("advisory_mode"))
        sections = sanitize_provider_request_sections(raw.get("sections"))
        source_refs = sanitize_advisory_source_refs(raw.get("source_refs"))

        insights: list[dict] = [
            {
                "insight_code": MOCK_INSIGHT_ADVISORY_SCOPE,
                "text": MOCK_ADVISORY_TEXT[MOCK_INSIGHT_ADVISORY_SCOPE],
                "source_refs": [],
                "research_only": True,
            }
        ]
        evaluation = sections["evaluation_summary"]
        if evaluation.get("present"):
            insights.append(
                {
                    "insight_code": MOCK_INSIGHT_EVALUATION_STATE,
                    "text": (
                        "Evaluation quality is "
                        f"{evaluation['overall_rating']} with safety state "
                        f"{evaluation['safety_state']}; this is a "
                        "research-output quality signal only and not a "
                        "security conclusion."
                    ),
                    "source_refs": [
                        ref for ref in source_refs if ref["layer"] == "R42"
                    ],
                    "research_only": True,
                }
            )
        collaboration = sections["collaboration_summary"]
        if collaboration.get("present"):
            insights.append(
                {
                    "insight_code": MOCK_INSIGHT_COLLABORATION_STATE,
                    "text": (
                        "Collaboration covers "
                        f"{collaboration['participant_count']} "
                        "participant(s), "
                        f"{collaboration['hypothesis_group_count']} "
                        "hypothesis group(s) and "
                        f"{collaboration['conflict_count']} reported "
                        "conflict(s)."
                    ),
                    "source_refs": [
                        ref for ref in source_refs if ref["layer"] == "R43"
                    ],
                    "research_only": True,
                }
            )
            if collaboration["conflict_count"] > 0:
                conflict_types = collaboration["conflict_types"] or [
                    "UNKNOWN"
                ]
                insights.append(
                    {
                        "insight_code": MOCK_INSIGHT_CONFLICT_STATE,
                        "text": (
                            "Reported conflict types are "
                            f"{', '.join(conflict_types)}; they remain "
                            "research-level divergences."
                        ),
                        "source_refs": [
                            ref
                            for ref in source_refs
                            if ref["layer"] == "R43"
                        ],
                        "research_only": True,
                    }
                )
        signals = sections["learning_signals"]
        if signals:
            signal_types: list[str] = []
            for signal in signals:
                text = str(signal.get("signal_type") or "")
                if text and text not in signal_types:
                    signal_types.append(text)
            insights.append(
                {
                    "insight_code": MOCK_INSIGHT_LEARNING_STATE,
                    "text": (
                        "Advisory learning signals present: "
                        f"{', '.join(signal_types)}."
                    ),
                    "source_refs": [
                        ref for ref in source_refs if ref["layer"] == "R44"
                    ],
                    "research_only": True,
                }
            )

        recommendations: list[dict] = [
            {
                "recommendation_code": (
                    MOCK_RECOMMENDATION_REQUIRE_EVIDENCE
                ),
                "text": MOCK_ADVISORY_TEXT[
                    MOCK_RECOMMENDATION_REQUIRE_EVIDENCE
                ],
                "source_refs": [],
                "research_only": True,
            }
        ]
        if sections["safety_state"] not in ("PASS",):
            recommendations.append(
                {
                    "recommendation_code": (
                        MOCK_RECOMMENDATION_PRESERVE_SAFETY
                    ),
                    "text": MOCK_ADVISORY_TEXT[
                        MOCK_RECOMMENDATION_PRESERVE_SAFETY
                    ],
                    "source_refs": [
                        ref for ref in source_refs if ref["layer"] == "R42"
                    ],
                    "research_only": True,
                }
            )
        if collaboration.get("conflict_count", 0) > 0:
            recommendations.append(
                {
                    "recommendation_code": (
                        MOCK_RECOMMENDATION_KEEP_CONFLICTS
                    ),
                    "text": MOCK_ADVISORY_TEXT[
                        MOCK_RECOMMENDATION_KEEP_CONFLICTS
                    ],
                    "source_refs": [
                        ref for ref in source_refs if ref["layer"] == "R43"
                    ],
                    "research_only": True,
                }
            )
        if signals:
            recommendations.append(
                {
                    "recommendation_code": (
                        MOCK_RECOMMENDATION_APPLY_LEARNING
                    ),
                    "text": MOCK_ADVISORY_TEXT[
                        MOCK_RECOMMENDATION_APPLY_LEARNING
                    ],
                    "source_refs": [
                        ref for ref in source_refs if ref["layer"] == "R44"
                    ],
                    "research_only": True,
                }
            )

        plan = LLMProviderResponsePlan(
            rule_version=LLM_PROVIDER_RULE_VERSION,
            provider_kind=PROVIDER_KIND_MOCK,
            advisory_id=str(raw.get("advisory_id") or ""),
            advisory_mode=mode,
            summary=MOCK_MODE_SUMMARIES.get(mode, ""),
            insights=insights,
            recommendations=recommendations,
            source_refs=source_refs,
            limitations=list(PROVIDER_LIMITATIONS),
            research_only=True,
            deterministic=True,
        )
        result = llm_provider_response_plan_projection(plan)
        result["rule_version"] = LLM_PROVIDER_RULE_VERSION
        return result


def get_advisory_provider(
    provider_kind: object = PROVIDER_KIND_MOCK,
) -> AdvisoryProvider:
    """Return the R45-native provider for a kind (mock only).

    This pure R45 layer constructs only the deterministic mock provider.
    Real provider kinds (OPENROUTER, OPENAI) are implemented by the R51
    provider layer under ``ai/providers`` and must be selected there or
    injected explicitly; this factory never constructs a network provider
    and never silently falls back. Ollama/local remain unsupported.
    """

    text = _normalize_provider_kind(provider_kind) or PROVIDER_KIND_MOCK
    if text == PROVIDER_KIND_MOCK:
        return MockLLMProvider()
    if text in REAL_PROVIDER_KINDS:
        raise UnsupportedProviderError(
            "provider kind is implemented by the R51 provider layer: "
            f"{text}",
            {
                "rule_version": LLM_PROVIDER_ENGINE_RULE_VERSION,
                "provider_kind": text,
                "supported_kinds": list(SUPPORTED_PROVIDER_KINDS),
                "future_kinds": list(FUTURE_PROVIDER_KINDS),
                "implementation_layer": "R51",
                "network_access": False,
                "credentials_used": False,
            },
        )
    if text in FUTURE_PROVIDER_KINDS:
        raise UnsupportedProviderError(
            f"provider kind not implemented in version 1: {text}",
            {
                "rule_version": LLM_PROVIDER_ENGINE_RULE_VERSION,
                "provider_kind": text,
                "supported_kinds": list(SUPPORTED_PROVIDER_KINDS),
                "future_kinds": list(FUTURE_PROVIDER_KINDS),
                "network_access": False,
                "credentials_used": False,
            },
        )
    raise UnsupportedProviderError(
        f"unknown provider kind: {text}",
        {
            "rule_version": LLM_PROVIDER_ENGINE_RULE_VERSION,
            "provider_kind": text,
            "supported_kinds": list(SUPPORTED_PROVIDER_KINDS),
            "future_kinds": list(FUTURE_PROVIDER_KINDS),
            "network_access": False,
            "credentials_used": False,
        },
    )


def provider_descriptor(
    provider_kind: object = PROVIDER_KIND_MOCK,
) -> dict:
    """Return the deterministic provider boundary description."""

    return get_advisory_provider(provider_kind).describe()


__all__ = [
    "LLM_PROVIDER_ENGINE_RULE_VERSION",
    "RULE_VERSION",
    "MOCK_MODE_SUMMARIES",
    "MOCK_ADVISORY_TEXT",
    "MOCK_INSIGHT_ADVISORY_SCOPE",
    "MOCK_INSIGHT_EVALUATION_STATE",
    "MOCK_INSIGHT_COLLABORATION_STATE",
    "MOCK_INSIGHT_CONFLICT_STATE",
    "MOCK_INSIGHT_LEARNING_STATE",
    "MOCK_RECOMMENDATION_REQUIRE_EVIDENCE",
    "MOCK_RECOMMENDATION_PRESERVE_SAFETY",
    "MOCK_RECOMMENDATION_KEEP_CONFLICTS",
    "MOCK_RECOMMENDATION_APPLY_LEARNING",
    "AdvisoryProviderError",
    "UnsupportedProviderError",
    "AdvisoryProvider",
    "MockLLMProvider",
    "get_advisory_provider",
    "provider_descriptor",
]
