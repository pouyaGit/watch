from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from ai.llm.base import LLMProvider
from ai.schemas.xss import (
    XSSCase,
    XSSContextObservation,
    XSSResearchContext,
    XSSResearchLLMResult,
    XSSSuggestedPayload,
    XSSVerificationIdea,
)


class XSSLLMAttributionError(ValueError):
    """Raised when an LLM response fails attribution cross-validation."""


_ALLOWED_EVIDENCE_PREFIXES = (
    "CONFIRMED:",
    "UNKNOWN:",
    "NOT OBSERVED:",
    "SECONDARY:",
    "MODEL_GENERATED:",
)


def _parse_llm_json(raw: str) -> dict:
    """
    Extract the first valid JSON object from an LLM response.

    Handles ```` ```json ... ``` ``` fences, valid JSON followed by
    extra prose, and surrounding whitespace. Returns the parsed
    object. Raises ``ValueError`` on failure.
    """

    text = raw.strip()

    if text.startswith("```"):
        text = text.replace("```json", "", 1)
        text = text.replace("```", "", 1).strip()

    decoder = json.JSONDecoder()
    start = text.find("{")

    if start == -1:
        raise ValueError(
            f"LLM response does not contain JSON:\n{raw}"
        )

    try:
        data, _ = decoder.raw_decode(text[start:])
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"LLM returned invalid JSON:\n{raw}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            "LLM JSON root must be an object."
        )

    return data


def _projected_context_payload(
    context: XSSResearchContext,
) -> dict:
    """
    Project the supplied :class:`XSSResearchContext` into the
    fields the LLM is allowed to see.

    Full :class:`KnowledgeDocument` blobs are intentionally not
    included. The LLM receives only the attribution-bearing
    projections and the case metadata it needs to reason about.
    """

    def _items(values):
        return [
            {
                "value": item.value,
                "source_ids": list(item.source_ids),
            }
            for item in values
        ]

    return {
        "case_id": context.case_id,
        "retrieved_knowledge_ids": list(
            context.retrieved_knowledge_ids
        ),
        "payload_patterns": _items(
            context.payload_patterns
        ),
        "verification_patterns": _items(
            context.verification_patterns
        ),
        "contexts": _items(context.contexts),
        "technologies": _items(context.technologies),
        "waf_observations": _items(
            context.waf_observations
        ),
    }


def _build_prompt(
    case: XSSCase,
    context: XSSResearchContext,
) -> str:
    projection = _projected_context_payload(context)

    return f"""
You are an expert XSS research analyst.
You receive an already-retrieved XSS research context for one
investigation case. You MUST NOT invent knowledge attribution.

CASE
----
case_id: {case.case_id}
target: {case.target}
endpoint: {case.endpoint}
method: {case.method}
parameter: {case.parameter}
parameter_location: {case.parameter_location}
xss_type: {case.xss_type}
context.type: {case.context.type}
context.attribute_name: {case.context.attribute_name}
context.attribute_quoted: {case.context.attribute_quoted}
context.tag_name: {case.context.tag_name}
context.script_context: {case.context.script_context}
context.javascript_context: {case.context.javascript_context}
context.html_encoded: {case.context.html_encoded}
context.url_encoded: {case.context.url_encoded}
context.js_encoded: {case.context.js_encoded}
technology: {json.dumps(case.technology, ensure_ascii=False)}
waf: {case.waf}
source_type: {case.source_type}
discovery_evidence: {json.dumps(case.discovery_evidence, ensure_ascii=False)}

SUPPLIED RESEARCH CONTEXT
-------------------------

{json.dumps(projection, ensure_ascii=False, indent=2)}

ATTRIBUTION RULES
-----------------

1. Set origin to "knowledge" ONLY when the suggestion is directly
   based on a supplied pattern. In that case you MUST populate
   knowledge_ids and source_ids with values taken verbatim from
   the supplied context, and based_on_pattern MUST exactly match
   one of the values in the corresponding supplied list.
2. Set origin to "model_generated" for any novel adaptation that
   goes beyond the supplied patterns. knowledge_ids and source_ids
   MUST be empty lists in that case. based_on_pattern MAY be null
   or may reference an exact value from the supplied context as
   the inspiration.
3. NEVER invent knowledge_ids or source_ids.
4. NEVER claim vulnerability confirmation. Set
   case_status_suggestion to one of:
     "NEW", "ANALYZED", "VERIFYING", "INCONCLUSIVE"
   You MUST NOT return "CONFIRMED" or "NOT_VULNERABLE".
5. Every evidence string MUST start with EXACTLY one prefix:
     CONFIRMED:
     UNKNOWN:
     NOT OBSERVED:
     SECONDARY:
     MODEL_GENERATED:
6. Return ONLY valid JSON. No prose before or after.

RETURN JSON MATCHING THIS SCHEMA
--------------------------------

{{
  "case_id": "string",
  "case_status_suggestion": "NEW" | "ANALYZED" | "VERIFYING" | "INCONCLUSIVE",
  "suggested_payloads": [
    {{
      "pattern": "string",
      "origin": "knowledge" | "model_generated",
      "knowledge_ids": ["kb-..."],
      "source_ids": ["src-..."],
      "based_on_pattern": "string or null",
      "rationale": "string"
    }}
  ],
  "verification_ideas": [
    {{
      "pattern": "string",
      "origin": "knowledge" | "model_generated",
      "knowledge_ids": ["kb-..."],
      "source_ids": ["src-..."],
      "based_on_pattern": "string or null",
      "rationale": "string"
    }}
  ],
  "context_observations": [
    {{
      "observation": "string",
      "origin": "knowledge" | "model_generated",
      "knowledge_ids": ["kb-..."],
      "source_ids": ["src-..."],
      "based_on_pattern": "string or null",
      "rationale": "string"
    }}
  ],
  "next_research_questions": ["string"],
  "evidence": ["CONFIRMED: ...", "MODEL_GENERATED: ..."],
  "model": "string or null",
  "raw_response_id": "string or null"
}}
"""


def _available_payload_patterns(
    context: XSSResearchContext,
) -> set[str]:
    return {
        item.value
        for item in context.payload_patterns
    }


def _available_verification_patterns(
    context: XSSResearchContext,
) -> set[str]:
    return {
        item.value
        for item in context.verification_patterns
    }


def _source_ids_by_knowledge_id(
    context: XSSResearchContext,
) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for document in context.documents:
        for provenance in document.provenance:
            if provenance.source_id is None:
                continue
            mapping.setdefault(
                document.knowledge_id,
                set(),
            ).add(provenance.source_id)
    return mapping


def _validate_evidence(evidence: list[str]) -> None:
    for entry in evidence:
        if not isinstance(entry, str):
            raise XSSLLMAttributionError(
                "evidence entry is not a string"
            )
        if not any(
            entry.startswith(prefix)
            for prefix in _ALLOWED_EVIDENCE_PREFIXES
        ):
            raise XSSLLMAttributionError(
                "evidence entry lacks a recognized prefix: "
                f"{entry!r}"
            )


def _validate_payload_suggestion(
    item: XSSSuggestedPayload,
    *,
    context: XSSResearchContext,
    allowed_patterns: set[str],
    sources_by_kid: dict[str, set[str]],
    retrieved_ids: set[str],
) -> None:
    if item.origin == "knowledge":
        if not item.knowledge_ids:
            raise XSSLLMAttributionError(
                "knowledge payload lacks knowledge_ids: "
                f"{item.pattern!r}"
            )
        if not item.source_ids:
            raise XSSLLMAttributionError(
                "knowledge payload lacks source_ids: "
                f"{item.pattern!r}"
            )
        _check_attribution(
            item=item,
            retrieved_ids=retrieved_ids,
            sources_by_kid=sources_by_kid,
        )
        if (
            item.based_on_pattern is not None
            and item.based_on_pattern
            not in allowed_patterns
        ):
            raise XSSLLMAttributionError(
                "knowledge payload based_on_pattern is not "
                f"a payload pattern in context: "
                f"{item.based_on_pattern!r}"
            )
        return

    if item.knowledge_ids or item.source_ids:
        raise XSSLLMAttributionError(
            "model_generated payload must not carry "
            "knowledge_ids or source_ids: "
            f"{item.pattern!r}"
        )
    if (
        item.based_on_pattern is not None
        and item.based_on_pattern
        not in allowed_patterns
    ):
        raise XSSLLMAttributionError(
            "model_generated payload based_on_pattern is "
            "not a payload pattern in context: "
            f"{item.based_on_pattern!r}"
        )


def _validate_verification_idea(
    item: XSSVerificationIdea,
    *,
    context: XSSResearchContext,
    allowed_patterns: set[str],
    sources_by_kid: dict[str, set[str]],
    retrieved_ids: set[str],
) -> None:
    if item.origin == "knowledge":
        if not item.knowledge_ids:
            raise XSSLLMAttributionError(
                "knowledge verification lacks knowledge_ids: "
                f"{item.pattern!r}"
            )
        if not item.source_ids:
            raise XSSLLMAttributionError(
                "knowledge verification lacks source_ids: "
                f"{item.pattern!r}"
            )
        _check_attribution(
            item=item,
            retrieved_ids=retrieved_ids,
            sources_by_kid=sources_by_kid,
        )
        if (
            item.based_on_pattern is not None
            and item.based_on_pattern
            not in allowed_patterns
        ):
            raise XSSLLMAttributionError(
                "knowledge verification based_on_pattern is "
                "not a verification pattern in context: "
                f"{item.based_on_pattern!r}"
            )
        return

    if item.knowledge_ids or item.source_ids:
        raise XSSLLMAttributionError(
            "model_generated verification must not carry "
            "knowledge_ids or source_ids: "
            f"{item.pattern!r}"
        )
    if (
        item.based_on_pattern is not None
        and item.based_on_pattern
        not in allowed_patterns
    ):
        raise XSSLLMAttributionError(
            "model_generated verification based_on_pattern "
            "is not a verification pattern in context: "
            f"{item.based_on_pattern!r}"
        )


def _validate_context_observation(
    item: XSSContextObservation,
    *,
    context: XSSResearchContext,
    sources_by_kid: dict[str, set[str]],
    retrieved_ids: set[str],
) -> None:
    if item.origin == "knowledge":
        if not item.knowledge_ids:
            raise XSSLLMAttributionError(
                "knowledge observation lacks knowledge_ids: "
                f"{item.observation!r}"
            )
        if not item.source_ids:
            raise XSSLLMAttributionError(
                "knowledge observation lacks source_ids: "
                f"{item.observation!r}"
            )
        _check_attribution(
            item=item,
            retrieved_ids=retrieved_ids,
            sources_by_kid=sources_by_kid,
        )
        return

    if item.knowledge_ids or item.source_ids:
        raise XSSLLMAttributionError(
            "model_generated observation must not carry "
            "knowledge_ids or source_ids: "
            f"{item.observation!r}"
        )


def _check_attribution(
    *,
    item: Any,
    retrieved_ids: set[str],
    sources_by_kid: dict[str, set[str]],
) -> None:
    for kid in item.knowledge_ids:
        if kid not in retrieved_ids:
            raise XSSLLMAttributionError(
                f"unknown knowledge_id in {type(item).__name__}: "
                f"{kid!r}"
            )

    attributed_source_ids: set[str] = set()
    for kid in item.knowledge_ids:
        attributed_source_ids.update(
            sources_by_kid.get(kid, set())
        )

    for sid in item.source_ids:
        if sid not in attributed_source_ids:
            raise XSSLLMAttributionError(
                f"unknown source_id in {type(item).__name__}: "
                f"{sid!r}"
            )


class XSSLLMResearcher:
    """
    First LLM layer over an already-built :class:`XSSResearchContext`.

    The LLM is a projector, not a researcher. It does not retrieve
    knowledge, does not access the :class:`KnowledgeStore`, does not
    perform network or browser actions, and does not confirm
    vulnerabilities. It receives the case and the deterministic
    research context, returns a structured
    :class:`XSSResearchLLMResult`, and is strictly limited to
    pre-confirmation ``case_status_suggestion`` values.
    """

    def __init__(self, llm: LLMProvider) -> None:
        self.llm = llm

    def analyze(
        self,
        case: XSSCase,
        context: XSSResearchContext,
    ) -> XSSResearchLLMResult:
        prompt = _build_prompt(case, context)

        provider_result = self.llm.complete(prompt)

        data = _parse_llm_json(provider_result.content)

        try:
            result = XSSResearchLLMResult.model_validate(data)
        except ValidationError as exc:
            raise XSSLLMAttributionError(
                "LLM response failed schema validation: "
                f"{exc}"
            ) from exc

        if result.case_id != case.case_id:
            raise XSSLLMAttributionError(
                "LLM returned case_id "
                f"{result.case_id!r} but case.case_id is "
                f"{case.case_id!r}"
            )

        if result.case_status_suggestion in (
            "CONFIRMED",
            "NOT_VULNERABLE",
        ):
            raise XSSLLMAttributionError(
                "LLM returned forbidden case_status_suggestion: "
                f"{result.case_status_suggestion!r}"
            )

        _validate_evidence(result.evidence)

        retrieved_ids = set(context.retrieved_knowledge_ids)
        sources_by_kid = _source_ids_by_knowledge_id(
            context
        )
        available_payload_patterns = _available_payload_patterns(
            context
        )
        available_verification_patterns = (
            _available_verification_patterns(context)
        )

        for item in result.suggested_payloads:
            _validate_payload_suggestion(
                item,
                context=context,
                allowed_patterns=available_payload_patterns,
                sources_by_kid=sources_by_kid,
                retrieved_ids=retrieved_ids,
            )

        for item in result.verification_ideas:
            _validate_verification_idea(
                item,
                context=context,
                allowed_patterns=available_verification_patterns,
                sources_by_kid=sources_by_kid,
                retrieved_ids=retrieved_ids,
            )

        for item in result.context_observations:
            _validate_context_observation(
                item,
                context=context,
                sources_by_kid=sources_by_kid,
                retrieved_ids=retrieved_ids,
            )

        return result.model_copy(
            update={
                "model": provider_result.model,
                "raw_response_id": provider_result.request_id,
            }
        )
