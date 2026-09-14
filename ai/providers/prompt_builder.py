"""Stage R51 deterministic prompt builder and strict response parser.

Builds the bounded, deterministic provider prompt from the allowlisted
outbound context and parses the provider's structured content back into
the R45 provider response contract:

    allowlisted context -> prompt -> provider -> strict JSON -> R45 response

Hard boundaries encoded here:

- Deterministic construction: the same context produces byte-identical
  messages and the same content fingerprint.
- Allowlist only: the prompt is built exclusively from the R51 context
  projection; no arbitrary Watch object is serialized.
- Advisory-only instructions: the system instruction forbids exploitation,
  execution, payload generation, vulnerability confirmation and attack
  planning, and requires strict JSON.
- Strict parsing: malformed, oversized, incomplete or extra-key provider
  content is rejected (INVALID_RESPONSE) and empty content is rejected
  (EMPTY_RESPONSE). Provider content is never repaired into an acceptable
  shape.
- Provenance preserved: advisory identity, mode, source references and
  limitations from the validated request are carried into the normalized
  response; per-item source references are not invented.
- No I/O, no network, no LLM, no Mongo, no execution.

The parsed response is an R45 ``LLMProviderResponsePlan`` projection and
is still subject to the R45.6 advisory validator before any consumer sees
it.
"""

from __future__ import annotations

import hashlib
import json
import re

from ai.schemas.llm_advisory_policy import MAX_ADVISORY_TEXT_LEN
from ai.schemas.llm_provider import (
    LLM_PROVIDER_RULE_VERSION,
    REAL_PROVIDER_LIMITATIONS,
    LLMProviderResponsePlan,
    llm_provider_response_plan_projection,
)
from ai.schemas.llm_provider_error import (
    CODE_EMPTY_PROVIDER_RESPONSE,
    CODE_INVALID_PROVIDER_RESPONSE,
    ERROR_EMPTY_RESPONSE,
    ERROR_INVALID_RESPONSE,
)

from ai.providers.provider_errors import ProviderCallError

PROVIDER_PROMPT_RULE_VERSION = "r51-prompt"
RULE_VERSION = PROVIDER_PROMPT_RULE_VERSION

MAX_PROMPT_CHARS = 8000
MAX_RESPONSE_CONTENT_CHARS = 10000
MAX_RESPONSE_ITEMS = 8
MAX_CODE_LEN = 80
MAX_INSIGHT_TEXT_LEN = MAX_ADVISORY_TEXT_LEN

_CODE_RE = re.compile(r"^[A-Z0-9_]{1,80}$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

RESPONSE_SHAPE_KEYS: tuple[str, ...] = (
    "summary",
    "insights",
    "recommendations",
)

SYSTEM_INSTRUCTION = (
    "You are an advisory-only research explainer for a deterministic "
    "security-research pipeline. You must not confirm vulnerabilities, "
    "must not claim exploitation success, must not provide execution "
    "steps, payloads or attack plans, and must not request or repeat "
    "credentials, tokens or URLs. Explain only the structured research "
    "state supplied by the user. Respond with a single strict JSON object "
    "and no other text."
)

RESPONSE_FORMAT_INSTRUCTION = (
    "JSON shape: {"
    '"summary": string, '
    '"insights": [{"insight_code": "UPPER_SNAKE_CASE", "text": string}], '
    '"recommendations": [{"recommendation_code": "UPPER_SNAKE_CASE", '
    '"text": string}]'
    "}. Use at most 8 insights and 8 recommendations; keep every text "
    "under 400 characters; do not add extra keys."
)


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _text(value: object, limit: int = 240) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def build_provider_prompt(context_bundle: object = None) -> dict:
    """Build the deterministic bounded provider prompt (read-only)."""

    bundle = context_bundle if isinstance(context_bundle, dict) else {}
    context = bundle.get("context")
    if not isinstance(context, dict):
        raise ProviderCallError(
            ERROR_INVALID_RESPONSE,
            CODE_INVALID_PROVIDER_RESPONSE,
            retryable=False,
            attempts=0,
            safe_message="allowlisted context is missing",
        )

    user_payload = _canonical_json(context)
    if len(user_payload) > MAX_PROMPT_CHARS:
        raise ProviderCallError(
            ERROR_INVALID_RESPONSE,
            CODE_INVALID_PROVIDER_RESPONSE,
            retryable=False,
            attempts=0,
            safe_message="provider prompt exceeds the bounded size",
        )

    messages = [
        {
            "role": "system",
            "content": SYSTEM_INSTRUCTION + " " + RESPONSE_FORMAT_INSTRUCTION,
        },
        {"role": "user", "content": user_payload},
    ]
    canonical = _canonical_json(messages)
    if len(canonical) > MAX_PROMPT_CHARS:
        raise ProviderCallError(
            ERROR_INVALID_RESPONSE,
            CODE_INVALID_PROVIDER_RESPONSE,
            retryable=False,
            attempts=0,
            safe_message="provider prompt exceeds the bounded size",
        )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {
        "rule_version": PROVIDER_PROMPT_RULE_VERSION,
        "messages": messages,
        "prompt_chars": len(canonical),
        "prompt_fingerprint": "prompt-" + digest[:16],
        "research_only": True,
    }


def _invalid(message: str) -> ProviderCallError:
    return ProviderCallError(
        ERROR_INVALID_RESPONSE,
        CODE_INVALID_PROVIDER_RESPONSE,
        retryable=False,
        attempts=0,
        safe_message=message,
    )


def _empty(message: str) -> ProviderCallError:
    return ProviderCallError(
        ERROR_EMPTY_RESPONSE,
        CODE_EMPTY_PROVIDER_RESPONSE,
        retryable=False,
        attempts=0,
        safe_message=message,
    )


def parse_advisory_content(
    content: object = None,
    request: object = None,
    provider_kind: str = "",
) -> dict:
    """Parse strict provider JSON into the R45 response contract.

    Rejects malformed/empty/oversized content. Never fabricates or repairs
    provider content.
    """

    if not isinstance(content, str):
        raise _invalid("provider content is not text")
    stripped = content.strip()
    if not stripped:
        raise _empty("provider content is empty")
    if _CONTROL_RE.search(stripped):
        raise _invalid("provider content contains control characters")
    if len(stripped) > MAX_RESPONSE_CONTENT_CHARS:
        raise _invalid("provider content exceeds the bounded size")
    try:
        payload = json.loads(stripped)
    except (ValueError, TypeError):
        raise _invalid("provider content is not valid JSON")
    if not isinstance(payload, dict):
        raise _invalid("provider content is not a JSON object")
    if set(payload.keys()) != set(RESPONSE_SHAPE_KEYS):
        raise _invalid("provider content has unexpected keys")

    summary = payload.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise _invalid("provider summary is missing")
    if len(summary) > MAX_INSIGHT_TEXT_LEN:
        raise _invalid("provider summary exceeds the bounded size")

    insights = _parse_items(
        payload.get("insights"), "insight_code", "insights"
    )
    recommendations = _parse_items(
        payload.get("recommendations"),
        "recommendation_code",
        "recommendations",
    )

    request_value = request if isinstance(request, dict) else {}
    plan = LLMProviderResponsePlan(
        rule_version=LLM_PROVIDER_RULE_VERSION,
        provider_kind=str(provider_kind or "").strip().upper(),
        advisory_id=str(request_value.get("advisory_id") or ""),
        advisory_mode=str(request_value.get("advisory_mode") or "SUMMARY"),
        summary=summary.strip(),
        insights=insights,
        recommendations=recommendations,
        source_refs=list(request_value.get("source_refs") or []),
        limitations=list(REAL_PROVIDER_LIMITATIONS),
        research_only=True,
        deterministic=True,
    )
    return llm_provider_response_plan_projection(plan)


def _parse_items(value: object, code_key: str, label: str) -> list[dict]:
    if not isinstance(value, list):
        raise _invalid(f"provider {label} are not a list")
    if len(value) > MAX_RESPONSE_ITEMS:
        raise _invalid(f"provider {label} exceed the bounded count")
    out: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            raise _invalid(f"provider {label} item is malformed")
        if set(item.keys()) != {code_key, "text"}:
            raise _invalid(f"provider {label} item has unexpected keys")
        code = item.get(code_key)
        text = item.get("text")
        if not isinstance(code, str) or not _CODE_RE.match(code.strip()):
            raise _invalid(f"provider {label} code is invalid")
        if not isinstance(text, str) or not text.strip():
            raise _invalid(f"provider {label} text is missing")
        if len(text) > MAX_INSIGHT_TEXT_LEN:
            raise _invalid(f"provider {label} text exceeds the bound")
        out.append(
            {
                code_key: code.strip(),
                "text": text.strip(),
                "source_refs": [],
                "research_only": True,
            }
        )
    return out


__all__ = [
    "PROVIDER_PROMPT_RULE_VERSION",
    "RULE_VERSION",
    "MAX_PROMPT_CHARS",
    "MAX_RESPONSE_CONTENT_CHARS",
    "MAX_RESPONSE_ITEMS",
    "RESPONSE_SHAPE_KEYS",
    "SYSTEM_INSTRUCTION",
    "RESPONSE_FORMAT_INSTRUCTION",
    "build_provider_prompt",
    "parse_advisory_content",
]
