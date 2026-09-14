"""Stage R51 outbound context allowlist and data minimization.

Builds the exact, bounded projection of an R45 advisory request that may
cross the real-provider boundary:

    R45 advisory request -> allowlist projection -> provider prompt

Hard boundaries encoded here:

- Allowlist only: only explicitly listed fields may cross. The projection
  is built by picking approved keys, never by serializing arbitrary Watch
  objects or passing dictionaries through.
- Reject, never rewrite: sensitive content (credential-like material,
  authorization headers, cookies, session/access/refresh tokens, private
  key blocks, URLs, payload markers, control characters) causes the
  request to be rejected before any provider call. Content is never
  silently transformed into apparently safe content.
- Data minimization: secrets, credentials, authentication material,
  provider credentials, raw tokens, payloads and arbitrary URLs never
  cross; approved research metadata (source refs, provenance, governance
  state, safety state, advisory identity/mode, bounded summaries and
  learning signals) is preserved.
- Deterministic: the same request produces the same projection and reason
  codes.
- No I/O, no network, no LLM, no Mongo, no execution.

The reason codes carry no matched content, so a rejection can be reported
without echoing the offending value.
"""

from __future__ import annotations

import json
import re

from ai.schemas.llm_advisory_input import (
    ADVISORY_INPUT_LIMITATIONS,
    ADVISORY_ID_RE,
    LLM_ADVISORY_SOURCE_LAYERS,
)
from ai.schemas.llm_advisory_policy import ADVISORY_MODES, MAX_ADVISORY_TEXT_LEN
from ai.schemas.llm_provider import SOURCE_REF_LAYERS

from ai.providers.provider_errors import ProviderCallError, ProviderContextRejected
from ai.schemas.llm_provider_error import (
    CODE_CONFIG_INVALID_PARAMETER,
    ERROR_CONFIGURATION,
)

PROVIDER_CONTEXT_ALLOWLIST_RULE_VERSION = "r51-context-allowlist"
RULE_VERSION = PROVIDER_CONTEXT_ALLOWLIST_RULE_VERSION

MAX_CONTEXT_CHARS = 4000
MAX_SOURCE_REFS = 8
MAX_LEARNING_SIGNALS = 8
MAX_LIMITATIONS = 12
MAX_CODE_LEN = 80
MAX_SMALL_TEXT_LEN = 240

REQUEST_ALLOWED_KEYS: tuple[str, ...] = (
    "rule_version",
    "advisory_id",
    "advisory_mode",
    "provider_kind",
    "source_layer",
    "instruction",
    "sections",
    "source_refs",
    "limitations",
    "research_only",
    "deterministic",
)

SECTION_ALLOWED_KEYS: dict[str, tuple[str, ...]] = {
    "research_context": (
        "research_question",
        "research_focus",
        "context_fact_count",
        "source_layers",
        "research_only",
    ),
    "evaluation_summary": (
        "present",
        "reference_rule_version",
        "evaluated_agent_category",
        "overall_score",
        "overall_rating",
        "hard_gate_state",
        "safety_state",
        "diagnostic_count",
        "diagnostic_codes",
    ),
    "collaboration_summary": (
        "present",
        "reference_rule_version",
        "participant_count",
        "hypothesis_group_count",
        "conflict_count",
        "conflict_types",
        "merged_evidence_state",
        "governance_state",
        "provenance_state",
    ),
    "learning_signals": (),
    "governance_state": (),
    "safety_state": (),
}

LEARNING_SIGNAL_ALLOWED_KEYS: tuple[str, ...] = (
    "signal_type",
    "subject",
    "source_agent",
    "source_classification",
    "recommendation",
    "confidence",
    "research_only",
)

SOURCE_REF_ALLOWED_KEYS: tuple[str, ...] = ("layer", "reference")

# (reason code, pattern). Matched values are never returned.
SENSITIVE_RULES: tuple[tuple[str, re.Pattern], ...] = (
    ("CREDENTIAL_PATTERN", re.compile(r"\bsk-[A-Za-z0-9._\-]{6,}")),
    (
        "API_KEY_PATTERN",
        re.compile(r"(?i)\b(api[_-]?key|apikey)\b\s*[:=]"),
    ),
    (
        "AUTHORIZATION_PATTERN",
        re.compile(r"(?i)\bauthorization\b\s*[:=]"),
    ),
    (
        "BEARER_PATTERN",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"),
    ),
    ("COOKIE_PATTERN", re.compile(r"(?i)\b(set-)?cookie\b\s*[:=]")),
    (
        "SESSION_TOKEN_PATTERN",
        re.compile(
            r"(?i)\b(session|access|refresh|id)[_-]?token\b\s*[:=]"
        ),
    ),
    (
        "TOKEN_ASSIGNMENT_PATTERN",
        re.compile(r"(?i)\btoken\b\s*[:=]"),
    ),
    (
        "CREDENTIAL_ASSIGNMENT_PATTERN",
        re.compile(r"(?i)\b(password|passwd|secret)\b\s*[:=]"),
    ),
    (
        "PRIVATE_KEY_PATTERN",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ),
    ("URL_PATTERN", re.compile(r"https?://[^\s\"'<>]+")),
    (
        "PAYLOAD_PATTERN",
        re.compile(
            r"(?i)(<script\b|\bunion\s+select\b|\bor\s+1\s*=\s*1\b|\.\./\.\./)"
        ),
    ),
    ("CONTROL_CHAR_PATTERN", re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")),
)

SENSITIVE_REASON_CODES: tuple[str, ...] = tuple(
    code for code, _pattern in SENSITIVE_RULES
)


def _text(value: object, limit: int = MAX_SMALL_TEXT_LEN) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def detect_sensitive_content(value: object) -> list[str]:
    """Return reason codes for sensitive content in a projected context."""

    found: list[str] = []

    def walk(item: object) -> None:
        if len(found) >= len(SENSITIVE_REASON_CODES):
            return
        if isinstance(item, dict):
            for key, child in item.items():
                walk(str(key))
                walk(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                walk(child)
        elif isinstance(item, str):
            for code, pattern in SENSITIVE_RULES:
                if pattern.search(item) and code not in found:
                    found.append(code)

    walk(value)
    return found


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def _bounded_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _text(item, MAX_CODE_LEN).strip().upper()
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _reject_structural(message: str) -> None:
    raise ProviderCallError(
        ERROR_CONFIGURATION,
        CODE_CONFIG_INVALID_PARAMETER,
        retryable=False,
        attempts=0,
        safe_message=message,
    )


def _project_section(name: str, value: object) -> object:
    allowed = SECTION_ALLOWED_KEYS[name]
    if name in ("governance_state", "safety_state"):
        if not isinstance(value, str):
            _reject_structural(f"malformed advisory section: {name}")
        return _text(value, MAX_SMALL_TEXT_LEN).strip().upper()
    if name == "learning_signals":
        if isinstance(value, dict):
            raw_items = [value]
        elif isinstance(value, (list, tuple)):
            raw_items = list(value)
        else:
            _reject_structural("malformed advisory learning signals")
        out: list[dict] = []
        for item in raw_items:
            if not isinstance(item, dict):
                _reject_structural("malformed advisory learning signal")
            if set(item.keys()) - set(LEARNING_SIGNAL_ALLOWED_KEYS):
                _reject_structural(
                    "unexpected key in advisory learning signal"
                )
            bounded: dict = {}
            for key in LEARNING_SIGNAL_ALLOWED_KEYS:
                if key not in item:
                    continue
                child = item.get(key)
                if isinstance(child, bool):
                    bounded[key] = bool(child)
                elif isinstance(child, int):
                    bounded[key] = _bounded_int(child, 0, 10000)
                else:
                    bounded[key] = _text(
                        child,
                        MAX_ADVISORY_TEXT_LEN
                        if key == "recommendation"
                        else MAX_SMALL_TEXT_LEN,
                    )
            out.append(bounded)
            if len(out) >= MAX_LEARNING_SIGNALS:
                break
        return out
    if not isinstance(value, dict):
        _reject_structural(f"malformed advisory section: {name}")
    if set(value.keys()) - set(allowed):
        _reject_structural(f"unexpected key in advisory section: {name}")
    projected: dict = {}
    for key in allowed:
        if key not in value:
            continue
        child = value.get(key)
        if isinstance(child, bool):
            projected[key] = bool(child)
        elif isinstance(child, int):
            projected[key] = _bounded_int(child, 0, 10000)
        elif isinstance(child, (list, tuple)):
            projected[key] = [
                _text(entry, MAX_CODE_LEN).strip().upper()
                for entry in list(child)[:16]
                if _text(entry, MAX_CODE_LEN).strip()
            ]
        else:
            projected[key] = _text(
                child,
                MAX_ADVISORY_TEXT_LEN
                if key in ("research_question",)
                else MAX_SMALL_TEXT_LEN,
            )
    return projected


def sanitize_provider_context(request: object = None) -> dict:
    """Build the allowlisted, minimized outbound advisory context.

    Raises :class:`ProviderCallError` (CONFIGURATION_ERROR) for structural
    violations and :class:`ProviderContextRejected` (SAFETY_VALIDATION_
    ERROR) when sensitive content is detected. No value is ever rewritten.
    """

    if not isinstance(request, dict):
        _reject_structural("advisory request is malformed")
    if set(request.keys()) - set(REQUEST_ALLOWED_KEYS):
        _reject_structural("unexpected key in advisory request")

    advisory_id = _text(request.get("advisory_id"), 80)
    if advisory_id and not ADVISORY_ID_RE.match(advisory_id):
        _reject_structural("advisory_id is malformed")
    advisory_mode = _text(request.get("advisory_mode"), 40).strip().upper()
    if advisory_mode not in ADVISORY_MODES:
        _reject_structural("advisory_mode is invalid")
    source_layer = _text(request.get("source_layer"), 40).strip().upper()
    if source_layer not in LLM_ADVISORY_SOURCE_LAYERS:
        _reject_structural("source_layer is invalid")

    instruction = _text(request.get("instruction"), MAX_ADVISORY_TEXT_LEN)
    sections_value = request.get("sections")
    if not isinstance(sections_value, dict):
        _reject_structural("advisory sections are malformed")
    if set(sections_value.keys()) - set(SECTION_ALLOWED_KEYS):
        _reject_structural("unexpected advisory section")

    sections: dict = {}
    for name in SECTION_ALLOWED_KEYS:
        if name in sections_value:
            sections[name] = _project_section(
                name, sections_value.get(name)
            )

    refs: list[dict] = []
    raw_refs = request.get("source_refs")
    if raw_refs is not None and not isinstance(raw_refs, (list, tuple)):
        _reject_structural("source_refs are malformed")
    for item in raw_refs or ():
        if not isinstance(item, dict):
            _reject_structural("source reference is malformed")
        if set(item.keys()) - set(SOURCE_REF_ALLOWED_KEYS):
            _reject_structural("unexpected key in source reference")
        layer = _text(item.get("layer"), 40).strip().upper()
        if layer not in SOURCE_REF_LAYERS:
            _reject_structural("source reference layer is invalid")
        refs.append(
            {
                "layer": layer,
                "reference": _text(item.get("reference"), 40).strip().lower(),
            }
        )
        if len(refs) >= MAX_SOURCE_REFS:
            break

    limitations = _bounded_codes(
        request.get("limitations"),
        ADVISORY_INPUT_LIMITATIONS,
        MAX_LIMITATIONS,
    )

    context = {
        "advisory_id": advisory_id,
        "advisory_mode": advisory_mode,
        "source_layer": source_layer,
        "instruction": instruction,
        "sections": sections,
        "source_refs": refs,
        "limitations": limitations,
        "research_only": True,
    }

    reasons = detect_sensitive_content(context)
    if reasons:
        raise ProviderContextRejected(reason_codes=reasons)

    canonical = json.dumps(
        context, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    if len(canonical) > MAX_CONTEXT_CHARS:
        _reject_structural("advisory context exceeds the bounded size")

    crossing: list[str] = []
    for name in ("advisory_id", "advisory_mode", "source_layer",
                 "instruction"):
        crossing.append(name)
    for name in sorted(sections):
        crossing.append(f"sections.{name}")
    crossing.append("source_refs")
    crossing.append("limitations")
    return {
        "context": context,
        "crossing_fields": crossing,
        "context_chars": len(canonical),
    }


__all__ = [
    "PROVIDER_CONTEXT_ALLOWLIST_RULE_VERSION",
    "RULE_VERSION",
    "MAX_CONTEXT_CHARS",
    "REQUEST_ALLOWED_KEYS",
    "SECTION_ALLOWED_KEYS",
    "LEARNING_SIGNAL_ALLOWED_KEYS",
    "SOURCE_REF_ALLOWED_KEYS",
    "SENSITIVE_RULES",
    "SENSITIVE_REASON_CODES",
    "detect_sensitive_content",
    "sanitize_provider_context",
]
