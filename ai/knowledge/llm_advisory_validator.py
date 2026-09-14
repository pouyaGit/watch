"""Stage R45.6 deterministic advisory response validator (pure engine).

Validates provider/advisory output against the R45 safety contract:

    "Is this advisory output safe to present as an explanation?"

Hard boundaries encoded here:

- Reject, never sanitize: forbidden output categories are rejected while the
  diagnostic state is preserved. The validator never rewrites unsafe content
  into apparently safe content.
- Forbidden output categories: vulnerability confirmation, exploitation
  success, execution instructions, payload content, authentication bypass and
  attack sequences.
- Structural validation: required fields, allowed modes, mode/identity
  agreement with the request, source-reference provenance and bounded
  deterministic text.
- Pure and offline: no I/O, no network, no provider call, no LLM, no Mongo,
  no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import re

from ai.schemas.llm_advisory_input import ADVISORY_SAFETY_STATES
from ai.schemas.llm_advisory_policy import (
    ADVISORY_MODES,
    FORBIDDEN_ADVISORY_MODES,
    MAX_ADVISORY_TEXT_LEN,
)
from ai.schemas.llm_advisory_result import (
    MAX_DIAGNOSTICS,
    VALIDATION_PASS,
    VALIDATION_REJECTED,
)
from ai.schemas.llm_provider import SUPPORTED_PROVIDER_KINDS

LLM_ADVISORY_VALIDATOR_RULE_VERSION = "r45-6"
RULE_VERSION = LLM_ADVISORY_VALIDATOR_RULE_VERSION

# ---------------------------------------------------------------------------
# Violation taxonomy
# ---------------------------------------------------------------------------

CATEGORY_STRUCTURE = "STRUCTURE"
CATEGORY_SAFETY = "SAFETY"
CATEGORY_CONTENT = "CONTENT"
CATEGORY_PROVENANCE = "PROVENANCE"
CATEGORY_DETERMINISM = "DETERMINISM"

VIOLATION_CATEGORIES: tuple[str, ...] = (
    CATEGORY_STRUCTURE,
    CATEGORY_SAFETY,
    CATEGORY_CONTENT,
    CATEGORY_PROVENANCE,
    CATEGORY_DETERMINISM,
)

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"

VIOLATION_SEVERITIES: tuple[str, ...] = (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)

VIOLATION_MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
VIOLATION_INVALID_ADVISORY_MODE = "INVALID_ADVISORY_MODE"
VIOLATION_FORBIDDEN_ADVISORY_MODE = "FORBIDDEN_ADVISORY_MODE"
VIOLATION_VULNERABILITY_CONFIRMATION = "VULNERABILITY_CONFIRMATION_CLAIM"
VIOLATION_EXPLOIT_CONFIRMATION = "EXPLOIT_CONFIRMATION_CLAIM"
VIOLATION_EXECUTION_INSTRUCTION = "EXECUTION_INSTRUCTION"
VIOLATION_PAYLOAD_CONTENT = "PAYLOAD_CONTENT"
VIOLATION_ATTACK_PLANNING = "ATTACK_PLANNING"
VIOLATION_EXPLOITATION_GUIDANCE = "EXPLOITATION_GUIDANCE"
VIOLATION_RESEARCH_ONLY_FALSE = "RESEARCH_ONLY_FALSE"
VIOLATION_NON_DETERMINISTIC_OUTPUT = "NON_DETERMINISTIC_OUTPUT"
VIOLATION_MODE_MISMATCH = "ADVISORY_MODE_MISMATCH"
VIOLATION_IDENTITY_MISMATCH = "ADVISORY_ID_MISMATCH"
VIOLATION_UNKNOWN_SOURCE_REFERENCE = "UNKNOWN_SOURCE_REFERENCE"
VIOLATION_UNBOUNDED_TEXT = "UNBOUNDED_TEXT"
VIOLATION_UNSUPPORTED_PROVIDER_KIND = "UNSUPPORTED_PROVIDER_KIND"
VIOLATION_REJECTED_CONTENT_PRESENT = "REJECTED_CONTENT_PRESENT"
VIOLATION_MISSING_DIAGNOSTICS = "MISSING_DIAGNOSTICS"

VIOLATION_CODES: tuple[str, ...] = (
    VIOLATION_MISSING_REQUIRED_FIELD,
    VIOLATION_INVALID_ADVISORY_MODE,
    VIOLATION_FORBIDDEN_ADVISORY_MODE,
    VIOLATION_VULNERABILITY_CONFIRMATION,
    VIOLATION_EXPLOIT_CONFIRMATION,
    VIOLATION_EXECUTION_INSTRUCTION,
    VIOLATION_PAYLOAD_CONTENT,
    VIOLATION_ATTACK_PLANNING,
    VIOLATION_EXPLOITATION_GUIDANCE,
    VIOLATION_RESEARCH_ONLY_FALSE,
    VIOLATION_NON_DETERMINISTIC_OUTPUT,
    VIOLATION_MODE_MISMATCH,
    VIOLATION_IDENTITY_MISMATCH,
    VIOLATION_UNKNOWN_SOURCE_REFERENCE,
    VIOLATION_UNBOUNDED_TEXT,
    VIOLATION_UNSUPPORTED_PROVIDER_KIND,
    VIOLATION_REJECTED_CONTENT_PRESENT,
    VIOLATION_MISSING_DIAGNOSTICS,
)

MAX_VIOLATIONS = MAX_DIAGNOSTICS

# ---------------------------------------------------------------------------
# Forbidden claim detection (reject, never sanitize)
# ---------------------------------------------------------------------------

FORBIDDEN_CLAIM_RULES: tuple[tuple[str, str, tuple], ...] = (
    (
        CATEGORY_SAFETY,
        VIOLATION_VULNERABILITY_CONFIRMATION,
        (
            re.compile(
                r"\b(vulnerability|vulnerabilities|flaw|bug)\s+"
                r"(is\s+|was\s+|has\s+been\s+)?"
                r"(confirmed|verified|proven)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\bconfirmed\s+(vulnerability|vulnerabilities|flaw|bug)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        CATEGORY_SAFETY,
        VIOLATION_EXPLOIT_CONFIRMATION,
        (
            re.compile(
                r"\bexploitation\s+(was\s+|is\s+)?"
                r"(successful|succeeded|success)\b",
                re.IGNORECASE,
            ),
            re.compile(r"\bsuccessfully\s+exploited\b", re.IGNORECASE),
            re.compile(
                r"\bexploit\s+(was\s+|is\s+)?"
                r"(successful|succeeded|success)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        CATEGORY_CONTENT,
        VIOLATION_EXECUTION_INSTRUCTION,
        (
            re.compile(
                r"\b(execute|run|launch)\s+(this|the|following)\s+"
                r"(command|script|code|program|binary|tool)\b",
                re.IGNORECASE,
            ),
            re.compile(r"\bshell\s+command\b", re.IGNORECASE),
            re.compile(
                r"\b(curl|wget|nc|netcat)\s+(-{1,2}\w+\s+)*"
                r"https?://",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        CATEGORY_CONTENT,
        VIOLATION_PAYLOAD_CONTENT,
        (
            re.compile(
                r"\b(send|inject|submit|deliver|try|use)\s+"
                r"(this|the|following)\s+payload\b",
                re.IGNORECASE,
            ),
            re.compile(r"\bpayload\s*[:=]\s*\S", re.IGNORECASE),
            re.compile(r"<script\b", re.IGNORECASE),
            re.compile(r"\bunion\s+select\b", re.IGNORECASE),
            re.compile(r"\bor\s+1\s*=\s*1\b", re.IGNORECASE),
            re.compile(r"\.\./\.\./"),
        ),
    ),
    (
        CATEGORY_SAFETY,
        VIOLATION_ATTACK_PLANNING,
        (
            re.compile(
                r"\battack\s+(plan|sequence|steps|chain)\b", re.IGNORECASE
            ),
            re.compile(
                r"\bbypass\s+(authentication|auth|login)\b", re.IGNORECASE
            ),
            re.compile(
                r"\b(steal|exfiltrate)\s+(credentials|data|tokens)\b",
                re.IGNORECASE,
            ),
            re.compile(r"\bprivilege\s+escalation\b", re.IGNORECASE),
            re.compile(
                r"\bgain\s+(unauthorized|admin(?:istrative)?|root)\s+"
                r"access\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\bstep\s*1\s*:\s*(exploit|attack|inject|send)",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        CATEGORY_CONTENT,
        VIOLATION_EXPLOITATION_GUIDANCE,
        (
            re.compile(
                r"\b(build|craft|create|generate|write)\s+"
                r"(an?\s+)?(exploit|payload|shellcode)\b",
                re.IGNORECASE,
            ),
            re.compile(r"\b(sqlmap|nuclei)\b", re.IGNORECASE),
        ),
    ),
)

NONDETERMINISTIC_KEY_TOKENS: tuple[str, ...] = (
    "timestamp",
    "created_at",
    "updated_at",
    "started_at",
    "finished_at",
    "generated_at",
    "runtime_id",
    "nonce",
    "uuid",
    "random",
)

RESPONSE_REQUIRED_FIELDS: tuple[str, ...] = (
    "rule_version",
    "provider_kind",
    "advisory_id",
    "advisory_mode",
    "summary",
    "insights",
    "recommendations",
    "source_refs",
    "research_only",
    "deterministic",
)

RESULT_REQUIRED_FIELDS: tuple[str, ...] = (
    "rule_version",
    "advisory_rule_version",
    "advisory_id",
    "advisory_mode",
    "summary",
    "insights",
    "recommendations",
    "limitations",
    "safety_state",
    "validation_state",
    "research_only",
    "deterministic",
)


class AdvisoryValidationError(ValueError):
    """Raised for a rejected advisory response with preserved diagnostics."""

    def __init__(self, message: str, validation: dict | None = None):
        super().__init__(message)
        self.validation = validation or {}


def _violation(
    violation_code: str,
    category: str,
    severity: str,
    field: str,
) -> dict:
    return {
        "rule_version": LLM_ADVISORY_VALIDATOR_RULE_VERSION,
        "violation_code": violation_code,
        "category": category,
        "severity": severity,
        "field": field,
    }


def _has_nondeterministic_keys(value: object, depth: int = 0) -> bool:
    if depth > 4:
        return False
    if isinstance(value, dict):
        for key, child in value.items():
            name = str(key).lower()
            if any(token in name for token in NONDETERMINISTIC_KEY_TOKENS):
                return True
            if _has_nondeterministic_keys(child, depth + 1):
                return True
    elif isinstance(value, (list, tuple)):
        for item in list(value)[:32]:
            if _has_nondeterministic_keys(item, depth + 1):
                return True
    return False


def _text_fields(response: object):
    if not isinstance(response, dict):
        return
    summary = response.get("summary")
    if isinstance(summary, str):
        yield "summary", summary
    for index, item in enumerate(response.get("insights") or ()):
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            yield f"insights[{index}].text", item["text"]
    for index, item in enumerate(response.get("recommendations") or ()):
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            yield f"recommendations[{index}].text", item["text"]


def detect_forbidden_claims(text: object) -> list[tuple[str, str]]:
    """Return (violation_code, category) pairs detected in text."""

    value = str(text if text is not None else "")
    if not value:
        return []
    found: list[tuple[str, str]] = []
    for category, code, patterns in FORBIDDEN_CLAIM_RULES:
        for pattern in patterns:
            if pattern.search(value):
                if (code, category) not in found:
                    found.append((code, category))
                break
    return found


def _validate_text_content(response: object) -> list[dict]:
    violations: list[dict] = []
    for field, text in _text_fields(response):
        if len(text) > MAX_ADVISORY_TEXT_LEN:
            violations.append(
                _violation(
                    VIOLATION_UNBOUNDED_TEXT,
                    CATEGORY_STRUCTURE,
                    SEVERITY_MEDIUM,
                    field,
                )
            )
        for code, category in detect_forbidden_claims(text):
            severity = (
                SEVERITY_CRITICAL
                if category == CATEGORY_SAFETY
                else SEVERITY_HIGH
            )
            violations.append(
                _violation(code, category, severity, field)
            )
    return violations


def _validation_result(response: object, violations: list[dict]) -> dict:
    bounded = violations[:MAX_VIOLATIONS]
    state = VALIDATION_PASS if not bounded else VALIDATION_REJECTED
    advisory_id = ""
    if isinstance(response, dict):
        advisory_id = str(response.get("advisory_id") or "")
    return {
        "rule_version": LLM_ADVISORY_VALIDATOR_RULE_VERSION,
        "advisory_id": advisory_id,
        "validation_state": state,
        "violations": bounded,
        "violation_count": len(bounded),
        "deterministic": True,
        "research_only": True,
    }


def _reference_keys(value: object) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    if not isinstance(value, (list, tuple)):
        return keys
    for item in value:
        if isinstance(item, dict):
            keys.add(
                (
                    str(item.get("layer") or ""),
                    str(item.get("reference") or ""),
                )
            )
    return keys


def validate_advisory_response(
    response: object = None, request: object = None
) -> dict:
    """Validate a provider response (read-only, deterministic)."""

    if not isinstance(response, dict):
        return _validation_result(
            response,
            [
                _violation(
                    VIOLATION_MISSING_REQUIRED_FIELD,
                    CATEGORY_STRUCTURE,
                    SEVERITY_HIGH,
                    "response",
                )
            ],
        )

    violations: list[dict] = []

    for field in RESPONSE_REQUIRED_FIELDS:
        if field not in response:
            violations.append(
                _violation(
                    VIOLATION_MISSING_REQUIRED_FIELD,
                    CATEGORY_STRUCTURE,
                    SEVERITY_HIGH,
                    field,
                )
            )

    if "summary" in response and not isinstance(response.get("summary"), str):
        violations.append(
            _violation(
                VIOLATION_MISSING_REQUIRED_FIELD,
                CATEGORY_STRUCTURE,
                SEVERITY_HIGH,
                "summary",
            )
        )
    for field in ("insights", "recommendations", "source_refs"):
        if field in response and not isinstance(response.get(field), list):
            violations.append(
                _violation(
                    VIOLATION_MISSING_REQUIRED_FIELD,
                    CATEGORY_STRUCTURE,
                    SEVERITY_HIGH,
                    field,
                )
            )

    mode = str(response.get("advisory_mode") or "").strip().upper()
    if mode in FORBIDDEN_ADVISORY_MODES:
        violations.append(
            _violation(
                VIOLATION_FORBIDDEN_ADVISORY_MODE,
                CATEGORY_SAFETY,
                SEVERITY_CRITICAL,
                "advisory_mode",
            )
        )
    elif mode not in ADVISORY_MODES:
        violations.append(
            _violation(
                VIOLATION_INVALID_ADVISORY_MODE,
                CATEGORY_STRUCTURE,
                SEVERITY_HIGH,
                "advisory_mode",
            )
        )

    provider_kind = str(response.get("provider_kind") or "").strip().upper()
    if provider_kind not in SUPPORTED_PROVIDER_KINDS:
        violations.append(
            _violation(
                VIOLATION_UNSUPPORTED_PROVIDER_KIND,
                CATEGORY_STRUCTURE,
                SEVERITY_HIGH,
                "provider_kind",
            )
        )

    if response.get("research_only") is not True:
        violations.append(
            _violation(
                VIOLATION_RESEARCH_ONLY_FALSE,
                CATEGORY_SAFETY,
                SEVERITY_CRITICAL,
                "research_only",
            )
        )
    if response.get("deterministic") is not True:
        violations.append(
            _violation(
                VIOLATION_NON_DETERMINISTIC_OUTPUT,
                CATEGORY_DETERMINISM,
                SEVERITY_HIGH,
                "deterministic",
            )
        )

    if isinstance(request, dict):
        request_mode = str(request.get("advisory_mode") or "").strip().upper()
        if request_mode and mode != request_mode:
            violations.append(
                _violation(
                    VIOLATION_MODE_MISMATCH,
                    CATEGORY_STRUCTURE,
                    SEVERITY_HIGH,
                    "advisory_mode",
                )
            )
        request_id = str(request.get("advisory_id") or "")
        response_id = str(response.get("advisory_id") or "")
        if request_id and response_id != request_id:
            violations.append(
                _violation(
                    VIOLATION_IDENTITY_MISMATCH,
                    CATEGORY_PROVENANCE,
                    SEVERITY_MEDIUM,
                    "advisory_id",
                )
            )
        allowed_refs = _reference_keys(request.get("source_refs"))
        response_refs = _reference_keys(response.get("source_refs"))
        for layer, reference in sorted(response_refs):
            if (layer, reference) not in allowed_refs:
                violations.append(
                    _violation(
                        VIOLATION_UNKNOWN_SOURCE_REFERENCE,
                        CATEGORY_PROVENANCE,
                        SEVERITY_HIGH,
                        "source_refs",
                    )
                )
                break

    if _has_nondeterministic_keys(response):
        violations.append(
            _violation(
                VIOLATION_NON_DETERMINISTIC_OUTPUT,
                CATEGORY_DETERMINISM,
                SEVERITY_HIGH,
                "response",
            )
        )

    violations.extend(_validate_text_content(response))

    return _validation_result(response, violations)


def validate_advisory_result(result: object = None) -> dict:
    """Validate an assembled advisory result contract (read-only)."""

    if not isinstance(result, dict):
        return _validation_result(
            result,
            [
                _violation(
                    VIOLATION_MISSING_REQUIRED_FIELD,
                    CATEGORY_STRUCTURE,
                    SEVERITY_HIGH,
                    "result",
                )
            ],
        )

    violations: list[dict] = []
    for field in RESULT_REQUIRED_FIELDS:
        if field not in result:
            violations.append(
                _violation(
                    VIOLATION_MISSING_REQUIRED_FIELD,
                    CATEGORY_STRUCTURE,
                    SEVERITY_HIGH,
                    field,
                )
            )

    mode = str(result.get("advisory_mode") or "").strip().upper()
    if mode not in ADVISORY_MODES:
        violations.append(
            _violation(
                VIOLATION_INVALID_ADVISORY_MODE,
                CATEGORY_STRUCTURE,
                SEVERITY_HIGH,
                "advisory_mode",
            )
        )

    safety_state = str(result.get("safety_state") or "").strip().upper()
    if safety_state not in ADVISORY_SAFETY_STATES:
        violations.append(
            _violation(
                VIOLATION_MISSING_REQUIRED_FIELD,
                CATEGORY_STRUCTURE,
                SEVERITY_HIGH,
                "safety_state",
            )
        )

    if result.get("research_only") is not True:
        violations.append(
            _violation(
                VIOLATION_RESEARCH_ONLY_FALSE,
                CATEGORY_SAFETY,
                SEVERITY_CRITICAL,
                "research_only",
            )
        )
    if result.get("deterministic") is not True:
        violations.append(
            _violation(
                VIOLATION_NON_DETERMINISTIC_OUTPUT,
                CATEGORY_DETERMINISM,
                SEVERITY_HIGH,
                "deterministic",
            )
        )

    validation_state = result.get("validation_state")
    if validation_state == VALIDATION_REJECTED:
        if (
            result.get("summary")
            or result.get("insights")
            or result.get("recommendations")
        ):
            violations.append(
                _violation(
                    VIOLATION_REJECTED_CONTENT_PRESENT,
                    CATEGORY_SAFETY,
                    SEVERITY_CRITICAL,
                    "validation_state",
                )
            )
        if not result.get("validation_diagnostics"):
            violations.append(
                _violation(
                    VIOLATION_MISSING_DIAGNOSTICS,
                    CATEGORY_STRUCTURE,
                    SEVERITY_HIGH,
                    "validation_diagnostics",
                )
            )

    if _has_nondeterministic_keys(result):
        violations.append(
            _violation(
                VIOLATION_NON_DETERMINISTIC_OUTPUT,
                CATEGORY_DETERMINISM,
                SEVERITY_HIGH,
                "result",
            )
        )

    violations.extend(_validate_text_content(result))

    return _validation_result(result, violations)


def require_valid_advisory_response(
    response: object = None, request: object = None
) -> dict:
    """Validate a response and raise with preserved diagnostics if rejected."""

    validation = validate_advisory_response(response, request)
    if validation["validation_state"] == VALIDATION_REJECTED:
        raise AdvisoryValidationError(
            "advisory response rejected: "
            + ", ".join(
                violation["violation_code"]
                for violation in validation["violations"]
            ),
            validation,
        )
    return validation


def advisory_safety_state(
    input_safety_state: object = None, validation: object = None
) -> str:
    """Derive the deterministic advisory safety state."""

    result = validation if isinstance(validation, dict) else {}
    if result.get("validation_state") == VALIDATION_REJECTED:
        return "FAILED"
    state = str(
        input_safety_state if input_safety_state is not None else ""
    ).strip().upper()
    if state == "FAILED":
        return "FAILED"
    if state == "DEGRADED":
        return "DEGRADED"
    return "PASS"


__all__ = [
    "LLM_ADVISORY_VALIDATOR_RULE_VERSION",
    "RULE_VERSION",
    "VIOLATION_CATEGORIES",
    "VIOLATION_SEVERITIES",
    "CATEGORY_STRUCTURE",
    "CATEGORY_SAFETY",
    "CATEGORY_CONTENT",
    "CATEGORY_PROVENANCE",
    "CATEGORY_DETERMINISM",
    "SEVERITY_CRITICAL",
    "SEVERITY_HIGH",
    "SEVERITY_MEDIUM",
    "VIOLATION_CODES",
    "VIOLATION_MISSING_REQUIRED_FIELD",
    "VIOLATION_INVALID_ADVISORY_MODE",
    "VIOLATION_FORBIDDEN_ADVISORY_MODE",
    "VIOLATION_VULNERABILITY_CONFIRMATION",
    "VIOLATION_EXPLOIT_CONFIRMATION",
    "VIOLATION_EXECUTION_INSTRUCTION",
    "VIOLATION_PAYLOAD_CONTENT",
    "VIOLATION_ATTACK_PLANNING",
    "VIOLATION_EXPLOITATION_GUIDANCE",
    "VIOLATION_RESEARCH_ONLY_FALSE",
    "VIOLATION_NON_DETERMINISTIC_OUTPUT",
    "VIOLATION_MODE_MISMATCH",
    "VIOLATION_IDENTITY_MISMATCH",
    "VIOLATION_UNKNOWN_SOURCE_REFERENCE",
    "VIOLATION_UNBOUNDED_TEXT",
    "VIOLATION_UNSUPPORTED_PROVIDER_KIND",
    "VIOLATION_REJECTED_CONTENT_PRESENT",
    "VIOLATION_MISSING_DIAGNOSTICS",
    "FORBIDDEN_CLAIM_RULES",
    "NONDETERMINISTIC_KEY_TOKENS",
    "RESPONSE_REQUIRED_FIELDS",
    "RESULT_REQUIRED_FIELDS",
    "MAX_VIOLATIONS",
    "AdvisoryValidationError",
    "detect_forbidden_claims",
    "validate_advisory_response",
    "validate_advisory_result",
    "require_valid_advisory_response",
    "advisory_safety_state",
]
