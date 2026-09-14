"""Agent orchestration policy schema (Stage R52.3).

An :class:`AgentOrchestrationPolicyPlan` is the explicit, bounded execution
policy contract of the orchestrator. It answers the orchestration question:

    "Which coordination steps may run, with which bounds?"

Hard boundaries encoded here:

- Orchestration/model only: the policy is declarative data. It contains no
  executable instructions, no callables, no scripts and no dynamic values.
- Fail closed: every value is validated against a closed vocabulary or an
  explicit numeric bound. An invalid policy can never widen orchestration.
- No recursion: ``max_orchestration_depth`` is fixed at ``1``; R52 never
  invokes itself.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

from ai.schemas.llm_advisory_policy import ADVISORY_MODES, DEFAULT_ADVISORY_MODE
from ai.schemas.llm_provider import (
    PROVIDER_KIND_MOCK,
    SUPPORTED_PROVIDER_KINDS,
)
from ai.schemas.security_agent_identity import (
    AGENT_CATEGORIES,
    CATEGORY_UNKNOWN,
)

AGENT_ORCHESTRATOR_POLICY_RULE_VERSION = "r52-3"
RULE_VERSION = AGENT_ORCHESTRATOR_POLICY_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

MODE_AUTOMATIC = "AUTOMATIC"
MODE_EXPLICIT = "EXPLICIT"

SELECTION_MODES: tuple[str, ...] = (
    MODE_AUTOMATIC,
    MODE_EXPLICIT,
)

MAX_SPECIALISTS_MIN = 1
MAX_SPECIALISTS_MAX = 8
DEFAULT_MAX_SPECIALISTS = MAX_SPECIALISTS_MAX

MAX_HYPOTHESES_MIN = 1
MAX_HYPOTHESES_MAX = 256
DEFAULT_MAX_HYPOTHESES = 192

MAX_EVIDENCE_ITEMS_MIN = 1
MAX_EVIDENCE_ITEMS_MAX = 512
DEFAULT_MAX_EVIDENCE_ITEMS = 256

MAX_ADVISORY_REQUESTS_MIN = 0
MAX_ADVISORY_REQUESTS_MAX = 1
DEFAULT_MAX_ADVISORY_REQUESTS = 1

MAX_ORCHESTRATION_STAGES_MIN = 1
MAX_ORCHESTRATION_STAGES_MAX = 8
DEFAULT_MAX_ORCHESTRATION_STAGES = 6

#: Recursive orchestration is impossible by policy: depth is fixed at 1.
MAX_ORCHESTRATION_DEPTH = 1

MAX_VALUE_LEN = 160

_BOUNDED_INT_FIELDS: dict[str, tuple[int, int]] = {
    "max_specialists": (MAX_SPECIALISTS_MIN, MAX_SPECIALISTS_MAX),
    "max_hypotheses_processed": (
        MAX_HYPOTHESES_MIN,
        MAX_HYPOTHESES_MAX,
    ),
    "max_evidence_items_processed": (
        MAX_EVIDENCE_ITEMS_MIN,
        MAX_EVIDENCE_ITEMS_MAX,
    ),
    "max_advisory_requests": (
        MAX_ADVISORY_REQUESTS_MIN,
        MAX_ADVISORY_REQUESTS_MAX,
    ),
    "max_orchestration_stages": (
        MAX_ORCHESTRATION_STAGES_MIN,
        MAX_ORCHESTRATION_STAGES_MAX,
    ),
}

_BOOLEAN_FIELDS: tuple[str, ...] = (
    "continue_on_specialist_error",
    "evaluate_results",
    "collaborate_results",
    "generate_feedback",
    "advisory_enabled",
)

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _bounded_int(value: object, minimum: int, maximum: int, fallback: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return fallback
    return max(minimum, min(maximum, value))


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def sanitize_orchestration_policy(value: object) -> dict:
    """Project a policy onto its fixed bounded key set (never raises).

    Invalid values degrade to safe closed defaults; the orchestrator uses
    :func:`validate_orchestration_policy` to fail closed instead of silently
    accepting a degraded policy.
    """

    if not isinstance(value, dict):
        value = {}
    categories: list[str] = []
    for item in value.get("allowed_categories") or ():
        text = _safe_text(item).strip().upper()
        if (
            text in AGENT_CATEGORIES
            and text != CATEGORY_UNKNOWN
            and text not in categories
        ):
            categories.append(text)
    mode = _closed(value.get("mode"), SELECTION_MODES, MODE_AUTOMATIC)
    if mode == MODE_AUTOMATIC:
        categories = []
    advisory_mode = _closed(
        value.get("advisory_mode"), ADVISORY_MODES, DEFAULT_ADVISORY_MODE
    )
    provider_kind = _closed(
        value.get("advisory_provider_kind"),
        SUPPORTED_PROVIDER_KINDS,
        PROVIDER_KIND_MOCK,
    )
    return {
        "rule_version": AGENT_ORCHESTRATOR_POLICY_RULE_VERSION,
        "mode": mode,
        "allowed_categories": categories,
        "max_specialists": _bounded_int(
            value.get("max_specialists"),
            MAX_SPECIALISTS_MIN,
            MAX_SPECIALISTS_MAX,
            DEFAULT_MAX_SPECIALISTS,
        ),
        "continue_on_specialist_error": (
            bool(value.get("continue_on_specialist_error", True)) is True
        ),
        "evaluate_results": bool(value.get("evaluate_results", True)) is True,
        "collaborate_results": (
            bool(value.get("collaborate_results", True)) is True
        ),
        "generate_feedback": (
            bool(value.get("generate_feedback", True)) is True
        ),
        "advisory_enabled": bool(value.get("advisory_enabled", False)) is True,
        "advisory_mode": advisory_mode,
        "advisory_provider_kind": provider_kind,
        "max_advisory_requests": _bounded_int(
            value.get("max_advisory_requests"),
            MAX_ADVISORY_REQUESTS_MIN,
            MAX_ADVISORY_REQUESTS_MAX,
            DEFAULT_MAX_ADVISORY_REQUESTS,
        ),
        "max_hypotheses_processed": _bounded_int(
            value.get("max_hypotheses_processed"),
            MAX_HYPOTHESES_MIN,
            MAX_HYPOTHESES_MAX,
            DEFAULT_MAX_HYPOTHESES,
        ),
        "max_evidence_items_processed": _bounded_int(
            value.get("max_evidence_items_processed"),
            MAX_EVIDENCE_ITEMS_MIN,
            MAX_EVIDENCE_ITEMS_MAX,
            DEFAULT_MAX_EVIDENCE_ITEMS,
        ),
        "max_orchestration_stages": _bounded_int(
            value.get("max_orchestration_stages"),
            MAX_ORCHESTRATION_STAGES_MIN,
            MAX_ORCHESTRATION_STAGES_MAX,
            DEFAULT_MAX_ORCHESTRATION_STAGES,
        ),
        "max_orchestration_depth": MAX_ORCHESTRATION_DEPTH,
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class AgentOrchestrationPolicyPlan(BaseModel):
    """Explicit bounded orchestration policy (R52.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = AGENT_ORCHESTRATOR_POLICY_RULE_VERSION
    mode: str = MODE_AUTOMATIC
    allowed_categories: list[str] = []
    max_specialists: int = DEFAULT_MAX_SPECIALISTS
    continue_on_specialist_error: bool = True
    evaluate_results: bool = True
    collaborate_results: bool = True
    generate_feedback: bool = True
    advisory_enabled: bool = False
    advisory_mode: str = DEFAULT_ADVISORY_MODE
    advisory_provider_kind: str = PROVIDER_KIND_MOCK
    max_advisory_requests: int = DEFAULT_MAX_ADVISORY_REQUESTS
    max_hypotheses_processed: int = DEFAULT_MAX_HYPOTHESES
    max_evidence_items_processed: int = DEFAULT_MAX_EVIDENCE_ITEMS
    max_orchestration_stages: int = DEFAULT_MAX_ORCHESTRATION_STAGES
    max_orchestration_depth: int = MAX_ORCHESTRATION_DEPTH
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return AGENT_ORCHESTRATOR_POLICY_RULE_VERSION

    @field_validator("mode")
    @classmethod
    def _valid_mode(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SELECTION_MODES:
            raise ValueError(f"invalid orchestration mode: {value!r}")
        return text

    @field_validator("allowed_categories")
    @classmethod
    def _valid_categories(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item).strip().upper()
            if not text:
                raise ValueError(f"invalid allowed category: {item!r}")
            if text not in AGENT_CATEGORIES or text == CATEGORY_UNKNOWN:
                raise ValueError(f"unknown specialist category: {item!r}")
            if text not in out:
                out.append(text)
        return out

    @field_validator(
        "max_specialists",
    )
    @classmethod
    def _valid_max_specialists(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid max_specialists: {value!r}")
        if not (MAX_SPECIALISTS_MIN <= value <= MAX_SPECIALISTS_MAX):
            raise ValueError(f"max_specialists out of bounds: {value!r}")
        return value

    @field_validator("max_hypotheses_processed")
    @classmethod
    def _valid_max_hypotheses(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid max_hypotheses_processed: {value!r}")
        if not (MAX_HYPOTHESES_MIN <= value <= MAX_HYPOTHESES_MAX):
            raise ValueError(
                f"max_hypotheses_processed out of bounds: {value!r}"
            )
        return value

    @field_validator("max_evidence_items_processed")
    @classmethod
    def _valid_max_evidence(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                f"invalid max_evidence_items_processed: {value!r}"
            )
        if not (MAX_EVIDENCE_ITEMS_MIN <= value <= MAX_EVIDENCE_ITEMS_MAX):
            raise ValueError(
                f"max_evidence_items_processed out of bounds: {value!r}"
            )
        return value

    @field_validator("max_advisory_requests")
    @classmethod
    def _valid_max_advisory(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid max_advisory_requests: {value!r}")
        if not (MAX_ADVISORY_REQUESTS_MIN <= value
                <= MAX_ADVISORY_REQUESTS_MAX):
            raise ValueError(
                f"max_advisory_requests out of bounds: {value!r}"
            )
        return value

    @field_validator("max_orchestration_stages")
    @classmethod
    def _valid_max_stages(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid max_orchestration_stages: {value!r}")
        if not (MAX_ORCHESTRATION_STAGES_MIN <= value
                <= MAX_ORCHESTRATION_STAGES_MAX):
            raise ValueError(
                f"max_orchestration_stages out of bounds: {value!r}"
            )
        return value

    @field_validator("max_orchestration_depth")
    @classmethod
    def _fixed_depth(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid max_orchestration_depth: {value!r}")
        if value != MAX_ORCHESTRATION_DEPTH:
            raise ValueError(
                "recursive orchestration is not permitted; depth must be 1"
            )
        return MAX_ORCHESTRATION_DEPTH

    @field_validator("advisory_mode")
    @classmethod
    def _valid_advisory_mode(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ADVISORY_MODES:
            raise ValueError(f"invalid advisory_mode: {value!r}")
        return text

    @field_validator("advisory_provider_kind")
    @classmethod
    def _valid_provider_kind(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SUPPORTED_PROVIDER_KINDS:
            raise ValueError(f"invalid advisory_provider_kind: {value!r}")
        return text

    @field_validator(
        "continue_on_specialist_error",
        "evaluate_results",
        "collaborate_results",
        "generate_feedback",
        "advisory_enabled",
    )
    @classmethod
    def _valid_booleans(cls, value: object) -> bool:
        if not isinstance(value, bool):
            raise ValueError(f"invalid boolean policy value: {value!r}")
        return value

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("orchestration policies are research-only")
        return True


def validate_orchestration_policy(value: object = None) -> dict:
    """Validate and project a policy, failing closed on any invalid value.

    Raises ``ValueError`` when the policy is malformed, references an unknown
    category, violates a bound, enables advisory without an advisory request
    budget or requests recursive orchestration.
    """

    projected = sanitize_orchestration_policy(value)
    source = value if isinstance(value, dict) else {}

    # Fail closed on silently-ignored or malformed caller intent.
    raw_categories = source.get("allowed_categories")
    if raw_categories is not None:
        if not isinstance(raw_categories, (list, tuple)):
            raise ValueError("allowed_categories must be a list")
        for item in raw_categories:
            text = _safe_text(item).strip().upper()
            if item in (None, "") or text not in AGENT_CATEGORIES or (
                text == CATEGORY_UNKNOWN
            ):
                raise ValueError(f"unknown specialist category: {item!r}")
    raw_mode = source.get("mode")
    if raw_mode is not None and (
        not isinstance(raw_mode, str)
        or raw_mode.strip().upper() not in SELECTION_MODES
    ):
        raise ValueError(f"invalid orchestration mode: {raw_mode!r}")
    raw_resolved_mode = (
        raw_mode.strip().upper()
        if isinstance(raw_mode, str)
        else MODE_AUTOMATIC
    )
    if raw_resolved_mode != MODE_EXPLICIT:
        raw_categories = source.get("allowed_categories")
        if isinstance(raw_categories, (list, tuple)) and raw_categories:
            raise ValueError(
                "automatic mode must not declare explicit allowed_categories"
            )
    raw_depth = source.get("max_orchestration_depth")
    if raw_depth is not None and raw_depth != MAX_ORCHESTRATION_DEPTH:
        raise ValueError(
            "recursive orchestration is not permitted; depth must be 1"
        )
    for field, (minimum, maximum) in _BOUNDED_INT_FIELDS.items():
        if field not in source or source[field] is None:
            continue
        raw_value = source[field]
        if isinstance(raw_value, bool) or not isinstance(raw_value, int):
            raise ValueError(f"invalid {field}: {raw_value!r}")
        if not (minimum <= raw_value <= maximum):
            raise ValueError(f"{field} out of bounds: {raw_value!r}")
    for field in _BOOLEAN_FIELDS:
        if field in source and source[field] is not None and (
            not isinstance(source[field], bool)
        ):
            raise ValueError(f"invalid boolean policy value: {source[field]!r}")
    for field, allowed in (
        ("advisory_mode", ADVISORY_MODES),
        ("advisory_provider_kind", SUPPORTED_PROVIDER_KINDS),
    ):
        if field in source and source[field] is not None:
            raw_value = source[field]
            if not isinstance(raw_value, str) or (
                raw_value.strip().upper() not in allowed
            ):
                raise ValueError(f"invalid {field}: {raw_value!r}")

    plan = AgentOrchestrationPolicyPlan(**projected)

    if plan.mode == MODE_EXPLICIT and not plan.allowed_categories:
        raise ValueError("explicit mode requires allowed_categories")
    if plan.mode == MODE_AUTOMATIC and plan.allowed_categories:
        raise ValueError(
            "automatic mode must not declare explicit allowed_categories"
        )
    if plan.advisory_enabled and plan.max_advisory_requests < 1:
        raise ValueError(
            "advisory_enabled requires max_advisory_requests >= 1"
        )
    return agent_orchestration_policy_plan_projection(plan)


def agent_orchestration_policy_plan_projection(
    value: AgentOrchestrationPolicyPlan,
) -> dict:
    """Serialize an orchestration policy to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "AGENT_ORCHESTRATOR_POLICY_RULE_VERSION",
    "RULE_VERSION",
    "SELECTION_MODES",
    "MODE_AUTOMATIC",
    "MODE_EXPLICIT",
    "MAX_SPECIALISTS_MIN",
    "MAX_SPECIALISTS_MAX",
    "DEFAULT_MAX_SPECIALISTS",
    "MAX_HYPOTHESES_MIN",
    "MAX_HYPOTHESES_MAX",
    "DEFAULT_MAX_HYPOTHESES",
    "MAX_EVIDENCE_ITEMS_MIN",
    "MAX_EVIDENCE_ITEMS_MAX",
    "DEFAULT_MAX_EVIDENCE_ITEMS",
    "MAX_ADVISORY_REQUESTS_MIN",
    "MAX_ADVISORY_REQUESTS_MAX",
    "DEFAULT_MAX_ADVISORY_REQUESTS",
    "MAX_ORCHESTRATION_STAGES_MIN",
    "MAX_ORCHESTRATION_STAGES_MAX",
    "DEFAULT_MAX_ORCHESTRATION_STAGES",
    "MAX_ORCHESTRATION_DEPTH",
    "MAX_VALUE_LEN",
    "sanitize_orchestration_policy",
    "validate_orchestration_policy",
    "AgentOrchestrationPolicyPlan",
    "agent_orchestration_policy_plan_projection",
]
