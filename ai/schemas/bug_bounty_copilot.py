"""Bug bounty copilot input schema (Stage R60.1).

Defines the bounded, deterministic input of the Watch Bug Bounty Copilot. It
answers:

    "Which existing structured research artifacts describe the current
     research context the copilot should brief?"

Hard boundaries encoded here:

- Reference-based and advisory: the input carries bounded references to
  existing R53-R59 artifacts and bounded research context. It never carries
  commands, payloads, credentials or execution instructions, and
  ``execution_performed`` / ``vulnerability_confirmed`` /
  ``exploit_authorized`` are forced ``False``.
- No new intelligence: the input is a composition surface over artifacts
  produced by the existing public APIs; it never re-describes or re-infers
  their content.
- Partial context is first-class: every reference is optional so the copilot
  can brief from any coherent subset.
- Bounded, privacy-safe, JSON serializable; no timestamps, UUIDs or
  randomness.

No I/O, no network, no LLM, no Mongo, no subprocess, no execution of any kind
is represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

BUG_BOUNTY_COPILOT_RULE_VERSION = "r60-1"
RULE_VERSION = BUG_BOUNTY_COPILOT_RULE_VERSION

# ---------------------------------------------------------------------------
# Bounds and ids
# ---------------------------------------------------------------------------

COPILOT_ID_PREFIX = "bbc-"
COPILOT_ID_RE = re.compile(r"^bbc-[0-9a-f]{16}$")

MAX_VALUE_LEN = 160
MAX_LIST = 24
MAX_LIMITATIONS = 16
MAX_DEPTH = 4
MAX_MAPPING_KEYS = 32
DEFAULT_MAX_OPPORTUNITIES = 8
MAX_OPPORTUNITIES_LIMIT = 24

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def _bounded_value(value: object, depth: int = 0) -> object:
    """Deep-bound arbitrary caller context (no I/O, no execution semantics)."""

    if depth > MAX_DEPTH:
        return ""
    if isinstance(value, dict):
        out: dict = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_MAPPING_KEYS:
                break
            text_key = _safe_text(key, 80)
            if text_key:
                out[text_key] = _bounded_value(item, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [
            _bounded_value(item, depth + 1)
            for item in list(value)[:MAX_LIST]
        ]
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return max(-10**9, min(10**9, value))
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        return _safe_text(value, 240)
    return ""


def sanitize_bounded_mapping(value: object) -> dict:
    """Project arbitrary caller context onto a bounded mapping."""

    if not isinstance(value, dict) or not value:
        return {}
    projected = _bounded_value(value)
    return projected if isinstance(projected, dict) else {}


# ---------------------------------------------------------------------------
# Copilot options (closed)
# ---------------------------------------------------------------------------

OPTION_INCLUDE_LEARNING_CONTEXT = "include_learning_context"
OPTION_INCLUDE_EXECUTION_CONTEXT = "include_execution_context"
OPTION_MAX_OPPORTUNITIES = "max_opportunities"

COPILOT_OPTION_KEYS: tuple[str, ...] = (
    OPTION_INCLUDE_LEARNING_CONTEXT,
    OPTION_INCLUDE_EXECUTION_CONTEXT,
    OPTION_MAX_OPPORTUNITIES,
)

COPILOT_BOOLEAN_OPTIONS: tuple[str, ...] = (
    OPTION_INCLUDE_LEARNING_CONTEXT,
    OPTION_INCLUDE_EXECUTION_CONTEXT,
)


def sanitize_copilot_options(value: object) -> dict:
    """Project the bounded copilot options onto closed keys."""

    source = value if isinstance(value, dict) else {}
    out: dict = {}
    for key in COPILOT_BOOLEAN_OPTIONS:
        raw = source.get(key)
        out[key] = True if raw is None else raw is True
    raw_max = source.get(OPTION_MAX_OPPORTUNITIES)
    if isinstance(raw_max, bool) or not isinstance(raw_max, int):
        out[OPTION_MAX_OPPORTUNITIES] = DEFAULT_MAX_OPPORTUNITIES
    else:
        out[OPTION_MAX_OPPORTUNITIES] = _bounded_int(
            raw_max, 1, MAX_OPPORTUNITIES_LIMIT
        )
    return out


# ---------------------------------------------------------------------------
# Layer references (bounded)
# ---------------------------------------------------------------------------

REFERENCE_KINDS: tuple[str, ...] = (
    "WORKFLOW",
    "FINDING",
    "CORRELATION",
    "PRIORITIZATION",
    "HUMAN_DECISION",
    "LEARNING",
    "EXECUTION_CONTROL",
)


def sanitize_copilot_reference(value: object) -> dict:
    """Project one bounded layer reference onto fixed keys."""

    if not isinstance(value, dict) or not value:
        return {
            "present": False,
            "reference_kind": "",
            "reference_id": "",
            "rule_version": "",
            "status": "",
            "item_count": 0,
            "research_only": True,
        }
    kind = _safe_text(value.get("reference_kind")).strip().upper()
    if kind not in REFERENCE_KINDS:
        kind = ""
    return {
        "present": bool(value.get("present")) is True,
        "reference_kind": kind,
        "reference_id": _safe_text(value.get("reference_id")),
        "rule_version": _safe_text(value.get("rule_version")),
        "status": _safe_text(value.get("status")).upper(),
        "item_count": _bounded_int(value.get("item_count"), 0, 4096),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Limitations (closed)
# ---------------------------------------------------------------------------

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_EXPLOIT_AUTHORIZATION = "NO_EXPLOIT_AUTHORIZATION"
LIMITATION_RESEARCH_ONLY = "RESEARCH_ONLY"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"
LIMITATION_HUMAN_AUTHORITY_REQUIRED = "HUMAN_AUTHORITY_REQUIRED"
LIMITATION_R58_GATE_REQUIRED = "R58_GATE_REQUIRED"
LIMITATION_REFERENCE_BASED_CONTEXT = "REFERENCE_BASED_CONTEXT"
LIMITATION_NO_WALL_CLOCK_METADATA = "NO_WALL_CLOCK_METADATA"
LIMITATION_NO_LLM_INVOLVEMENT = "NO_LLM_INVOLVEMENT"
LIMITATION_PARTIAL_CONTEXT_SUPPORTED = "PARTIAL_CONTEXT_SUPPORTED"

COPILOT_INPUT_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_AUTHORIZATION,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_HUMAN_AUTHORITY_REQUIRED,
    LIMITATION_R58_GATE_REQUIRED,
    LIMITATION_REFERENCE_BASED_CONTEXT,
    LIMITATION_NO_WALL_CLOCK_METADATA,
    LIMITATION_NO_LLM_INVOLVEMENT,
    LIMITATION_PARTIAL_CONTEXT_SUPPORTED,
)


def _ordered_limitations(codes: object) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in COPILOT_INPUT_LIMITATIONS:
            found.add(text)
    return [
        code for code in COPILOT_INPUT_LIMITATIONS if code in found
    ][:MAX_LIMITATIONS]


def sanitize_copilot_input_provenance(value: object) -> dict:
    """Project copilot input provenance onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "input_rule_version": BUG_BOUNTY_COPILOT_RULE_VERSION,
            "workflow_id": "",
            "intelligence_id": "",
            "correlation_id": "",
            "prioritization_id": "",
            "review_result_id": "",
            "source_stages": [],
            "deterministic": True,
            "research_only": True,
        }
    return {
        "input_rule_version": BUG_BOUNTY_COPILOT_RULE_VERSION,
        "workflow_id": _safe_text(value.get("workflow_id")),
        "intelligence_id": _safe_text(value.get("intelligence_id")),
        "correlation_id": _safe_text(value.get("correlation_id")),
        "prioritization_id": _safe_text(value.get("prioritization_id")),
        "review_result_id": _safe_text(value.get("review_result_id")),
        "source_stages": [
            _safe_text(item, 80)
            for item in (value.get("source_stages") or ())[:MAX_LIST]
            if _safe_text(item, 80)
        ],
        "deterministic": True,
        "research_only": True,
    }


def sanitize_bug_bounty_copilot_input(value: object) -> dict:
    """Project an R60 copilot input onto its fixed key set."""

    if not isinstance(value, dict) or not value:
        return _default_input()
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "copilot_id": _safe_text(value.get("copilot_id")),
        "target_reference": _safe_text(value.get("target_reference")),
        "research_context": sanitize_bounded_mapping(
            value.get("research_context")
        ),
        "intelligence_context": sanitize_bounded_mapping(
            value.get("intelligence_context")
        ),
        "workflow_reference": sanitize_copilot_reference(
            value.get("workflow_reference")
        ),
        "finding_reference": sanitize_copilot_reference(
            value.get("finding_reference")
        ),
        "correlation_reference": sanitize_copilot_reference(
            value.get("correlation_reference")
        ),
        "priority_reference": sanitize_copilot_reference(
            value.get("priority_reference")
        ),
        "human_reference": sanitize_copilot_reference(
            value.get("human_reference")
        ),
        "learning_reference": sanitize_copilot_reference(
            value.get("learning_reference")
        ),
        "execution_reference": sanitize_copilot_reference(
            value.get("execution_reference")
        ),
        "copilot_options": sanitize_copilot_options(
            value.get("copilot_options")
        ),
        "provenance": sanitize_copilot_input_provenance(
            value.get("provenance")
        ),
        "governance": value.get("governance")
        if isinstance(value.get("governance"), dict)
        else {},
        "limitations": _ordered_limitations(value.get("limitations")),
        "execution_requested": False,
        "execution_performed": False,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }


def _default_input() -> dict:
    return {
        "rule_version": "",
        "copilot_id": "",
        "target_reference": "",
        "research_context": {},
        "intelligence_context": {},
        "workflow_reference": sanitize_copilot_reference(None),
        "finding_reference": sanitize_copilot_reference(None),
        "correlation_reference": sanitize_copilot_reference(None),
        "priority_reference": sanitize_copilot_reference(None),
        "human_reference": sanitize_copilot_reference(None),
        "learning_reference": sanitize_copilot_reference(None),
        "execution_reference": sanitize_copilot_reference(None),
        "copilot_options": sanitize_copilot_options(None),
        "provenance": sanitize_copilot_input_provenance(None),
        "governance": {},
        "limitations": list(COPILOT_INPUT_LIMITATIONS),
        "execution_requested": False,
        "execution_performed": False,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class BugBountyCopilotInputPlan(BaseModel):
    """Deterministic R60 bug bounty copilot input (R60.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = BUG_BOUNTY_COPILOT_RULE_VERSION
    copilot_id: str
    target_reference: str = ""
    research_context: dict = Field(default_factory=dict)
    intelligence_context: dict = Field(default_factory=dict)
    workflow_reference: dict = Field(default_factory=dict)
    finding_reference: dict = Field(default_factory=dict)
    correlation_reference: dict = Field(default_factory=dict)
    priority_reference: dict = Field(default_factory=dict)
    human_reference: dict = Field(default_factory=dict)
    learning_reference: dict = Field(default_factory=dict)
    execution_reference: dict = Field(default_factory=dict)
    copilot_options: dict = Field(default_factory=dict)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    execution_requested: bool = False
    execution_performed: bool = False
    execution_authorized: bool = False
    vulnerability_confirmed: bool = False
    exploit_authorized: bool = False
    confirmation_state: str = "NOT_CONFIRMED"
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return BUG_BOUNTY_COPILOT_RULE_VERSION

    @field_validator("copilot_id")
    @classmethod
    def _valid_copilot_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not COPILOT_ID_RE.match(text):
            raise ValueError(f"malformed copilot_id: {value!r}")
        return text

    @field_validator(
        "workflow_reference",
        "finding_reference",
        "correlation_reference",
        "priority_reference",
        "human_reference",
        "learning_reference",
        "execution_reference",
    )
    @classmethod
    def _bounded_reference(cls, value: object) -> dict:
        return sanitize_copilot_reference(value)

    @field_validator("copilot_options")
    @classmethod
    def _bounded_options(cls, value: object) -> dict:
        return sanitize_copilot_options(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_copilot_input_provenance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator(
        "execution_requested",
        "execution_performed",
        "execution_authorized",
        "vulnerability_confirmed",
        "exploit_authorized",
    )
    @classmethod
    def _never_executes(cls, value: object) -> bool:
        if value is not False:
            raise ValueError(
                "copilot inputs never request, perform or authorize "
                "execution, confirmation or exploitation"
            )
        return False

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NOT_CONFIRMED":
            raise ValueError("copilot inputs never confirm a vulnerability")
        return "NOT_CONFIRMED"

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("copilot inputs are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("copilot inputs are deterministic")
        return True


def bug_bounty_copilot_input_plan_projection(
    value: BugBountyCopilotInputPlan,
) -> dict:
    """Serialize an R60 copilot input to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "BUG_BOUNTY_COPILOT_RULE_VERSION",
    "RULE_VERSION",
    "COPILOT_ID_PREFIX",
    "COPILOT_ID_RE",
    "MAX_VALUE_LEN",
    "MAX_LIST",
    "MAX_LIMITATIONS",
    "MAX_DEPTH",
    "MAX_MAPPING_KEYS",
    "DEFAULT_MAX_OPPORTUNITIES",
    "MAX_OPPORTUNITIES_LIMIT",
    "OPTION_INCLUDE_LEARNING_CONTEXT",
    "OPTION_INCLUDE_EXECUTION_CONTEXT",
    "OPTION_MAX_OPPORTUNITIES",
    "COPILOT_OPTION_KEYS",
    "COPILOT_BOOLEAN_OPTIONS",
    "REFERENCE_KINDS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_EXPLOIT_AUTHORIZATION",
    "LIMITATION_RESEARCH_ONLY",
    "LIMITATION_ADVISORY_ONLY",
    "LIMITATION_HUMAN_AUTHORITY_REQUIRED",
    "LIMITATION_R58_GATE_REQUIRED",
    "LIMITATION_REFERENCE_BASED_CONTEXT",
    "LIMITATION_NO_WALL_CLOCK_METADATA",
    "LIMITATION_NO_LLM_INVOLVEMENT",
    "LIMITATION_PARTIAL_CONTEXT_SUPPORTED",
    "COPILOT_INPUT_LIMITATIONS",
    "sanitize_bounded_mapping",
    "sanitize_copilot_options",
    "sanitize_copilot_reference",
    "sanitize_copilot_input_provenance",
    "sanitize_bug_bounty_copilot_input",
    "BugBountyCopilotInputPlan",
    "bug_bounty_copilot_input_plan_projection",
]
