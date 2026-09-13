"""Security agent framework export schema (Stage R38.7).

A :class:`SecurityAgentFrameworkExportPlan` combines all R38 models into the
final deterministic framework contract. It answers the framework question:

    "Is the security agent framework core complete and internally valid?"

Hard boundaries encoded here:

- Framework/model only: this is the Security Agent SDK foundation, not an
  execution engine. No agent runtime, no vulnerability agent, no autonomous
  loop, no worker, no tool execution, no plugin loading and no dynamic import
  is represented or created.
- ``ready`` is true only when identity, capability, lifecycle and registry
  contracts are valid; UNKNOWN critical states prevent readiness.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.security_agent_capability import (
    sanitize_security_agent_capability_plan,
)
from ai.schemas.security_agent_identity import (
    sanitize_security_agent_identity_plan,
)
from ai.schemas.security_agent_input import (
    sanitize_security_agent_input_plan,
)
from ai.schemas.security_agent_lifecycle import (
    sanitize_security_agent_lifecycle_plan,
)
from ai.schemas.security_agent_registry import (
    sanitize_security_agent_registry_plan,
)
from ai.schemas.security_agent_result import (
    sanitize_security_agent_result_plan,
)

SECURITY_AGENT_FRAMEWORK_EXPORT_RULE_VERSION = "r38-7"
RULE_VERSION = SECURITY_AGENT_FRAMEWORK_EXPORT_RULE_VERSION

LIMITATION_UNKNOWN_IDENTITY = "UNKNOWN_IDENTITY"
LIMITATION_UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
LIMITATION_UNKNOWN_LIFECYCLE = "UNKNOWN_LIFECYCLE"
LIMITATION_UNKNOWN_REGISTRY = "UNKNOWN_REGISTRY"
LIMITATION_NO_REGISTERED_AGENTS = "NO_REGISTERED_AGENTS"
LIMITATION_PLACEHOLDER_TEMPLATES = "PLACEHOLDER_TEMPLATES"

FRAMEWORK_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_UNKNOWN_IDENTITY,
    LIMITATION_UNKNOWN_CAPABILITY,
    LIMITATION_UNKNOWN_LIFECYCLE,
    LIMITATION_UNKNOWN_REGISTRY,
    LIMITATION_NO_REGISTERED_AGENTS,
    LIMITATION_PLACEHOLDER_TEMPLATES,
)

MAX_IDENTITIES = 8
MAX_CAPABILITIES = 8
MAX_LIMITATIONS = 8
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _bounded_items(value: object, project, limit: int) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            continue
        out.append(project(item))
        if len(out) >= limit:
            break
    return out


def _require_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in allowed:
            raise ValueError(f"invalid closed code: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SecurityAgentFrameworkExportPlan(BaseModel):
    """Final deterministic security agent framework export (R38.7)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SECURITY_AGENT_FRAMEWORK_EXPORT_RULE_VERSION
    ready: bool
    identities: list[dict] = Field(default_factory=list)
    capabilities: list[dict] = Field(default_factory=list)
    input_contract: dict = Field(default_factory=dict)
    lifecycle: dict = Field(default_factory=dict)
    result_contract: dict = Field(default_factory=dict)
    registry: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SECURITY_AGENT_FRAMEWORK_EXPORT_RULE_VERSION

    @field_validator("identities")
    @classmethod
    def _bounded_identities(cls, value: list) -> list[dict]:
        return _bounded_items(
            value, sanitize_security_agent_identity_plan, MAX_IDENTITIES
        )

    @field_validator("capabilities")
    @classmethod
    def _bounded_capabilities(cls, value: list) -> list[dict]:
        return _bounded_items(
            value, sanitize_security_agent_capability_plan,
            MAX_CAPABILITIES,
        )

    @field_validator("input_contract")
    @classmethod
    def _bounded_input(cls, value: object) -> dict:
        return sanitize_security_agent_input_plan(value)

    @field_validator("lifecycle")
    @classmethod
    def _bounded_lifecycle(cls, value: object) -> dict:
        return sanitize_security_agent_lifecycle_plan(value)

    @field_validator("result_contract")
    @classmethod
    def _bounded_result(cls, value: object) -> dict:
        return sanitize_security_agent_result_plan(value)

    @field_validator("registry")
    @classmethod
    def _bounded_registry(cls, value: object) -> dict:
        return sanitize_security_agent_registry_plan(value)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, FRAMEWORK_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "security agent framework exports are research-only"
            )
        return True


def security_agent_framework_export_plan_projection(
    value: SecurityAgentFrameworkExportPlan,
) -> dict:
    """Serialize a framework export to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SECURITY_AGENT_FRAMEWORK_EXPORT_RULE_VERSION",
    "RULE_VERSION",
    "FRAMEWORK_LIMITATIONS",
    "LIMITATION_UNKNOWN_IDENTITY",
    "LIMITATION_UNKNOWN_CAPABILITY",
    "LIMITATION_UNKNOWN_LIFECYCLE",
    "LIMITATION_UNKNOWN_REGISTRY",
    "LIMITATION_NO_REGISTERED_AGENTS",
    "LIMITATION_PLACEHOLDER_TEMPLATES",
    "MAX_IDENTITIES",
    "MAX_CAPABILITIES",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "SecurityAgentFrameworkExportPlan",
    "security_agent_framework_export_plan_projection",
]
