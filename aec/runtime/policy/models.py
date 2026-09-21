"""EPIC7 Part 2+7: runtime policy — observation allowlist, methods, limits.

Every limit and permit is explicit. There is no implicit default that
widens scope at runtime: an observation type, method, evidence level, or
policy version the caller did not name is refused.
"""

from __future__ import annotations

from aec.runtime.policy.limits import ResourceLimits, default_limits

#: Deliberately small evidence-only allowlist (EPIC7 §3).
OBSERVATION_TYPES = (
    "HTTP_METADATA",
    "HTTP_HEADERS",
    "HTTP_STATUS",
    "HTTP_BODY_METADATA",
)

PERMITTED_METHODS = ("GET",)

SUPPORTED_POLICY_VERSIONS = ("v1",)

#: The highest evidence level any metadata observation may claim.
TYPE_EVIDENCE_LEVELS = {
    "HTTP_METADATA": "PARTIAL",
    "HTTP_HEADERS": "PARTIAL",
    "HTTP_STATUS": "PARTIAL",
    "HTTP_BODY_METADATA": "PARTIAL",
}

_LEVEL_RANK = {"NONE": 0, "PARTIAL": 1, "READY": 2}


def is_observation_type(value: object) -> bool:
    return isinstance(value, str) and value in OBSERVATION_TYPES


def method_permitted(method: object) -> bool:
    return isinstance(method, str) and method in PERMITTED_METHODS


def policy_version_supported(version: object) -> bool:
    return isinstance(version, str) and version in SUPPORTED_POLICY_VERSIONS


def evidence_level_compatible(required: object,
                              observation_type: str) -> bool:
    """True when the observation type can satisfy the required level."""
    if not isinstance(required, str) or required not in _LEVEL_RANK:
        return False
    produced = TYPE_EVIDENCE_LEVELS.get(observation_type)
    if produced is None or produced not in _LEVEL_RANK:
        return False
    return _LEVEL_RANK[required] <= _LEVEL_RANK[produced]


class ObservationPolicy:
    """One immutable policy: types, methods, version, limits."""

    def __init__(
        self,
        observation_types: tuple[str, ...],
        policy_version: str = "v1",
        permitted_methods: tuple[str, ...] = PERMITTED_METHODS,
        limits: ResourceLimits | None = None,
    ) -> None:
        if not isinstance(observation_types, tuple) or not observation_types:
            raise ValueError("observation_types must be a non-empty tuple")
        for kind in observation_types:
            if not is_observation_type(kind):
                raise ValueError(f"unknown observation type: {kind!r}")
        if not policy_version_supported(policy_version):
            raise ValueError(f"unsupported policy version: {policy_version!r}")
        for method in permitted_methods:
            if not method_permitted(method):
                raise ValueError(f"method not permitted: {method!r}")
        self.observation_types = tuple(sorted(observation_types))
        self.policy_version = policy_version
        self.permitted_methods = permitted_methods
        self.limits = limits if limits is not None else default_limits()

    def to_dict(self) -> dict[str, object]:
        return {
            "policy_version": self.policy_version,
            "observation_types": list(self.observation_types),
            "permitted_methods": list(self.permitted_methods),
            "limits": self.limits.to_dict(),
        }


def default_policy() -> ObservationPolicy:
    return ObservationPolicy(observation_types=tuple(OBSERVATION_TYPES))


def policy_refuses_type(policy: ObservationPolicy, kind: object) -> bool:
    return not (isinstance(kind, str) and kind in policy.observation_types)


def validate_policy_for_request(request: dict[str, object],
                                policy: ObservationPolicy) -> str:
    """First policy failure as a reason string, or empty string."""
    kind = request.get("observation_type")
    if not isinstance(kind, str) or not is_observation_type(kind):
        return "TYPE_UNKNOWN"
    if policy_refuses_type(policy, kind):
        return "TYPE_NOT_PERMITTED"
    method = request.get("method")
    if not isinstance(method, str) or not method_permitted(method):
        return "METHOD_NOT_PERMITTED"
    level = request.get("required_evidence_level")
    if not isinstance(level, str) or not level:
        return "EVIDENCE_LEVEL_MISSING"
    if not evidence_level_compatible(level, kind):
        return "EVIDENCE_LEVEL_INCOMPATIBLE"
    version = request.get("policy_version")
    if not policy_version_supported(version):
        return "POLICY_VERSION_UNSUPPORTED"
    return ""


__all__ = [
    "OBSERVATION_TYPES", "PERMITTED_METHODS", "SUPPORTED_POLICY_VERSIONS",
    "TYPE_EVIDENCE_LEVELS", "ObservationPolicy", "default_policy",
    "evidence_level_compatible", "is_observation_type",
    "method_permitted", "policy_refuses_type", "policy_version_supported",
    "validate_policy_for_request",
]