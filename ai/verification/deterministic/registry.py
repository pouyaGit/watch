"""Versioned 5I rule registry (Phase 5I, replayable, fail-closed).

Each classification cites the exact rule that proved it. Rules are
pure data + pure functions: no hidden behavior, no unlogged
heuristics, no LLM calls, no I/O. Unknown rule versions, schema
versions this build does not implement, or policy versions it cannot
resolve fail closed (blocked/unknown with an explicit reason) — a
downgrade is never silently accepted.
"""

from __future__ import annotations

from dataclasses import dataclass

from ai.verification.deterministic.models import (
    ARTIFACT_SCHEMA_VERSION,
    OBSERVATION_SCHEMA_VERSION,
    POLICY_VERSION,
    RULES_VERSION,
    VERIFIER_VERSION,
)

__all__ = [
    "ARTIFACT_SCHEMA_VERSION",
    "OBSERVATION_SCHEMA_VERSION",
    "POLICY_VERSION",
    "RULES_VERSION",
    "VERIFIER_VERSION",
    "RuleSpec",
    "SUPPORTED_RULES",
    "resolve_rule",
]


@dataclass(frozen=True)
class RuleSpec:
    """One replayable proof-path registration (immutable)."""

    rule_id: str
    rule_version: int
    observation_schema_version: str
    artifact_schema_version: str
    policy_version: str
    verifier_version: str
    execution_classes: tuple[str, ...]
    #: Finding eligibility at CONFIRMED (policy-backed; POTENTIAL is
    #: never eligible under the pinned policy).
    finding_eligible_on_confirmed: bool = True


_RULES: tuple[RuleSpec, ...] = (
    RuleSpec(
        rule_id="xss-reflected-oracle",
        rule_version=1,
        observation_schema_version=OBSERVATION_SCHEMA_VERSION,
        artifact_schema_version=ARTIFACT_SCHEMA_VERSION,
        policy_version=POLICY_VERSION,
        verifier_version=VERIFIER_VERSION,
        execution_classes=("browser_verification",),
    ),
    RuleSpec(
        rule_id="xss-stored-round",
        rule_version=1,
        observation_schema_version=OBSERVATION_SCHEMA_VERSION,
        artifact_schema_version=ARTIFACT_SCHEMA_VERSION,
        policy_version=POLICY_VERSION,
        verifier_version=VERIFIER_VERSION,
        execution_classes=("browser_verification", "http_verification"),
    ),
    RuleSpec(
        rule_id="xss-stored-legacy",
        rule_version=1,
        observation_schema_version=OBSERVATION_SCHEMA_VERSION,
        artifact_schema_version=ARTIFACT_SCHEMA_VERSION,
        policy_version=POLICY_VERSION,
        verifier_version=VERIFIER_VERSION,
        execution_classes=("browser_verification",),
    ),
    RuleSpec(
        rule_id="http-meaningful-reflection",
        rule_version=1,
        observation_schema_version=OBSERVATION_SCHEMA_VERSION,
        artifact_schema_version=ARTIFACT_SCHEMA_VERSION,
        policy_version=POLICY_VERSION,
        verifier_version=VERIFIER_VERSION,
        execution_classes=("http_probe", "http_verification"),
    ),
    RuleSpec(
        rule_id="nuclei-advisory",
        rule_version=1,
        observation_schema_version=OBSERVATION_SCHEMA_VERSION,
        artifact_schema_version=ARTIFACT_SCHEMA_VERSION,
        policy_version=POLICY_VERSION,
        verifier_version=VERIFIER_VERSION,
        execution_classes=("nuclei_scan",),
    ),
)

SUPPORTED_RULES: dict[str, RuleSpec] = {spec.rule_id: spec for spec in _RULES}


def resolve_rule(
    rule_id: str,
    *,
    execution_class: str,
    observation_schema_version: str,
    artifact_schema_version: str,
    policy_version: str,
) -> RuleSpec | None:
    """Resolve a rule for a record (fail-closed on any mismatch).

    Returns ``None`` when: the rule is unknown, the schema versions
    are not implemented by this build, the policy version is not the
    pinned one, or the rule does not cover the execution class (a
    silent class confusion would be a downgrade). Callers translate
    ``None`` into a blocked/unknown classification — never a guess.
    """
    spec = SUPPORTED_RULES.get(rule_id)
    if spec is None:
        return None
    if spec.observation_schema_version != observation_schema_version:
        return None
    if spec.artifact_schema_version != artifact_schema_version:
        return None
    if spec.policy_version != policy_version:
        return None
    if execution_class not in spec.execution_classes:
        return None
    return spec


def rule_display_id(spec: RuleSpec) -> str:
    """Versioned display id, e.g. ``xss-reflected-oracle/v1``."""
    return f"{spec.rule_id}/v{spec.rule_version}"


__all__ += ["rule_display_id"]
