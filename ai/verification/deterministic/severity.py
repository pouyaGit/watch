"""Deterministic versioned severity policy (Phase 5I).

Severity derives ONLY from (vulnerability class × verifier rule ×
evidence strength) via the pinned policy table below. No LLM,
Nuclei, researcher, caller, or upstream-template severity is ever
consulted. When the table has no entry the severity is UNSET with an
explicit reason — never guessed, interpolated, or inherited.

The legacy ``_STATUS_TO_CONFIDENCE`` map is confidence, not severity;
it is deliberately NOT repurposed here and no confidence field exists
on any 5I model.
"""

from __future__ import annotations

from dataclasses import dataclass

from ai.verification.deterministic.models import POLICY_VERSION

SEVERITY_UNSET = "UNSET"

__all__ = [
    "SEVERITY_UNSET",
    "SeverityDecision",
    "resolve_severity",
    "policy_table",
]


@dataclass(frozen=True)
class SeverityDecision:
    """Deterministic severity outcome (value or explicit unset)."""

    severity: str
    unset_reason: str | None = None

    @property
    def is_unset(self) -> bool:
        return self.severity == SEVERITY_UNSET


@dataclass(frozen=True)
class _SeverityEntry:
    severity: str
    justification: str


# Pinned policy table: (vulnerability_class, rule_id) -> entry.
# Evidence strength is encoded by the rule itself (a rule only emits
# CONFIRMED on full proof paths; weak evidence never reaches the
# strong rows). Policy version: 5i-severity-policy/v1.
_POLICY_TABLE: dict[tuple[str, str], _SeverityEntry] = {
    ("reflected_xss", "xss-reflected-oracle"): _SeverityEntry(
        "high", "confirmed reflected XSS execution proof"
    ),
    ("stored_xss", "xss-stored-round"): _SeverityEntry(
        "high", "confirmed stored XSS round execution proof"
    ),
    ("dom_xss", "xss-reflected-oracle"): _SeverityEntry(
        "medium", "confirmed DOM XSS execution proof"
    ),
    ("mutation_xss", "xss-reflected-oracle"): _SeverityEntry(
        "medium", "confirmed mutation XSS execution proof"
    ),
    ("reflected_xss", "http-meaningful-reflection"): _SeverityEntry(
        "low", "meaningful reflection without execution proof"
    ),
    ("stored_xss", "xss-stored-legacy"): _SeverityEntry(
        "low", "legacy stored shape, POTENTIAL ceiling only"
    ),
}


def policy_table() -> dict[tuple[str, str], str]:
    """Read-only view of the pinned table (for audit/tests)."""
    return {
        key: entry.severity for key, entry in _POLICY_TABLE.items()
    }


def resolve_severity(
    *,
    vulnerability_class: str,
    rule_id: str,
    outcome: str,
    policy_version: str,
) -> SeverityDecision:
    """Resolve severity from the pinned table (never from upstream).

    ``POTENTIAL`` resolves only against the weak-evidence rows;
    ``UNKNOWN`` is always UNSET (nothing was proven). If the table
    has no entry the severity is UNSET with an explicit reason.
    """
    if policy_version != POLICY_VERSION:
        return SeverityDecision(
            SEVERITY_UNSET, "policy_version_not_pinned"
        )
    if outcome == "UNKNOWN":
        return SeverityDecision(SEVERITY_UNSET, "outcome_unknown")
    if outcome == "NOT_VULNERABLE":
        return SeverityDecision(
            SEVERITY_UNSET, "negative_schema_absent"
        )
    normalized_class = (vulnerability_class or "").strip().lower()
    if not normalized_class:
        return SeverityDecision(SEVERITY_UNSET, "vulnerability_class_absent")
    entry = _POLICY_TABLE.get((normalized_class, rule_id))
    if entry is None:
        return SeverityDecision(
            SEVERITY_UNSET, "no_policy_entry_for_class_and_rule"
        )
    if outcome == "POTENTIAL" and entry.severity in ("critical", "high"):
        # Weak evidence never carries a confirmed-class severity.
        return SeverityDecision(
            SEVERITY_UNSET, "weak_evidence_no_confirmed_class_severity"
        )
    return SeverityDecision(entry.severity, entry.justification)
