"""Contract-driven specialist registry (EPIC 6 Part 3).

Five roles, each with declared capabilities and accepted inputs. Unknown
categories fall through to the general researcher — never to an error
that would silently drop a job.
"""

from __future__ import annotations

from aec.specialists.models import SpecialistProfile

EVIDENCE_LEVELS = ("NONE", "PARTIAL", "READY")

_OUTPUT_SCHEMA = (
    "job_id", "role", "outcome", "confidence", "rationale")

_CONFIDENCE = ("low", "medium", "high")


def _profile(role: str, capabilities: tuple[str, ...],
             accepted: tuple[str, ...], required: str,
             refusals: tuple[str, ...], fallback: str) -> SpecialistProfile:
    return SpecialistProfile(
        role=role,
        capabilities=capabilities,
        accepted_inputs=accepted,
        required_evidence=required,
        output_schema=_OUTPUT_SCHEMA,
        confidence_levels=_CONFIDENCE,
        refusals=refusals,
        fallback=fallback,
    )


def default_registry() -> tuple[SpecialistProfile, ...]:
    """The five established research roles with fixed contracts."""
    return (
        _profile(
            "authorization-researcher",
            ("authz-surface-review", "access-control-mapping"),
            ("IDOR_CANDIDATE", "AUTHZ_CANDIDATE"),
            "PARTIAL",
            ("UNSUPPORTED_INPUT", "BELOW_EVIDENCE_LEVEL"),
            "REQUIRES_OBSERVATION",
        ),
        _profile(
            "input-researcher",
            ("input-surface-review", "parameter-mapping"),
            ("XSS_CANDIDATE",),
            "PARTIAL",
            ("UNSUPPORTED_INPUT", "BELOW_EVIDENCE_LEVEL"),
            "REQUIRES_OBSERVATION",
        ),
        _profile(
            "server-researcher",
            ("server-surface-review", "request-flow-mapping"),
            ("SSRF_CANDIDATE",),
            "PARTIAL",
            ("UNSUPPORTED_INPUT", "BELOW_EVIDENCE_LEVEL"),
            "REQUIRES_OBSERVATION",
        ),
        _profile(
            "technology-researcher",
            ("technology-review", "version-mapping"),
            ("TECH_CANDIDATE",),
            "PARTIAL",
            ("UNSUPPORTED_INPUT", "BELOW_EVIDENCE_LEVEL"),
            "REQUIRES_OBSERVATION",
        ),
        _profile(
            "general-researcher",
            ("general-surface-review",),
            ("ANY",),
            "NONE",
            ("BELOW_EVIDENCE_LEVEL",),
            "REQUIRES_OBSERVATION",
        ),
    )


def lookup(registry: tuple[SpecialistProfile, ...], role: str,
           ) -> SpecialistProfile:
    """Find a profile by role. Unknown roles raise ValueError."""
    for profile in registry:
        if profile.role == role:
            return profile
    raise ValueError(f"unknown specialist role: {role!r}")


def match_category(registry: tuple[SpecialistProfile, ...],
                   category: str) -> SpecialistProfile:
    """First specific role accepting the category, else the generalist."""
    for profile in registry:
        if profile.role != "general-researcher" \
                and profile.can_handle(category):
            return profile
    return lookup(registry, "general-researcher")


__all__ = ["EVIDENCE_LEVELS", "default_registry", "lookup", "match_category"]
