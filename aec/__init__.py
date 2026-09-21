"""aec — Authorized Evidence Completion (AEC-1), phase-1 preparation surface.

This package holds the **offline** half of AEC-1: constants, models and the
deterministic pilot case selector (Task T1).

Capability boundaries (unchanged by anything in this package):

- ``AEC_LIVE_HTTP_ENABLED`` is ``False`` and no code path here can set it.
- There is no transport, no socket, no name resolution, no subprocess and no
  target interaction anywhere in ``aec/``.
- ``aec/live_deps.py`` and ``aec/observation_lane.py`` deliberately do **not**
  exist in this phase; they belong to the separately authorized Track B.

See ``AEC-1_IMPLEMENTATION_EXECUTION_PLAN.md`` (S2) for the rationale.
"""

from __future__ import annotations

from dataclasses import dataclass

AEC_VERSION = "aec-1"

#: Live HTTP capability for AEC-1. Hard ``False`` in the preparation phase;
#: nothing in ``aec/`` may flip it. The live leg is Track B and requires an
#: explicit operator authorization before it can exist at all.
AEC_LIVE_HTTP_ENABLED = False

#: Rule versions stamped on every artifact this package produces.
SELECTION_RULE_VERSION = "aec-selection/v1"
APPROVAL_SHEET_VERSION = "aec-approval-sheet/v1"

# --------------------------------------------------------------------------
# Pilot families (what the pilot is allowed to look at) and their caps
# --------------------------------------------------------------------------

#: Ordered pilot families. Order is the selection priority.
FAMILY_ORDER = (
    "IDOR_JSON_RESOURCE",
    "SSRF_OEMBED",
    "XSS_REFLECTED",
)

#: Per-family selection caps. They sum to the global case budget (10+6+4=20).
FAMILY_CAPS = {
    "IDOR_JSON_RESOURCE": 10,
    "SSRF_OEMBED": 6,
    "XSS_REFLECTED": 4,
}

FAMILY_DESCRIPTIONS = {
    "IDOR_JSON_RESOURCE": (
        "WordPress REST resource reference (wp-json wp/v2 resource + id-like "
        "parameter): two distinct public object references are comparable."
    ),
    "SSRF_OEMBED": (
        "WordPress oEmbed proxy (wp-json/oembed + url-like parameter): the "
        "delivery behaviour of the remote-resource parameter is comparable."
    ),
    "XSS_REFLECTED": (
        "Reflected query parameter on a public page: raw vs encoded delivery "
        "is comparable."
    ),
}

#: Distinct-host window the pilot aims for. The upper bound is enforced.
PILOT_HOST_RANGE = (3, 5)
MAX_HOSTS = PILOT_HOST_RANGE[1]

# --------------------------------------------------------------------------
# Risk categories (assigned to every case, selected or excluded)
# --------------------------------------------------------------------------

RISK_CATEGORIES = (
    "R0_UNCLASSIFIED",
    "R1_OBJECT_REFERENCE",
    "R2_SERVER_FETCH",
    "R3_REFLECTION",
    "R4_CONTENT_HANDLING",
    "R5_ACCESS_CONTROL",
)

#: Deterministic category -> risk class map of the case itself (not of the
#: pilot decision).
CATEGORY_RISK = {
    "idor": "R1_OBJECT_REFERENCE",
    "ssrf": "R2_SERVER_FETCH",
    "xss": "R3_REFLECTION",
    "file_upload": "R4_CONTENT_HANDLING",
    "authz": "R5_ACCESS_CONTROL",
}

# --------------------------------------------------------------------------
# Pilot budget (hard limits; the selector enforces the case/host subset of it)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PilotBudgetLimits:
    """Hard pilot limits. AEC-1 may only tighten these, never widen them."""

    max_cases: int = 20
    max_requests: int = 60
    max_requests_per_case: int = 4
    max_requests_per_host: int = 5
    min_seconds_between_requests: float = 1.0
    max_concurrency: int = 1
    max_wall_seconds_per_run: int = 600


PILOT_BUDGET = PilotBudgetLimits()

# --------------------------------------------------------------------------
# Output locations (the only places AEC-1 may write)
# --------------------------------------------------------------------------

SELECTION_DIR = "ai_data/aec"
SELECTION_FILENAME = "pilot-selection.json"
APPROVAL_SHEET_DIR = "agent-reports"
APPROVAL_SHEET_FILENAME = "aec-1-pilot-selection.md"

#: Output roots AEC-1 is permitted to write under, relative to the repo root.
ALLOWED_OUTPUT_ROOTS = (SELECTION_DIR, APPROVAL_SHEET_DIR)

# --------------------------------------------------------------------------
# Evidence ladder positions used by the selector's evidence-gap projection
# --------------------------------------------------------------------------

EVIDENCE_LEVEL_CURRENT = "L0_STORED_OBSERVATION"
EVIDENCE_LEVEL_TARGET = "L3_COMPARATIVE"

#: Framing that must appear on every human-facing artifact of this phase.
NOT_CONFIRMED_NOTE = (
    "NOT_CONFIRMED: this selection is a work plan for a bounded read-only "
    "observation pilot. No vulnerability is confirmed, implied or claimed, and "
    "no finding exists or can be created by this phase."
)

__all__ = [
    "AEC_LIVE_HTTP_ENABLED",
    "AEC_VERSION",
    "ALLOWED_OUTPUT_ROOTS",
    "APPROVAL_SHEET_DIR",
    "APPROVAL_SHEET_FILENAME",
    "APPROVAL_SHEET_VERSION",
    "CATEGORY_RISK",
    "EVIDENCE_LEVEL_CURRENT",
    "EVIDENCE_LEVEL_TARGET",
    "FAMILY_CAPS",
    "FAMILY_DESCRIPTIONS",
    "FAMILY_ORDER",
    "MAX_HOSTS",
    "NOT_CONFIRMED_NOTE",
    "PILOT_BUDGET",
    "PILOT_HOST_RANGE",
    "PilotBudgetLimits",
    "RISK_CATEGORIES",
    "SELECTION_DIR",
    "SELECTION_FILENAME",
    "SELECTION_RULE_VERSION",
]
