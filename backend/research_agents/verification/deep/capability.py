"""EPIC15 §2/§3/§21 — the deep-verification capability contract.

One place that states, for every deep lane, whether the capability is
``IMPLEMENTED``, ``LIMITED`` or ``NOT_IMPLEMENTED`` (EPIC13's closed
capability vocabulary — not a new one), what it can produce, what it
cannot, and the exact blocker.

The platform's own frozen boundary is read **through** — imported, never
re-declared, never modified.  Nothing in this module can enable a live
lane: the switches it reads are literal constants in
``ai.execution.browser_executor``.
"""
from __future__ import annotations

from typing import Any

from ai.execution import browser_executor as bx
from ai.limits import ceilings as ce
from backend.research_agents.verification import actions as ac
from backend.research_agents.verification.acquisition.capabilities import (
    IMPLEMENTED, LIMITED, NOT_IMPLEMENTED)

DEEP_RULE_VERSION = "epic15-deep-verification-1"

#: the platform's refusal token, reused verbatim (never re-spelled).
BROWSER_EXECUTION_BLOCKED = "BROWSER_EXECUTION_BLOCKED"

#: lane availability vocabulary (this is a *lane* state, not a capability
#: state: the capability vocabulary above is EPIC13's closed one).
LANE_OFFLINE_ONLY = "OFFLINE_HARNESS_ONLY"
LANE_CLOSED = "CLOSED"
LANE_ABSENT = "ABSENT"

LANE_STATES: tuple[str, ...] = (LANE_OFFLINE_ONLY, LANE_CLOSED, LANE_ABSENT)


def lane_states() -> tuple[str, ...]:
    return LANE_STATES


def _live_switch() -> bool:
    """The platform's frozen master switch, read not written."""
    return bool(bx.LIVE_BROWSER)


def browser_lane() -> dict[str, Any]:
    """The state of the platform browser lane, with its exact blockers."""
    live = _live_switch()
    return {
        "lane": "browser",
        "state": LANE_CLOSED if not live else LANE_OFFLINE_ONLY,
        "capability": NOT_IMPLEMENTED,
        "live_switch": live,
        "switch_name": "LIVE_BROWSER",
        "switch_configurable": False,
        "blockers": {
            "B1": bx.B1_STATUS,
            "B2": bx.B2_STATUS,
            "B4": bx.B4_STATUS,
            "B5": bx.B5_STATUS,
        },
        "schema_version": bx.SCHEMA_VERSION,
        "browser_id": bx.SERVER_CONTROLLED_BROWSER_ID,
        "available_runner": "offline_harness",
        "refusal": BROWSER_EXECUTION_BLOCKED,
        "not_implemented": (
            "no browser can be launched, navigated or instrumented in this "
            "runtime; the live gate is a literal constant and the B5 "
            "network/containment boundary is pending, so in-browser hooks "
            "could not be enforced"),
        "rule_version": DEEP_RULE_VERSION,
    }


def execution_lane() -> dict[str, Any]:
    """The state of the execution-evidence lane (always fail-closed here)."""
    return {
        "lane": "execution",
        "state": LANE_CLOSED,
        "capability": NOT_IMPLEMENTED,
        "actions": (ac.DELIVER_CONTROLLED_PAYLOAD, ac.OBSERVE_EXECUTION),
        "evidence": ("PAYLOAD_EXECUTION", "EXPLOITABILITY_ESTABLISHED"),
        "producible_here": (),
        "refusal": BROWSER_EXECUTION_BLOCKED,
        "not_implemented": (
            "controlled payload delivery and execution observation require a "
            "pinned browser execution lane that is not reachable from the "
            "bounded research worker; no synthetic execution evidence is ever "
            "produced"),
        "rule_version": DEEP_RULE_VERSION,
    }


def dom_verification_lane() -> dict[str, Any]:
    """The DOM lane: real, deterministic, and explicitly not execution."""
    return {
        "lane": "dom",
        "state": LANE_OFFLINE_ONLY,
        "capability": LIMITED,
        "actions": (ac.TRACE_DOM_SOURCE, ac.TRACE_DOM_SINK),
        "evidence": ("DOM_SINK_IDENTIFIED", "NEGATIVE_EVIDENCE"),
        "instrumentation": "served_document_static_analysis",
        "producible_here": ("DOM_SINK_IDENTIFIED",),
        "not_implemented": (
            "no JavaScript execution, no taint tracking and no runtime sink "
            "instrumentation: the trace is a deterministic analysis of the "
            "served document and its inline scripts, so it establishes a "
            "source→sink flow in the served material — never that the sink "
            "executed"),
        "limitation": (
            "operates on a recorded/served document; no browser is launched"),
        "rule_version": DEEP_RULE_VERSION,
    }


def capability_document() -> dict[str, Any]:
    """The whole contract, for the report, the projection and the audit."""
    return {
        "rule_version": DEEP_RULE_VERSION,
        "authoritative": (
            "Browser execution evidence is authoritative only when produced "
            "by the trusted, authorized verification producer."),
        "lanes": {
            "browser": browser_lane(),
            "execution": execution_lane(),
            "dom": dom_verification_lane(),
        },
        "ceilings": {
            "browser_wall_seconds": ce.CEILINGS["browser_wall_seconds"],
            "browser_pages": ce.CEILINGS["browser_pages"],
            "browser_contexts": ce.CEILINGS["browser_contexts"],
            "redirect_hops": ce.CEILINGS["redirect_hops"],
            "requests_per_execution": ce.CEILINGS["requests_per_execution"],
            "browser_dom_observation_bytes":
                ce.CEILINGS["browser_dom_observation_bytes"],
        },
        "ceilings_source": "ai.limits.ceilings.CEILINGS (frozen, reused)",
        "live_execution_in_production": False,
    }
