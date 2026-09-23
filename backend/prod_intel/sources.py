"""backend/prod_intel/sources.py — bounded, fail-closed source readers.

Every function here wraps ONE authoritative store read. Any exception
becomes an ``unavailable`` envelope instead of a crash or a fabricated
empty list — projections then render ``unavailable`` honestly.

Stores are constructed FRESH per call so ``WATCH_AGENT_RUNTIME_DIR``
(checked dynamically by ``runtime_base_dir()``) is honored — tests point
the env var at a tmp dir and get hermetic reads with no rebind dance.

No network, no execution, no code paths beyond local file reads and one
bounded Mongo count (attack surface). Reads are bounded: capped audit /
activity / list limits, per-object plan/authorization lookups only for
the objectives already enumerated.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from backend.prod_intel.semantics import UNAVAILABLE

AUDIT_CAP = 2000
ACTIVITY_CAP = 200
OBJECTIVE_CAP = 500
CAMPAIGN_CAP = 200


def _safe(name: str, fn: Callable[[], Any]) -> dict[str, Any]:
    try:
        return {"state": "ok", "data": fn(), "reason": ""}
    except Exception as exc:                     # fail closed, never raise
        return {"state": UNAVAILABLE, "data": None,
                "reason": f"{name}: {type(exc).__name__}: {str(exc)[:160]}"}


def _runtime():
    from backend.research_agents.runtime_store import RuntimeStore
    return RuntimeStore()


def _finding_store():
    from backend.research_agents.finding.store import FindingStore
    from backend.research_agents.runtime_store import runtime_base_dir
    return FindingStore(runtime_base_dir())


def _campaign_store():
    from backend.research_agents.campaign.store import CampaignStore
    return CampaignStore()


def _hunt_store():
    from backend.research_agents.hunt.store import HuntStore
    return HuntStore()


def _memory_store():
    from backend.research_agents.intelligence.memory import MemoryStore
    return MemoryStore()


# ---------------------------------------------------------------- runtime
def _state_guard() -> str | None:
    """Detect an unreadable runtime state.json BEFORE the store's own
    OSError/ValueError -> {} fallback silently presents corrupt state as
    an empty-but-ok observation (spec: unavailable, never zero-filled).

    A *missing* state file is a fresh store, not corruption — that stays
    ok/empty like the store's own contract.
    """
    try:
        raw = _runtime().state_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None                      # fresh store: no state yet
    except OSError as exc:
        return (f"runtime state unreadable (OSError: {exc})")
    except Exception as exc:             # noqa: BLE001 — fail-closed: the
        # guard itself must never raise out of a source read — any read
        # failure (mocked store, disk error) becomes an unavailable reason
        return (f"runtime state unreadable ({type(exc).__name__}: "
                f"{exc})")
    try:
        payload = json.loads(raw)
    except ValueError:
        return "runtime state unreadable"
    if not isinstance(payload, dict):
        return "runtime state is not an object"
    return None


def _guarded(name: str, fn: Callable[[], Any]) -> dict[str, Any]:
    guard = _state_guard()
    if guard:
        return {"state": UNAVAILABLE, "data": None,
                "reason": f"{name}: {guard}"}
    return _safe(name, fn)


def jobs() -> dict[str, Any]:
    return _guarded("runtime.jobs", lambda: _runtime().list_jobs())


def evidence() -> dict[str, Any]:
    return _guarded("runtime.evidence", lambda: _runtime().list_evidence())


def runtime_cases() -> dict[str, Any]:
    return _guarded("runtime.cases", lambda: _runtime().list_cases())


def knowledge_use() -> dict[str, Any]:
    return _guarded("runtime.knowledge_use",
                    lambda: _runtime().list_knowledge_use())


def activity(limit: int = ACTIVITY_CAP) -> dict[str, Any]:
    n = max(1, min(int(limit), ACTIVITY_CAP))
    return _safe("runtime.activity", lambda: _runtime().list_activity(n))


def audit(limit: int = AUDIT_CAP) -> dict[str, Any]:
    n = max(1, min(int(limit), AUDIT_CAP))
    return _safe("runtime.audit", lambda: _runtime().audit_events(n))


def worker() -> dict[str, Any]:
    return _safe("runtime.worker", lambda: _runtime().worker_alive())


# --------------------------------------------------------------- findings
def candidates() -> dict[str, Any]:
    return _safe("finding.candidates", lambda: _finding_store().list_candidates())


def verifications() -> dict[str, Any]:
    return _safe("finding.verifications",
                 lambda: _finding_store().list_verifications())


def correlations() -> dict[str, Any]:
    return _safe("finding.correlations",
                 lambda: _finding_store().list_correlations())


def finding_cases() -> dict[str, Any]:
    return _safe("finding.cases", lambda: _finding_store().list_cases())


# -------------------------------------------------------------- campaign
def campaigns() -> dict[str, Any]:
    return _safe("campaign.campaigns",
                 lambda: _campaign_store().list_campaigns()[:CAMPAIGN_CAP])


def campaign_objectives(campaign_id: str) -> dict[str, Any]:
    return _safe(
        "campaign.objectives",
        lambda: _campaign_store().objectives_for_campaign(str(campaign_id)))


# ------------------------------------------------------------------ hunt
def hunt_objectives() -> dict[str, Any]:
    return _safe("hunt.objectives",
                 lambda: _hunt_store().list_objectives(limit=OBJECTIVE_CAP))


def hunt_plans(objective_id: str) -> dict[str, Any]:
    return _safe("hunt.plans",
                 lambda: _hunt_store().plans_for_objective(str(objective_id)))


def hunt_authorizations(plan_id: str) -> dict[str, Any]:
    return _safe(
        "hunt.authorizations",
        lambda: _hunt_store().authorizations_for_plan(str(plan_id)))


# --------------------------------------------------------------- memory
def memory_heads() -> dict[str, Any]:
    return _safe("memory.heads", lambda: _memory_store().heads())


# ------------------------------------------------------------------ KB
def kb_total() -> dict[str, Any]:
    def _read() -> int:
        from backend import research_data
        return int(research_data.list_kb(limit=1).get("total") or 0)
    return _safe("knowledge.inventory", _read)


# ------------------------------------------------------- attack surface
def attack_surface(target: str) -> dict[str, Any]:
    """Bounded per-target Mongo counts; unavailable when unreachable.

    Filter fields are introspected from the real models — a schema drift
    fails closed to ``unavailable`` instead of counting the wrong rows.
    """
    def _read() -> dict[str, Any]:
        from database import db
        fields_u = set(getattr(db.Urls, "_fields", set()))
        fields_e = set(getattr(db.Endpoints, "_fields", set()))
        if "subdomain" not in fields_u or "subdomain" not in fields_e:
            raise RuntimeError("models expose no subdomain field")
        t = str(target)
        return {
            "urls": int(db.Urls.objects(subdomain=t).count()),
            "endpoints": int(db.Endpoints.objects(subdomain=t).count()),
        }
    return _safe(f"attack_surface:{target}", _read)


def scope_programs() -> dict[str, Any]:
    """Distinct program names known to the recon database (bounded)."""
    def _read() -> list[str]:
        from database import db
        if "program_name" not in set(getattr(db.Urls, "_fields", set())):
            raise RuntimeError("models expose no program_name field")
        return sorted(str(p) for p in db.Urls.objects.distinct("program_name"))
    return _safe("attack_surface.programs", _read)
