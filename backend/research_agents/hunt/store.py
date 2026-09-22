"""Hunt persistence — append-only JSONL beside the runtime store.

Streams (all append-only, one JSON object per line):
  hunt_objectives.jsonl          — objective revisions (state history)
  hunt_plans.jsonl               — immutable plan definitions (one/plan_id)
  hunt_plan_transitions.jsonl    — plan state changes (never rewrites)
  hunt_authorizations.jsonl      — authorization bridge records
  hunt_observations.jsonl        — observation execution records

Rules enforced here (fail-closed):
  * objectives are created once; every later record is a validated
    revision (uncertainty.transition between revisions);
  * plan definitions are immutable — re-appending a plan_id with a
    different definition hash is rejected (duplicate/mutation guard);
  * plan state moves only through plan_transition() and only via the
    transitions stream.

No LLM, no network, no execution: pure file persistence with an
inter-process lock for read-modify-write sequences.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from backend.research_agents.hunt.models import (
    AuthorizationRecord,
    HuntObjective,
    HuntPlan,
    ObservationRecord,
    PlanError,
    PlanTransition,
    plan_transition,
)
from backend.research_agents.hunt.uncertainty import (
    UncertaintyError,
    transition as uncertainty_transition,
)

try:  # pragma: no cover - platform guard
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

OBJECTIVES_FILE = "hunt_objectives.jsonl"
PLANS_FILE = "hunt_plans.jsonl"
TRANSITIONS_FILE = "hunt_plan_transitions.jsonl"
AUTHORIZATIONS_FILE = "hunt_authorizations.jsonl"
OBSERVATIONS_FILE = "hunt_observations.jsonl"


class HuntStoreError(RuntimeError):
    """Persistence-level failure (integrity, duplicate, malformed row)."""


def utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class HuntStore:
    """Append-only hunt state store pinned to the runtime base dir."""

    def __init__(self, base_dir: str | Path | None = None):
        if base_dir is None:
            from backend.research_agents.runtime_store import runtime_base_dir
            base = runtime_base_dir()
        else:
            base = Path(base_dir)
            if base.name != "runtime":
                base = Path(base) / "runtime"
        self.base = Path(base)
        self.base.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.base / ".hunt.lock"

    # ----------------------------------------------------------- plumbing
    def _path(self, name: str) -> Path:
        return self.base / name

    def _lines(self, name: str) -> Iterator[dict[str, Any]]:
        path = self._path(name)
        if not path.exists():
            return
        with path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    row = json.loads(raw)
                except (ValueError, TypeError):
                    raise HuntStoreError(
                        f"malformed row in {name}") from None
                if isinstance(row, dict):
                    yield row

    def _append(self, name: str, row: dict[str, Any]) -> None:
        path = self._path(name)
        blob = json.dumps(row, sort_keys=True, default=str) + "\n"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(blob)
            fh.flush()

    def _locked(self) -> Any:
        class _Ctx:
            def __enter__(inner_self):
                inner_self.fh = self._lock_path.open("a")
                if fcntl is not None:
                    fcntl.flock(inner_self.fh.fileno(), fcntl.LOCK_EX)
                return inner_self.fh

            def __exit__(inner_self, *exc):
                fh = getattr(inner_self, "fh", None)
                inner_self.fh = None
                if fh is not None:
                    try:
                        if fcntl is not None:
                            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                    finally:
                        fh.close()
                return False

        return _Ctx()

    # ---------------------------------------------------------- objectives
    def objective_history(self, objective_id: str) -> list[HuntObjective]:
        out: list[HuntObjective] = []
        for row in self._lines(OBJECTIVES_FILE):
            if row.get("objective_id") == objective_id:
                try:
                    out.append(HuntObjective.from_dict(row))
                except (TypeError, ValueError) as exc:
                    raise HuntStoreError(
                        f"malformed objective row: {exc}") from None
        return out

    def get_objective(self, objective_id: str) -> HuntObjective | None:
        hist = self.objective_history(objective_id)
        return hist[-1] if hist else None

    def objectives_for_job(self, job_id: str) -> list[HuntObjective]:
        """Latest revision per objective for one job."""
        latest: dict[str, HuntObjective] = {}
        for row in self._lines(OBJECTIVES_FILE):
            if row.get("job_id") == job_id:
                try:
                    obj = HuntObjective.from_dict(row)
                except (TypeError, ValueError) as exc:
                    raise HuntStoreError(
                        f"malformed objective row: {exc}") from None
                latest[obj.objective_id] = obj
        return list(latest.values())

    def list_objectives(self, *, category: str | None = None,
                        limit: int = 50) -> list[HuntObjective]:
        latest: dict[str, HuntObjective] = {}
        for row in self._lines(OBJECTIVES_FILE):
            try:
                obj = HuntObjective.from_dict(row)
            except (TypeError, ValueError):
                continue
            latest[obj.objective_id] = obj
        objs = sorted(latest.values(), key=lambda o: o.updated_at,
                      reverse=True)
        if category:
            objs = [o for o in objs if o.category == category]
        return objs[: max(0, int(limit))]

    def create_objective(self, objective: HuntObjective) -> HuntObjective:
        """Create (idempotent): returns the existing latest revision when
        the objective already exists — never a second create."""
        with self._locked():
            existing = self.get_objective(objective.objective_id)
            if existing is not None:
                return existing
            self._append(OBJECTIVES_FILE, objective.to_dict())
            return objective

    def revise_objective(
        self,
        objective_id: str,
        *,
        state: str | None = None,
        reason: str = "",
        iteration: int | None = None,
        plans_created: int | None = None,
        observations_run: int | None = None,
        llm_plans_used: int | None = None,
        termination_reason: str = "",
        termination_detail: str = "",
        now: str | None = None,
    ) -> HuntObjective:
        """Append a validated revision (state moves via uncertainty
        transition table — terminal states never move)."""
        with self._locked():
            current = self.get_objective(objective_id)
            if current is None:
                raise HuntStoreError(f"unknown objective {objective_id!r}")
            if state is not None and state != current.state:
                try:
                    uncertainty_transition(current.state, state)
                except UncertaintyError as exc:
                    raise HuntStoreError(str(exc)) from None
            revised = HuntObjective.from_dict(current.to_dict())
            revised.revision = current.revision + 1
            if state is not None:
                revised.state = state
            if iteration is not None:
                revised.iteration = int(iteration)
            if plans_created is not None:
                revised.plans_created = int(plans_created)
            if observations_run is not None:
                revised.observations_run = int(observations_run)
            if llm_plans_used is not None:
                revised.llm_plans_used = int(llm_plans_used)
            if termination_reason:
                revised.termination_reason = termination_reason
                revised.termination_detail = termination_detail
            revised.updated_at = now or utcnow()
            # record the move reason on the revision provenance
            if reason:
                revised.provenance = dict(revised.provenance)
                revised.provenance["last_reason"] = reason[:200]
            self._append(OBJECTIVES_FILE, revised.to_dict())
            return revised

    # ---------------------------------------------------------------- plans
    def get_plan(self, plan_id: str) -> HuntPlan | None:
        for row in self._lines(PLANS_FILE):
            if row.get("plan_id") == plan_id:
                try:
                    return HuntPlan.from_dict(row)
                except PlanError as exc:
                    raise HuntStoreError(f"malformed plan row: {exc}") from None
        return None

    def append_plan(self, plan: HuntPlan) -> HuntPlan:
        """Append an immutable definition; duplicate id with a different
        definition is rejected (duplicate/mutation guard)."""
        with self._locked():
            existing = self.get_plan(plan.plan_id)
            if existing is not None:
                if existing.definition_hash() != plan.definition_hash():
                    raise HuntStoreError(
                        "plan definition is immutable once stored")
                return existing
            self._append(PLANS_FILE, plan.to_dict())
            return plan

    def plans_for_objective(self, objective_id: str) -> list[HuntPlan]:
        plans: list[HuntPlan] = []
        for row in self._lines(PLANS_FILE):
            if row.get("objective_id") == objective_id:
                plans.append(HuntPlan.from_dict(row))
        return sorted(plans, key=lambda p: (p.version, p.created_at))

    # ----------------------------------------------------------- transitions
    def record_transition(self, transition_row: PlanTransition) -> None:
        current = self.plan_state(transition_row.plan_id)
        if current is None:
            raise HuntStoreError(
                f"transition for unknown plan {transition_row.plan_id!r}")
        try:
            plan_transition(current, transition_row.to_state)
        except PlanError as exc:
            raise HuntStoreError(str(exc)) from None
        with self._locked():
            self._append(TRANSITIONS_FILE, transition_row.to_dict())

    def plan_state(self, plan_id: str) -> str | None:
        plan = self.get_plan(plan_id)
        if plan is None:
            return None
        state = "DRAFT"
        for row in self._lines(TRANSITIONS_FILE):
            if row.get("plan_id") == plan_id:
                state = str(row.get("to_state") or state)
        return state

    def plan_transitions(self, plan_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self._lines(TRANSITIONS_FILE)
                if r.get("plan_id") == plan_id]

    def plan_states(self, plan_ids: list[str]) -> dict[str, str]:
        wanted = set(plan_ids)
        states: dict[str, str] = {}
        for row in self._lines(PLANS_FILE):
            pid = str(row.get("plan_id") or "")
            if pid in wanted:
                states[pid] = "DRAFT"
        for row in self._lines(TRANSITIONS_FILE):
            pid = str(row.get("plan_id") or "")
            if pid in wanted:
                states[pid] = str(row.get("to_state") or states.get(pid,
                                                                   "DRAFT"))
        return states

    def executing_definition_hash(self, plan_id: str) -> str:
        """Definition hash recorded when the plan entered EXECUTING."""
        for row in self._lines(TRANSITIONS_FILE):
            if (row.get("plan_id") == plan_id
                    and row.get("to_state") == "EXECUTING"):
                return str(row.get("definition_hash") or "")
        return ""

    # -------------------------------------------------------- authorizations
    def append_authorization(self, record: AuthorizationRecord) -> None:
        with self._locked():
            self._append(AUTHORIZATIONS_FILE, record.to_dict())

    def get_authorization(self, auth_id: str) -> AuthorizationRecord | None:
        for row in self._lines(AUTHORIZATIONS_FILE):
            if row.get("auth_id") == auth_id:
                return AuthorizationRecord.from_dict(row)
        return None

    def authorizations_for_plan(self, plan_id: str) -> list[
            AuthorizationRecord]:
        return [AuthorizationRecord.from_dict(r)
                for r in self._lines(AUTHORIZATIONS_FILE)
                if r.get("plan_id") == plan_id]

    # --------------------------------------------------------- observations
    def append_observation(self, record: ObservationRecord) -> None:
        with self._locked():
            self._append(OBSERVATIONS_FILE, record.to_dict())

    def observations_for_objective(self, objective_id: str) -> list[
            ObservationRecord]:
        return [ObservationRecord.from_dict(r)
                for r in self._lines(OBSERVATIONS_FILE)
                if r.get("objective_id") == objective_id]

    def observations_for_job(self, job_id: str) -> list[ObservationRecord]:
        return [ObservationRecord.from_dict(r)
                for r in self._lines(OBSERVATIONS_FILE)
                if r.get("job_id") == job_id]

    # ------------------------------------------------------------- summary
    def objective_bundle(self, objective_id: str) -> dict[str, Any]:
        """Everything SOC/audit needs for one objective in one call."""
        objective = self.get_objective(objective_id)
        if objective is None:
            return {}
        plans = self.plans_for_objective(objective_id)
        states = self.plan_states([p.plan_id for p in plans])
        return {
            "objective": objective.to_dict(),
            "history": [o.to_dict() for o in
                        self.objective_history(objective_id)],
            "plans": [dict(p.to_dict(), state=states.get(p.plan_id, "DRAFT"))
                      for p in plans],
            "transitions": [dict(r) for r in self._lines(TRANSITIONS_FILE)
                            if any(p.plan_id == r.get("plan_id")
                                   for p in plans)],
            "authorizations": [a.to_dict() for a in
                               self._all_auths_for_objective(objective_id)],
            "observations": [o.to_dict() for o in
                             self.observations_for_objective(objective_id)],
        }

    def _all_auths_for_objective(self, objective_id: str) -> list[
            AuthorizationRecord]:
        return [AuthorizationRecord.from_dict(r)
                for r in self._lines(AUTHORIZATIONS_FILE)
                if r.get("objective_id") == objective_id]


__all__ = [
    "AUTHORIZATIONS_FILE",
    "OBJECTIVES_FILE",
    "OBSERVATIONS_FILE",
    "PLANS_FILE",
    "TRANSITIONS_FILE",
    "HuntStore",
    "HuntStoreError",
    "utcnow",
]
