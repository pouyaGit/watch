"""Phase 1/2/3 persistence: append-only campaign store with lease safety.

Mirrors ``hunt.store.HuntStore``: JSONL snapshots under the runtime base
dir, ``flock`` serialized mutations, latest-row-wins reads, append-only
transition/budget/context ledgers.  A separate ``.campaign.lock`` is the
one new lock file — campaign mutations span several files (campaign +
objectives + budget + context) so they must serialize atomically; job and
hunt locks stay untouched (Phase 13: reuse where possible, new only where
necessary).
"""
from __future__ import annotations

import fcntl
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from backend.research_agents.campaign.models import (
    Campaign, CampaignObjective, CampaignStateError, Dependency,
    validate_campaign_transition, validate_objective_transition, utcnow,
)

# Phase 7: default cumulative budget (limits). Consumed amounts live in
# Campaign.budget and the append-only ledger; they never reset per
# objective.
DEFAULT_LIMITS: dict[str, int] = {
    "max_objectives": 6,
    "max_completed_objectives": 6,
    "max_active_objectives": 1,
    "max_llm_calls": 4,
    "max_observations": 12,
    "max_hunt_plans": 8,
    "max_runtime_seconds": 600,
    "max_retries": 3,
    "max_context_chars": 4000,
    "max_knowledge_documents": 20,
    "max_campaign_lifetime_seconds": 86400,
}

# Budget keys that are consumed cumulatively (Phase 7 examples).
CONSUMABLE_KEYS: tuple[str, ...] = (
    "llm_calls", "observations", "hunt_plans", "runtime_seconds",
    "knowledge_documents", "retries", "completed_objectives",
    "active_objectives", "objectives", "context_chars",
    "campaign_lifetime_seconds",
)

_FILE_CAMPAIGNS = "campaigns.jsonl"
_FILE_OBJECTIVES = "campaign_objectives.jsonl"
_FILE_TRANSITIONS = "campaign_transitions.jsonl"
_FILE_BUDGET = "campaign_budget.jsonl"
_FILE_CONTEXT = "campaign_context.jsonl"


class CampaignStoreError(RuntimeError):
    """Persistence-level failure (integrity, duplicate, malformed row)."""


class CampaignStore:
    """Append-only campaign state store pinned to the runtime base dir."""

    def __init__(self, base_dir: str | Path | None = None):
        if base_dir is None:
            from backend.research_agents.runtime_store import runtime_base_dir
            base = runtime_base_dir()
        else:
            base = Path(base_dir)
        self.base = Path(base)
        self.base.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.base / ".campaign.lock"

    # -- primitives --------------------------------------------------------

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
                except (TypeError, ValueError):
                    continue
                if isinstance(row, dict):
                    yield row

    def _append(self, name: str, row: dict[str, Any]) -> None:
        path = self._path(name)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True,
                                ensure_ascii=True) + "\n")
            fh.flush()

    def _locked(self):
        """flock context manager over the campaign lock file."""

        class _Ctx:
            def __init__(self, path: Path):
                self.path = path
                self.fh = None

            def __enter__(self_inner):
                self_inner.fh = self_inner.path.open("a+",
                                                     encoding="utf-8")
                fcntl.flock(self_inner.fh.fileno(), fcntl.LOCK_EX)
                return self_inner

            def __exit__(self_inner, *exc):
                try:
                    fcntl.flock(self_inner.fh.fileno(), fcntl.LOCK_UN)
                finally:
                    self_inner.fh.close()
                return False

        return _Ctx(self._lock_path)

    # -- campaigns ---------------------------------------------------------

    def get_campaign(self, campaign_id: str) -> Campaign | None:
        latest: dict[str, Any] | None = None
        for row in self._lines(_FILE_CAMPAIGNS):
            if row.get("campaign_id") == campaign_id:
                latest = row
        if latest is None:
            return None
        return Campaign.from_dict(latest)

    def list_campaigns(self, *, state: str | None = None) -> list[Campaign]:
        latest: dict[str, dict[str, Any]] = {}
        for row in self._lines(_FILE_CAMPAIGNS):
            cid = str(row.get("campaign_id") or "")
            if cid:
                latest[cid] = row
        out = [Campaign.from_dict(r) for r in latest.values()]
        if state:
            out = [c for c in out if c.state == state]
        out.sort(key=lambda c: c.created_at)
        return out

    def create_campaign(self, campaign: Campaign) -> Campaign:
        """Create; refuses duplicates and scope-less campaigns."""

        with self._locked():
            if self.get_campaign(campaign.campaign_id) is not None:
                raise CampaignStoreError(
                    f"duplicate campaign: {campaign.campaign_id}")
            if not campaign.scope_ref:
                raise CampaignStoreError("campaign without scope refused")
            self._append(_FILE_CAMPAIGNS, campaign.to_dict())
            self._append(_FILE_TRANSITIONS, {
                "kind": "campaign",
                "id": campaign.campaign_id,
                "old": "", "new": campaign.state,
                "reason": "created",
                "at": utcnow(),
            })
        return campaign

    def save_campaign(self, campaign: Campaign) -> Campaign:
        """Append a new snapshot (latest wins). Validates transitions."""

        with self._locked():
            current = self.get_campaign(campaign.campaign_id)
            if current is None:
                raise CampaignStoreError(
                    f"unknown campaign: {campaign.campaign_id}")
            if campaign.state != current.state:
                validate_campaign_transition(current.state, campaign.state)
            if campaign.revision < current.revision:
                raise CampaignStoreError(
                    f"stale campaign snapshot for {campaign.campaign_id}")
            campaign.revision = max(campaign.revision, current.revision + 1)
            campaign.updated_at = utcnow()
            self._append(_FILE_CAMPAIGNS, campaign.to_dict())
            if campaign.state != current.state:
                self._append(_FILE_TRANSITIONS, {
                    "kind": "campaign",
                    "id": campaign.campaign_id,
                    "old": current.state, "new": campaign.state,
                    "reason": campaign.termination_reason or "transition",
                    "at": campaign.updated_at,
                })
        return campaign

    def transition_campaign(self, campaign_id: str, new_state: str, *,
                            reason: str = "",
                            detail: str = "") -> Campaign:
        """Validated transition + auditable transition row."""

        with self._locked():
            campaign = self.get_campaign(campaign_id)
            if campaign is None:
                raise CampaignStoreError(f"unknown campaign: {campaign_id}")
            validate_campaign_transition(campaign.state, new_state)
            old = campaign.state
            campaign.transition(new_state, reason=reason, detail=detail)
            self._append(_FILE_CAMPAIGNS, campaign.to_dict())
            self._append(_FILE_TRANSITIONS, {
                "kind": "campaign",
                "id": campaign_id,
                "old": old, "new": new_state,
                "reason": reason or "transition",
                "detail": str(detail or "")[:400],
                "at": campaign.updated_at,
            })
        return campaign

    def record_termination(self, campaign_id: str, record: dict[str, Any],
                           *, state: str, reason: str) -> Campaign:
        """Phase 11: terminal state + full termination record atomically."""

        with self._locked():
            campaign = self.get_campaign(campaign_id)
            if campaign is None:
                raise CampaignStoreError(f"unknown campaign: {campaign_id}")
            validate_campaign_transition(campaign.state, state)
            old = campaign.state
            campaign.transition(state, reason=reason,
                                detail=str(record.get("detail") or ""))
            campaign.termination_record = {
                "reason": reason,
                "timestamp": campaign.updated_at,
                "remaining_objectives": record.get(
                    "remaining_objectives", []),
                "budget_state": record.get("budget_state", {}),
                "last_completed_objective": record.get(
                    "last_completed_objective", ""),
                "last_evidence_state": record.get(
                    "last_evidence_state", ""),
                "detail": str(record.get("detail") or "")[:600],
            }
            self._append(_FILE_CAMPAIGNS, campaign.to_dict())
            self._append(_FILE_TRANSITIONS, {
                "kind": "campaign",
                "id": campaign_id,
                "old": old, "new": state,
                "reason": reason,
                "detail": str(record.get("detail") or "")[:400],
                "at": campaign.updated_at,
            })
        return campaign

    # -- coordinator lease (Phase 13) --------------------------------------

    def claim_lease(self, campaign_id: str, owner: str, *,
                    ttl_seconds: int = 120,
                    now: str | None = None) -> tuple[bool, str]:
        """One coordinator per campaign. Returns (ok, reason).

        Fail closed: an unexpired foreign lease refuses; an expired lease
        (crashed coordinator) is reclaimable; a stale RUNNING state from a
        dead coordinator is handled by lease expiry, never by guessing.
        """

        now = now or utcnow()

        def _ts(value: object) -> datetime | None:
            """Parse a stored/lease timestamp (Z or +00:00 tolerant).

            Unparseable timestamps are treated as UNEXPIRED (fail
            closed): a lease we cannot age must be assumed live."""
            if value in (None, ""):
                return None
            try:
                return datetime.fromisoformat(
                    str(value).replace("Z", "+00:00"))
            except ValueError:
                return None

        with self._locked():
            campaign = self.get_campaign(campaign_id)
            if campaign is None:
                return False, f"unknown campaign: {campaign_id}"
            if campaign.is_terminal:
                return False, f"campaign is terminal ({campaign.state})"
            holder = campaign.lease_owner
            expiry = campaign.lease_expires_at
            now_dt = _ts(now) or datetime.now(timezone.utc)
            expiry_dt = _ts(expiry)
            live = (expiry_dt is not None
                    and expiry_dt > now_dt) if expiry else False
            if holder and holder != owner:
                if live:
                    return False, (
                        f"coordinator lease held by {holder} until "
                        f"{expiry}")
                # expired / unageable lease: reclaim below
            if holder == owner and live:
                return True, "lease renewed"
            from datetime import timedelta
            # expiry is computed from the SAME `now` the caller passed,
            # so simulated clocks (tests/recovery) age correctly.
            expires = (now_dt
                       + timedelta(seconds=max(1, int(ttl_seconds)))
                       ).isoformat(timespec="seconds")
            campaign.lease_owner = owner
            campaign.lease_expires_at = expires
            campaign.updated_at = now
            self._append(_FILE_CAMPAIGNS, campaign.to_dict())
            self._append(_FILE_TRANSITIONS, {
                "kind": "lease",
                "id": campaign_id,
                "old": holder, "new": owner,
                "reason": "coordinator lease claimed",
                "at": now,
            })
            return True, "lease acquired"

    def renew_lease(self, campaign_id: str, owner: str, *,
                    ttl_seconds: int = 120) -> bool:
        with self._locked():
            campaign = self.get_campaign(campaign_id)
            if campaign is None or campaign.lease_owner != owner:
                return False
            from datetime import datetime, timedelta, timezone
            campaign.lease_expires_at = (
                datetime.now(timezone.utc)
                + timedelta(seconds=max(5, int(ttl_seconds)))
            ).isoformat(timespec="seconds")
            campaign.updated_at = utcnow()
            self._append(_FILE_CAMPAIGNS, campaign.to_dict())
            return True

    def release_lease(self, campaign_id: str, owner: str) -> bool:
        with self._locked():
            campaign = self.get_campaign(campaign_id)
            if campaign is None or campaign.lease_owner != owner:
                return False
            campaign.lease_owner = ""
            campaign.lease_expires_at = ""
            campaign.updated_at = utcnow()
            self._append(_FILE_CAMPAIGNS, campaign.to_dict())
            self._append(_FILE_TRANSITIONS, {
                "kind": "lease",
                "id": campaign_id,
                "old": owner, "new": "",
                "reason": "coordinator lease released",
                "at": campaign.updated_at,
            })
            return True

    # -- objectives (Phase 2/3) -------------------------------------------

    def get_objective(self, objective_id: str) -> CampaignObjective | None:
        latest: dict[str, Any] | None = None
        for row in self._lines(_FILE_OBJECTIVES):
            if row.get("objective_id") == objective_id:
                latest = row
        if latest is None:
            return None
        return CampaignObjective.from_dict(latest)

    def objectives_for_campaign(self, campaign_id: str) -> list[CampaignObjective]:
        latest: dict[str, dict[str, Any]] = {}
        for row in self._lines(_FILE_OBJECTIVES):
            if row.get("campaign_id") != campaign_id:
                continue
            oid = str(row.get("objective_id") or "")
            if oid:
                latest[oid] = row
        out = [CampaignObjective.from_dict(r) for r in latest.values()]
        out.sort(key=lambda o: (o.created_at, o.objective_id))
        return out

    def add_objective(self, objective: CampaignObjective,
                      campaign: Campaign | None = None) -> CampaignObjective:
        """Create objective; scope must match the campaign (rule 16)."""

        with self._locked():
            if campaign is None:
                campaign = self.get_campaign(objective.campaign_id)
            if campaign is None:
                raise CampaignStoreError(
                    f"unknown campaign: {objective.campaign_id}")
            if not campaign.scope_matches(objective.scope_ref):
                raise CampaignStoreError(
                    "objective scope does not match campaign scope "
                    "(scope widening refused)")
            if self.get_objective(objective.objective_id) is not None:
                raise CampaignStoreError(
                    f"duplicate objective: {objective.objective_id}")
            existing = self.objectives_for_campaign(campaign.campaign_id)
            limit = int(campaign.limits.get("max_objectives", 0))
            if limit and len(existing) >= limit:
                raise CampaignStoreError(
                    f"max_objectives budget reached ({limit})")
            # Phase 3: validate dependency graph (no cycles, endpoints exist)
            by_id = {o.objective_id: o for o in existing}
            for dep in objective.dependencies:
                if dep.objective_id != objective.objective_id:
                    raise CampaignStoreError(
                        "dependency objective_id must reference the new "
                        "objective")
                if dep.depends_on != objective.objective_id:
                    if dep.depends_on not in by_id:
                        raise CampaignStoreError(
                            f"unknown dependency endpoint: {dep.depends_on}")
                    # cycle: dep.depends_on must not (transitively) depend
                    # on the new objective — validated fully below.
            from backend.research_agents.campaign.dependencies import (
                assert_acyclic,
            )
            assert_acyclic([*existing, objective])
            self._append(_FILE_OBJECTIVES, objective.to_dict())
            self._append(_FILE_TRANSITIONS, {
                "kind": "objective",
                "id": objective.objective_id,
                "campaign_id": objective.campaign_id,
                "old": "", "new": objective.state,
                "reason": "created",
                "at": objective.created_at,
            })
        return objective

    def save_objective(self, objective: CampaignObjective) -> CampaignObjective:
        """Append snapshot; validates transition + scope invariants."""

        with self._locked():
            current = self.get_objective(objective.objective_id)
            if current is None:
                raise CampaignStoreError(
                    f"unknown objective: {objective.objective_id}")
            campaign = self.get_campaign(objective.campaign_id)
            if campaign is not None and \
                    not campaign.scope_matches(objective.scope_ref):
                raise CampaignStoreError(
                    "objective scope no longer matches campaign scope")
            # invariant: dependency edits can never introduce a cycle
            # (Phase 3: A -> B -> A refused at the persistence layer,
            # before execution, not only at resolve time).
            from backend.research_agents.campaign.dependencies import (
                assert_acyclic,
            )
            others = [o for o in
                      self.objectives_for_campaign(objective.campaign_id)
                      if o.objective_id != objective.objective_id]
            assert_acyclic([*others, objective])
            if objective.state != current.state:
                validate_objective_transition(current.state, objective.state)
            if objective.revision < current.revision:
                raise CampaignStoreError(
                    f"stale objective snapshot: {objective.objective_id}")
            objective.revision = max(objective.revision,
                                     current.revision + 1)
            objective.updated_at = utcnow()
            self._append(_FILE_OBJECTIVES, objective.to_dict())
            if objective.state != current.state:
                self._append(_FILE_TRANSITIONS, {
                    "kind": "objective",
                    "id": objective.objective_id,
                    "campaign_id": objective.campaign_id,
                    "old": current.state, "new": objective.state,
                    "reason": objective.termination_reason or "transition",
                    "detail": str(objective.termination_detail or "")[:400],
                    "at": objective.updated_at,
                })
        return objective

    def transition_objective(self, objective_id: str, new_state: str, *,
                             reason: str = "",
                             detail: str = "") -> CampaignObjective:
        with self._locked():
            objective = self.get_objective(objective_id)
            if objective is None:
                raise CampaignStoreError(
                    f"unknown objective: {objective_id}")
            validate_objective_transition(objective.state, new_state)
            old = objective.state
            objective.transition(new_state, reason=reason, detail=detail)
            self._append(_FILE_OBJECTIVES, objective.to_dict())
            self._append(_FILE_TRANSITIONS, {
                "kind": "objective",
                "id": objective_id,
                "campaign_id": objective.campaign_id,
                "old": old, "new": new_state,
                "reason": reason or "transition",
                "detail": str(detail or "")[:400],
                "at": objective.updated_at,
            })
        return objective

    # -- budget ledger (Phase 7) ------------------------------------------

    def record_budget(self, campaign_id: str, *, resource: str,
                      delta: int, before: int, after: int,
                      reason: str, objective_id: str = "") -> None:
        """Every budget consumption is auditable (before/after)."""

        with self._locked():
            self._append(_FILE_BUDGET, {
                "campaign_id": campaign_id,
                "resource": resource,
                "delta": int(delta),
                "before": int(before),
                "after": int(after),
                "reason": str(reason)[:200],
                "objective_id": objective_id,
                "at": utcnow(),
            })

    def budget_ledger(self, campaign_id: str) -> list[dict[str, Any]]:
        return [r for r in self._lines(_FILE_BUDGET)
                if r.get("campaign_id") == campaign_id]

    # -- cross-objective context (Phase 9) --------------------------------

    def record_context(self, row: dict[str, Any]) -> dict[str, Any]:
        """Provenance-aware context item (NEVER evidence, never authoritative)."""

        payload = {
            "context_id": str(row.get("context_id") or
                              f"ctx-{len(list(self._lines(_FILE_CONTEXT))) + 1:06d}"),
            "campaign_id": str(row.get("campaign_id") or ""),
            "source_objective_id": str(row.get("source_objective_id") or ""),
            "source_job_id": str(row.get("source_job_id") or ""),
            "source_ref": str(row.get("source_ref") or ""),
            "confidence": str(row.get("confidence") or "not_evaluated"),
            "state": str(row.get("state") or ""),
            "scope_ref": str(row.get("scope_ref") or ""),
            "text": str(row.get("text") or "")[:400],
            "research_context_only": True,   # hard label: not evidence
            "at": str(row.get("at") or utcnow()),
        }
        if not payload["campaign_id"] or not payload["text"]:
            raise CampaignStoreError("context row requires campaign_id+text")
        with self._locked():
            self._append(_FILE_CONTEXT, payload)
        return payload

    def context_for(self, campaign_id: str, *, scope_ref: str = "",
                    exclude_objective: str = "",
                    limit: int = 6) -> list[dict[str, Any]]:
        """Bounded, scope-safe context for a starting objective."""

        rows = [r for r in self._lines(_FILE_CONTEXT)
                if r.get("campaign_id") == campaign_id]
        if scope_ref:
            rows = [r for r in rows if r.get("scope_ref") == scope_ref]
        if exclude_objective:
            rows = [r for r in rows
                    if r.get("source_objective_id") != exclude_objective]
        rows.sort(key=lambda r: str(r.get("at") or ""))
        return rows[-max(1, int(limit)):]


__all__ = [
    "CampaignStore", "CampaignStoreError", "DEFAULT_LIMITS",
    "CONSUMABLE_KEYS",
]
