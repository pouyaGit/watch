"""Phase 7: cumulative campaign budget with auditable consumption.

Budgets are CUMULATIVE across the campaign and never reset per objective.
Every consumption records before/after in the append-only budget ledger.
When a limit is reached the caller must transition the campaign honestly
to BUDGET_EXHAUSTED (or the objective to its explicit terminal state) —
never silently continue.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from backend.research_agents.campaign.models import Campaign
from backend.research_agents.campaign.store import (
    CampaignStore, CONSUMABLE_KEYS, DEFAULT_LIMITS,
)


class BudgetExhausted(Exception):
    """Raised (and caught by the executor) when a limit is hit."""

    def __init__(self, resource: str, limit: int, used: int):
        self.resource = resource
        self.limit = limit
        self.used = used
        super().__init__(
            f"budget exhausted: {resource} {used}/{limit}")


@dataclass
class BudgetReport:
    """Remaining budget view for UI/advisor/termination records."""

    limits: dict[str, int] = field(default_factory=dict)
    used: dict[str, int] = field(default_factory=dict)
    remaining: dict[str, int] = field(default_factory=dict)
    exhausted: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"limits": dict(self.limits), "used": dict(self.used),
                "remaining": dict(self.remaining),
                "exhausted": list(self.exhausted)}


class CampaignBudget:
    """Cumulative budget controller bound to one campaign."""

    def __init__(self, store: CampaignStore, campaign: Campaign):
        self.store = store
        self.campaign = campaign
        self.limits: dict[str, int] = {**DEFAULT_LIMITS,
                                       **(campaign.limits or {})}
        self.used: dict[str, int] = {k: int((campaign.budget or {}).get(k, 0))
                                     for k in CONSUMABLE_KEYS}
        # non-consumable counters tracked from objectives when present
        for key in ("objectives", "completed_objectives",
                    "active_objectives"):
            self.used.setdefault(key, 0)

    # -- reporting ---------------------------------------------------------

    def report(self) -> BudgetReport:
        remaining: dict[str, int] = {}
        exhausted: list[str] = []
        for key, limit in self.limits.items():
            if key.startswith("max_"):
                resource = key[4:]
                left = int(limit) - int(self.used.get(resource, 0))
                remaining[resource] = left
                if left <= 0:
                    exhausted.append(resource)
        return BudgetReport(limits=dict(self.limits),
                            used=dict(self.used),
                            remaining=remaining,
                            exhausted=sorted(set(exhausted)))

    def remaining(self, resource: str) -> int:
        limit = self.limits.get(f"max_{resource}")
        if limit is None:
            return 10**9   # unlimited resource (not declared)
        return int(limit) - int(self.used.get(resource, 0))

    def is_exhausted(self, resource: str) -> bool:
        return self.remaining(resource) <= 0

    # -- consumption -------------------------------------------------------

    def consume(self, resource: str, amount: int, *, reason: str,
                objective_id: str = "") -> int:
        """Consume cumulatively; records ledger; raises BudgetExhausted
        ONLY when ``check_first`` semantics are requested by the caller
        via ``ensure()`` — consume() itself refuses to go below zero only
        for strictly-bounded resources when the caller asks.

        This method is intentionally permissive about overshoot from a
        single already-executed action (the action already happened);
        the executor checks ``ensure()`` BEFORE starting each objective.
        Negative amounts are refused (no budget refunds by code).
        """

        amount = int(amount)
        if amount <= 0:
            return self.used.get(resource, 0)
        limit = self.limits.get(f"max_{resource}")
        before = int(self.used.get(resource, 0))
        after = before + amount
        self.used[resource] = after
        self.campaign.budget[resource] = after
        self.store.record_budget(self.campaign.campaign_id,
                                 resource=resource, delta=amount,
                                 before=before, after=after, reason=reason,
                                 objective_id=objective_id)
        # persist consumed totals onto the campaign snapshot
        self.store.save_campaign(self.campaign)
        if limit is not None and after > int(limit):
            # recorded honestly; executor transitions on next ensure()
            pass
        return after

    def ensure(self, *resources: str) -> None:
        """Raise BudgetExhausted if any listed resource has no remaining."""

        for resource in resources:
            if self.is_exhausted(resource):
                limit = int(self.limits.get(f"max_{resource}", 0))
                raise BudgetExhausted(
                    resource, limit, int(self.used.get(resource, 0)))

    def can_start_objective(self) -> bool:
        """True if a new objective may start within cumulative limits."""

        checks = ("objectives", "runtime_seconds", "llm_calls",
                  "observations", "hunt_plans")
        return all(not self.is_exhausted(c) for c in checks)

    def sync_from_objectives(self, objectives: list[Any]) -> None:
        """Recompute counter-style usages from persisted objectives (used
        on resume so counters are never double-counted or lost)."""

        total = len(objectives)
        completed = sum(1 for o in objectives
                        if getattr(o, "state", "") in
                        ("RESOLVED", "REJECTED", "EXPIRED", "FAILED",
                         "CANCELLED"))
        running = sum(1 for o in objectives
                      if getattr(o, "state", "") == "RUNNING")
        for key, value in (("objectives", total),
                           ("completed_objectives", completed),
                           ("active_objectives", running)):
            if int(self.used.get(key, 0)) != value:
                self.used[key] = value
                self.campaign.budget[key] = value


__all__ = ["CampaignBudget", "BudgetReport", "BudgetExhausted",
           "DEFAULT_LIMITS"]
