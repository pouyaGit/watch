"""Resource control (Phase 21) — cumulative, auditable, fail-closed.

Mirrors the campaign budget pattern: usage accumulates across the whole
finding workflow (never per-objective resets), every consumption writes a
before/after ledger row, and exhaustion raises BEFORE the work starts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

DEFAULT_LIMITS: dict[str, int] = {
    "max_candidates_per_job": 10,
    "max_candidates_total": 60,
    "max_verification_objectives": 6,
    "max_verification_observations": 12,
    "max_llm_calls": 6,
    "max_context_chars": 4000,
    "max_historical_candidates": 20,
    "max_related_cases": 6,
    "max_verification_runtime_seconds": 600,
    "max_retries": 3,
}


class BudgetExhausted(Exception):
    """Raised BEFORE work whose budget is already spent (fail closed)."""


@dataclass
class FindingBudget:
    store: Any
    limits: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_LIMITS))

    def used(self) -> dict[str, int]:
        try:
            return dict(self.store.budget_used())
        except Exception:  # noqa: BLE001 - a broken ledger fails closed
            raise BudgetExhausted("budget_ledger_unreadable")

    def remaining(self) -> dict[str, int]:
        used = self.used()
        return {k: int(self.limits.get(k, 0)) - int(used.get(k, 0))
                for k in self.limits}

    def exhausted(self) -> list[str]:
        return sorted(k for k, v in self.remaining().items() if v <= 0)

    def ok(self, resource: str) -> bool:
        return self.remaining().get(resource, 0) > 0

    def ensure(self, resource: str, delta: int = 1, *,
               reason: str = "", verification_id: str = "") -> None:
        """Check + record atomically: refuses when the budget cannot
        cover ``delta``; on success appends the before/after row."""
        if resource not in self.limits:
            raise BudgetExhausted(f"unknown_resource:{resource}")
        before = int(self.used().get(resource, 0))
        limit = int(self.limits[resource])
        if before + int(delta) > limit:
            # still record the refusal so exhaustion is auditable
            try:
                self.store.record_budget(
                    resource=resource, delta=0, before=before,
                    after=before,
                    reason=(reason or "refused")
                            + f":over_limit:{before + int(delta)}>{limit}",
                    verification_id=verification_id)
            finally:
                raise BudgetExhausted(
                    f"{resource} exhausted: {before}+{delta} > {limit}")
        after = before + int(delta)
        self.store.record_budget(
            resource=resource, delta=int(delta), before=before, after=after,
            reason=reason or "consumed", verification_id=verification_id)

    def report(self) -> dict[str, Any]:
        used = self.used()
        return {
            "limits": dict(self.limits),
            "used": used,
            "remaining": self.remaining(),
            "exhausted": self.exhausted(),
        }
