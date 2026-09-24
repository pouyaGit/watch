"""EPIC12 — the evidence budget for deep verification (§16).

Every deep-verification objective carries explicit limits: maximum actions,
requests, payload attempts, runtime, observations and retries.  Consumption is
cumulative and auditable (one ledger row per check, refusals included), and
exhaustion **raises before the work starts** — it can never produce a
confirmation.

The budget composes with the finding layer's budget instead of replacing it:
resources owned by EPIC11 (``max_verification_observations``, ``max_llm_calls``,
``max_verification_runtime_seconds`` …) are delegated to the existing
:class:`~backend.research_agents.finding.limits.FindingBudget` when one is
supplied, so there is exactly one ledger per layer and no double accounting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Verification-layer limits (§16).  ``max_payload_attempts`` defaults to 0
#: because no payload-execution lane is wired in this runtime: the budget
#: refuses before anything could be attempted, which is the honest state.
DEFAULT_VERIFICATION_LIMITS: dict[str, int] = {
    "max_actions": 6,
    "max_requests": 4,
    "max_payload_attempts": 0,
    "max_runtime_seconds": 60,
    "max_observations": 12,
    "max_retries": 1,
}

#: Resources the verification layer owns (everything else is delegated).
VERIFICATION_RESOURCES: tuple[str, ...] = tuple(sorted(
    DEFAULT_VERIFICATION_LIMITS))

BUDGET_RULE_VERSION = "epic12-verification-budget-1"


class VerificationBudgetExhausted(Exception):
    """Raised BEFORE work whose budget is already spent (fail closed)."""


@dataclass
class VerificationBudget:
    """Cumulative, auditable, fail-closed budget for one verification loop."""

    store: Any
    limits: dict[str, int] = field(
        default_factory=lambda: dict(DEFAULT_VERIFICATION_LIMITS))
    objective_id: str = ""
    outer: Any = None                     # optional FindingBudget (EPIC11)
    rule_version: str = BUDGET_RULE_VERSION

    # ------------------------------------------------------------- reading

    def used(self) -> dict[str, int]:
        try:
            return dict(self.store.budget_used())
        except Exception as exc:  # noqa: BLE001 - a broken ledger fails closed
            raise VerificationBudgetExhausted(
                f"budget_ledger_unreadable:{type(exc).__name__}")

    def remaining(self) -> dict[str, int]:
        used = self.used()
        return {k: int(v) - int(used.get(k, 0)) for k, v in self.limits.items()}

    def exhausted(self) -> list[str]:
        return sorted(k for k, v in self.remaining().items() if v <= 0)

    def ok(self, resource: str) -> bool:
        return self.remaining().get(resource, 0) > 0

    def delegated(self, resource: str) -> bool:
        """True when the resource belongs to the outer (EPIC11) budget."""
        if resource in self.limits:
            return False
        outer_limits = getattr(self.outer, "limits", None)
        return bool(outer_limits) and resource in outer_limits

    # ------------------------------------------------------------ consuming

    def ensure(self, resource: str, delta: int = 1, *, reason: str = "") -> None:
        """Check + record atomically; refuse when the budget cannot cover it."""
        resource = str(resource or "").strip()
        if self.delegated(resource):
            try:
                self.outer.ensure(resource, delta, reason=reason)
            except Exception as exc:  # noqa: BLE001 - outer refuses -> refuse
                raise VerificationBudgetExhausted(
                    f"{resource} exhausted by finding budget: "
                    f"{type(exc).__name__}")
            return
        if resource not in self.limits:
            raise VerificationBudgetExhausted(f"unknown_resource:{resource}")
        before = int(self.used().get(resource, 0))
        limit = int(self.limits[resource])
        if before + int(delta) > limit:
            try:
                self.store.record_budget(
                    resource=resource, delta=0, before=before, after=before,
                    reason=(reason or "refused")
                            + f":over_limit:{before + int(delta)}>{limit}",
                    objective_id=self.objective_id)
            finally:
                raise VerificationBudgetExhausted(
                    f"{resource} exhausted: {before}+{int(delta)} > {limit}")
        after = before + int(delta)
        self.store.record_budget(
            resource=resource, delta=int(delta), before=before, after=after,
            reason=reason or "consumed", objective_id=self.objective_id)

    def allow(self, resource: str, delta: int = 1) -> bool:
        """Non-raising check (for planning): would ``ensure`` succeed?"""
        if self.delegated(resource):
            try:
                return bool(self.outer.ok(resource))
            except Exception:  # noqa: BLE001
                return False
        if resource not in self.limits:
            return False
        return int(self.remaining().get(resource, 0)) >= int(delta)

    def report(self) -> dict[str, Any]:
        used = self.used()
        return {
            "objective_id": self.objective_id,
            "limits": {k: int(v) for k, v in self.limits.items()},
            "used": {k: int(used.get(k, 0)) for k in self.limits},
            "remaining": self.remaining(),
            "exhausted": self.exhausted(),
            "rule_version": self.rule_version,
        }


__all__ = [
    "BUDGET_RULE_VERSION", "DEFAULT_VERIFICATION_LIMITS",
    "VERIFICATION_RESOURCES", "VerificationBudget",
    "VerificationBudgetExhausted",
]
