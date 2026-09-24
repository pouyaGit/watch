"""EPIC15 §17 — the deep-verification budget.

No new ceilings: every bound is read **through** from the platform's
frozen ``ai.limits.ceilings.CEILINGS`` and from EPIC13's acquisition
limits.  The budget is a counter object: it can only be spent, never
raised, and an exhausted budget stops the attempt rather than degrading
into an unbounded loop.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ai.limits import ceilings as ce
from backend.research_agents.verification.acquisition import limits as acq_limits

BUDGET_VERSION = "epic15-budget-1"

#: fallbacks only if EPIC13's limit module ever loses a key (never a
#: replacement for it — the frozen ceilings above win)
_FALLBACK = {
    "max_evidence": 32,
    "max_attempts": 1,
    "max_requests": ce.CEILINGS["requests_per_execution"],
}


def _acq_defaults() -> dict[str, Any]:
    defaults = getattr(acq_limits, "DEFAULT_LIMITS", None)
    if isinstance(defaults, dict):
        return dict(defaults)
    return {}


@dataclass
class DeepBudget:
    """The bounded allowance for one deep-verification run."""

    max_sessions: int = ce.CEILINGS["browser_contexts"]
    max_pages: int = ce.CEILINGS["browser_pages"]
    max_navigations: int = 1
    max_redirects: int = ce.CEILINGS["redirect_hops"]
    max_runtime_seconds: float = float(ce.CEILINGS["browser_wall_seconds"])
    max_js_seconds: float = float(ce.CEILINGS["browser_wall_seconds"])
    max_requests: int = ce.CEILINGS["requests_per_execution"]
    max_evidence: int = _FALLBACK["max_evidence"]
    max_attempts: int = _FALLBACK["max_attempts"]
    dom_observation_bytes: int = ce.CEILINGS["browser_dom_observation_bytes"]
    sessions_used: int = 0
    pages_used: int = 0
    navigations_used: int = 0
    redirects_used: int = 0
    runtime_used: float = 0.0
    requests_used: int = 0
    evidence_used: int = 0
    attempts_used: int = 0
    rule_version: str = BUDGET_VERSION

    @property
    def attempts_remaining(self) -> int:
        return max(0, int(self.max_attempts) - int(self.attempts_used))

    @property
    def exhausted(self) -> bool:
        return any((
            self.sessions_used >= self.max_sessions,
            self.pages_used >= self.max_pages,
            self.navigations_used >= self.max_navigations,
            self.redirects_used >= self.max_redirects,
            self.requests_used >= self.max_requests,
            self.evidence_used >= self.max_evidence,
            self.attempts_used >= self.max_attempts,
            self.runtime_used >= self.max_runtime_seconds,
        ))

    def spend_attempt(self) -> bool:
        if self.attempts_remaining <= 0:
            return False
        self.attempts_used += 1
        return True

    def spend_session(self) -> bool:
        if self.sessions_used >= self.max_sessions:
            return False
        self.sessions_used += 1
        return True

    def spend_navigation(self) -> bool:
        if self.navigations_used >= self.max_navigations:
            return False
        self.navigations_used += 1
        return True

    def spend_redirect(self) -> bool:
        if self.redirects_used >= self.max_redirects:
            return False
        self.redirects_used += 1
        return True

    def spend_evidence(self, count: int = 1) -> bool:
        if self.evidence_used + int(count) > self.max_evidence:
            return False
        self.evidence_used += int(count)
        return True

    def spend_runtime(self, seconds: float) -> bool:
        self.runtime_used += float(seconds)
        return self.runtime_used <= self.max_runtime_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_sessions": self.max_sessions,
            "max_pages": self.max_pages,
            "max_navigations": self.max_navigations,
            "max_redirects": self.max_redirects,
            "max_runtime_seconds": self.max_runtime_seconds,
            "max_js_seconds": self.max_js_seconds,
            "max_requests": self.max_requests,
            "max_evidence": self.max_evidence,
            "max_attempts": self.max_attempts,
            "dom_observation_bytes": self.dom_observation_bytes,
            "sessions_used": self.sessions_used,
            "pages_used": self.pages_used,
            "navigations_used": self.navigations_used,
            "redirects_used": self.redirects_used,
            "runtime_used": self.runtime_used,
            "requests_used": self.requests_used,
            "evidence_used": self.evidence_used,
            "attempts_used": self.attempts_used,
            "attempts_remaining": self.attempts_remaining,
            "exhausted": self.exhausted,
            "ceilings_source": "ai.limits.ceilings.CEILINGS (frozen, reused)",
            "rule_version": self.rule_version,
        }


def budget_from_ceilings(**overrides: Any) -> DeepBudget:
    """A budget whose bounds are the frozen platform ceilings."""
    defaults = _acq_defaults()
    evidence_cap = int(defaults.get("max_evidence")
                       or _FALLBACK["max_evidence"])
    budget = DeepBudget(max_evidence=evidence_cap)
    for key, value in (overrides or {}).items():
        if hasattr(budget, key):
            setattr(budget, key, value)
    return budget
