"""aec/budget_ledger.py — AEC-1 T3 (S6): deterministic budget ledger.

The ledger answers one question: "Is this proposed observation allowed by the
approved budget?" It does not execute anything, approve any authorization, or
decide security impact. It only tracks budget consumption and refusal reasons.

Design constraints:

- **Offline.** Stdlib ``dataclasses`` + ``typing`` and the ``aec`` constants
  only. No transport, no subprocess, no filesystem, no clock: event timestamps
  default to a deterministic logical clock (``t-000001`` …), so two runs over
  the same inputs produce byte-identical output. A caller that wants wall-clock
  time passes it in explicitly.
- **Fail-closed.** The check order is fixed and every refusal carries exactly
  one code from the closed ``REASON_CODES`` vocabulary. Unknown cases, unknown
  hosts, case/host mismatches and non-positive costs are all denials.
- **Pure proposal, single writer.** :meth:`BudgetLedger.propose` never mutates
  anything; :meth:`BudgetLedger.commit` is the only method that records
  consumption, and it appends exactly one immutable :class:`BudgetEvent` per
  call — ``COMMIT`` for allowances, ``DENIED`` for refusals. Counters only move
  one way: a denial consumes nothing.
- **Never verdicts.** Reason codes describe budget state, never security
  impact. There is no finding, severity or confirmed vocabulary anywhere here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from aec import MAX_HOSTS, PILOT_BUDGET

RULE_VERSION = "aec-budget-ledger/v1"

#: The single allowance code.
BUDGET_AVAILABLE = "BUDGET_AVAILABLE"

#: Closed refusal vocabulary. No free-form denial reasons exist.
TOTAL_BUDGET_EXCEEDED = "TOTAL_BUDGET_EXCEEDED"
CASE_BUDGET_EXCEEDED = "CASE_BUDGET_EXCEEDED"
HOST_BUDGET_EXCEEDED = "HOST_BUDGET_EXCEEDED"
CASE_COUNT_EXCEEDED = "CASE_COUNT_EXCEEDED"
HOST_COUNT_EXCEEDED = "HOST_COUNT_EXCEEDED"
INVALID_COST = "INVALID_COST"
UNKNOWN_CASE = "UNKNOWN_CASE"
UNKNOWN_HOST = "UNKNOWN_HOST"
CASE_HOST_MISMATCH = "CASE_HOST_MISMATCH"

REASON_CODES = (
    BUDGET_AVAILABLE,
    TOTAL_BUDGET_EXCEEDED,
    CASE_BUDGET_EXCEEDED,
    HOST_BUDGET_EXCEEDED,
    CASE_COUNT_EXCEEDED,
    HOST_COUNT_EXCEEDED,
    INVALID_COST,
    UNKNOWN_CASE,
    UNKNOWN_HOST,
    CASE_HOST_MISMATCH,
)

#: Closed event-action vocabulary.
ACTION_COMMIT = "COMMIT"
ACTION_DENIED = "DENIED"
ACTIONS = (ACTION_COMMIT, ACTION_DENIED)


def _require_positive_int(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive int, got {value!r}")
    return value


def _text(value: object) -> str:
    return str(value or "").strip()


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class BudgetPolicy:
    """Approved budget limits. Invalid construction is refused, never repaired."""

    max_total_requests: int
    max_case_requests: int
    max_host_requests: int
    max_cases: int
    max_hosts: int

    def __post_init__(self) -> None:
        _require_positive_int("max_total_requests", self.max_total_requests)
        _require_positive_int("max_case_requests", self.max_case_requests)
        _require_positive_int("max_host_requests", self.max_host_requests)
        _require_positive_int("max_cases", self.max_cases)
        _require_positive_int("max_hosts", self.max_hosts)

    def to_dict(self) -> dict[str, int]:
        return {
            "max_total_requests": self.max_total_requests,
            "max_case_requests": self.max_case_requests,
            "max_host_requests": self.max_host_requests,
            "max_cases": self.max_cases,
            "max_hosts": self.max_hosts,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "BudgetPolicy":
        return cls(
            max_total_requests=payload["max_total_requests"],
            max_case_requests=payload["max_case_requests"],
            max_host_requests=payload["max_host_requests"],
            max_cases=payload["max_cases"],
            max_hosts=payload["max_hosts"],
        )


def default_policy() -> BudgetPolicy:
    """The approved pilot budget as a ledger policy (tighten-only downstream)."""
    return BudgetPolicy(
        max_total_requests=PILOT_BUDGET.max_requests,
        max_case_requests=PILOT_BUDGET.max_requests_per_case,
        max_host_requests=PILOT_BUDGET.max_requests_per_host,
        max_cases=PILOT_BUDGET.max_cases,
        max_hosts=MAX_HOSTS,
    )


@dataclass(frozen=True)
class BudgetUsage:
    """Immutable consumption snapshot. Per-key pairs are sorted tuples."""

    total_requests_used: int = 0
    case_usage: tuple = ()
    host_usage: tuple = ()

    def cases(self) -> dict[str, int]:
        return dict(self.case_usage)

    def hosts(self) -> dict[str, int]:
        return dict(self.host_usage)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_requests_used": self.total_requests_used,
            "case_usage": [list(pair) for pair in self.case_usage],
            "host_usage": [list(pair) for pair in self.host_usage],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "BudgetUsage":
        return cls(
            total_requests_used=int(payload.get("total_requests_used", 0)),
            case_usage=tuple(
                (str(pair[0]), int(pair[1])) for pair in payload.get("case_usage", ())
            ),
            host_usage=tuple(
                (str(pair[0]), int(pair[1])) for pair in payload.get("host_usage", ())
            ),
        )


@dataclass(frozen=True)
class BudgetDecision:
    """One allow/deny answer. ``allowed`` is true exactly for BUDGET_AVAILABLE."""

    allowed: bool
    reason_code: str
    remaining_budget: int
    requested_cost: int
    case_id: str = ""
    host: str = ""

    def __post_init__(self) -> None:
        if self.reason_code not in REASON_CODES:
            raise ValueError(f"unknown reason code: {self.reason_code!r}")
        if self.allowed != (self.reason_code == BUDGET_AVAILABLE):
            raise ValueError("allowed must agree with the reason code")

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "remaining_budget": self.remaining_budget,
            "requested_cost": self.requested_cost,
            "case_id": self.case_id,
            "host": self.host,
        }


@dataclass(frozen=True)
class BudgetEvent:
    """One immutable accounting event, appended in call order."""

    event_id: str
    case_id: str
    host: str
    action: str
    cost: int
    timestamp: str
    reason: str

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError(f"unknown event action: {self.action!r}")
        if self.reason not in REASON_CODES:
            raise ValueError(f"unknown event reason: {self.reason!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "case_id": self.case_id,
            "host": self.host,
            "action": self.action,
            "cost": self.cost,
            "timestamp": self.timestamp,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "BudgetEvent":
        return cls(
            event_id=str(payload["event_id"]),
            case_id=str(payload["case_id"]),
            host=str(payload["host"]),
            action=str(payload["action"]),
            cost=int(payload["cost"]),
            timestamp=str(payload["timestamp"]),
            reason=str(payload["reason"]),
        )


# --------------------------------------------------------------------------
# Ledger
# --------------------------------------------------------------------------


class BudgetLedger:
    """Deterministic budget accounting over a registered case -> host map.

    ``known`` maps each in-scope case id to its host. It is copied at
    construction: later caller-side mutation of the passed mapping cannot move
    the ledger. :meth:`propose` is pure; :meth:`commit` appends one event.
    """

    def __init__(
        self,
        policy: BudgetPolicy | None = None,
        known: Mapping[str, str] | None = None,
    ) -> None:
        self._policy = policy if policy is not None else default_policy()
        if not isinstance(self._policy, BudgetPolicy):
            raise ValueError("policy must be a BudgetPolicy")
        self._known: dict[str, str] = {}
        if known:
            for case_id, host in dict(known).items():
                case, host_text = _text(case_id), _text(host)
                if case and host_text:
                    self._known[case] = host_text
        self._case_used: dict[str, int] = {}
        self._host_used: dict[str, int] = {}
        self._total_used = 0
        self._events: list[BudgetEvent] = []
        self._seq = 0

    # -- read-only views ----------------------------------------------------

    @property
    def policy(self) -> BudgetPolicy:
        return self._policy

    def usage(self) -> BudgetUsage:
        return BudgetUsage(
            total_requests_used=self._total_used,
            case_usage=tuple(sorted(self._case_used.items())),
            host_usage=tuple(sorted(self._host_used.items())),
        )

    def events(self) -> tuple[BudgetEvent, ...]:
        return tuple(self._events)

    # -- decisions ----------------------------------------------------------

    @staticmethod
    def _valid_cost(cost: object) -> bool:
        return isinstance(cost, int) and not isinstance(cost, bool) and cost > 0

    def _remaining(self, extra: int = 0) -> int:
        return max(0, self._policy.max_total_requests - self._total_used - extra)

    def _decide(self, case_id: str, host: str, cost: int) -> BudgetDecision:
        policy = self._policy
        if not self._valid_cost(cost):
            return BudgetDecision(False, INVALID_COST, self._remaining(), 0, case_id, host)
        if not case_id or case_id not in self._known:
            return BudgetDecision(False, UNKNOWN_CASE, self._remaining(), cost, case_id, host)
        expected = self._known[case_id]
        if not host or host not in {expected} | set(self._known.values()):
            return BudgetDecision(False, UNKNOWN_HOST, self._remaining(), cost, case_id, host)
        if host != expected:
            return BudgetDecision(False, CASE_HOST_MISMATCH, self._remaining(), cost, case_id, host)
        if self._total_used + cost > policy.max_total_requests:
            return BudgetDecision(
                False, TOTAL_BUDGET_EXCEEDED, self._remaining(), cost, case_id, host
            )
        if self._case_used.get(case_id, 0) + cost > policy.max_case_requests:
            return BudgetDecision(
                False, CASE_BUDGET_EXCEEDED, self._remaining(), cost, case_id, host
            )
        if self._host_used.get(host, 0) + cost > policy.max_host_requests:
            return BudgetDecision(
                False, HOST_BUDGET_EXCEEDED, self._remaining(), cost, case_id, host
            )
        if case_id not in self._case_used and len(self._case_used) >= policy.max_cases:
            return BudgetDecision(
                False, CASE_COUNT_EXCEEDED, self._remaining(), cost, case_id, host
            )
        if host not in self._host_used and len(self._host_used) >= policy.max_hosts:
            return BudgetDecision(
                False, HOST_COUNT_EXCEEDED, self._remaining(), cost, case_id, host
            )
        return BudgetDecision(
            True, BUDGET_AVAILABLE, self._remaining(cost), cost, case_id, host
        )

    def propose(self, case_id: object, host: object, cost: object) -> BudgetDecision:
        """Pure allow/deny answer. Never mutates the ledger or its inputs."""
        cost_value = cost if isinstance(cost, int) and not isinstance(cost, bool) else cost
        return self._decide(_text(case_id), _text(host), cost_value)  # type: ignore[arg-type]

    def commit(
        self,
        case_id: object,
        host: object,
        cost: object,
        timestamp: object = None,
    ) -> tuple[BudgetDecision, BudgetEvent]:
        """Decide and record exactly one immutable event.

        Allowances consume budget; denials consume nothing. The event stamp
        defaults to a deterministic logical clock; pass ``timestamp`` for an
        explicit stamp (recorded verbatim).
        """
        decision = self.propose(case_id, host, cost)
        self._seq += 1
        stamp = _text(timestamp) if timestamp is not None else f"t-{self._seq:06d}"
        event = BudgetEvent(
            event_id=f"evt-{self._seq:06d}",
            case_id=decision.case_id,
            host=decision.host,
            action=ACTION_COMMIT if decision.allowed else ACTION_DENIED,
            cost=decision.requested_cost,
            timestamp=stamp,
            reason=decision.reason_code,
        )
        if decision.allowed:
            self._total_used += decision.requested_cost
            self._case_used[decision.case_id] = (
                self._case_used.get(decision.case_id, 0) + decision.requested_cost
            )
            self._host_used[decision.host] = (
                self._host_used.get(decision.host, 0) + decision.requested_cost
            )
        self._events.append(event)
        return decision, event

    # -- persistence without a filesystem ------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Full ledger state as plain data (caller decides where it lives)."""
        return {
            "rule_version": RULE_VERSION,
            "policy": self._policy.to_dict(),
            "known": dict(sorted(self._known.items())),
            "usage": self.usage().to_dict(),
            "events": [event.to_dict() for event in self._events],
            "seq": self._seq,
        }

    @classmethod
    def restore(cls, payload: Mapping[str, Any]) -> "BudgetLedger":
        """Rebuild a ledger from :meth:`snapshot` without re-running logic."""
        ledger = cls(policy=BudgetPolicy.from_dict(payload["policy"]), known=dict(payload.get("known", {})))
        usage = BudgetUsage.from_dict(payload.get("usage", {}))
        ledger._case_used = dict(usage.case_usage)
        ledger._host_used = dict(usage.host_usage)
        ledger._total_used = usage.total_requests_used
        ledger._events = [BudgetEvent.from_dict(item) for item in payload.get("events", ())]
        ledger._seq = int(payload.get("seq", len(ledger._events)))
        return ledger

    # -- human-readable audit --------------------------------------------------

    def audit_text(self) -> str:
        """Deterministic audit rendering: policy, usage, then events in order."""
        policy = self._policy
        usage = self.usage()
        lines = [
            f"budget ledger audit ({RULE_VERSION})",
            (
                f"policy: total={policy.max_total_requests} "
                f"per-case={policy.max_case_requests} "
                f"per-host={policy.max_host_requests} "
                f"cases={policy.max_cases} hosts={policy.max_hosts}"
            ),
            (
                f"usage: total={usage.total_requests_used} "
                f"remaining={self._remaining()} "
                f"cases={len(usage.case_usage)} hosts={len(usage.host_usage)}"
            ),
        ]
        for case_id, used in usage.case_usage:
            lines.append(f"  case {case_id}: {used}")
        for host, used in usage.host_usage:
            lines.append(f"  host {host}: {used}")
        lines.append(f"events: {len(self._events)}")
        for event in self._events:
            lines.append(
                f"  {event.event_id} {event.timestamp} {event.action} "
                f"{event.case_id} {event.host} cost={event.cost} {event.reason}"
            )
        return "\n".join(lines) + "\n"


__all__ = [
    "ACTIONS",
    "ACTION_COMMIT",
    "ACTION_DENIED",
    "BUDGET_AVAILABLE",
    "CASE_BUDGET_EXCEEDED",
    "CASE_COUNT_EXCEEDED",
    "CASE_HOST_MISMATCH",
    "HOST_BUDGET_EXCEEDED",
    "HOST_COUNT_EXCEEDED",
    "INVALID_COST",
    "REASON_CODES",
    "RULE_VERSION",
    "TOTAL_BUDGET_EXCEEDED",
    "UNKNOWN_CASE",
    "UNKNOWN_HOST",
    "BudgetDecision",
    "BudgetEvent",
    "BudgetLedger",
    "BudgetPolicy",
    "BudgetUsage",
    "default_policy",
]
