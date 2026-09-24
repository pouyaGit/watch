"""EPIC12 — integration of the verification chain loop into the finding pass.

The loop is *not* a new scheduler: it is invoked inside the existing bounded
finding workflow (``run_findings``), for an objective that the existing
authorization boundary has already admitted, using the existing finding budget
when one is supplied.  This module builds the hook that the executor calls.

The hook is opt-in (``run_findings(chain_loop_fn=...)``) so the promoted EPIC11
behaviour is unchanged unless a caller asks for deep verification — and when it
is asked for, it can only *add* structured observations and chain state.  The
gate decision stays exactly where it was: the EPIC11 claim contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from backend.research_agents.verification import budget as vb
from backend.research_agents.verification import chains as ch
from backend.research_agents.verification import loop as lp
from backend.research_agents.verification import store as vs

INTEGRATION_RULE_VERSION = "epic12-verification-integration-1"


@dataclass
class ChainLoopHookResult:
    """What the executor gets back from one chain-loop invocation."""

    outcome: dict[str, Any] = field(default_factory=dict)
    evidence_rows: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    rule_version: str = INTEGRATION_RULE_VERSION

    @property
    def termination(self) -> str:
        return str(self.outcome.get("termination") or "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "termination": self.termination,
            "termination_reason": self.outcome.get("termination_reason"),
            "verdict": self.outcome.get("verdict"),
            "steps": self.outcome.get("steps"),
            "evidence_row_count": len(self.evidence_rows),
            "evidence_gained": self.outcome.get("evidence_gained"),
            "evidence_missing": self.outcome.get("evidence_missing"),
            "llm_calls": self.outcome.get("llm_calls"),
            "llm_failures": self.outcome.get("llm_failures"),
            "error": self.error,
            "rule_version": self.rule_version,
        }


def make_chain_loop_fn(
    *,
    verification_store: Any = None,
    context_fn: Callable[..., Mapping[str, Any]] | None = None,
    advisor: Callable[..., Any] | None = None,
    limits: dict[str, int] | None = None,
    max_steps: int = lp.DEFAULT_MAX_STEPS,
) -> Callable[..., ChainLoopHookResult]:
    """Build the ``chain_loop_fn`` hook for :func:`run_findings`.

    ``context_fn(candidate, verification, job, rows) -> mapping`` supplies the
    material a read-only executor may read (a recorded response body, a recorded
    document, known parameters).  Without it, executors honestly report
    ``NOT_TESTED`` rather than inventing material.
    """
    def hook(*, candidate: Any, verification: Any, job: Any,
             rows: Iterable[Mapping[str, Any]] = (), authorization: Any = None,
             budget: Any = None, summary: Any = None,
             **extra: Any) -> ChainLoopHookResult:
        result = ChainLoopHookResult()
        try:
            candidate_id = str(getattr(candidate, "candidate_id", "") or "")
            objective_id = str(getattr(verification, "verification_id", "")
                               or "")
            scope_ref = str(getattr(verification, "scope_ref", "")
                            or getattr(candidate, "scope_ref", "") or "")
            vulnerability_class = str(
                getattr(candidate, "vulnerability_class", "") or "")
            chain = ch.chain_for(vulnerability_class)
            if chain is None or not chain.implemented:
                result.outcome = {
                    "termination": lp.LOOP_BLOCKED,
                    "termination_reason": (
                        lp.pl.REASON_CHAIN_NOT_IMPLEMENTED
                        if chain is None else lp.pl.REASON_CAPABILITY_CONTRACT_ONLY),
                    "vulnerability_class": ch.normalize_class(
                        vulnerability_class),
                    "capability": (chain.capability if chain is not None
                                   else ch.CAPABILITY_NOT_IMPLEMENTED),
                    "confirmed": False,
                }
                result.error = result.outcome["termination_reason"]
                return result

            store = verification_store
            if store is None:
                base = getattr(getattr(verification, "store", None), "base", None)
                store = vs.VerificationActionStore(base)

            context: dict[str, Any] = {"job_id": str(getattr(job, "id", "") or "")}
            if context_fn is not None:
                supplied = context_fn(candidate=candidate,
                                      verification=verification, job=job,
                                      rows=list(rows))
                if isinstance(supplied, Mapping):
                    context.update({k: v for k, v in supplied.items()
                                    if v is not None})

            authorization_ids = list(
                getattr(verification, "authorization_ids", ()) or ())
            outcome = lp.run_verification_loop(
                candidate_id=candidate_id, objective_id=objective_id,
                vulnerability_class=vulnerability_class, scope_ref=scope_ref,
                store=store, target=str(context.get("target")
                                        or getattr(candidate, "endpoint", "")
                                        or ""),
                rows=list(rows), authorization=authorization,
                authorization_id=(str(authorization_ids[0])
                                  if authorization_ids else ""),
                context=context,
                budget=budget,
                limits=dict(limits or {}),
                max_steps=max_steps, advisor=advisor)
            result.outcome = outcome.to_dict()
            result.evidence_rows = store.evidence_rows_for_candidate(
                candidate_id)
        except Exception as exc:  # noqa: BLE001 - an integration failure must
            # never fabricate evidence, and must never crash the finding pass
            result.error = f"chain_loop_error:{type(exc).__name__}"
        return result

    return hook


def default_verification_limits() -> dict[str, int]:
    return dict(vb.DEFAULT_VERIFICATION_LIMITS)


__all__ = [
    "ChainLoopHookResult", "INTEGRATION_RULE_VERSION", "default_verification_limits",
    "make_chain_loop_fn",
]
