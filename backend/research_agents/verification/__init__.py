"""EPIC12 — autonomous vulnerability discovery & deep verification.

The layer that turns *observations* into *verification work*: a per-vulnerability
**verification chain**, typed and auditable **verification actions**, an
authorization/budget-bounded **execution** step, **structured observations**,
and a deterministic **verdict** that only ever comes from the EPIC11 claim
contract and gate.

    parameter discovery is not vulnerability confirmation.

XSS is the reference implementation (``FULL``); CORS, open redirect and SSRF are
declared as ``CONTRACT_ONLY`` reference chains so a shallow observation can never
be mistaken for confirmation there either.  Classes without a chain report
``NOT_IMPLEMENTED`` — honestly, never with an invented stage list.

Nothing in this package executes a shell, opens a socket, or reads a model
directly: execution goes through the typed action executors, and the advisory
role is an injected callable.
"""

from __future__ import annotations

from backend.research_agents.verification import actions
from backend.research_agents.verification import advisor
from backend.research_agents.verification import budget
from backend.research_agents.verification import chains
from backend.research_agents.verification import engine
from backend.research_agents.verification import executors
from backend.research_agents.verification import loop
from backend.research_agents.verification import observations
from backend.research_agents.verification import planner
from backend.research_agents.verification import projection
from backend.research_agents.verification import store

VERIFICATION_RULE_VERSION = "epic12-verification-1"

__all__ = [
    "VERIFICATION_RULE_VERSION", "actions", "advisor", "budget", "chains",
    "engine", "executors", "loop", "observations", "planner", "projection",
    "store", "verification_catalog",
]


def verification_catalog() -> dict:
    """A single bounded projection of the whole verification layer."""
    return {
        "rule_version": VERIFICATION_RULE_VERSION,
        "implemented_classes": list(chains.implemented_classes()),
        "chains": chains.chain_catalog(),
        "actions": actions.action_catalog(),
        "executors": executors.executor_catalog(),
        "limits": dict(budget.DEFAULT_VERIFICATION_LIMITS),
        "loop_terminations": list(loop.LOOP_TERMINATIONS),
        "advisor_model": advisor.ADVISOR_MODEL,
        "stage_states": list(chains.STAGE_STATES),
        "limitations": [
            "parameter discovery is not vulnerability confirmation",
            "a reflected parameter is not automatically XSS",
            "payload execution is not available in this runtime: the chain "
            "reports VERIFICATION_PENDING with the exact missing evidence",
            "the EPIC11 claim contract and gate remain the only authority",
        ],
    }
