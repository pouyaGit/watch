"""backend/research_agents/hunt — the autonomous research-control loop.

OBSERVATION -> RESEARCH -> UNCERTAINTY -> MISSING EVIDENCE -> HUNT PLAN
-> AUTHORIZED OBSERVATION PLAN -> OBSERVATION RUNTIME -> NEW EVIDENCE ->
EVIDENCE GATE -> LEARNING -> RE-PLAN

Safety posture (by construction, verified by test_safety):
  * the LLM advisor only suggests; trusted code validates and builds
    the final plan from the closed observation registry;
  * the planner never widens scope (plan.scope_ref == job
    .authorization_ref, re-verified before every observation);
  * the planner never executes: observations run only through the
    injected ObservationProvider, authorization only through the
    injected AuthorizationChecker;
  * this package never records evidence or cases — the evidence gate
    stays authoritative;
  * free-only via the existing provider guard; hard budgets make
    infinite loops impossible.

Nothing in this package contacts targets, runs shell/code, or performs
network I/O.
"""

from backend.research_agents.hunt.executor import (  # noqa: F401
    HUNT_RULE_VERSION,
    HuntLimits,
    HuntOutcome,
    run_hunt,
)
from backend.research_agents.hunt.models import (  # noqa: F401
    ADVISOR_PROMPT_VERSION,
    PLANNER_VERSION,
    AuthorizationRecord,
    HuntObjective,
    HuntPlan,
    ObservationRecord,
    PLAN_STATES,
    PlanTransition,
    new_id,
)
from backend.research_agents.hunt.missing_evidence import (  # noqa: F401
    MISSING_EVIDENCE_RULE_VERSION,
    MissingEvidenceItem,
    compute_missing_evidence,
)
from backend.research_agents.hunt.planner import (  # noqa: F401
    AdvisorOutcome,
    Candidate,
    advisor_request,
    build_candidates,
    build_plan,
    map_advisor_response,
    validate_final_plan,
)
from backend.research_agents.hunt.registry import (  # noqa: F401
    ALLOWED_TYPES,
    REGISTRY,
    registry_catalog,
    scan_forbidden,
    validate_observation_requests,
)
from backend.research_agents.hunt.store import (  # noqa: F401
    HuntStore,
    HuntStoreError,
)
from backend.research_agents.hunt.uncertainty import (  # noqa: F401
    UNCERTAINTY_STATES,
    ResearchUncertainty,
    UncertaintyError,
)

__all__ = [
    "ADVISOR_PROMPT_VERSION",
    "ALLOWED_TYPES",
    "AdvisorOutcome",
    "AuthorizationRecord",
    "Candidate",
    "HUNT_RULE_VERSION",
    "HuntLimits",
    "HuntObjective",
    "HuntOutcome",
    "HuntPlan",
    "HuntStore",
    "HuntStoreError",
    "MISSING_EVIDENCE_RULE_VERSION",
    "MissingEvidenceItem",
    "ObservationRecord",
    "PLANNER_VERSION",
    "PLAN_STATES",
    "PlanTransition",
    "REGISTRY",
    "ResearchUncertainty",
    "UNCERTAINTY_STATES",
    "UncertaintyError",
    "advisor_request",
    "build_candidates",
    "build_plan",
    "compute_missing_evidence",
    "map_advisor_response",
    "new_id",
    "registry_catalog",
    "run_hunt",
    "scan_forbidden",
    "validate_final_plan",
    "validate_observation_requests",
]
