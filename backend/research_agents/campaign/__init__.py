"""Autonomous Security Campaign Orchestrator v1.

Bounded campaign-level control layer over the EXISTING research stack:

CAMPAIGN -> OBJECTIVES -> PRIORITIZER -> AGENT SELECTOR ->
HUNT PLANNER -> AUTHORIZATION -> OBSERVATION RUNTIME -> EVIDENCE GATE ->
RESEARCH MEMORY -> OBJECTIVE RESULT -> REPRIORITIZATION ->
NEXT OBJECTIVE / TERMINATION

Safety invariants (see executor/dependencies/advisor):
  * every campaign and objective carries an explicit authorized scope
    equal to ``watch:scope:`` / ``fixture:`` — never widened;
  * every objective executes as ONE existing RuntimeStore job through the
    existing AgentWorker (Hunt Planner + AuthorizationChecker +
    Observation Runtime + Evidence Gate untouched);
  * LLM output is advisory: validated reorder of deterministic priority
    only — free-only (openrouter/free), no paid fallback;
  * budgets are cumulative and auditable; stops are honest
    (BUDGET_EXHAUSTED / EXPIRED / BLOCKED / FAILED, never fake
    COMPLETED);
  * one coordinator lease per campaign; pause/resume revalidates.
"""

from backend.research_agents.campaign.models import (  # noqa: F401
    CAMPAIGN_RULE_VERSION,
    CAMPAIGN_STATES,
    CAMPAIGN_TERMINAL,
    OBJECTIVE_STATES,
    OBJECTIVE_TERMINAL,
    Campaign,
    CampaignObjective,
    CampaignScopeError,
    CampaignStateError,
    Dependency,
    validate_scope_ref,
)
from backend.research_agents.campaign.store import (  # noqa: F401
    CampaignStore,
    CampaignStoreError,
    DEFAULT_LIMITS,
)
from backend.research_agents.campaign.dependencies import (  # noqa: F401
    DependencyCycleError,
    assert_acyclic,
    resolve_all,
    resolve_dependencies,
)
from backend.research_agents.campaign.budget import (  # noqa: F401
    BudgetExhausted,
    BudgetReport,
    CampaignBudget,
)
from backend.research_agents.campaign.prioritizer import (  # noqa: F401
    PRIORITIZER_VERSION,
    PrioritizationResult,
    prioritize,
)
from backend.research_agents.campaign.selector import (  # noqa: F401
    SELECTOR_VERSION,
    select_specialist,
)
from backend.research_agents.campaign.advisor import (  # noqa: F401
    ADVISOR_PROMPT_VERSION,
    AdvisorOutcome,
    advisor_request,
    map_advisor_response,
    validate_recommendation,
)
from backend.research_agents.campaign.executor import (  # noqa: F401
    CampaignRunSummary,
    build_objective_job,
    execute_campaign,
)

__all__ = [
    "CAMPAIGN_RULE_VERSION", "CAMPAIGN_STATES", "CAMPAIGN_TERMINAL",
    "OBJECTIVE_STATES", "OBJECTIVE_TERMINAL",
    "Campaign", "CampaignObjective", "CampaignStateError",
    "CampaignScopeError", "Dependency", "validate_scope_ref",
    "CampaignStore", "CampaignStoreError", "DEFAULT_LIMITS",
    "DependencyCycleError", "assert_acyclic", "resolve_all",
    "resolve_dependencies",
    "BudgetExhausted", "BudgetReport", "CampaignBudget",
    "PRIORITIZER_VERSION", "PrioritizationResult", "prioritize",
    "SELECTOR_VERSION", "select_specialist",
    "ADVISOR_PROMPT_VERSION", "AdvisorOutcome", "advisor_request",
    "map_advisor_response", "validate_recommendation",
    "CampaignRunSummary", "build_objective_job", "execute_campaign",
]
