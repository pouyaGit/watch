"""Stage R23 autonomous research agent package.

Research-only, bounded, fail-soft. See ``agent.py`` (execution),
``scheduler.py`` (policy), ``sources.py`` (validated public sources),
``storage.py`` (atomic/idempotent results) and ``prompts.py`` (LLM boundary).
"""

from ai.research_agent.agent import ResearchAgent, ResearchAgentError
from ai.research_agent.scheduler import (
    SchedulerConfig,
    ResearchScheduler,
    select_plans,
    in_window,
)
from ai.research_agent.sources import (
    ResearchSourceCollector,
    SourceValidationError,
    validate_source_url,
)

__all__ = [
    "ResearchAgent",
    "ResearchAgentError",
    "ResearchSourceCollector",
    "SourceValidationError",
    "validate_source_url",
    "SchedulerConfig",
    "ResearchScheduler",
    "select_plans",
    "in_window",
]
