"""backend/prod_intel — Production Intelligence & Hunt Operations v1.

A deterministic READ-PROJECTION layer over the existing authoritative
stores (runtime, finding/verification, campaign, hunt, knowledge, memory,
SOC adapters). It never writes state, never invents values, and never
becomes a competing source of truth: every metric it emits carries full
provenance (source, population, aggregation semantics, time range) and
honest unavailable / unknown / not_observed states.

One authoritative projection feeds BOTH the JSON API
(``backend/routers/intel.py``) and the AI SOC UI templates.
"""

from backend.prod_intel.semantics import (  # noqa: F401
    INSUFFICIENT_POPULATION,
    NOT_OBSERVED,
    OK,
    PROJECTION_RULE_VERSION,
    UNKNOWN,
    UNAVAILABLE,
    metric,
    unavailable_metric,
    window_bounds,
)

__all__ = [
    "OK", "UNKNOWN", "UNAVAILABLE", "NOT_OBSERVED",
    "INSUFFICIENT_POPULATION", "PROJECTION_RULE_VERSION",
    "metric", "unavailable_metric", "window_bounds",
]
