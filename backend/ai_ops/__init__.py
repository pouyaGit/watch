"""EPIC9: Autonomous AI Operations Window — bounded dispatcher package.

One authoritative window definition (``window``), one bounded tick
(``dispatcher``), existing stores/leases/executors stay authoritative.
No persistent worker, no daemon: the hourly ``watch-research.timer`` tick
invokes the dispatcher through the existing research scheduler entrypoint
(``ai.research_cli agent run``) when ``WATCH_AI_OPS_ENABLED=true``.

Worker process liveness and AI operations state are deliberately kept in
separate stores: ``worker.json`` (RuntimeStore, TTL heartbeat) answers
"is a process alive", ``ai_ops_state.json`` (this package) answers
"is AI operations working / why not".
"""
from backend.ai_ops.window import (  # noqa: F401 - re-exported authority
    DEFAULT_WINDOW,
    AIWindow,
)
