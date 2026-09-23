"""EPIC9 §8/§9: bounded dispatcher configuration (env-overridable).

Fail-safe defaults: the dispatcher is DISABLED unless the scheduling
service explicitly opts in with ``WATCH_AI_OPS_ENABLED=true`` (same
opt-in pattern as ``WATCH_RESEARCH_ENABLED``), so a manual
``ai.research_cli agent run`` never executes autonomous work by
accident. Every budget is explicit, bounded and documented; there is no
setting that can disable the window check, the Evidence Gate, or
authorization — those remain with the existing architecture.

Environment (all optional):

    WATCH_AI_OPS_ENABLED        default false   opt into dispatching
    WATCH_AI_OPS_MAX_SECONDS    default 600     wall-clock budget / tick
    WATCH_AI_OPS_MAX_WORK       default 4       max work items / tick
    WATCH_AI_OPS_MAX_PER_TARGET default 2       fairness cap per target
    WATCH_AI_OPS_MAX_PER_CAMPAIGN default 1     fairness cap per campaign
    WATCH_AI_OPS_MAX_ATTEMPTS   default 3       retry ceiling before
                                                RETRY_NOT_DUE
    WATCH_AI_OPS_BACKOFF_SECONDS default 900    retry backoff base
                                                (x attempts)
    WATCH_AI_OPS_TICK_MINUTE    default 30      next-tick display minute
                                                (watch-research.timer fires
                                                hourly at :00 UTC = :30
                                                Asia/Tehran)
"""

from __future__ import annotations

import os
from dataclasses import dataclass

RULE_VERSION = "ai-ops-dispatcher-v1"


def _bool(value: str | None, default: bool) -> bool:
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _int(value: str | None, default: int, lo: int, hi: int) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, parsed))


@dataclass(frozen=True)
class DispatcherConfig:
    enabled: bool = False
    max_seconds: int = 600
    max_work: int = 4
    max_per_target: int = 2
    max_per_campaign: int = 1
    max_attempts: int = 3
    backoff_seconds: int = 900
    tick_minute: int = 30

    @classmethod
    def from_env(cls, env: dict | None = None) -> "DispatcherConfig":
        source = os.environ if env is None else env
        return cls(
            enabled=_bool(source.get("WATCH_AI_OPS_ENABLED"), False),
            max_seconds=_int(source.get("WATCH_AI_OPS_MAX_SECONDS"),
                             600, 1, 3600),
            max_work=_int(source.get("WATCH_AI_OPS_MAX_WORK"), 4, 1, 50),
            max_per_target=_int(source.get("WATCH_AI_OPS_MAX_PER_TARGET"),
                                2, 1, 50),
            max_per_campaign=_int(source.get("WATCH_AI_OPS_MAX_PER_CAMPAIGN"),
                                  1, 1, 50),
            max_attempts=_int(source.get("WATCH_AI_OPS_MAX_ATTEMPTS"),
                              3, 1, 10),
            backoff_seconds=_int(source.get("WATCH_AI_OPS_BACKOFF_SECONDS"),
                                 900, 0, 86400),
            tick_minute=_int(source.get("WATCH_AI_OPS_TICK_MINUTE"),
                             30, 0, 59),
        )
