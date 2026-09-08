"""Environment-based kill switch for live validation (Phase 5K-live).

Default is ``false``. Live execution requires BOTH:
1. WATCH_AI_LIVE_VALIDATION=true (or 1/yes/on)
2. Explicit caller-supplied --target flag
"""

from __future__ import annotations

import os

import re

_TRUTHY = frozenset({"1", "true", "yes", "on"})


class LiveValidationDisabled(Exception):
    """Raised when the live validation gate is not enabled."""


def live_validation_enabled() -> bool:
    """Return True when WATCH_AI_LIVE_VALIDATION is enabled.

    Strict lowercase comparison. Unknown values (including '0',
    'false', 'no', empty string) are treated as disabled.
    """
    raw = os.environ.get("WATCH_AI_LIVE_VALIDATION", "").strip().casefold()
    return raw in _TRUTHY


def require_live_validation_enabled() -> None:
    """Fail-closed check: raises LiveValidationDisabled if not enabled."""
    if not live_validation_enabled():
        raise LiveValidationDisabled(
            "WATCH_AI_LIVE_VALIDATION is not enabled; "
            "live validation blocked (dry_run only)"
        )
