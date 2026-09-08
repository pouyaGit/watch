"""Strictly bounded 429-only retry policy (research-only).

Scope (deliberately narrow — NOT a retry framework):

- HTTP 429: exactly ONE additional attempt after a small capped
  backoff. No loop, no exponential backoff, no policy table.
- HTTP 402 / 5xx / network-timeout: NEVER retried (degrade
  immediately via the frozen fail-soft path).
- Programming / non-transient errors: NEVER retried.

Layering invariant (exactly one retry per CVE, globally): the CLI
layer retries only 429 failures raised by its own LLM call, and it
never lets a 429 escape (it converts the outcome to a payload). The
batch layer therefore retries only 429 failures raised directly by
its injected ``research_fn`` — which the real CLI never produces.
The two layers can never stack on the same CVE.

Backoff: ``DEFAULT_RETRY_429_DELAY_SECONDS`` (2.0s) with a hard cap
(``MAX_RETRY_429_DELAY_SECONDS`` = 5.0s). Rationale: 429 signals a
rate limit, so one short pause lets the provider bucket refill
without stalling the batch; the cap bounds worst-case overhead to
~2s per 429 CVE. Sleep goes through ``sleep_before_429_retry`` so
tests inject a recorder and never actually sleep.
"""

from __future__ import annotations

import time

#: Production default pause before the single allowed 429 retry.
DEFAULT_RETRY_429_DELAY_SECONDS = 2.0

#: Hard cap: the pause never exceeds this, however configured.
MAX_RETRY_429_DELAY_SECONDS = 5.0

#: The only status that may be retried.
RETRYABLE_429_STATUS = 429


def is_retryable_429(info) -> bool:
    """Return True only for transient HTTP 429 classifier results."""
    return bool(
        info is not None
        and getattr(info, "transient", False) is True
        and getattr(info, "status_code", None) == RETRYABLE_429_STATUS
    )


def clamp_retry_delay(delay) -> float:
    """Clamp a retry delay into ``[0, MAX_RETRY_429_DELAY_SECONDS``]."""
    try:
        value = float(delay)
    except (TypeError, ValueError):
        return DEFAULT_RETRY_429_DELAY_SECONDS
    if value != value:  # NaN
        return DEFAULT_RETRY_429_DELAY_SECONDS
    if value < 0:
        return 0.0
    return min(value, MAX_RETRY_429_DELAY_SECONDS)


def empty_retry_histogram() -> dict[str, int]:
    """Return a zeroed retry histogram (stable schema)."""
    return {"attempted": 0, "succeeded": 0, "exhausted": 0}


def sleep_before_429_retry(delay=None, sleep_fn=None) -> float:
    """Sleep once before the single allowed 429 retry.

    Returns the seconds waited. ``sleep_fn`` defaults to
    :func:`time.sleep`; tests inject a recorder so they never sleep
    and never depend on timing.
    """
    seconds = clamp_retry_delay(
        DEFAULT_RETRY_429_DELAY_SECONDS if delay is None else delay
    )
    (sleep_fn or time.sleep)(seconds)
    return seconds
