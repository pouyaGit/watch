"""EPIC7 Part 7: resource limits — policy-driven, fail-closed.

Every limit is explicit policy. The enforcer grants concurrency, counts
per-host observations, tracks runtime, and budgets retries. There is no
infinite retry and no uncontrolled concurrency.
"""

from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_REQUEST_TIMEOUT_SECONDS = 10
DEFAULT_MAX_RESPONSE_BYTES = 1_048_576
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_MAX_CONCURRENT_OBSERVATIONS = 4
DEFAULT_MAX_OBSERVATIONS_PER_HOST = 25
DEFAULT_MAX_TOTAL_RUNTIME_SECONDS = 3600
DEFAULT_RETRY_LIMIT = 2


@dataclass(frozen=True)
class ResourceLimits:
    request_timeout_seconds: int
    max_response_bytes: int
    max_redirects: int
    max_concurrent_observations: int
    max_observations_per_host: int
    max_total_runtime_seconds: int
    retry_limit: int

    def __post_init__(self) -> None:
        for value in (
            self.request_timeout_seconds,
            self.max_response_bytes,
            self.max_redirects,
            self.max_concurrent_observations,
            self.max_observations_per_host,
            self.max_total_runtime_seconds,
            self.retry_limit,
        ):
            if not isinstance(value, int) or value <= 0:
                raise ValueError(
                    "every resource limit must be a positive integer")

    def to_dict(self) -> dict[str, int]:
        return {
            "request_timeout_seconds": self.request_timeout_seconds,
            "max_response_bytes": self.max_response_bytes,
            "max_redirects": self.max_redirects,
            "max_concurrent_observations": self.max_concurrent_observations,
            "max_observations_per_host": self.max_observations_per_host,
            "max_total_runtime_seconds": self.max_total_runtime_seconds,
            "retry_limit": self.retry_limit,
        }


def default_limits() -> ResourceLimits:
    return ResourceLimits(
        request_timeout_seconds=DEFAULT_REQUEST_TIMEOUT_SECONDS,
        max_response_bytes=DEFAULT_MAX_RESPONSE_BYTES,
        max_redirects=DEFAULT_MAX_REDIRECTS,
        max_concurrent_observations=DEFAULT_MAX_CONCURRENT_OBSERVATIONS,
        max_observations_per_host=DEFAULT_MAX_OBSERVATIONS_PER_HOST,
        max_total_runtime_seconds=DEFAULT_MAX_TOTAL_RUNTIME_SECONDS,
        retry_limit=DEFAULT_RETRY_LIMIT,
    )


class LimitsEnforcer:
    """Tracks live usage against one ResourceLimits policy."""

    def __init__(self, limits: ResourceLimits) -> None:
        self.limits = limits
        self._active: int = 0
        self._per_host: dict[str, int] = {}
        self._retries_consumed: int = 0

    def acquire(self, host: str) -> bool:
        """Grant a concurrency slot, fail-closed when the cap is reached."""
        if self._active >= self.limits.max_concurrent_observations:
            return False
        self._active += 1
        return True

    def release(self, host: str) -> None:
        if self._active > 0:
            self._active -= 1

    def observe_host(self, host: str) -> bool:
        """True while the per-host observation cap has room."""
        current = self._per_host.get(host, 0)
        if current >= self.limits.max_observations_per_host:
            return False
        self._per_host[host] = current + 1
        return True

    def host_counts(self) -> dict[str, int]:
        return dict(self._per_host)

    def runtime_exceeded(self, budget_seconds: int,
                         elapsed_seconds: int) -> bool:
        """True when elapsed time exceeded the total runtime budget."""
        return elapsed_seconds > budget_seconds

    def retry_budget_available(self) -> bool:
        return self._retries_consumed < self.limits.retry_limit

    def consume_retry(self) -> None:
        self._retries_consumed += 1

    def snapshot(self) -> dict[str, object]:
        return {
            "active": self._active,
            "per_host": dict(self._per_host),
            "retries_consumed": self._retries_consumed,
            "limits": self.limits.to_dict(),
        }


__all__ = [
    "DEFAULT_MAX_CONCURRENT_OBSERVATIONS",
    "DEFAULT_MAX_OBSERVATIONS_PER_HOST",
    "DEFAULT_MAX_REDIRECTS",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_MAX_TOTAL_RUNTIME_SECONDS",
    "DEFAULT_RETRY_LIMIT",
    "DEFAULT_REQUEST_TIMEOUT_SECONDS",
    "LimitsEnforcer",
    "ResourceLimits",
    "default_limits",
]