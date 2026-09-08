"""Egress / proxy guard (Phase B1).

v1 policy: DIRECT EGRESS ONLY, NO PROXY.

- :func:`check_environment` fails closed with ``PROXY_DETECTED``
  when any proxy-shaped variable is present in the executor process
  environment (both cases, plus ``NO_PROXY`` semantics abuse, plus
  PAC/WPAD-shaped variables). There is no caller override and no
  bypass variable (no ``ALLOW_*`` / ``DISABLE_*`` / ``SKIP_*``
  escape hatch exists anywhere in this module).
- :func:`scrubbed_environment` returns a copy without proxy-shaped
  keys for the production launcher to exec with. Scrubbing alone
  never authorizes: executor boot must still call
  :func:`check_environment` on the scrubbed environment.
- :func:`assert_topology` pins the deployment to the reviewed
  direct-egress allowlist; anything else is ``TOPOLOGY_UNSUPPORTED``
  (fail closed).

Pure module: no sockets, no subprocess, no network. Reads the
process environment only when the caller passes none (read-only
snapshot, never mutated).
"""

from __future__ import annotations

import os
from typing import Mapping

__all__ = [
    "EGRESS_GUARD_VERSION",
    "EGRESS_GUARD_ERROR_CODES",
    "EgressGuardError",
    "PROXY_ENV_VARS",
    "SUPPORTED_TOPOLOGIES",
    "is_proxy_shaped",
    "check_environment",
    "scrubbed_environment",
    "assert_topology",
]

#: Guard policy identity (versioned with the closed scrub list).
EGRESS_GUARD_VERSION = "b1-egress-guard/v1"

#: Closed guard-failure vocabulary.
EGRESS_GUARD_ERROR_CODES = frozenset(
    {
        "PROXY_DETECTED",
        "TOPOLOGY_UNSUPPORTED",
    }
)


class EgressGuardError(ValueError):
    """Bounded, secret-free egress-guard failure (closed code)."""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in EGRESS_GUARD_ERROR_CODES:
            raise ValueError(f"unknown egress guard code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("egress guard detail must be single-line")
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


#: Explicit proxy-shaped names (both cases enumerated so the closed
#: list is auditable; matching itself is case-insensitive anyway).
PROXY_ENV_VARS = frozenset(
    {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "HTTP_PROXY_PAC",
        "HTTPS_PROXY_PAC",
        "http_proxy_pac",
        "https_proxy_pac",
        "PAC_URL",
        "pac_url",
        "WPAD_URL",
        "wpad_url",
    }
)

#: Reviewed v1 deployment topologies (direct egress only).
SUPPORTED_TOPOLOGIES = frozenset(
    {
        "direct",
        "direct-nat-preserving",
    }
)


def is_proxy_shaped(name: object) -> bool:
    """True when an environment name is proxy/PAC/WPAD-shaped.

    Case-insensitive. Covers the explicit list plus patterned
    shapes (``*_PAC`` suffix, ``WPAD`` infix, ``PROXY`` infix, and
    ``NO_PROXY`` in any case) so novel proxy-injecting names fail
    closed instead of slipping through an enumeration.
    """

    if not isinstance(name, str) or not name:
        return False
    upper = name.upper()
    if upper in {item.upper() for item in PROXY_ENV_VARS}:
        return True
    if upper == "NO_PROXY" or "PROXY" in upper:
        return True
    if upper.endswith("_PAC") or upper == "PAC_URL":
        return True
    if "WPAD" in upper:
        return True
    return False


def check_environment(env: Mapping[str, str] | None = None) -> None:
    """Fail closed when any proxy-shaped variable is present.

    Presence alone (regardless of value, including empty) is
    ``PROXY_DETECTED``: ``NO_PROXY`` allowlist semantics are never
    consulted. No override parameter exists by design.
    """

    snapshot = dict(os.environ) if env is None else dict(env)
    for key in snapshot:
        if is_proxy_shaped(key):
            raise EgressGuardError("PROXY_DETECTED", "proxy-shaped environment")
    return None


def scrubbed_environment(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return an env copy without proxy-shaped keys (launcher use).

    Scrubbing is a launcher hygiene step, not an authorization: boot
    must still run :func:`check_environment` afterwards.
    """

    snapshot = dict(os.environ) if env is None else dict(env)
    return {
        key: value for key, value in snapshot.items() if not is_proxy_shaped(key)
    }


def assert_topology(topology: str) -> str:
    """Pin the deployment to the reviewed direct-egress allowlist."""

    if not isinstance(topology, str) or topology not in SUPPORTED_TOPOLOGIES:
        raise EgressGuardError("TOPOLOGY_UNSUPPORTED", "topology not allowlisted")
    return topology
