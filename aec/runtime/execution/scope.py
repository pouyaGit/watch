"""EPIC7 Part 6: explicit runtime scope enforcement.

A request carries an explicit authorized scope; the runtime validates
host, scheme, port, path constraints, and observation type against it.
Nothing is silently normalized into scope; every mismatch is explicit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from aec.runtime.adapters.target import ResolvedTarget
from aec.runtime.policy.models import is_observation_type

_HTTPS_PORT = 443


class ScopeRefusal(Exception):
    """Refused scope: host, scheme, port, path, or type mismatch."""


@dataclass(frozen=True)
class Scope:
    hosts: frozenset[str]
    schemes: frozenset[str]
    ports: frozenset[int]
    path_prefixes: tuple[str, ...]
    observation_types: frozenset[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "hosts": sorted(self.hosts),
            "schemes": sorted(self.schemes),
            "ports": sorted(self.ports),
            "path_prefixes": list(self.path_prefixes),
            "observation_types": sorted(self.observation_types),
        }


def build_scope(
    hosts: frozenset[str] | None = None,
    schemes: frozenset[str] | None = None,
    ports: frozenset[int] | None = None,
    path_prefixes: tuple[str, ...] = (),
    observation_types: frozenset[str] | None = None,
) -> Scope:
    from aec.runtime.policy.models import OBSERVATION_TYPES

    if hosts is None or not hosts:
        raise ScopeRefusal("SCOPE_HOSTS_REQUIRED")
    if schemes is None or not schemes:
        schemes = frozenset({"https"})
    if ports is None:
        ports = frozenset()
    if observation_types is None:
        observation_types = frozenset(OBSERVATION_TYPES)
    return Scope(
        hosts=frozenset(hosts),
        schemes=frozenset(schemes),
        ports=frozenset(ports),
        path_prefixes=tuple(path_prefixes) if path_prefixes else (),
        observation_types=frozenset(observation_types),
    )


def target_in_scope(host: str, scope_hosts: frozenset[str]) -> bool:
    return host in scope_hosts


def scheme_permitted(scheme: str, scope_schemes: frozenset[str]) -> bool:
    return scheme in scope_schemes


def port_permitted(port: int | None, authorized_port: int | None,
                   scheme: str) -> bool:
    if authorized_port is not None:
        return port == authorized_port
    if port is None:
        return True
    if scheme == "https":
        return port == _HTTPS_PORT
    return port == 80


def path_in_scope(path: str, allowed_path: str) -> bool:
    return path == allowed_path


def path_allowed_by_prefix(path: str, prefix: str) -> bool:
    return path.startswith(prefix) if prefix else False


def observation_type_allowed(kind: str,
                             allowed_types: frozenset[str]) -> bool:
    return is_observation_type(kind) and kind in allowed_types


def userinfo_present(url: str) -> bool:
    return "@" in url.split("://")[-1].split("/")[0]


def validate_target_against_scope(target: ResolvedTarget, scope: Scope,
                                  observation_type: str) -> str:
    """Return PASS or a closed scope-mismatch code."""
    if target.host not in scope.hosts:
        return "SCOPE_MISMATCH"
    if target.scheme not in scope.schemes:
        return "SCOPE_MISMATCH"
    if scope.ports and target.port not in scope.ports:
        return "SCOPE_MISMATCH"
    if scope.observation_types and \
            observation_type not in scope.observation_types:
        return "TYPE_NOT_ALLOWED"
    return "PASS"


__all__ = [
    "Scope", "ScopeRefusal", "build_scope", "observation_type_allowed",
    "path_allowed_by_prefix", "path_in_scope", "port_permitted",
    "scheme_permitted", "target_in_scope", "userinfo_present",
    "validate_target_against_scope",
]