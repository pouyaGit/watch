"""EPIC7 Part 4: target adapter — normalized identities only.

A specialist can never hand the runtime a raw URL. resolve_target()
accepts only a mapping of normalized Watch/AEC target fields (host,
scheme, endpoint, explicit port, source, authorization_reference) and
re-resolves it against scope. Raw URL strings, userinfo hosts, IP
substitutions, private-network targets, and wildcards are refused. The
target's identity is a content hash over its normalized fields — a
caller-supplied target_id is never trusted.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Mapping

from aec.runtime.policy.models import is_observation_type  # noqa: F401


class TargetRefusal(Exception):
    """Refused target: scope, shape, or authorization mismatch."""


_HTTP_PORT = 80
_HTTPS_PORT = 443

_DEFAULT_SCHEMES = frozenset({"https"})


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      default=str)


def target_identity(raw: Mapping[str, Any]) -> str:
    """Content identity over the normalized fields (host, scheme,
    endpoint, port). The caller's target_id field is never trusted."""
    basis = _canonical({
        "host": str(raw.get("host") or "").strip().lower(),
        "scheme": str(raw.get("scheme") or "").strip().lower(),
        "endpoint": str(raw.get("endpoint") or "").strip(),
        "port": raw.get("port"),
    })
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return "tgt-" + digest[:12]


def _refuse(reason: str) -> "TargetRefusal":
    return TargetRefusal(reason)


@dataclass(frozen=True)
class ResolvedTarget:
    target_id: str
    host: str
    scheme: str
    endpoint: str
    port: int | None
    source: str
    authorization_reference: str
    scope_validation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "host": self.host,
            "scheme": self.scheme,
            "endpoint": self.endpoint,
            "port": self.port,
            "source": self.source,
            "authorization_reference": self.authorization_reference,
            "scope_validation": self.scope_validation,
        }


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_private_host(host: str) -> bool:
    lowered = host.strip().lower()
    if lowered in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    if lowered.endswith((".local", ".localhost", ".internal")):
        return True
    try:
        return ipaddress.ip_address(lowered).is_private
    except ValueError:
        return False


def resolve_target(
    raw: Mapping[str, Any] | str,
    scope_hosts: frozenset[str] = frozenset(),
    permitted_schemes: frozenset[str] = _DEFAULT_SCHEMES,
) -> ResolvedTarget:
    """Resolve a normalized target identity. Refuses anything else."""
    if isinstance(raw, str):
        raise _refuse("TARGET_RAW_URL: raw target strings are not accepted")
    if not isinstance(raw, Mapping):
        raise _refuse("TARGET_NOT_MAPPING: target must be a mapping")

    host = raw.get("host")
    scheme = raw.get("scheme")
    endpoint = str(raw.get("endpoint") or "").strip()
    port = raw.get("port")
    source = str(raw.get("source") or "unknown")
    authorization_reference = str(
        raw.get("authorization_reference") or "")

    if not isinstance(host, str) or not host.strip():
        raise _refuse("TARGET_HOST_MISSING")
    host = host.strip().lower()
    if "://" in host or "/" in host:
        raise _refuse("TARGET_RAW_URL: host carries a URL shape")
    if "@" in host:
        raise _refuse("TARGET_USERINFO: userinfo is never accepted")
    if "*" in host or "?" in host:
        raise _refuse("TARGET_WILDCARD: wildcard hosts are not accepted")

    if not isinstance(scheme, str) or not scheme.strip():
        raise _refuse("TARGET_SCHEME_MISSING: no implicit default scheme")
    scheme = scheme.strip().lower()
    if scheme not in permitted_schemes:
        raise _refuse("TARGET_SCHEME_NOT_PERMITTED")
    if scheme == "http" and port is None:
        raise _refuse("TARGET_PORT_MISSING: http requires an explicit port")
    if port is not None:
        if not isinstance(port, int) or port <= 0 or port > 65535:
            raise _refuse("TARGET_PORT_INVALID")
        expected = _HTTPS_PORT if scheme == "https" else _HTTP_PORT
        if port != expected:
            raise _refuse("TARGET_PORT_UNEXPECTED")

    if not authorization_reference:
        raise _refuse("TARGET_AUTHORIZATION_MISSING")

    if scope_hosts and host not in scope_hosts:
        raise _refuse("TARGET_HOST_OUT_OF_SCOPE")

    if _is_ip_host(host):
        raise _refuse("TARGET_IP_SUBSTITUTION: IP targets refused unless "
                      "explicitly authorized")
    if _is_private_host(host):
        raise _refuse("TARGET_PRIVATE_NETWORK: localhost/private targets "
                      "refused unless explicitly authorized")

    if "*" in endpoint:
        raise _refuse("TARGET_WILDCARD: wildcard endpoints are not accepted")
    if "://" in endpoint:
        raise _refuse("TARGET_RAW_URL: endpoint carries a URL shape")

    return ResolvedTarget(
        target_id=target_identity(raw),
        host=host,
        scheme=scheme,
        endpoint=endpoint,
        port=port,
        source=source,
        authorization_reference=authorization_reference,
        scope_validation="PASS",
    )


__all__ = ["ResolvedTarget", "TargetRefusal", "resolve_target",
           "target_identity"]