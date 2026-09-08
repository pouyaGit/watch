"""Compiled scope-policy contract (Phase 5D).

A ``CompiledScopePolicy`` is the strict, immutable, deterministic
compilation of one program's ``Programs.scopes`` (inclusions) and
``Programs.ooscopes`` (exclusions). Stored lists are treated as
hostile input: every entry is validated fail-closed at compile time,
and ANY malformed entry fails the whole policy
(``SCOPE_POLICY_INVALID``) instead of best-effort compiling the rest.

Entry grammar (frozen):

- Exact: a canonical DNS hostname (``ai.resolver.canonicalization``,
  kind ``"dns"``, multi-label — single-label entries are rejected).
- Wildcard: exactly ``*.`` + canonical multi-label DNS hostname
  (single ``*`` as the full leftmost label; nothing else).

Rejected at compile (never skipped): empty/whitespace/control
entries, userinfo (``@``), URL-like entries (``://``, ``/``, ``?``,
``#``), IP literals in any notation (B2: IP/CIDR unsupported —
accepting one would silently narrow-or-widen semantics the operator
never expressed), CIDR shapes, multiple wildcards, non-leftmost
wildcards, wildcard public-suffix/single-label bases, malformed
IDNA, and anything over the entry-count ceiling.

The policy hash reuses 5C ``scope_lists_hash_for()`` over the RAW
source lists (the exact bytes the 5B issuer bound), so drift
detection compares identical bases. The content hash — never the
``policy_version`` string — decides drift.

This module is PURE and DETERMINISTIC: no network, no DNS, no
database driver, no LLM. It imports the 5C canonicalizer (shared,
never forked) and 5H-core hashing only.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Protocol

from ai.resolver.canonicalization import (
    CanonicalizationError,
    canonicalize_host,
)
from ai.resolver.inventory import scope_lists_hash_for

__all__ = [
    "MAX_POLICY_ENTRIES",
    "MAX_POLICY_ENTRY_LENGTH",
    "ScopeRule",
    "CompiledScopePolicy",
    "PolicyError",
    "PolicyStore",
    "InMemoryPolicyStore",
    "compile_policy",
]

#: Frozen bound on entries per program (世代 architecture §22: exact
#: number frozen at implementation). Generous vs current data (single
#: digits); anything larger is a data-integrity signal, not a policy.
MAX_POLICY_ENTRIES = 1024

#: Frozen bound on one raw entry (hostnames cannot exceed 253; margin
#: covers the `*.` prefix without admitting URL-sized inputs).
MAX_POLICY_ENTRY_LENGTH = 258

_CIDR_RE = re.compile(r"^[^/]+/\d{1,3}$")
_URLISH_RE = re.compile(r"://")


class PolicyError(ValueError):
    """Closed policy-compile/access failure (secret-free, bounded)."""

    _CODES = frozenset(
        {
            "SCOPE_POLICY_INVALID",
            "SCOPE_POLICY_MISSING",
            "PROGRAM_NOT_FOUND",
        }
    )

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in self._CODES:
            raise ValueError(f"unknown policy code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("policy error detail must be single-line")
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


@dataclass(frozen=True)
class ScopeRule:
    """One compiled inclusion/exclusion rule.

    ``kind`` is ``"exact"`` (``host`` matches only itself) or
    ``"wildcard"`` (``host`` is the base BELOW the ``*.`` prefix:
    rule text ``*.example.com`` compiles to base ``example.com``).
    ``source`` is the inclusion list (``"scopes"``) or exclusion list
    (``"ooscopes"``) the rule came from. ``text`` is the canonical
    rule spelling echoed into decisions for audit.
    """

    kind: str
    host: str
    source: str
    text: str


def _reject(reason: str) -> PolicyError:
    # Static, value-free details: stored entries are hostile input and
    # must never be reflected into errors/logs/audit.
    return PolicyError("SCOPE_POLICY_INVALID", reason)


def _check_basic_shape(entry: object) -> str:
    if not isinstance(entry, str):
        raise _reject("entry not a string")
    if not entry:
        raise _reject("empty entry")
    if len(entry) > MAX_POLICY_ENTRY_LENGTH:
        raise _reject("entry too long")
    if any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in entry):
        raise _reject("whitespace or control in entry")
    if "@" in entry:
        raise _reject("userinfo in entry")
    if _URLISH_RE.search(entry) or "/" in entry or "?" in entry or "#" in entry:
        raise _reject("url-like entry")
    if _CIDR_RE.match(entry):
        raise _reject("cidr entries unsupported")
    return entry


def _looks_like_ip(entry: str) -> bool:
    """True when the entry is an IP literal in any recognized notation."""

    lowered = entry.lower()
    if lowered.startswith("[") and lowered.endswith("]"):
        lowered = lowered[1:-1]
    try:
        ipaddress.ip_address(lowered)
        return True
    except ValueError:
        pass
    # Dotted-numeric / hex / octal forms the 5C canonicalizer polices
    # as IPs must equally never become host rules.
    if re.fullmatch(r"[0-9a-fA-FxX.]+", lowered) and (
        "." in lowered or lowered.startswith("0x") or lowered.isdigit()
    ):
        try:
            _, kind = canonicalize_host(entry)
        except (CanonicalizationError, TypeError):
            # Numeric-looking but unparseable: hostile either way, so
            # it must never become a host rule.
            return True
        return kind in ("ipv4", "ipv6")
    return False


def _compile_exact(entry: str, source: str) -> ScopeRule:
    if _looks_like_ip(entry):
        raise _reject("ip entries unsupported")
    try:
        host, kind = canonicalize_host(entry)
    except (CanonicalizationError, TypeError) as exc:
        raise _reject("malformed hostname") from exc
    if kind != "dns":
        raise _reject("non-dns entries unsupported")
    if "." not in host:
        # Single-label entries (dotless hosts, suffix-adjacent tokens)
        # cannot be scoped safely without a suffix oracle: reject.
        raise _reject("single-label entries unsupported")
    return ScopeRule(kind="exact", host=host, source=source, text=host)


def _compile_wildcard(entry: str, source: str) -> ScopeRule:
    if entry.count("*") != 1 or not entry.startswith("*."):
        raise _reject("malformed wildcard")
    base = entry[2:]
    if not base or "*" in base:
        raise _reject("malformed wildcard")
    if _looks_like_ip(base):
        raise _reject("wildcard ip unsupported")
    try:
        host, kind = canonicalize_host(base)
    except (CanonicalizationError, TypeError) as exc:
        raise _reject("malformed wildcard base") from exc
    if kind != "dns":
        raise _reject("wildcard non-dns unsupported")
    if "." not in host:
        # `*.com`-style suffix wildcards are unrepresentable.
        raise _reject("wildcard suffix unsupported")
    return ScopeRule(
        kind="wildcard", host=host, source=source, text="*." + host
    )


def compile_entry(entry: object, source: str) -> ScopeRule:
    """Compile one stored entry (raises ``PolicyError`` closed)."""

    if source not in ("scopes", "ooscopes"):
        raise TypeError(f"unknown rule source: {source!r}")
    text = _check_basic_shape(entry)
    if "*" in text:
        return _compile_wildcard(text, source)
    return _compile_exact(text, source)


@dataclass(frozen=True)
class CompiledScopePolicy:
    """Immutable per-program policy (fresh-read, hash-bound)."""

    program_name: str
    inclusions: tuple[ScopeRule, ...]
    exclusions: tuple[ScopeRule, ...]
    policy_version: str
    scope_lists_hash: str

    def rules_from(self, source: str) -> tuple[ScopeRule, ...]:
        """Rules of one list (``"scopes"`` inclusions shown first)."""
        if source == "scopes":
            return self.inclusions
        if source == "ooscopes":
            return self.exclusions
        raise TypeError(f"unknown rule source: {source!r}")


def compile_policy(
    *,
    program_name: str,
    scopes: object,
    ooscopes: object,
    policy_version: str = "scope-policy/v1",
) -> CompiledScopePolicy:
    """Strict whole-policy compilation (all-or-nothing, fail-closed)."""

    if (
        not isinstance(program_name, str)
        or not program_name
        or not program_name.strip()
    ):
        raise PolicyError("SCOPE_POLICY_INVALID", "bad program name")
    if "\n" in program_name or "\r" in program_name:
        raise PolicyError("SCOPE_POLICY_INVALID", "bad program name")
    if not isinstance(scopes, (list, tuple)) or not isinstance(
        ooscopes, (list, tuple)
    ):
        raise PolicyError("SCOPE_POLICY_INVALID", "scope lists malformed")
    if len(scopes) + len(ooscopes) > MAX_POLICY_ENTRIES:
        raise PolicyError("SCOPE_POLICY_INVALID", "policy over entry ceiling")
    inclusions = tuple(compile_entry(item, "scopes") for item in scopes)
    exclusions = tuple(compile_entry(item, "ooscopes") for item in ooscopes)
    if not isinstance(policy_version, str) or not policy_version:
        raise PolicyError("SCOPE_POLICY_INVALID", "bad policy version")
    # Canonical content hash over the RAW source lists: this is the
    # exact basis 5B issuance binds, so drift comparison is apples to
    # apples. Version strings are audit only.
    content_hash = scope_lists_hash_for(tuple(scopes), tuple(ooscopes))
    return CompiledScopePolicy(
        program_name=program_name,
        inclusions=inclusions,
        exclusions=exclusions,
        policy_version=policy_version,
        scope_lists_hash=content_hash,
    )


class PolicyStore(Protocol):
    """Read-only program-policy accessor (DI boundary).

    Keyed by ``program_name`` only. A host-keyed lookup is
    unrepresentable by design: the evaluator must always name the
    program whose policy it evaluates.
    """

    def get_policy(self, program_name: str) -> CompiledScopePolicy | None:
        """Fresh compiled policy, or None when the program is unknown."""
        ...  # pragma: no cover


class InMemoryPolicyStore:
    """Deterministic offline fixture implementing :class:`PolicyStore`.

    Seeded once with raw ``program -> (scopes, ooscopes[, version])``
    mappings; compiles fresh on every read (models read-fresh
    semantics). Exposes no mutation surface. Malformed programs raise
    closed ``PolicyError`` on read (fail-closed, never silent).
    """

    def __init__(
        self,
        programs: dict[str, tuple] | None = None,
    ) -> None:
        if programs is not None and not isinstance(programs, dict):
            raise TypeError(
                "InMemoryPolicyStore seeds from a mapping, "
                f"not {type(programs).__name__}"
            )
        self._programs: dict[str, tuple] = dict(programs or {})

    def get_policy(self, program_name: str) -> CompiledScopePolicy | None:
        if not isinstance(program_name, str):
            raise TypeError(
                "get_policy accepts only str, "
                f"not {type(program_name).__name__}"
            )
        seed = self._programs.get(program_name)
        if seed is None:
            return None
        if not isinstance(seed, (list, tuple)) or not 2 <= len(seed) <= 3:
            raise PolicyError(
                "SCOPE_POLICY_INVALID", "seed shape malformed"
            )
        scopes, ooscopes = seed[0], seed[1]
        version = seed[2] if len(seed) == 3 else "scope-policy/v1"
        return compile_policy(
            program_name=program_name,
            scopes=scopes,
            ooscopes=ooscopes,
            policy_version=version,
        )
