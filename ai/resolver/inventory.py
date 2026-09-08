"""Authoritative-inventory boundary for TargetResolver (Phase 5C).

The resolver never touches Mongo directly: it reads through the
:class:`InventoryRepository` protocol (injected, fake-testable),
which models the architecture's read-only adapter over the
``Programs`` / ``Subdomains`` / ``Http`` / ``Endpoints`` collections
(``database/db.py`` is never imported here, so unit tests run without
MongoDB and without credentials).

Authoritative vs historical (normative):

- AUTHORITATIVE CURRENT INVENTORY = the program row (live scope
  lists) + the asset row for ``(program_name, canonical_host)`` as
  returned by the repository. Only these decide gone/drift/base.
- HISTORICAL OBSERVATION = ``Http.ips``, ``Urls`` rows, crawl data,
  past DNS answers, and the ``TargetIntelligence`` snapshot. These
  are exposed as advisory context (``ips_observed`` /
  ``snapshot_current``) and can never grant authority: the resolver
  records them, never reasons from them.

The repository is strictly READ-ONLY: the protocol exposes no
insert/update/delete/upsert surface, and this package performs no
inventory repair or learning. Lookups are always keyed by the full
``(program_name, canonical_host)`` pair — a global host-only lookup
is unrepresentable.

This module is DETERMINISTIC and OFFLINE: no network, no subprocess,
no database driver, no LLM.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

from ai.evidence.hashing import hash_payload
from ai.resolver.canonicalization import canonicalize_host
from ai.schemas.target_resolution import base_authority_for

__all__ = [
    "ProgramRecord",
    "AssetRecord",
    "InventoryRepository",
    "InMemoryInventoryRepository",
    "InventoryError",
    "scope_lists_hash_for",
]

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class InventoryError(ValueError):
    """Closed inventory-boundary failure (secret-free, bounded)."""

    _CODES = frozenset({"INVENTORY_MALFORMED", "INVENTORY_UNAVAILABLE"})

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in self._CODES:
            raise ValueError(f"unknown inventory code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("inventory error detail must be single-line")
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


def scope_lists_hash_for(
    scopes: tuple[str, ...] | list[str],
    ooscopes: tuple[str, ...] | list[str],
) -> str:
    """Canonical hash of the CURRENT program scope lists.

    Sorting makes list order irrelevant; the hash binds the exact
    lists reviewed at issuance, so any drift fails closed at resolve
    time. Issuers must mint ``TargetBinding.scope_lists_hash`` with
    this function (single source of truth — no duplicate hashing).
    """

    return hash_payload(
        {
            "ooscopes": sorted(ooscopes),
            "scopes": sorted(scopes),
        }
    )


def _check_program_name(value: object) -> str:
    if not isinstance(value, str) or not value or not value.strip():
        raise InventoryError("INVENTORY_MALFORMED", "bad program name")
    if "\n" in value or "\r" in value or len(value) > 256:
        raise InventoryError("INVENTORY_MALFORMED", "bad program name")
    return value


@dataclass(frozen=True)
class ProgramRecord:
    """Current program row projection (scope lists are live data)."""

    program_name: str
    scopes: tuple[str, ...] = ()
    ooscopes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _check_program_name(self.program_name)
        for label, entries in (
            ("scopes", self.scopes),
            ("ooscopes", self.ooscopes),
        ):
            if not isinstance(entries, (list, tuple)):
                raise InventoryError(
                    "INVENTORY_MALFORMED", f"bad program {label}"
                )
            for entry in entries:
                if not isinstance(entry, str) or not entry:
                    raise InventoryError(
                        "INVENTORY_MALFORMED", f"bad program {label} entry"
                    )
        object.__setattr__(self, "scopes", tuple(self.scopes))
        object.__setattr__(self, "ooscopes", tuple(self.ooscopes))

    @property
    def scope_lists_hash(self) -> str:
        """Live hash of the current scope lists (drift detector)."""
        return scope_lists_hash_for(self.scopes, self.ooscopes)


@dataclass(frozen=True)
class AssetRecord:
    """Current asset row for one ``(program_name, canonical_host)`` slot.

    ``scheme``/``effective_port`` describe the CURRENT inventory
    endpoint base (compared against the authorized base to detect
    reassignment). ``snapshot_current`` pins the current observation
    state for staleness reporting. ``ips_observed`` preserves
    historical inventory addresses as advisory context only — the
    resolver never treats them as resolution results.
    """

    program_name: str
    canonical_host: str
    scheme: str = "https"
    effective_port: int = 443
    snapshot_current: str | None = None
    ips_observed: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _check_program_name(self.program_name)
        if not isinstance(self.canonical_host, str):
            raise InventoryError(
                "INVENTORY_MALFORMED", "bad asset host"
            )
        try:
            canonical, _ = canonicalize_host(self.canonical_host)
        except (ValueError, TypeError) as exc:
            raise InventoryError(
                "INVENTORY_MALFORMED", "asset host not canonical"
            ) from exc
        if canonical != self.canonical_host:
            raise InventoryError(
                "INVENTORY_MALFORMED", "asset host not canonical"
            )
        if self.scheme not in ("http", "https"):
            raise InventoryError(
                "INVENTORY_MALFORMED", "bad asset scheme"
            )
        if (
            not isinstance(self.effective_port, int)
            or isinstance(self.effective_port, bool)
            or not 1 <= self.effective_port <= 65535
        ):
            raise InventoryError(
                "INVENTORY_MALFORMED", "bad asset port"
            )
        if self.snapshot_current is not None and not _SHA256_RE.match(
            self.snapshot_current
        ):
            raise InventoryError(
                "INVENTORY_MALFORMED", "bad asset snapshot"
            )
        if not isinstance(self.ips_observed, (list, tuple)):
            raise InventoryError(
                "INVENTORY_MALFORMED", "bad asset ips"
            )
        for entry in self.ips_observed:
            if not isinstance(entry, str):
                raise InventoryError(
                    "INVENTORY_MALFORMED", "bad asset ip entry"
                )
        object.__setattr__(self, "ips_observed", tuple(self.ips_observed))

    @property
    def endpoint_base(self) -> str:
        """Current inventory endpoint base (observation, not authority)."""
        _, kind = canonicalize_host(self.canonical_host)
        return base_authority_for(
            scheme=self.scheme,
            canonical_host=self.canonical_host,
            effective_port=self.effective_port,
            host_kind=kind,
        )


class InventoryRepository(Protocol):
    """Read-only authoritative-inventory contract (DI boundary)."""

    def get_program(self, program_name: str) -> ProgramRecord | None:
        """Current program row, or None when the program is gone."""
        ...  # pragma: no cover

    def get_asset(
        self, program_name: str, canonical_host: str
    ) -> AssetRecord | None:
        """Current asset row for the exact pair, or None when gone."""
        ...  # pragma: no cover


class InMemoryInventoryRepository:
    """Deterministic offline fixture implementing :class:`InventoryRepository`.

    Seeded once at construction; exposes no mutation surface (no
    insert/update/delete/upsert/learn-back). A fresh target requires a
    freshly seeded repository — mirroring the production rule that a
    new target requires a new resolution.
    """

    def __init__(
        self,
        *,
        programs: list[ProgramRecord] | None = None,
        assets: list[AssetRecord] | None = None,
    ) -> None:
        self._programs: dict[str, ProgramRecord] = {}
        self._assets: dict[tuple[str, str], AssetRecord] = {}
        for record in programs or []:
            if not isinstance(record, ProgramRecord):
                raise TypeError(
                    "programs must be ProgramRecord, "
                    f"not {type(record).__name__}"
                )
            self._programs[record.program_name] = record
        for record in assets or []:
            if not isinstance(record, AssetRecord):
                raise TypeError(
                    "assets must be AssetRecord, "
                    f"not {type(record).__name__}"
                )
            self._assets[(record.program_name, record.canonical_host)] = record

    def get_program(self, program_name: str) -> ProgramRecord | None:
        if not isinstance(program_name, str):
            raise TypeError(
                "get_program accepts only str, "
                f"not {type(program_name).__name__}"
            )
        return self._programs.get(program_name)

    def get_asset(
        self, program_name: str, canonical_host: str
    ) -> AssetRecord | None:
        if not isinstance(program_name, str) or not isinstance(
            canonical_host, str
        ):
            raise TypeError("get_asset accepts only str pair keys")
        return self._assets.get((program_name, canonical_host))
