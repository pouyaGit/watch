"""Persistent Pattern Store (Phase 2C).

A durable, auditable home for Phase 2A research patterns
(:class:`VulnerabilityPattern` / :class:`AttackPattern`). The store
is a STORAGE / LIFECYCLE / IDENTITY layer only. It is NOT a target
matcher, scope engine, execution engine, finding store, verifier,
LLM, collector, or scheduler. It stores research intelligence only:
it never decides whether a target is vulnerable, never decides
scope, never executes tests, never produces evidence, never
verifies vulnerabilities, and never produces findings.

Identity model (Phase 2A semantics preserved exactly, never
redefined):

- ``semantic_key``: SHA-256 over the provenance-free semantic
  basis. The same normalized pattern from different sources or
  models converges here.
- ``idempotency_key``: SHA-256 over ``semantic_key`` + the sorted
  provenance basis. The same pattern from a different provenance
  basis is a distinct provenance-bound identity.
- ``pattern_id``: ``vp-``/``ap-`` + first 16 hex of the
  idempotency key (short alias, KnowledgeStore convention).

Storage follows the ``KnowledgeStore`` (``ai/knowledge/store.py``)
conventions: file-backed JSON under a root directory, one record
file per content-addressed key, a sorted ``index.json``, atomic
temp-file + rename writes, deterministic ordering everywhere, and
fail-closed integrity errors. No MongoDB, no network, no LLM, no
subprocess, no pickle.
"""

from __future__ import annotations

import itertools
import json
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Union

from pydantic import ValidationError

from ai.schemas.hypothesis import ResearchProvenance
from ai.schemas.research_pattern import (
    ATTACK_SCHEMA_VERSION,
    SCHEMA_VERSION,
    AttackFacts,
    AttackPattern,
    ModelInterpretation,
    VulnerabilityFacts,
    VulnerabilityPattern,
    attack_pattern_id_from_key,
    vulnerability_pattern_id_from_key,
)

Pattern = Union[VulnerabilityPattern, AttackPattern]

PatternTypeName = Literal["vulnerability", "attack"]
PatternStatusName = Literal["ACTIVE", "SUPERSEDED", "RETIRED"]

_VP_ID_RE = re.compile(r"^vp-[0-9a-f]{16}$")
_AP_ID_RE = re.compile(r"^ap-[0-9a-f]{16}$")
_IDEMPOTENCY_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
_SEMANTIC_KEY_RE = re.compile(r"^[0-9a-f]{64}$")

_PATTERN_TYPES: dict[str, type] = {
    "vulnerability": VulnerabilityPattern,
    "attack": AttackPattern,
}

_VALID_STATUSES = frozenset({"ACTIVE", "SUPERSEDED", "RETIRED"})

# Explicit transition allowlist. RETIRED is terminal. There are no
# CONFIRMED / VERIFIED / NOT_VULNERABLE states anywhere in this
# lifecycle; such values are rejected by the schema Literal and
# again by the transition map below.
_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "ACTIVE": frozenset({"SUPERSEDED", "RETIRED"}),
    "SUPERSEDED": frozenset({"RETIRED"}),
    "RETIRED": frozenset(),
}


class PatternStoreError(ValueError):
    """Base error for deterministic, testable store failures."""


class PatternIdentityConflictError(PatternStoreError):
    """Same pattern_id bound to a different idempotency identity."""


class PatternNotFoundError(PatternStoreError):
    """A lifecycle operation targeted an unknown pattern_id."""


class PatternCorruptError(PatternStoreError):
    """Stored bytes fail validation; never silently repaired."""


class InvalidPatternTransitionError(PatternStoreError):
    """A lifecycle transition outside the explicit allowlist."""


@dataclass(frozen=True)
class PutResult:
    """Outcome of :meth:`PatternStore.put`."""

    pattern: Pattern
    created: bool


_TEMP_COUNTER = itertools.count()


def _write_json_atomic(path: Path, payload: dict) -> None:
    """Atomic record write (KnowledgeStore primitive, hardened).

    Temp file + atomic rename: a crash can leave at most an orphan
    temp file, never a half-written record visible to readers.
    Unlike the KnowledgeStore helper this uses a per-write unique
    temp name (pid + thread + counter), so concurrent identical
    writers never share — and unlink under — each other's temp
    file; both atomic renames succeed and readers only ever see
    whole records.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    unique = f"{os.getpid()}.{threading.get_ident()}.{next(_TEMP_COUNTER)}"
    temp_path = path.with_name(f"{path.name}.{unique}.tmp")
    temp_path.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    temp_path.replace(path)


def _canonical_record_bytes(record: dict) -> str:
    return json.dumps(
        record,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


class PatternStore:
    """File-backed store for research patterns.

    Layout under ``root_dir`` (default ``ai_data/patterns``)::

        index.json
        records/<idempotency_key>.json

    Record filenames derive ONLY from regex-validated
    ``idempotency_key`` values (``^[0-9a-f]{64}$``); index keys are
    ONLY regex-validated ``pattern_id`` values. No pattern field
    (title, product, technique, …) ever influences a path.
    """

    def __init__(self, root_dir: str | Path = "ai_data/patterns") -> None:
        self.root_dir = Path(root_dir)
        self.records_dir = self.root_dir / "records"
        self.index_path = self.root_dir / "index.json"

    # ------------------------------------------------------------------
    # Paths and validation helpers
    # ------------------------------------------------------------------

    def _record_path(self, idempotency_key: str) -> Path:
        if not _IDEMPOTENCY_KEY_RE.match(idempotency_key or ""):
            raise PatternStoreError(
                f"invalid idempotency_key for storage path: "
                f"{idempotency_key!r}"
            )
        return self.records_dir / f"{idempotency_key}.json"

    @staticmethod
    def _check_pattern_id(pattern_id: str) -> None:
        if not (
            _VP_ID_RE.match(pattern_id or "")
            or _AP_ID_RE.match(pattern_id or "")
        ):
            raise PatternStoreError(
                f"malformed pattern_id rejected: {pattern_id!r}"
            )

    @staticmethod
    def _pattern_type_of(pattern: Pattern) -> PatternTypeName:
        if isinstance(pattern, VulnerabilityPattern):
            return "vulnerability"
        if isinstance(pattern, AttackPattern):
            return "attack"
        raise TypeError(
            "PatternStore accepts only VulnerabilityPattern or "
            f"AttackPattern, not {type(pattern).__name__}"
        )

    # ------------------------------------------------------------------
    # Write-side revalidation (defense in depth)
    # ------------------------------------------------------------------

    def _revalidate(self, pattern: Pattern) -> Pattern:
        """Independently verify identity before persistence.

        The caller-provided ``pattern_id`` / ``semantic_key`` /
        ``idempotency_key`` are never trusted: the pattern is
        re-parsed through its own contract (which recomputes both
        keys from the stored basis and rejects any mismatch), and
        the ``pattern_id`` alias is additionally recomputed here via
        the public ``*_id_from_key`` factories while checking that
        the ``vp-``/``ap-`` prefix matches the concrete model type
        (no cross-type masquerade).
        """

        pattern_type = self._pattern_type_of(pattern)
        # Genuine-instance check: a facsimile rebuilt with
        # model_construct from raw mappings (nested dicts instead
        # of validated submodels, silently-dropped smuggled extras)
        # must not slip through revalidation on its serialized
        # shadow. Only fully validated objects are storable.
        expected_facts = (
            VulnerabilityFacts
            if pattern_type == "vulnerability"
            else AttackFacts
        )
        if not (
            isinstance(pattern.facts, expected_facts)
            and isinstance(pattern.provenance, ResearchProvenance)
            and isinstance(
                pattern.interpretation, ModelInterpretation
            )
        ):
            raise PatternStoreError(
                "pattern submodels must be genuine validated "
                "instances, not reconstructed mappings"
            )
        model_class = _PATTERN_TYPES[pattern_type]
        try:
            validated = model_class.model_validate(
                pattern.model_dump(mode="json")
            )
        except ValidationError as exc:
            raise PatternStoreError(
                f"write validation failed: {exc}"
            ) from exc
        if pattern_type == "vulnerability":
            expected_id = vulnerability_pattern_id_from_key(
                validated.idempotency_key
            )
        else:
            expected_id = attack_pattern_id_from_key(
                validated.idempotency_key
            )
        if validated.pattern_id != expected_id:
            raise PatternStoreError(
                "pattern_id does not match the recomputed "
                f"idempotency alias: {validated.pattern_id!r}"
            )
        return validated

    # ------------------------------------------------------------------
    # Index handling
    # ------------------------------------------------------------------

    def _load_index(self) -> dict:
        if not self.index_path.exists():
            return {"patterns": {}, "version": 1}
        try:
            index = json.loads(
                self.index_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            raise PatternCorruptError(
                f"pattern-store index is not valid JSON: "
                f"{self.index_path}"
            ) from exc
        if not isinstance(index, dict):
            raise PatternCorruptError(
                "pattern-store index must be a JSON object"
            )
        patterns = index.get("patterns")
        if not isinstance(patterns, dict):
            raise PatternCorruptError(
                "pattern-store index has no valid patterns map"
            )
        return index

    def _save_index(self, index: dict) -> None:
        patterns = index.get("patterns", {})
        ordered = {key: patterns[key] for key in sorted(patterns)}
        _write_json_atomic(
            self.index_path,
            {"patterns": ordered, "version": 1},
        )

    @staticmethod
    def _check_index_entry(
        pattern_id: str, entry: object
    ) -> dict:
        if not isinstance(entry, dict):
            raise PatternCorruptError(
                "pattern-store index entry must be a JSON object: "
                f"{pattern_id}"
            )
        for field in (
            "pattern_type",
            "idempotency_key",
            "semantic_key",
            "path",
        ):
            if not isinstance(entry.get(field), str):
                raise PatternCorruptError(
                    f"pattern-store index entry for {pattern_id} "
                    f"has an invalid {field!r}"
                )
        if entry["pattern_type"] not in _PATTERN_TYPES:
            raise PatternCorruptError(
                f"pattern-store index entry for {pattern_id} has "
                f"an unknown pattern_type: "
                f"{entry['pattern_type']!r}"
            )
        if not _IDEMPOTENCY_KEY_RE.match(entry["idempotency_key"]):
            raise PatternCorruptError(
                f"pattern-store index entry for {pattern_id} has "
                "an invalid idempotency_key"
            )
        if not _SEMANTIC_KEY_RE.match(entry["semantic_key"]):
            raise PatternCorruptError(
                f"pattern-store index entry for {pattern_id} has "
                "an invalid semantic_key"
            )
        expected_path = f"records/{entry['idempotency_key']}.json"
        if entry["path"] != expected_path:
            raise PatternCorruptError(
                f"pattern-store index path does not match record: "
                f"{pattern_id}"
            )
        return entry

    # ------------------------------------------------------------------
    # Record handling
    # ------------------------------------------------------------------

    def _record_payload(
        self, pattern: Pattern, pattern_type: PatternTypeName
    ) -> dict:
        schema_version = (
            SCHEMA_VERSION
            if pattern_type == "vulnerability"
            else ATTACK_SCHEMA_VERSION
        )
        return {
            "pattern": pattern.model_dump(mode="json"),
            "pattern_type": pattern_type,
            "schema_version": schema_version,
        }

    def _load_record(self, idempotency_key: str) -> Pattern:
        """Load, validate, and identity-check one record file.

        Fail closed on malformed JSON, unknown schema version,
        unknown pattern type, schema violations, tampered identity,
        or forbidden extra fields (``extra="forbid"`` on every
        contract model rejects ``scope_allowed`` / ``command`` /
        ``verdict`` style keys). Never repairs, never returns
        partial data.
        """

        path = self._record_path(idempotency_key)
        if not path.exists():
            raise PatternCorruptError(
                "pattern-store index references a missing "
                f"record: {idempotency_key}"
            )
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise PatternCorruptError(
                f"pattern record is not valid JSON: {path}"
            ) from exc
        if not isinstance(envelope, dict):
            raise PatternCorruptError(
                f"pattern record must be a JSON object: {path}"
            )
        if set(envelope.keys()) != {
            "pattern",
            "pattern_type",
            "schema_version",
        }:
            raise PatternCorruptError(
                f"pattern record envelope is malformed: {path}"
            )
        pattern_type = envelope["pattern_type"]
        if pattern_type not in _PATTERN_TYPES:
            raise PatternCorruptError(
                f"pattern record has unknown pattern_type "
                f"{pattern_type!r}: {path}"
            )
        expected_schema = (
            SCHEMA_VERSION
            if pattern_type == "vulnerability"
            else ATTACK_SCHEMA_VERSION
        )
        if envelope["schema_version"] != expected_schema:
            raise PatternCorruptError(
                f"pattern record has unsupported schema_version "
                f"{envelope['schema_version']!r}: {path}"
            )
        model_class = _PATTERN_TYPES[pattern_type]
        try:
            pattern = model_class.model_validate(envelope["pattern"])
        except ValidationError as exc:
            raise PatternCorruptError(
                f"pattern record fails contract validation: "
                f"{path}: {exc}"
            ) from exc
        if pattern.idempotency_key != idempotency_key:
            raise PatternCorruptError(
                f"pattern record identity does not match "
                f"filename: {path}"
            )
        if pattern.schema_version != expected_schema:
            raise PatternCorruptError(
                f"pattern record schema_version mismatch: {path}"
            )
        prefix_ok = (
            pattern_type == "vulnerability"
            and _VP_ID_RE.match(pattern.pattern_id)
        ) or (
            pattern_type == "attack"
            and _AP_ID_RE.match(pattern.pattern_id)
        )
        if not prefix_ok:
            raise PatternCorruptError(
                f"pattern record type masquerade: {path}"
            )
        return pattern

    def _load_entry_pattern(
        self, pattern_id: str, entry: dict
    ) -> Pattern:
        pattern = self._load_record(entry["idempotency_key"])
        if pattern.pattern_id != pattern_id:
            raise PatternCorruptError(
                f"pattern-store index pattern_id does not match "
                f"record: {pattern_id}"
            )
        if pattern.semantic_key != entry["semantic_key"]:
            raise PatternCorruptError(
                f"pattern-store index semantic_key does not match "
                f"record: {pattern_id}"
            )
        return pattern

    # ------------------------------------------------------------------
    # Public write API
    # ------------------------------------------------------------------

    def put(self, pattern: Pattern) -> PutResult:
        """Persist a pattern idempotently.

        The exact same provenance-bound pattern written twice
        yields one record (``created=False`` on the repeat).
        Sequential repeats converge on the first stored bytes;
        identity-excluded prose/metadata from later repeats is
        ignored. Under true concurrency, identical writers still
        converge on a single identity-bound record (whichever
        atomic write lands is identity-equal, so readers never see
        a mix). A ``pattern_id`` already bound to a different
        ``idempotency_key`` raises
        :class:`PatternIdentityConflictError` — stored provenance
        is never silently overwritten.
        """

        if not isinstance(
            pattern, (VulnerabilityPattern, AttackPattern)
        ):
            raise TypeError(
                "PatternStore.put accepts only VulnerabilityPattern "
                f"or AttackPattern, not {type(pattern).__name__}"
            )
        validated = self._revalidate(pattern)
        pattern_type = self._pattern_type_of(validated)
        index = self._load_index()
        patterns = index["patterns"]
        entry = patterns.get(validated.pattern_id)
        if entry is not None:
            checked = self._check_index_entry(
                validated.pattern_id, entry
            )
            if (
                checked["idempotency_key"]
                != validated.idempotency_key
            ):
                raise PatternIdentityConflictError(
                    f"pattern_id {validated.pattern_id} is already "
                    "bound to a different idempotency_key; stored "
                    "provenance is never overwritten"
                )
            stored = self._load_entry_pattern(
                validated.pattern_id, checked
            )
            return PutResult(pattern=stored, created=False)
        record_path = self._record_path(validated.idempotency_key)
        if not record_path.exists():
            # First write wins for one provenance-bound identity:
            # identity-equal repeats (differing only in
            # identity-excluded prose/metadata) converge here.
            _write_json_atomic(
                record_path,
                self._record_payload(validated, pattern_type),
            )
        patterns[validated.pattern_id] = {
            "idempotency_key": validated.idempotency_key,
            "path": f"records/{validated.idempotency_key}.json",
            "pattern_type": pattern_type,
            "semantic_key": validated.semantic_key,
        }
        self._save_index(index)
        return PutResult(
            pattern=self._load_entry_pattern(
                validated.pattern_id,
                patterns[validated.pattern_id],
            ),
            created=True,
        )

    # ------------------------------------------------------------------
    # Public read API
    # ------------------------------------------------------------------

    def get(self, pattern_id: str) -> Pattern | None:
        """Return one pattern by id, or None when unknown.

        Malformed ids are rejected with :class:`PatternStoreError`;
        corrupted records raise :class:`PatternCorruptError`.
        """

        self._check_pattern_id(pattern_id)
        index = self._load_index()
        entry = index["patterns"].get(pattern_id)
        if entry is None:
            return None
        return self._load_entry_pattern(
            pattern_id, self._check_index_entry(pattern_id, entry)
        )

    def get_by_idempotency_key(
        self, idempotency_key: str
    ) -> Pattern | None:
        """Return the exact provenance-bound identity, or None."""

        if not _IDEMPOTENCY_KEY_RE.match(idempotency_key or ""):
            raise PatternStoreError(
                "malformed idempotency_key rejected: "
                f"{idempotency_key!r}"
            )
        path = self.records_dir / f"{idempotency_key}.json"
        if not path.exists():
            index = self._load_index()
            for entry_pid, entry in index["patterns"].items():
                checked = self._check_index_entry(entry_pid, entry)
                if checked["idempotency_key"] == idempotency_key:
                    return self._load_entry_pattern(
                        entry_pid, checked
                    )
            return None
        pattern = self._load_record(idempotency_key)
        index = self._load_index()
        entry = index["patterns"].get(pattern.pattern_id)
        if entry is None:
            raise PatternCorruptError(
                "pattern record is missing an index entry: "
                f"{pattern.pattern_id}"
            )
        return self._load_entry_pattern(
            pattern.pattern_id,
            self._check_index_entry(pattern.pattern_id, entry),
        )

    def get_by_semantic_key(self, semantic_key: str) -> list[Pattern]:
        """Return ALL provenance variants of one semantic pattern.

        Semantic equality is exactly the deterministic Phase 2A
        ``semantic_key`` — no fuzzy matching, no string similarity,
        no LLM. Results are ordered by ``pattern_id``.
        """

        if not _SEMANTIC_KEY_RE.match(semantic_key or ""):
            raise PatternStoreError(
                f"malformed semantic_key rejected: {semantic_key!r}"
            )
        index = self._load_index()
        matches: list[Pattern] = []
        for pattern_id in sorted(index["patterns"]):
            entry = self._check_index_entry(
                pattern_id, index["patterns"][pattern_id]
            )
            if entry["semantic_key"] == semantic_key:
                matches.append(
                    self._load_entry_pattern(pattern_id, entry)
                )
        return sorted(matches, key=lambda item: item.pattern_id)

    def list(
        self,
        *,
        pattern_type: PatternTypeName | None = None,
        status: PatternStatusName | None = None,
        semantic_key: str | None = None,
    ) -> list[Pattern]:
        """List stored patterns with deterministic filters.

        Only research-side filters exist (type / lifecycle status /
        semantic key). There is deliberately no target, scope,
        severity-gated, or match-score filtering: the store owns no
        target authority. Results are ordered by ``pattern_id``.
        """

        if pattern_type is not None and (
            pattern_type not in _PATTERN_TYPES
        ):
            raise PatternStoreError(
                f"unknown pattern_type filter: {pattern_type!r}"
            )
        if status is not None and status not in _VALID_STATUSES:
            raise PatternStoreError(
                f"unknown status filter: {status!r}"
            )
        if semantic_key is not None and not _SEMANTIC_KEY_RE.match(
            semantic_key
        ):
            raise PatternStoreError(
                f"malformed semantic_key filter: {semantic_key!r}"
            )
        index = self._load_index()
        results: list[Pattern] = []
        for pattern_id in sorted(index["patterns"]):
            entry = self._check_index_entry(
                pattern_id, index["patterns"][pattern_id]
            )
            if (
                pattern_type is not None
                and entry["pattern_type"] != pattern_type
            ):
                continue
            if (
                semantic_key is not None
                and entry["semantic_key"] != semantic_key
            ):
                continue
            pattern = self._load_entry_pattern(pattern_id, entry)
            if status is not None and pattern.status != status:
                continue
            results.append(pattern)
        return sorted(results, key=lambda item: item.pattern_id)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def transition(
        self,
        pattern_id: str,
        *,
        status: str,
        supersedes: str | None = None,
        retirement_reason: str | None = None,
    ) -> Pattern:
        """Move a pattern along the explicit lifecycle allowlist.

        Allowed: ``ACTIVE → SUPERSEDED`` (requires ``supersedes``),
        ``ACTIVE → RETIRED`` and ``SUPERSEDED → RETIRED`` (require
        ``retirement_reason``). Same-status calls are idempotent
        no-ops. ``RETIRED`` is terminal and means "research became
        obsolete" — never "a target was verified safe". Supersede
        targets must exist, must be same-typed (enforced by the
        contract's ``vp-``/``ap-`` regexes), must not be self, and
        must not close a cycle. Historical records are never
        deleted; the transition rewrites only lifecycle fields of
        the same identity-bound record.
        """

        self._check_pattern_id(pattern_id)
        if status not in _VALID_STATUSES:
            raise InvalidPatternTransitionError(
                f"unknown lifecycle status: {status!r}; patterns "
                "never carry CONFIRMED / VERIFIED / NOT_VULNERABLE"
            )
        index = self._load_index()
        entry = index["patterns"].get(pattern_id)
        if entry is None:
            raise PatternNotFoundError(
                f"unknown pattern_id: {pattern_id}"
            )
        checked = self._check_index_entry(pattern_id, entry)
        stored = self._load_entry_pattern(pattern_id, checked)
        if stored.status == status:
            return stored
        if status not in _ALLOWED_TRANSITIONS[stored.status]:
            raise InvalidPatternTransitionError(
                f"transition {stored.status} → {status} is not "
                "allowed"
            )
        if status == "SUPERSEDED":
            self._check_supersedes_target(
                pattern_id, stored, supersedes, index
            )
        if status == "RETIRED" and not (
            retirement_reason and retirement_reason.strip()
        ):
            raise InvalidPatternTransitionError(
                "RETIRED requires retirement_reason"
            )
        try:
            updated = type(stored).model_validate(
                {
                    **stored.model_dump(mode="json"),
                    "status": status,
                    "supersedes": supersedes,
                    "retirement_reason": retirement_reason,
                }
            )
        except ValidationError as exc:
            raise PatternStoreError(
                f"transition failed contract validation: {exc}"
            ) from exc
        _write_json_atomic(
            self._record_path(updated.idempotency_key),
            self._record_payload(
                updated, self._pattern_type_of(updated)
            ),
        )
        return self._load_entry_pattern(pattern_id, checked)

    def _check_supersedes_target(
        self,
        pattern_id: str,
        stored: Pattern,
        supersedes: str | None,
        index: dict,
    ) -> None:
        expected_re = (
            _VP_ID_RE
            if isinstance(stored, VulnerabilityPattern)
            else _AP_ID_RE
        )
        if not supersedes or not expected_re.match(supersedes):
            raise InvalidPatternTransitionError(
                f"SUPERSEDED requires a same-type supersedes "
                f"pattern_id, got {supersedes!r}"
            )
        if supersedes == pattern_id:
            raise InvalidPatternTransitionError(
                "a pattern cannot supersede itself"
            )
        target_entry = index["patterns"].get(supersedes)
        if target_entry is None:
            raise PatternNotFoundError(
                f"supersedes target does not exist: {supersedes}"
            )
        target = self._load_entry_pattern(
            supersedes,
            self._check_index_entry(supersedes, target_entry),
        )
        seen = {pattern_id}
        current: Pattern | None = target
        for _ in range(len(index["patterns"]) + 1):
            if current is None or not current.supersedes:
                return
            if current.supersedes in seen:
                raise InvalidPatternTransitionError(
                    "circular supersession rejected: "
                    f"{pattern_id} → … → {current.supersedes}"
                )
            seen.add(current.supersedes)
            nxt = index["patterns"].get(current.supersedes)
            current = (
                self._load_entry_pattern(
                    current.supersedes,
                    self._check_index_entry(
                        current.supersedes, nxt
                    ),
                )
                if nxt is not None
                else None
            )
        raise InvalidPatternTransitionError(
            "supersession chain too long; rejected as circular"
        )


__all__ = [
    "Pattern",
    "PatternStatusName",
    "PatternTypeName",
    "PutResult",
    "PatternStore",
    "PatternStoreError",
    "PatternIdentityConflictError",
    "PatternNotFoundError",
    "PatternCorruptError",
    "InvalidPatternTransitionError",
]
