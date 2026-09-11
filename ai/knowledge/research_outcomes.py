"""Append-only economic research outcome store (Stage R25.5).

One JSONL file under ``ai_data/research/outcomes/outcomes.jsonl`` with:

- atomic single-line appends (``O_APPEND`` + flush + fsync) under an advisory
  ``flock`` so concurrent writers never interleave a line;
- **no overwrite**: an existing outcome is never mutated or deleted; the file
  is append-only by construction;
- deterministic content-addressed ``outcome_id``s, so an identical duplicate
  submission is idempotent (returns the stored record, ``created=False``);
- fail-closed reads: a malformed line is skipped and counted, never crashes a
  listing or fabricates a record.

No network, no LLM, no subprocess, no Mongo, no findings, no alerts.
Outcome capture is research management only.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path

try:  # POSIX advisory locking (Linux)
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None

from ai.schemas.research_outcome import (
    OUTCOME_ID_RE,
    OUTCOME_RULE_VERSION,
    OUTCOME_STATUSES,
    ResearchOutcome,
    normalize_note,
    outcome_id_for,
)

DEFAULT_OUTCOMES_DIR = "ai_data/research/outcomes"
OUTCOMES_FILENAME = "outcomes.jsonl"
LOCK_FILENAME = ".outcomes.lock"

MAX_LIST_LIMIT = 100


class OutcomeStoreError(ValueError):
    """Base class for outcome-store failures."""


class OutcomeNotFound(OutcomeStoreError):
    """No persisted outcome for the given id."""


class OutcomeValidationError(OutcomeStoreError):
    """Invalid outcome input (status/time/note/ids)."""


def _normalize_status(value: object) -> str:
    text = str(value or "").strip().upper()
    if text not in OUTCOME_STATUSES:
        raise OutcomeValidationError(f"invalid outcome status: {value!r}")
    return text


class OutcomeStore:
    """Append-only, corruption-resistant local JSONL outcome store."""

    def __init__(self, root_dir: str | Path = DEFAULT_OUTCOMES_DIR):
        self.root_dir = Path(root_dir)

    # -- paths --------------------------------------------------------------
    @property
    def path(self) -> Path:
        return self.root_dir / OUTCOMES_FILENAME

    @contextmanager
    def _locked(self):
        """Exclusive advisory lock serializing append/read-check-append."""

        self.root_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.root_dir / LOCK_FILENAME
        handle = open(lock_path, "a+")
        try:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            handle.close()

    # -- reads --------------------------------------------------------------
    def _parse_line(self, line: str) -> ResearchOutcome | None:
        """Fail-closed per-record parse: malformed data yields None."""

        text = line.strip()
        if not text:
            return None
        try:
            payload = json.loads(text)
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None
        try:
            return ResearchOutcome.model_validate(payload)
        except ValueError:
            return None

    def _read_all(self) -> tuple[list[ResearchOutcome], int]:
        """Return (records, malformed_count); never raises on bad lines."""

        records: list[ResearchOutcome] = []
        malformed = 0
        if not self.path.exists():
            return records, malformed
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    outcome = self._parse_line(line)
                    if outcome is None:
                        malformed += 1
                    else:
                        records.append(outcome)
        except OSError as exc:
            raise OutcomeStoreError(
                "unreadable outcomes artifact"
            ) from exc
        return records, malformed

    def all(self, lead_id: str | None = None) -> list[ResearchOutcome]:
        """Every persisted record (optionally one lead); used for summaries.

        Unbounded by design for aggregation accuracy; callers that paginate
        user-visible output must use :meth:`list` instead.
        """

        records, _ = self._read_all()
        if lead_id:
            records = [r for r in records if r.lead_id == str(lead_id).strip()]
        return records

    def get(self, outcome_id: str) -> ResearchOutcome:
        safe_id = str(outcome_id or "").strip()
        if not OUTCOME_ID_RE.match(safe_id):
            raise OutcomeValidationError(
                f"malformed outcome_id: {outcome_id!r}"
            )
        records, _ = self._read_all()
        for record in records:
            if record.outcome_id == safe_id:
                return record
        raise OutcomeNotFound(f"unknown outcome id: {outcome_id}")

    def list(
        self,
        limit: int = 50,
        offset: int = 0,
        lead_id: str | None = None,
        cve: str | None = None,
        program: str | None = None,
        status: str | None = None,
    ) -> dict:
        """Capped deterministic outcome list (timestamp DESC, id ASC)."""

        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 50
        limit = min(max(limit, 1), MAX_LIST_LIMIT)
        try:
            offset = max(int(offset or 0), 0)
        except (TypeError, ValueError):
            offset = 0
        lead_filter = str(lead_id or "").strip()
        cve_filter = str(cve or "").strip().upper()
        program_filter = str(program or "").strip()
        status_filter = str(status or "").strip().upper()

        records, malformed = self._read_all()
        if lead_filter:
            records = [r for r in records if r.lead_id == lead_filter]
        if cve_filter:
            records = [r for r in records if r.cve_id == cve_filter]
        if program_filter:
            records = [r for r in records if r.program == program_filter]
        if status_filter:
            records = [r for r in records if r.status == status_filter]
        # timestamp DESC, outcome_id ASC (stable two-pass sort)
        records.sort(key=lambda r: r.outcome_id)
        records.sort(key=lambda r: r.timestamp, reverse=True)
        total = len(records)
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "items": [
                record.model_dump(mode="json")
                for record in records[offset : offset + limit]
            ],
            "malformed": malformed,
            "rule_version": OUTCOME_RULE_VERSION,
            "research_only": True,
        }

    # -- writes -------------------------------------------------------------
    def append(
        self,
        *,
        lead_id: str,
        cve_id: str,
        program: str,
        status: str,
        timestamp: str,
        researcher_note: str = "",
        time_spent_minutes: int = 0,
        source: str = "MANUAL",
    ) -> tuple[ResearchOutcome, bool]:
        """Append one outcome; idempotent on identical content.

        Returns ``(record, created)``. A repeated identical submission returns
        the stored record with ``created=False`` and never appends a second
        line. Fail-closed: the record is fully validated before any write.
        """

        status = _normalize_status(status)
        note = normalize_note(researcher_note)
        outcome_id = outcome_id_for(
            lead_id=lead_id,
            status=status,
            time_spent_minutes=time_spent_minutes,
            researcher_note=note,
            source=source,
        )
        try:
            record = ResearchOutcome(
                outcome_id=outcome_id,
                lead_id=lead_id,
                cve_id=cve_id,
                program=program,
                status=status,
                timestamp=str(timestamp or ""),
                researcher_note=note,
                time_spent_minutes=time_spent_minutes,
                source=str(source or "MANUAL").strip().upper(),
                rule_version=OUTCOME_RULE_VERSION,
            )
        except ValueError as exc:
            raise OutcomeValidationError(str(exc)) from exc

        with self._locked():
            records, _ = self._read_all()
            for existing in records:
                if existing.outcome_id == outcome_id:
                    return existing, False
            self.root_dir.mkdir(parents=True, exist_ok=True)
            line = json.dumps(
                record.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
            ) + "\n"
            # O_APPEND: a single line write is atomic at the OS level; the
            # advisory lock additionally serializes read-check-append.
            fd = os.open(
                str(self.path),
                os.O_APPEND | os.O_CREAT | os.O_WRONLY,
                0o644,
            )
            try:
                os.write(fd, line.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            return record, True
