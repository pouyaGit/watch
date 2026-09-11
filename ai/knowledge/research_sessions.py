"""Append-only research session store (Stage R25.7).

Sessions are persisted as an immutable **event log** in one JSONL file
(``ai_data/research/sessions/sessions.jsonl``): each lifecycle transition is
one append-only line. The current :class:`ResearchSession` is a deterministic
fold of its events, so there is no update-in-place and no deletion.

Properties (same philosophy as the R25.5 outcome store):

- atomic single-line appends (``O_APPEND`` + fsync) under an advisory
  ``flock``; concurrent writers never interleave a line;
- deterministic content-addressed ``session_id`` / ``event_id``;
- idempotent creation and idempotent event re-submission;
- malformed lines are skipped and counted (fail-soft reads);
- no Mongo, no network, no subprocess, no LLM, no execution.

Session time accounting is metadata only; starting a session performs no
security testing of any kind.
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

from ai.schemas.research_session import (
    SESSION_ID_RE,
    SESSION_RULE_VERSION,
    ResearchSession,
    ResearchSessionEvent,
    normalize_note,
)

DEFAULT_SESSIONS_DIR = "ai_data/research/sessions"
SESSIONS_FILENAME = "sessions.jsonl"
LOCK_FILENAME = ".sessions.lock"

MAX_LIST_LIMIT = 100


class SessionStoreError(ValueError):
    """Base class for session-store failures."""


class SessionNotFound(SessionStoreError):
    """No persisted session for the given id."""


class SessionValidationError(SessionStoreError):
    """Invalid session input or lifecycle transition."""


# Allowed lifecycle transitions enforced by the backend layer.
ALLOWED_SESSION_TRANSITIONS: dict[str, frozenset[str]] = {
    "PLANNED": frozenset({"STARTED", "ABANDONED"}),
    "IN_PROGRESS": frozenset({"COMPLETED", "ABANDONED"}),
    "COMPLETED": frozenset(),
    "ABANDONED": frozenset(),
}

_EVENT_TO_STATUS = {
    "STARTED": "IN_PROGRESS",
    "COMPLETED": "COMPLETED",
    "ABANDONED": "ABANDONED",
}


def _merge_notes(*parts: str) -> str:
    texts = [normalize_note(p) for p in parts]
    return normalize_note("\n\n".join(text for text in texts if text))


class SessionStore:
    """Append-only, corruption-resistant local JSONL session store."""

    def __init__(self, root_dir: str | Path = DEFAULT_SESSIONS_DIR):
        self.root_dir = Path(root_dir)

    @property
    def path(self) -> Path:
        return self.root_dir / SESSIONS_FILENAME

    @contextmanager
    def _locked(self):
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
    def _parse_line(self, line: str) -> ResearchSessionEvent | None:
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
            return ResearchSessionEvent.model_validate(payload)
        except ValueError:
            return None

    def _read_all(self) -> tuple[list[ResearchSessionEvent], int]:
        events: list[ResearchSessionEvent] = []
        malformed = 0
        if not self.path.exists():
            return events, malformed
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    event = self._parse_line(line)
                    if event is None:
                        malformed += 1
                    else:
                        events.append(event)
        except OSError as exc:
            raise SessionStoreError("unreadable sessions artifact") from exc
        return events, malformed

    def events_for(self, session_id: str) -> list[ResearchSessionEvent]:
        safe_id = str(session_id or "").strip()
        if not SESSION_ID_RE.match(safe_id):
            raise SessionValidationError(
                f"malformed session_id: {session_id!r}"
            )
        events, _ = self._read_all()
        selected = [e for e in events if e.session_id == safe_id]
        selected.sort(key=lambda e: (e.timestamp, e.event_id))
        return selected

    def fold(self, session_id: str) -> ResearchSession | None:
        """Deterministic fold of one session's events -> view (or None).

        Fail-soft: malformed lines never reach here; out-of-order or duplicate
        lifecycle events are ignored deterministically (first valid wins).
        """

        events = self.events_for(session_id)
        created = [e for e in events if e.event_type == "CREATED"]
        if not created:
            return None
        origin = sorted(created, key=lambda e: (e.timestamp, e.event_id))[0]
        session = ResearchSession(
            session_id=origin.session_id,
            lead_id=origin.lead_id,
            cve_id=origin.cve_id,
            program=origin.program,
            status="PLANNED",
            created_at=origin.timestamp,
            planned_minutes=origin.planned_minutes,
            notes=origin.note,
        )
        rest = [e for e in events if e.event_type != "CREATED"]
        rest.sort(key=lambda e: (e.timestamp, e.event_id))
        for event in rest:
            target = _EVENT_TO_STATUS.get(event.event_type)
            if target is None:
                continue  # unknown event type cannot occur (schema)
            if event.event_type == "STARTED":
                if session.status != "PLANNED":
                    continue
                session.status = "IN_PROGRESS"
                session.started_at = event.timestamp
                continue
            if session.status not in ("PLANNED", "IN_PROGRESS"):
                continue
            session.status = target
            session.ended_at = event.timestamp
            session.actual_minutes = event.actual_minutes
            if event.outcome_id:
                session.outcome_id = event.outcome_id
            session.notes = _merge_notes(session.notes, event.note)
        return session

    def get(self, session_id: str) -> ResearchSession:
        session = self.fold(session_id)
        if session is None:
            raise SessionNotFound(f"unknown session id: {session_id}")
        return session

    def list(
        self,
        limit: int = 50,
        offset: int = 0,
        lead_id: str | None = None,
        cve: str | None = None,
        program: str | None = None,
        status: str | None = None,
    ) -> dict:
        """Capped deterministic session list (created_at DESC, id ASC)."""

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

        events, malformed = self._read_all()
        session_ids = sorted({event.session_id for event in events})
        sessions: list[ResearchSession] = []
        for session_id in session_ids:
            session = self.fold(session_id)
            if session is None:
                continue
            sessions.append(session)
        if lead_filter:
            sessions = [s for s in sessions if s.lead_id == lead_filter]
        if cve_filter:
            sessions = [s for s in sessions if s.cve_id == cve_filter]
        if program_filter:
            sessions = [s for s in sessions if s.program == program_filter]
        if status_filter:
            sessions = [s for s in sessions if s.status == status_filter]
        # created_at DESC, session_id ASC (stable two-pass)
        sessions.sort(key=lambda s: s.session_id)
        sessions.sort(key=lambda s: str(s.created_at or ""), reverse=True)
        total = len(sessions)
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "items": [
                session.to_view() for session in sessions[offset : offset + limit]
            ],
            "malformed": malformed,
            "rule_version": SESSION_RULE_VERSION,
            "research_only": True,
        }

    def all(self, lead_id: str | None = None) -> list[ResearchSession]:
        """Every folded session (optionally one lead); used for summaries."""

        events, _ = self._read_all()
        session_ids = sorted({event.session_id for event in events})
        sessions: list[ResearchSession] = []
        for session_id in session_ids:
            session = self.fold(session_id)
            if session is None:
                continue
            if lead_id and session.lead_id != str(lead_id).strip():
                continue
            sessions.append(session)
        return sessions

    # -- writes -------------------------------------------------------------
    def append_event(
        self, event: ResearchSessionEvent
    ) -> tuple[ResearchSessionEvent, bool]:
        """Append one immutable event; idempotent by content-addressed id."""

        if not isinstance(event, ResearchSessionEvent):
            raise SessionValidationError("expected a ResearchSessionEvent")

        with self._locked():
            events, _ = self._read_all()
            for existing in events:
                if existing.event_id == event.event_id:
                    return existing, False
            self.root_dir.mkdir(parents=True, exist_ok=True)
            line = json.dumps(
                event.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
            ) + "\n"
            fd = os.open(
                str(self.path), os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o644
            )
            try:
                os.write(fd, line.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            return event, True
