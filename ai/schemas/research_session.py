"""Research execution session schema (Stage R25.7).

A :class:`ResearchSession` is a human time-accounting record for one research
attempt against an existing R21/R25 lead. The persisted form is an append-only
event log (:class:`ResearchSessionEvent`); the session itself is the
deterministic fold of its events.

Hard boundaries encoded here:

- status values are PLANNED / IN_PROGRESS / COMPLETED / ABANDONED — never
  VULNERABLE / VERIFIED / EXPLOITED / FINDING.
- no target URL, IP/domain, credential, execution, payout or verdict fields
  exist; unknown fields are rejected (``extra="forbid"``).
- timestamps must be parseable ISO-8601; minutes are non-negative bounded
  integers; notes are whitespace-normalized and bounded.
- the session_id and event_id are deterministic (content-addressed).
- ``research_only`` is forced ``True``.

No execution of any kind is represented or authorized here.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from ai.schemas.research_outcome import normalize_note

SESSION_RULE_VERSION = "r25-1"

SESSION_STATUSES: tuple[str, ...] = (
    "PLANNED",
    "IN_PROGRESS",
    "COMPLETED",
    "ABANDONED",
)

SESSION_EVENT_TYPES: tuple[str, ...] = (
    "CREATED",
    "STARTED",
    "COMPLETED",
    "ABANDONED",
)

SESSION_ID_PREFIX = "rs-"
SESSION_ID_RE = re.compile(r"^rs-[0-9a-f]{16}$")
EVENT_ID_PREFIX = "re-"
EVENT_ID_RE = re.compile(r"^re-[0-9a-f]{16}$")
LEAD_ID_RE = re.compile(r"^rl-[0-9a-f]{16}$")
OUTCOME_ID_RE = re.compile(r"^ro-[0-9a-f]{16}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
PROGRAM_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")

MAX_NOTES_CHARS = 2000
MAX_MINUTES = 100000


def _validated_minutes(value: object, field: str) -> int:
    try:
        number = int(value if value is not None else 0)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be an integer") from None
    if number < 0:
        raise ValueError(f"{field} must be non-negative")
    if number > MAX_MINUTES:
        raise ValueError(f"{field} must be <= {MAX_MINUTES}")
    return number


def _validated_timestamp(value: object, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    try:
        datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f"{field} must be ISO-8601") from None
    return text


def session_id_for(
    lead_id: str,
    planned_minutes: int = 0,
    note: str = "",
    rule_version: str = SESSION_RULE_VERSION,
) -> str:
    """Deterministic content-addressed session id (no clock, no randomness).

    Timestamps are excluded so an identical create submission is idempotent.
    Distinct sessions for the same lead are distinguished by planned minutes
    and/or note (documented limitation).
    """

    basis = "\n".join(
        [
            str(rule_version or ""),
            str(lead_id or ""),
            str(int(planned_minutes or 0)),
            normalize_note(note),
        ]
    )
    return SESSION_ID_PREFIX + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def event_id_for(
    session_id: str,
    event_type: str,
    timestamp: str,
    actual_minutes: int = 0,
    outcome_id: str = "",
    note: str = "",
    rule_version: str = SESSION_RULE_VERSION,
) -> str:
    """Deterministic content-addressed event id (idempotent re-submission)."""

    basis = "\n".join(
        [
            str(rule_version or ""),
            str(session_id or ""),
            str(event_type or "").strip().upper(),
            str(timestamp or ""),
            str(int(actual_minutes or 0)),
            str(outcome_id or ""),
            normalize_note(note),
        ]
    )
    return EVENT_ID_PREFIX + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


class _SessionIdentifiers(BaseModel):
    """Shared identifier validation / normalization for the event model."""

    model_config = ConfigDict(extra="forbid")

    @field_validator("lead_id", check_fields=False)
    @classmethod
    def _valid_lead_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not LEAD_ID_RE.match(text):
            raise ValueError(f"malformed lead_id: {value!r}")
        return text

    @field_validator("cve_id", check_fields=False)
    @classmethod
    def _valid_cve(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if not CVE_RE.match(text):
            raise ValueError(f"malformed cve_id: {value!r}")
        return text

    @field_validator("program", check_fields=False)
    @classmethod
    def _valid_program(cls, value: str) -> str:
        text = str(value or "").strip()
        if not PROGRAM_RE.match(text):
            raise ValueError(f"malformed program: {value!r}")
        return text

    @field_validator("note", check_fields=False)
    @classmethod
    def _valid_note(cls, value: object) -> str:
        text = normalize_note(value)
        if len(text) > MAX_NOTES_CHARS:
            raise ValueError(f"note exceeds {MAX_NOTES_CHARS} characters")
        return text

    @field_validator("outcome_id", check_fields=False)
    @classmethod
    def _valid_outcome_id(cls, value: object) -> str:
        text = str(value or "").strip()
        if text and not OUTCOME_ID_RE.match(text):
            raise ValueError(f"malformed outcome_id: {value!r}")
        return text


class ResearchSessionEvent(_SessionIdentifiers):
    """One immutable session lifecycle event (append-only persisted record)."""

    event_id: str
    session_id: str
    lead_id: str
    cve_id: str
    program: str
    event_type: str
    timestamp: str
    planned_minutes: int = 0
    actual_minutes: int = 0
    outcome_id: str = ""
    note: str = ""
    rule_version: str = SESSION_RULE_VERSION
    research_only: bool = True

    @field_validator("event_id")
    @classmethod
    def _valid_event_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not EVENT_ID_RE.match(text):
            raise ValueError(f"malformed event_id: {value!r}")
        return text

    @field_validator("session_id")
    @classmethod
    def _valid_session_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not SESSION_ID_RE.match(text):
            raise ValueError(f"malformed session_id: {value!r}")
        return text

    @field_validator("event_type")
    @classmethod
    def _valid_event_type(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in SESSION_EVENT_TYPES:
            raise ValueError(f"invalid session event type: {value!r}")
        return text

    @field_validator("timestamp")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _validated_timestamp(value, "timestamp")

    @field_validator("planned_minutes")
    @classmethod
    def _valid_planned(cls, value: int) -> int:
        return _validated_minutes(value, "planned_minutes")

    @field_validator("actual_minutes")
    @classmethod
    def _valid_actual(cls, value: int) -> int:
        return _validated_minutes(value, "actual_minutes")

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: str) -> str:
        return SESSION_RULE_VERSION

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: bool) -> bool:
        if not value:
            raise ValueError("sessions are research-only")
        return True


class ResearchSession(_SessionIdentifiers):
    """Deterministic folded view of one research session (research-only)."""

    session_id: str
    lead_id: str
    cve_id: str
    program: str
    status: str = "PLANNED"
    created_at: str = ""
    started_at: str = ""
    ended_at: str = ""
    outcome_id: str = ""
    planned_minutes: int = 0
    actual_minutes: int = 0
    notes: str = ""
    rule_version: str = SESSION_RULE_VERSION
    research_only: bool = True

    @field_validator("session_id")
    @classmethod
    def _valid_session_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not SESSION_ID_RE.match(text):
            raise ValueError(f"malformed session_id: {value!r}")
        return text

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in SESSION_STATUSES:
            raise ValueError(f"invalid session status: {value!r}")
        return text

    @field_validator("started_at", "ended_at")
    @classmethod
    def _optional_timestamp(cls, value: object) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        try:
            datetime.fromisoformat(text)
        except ValueError:
            raise ValueError("timestamp must be ISO-8601") from None
        return text

    @field_validator("created_at")
    @classmethod
    def _created_timestamp(cls, value: str) -> str:
        return _validated_timestamp(value, "created_at")

    @field_validator("planned_minutes")
    @classmethod
    def _valid_planned(cls, value: int) -> int:
        return _validated_minutes(value, "planned_minutes")

    @field_validator("actual_minutes")
    @classmethod
    def _valid_actual(cls, value: int) -> int:
        return _validated_minutes(value, "actual_minutes")

    @field_validator("notes")
    @classmethod
    def _valid_notes(cls, value: object) -> str:
        text = normalize_note(value)
        if len(text) > MAX_NOTES_CHARS:
            raise ValueError(f"notes exceeds {MAX_NOTES_CHARS} characters")
        return text

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: str) -> str:
        return SESSION_RULE_VERSION

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: bool) -> bool:
        if not value:
            raise ValueError("sessions are research-only")
        return True

    # -- derived time accounting (never stored) ----------------------------
    @property
    def variance_minutes(self) -> int:
        """actual_minutes - planned_minutes (may be negative)."""

        return int(self.actual_minutes) - int(self.planned_minutes)

    @property
    def efficiency_ratio(self) -> float | None:
        """planned / actual, only when actual_minutes > 0 (never None-safe)."""

        if int(self.actual_minutes) <= 0:
            return None
        return round(int(self.planned_minutes) / int(self.actual_minutes), 4)

    def to_view(self) -> dict:
        """Serializable view with derived fields (no clock, no randomness)."""

        data = self.model_dump(mode="json")
        data["variance_minutes"] = self.variance_minutes
        data["efficiency_ratio"] = self.efficiency_ratio
        return data
