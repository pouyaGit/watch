"""Economic research outcome schema (Stage R25.5).

One :class:`ResearchOutcome` records what actually happened when a researcher
acted on an R25 economic lead (accepted, duplicate, rejected, not applicable,
wasted time, or still in progress). This is outcome capture for future Money
Score calibration only.

Hard boundaries encoded here:

- status is a closed research-outcome vocabulary; never a vulnerability
  verdict (no VULNERABLE / VERIFIED / EXPLOITED / FINDING).
- no payout/reward/bounty amount fields exist; unknown fields are rejected
  (``extra="forbid"``), so a payout field can never be persisted through this
  schema.
- ``time_spent_minutes`` is a non-negative bounded integer.
- ``researcher_note`` is whitespace-normalized and bounded.
- the outcome_id is deterministic (content-addressed) so an identical
  duplicate submission is idempotent.
"""

from __future__ import annotations

import hashlib
import re

from pydantic import BaseModel, ConfigDict, field_validator

OUTCOME_RULE_VERSION = "r25-1"

# Closed research-outcome vocabulary (never a vulnerability verdict).
OUTCOME_STATUSES: tuple[str, ...] = (
    "ACCEPTED",
    "DUPLICATE",
    "REJECTED",
    "NOT_APPLICABLE",
    "WASTED_TIME",
    "IN_PROGRESS",
)

OUTCOME_SOURCES: tuple[str, ...] = ("MANUAL", "IMPORT")

OUTCOME_ID_PREFIX = "ro-"
OUTCOME_ID_RE = re.compile(r"^ro-[0-9a-f]{16}$")

LEAD_ID_RE = re.compile(r"^rl-[0-9a-f]{16}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
PROGRAM_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")

MAX_NOTE_CHARS = 2000
MAX_TIME_MINUTES = 100000


def normalize_note(value: object) -> str:
    """Deterministic whitespace normalization for a researcher note.

    - CRLF/CR -> LF
    - trailing whitespace stripped per line
    - 3+ consecutive blank lines collapsed to one blank line
    - outer whitespace stripped
    """

    text = str(value if value is not None else "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.strip() for line in text.split("\n")]
    out: list[str] = []
    blanks = 0
    for line in lines:
        if line:
            blanks = 0
            out.append(line)
        else:
            blanks += 1
            if blanks <= 1:
                out.append("")
    return "\n".join(out).strip()


def outcome_id_for(
    lead_id: str,
    status: str,
    time_spent_minutes: int,
    researcher_note: str,
    source: str = "MANUAL",
    rule_version: str = OUTCOME_RULE_VERSION,
) -> str:
    """Deterministic content-addressed outcome id (no clock, no randomness).

    Timestamp is metadata and intentionally excluded so an identical duplicate
    submission resolves to the same id and stays idempotent.
    """

    basis = "\n".join(
        [
            str(rule_version or ""),
            str(lead_id or ""),
            str(status or "").strip().upper(),
            str(int(time_spent_minutes or 0)),
            normalize_note(researcher_note),
            str(source or "").strip().upper(),
        ]
    )
    return OUTCOME_ID_PREFIX + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


class ResearchOutcome(BaseModel):
    """One append-only economic research outcome record (research-only)."""

    model_config = ConfigDict(extra="forbid")

    outcome_id: str
    lead_id: str
    cve_id: str
    program: str
    status: str
    timestamp: str = ""
    researcher_note: str = ""
    time_spent_minutes: int = 0
    source: str = "MANUAL"
    rule_version: str = OUTCOME_RULE_VERSION

    @field_validator("outcome_id")
    @classmethod
    def _valid_outcome_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not OUTCOME_ID_RE.match(text):
            raise ValueError(f"malformed outcome_id: {value!r}")
        return text

    @field_validator("lead_id")
    @classmethod
    def _valid_lead_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not LEAD_ID_RE.match(text):
            raise ValueError(f"malformed lead_id: {value!r}")
        return text

    @field_validator("cve_id")
    @classmethod
    def _valid_cve(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if not CVE_RE.match(text):
            raise ValueError(f"malformed cve_id: {value!r}")
        return text

    @field_validator("program")
    @classmethod
    def _valid_program(cls, value: str) -> str:
        text = str(value or "").strip()
        if not PROGRAM_RE.match(text):
            raise ValueError(f"malformed program: {value!r}")
        return text

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in OUTCOME_STATUSES:
            raise ValueError(f"invalid outcome status: {value!r}")
        return text

    @field_validator("source")
    @classmethod
    def _valid_source(cls, value: str) -> str:
        text = str(value or "MANUAL").strip().upper()
        if text not in OUTCOME_SOURCES:
            raise ValueError(f"invalid outcome source: {value!r}")
        return text

    @field_validator("time_spent_minutes")
    @classmethod
    def _valid_time(cls, value: int) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise ValueError("time_spent_minutes must be an integer") from None
        if number < 0:
            raise ValueError("time_spent_minutes must be non-negative")
        if number > MAX_TIME_MINUTES:
            raise ValueError(
                f"time_spent_minutes must be <= {MAX_TIME_MINUTES}"
            )
        return number

    @field_validator("researcher_note")
    @classmethod
    def _valid_note(cls, value: object) -> str:
        text = normalize_note(value)
        if len(text) > MAX_NOTE_CHARS:
            raise ValueError(
                f"researcher_note exceeds {MAX_NOTE_CHARS} characters"
            )
        return text

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule_version(cls, value: str) -> str:
        return OUTCOME_RULE_VERSION
