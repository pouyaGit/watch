"""Historical candidate ranking schema (Stage R33.2).

A :class:`HistoricalCandidateRankingPlan` ranks research candidates using
historical memory signals. It answers the owner's personal-research question:

    "Which candidate deserves higher research attention based on history?"

Hard boundaries encoded here:

- Deterministic factor scoring only: no Money Score, no probability, no ML,
  no embeddings, no LLM.
- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: signal codes and ranking reasons are closed sets.
- Bounded, privacy-safe: only closed codes, bounded counts and caller-supplied
  candidate identity tokens are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

RESEARCH_CANDIDATE_RANKING_RULE_VERSION = "r33-2"
RULE_VERSION = RESEARCH_CANDIDATE_RANKING_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

SIGNAL_HISTORICAL_SUCCESS = "HISTORICAL_SUCCESS"
SIGNAL_REPEATED_SUCCESS = "REPEATED_SUCCESS"
SIGNAL_TECHNOLOGY_SUCCESS = "TECHNOLOGY_SUCCESS"
SIGNAL_EVIDENCE_AVAILABILITY = "EVIDENCE_AVAILABILITY"
SIGNAL_REPEATED_DEFER = "REPEATED_DEFER"
SIGNAL_REPEATED_MISSING_EVIDENCE = "REPEATED_MISSING_EVIDENCE"
SIGNAL_UNRESOLVED_BLOCKERS = "UNRESOLVED_BLOCKERS"

HISTORICAL_SIGNALS: tuple[str, ...] = (
    SIGNAL_HISTORICAL_SUCCESS,
    SIGNAL_REPEATED_SUCCESS,
    SIGNAL_TECHNOLOGY_SUCCESS,
    SIGNAL_EVIDENCE_AVAILABILITY,
    SIGNAL_REPEATED_DEFER,
    SIGNAL_REPEATED_MISSING_EVIDENCE,
    SIGNAL_UNRESOLVED_BLOCKERS,
)

REASON_NO_HISTORY = "NO_HISTORY"
REASON_SINGLE_CANDIDATE = "SINGLE_CANDIDATE"
REASON_HISTORICAL_SCORE = "HISTORICAL_SCORE"

RANKING_REASONS: tuple[str, ...] = (
    REASON_NO_HISTORY,
    REASON_SINGLE_CANDIDATE,
    REASON_HISTORICAL_SCORE,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_CANDIDATES = 64
MAX_SIGNALS = 8
MAX_RECORDS = 256
MAX_VALUE_LEN = 160

SCORE_MIN = 0
SCORE_MAX = 10

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _require_signals(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in HISTORICAL_SIGNALS:
            raise ValueError(f"invalid historical signal: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_signals(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in HISTORICAL_SIGNALS and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _require_scores(value: object, limit: int) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            raise ValueError(f"malformed candidate score: {item!r}")
        identity = _safe_text(item.get("candidate_identity"))
        try:
            score = int(item.get("score"))
        except (TypeError, ValueError):
            raise ValueError(f"malformed score: {item!r}")
        if score < 0:
            raise ValueError(f"negative score: {item!r}")
        try:
            records = int(item.get("records"))
        except (TypeError, ValueError):
            raise ValueError(f"malformed records: {item!r}")
        if records < 0:
            raise ValueError(f"negative records: {item!r}")
        entry = {
            "candidate_identity": identity,
            "score": score,
            "records": records,
            "signals": _require_signals(item.get("signals"), MAX_SIGNALS),
        }
        if entry not in out:
            out.append(entry)
        if len(out) >= limit:
            break
    return out


def _bounded_scores(value: object, limit: int) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            continue
        try:
            score = max(0, int(item.get("score")))
            records = max(0, int(item.get("records")))
        except (TypeError, ValueError):
            continue
        entry = {
            "candidate_identity": _safe_text(item.get("candidate_identity")),
            "score": score,
            "records": records,
            "signals": _bounded_signals(item.get("signals"), MAX_SIGNALS),
        }
        if entry not in out:
            out.append(entry)
        if len(out) >= limit:
            break
    return out


def sanitize_historical_candidate_ranking_plan(value: object) -> dict:
    """Project an R33.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "candidate_scores": [],
            "ranking_reason": "",
            "historical_signals": [],
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "candidate_scores": _bounded_scores(
            value.get("candidate_scores"), MAX_CANDIDATES
        ),
        "ranking_reason": _safe_text(value.get("ranking_reason")),
        "historical_signals": _bounded_signals(
            value.get("historical_signals"), MAX_SIGNALS
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class HistoricalCandidateRankingPlan(BaseModel):
    """Deterministic historical candidate ranking (R33.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_CANDIDATE_RANKING_RULE_VERSION
    candidate_scores: list[dict] = Field(default_factory=list)
    ranking_reason: str
    historical_signals: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_CANDIDATE_RANKING_RULE_VERSION

    @field_validator("candidate_scores")
    @classmethod
    def _valid_scores(cls, value: list) -> list[dict]:
        return _require_scores(value, MAX_CANDIDATES)

    @field_validator("ranking_reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in RANKING_REASONS:
            raise ValueError(f"invalid ranking_reason: {value!r}")
        return text

    @field_validator("historical_signals")
    @classmethod
    def _valid_signals(cls, value: list) -> list[str]:
        return _require_signals(value, MAX_SIGNALS)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "historical candidate rankings are research-only"
            )
        return True


def historical_candidate_ranking_plan_projection(
    value: HistoricalCandidateRankingPlan,
) -> dict:
    """Serialize a candidate ranking plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_CANDIDATE_RANKING_RULE_VERSION",
    "RULE_VERSION",
    "HISTORICAL_SIGNALS",
    "RANKING_REASONS",
    "SIGNAL_HISTORICAL_SUCCESS",
    "SIGNAL_REPEATED_SUCCESS",
    "SIGNAL_TECHNOLOGY_SUCCESS",
    "SIGNAL_EVIDENCE_AVAILABILITY",
    "SIGNAL_REPEATED_DEFER",
    "SIGNAL_REPEATED_MISSING_EVIDENCE",
    "SIGNAL_UNRESOLVED_BLOCKERS",
    "REASON_NO_HISTORY",
    "REASON_SINGLE_CANDIDATE",
    "REASON_HISTORICAL_SCORE",
    "MAX_CANDIDATES",
    "MAX_SIGNALS",
    "MAX_RECORDS",
    "MAX_VALUE_LEN",
    "SCORE_MIN",
    "SCORE_MAX",
    "HistoricalCandidateRankingPlan",
    "sanitize_historical_candidate_ranking_plan",
    "historical_candidate_ranking_plan_projection",
]
