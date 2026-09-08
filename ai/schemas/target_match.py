"""Target Pattern Match data contract (Phase 3B).

A TargetPatternMatch is a DETERMINISTIC, READ-ONLY relevance statement
joining one research pattern (VulnerabilityPattern / AttackPattern)
with one observed target (TargetIntelligence). It answers ONLY:

    "Does the available research pattern appear deterministically
    relevant to this observed target?"

It MUST NOT be read as, and carries no field expressing:

- vulnerable / affected / confirmed / verified / exploited
- not vulnerable / safe
- scope permission / execution authorization
- finding / evidence / verdict

MATCH means only "the deterministic research/asset criteria matched".
INCONCLUSIVE means required information is missing or unrepresentable.
PARTIAL_MATCH means some criteria matched while others are unmatched
or unknown. NO_MATCH means at least one prerequisite criterion
deterministically failed (product identity absent, observed version
outside the research-side bounds, or every applicable criterion
unmatched).

Neither input is ground truth: the pattern is research-derived
intelligence and the target is observed recon inventory. The result
is therefore RELEVANCE, never a vulnerability verdict. Any future
execution stage must re-resolve the current target, current scope
(via ai/correlator/scope_policy.py), and current inventory before
acting; a match result grants no future authority.

Identity follows the Watch content-addressing convention: ``match_id``
(``tm-`` + 16 hex) is the short alias of the full SHA-256 over the
canonical match basis (matcher version + pattern id + target key +
snapshot hash + sorted criteria). Same inputs produce the same id;
no timestamps, randomness, model output, or process state enters it.

The deterministic relevance score is the proportion of evaluated
criteria that matched::

    score = matched / (matched + unmatched + unknown)

It is derived ONLY from deterministic match fields (product, version,
endpoint, method, parameter, technology matches). Model priority,
LLM confidence, severity, and CVSS are never inputs and cannot
influence it.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

MATCHER_VERSION = "target_matcher/v1"

MatchKind = Literal[
    "MATCH",
    "PARTIAL_MATCH",
    "NO_MATCH",
    "INCONCLUSIVE",
]

MatchCriterion = Literal[
    "product",
    "version",
    "technology_context",
    "path",
    "method",
    "parameter",
    "parameter_location",
    "technique",
    "sink_characteristic",
    "precondition",
    "expected_observable",
    "required_condition",
    "observable",
]

_TM_ID_RE = re.compile(r"^tm-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PATTERN_ID_RE = re.compile(r"^(vp|ap)-[0-9a-f]{16}$")


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_json(payload: dict) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def match_id_for(
    *,
    pattern_id: str,
    target_key: str,
    snapshot_hash: str,
    matched_criteria: list[str],
    unmatched_criteria: list[str],
    unknown_criteria: list[str],
    matcher_version: str = MATCHER_VERSION,
) -> str:
    """Deterministic short alias for one match basis.

    The basis binds matcher version + pattern id + target key +
    snapshot hash + sorted criteria lists, so the same pattern
    evaluated against a changed inventory snapshot yields a
    distinct id instead of silently reusing a stale statement.
    """

    canonical = {
        "matched_criteria": sorted(matched_criteria),
        "matcher_version": matcher_version,
        "pattern_id": pattern_id,
        "snapshot_hash": snapshot_hash,
        "target_key": target_key,
        "unmatched_criteria": sorted(unmatched_criteria),
        "unknown_criteria": sorted(unknown_criteria),
    }
    return "tm-" + _sha256_hex(_canonical_json(canonical))[:16]


def deterministic_score_for(
    *,
    matched: int,
    unmatched: int,
    unknown: int,
) -> float:
    """Explainable relevance proportion over evaluated criteria.

    ``matched / (matched + unmatched + unknown)``, rounded to 4
    decimals; zero when nothing was evaluated. Every score is
    reconstructable from the three criteria lists.
    """

    total = matched + unmatched + unknown
    if total <= 0:
        return 0.0
    return round(matched / total, 4)


class TargetPatternMatch(BaseModel):
    """Deterministic relevance between one pattern and one target.

    RELEVANCE ONLY. This contract expresses no verdict, no finding,
    no scope decision, and no execution authority. Unknown fields
    (including ``verdict``, ``confirmed``, ``target_affected``,
    ``scope_allowed``, ``execution_allowed``, ``command``) are
    rejected fail-closed.
    """

    model_config = ConfigDict(extra="forbid")

    match_id: str
    pattern_id: str
    pattern_type: Literal["vulnerability", "attack"]
    target_key: str
    snapshot_hash: str
    program_name: str
    subdomain: str
    match_kind: MatchKind
    matched_criteria: list[MatchCriterion] = Field(
        default_factory=list
    )
    unmatched_criteria: list[MatchCriterion] = Field(
        default_factory=list
    )
    unknown_criteria: list[MatchCriterion] = Field(
        default_factory=list
    )
    deterministic_score: float = Field(default=0.0, ge=0.0, le=1.0)
    explanation: str = ""
    matcher_version: Literal["target_matcher/v1"] = (
        "target_matcher/v1"
    )

    @field_validator("match_id")
    @classmethod
    def _match_id(cls, value: str) -> str:
        if not _TM_ID_RE.match(value or ""):
            raise ValueError(f"invalid match_id: {value!r}")
        return value

    @field_validator("pattern_id")
    @classmethod
    def _pattern_id(cls, value: str) -> str:
        if not _PATTERN_ID_RE.match(value or ""):
            raise ValueError(f"invalid pattern_id: {value!r}")
        return value

    @field_validator("target_key", "snapshot_hash")
    @classmethod
    def _keys(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid key: {value!r}")
        return value

    @field_validator("program_name", "subdomain")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        if "\n" in value or "\r" in value:
            raise ValueError("must not contain newlines")
        return value

    @field_validator(
        "matched_criteria", "unmatched_criteria", "unknown_criteria"
    )
    @classmethod
    def _sorted_unique(
        cls, values: list[str]
    ) -> list[str]:
        if len(set(values)) != len(values):
            raise ValueError(
                "criteria lists must not contain duplicates"
            )
        if sorted(values) != list(values):
            raise ValueError(
                "criteria lists must be sorted for determinism"
            )
        return values

    @field_validator("explanation")
    @classmethod
    def _explanation(cls, value: str) -> str:
        if len(value) > 4096:
            raise ValueError("explanation exceeds 4096 characters")
        if "\n" in value or "\r" in value:
            raise ValueError("explanation must be single-line")
        return value


__all__ = [
    "MATCHER_VERSION",
    "MatchCriterion",
    "MatchKind",
    "TargetPatternMatch",
    "deterministic_score_for",
    "match_id_for",
]
