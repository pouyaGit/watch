"""Asset <-> CVE match schema (Stage R30.1).

An :class:`AssetCVEMatch` is a read-only, evidence-backed statement that one
piece of *observed* Watch asset intelligence corresponds to one piece of
researched CVE metadata. It answers the owner's personal-research question:

    "Does Watch have enough evidence that this CVE applies to something I
    actually monitor?"

Hard boundaries encoded here:

- ``match_type`` is a closed vocabulary (PRODUCT / COMPONENT / PLUGIN /
  TECHNOLOGY / VERSION / PARAMETER / VULNERABILITY_TYPE / PATH). It is never a
  vulnerability verdict.
- ``confidence`` is a closed deterministic class (HIGH / MEDIUM / LOW).
  ``confidence_score`` is a bounded per-match encoding of that class, never a
  new opportunity score and never combined with the Money Score.
- ``asset_identifier`` is the privacy-preserving internal asset identity: a
  deterministic token derived from the existing internal asset identity. Raw
  target URLs / IPs / hostnames are never stored here.
- ``rule_version`` is fixed to ``r30-1``; ``research_only`` is forced ``True``.
- no payout / bounty / reward / target URL / IP / domain / credential /
  exploit-command / execution-command / production-finding fields exist;
  unknown fields are rejected (``extra="forbid"``).

No I/O, no network, no LLM, no execution of any kind is represented here.
"""

from __future__ import annotations

import hashlib
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

ASSET_CVE_MATCH_RULE_VERSION = "r30-1"

# Closed match-type vocabulary. VULNERABILITY_TYPE and PATH are supporting
# signals only (documented in ai/knowledge/asset_cve_matching.py).
MATCH_TYPES: tuple[str, ...] = (
    "PRODUCT",
    "COMPONENT",
    "PLUGIN",
    "TECHNOLOGY",
    "VERSION",
    "PARAMETER",
    "VULNERABILITY_TYPE",
    "PATH",
)

# Supporting match types never independently make a target-specific match HIGH.
SUPPORTING_MATCH_TYPES: frozenset[str] = frozenset(
    {"VULNERABILITY_TYPE", "PATH"}
)

CONFIDENCES: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW")

# Deterministic per-match encoding of the confidence class. This is NOT an
# opportunity score: it is never summed across matches nor fed into R25/R26/R29.
CONFIDENCE_SCORES: dict[str, int] = {"HIGH": 90, "MEDIUM": 60, "LOW": 30}

SOURCES: tuple[str, ...] = (
    "ASSET_INVENTORY",
    "TECHNOLOGY_INVENTORY",
    "COMPONENT_INVENTORY",
    "PARAMETER_INVENTORY",
    "ENDPOINT_INVENTORY",
    "CVE_METADATA",
)

MATCH_ID_PREFIX = "am-"
MATCH_ID_RE = re.compile(r"^am-[0-9a-f]{16}$")
ASSET_ID_RE = re.compile(r"^asset-[0-9a-f]{16}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
PROGRAM_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")

MAX_EVIDENCE = 32
MAX_BLOCKERS = 16
MAX_REASON_LEN = 512
MAX_VALUE_LEN = 256


def confidence_score_for(confidence: str) -> int:
    """Bounded deterministic per-match confidence encoding (never summed)."""

    return CONFIDENCE_SCORES.get(str(confidence or "").strip().upper(), 0)


def match_id_for(
    cve_id: str,
    program: str,
    match_type: str,
    normalized_value: str,
    asset_identifier: str = "",
    rule_version: str = ASSET_CVE_MATCH_RULE_VERSION,
) -> str:
    """Deterministic match id from rule_version + cve + program + evidence.

    No randomness, no clock. Idempotent within a rule version.
    """

    basis = "\n".join(
        [
            str(rule_version or ""),
            str(cve_id or ""),
            str(program or ""),
            str(match_type or ""),
            str(normalized_value or ""),
            str(asset_identifier or ""),
        ]
    )
    return MATCH_ID_PREFIX + hashlib.sha256(
        basis.encode("utf-8")
    ).hexdigest()[:16]


class AssetCVEMatch(BaseModel):
    """One evidence-backed CVE <-> asset match (research-only)."""

    model_config = ConfigDict(extra="forbid")

    match_id: str
    cve_id: str
    program: str
    asset_identifier: str = ""

    match_type: str
    confidence: str = "LOW"
    confidence_score: int = 0
    matched_value: str = ""
    source: str = "CVE_METADATA"
    evidence: list[str] = Field(default_factory=list)
    reason: str = ""
    blocker_resolution: list[str] = Field(default_factory=list)

    rule_version: str = ASSET_CVE_MATCH_RULE_VERSION
    research_only: bool = True

    @field_validator("match_id")
    @classmethod
    def _valid_match_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not MATCH_ID_RE.match(text):
            raise ValueError(f"malformed match_id: {value!r}")
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

    @field_validator("asset_identifier")
    @classmethod
    def _valid_asset_identifier(cls, value: str) -> str:
        text = str(value or "").strip()
        if text and not ASSET_ID_RE.match(text):
            raise ValueError(f"malformed asset_identifier: {value!r}")
        return text

    @field_validator("match_type")
    @classmethod
    def _valid_match_type(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in MATCH_TYPES:
            raise ValueError(f"invalid match_type: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: str) -> str:
        text = str(value or "LOW").strip().upper()
        if text not in CONFIDENCES:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("source")
    @classmethod
    def _valid_source(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in SOURCES:
            raise ValueError(f"invalid source: {value!r}")
        return text

    @field_validator("confidence_score")
    @classmethod
    def _valid_confidence_score(cls, value: int) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"malformed confidence_score: {value!r}")
        return max(0, min(100, number))

    @field_validator("matched_value", "reason")
    @classmethod
    def _bounded_text(cls, value: object) -> str:
        return str(value or "").strip()[:MAX_REASON_LEN]

    @field_validator("evidence", "blocker_resolution")
    @classmethod
    def _bounded_lists(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = str(item or "").strip()[:MAX_VALUE_LEN]
            if text and text not in out:
                out.append(text)
            if len(out) >= MAX_EVIDENCE:
                break
        return out

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: str) -> str:
        return ASSET_CVE_MATCH_RULE_VERSION

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: bool) -> bool:
        if not value:
            raise ValueError("asset/CVE matches are research-only")
        return True


def match_projection(value: AssetCVEMatch) -> dict:
    """Serialize one asset/CVE match to a deterministic dict."""

    return value.model_dump(mode="json")
