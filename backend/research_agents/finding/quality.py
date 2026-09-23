"""Evidence quality metadata (Phase 9) + severity provenance (Phase 11).

Quality classifications are DETERMINISTIC functions of the actual
observation source — reliability values are never invented.  Severity is
UNASSESSED unless an authoritative rule (knowledge-base CVE record)
backs it; the LLM can never set severity (advisor validator drops it and
the models reject severity without provenance).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from backend.research_agents.finding.models import (
    SEVERITY_PROVENANCE_UNASSESSED,
    SEVERITY_UNASSESSED,
)
from backend.research_data import severity_bucket

QUALITY_RULE_VERSION = "finding-quality-1"

# source type -> (reliability class, direct?, authoritative-eligible?)
SOURCE_CLASSES: dict[str, tuple[str, bool, bool]] = {
    "observation":      ("observed_direct", True, True),
    "knowledge":        ("researched_knowledge", False, False),
    "prior_research":   ("prior_research", False, False),
    "prior_recommendation": ("prior_advisory", False, False),
    "llm_insight":      ("advisory_llm", False, False),
    "negative":         ("observed_negative", True, True),
    "memory":           ("research_memory", False, False),
}
UNKNOWN_SOURCE = ("unclassified", False, False)

NEGATIVE_SIGNALS = frozenset(
    {"negative", "contradiction", "disproved", "rejected"})


@dataclass
class EvidenceQuality:
    evidence_id: str
    source: str                  # evidence row type (actual source)
    observation_type: str        # hunt observation type when present
    reliability_class: str
    direct: bool
    authoritative_eligible: bool
    stance: str                  # supporting|contradicting|neutral
    verification_relevance: str  # verification|background
    observed_at: str
    provenance: dict[str, Any]
    rule_version: str = QUALITY_RULE_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "observation_type": self.observation_type,
            "reliability_class": self.reliability_class,
            "direct": self.direct,
            "authoritative_eligible": self.authoritative_eligible,
            "stance": self.stance,
            "verification_relevance": self.verification_relevance,
            "observed_at": self.observed_at,
            "provenance": dict(self.provenance),
            "rule_version": self.rule_version,
        }


def classify_evidence(
    row: dict[str, Any],
    *,
    vulnerability_class: str = "",
    verification_job_ids: Iterable[str] = (),
) -> EvidenceQuality:
    """Deterministic quality classification from the actual source row."""
    source = str(row.get("type") or "").lower()
    reliability, direct, authoritative = SOURCE_CLASSES.get(
        source, UNKNOWN_SOURCE)
    signal = str(row.get("signal") or "").lower()
    category = str(row.get("category") or "").upper()

    if source in NEGATIVE_SIGNALS or signal in NEGATIVE_SIGNALS:
        stance = "contradicting"
        if reliability == "unclassified":
            reliability, direct, authoritative = "observed_negative", True, True
    elif vulnerability_class and category == str(vulnerability_class).upper():
        stance = "supporting"
    elif vulnerability_class and not category:
        stance = "neutral"
    else:
        stance = "supporting" if source in ("observation", "knowledge") \
            else "neutral"

    vjobs = {str(j) for j in verification_job_ids}
    relevance = "verification" if str(row.get("job_id") or "") in vjobs \
        else "background"

    return EvidenceQuality(
        evidence_id=str(row.get("id") or ""),
        source=source or "unknown",
        observation_type=str(row.get("observation_ref") or ""),
        reliability_class=reliability,
        direct=direct,
        authoritative_eligible=authoritative,
        stance=stance,
        verification_relevance=relevance,
        observed_at=str(row.get("created_at") or ""),
        provenance={
            "source": "deterministic_quality_rules",
            "evidence_job": str(row.get("job_id") or ""),
            "confidence": str(row.get("confidence") or ""),
        },
    )


def classify_batch(rows: Iterable[dict[str, Any]], *,
                   vulnerability_class: str = "",
                   verification_job_ids: Iterable[str] = (),
                   ) -> list[EvidenceQuality]:
    return [classify_evidence(r, vulnerability_class=vulnerability_class,
                              verification_job_ids=verification_job_ids)
            for r in rows]


# ------------------------------------------------------- severity provenance

SEVERITY_RULE_VERSION = "finding-severity-1"


@dataclass
class SeverityDetermination:
    severity: str                      # bucket token or UNASSESSED
    provenance: str                    # authoritative rule id or unassessed
    source_record: str = ""            # KB/CVE record reference, if any
    rule_version: str = SEVERITY_RULE_VERSION
    limitations: str = ("severity is never LLM-authored; UNASSESSED "
                        "unless an authoritative record backs it")

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "provenance": self.provenance,
            "source_record": self.source_record,
            "rule_version": self.rule_version,
            "limitations": self.limitations,
        }


def derive_severity(*,
                    cve_id: str = "",
                    kb_record: dict[str, Any] | None = None,
                    ) -> SeverityDetermination:
    """Deterministic severity: UNASSESSED by default; a knowledge-base CVE
    record with a persisted severity/cvss is the only authoritative source
    in v1 (rule 21-23)."""
    if isinstance(kb_record, dict) and kb_record:
        raw = str(kb_record.get("severity") or "")
        bucket = severity_bucket(raw) if raw else ""
        cvss = kb_record.get("cvss_score")
        if bucket and bucket.upper() not in ("", "NONE"):
            return SeverityDetermination(
                severity=bucket.upper(),
                provenance=f"knowledge_base_cvss:{cve_id or 'unknown'}"
                           + (f":{cvss}" if cvss is not None else ""),
                source_record=str(kb_record.get("cve") or cve_id or ""),
            )
    return SeverityDetermination(
        severity=SEVERITY_UNASSESSED,
        provenance=SEVERITY_PROVENANCE_UNASSESSED)
