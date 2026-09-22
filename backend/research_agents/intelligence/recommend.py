"""backend/research_agents/intelligence/recommend.py — Phase 3.

Bounded, research-oriented recommendation engine.  Given the new job's
authorized observation set plus retrieved prior research, it emits
deterministic recommendations with reason codes and provenance.

Safety contract (enforced in-engine, not just in tests):

- Recommendations are RESEARCH/OBSERVATION suggestions only.
- No payloads, no exploit steps, no target URLs, no shell/HTTP commands.
- Any recommendation that trips the banned-pattern validator raises
  ``RecommendationUnsafe`` — callers record the failure honestly and
  persist nothing (``RecommendationUnsafe`` never becomes memory).
- Similarity-derived advice always repeats its limitation.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from backend.research_agents.intelligence.memory import scrub_text

BANNED_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("payload_marker", re.compile(r"(?i)<script|javascript:|onerror=|"
                                  r"union\s+select|\bor\b\s+1\s*=\s*1|"
                                  r"'\s*or\s*'")),
    ("shell_or_http_tool", re.compile(r"(?i)\bcurl\b|\bwget\b|\bnc\s+-|"
                                      r"/bin/(ba)?sh|\beval\s+\(|"
                                      r"base64\s+-d")),
    ("execution_word", re.compile(r"(?i)\bexploit|\bpayload|\bpenetrate|"
                                  r"\battack\b")),
    ("send_instruction", re.compile(r"(?i)send\s+(this|the)\s+(payload|"
                                    r"request)|fire\s+at\s+|launch\s+attack")),
    ("target_url", re.compile(r"(?i)https?://|www\.[a-z0-9]")),
    ("credential_ask", re.compile(r"(?i)\bpassword\b|\btoken\s*=\s*|"
                                  r"api[_-]?key\s*=")),
)


class RecommendationUnsafe(Exception):
    """A recommendation violated the research-only safety contract."""


@dataclass
class Recommendation:
    id: str
    type: str
    text: str
    reason_codes: list[str] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    limitations: str = "advisory research recommendation; no execution steps"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "type": self.type, "text": self.text,
            "reason_codes": list(self.reason_codes),
            "provenance": dict(self.provenance),
            "limitations": self.limitations,
        }


def _validate(text: str) -> None:
    if not text.strip():
        raise RecommendationUnsafe("empty recommendation text")
    if len(text) > 300:
        raise RecommendationUnsafe("recommendation text exceeds bound")
    for name, pattern in BANNED_PATTERNS:
        if pattern.search(text):
            raise RecommendationUnsafe(f"banned pattern: {name}")


def _make(job: Any, kind: str, text: str, reasons: list[str],
          refs: list[str]) -> Recommendation:
    _validate(text)
    job_id = str(getattr(job, "id", "") or "")
    digest = hashlib.sha256(
        f"{job_id}|{kind}|{text}".encode("utf-8")).hexdigest()[:12]
    return Recommendation(
        id=f"rec-{digest}", type=kind, text=scrub_text(text, 300),
        reason_codes=[scrub_text(r, 80) for r in reasons][:6],
        provenance={"job_id": job_id, "source": "recommendation_engine",
                    "refs": [scrub_text(r, 80) for r in refs][:6]},
    )


def recommend(
    *,
    job: Any,
    capability: Any,
    analysis: dict[str, Any],
    related: list[Any],
    memory_hits: list[Any],
    knowledge: list[dict[str, Any]],
    decision: Any,
    limit: int = 6,
) -> list[Recommendation]:
    """Post-gate deterministic recommendations (ordered, bounded)."""
    limit = max(0, int(limit))
    category = str(getattr(capability, "category", "") or "")
    out: list[Recommendation] = []

    # 1) Gate-authoritative negative result -> keep it as research memory
    if decision is not None and not getattr(decision, "create", False):
        reason = scrub_text(getattr(decision, "reason", ""), 60) or "unknown"
        out.append(_make(
            job, "research_negative_result",
            f"Gate decision {reason}: treat the hypothesis as not "
            f"established for this scope; retain it as negative research "
            f"memory and require fresh evidence before re-asserting.",
            [f"gate_{reason}"], [str(getattr(job, "id", ""))]))

    # 2) Missing required evidence types (deterministic, capability-set)
    req = getattr(capability, "evidence_requirements", None)
    present = {str(e.get("type") or "")
               for e in (analysis.get("evidence_candidates") or [])}
    for ev_type in (getattr(req, "required_types", None) or ()):
        if str(ev_type) not in present:
            out.append(_make(
                job, "acquire_evidence",
                f"{category} case creation requires evidence type "
                f"{ev_type}; request or inspect an authorized observation "
                f"that records it for the in-scope parameters before any "
                f"claim.",
                [f"missing_evidence_type:{ev_type}"],
                [str(getattr(capability, "agent_name", ""))]))

    # 2b) Specialist intelligence hints never observed in this attempt ->
    #     request an authorized observation carrying that signal first.
    observed_blob = " ".join(
        [str(s) for s in (analysis.get("signals") or [])]
        + [str(c.get("kind") or "") for c in
           (analysis.get("evidence_candidates") or [])]
        + [str(b) for b in (analysis.get("blockers") or [])]
    ).lower()
    hint_missing = [str(h) for h in
                    (getattr(capability, "intelligence_hints", ()) or ())
                    if str(h).lower() and str(h).lower() not in observed_blob]
    for hint in hint_missing[:2]:
        out.append(_make(
            job, "acquire_evidence",
            f"{category} research has not observed '{hint}' evidence in "
            f"this attempt; request or inspect an authorized observation "
            f"that records {hint}-related signals for the in-scope "
            f"parameter before claiming related findings.",
            [f"missing_signal_evidence:{hint}"],
            [str(getattr(capability, "agent_name", ""))]))

    # 3) Similar rejected hypothesis -> consult negative memory
    for rel in related:
        if rel.kind == "similar_rejected_hypothesis":
            out.append(_make(
                job, "consult_negative_memory",
                f"A similar prior hypothesis was not established by the "
                f"evidence gate (reasons {','.join(rel.reasons[:2])}); "
                f"consult the negative memory and require fresh "
                f"observation evidence before re-asserting it.",
                ["similar_rejected_hypothesis"] + rel.reasons[:2],
                [rel.ref]))
            break

    # 4) Similar verified case -> reference without claiming proof
    for rel in related:
        if rel.kind == "similar_verified_case":
            out.append(_make(
                job, "reference_prior_verified",
                f"Prior case {rel.ref} was verified under the same "
                f"evidence rules on a similar pattern ("
                f"{','.join(rel.reasons[:2])}); similarity is not proof — "
                f"verify current observations against the same rules.",
                ["similar_verified_case"] + rel.reasons[:2],
                [rel.ref]))
            break

    # 5) Specialist edge: focus parameter needs its class's observation
    focus = str(getattr(job, "parameter", "") or "")
    if focus:
        if category == "XSS":
            out.append(_make(
                job, "analyze_pattern",
                f"Parameter '{focus}' appears in the authorized "
                f"observation set; request reflection-oriented "
                f"observation evidence for it before claiming XSS.",
                ["parameter_reflection_evidence"], [focus]))
        elif category == "CVE_RESEARCH":
            out.append(_make(
                job, "analyze_pattern",
                f"Correlate stored technology and version signals for "
                f"the observed endpoints with knowledge-base CVE "
                f"references before claiming any version exposure "
                f"(focus '{focus}').",
                ["technology_correlation_evidence"], [focus]))

    # 6) Knowledge consulted -> applicability reminder
    for doc in knowledge[:2]:
        rel = doc.get("relevance") or {}
        out.append(_make(
            job, "consult_knowledge",
            f"Knowledge {doc.get('id', '')} was selected "
            f"({rel.get('why') or 'topic match'}); review applicability — "
            f"a knowledge-base reference alone never establishes target "
            f"exposure.",
            ["knowledge_relevance"] + list(rel.get("reasons") or [])[:2],
            [str(doc.get("id") or "")]))

    # 7) Negative evidence observed -> what is still missing
    negatives = [b for b in (analysis.get("blockers") or [])][:2]
    if negatives:
        out.append(_make(
            job, "acquire_evidence",
            "Deterministic analysis recorded blockers ("
            + "; ".join(scrub_text(n, 60) for n in negatives)
            + "); target the missing observation type directly.",
            ["negative_evidence_observed"], []))

    return out[:limit] if limit else []


def to_memory_item(job: Any, recommendation: Recommendation):
    """Promote a generated recommendation into research memory (Phase 1
    kind ``research_recommendation``).  Validation happens again in
    ``make_item`` (secret scrub) — unsafe items never get here."""
    from backend.research_agents.intelligence.memory import make_item
    return make_item(
        kind="research_recommendation", state="RESEARCHED",
        subject_key=recommendation.id,
        text=recommendation.text,
        category=str(getattr(job, "agent_category", "") or ""),
        agent=str(getattr(job, "assigned_agent", "") or ""),
        target=str(getattr(job, "subdomain", "") or ""),
        program=str(getattr(job, "program", "") or ""),
        confidence="advisory",
        provenance_job=str(getattr(job, "id", "") or ""),
        provenance_source="recommendation_engine",
        provenance_refs=recommendation.reason_codes[:4],
        limitations=recommendation.limitations,
    )


__all__ = ["BANNED_PATTERNS", "Recommendation", "RecommendationUnsafe",
           "recommend", "to_memory_item"]
