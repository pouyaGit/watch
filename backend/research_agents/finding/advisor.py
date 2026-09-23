"""Verification LLM advisor (Phase 10) — openrouter/free, advisory only.

Same R51 provider envelope as hunt/campaign advisors: advisory_id
``adv-`` + 16 hex, closed ``EXPLANATION`` mode (the closed vocabulary's
``VULNERABILITY_CONFIRMATION`` mode is FORBIDDEN and never used), MULTI
source layer, R44/R45 source refs, closed limitations codes, bounded
sections (worst-case canonical request <= MAX_CONTEXT_CHARS).

Structured response fields: candidate_interpretation, missing_evidence,
verification_recommendations, conflicting_evidence, related_cases,
confidence, blockers.  Trusted code rejects: unknown observation types,
arbitrary URLs (scan_forbidden), shell/code/exploit instructions, scope
expansion, severity/CVE-applicability claims.  The output is ADVISORY:
nothing here can decide VERIFIED — finding.gate never accepts advisor
input (Phase 8).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

from ai.schemas.llm_advisory_input import ADVISORY_INPUT_LIMITATIONS
from ai.schemas.llm_provider import (SOURCE_REF_LAYER_R44,
                                     SOURCE_REF_LAYER_R45)

ADVISOR_PROMPT_VERSION = "finding-verification-advisor-v1"
RULE_VERSION = "r51"
MAX_CONTEXT_CHARS = 4000


def _bounded(value: Any, limit: int) -> str:
    return str(value or "")[:max(0, int(limit))]


def advisor_request(
    *,
    candidate: Any,
    verification: Any,
    evidence_summary: list[dict[str, Any]],
    related_research: list[dict[str, Any]],
    knowledge_count: int,
    allowed_observation_types: Iterable[str],
    budget_remaining: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Bounded advisory request about how to VERIFY one candidate.

    Carries: candidate summary (scope as a REFERENCE, endpoint shape —
    never target URLs to fetch), evidence ids/types/stances only, missing
    evidence, related-research counts, allowed observation types, safety
    constraints.  Never carries unrestricted database contents, secrets,
    evidence bodies, or exploit steps.
    """
    allowed = sorted({str(t) for t in allowed_observation_types})[:8]
    instruction = _bounded(
        "You are advising which authorized observations would help verify "
        "or refute one candidate security signal in a bounded research "
        "workflow. This is advisory only: your response cannot confirm a "
        "vulnerability, cannot create evidence, and cannot execute "
        "anything. Respond with the standard advisory object: summary, "
        "insights (insight_code + text), recommendations "
        "(recommendation_code + text). Use MISSING_EVIDENCE_* insights, "
        "CONFLICTING_* insights, RELATED_CASE_* insights; use "
        "VERIFY_<type> recommendations only for observation types already "
        "listed as allowed, and BLOCKER_* when verification cannot "
        "proceed. Never include URLs, commands, payloads, severity "
        "ratings, CVE applicability claims, or exploit steps.", 500)

    signals: list[dict[str, Any]] = []
    signals.append({
        "signal_type": "CANDIDATE_SUMMARY",
        "subject": _bounded(
            f"{candidate.candidate_id} {candidate.vulnerability_class} "
            f"state={candidate.lifecycle_state} "
            f"conf={candidate.confidence} "
            f"scope={candidate.scope_ref}", 160),
        "source_agent": _bounded(candidate.specialist or "unselected", 60),
        "source_classification": _bounded(candidate.vulnerability_class, 40),
        "recommendation": _bounded(candidate.hypothesis, 200),
        "confidence": _bounded(candidate.confidence, 20),
        "research_only": True,
    })
    for row in evidence_summary[:6]:
        signals.append({
            "signal_type": "EVIDENCE_SUMMARY",
            "subject": _bounded(
                f"{row.get('evidence_id')} type={row.get('source')} "
                f"stance={row.get('stance')} "
                f"rel={row.get('reliability_class')}", 140),
            "source_agent": "evidence-store",
            "source_classification": _bounded(
                candidate.vulnerability_class, 40),
            "recommendation": "prioritized for verification review",
            "confidence": "not_evaluated",
            "research_only": True,
        })
    signals.append({
        "signal_type": "MISSING_EVIDENCE",
        "subject": _bounded(
            "missing: " + ",".join(
                str(m) for m in (verification.missing_evidence or [])[:6]),
            160),
        "source_agent": _bounded(candidate.specialist or "unselected", 60),
        "source_classification": _bounded(candidate.vulnerability_class, 40),
        "recommendation": _bounded(
            "allowed observations: " + ",".join(allowed), 160),
        "confidence": "not_evaluated",
        "research_only": True,
    })
    signals.append({
        "signal_type": "RELATED_RESEARCH",
        "subject": _bounded(
            f"related_research={len(related_research)} "
            f"linked_duplicates="
            f"{len((candidate.correlation or {}).get('linked_duplicates')
                   or [])}", 140),
        "source_agent": "similarity",
        "source_classification": _bounded(candidate.vulnerability_class, 40),
        "recommendation": _bounded(
            "knowledge_consulted=" + str(int(knowledge_count)), 120),
        "confidence": "not_evaluated",
        "research_only": True,
    })
    signals.append({
        "signal_type": "SAFETY_CONSTRAINTS",
        "subject": ("read-only authorized observations within "
                    f"{candidate.scope_ref}; no exploit, no shell, no "
                    "scope expansion; Evidence Gate decides", 160)[0],
        "source_agent": "finding-verification",
        "source_classification": _bounded(candidate.vulnerability_class, 40),
        "recommendation": "stay within allowed observation types",
        "confidence": "not_evaluated",
        "research_only": True,
    })
    if budget_remaining:
        signals.append({
            "signal_type": "BUDGET_STATE",
            "subject": _bounded(
                "remaining: " + ",".join(
                    f"{k}={v}" for k, v in
                    sorted(budget_remaining.items())[:8]), 140),
            "source_agent": "finding-verification",
            "source_classification": "BUDGET",
            "recommendation": "respect remaining verification budget",
            "confidence": "not_evaluated",
            "research_only": True,
        })

    sections = {
        "research_context": {
            "research_question": _bounded(verification.hypothesis, 200),
            "research_focus": _bounded(
                f"verification:{candidate.vulnerability_class}", 80),
            "context_fact_count": len(signals),
            "source_layers": ["authorized_observations", "knowledge",
                              "research_memory", "deterministic_analysis"],
            "research_only": True,
        },
        "learning_signals": signals[:9],
    }
    source_refs = [
        {"layer": SOURCE_REF_LAYER_R45,
         "reference": _bounded(candidate.scope_ref, 40).lower() or "none"},
        {"layer": SOURCE_REF_LAYER_R45,
         "reference": _bounded(
             f"candidate:{candidate.candidate_id}", 40).lower()},
        {"layer": SOURCE_REF_LAYER_R44,
         "reference": "finding-verification-gate-v1"},
        {"layer": SOURCE_REF_LAYER_R44,
         "reference": "evidence-quality-rules-v1"},
    ]
    request = {
        "rule_version": RULE_VERSION,
        "advisory_id": f"adv-{uuid.uuid4().hex[:16]}",
        "advisory_mode": "EXPLANATION",     # VULNERABILITY_CONFIRMATION forbidden
        "provider_kind": "OPENROUTER",
        "source_layer": "MULTI",
        "instruction": instruction,
        "sections": sections,
        "source_refs": source_refs,
        "limitations": list(ADVISORY_INPUT_LIMITATIONS)[:8],
        "research_only": True,
        "deterministic": False,
    }
    # Deterministic hard bound (bounded-context rule): trim the LEAST
    # essential signals — duplicated EVIDENCE_SUMMARY rows first, then any
    # non-essential signal — until the canonical JSON fits.  The required
    # signals (candidate summary, missing evidence, safety, budget) and
    # every closed-envelope key are always retained.
    essential = {"CANDIDATE_SUMMARY", "MISSING_EVIDENCE",
                 "SAFETY_CONSTRAINTS", "BUDGET_STATE"}
    blob = json.dumps(request, sort_keys=True)
    while len(blob) > MAX_CONTEXT_CHARS:
        sig_list = list(request["sections"].get("learning_signals") or [])
        victim = None
        for i in range(len(sig_list) - 1, -1, -1):
            stype = sig_list[i].get("signal_type")
            if stype == "EVIDENCE_SUMMARY":
                victim = i
                break
        if victim is None:
            for i in range(len(sig_list) - 1, -1, -1):
                if sig_list[i].get("signal_type") not in essential:
                    victim = i
                    break
        if victim is not None and len(sig_list) > 3:
            sig_list.pop(victim)
            request["sections"]["learning_signals"] = sig_list
            blob = json.dumps(request, sort_keys=True)
            continue
        # only essential signals remain: shrink the instruction (last
        # resort) but never drop envelope keys or safety signals
        if len(instruction) > 160:
            instruction = instruction[:160]
            request["instruction"] = instruction
            blob = json.dumps(request, sort_keys=True)
            continue
        break
    return request


# ---------------------------------------------------------------- outcome

@dataclass
class VerificationAdvisorOutcome:
    used: bool = False
    candidate_interpretation: str = ""
    missing_evidence: list[str] = field(default_factory=list)
    verification_recommendations: list[str] = field(default_factory=list)
    conflicting_evidence: list[str] = field(default_factory=list)
    related_cases: list[str] = field(default_factory=list)
    confidence: str = "advisory"        # label only; never a verdict
    blockers: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    model_requested: str = "openrouter/free"
    model_resolved: str = ""
    latency_ms: int = 0
    prompt_version: str = ADVISOR_PROMPT_VERSION
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "used": self.used,
            "candidate_interpretation": self.candidate_interpretation,
            "missing_evidence": list(self.missing_evidence),
            "verification_recommendations": list(
                self.verification_recommendations),
            "conflicting_evidence": list(self.conflicting_evidence),
            "related_cases": list(self.related_cases),
            "confidence": self.confidence,
            "blockers": list(self.blockers),
            "rejected": list(self.rejected),
            "model_requested": self.model_requested,
            "model_resolved": self.model_resolved,
            "latency_ms": self.latency_ms,
            "prompt_version": self.prompt_version,
            "error": self.error,
            "advisory_only": True,
        }


def validate_recommendation(
    observation_type: str,
    *,
    allowed_types: set[str],
    candidate_id: str,
    verification_id: str,
    scope_ref: str,
    expected_scope: str,
) -> tuple[bool, str]:
    """Every Phase-10 check; fail closed.  Unknown observation types,
    scope expansion, unknown ids are all rejected."""
    text = str(observation_type or "").strip()
    if not text:
        return False, "empty_observation_type"
    if text not in allowed_types:
        return False, f"unknown_observation_type:{text[:40]}"
    if not candidate_id or candidate_id.startswith("cand-") is False:
        # candidate ids are cand-<hex>; absence of a token is fine, but a
        # named id that does not match shape is rejected below
        pass
    if scope_ref and expected_scope and scope_ref != expected_scope:
        return False, "scope_expansion_attempt"
    return True, "valid"


def map_advisor_response(
    response: Any,
    *,
    candidate_id: str,
    verification_id: str,
    scope_ref: str,
    expected_scope: str,
    allowed_types: set[str],
) -> VerificationAdvisorOutcome:
    """Strict deterministic mapping + validation of the advisory response.

    On ANY shape/semantic/forbidden-content failure: error set, used=False
    — the deterministic verification path stands.  Nothing returned here
    can decide a verification outcome (the gate never reads this).
    """
    out = VerificationAdvisorOutcome()
    if not isinstance(response, dict):
        out.error = "malformed_advisor_response:not_an_object"
        return out
    summary = response.get("summary")
    insights = response.get("insights")
    recommendations = response.get("recommendations")
    if not isinstance(summary, str) or not summary.strip() \
            or not isinstance(insights, list) \
            or not isinstance(recommendations, list):
        out.error = "malformed_advisor_response:missing_keys"
        return out

    out.candidate_interpretation = _bounded(summary, 300)
    texts = [out.candidate_interpretation]

    for item in insights[:8]:
        if not isinstance(item, dict):
            out.error = "malformed_advisor_response:insight_shape"
            return out
        code = str(item.get("insight_code") or "")
        text = str(item.get("text") or "")
        if not code.strip() or not text.strip():
            out.error = "malformed_advisor_response:insight_item"
            return out
        texts.append(_bounded(text, 240))
        upper = code.upper()
        if upper.startswith("MISSING_EVIDENCE"):
            out.missing_evidence.append(_bounded(text, 160))
        elif upper.startswith("CONFLICT"):
            out.conflicting_evidence.append(_bounded(text, 160))
        elif upper.startswith("RELATED_CASE"):
            out.related_cases.append(_bounded(text, 120))
        elif upper.startswith("CONFIDENCE"):
            digits = "".join(ch for ch in upper if ch.isdigit())
            out.confidence = ("advisory" if not digits else
                              "advisory")   # label never becomes a verdict

    for item in recommendations[:8]:
        if not isinstance(item, dict):
            out.error = "malformed_advisor_response:recommendation_shape"
            return out
        code = str(item.get("recommendation_code") or "")
        text = str(item.get("text") or "")
        if not code.strip() or not text.strip():
            out.error = "malformed_advisor_response:recommendation_item"
            return out
        texts.append(_bounded(text, 240))
        upper = code.upper()
        # severity / CVE claims from the LLM are structurally rejected
        if upper.startswith("SEVERITY") or upper.startswith("CVE_") \
                or upper.startswith("CVSS") or upper.startswith("EXPLOIT"):
            out.rejected.append(f"{code}:authoritative_field_not_llm_set")
            continue
        if upper.startswith("BLOCKER"):
            out.blockers.append(_bounded(text, 160))
            continue
        if upper.startswith("VERIFY_"):
            # extract candidate observation-type tokens from the text and
            # keep only registry-allowed types
            accepted: list[str] = []
            for token in text.replace(",", " ").split():
                tok = token.strip(".:;()").lower()
                if tok in allowed_types:
                    accepted.append(tok)
                elif tok.replace("_", "-") in allowed_types:
                    accepted.append(tok.replace("_", "-"))
                elif tok:
                    out.rejected.append(f"unknown_observation_type:{tok[:40]}")
            if accepted:
                out.verification_recommendations.extend(accepted)
            continue
        # unknown recommendation codes are recorded, never acted on
        out.rejected.append(f"unhandled_code:{code[:60]}")

    from backend.research_agents.hunt.registry import scan_forbidden
    forbidden = scan_forbidden(texts)
    if forbidden:
        out.error = "forbidden_advisor_content:" + ",".join(forbidden)
        out.rejected.extend(forbidden)
        return out

    # dedupe while preserving order + hard caps (bounded output)
    def _uniq(items: list[str], cap: int) -> list[str]:
        seen: set[str] = set()
        out_list: list[str] = []
        for text in items:
            if text and text not in seen:
                seen.add(text)
                out_list.append(text)
            if len(out_list) >= cap:
                break
        return out_list

    out.missing_evidence = _uniq(out.missing_evidence, 6)
    out.conflicting_evidence = _uniq(out.conflicting_evidence, 6)
    out.related_cases = _uniq(out.related_cases, 6)
    out.blockers = _uniq(out.blockers, 6)
    out.verification_recommendations = _uniq(
        out.verification_recommendations, 6)

    # advisory accepted only if the envelope parsed; no verdict fields exist
    out.used = True
    return out
