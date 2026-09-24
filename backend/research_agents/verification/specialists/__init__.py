"""EPIC16 — Multi-Vulnerability Deep Verification v1.

The evidence-first discipline XSS already had (EPIC11–15), applied to the
other classes the platform hunts: CORS, OPEN_REDIRECT, SSRF, IDOR/BOLA and
CVE_RESEARCH.

This package adds exactly three things and duplicates nothing:

* ``base``        — the §13 shared specialist interface + capability matrix
* ``classifiers`` — deterministic, network-free per-class state classifiers
                    (§4–§12): ACAO classes, redirect target classes, the §10
                    destination policy, IDOR identity capability, CVE
                    applicability
* ``producer``    — the §15 trusted producer that turns a class assessment into
                    EPIC11-classified observations
* ``service``     — the §17 shared run: authorization, classification, chain
                    evaluation, and the §18/§24 honest outcome

Authoritative layers are untouched in their roles: EPIC11 owns the taxonomy and
the gate, EPIC12 the chain/engine/actions, EPIC13 acquisition, EPIC14
provenance, EPIC15 deep DOM verification.

Capability boundary (honest, verified in production):

* XSS            — IMPLEMENTED (EPIC13 + EPIC15, unchanged)
* CORS           — LIMITED: deterministic header classification; the running
                    runtime has no live request lane that can set the Origin
                    header, so active acquisition is CAPABILITY_UNAVAILABLE
                    and confirmation (browser-relevant exploitability) is
                    unreachable here
* OPEN_REDIRECT  — LIMITED: deterministic Location classification; the live
                    request that supplies a controlled destination is
                    unavailable here
* SSRF           — LIMITED: destination policy evaluation only. No internal,
                    loopback, metadata, non-http(s) or out-of-scope target is
                    ever probed, and server-side request evidence needs a
                    controlled callback capability this runtime does not have
* IDOR/BOLA      — NOT_IMPLEMENTED: no second authorized identity, no identity
                    switching, no object-ownership semantics → CHECK_OBJECT_ACCESS
                    refuses; only the chain contract exists
* CVE_RESEARCH   — LIMITED (research only): product/version applicability
                    correlation; the contract declares no confirmation claim,
                    so a CVE can never be confirmed here
"""
from __future__ import annotations

from backend.research_agents.verification.specialists.base import (
    CAP_IMPLEMENTED, CAP_LIMITED, CAP_NOT_IMPLEMENTED,
    CLASS_BLOCKED, CLASS_CAPABILITY_UNAVAILABLE, CLASS_CONFIRMED_ELIGIBLE,
    CLASS_INCONCLUSIVE, CLASS_NOT_CONFIRMED, CLASS_NOT_TESTED, CLASS_OUTCOMES,
    CLASS_PENDING, CLASS_RULE_VERSION, CORS, CVE_RESEARCH, IDOR,
    OPEN_REDIRECT, SPECIALISTS, SSRF, XSS, Specialist, capability_matrix,
    registered_classes, specialist_for)
from backend.research_agents.verification.specialists.classifiers import (
    CONTROLLED_DESTINATION_TOKEN, CONTROLLED_ORIGIN_TOKEN, CONTROLLED_SUFFIX,
    RULE_VERSION as CLASSIFIER_RULE_VERSION, CorsAssessment, CveApplicability,
    DestinationPolicy, IdorCapability, RedirectAssessment, SsrfAssessment,
    classify_cors, classify_cve_applicability, classify_idor,
    classify_redirect, classify_ssrf, controlled_destination,
    controlled_origin, evaluate_destination, is_controlled_origin)
from backend.research_agents.verification.specialists.producer import (
    CLASS_PRODUCER_VERSION, ClassObservationProducer, producer_for)
from backend.research_agents.verification.specialists.service import (
    CLASS_VERIFICATION_VERSION, ClassVerificationResult, OUTCOME_BLOCKED,
    OUTCOME_CAPABILITY_UNAVAILABLE, OUTCOME_CONFIRMED, OUTCOME_INCONCLUSIVE,
    OUTCOME_NOT_CONFIRMED, OUTCOME_NOT_IMPLEMENTED, OUTCOME_NOT_TESTED,
    OUTCOME_PENDING, OUTCOME_UNKNOWN_CLASS, project_class_verification,
    verify_class)

SPECIALISTS_VERSION = "epic16-multi-class-verification-1"

__all__ = [
    "CAP_IMPLEMENTED", "CAP_LIMITED", "CAP_NOT_IMPLEMENTED", "CLASS_BLOCKED",
    "CLASS_CAPABILITY_UNAVAILABLE", "CLASS_CONFIRMED_ELIGIBLE",
    "CLASS_INCONCLUSIVE", "CLASS_NOT_CONFIRMED", "CLASS_NOT_TESTED",
    "CLASS_OUTCOMES", "CLASS_PENDING", "CLASS_RULE_VERSION",
    "CLASS_PRODUCER_VERSION", "CLASS_VERIFICATION_VERSION",
    "CLASSIFIER_RULE_VERSION", "CONTROLLED_DESTINATION_TOKEN",
    "CONTROLLED_ORIGIN_TOKEN", "CONTROLLED_SUFFIX", "CORS", "CVE_RESEARCH",
    "ClassObservationProducer", "ClassVerificationResult", "CorsAssessment",
    "CveApplicability", "DestinationPolicy", "IDOR", "IdorCapability",
    "OPEN_REDIRECT", "OUTCOME_BLOCKED", "OUTCOME_CAPABILITY_UNAVAILABLE",
    "OUTCOME_CONFIRMED", "OUTCOME_INCONCLUSIVE", "OUTCOME_NOT_CONFIRMED",
    "OUTCOME_NOT_IMPLEMENTED", "OUTCOME_NOT_TESTED", "OUTCOME_PENDING",
    "OUTCOME_UNKNOWN_CLASS", "RedirectAssessment", "SPECIALISTS",
    "SPECIALISTS_VERSION", "SSRF", "Specialist", "SsrfAssessment", "XSS",
    "capability_matrix", "classify_cors", "classify_cve_applicability",
    "classify_idor", "classify_redirect", "classify_ssrf",
    "controlled_destination", "controlled_origin", "evaluate_destination",
    "is_controlled_origin", "producer_for", "project_class_verification",
    "registered_classes", "specialist_for", "verify_class",
]
