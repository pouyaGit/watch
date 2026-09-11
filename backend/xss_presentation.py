"""
backend/xss_presentation.py — Deterministic XSS presentation semantics (Stage D9).

Presentation-only layer. It NEVER changes matching, scoring, persistence,
verification, or finding semantics. It classifies an already-persisted XSS
research artifact into exactly one of:

- ``KNOWLEDGE_PATTERN`` — a generic, reusable XSS knowledge pattern with no
  explicit target/program/asset association. It was never live tested and
  must never be presented as a finding on any monitored program.
- ``TARGET_RESEARCH_CANDIDATE`` — a candidate that carries an EXPLICIT
  target-specific association (a non-empty ``program``/``target``/``asset``
  style field literally present in the persisted artifact). Still NOT
  verified, NOT a finding.

Classification rules (deliberately conservative):

- Only a non-empty value under an explicit target key counts as target
  association. CVE ids, KB ids, KB titles, evidence reasons, sinks/sources,
  query text, vulnerability patterns, preconditions, and test ideas NEVER
  count — they describe reusable knowledge, not a monitored target.
- No program/target/asset value is ever fabricated. When no explicit
  association exists the target renders as ``"No target associated"``.
- No network, no LLM, no Nuclei, no active validation, no verifier calls.
"""

from __future__ import annotations

from typing import Any

KNOWLEDGE_PATTERN = "KNOWLEDGE_PATTERN"
TARGET_RESEARCH_CANDIDATE = "TARGET_RESEARCH_CANDIDATE"

LABEL_KNOWLEDGE_PATTERN = "KNOWLEDGE PATTERN — NOT TARGET VALIDATED"
LABEL_TARGET_RESEARCH_CANDIDATE = "TARGET RESEARCH CANDIDATE — NOT VERIFIED"

SCOPE_KNOWLEDGE_PATTERN = "Generic XSS knowledge pattern"
SCOPE_TARGET_RESEARCH_CANDIDATE = "Target-specific research candidate"

TARGET_NONE = "No target associated"

VALIDATION_NOT_TESTED = "NOT_TESTED"
VALIDATION_NOT_VERIFIED = "NOT_VERIFIED"

SCOPE_WARNING = (
    "This record describes reusable security knowledge. "
    "It does NOT indicate an XSS finding on any monitored program."
)

# Only these top-level persisted keys, when present with a non-empty value,
# prove target-specific relevance. Everything else (CVE ids, KB ids,
# evidence, sinks/sources, query text, patterns) is generic knowledge.
EXPLICIT_TARGET_KEYS: tuple[str, ...] = (
    "program",
    "program_id",
    "target",
    "target_id",
    "asset",
    "asset_id",
    "target_program",
    "target_asset",
    "monitored_program",
)


def _first_text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def explicit_target(payload: dict) -> str | None:
    """Return the explicit program/asset association, or None.

    Only a non-empty string under one of EXPLICIT_TARGET_KEYS counts.
    Lists are NOT inspected (no fabrication from evidence lists).
    """
    if not isinstance(payload, dict):
        return None
    for key in EXPLICIT_TARGET_KEYS:
        text = _first_text(payload.get(key))
        if text:
            return text[:240]
    return None


def classify_xss_presentation(payload: dict) -> dict:
    """Deterministically classify a persisted XSS candidate for presentation.

    Never raises on malformed input: unknown shapes are KNOWLEDGE_PATTERN
    (no target is ever inferred).
    """
    target = explicit_target(payload) if isinstance(payload, dict) else None
    if target:
        return {
            "presentation_type": TARGET_RESEARCH_CANDIDATE,
            "label": LABEL_TARGET_RESEARCH_CANDIDATE,
            "scope": SCOPE_TARGET_RESEARCH_CANDIDATE,
            "target": target,
            "target_association": True,
            "validation_state": VALIDATION_NOT_VERIFIED,
        }
    return {
        "presentation_type": KNOWLEDGE_PATTERN,
        "label": LABEL_KNOWLEDGE_PATTERN,
        "scope": SCOPE_KNOWLEDGE_PATTERN,
        "target": TARGET_NONE,
        "target_association": False,
        "validation_state": VALIDATION_NOT_TESTED,
    }


def presentation_counts(payloads: list[dict]) -> dict:
    """Count presentation types across candidate payloads (deterministic)."""
    counts = {KNOWLEDGE_PATTERN: 0, TARGET_RESEARCH_CANDIDATE: 0}
    for payload in payloads or []:
        classified = classify_xss_presentation(
            payload if isinstance(payload, dict) else {}
        )
        counts[classified["presentation_type"]] += 1
    return counts
