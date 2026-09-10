"""Bounded research prompt for the R23 autonomous research agent.

The model receives only the R22 plan context plus supplied research
documents. It must return structured JSON that separates evidence (grounded
in a supplied source) from inference and unknowns.

Hard rules restated in the prompt:

- research only; never claim the target/program is vulnerable
- never invent evidence; every evidence item must reference a supplied source
- never send or request a content hash (the agent computes it)
- never perform or suggest active validation against the program
"""

from __future__ import annotations

import json
from typing import Any

from ai.collectors.body_extraction import normalize_text
from ai.schemas.research_agent import MAX_DOC_CHARS

PROMPT_RULE_VERSION = "r23-1"
MAX_PROMPT_CHARS = 60_000
MAX_PROMPT_DOCS = 8
MAX_PROMPT_DOC_CHARS = 4_000
MAX_OUTPUT_TOKENS = 4_096

_SYSTEM_RULES = """You are a security RESEARCH analyst for an authorized bug-bounty program.

This is RESEARCH-ONLY.
Do NOT claim the target or program is vulnerable.
Do NOT invent evidence, versions, exploits, PoCs, or patches.
Do NOT perform or suggest active validation against the program.
Do NOT request, scan, or fetch any program/target URL.
Separate EVIDENCE from INFERENCE and UNKNOWN.

EVIDENCE rules:
- Every evidence item MUST reference a source_url from the SUPPLIED DOCUMENTS.
- Only state what the supplied source actually says; include a short quote.
- If a claim is not grounded in a supplied source, put it under inferences
  or unknowns instead.
- Do NOT output a content_hash; the system computes it. Any content_hash you
  produce is ignored.

Return ONLY a single JSON object, no prose before or after, matching:

{
  "evidence": [
    {"claim": "string", "source_url": "string", "quote": "string",
     "confidence": "HIGH|MEDIUM|LOW"}
  ],
  "inferences": [
    {"statement": "string", "basis": "string", "confidence": "HIGH|MEDIUM|LOW"}
  ],
  "unknowns": ["string"],
  "affected_versions": ["string"],
  "affected_components": ["string"],
  "affected_parameters": ["string"],
  "exploitability_summary": "string",
  "nuclei_candidates": [
    {"product": "string", "template_source": "string",
     "request_shape": "string", "matcher_logic": "string"}
  ],
  "recommended_next_step": "string"
}
"""


def _clip(value: Any, limit: int) -> str:
    text = normalize_text(str(value or ""))
    return text[:limit]


def build_research_prompt(
    context: dict,
    sources: list[dict] | None = None,
    *,
    max_chars: int = MAX_PROMPT_CHARS,
    max_docs: int = MAX_PROMPT_DOCS,
    max_doc_chars: int = MAX_PROMPT_DOC_CHARS,
) -> str:
    """Render a size-bounded research prompt.

    ``sources`` items are dicts with at least ``url``, ``source_type``,
    ``title``, ``content`` and ``content_hash``. Only sources WITH a content
    hash are supplied as documents (URL-only references are listed
    separately and cannot back evidence).
    """
    documents: list[dict] = []
    url_only: list[dict] = []
    for source in sources or []:
        if not isinstance(source, dict):
            continue
        item = {
            "url": str(source.get("url") or ""),
            "source_type": str(source.get("source_type") or "other"),
            "title": source.get("title"),
        }
        content = source.get("content")
        if content and source.get("content_hash"):
            item["content"] = _clip(content, max_doc_chars)
            item["content_hash_supplied"] = True
            documents.append(item)
        else:
            url_only.append(item)
        if len(documents) >= max_docs:
            break

    cve_block = {
        "cve": context.get("cve_id") or context.get("cve"),
        "vulnerability_type": context.get("vulnerability_type"),
        "severity": context.get("severity"),
        "exploitability": context.get("exploitability") or {},
        "priority": context.get("priority") or {},
        "relevance": context.get("relevance") or {},
    }
    plan_block = {
        "plan_id": (context.get("plan") or {}).get("plan_id"),
        "recommended_start": (context.get("plan") or {}).get("recommended_start"),
        "steps": [
            s.get("code")
            for s in ((context.get("plan") or {}).get("steps") or [])
            if isinstance(s, dict)
        ],
        "unknowns": (context.get("plan") or {}).get("unknowns") or [],
    }
    lead_block = {
        "priority_level": (context.get("lead") or {}).get("priority_level"),
        "relevance_level": (context.get("lead") or {}).get("relevance_level"),
        "recommended_next_step": (context.get("lead") or {}).get(
            "recommended_next_step"
        ),
        "blockers": (context.get("lead") or {}).get("blockers") or [],
    }

    prompt = (
        _SYSTEM_RULES
        + "\n\nCVE / PROJECTION CONTEXT\n"
        + json.dumps(cve_block, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n\nRESEARCH PLAN\n"
        + json.dumps(plan_block, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n\nRESEARCH LEAD\n"
        + json.dumps(lead_block, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n\nSUPPLIED DOCUMENTS (ground evidence here)\n"
        + json.dumps(documents, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n\nKNOWN REFERENCE URLS WITHOUT A LOCAL BODY\n"
        + json.dumps(url_only, ensure_ascii=False, indent=2, sort_keys=True)
    )
    return prompt[:max_chars]
