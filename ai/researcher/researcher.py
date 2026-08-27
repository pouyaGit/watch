from __future__ import annotations

import json

from ai.llm.openrouter import OpenRouterProvider
from ai.schemas.reference import ReferenceContext
from ai.schemas.research import ResearchResult
from ai.schemas.source import ResearchDocument

def parse_llm_json(raw: str) -> dict:
    """
    Extract the first valid JSON object from an LLM response.

    Handles:
    - ```json ... ```
    - valid JSON followed by extra prose
    - surrounding whitespace
    """

    raw = raw.strip()

    if raw.startswith("```"):
        raw = raw.replace(
            "```json",
            "",
            1,
        )

        raw = raw.replace(
            "```",
            "",
            1,
        ).strip()

    decoder = json.JSONDecoder()

    # Find the first JSON object.
    start = raw.find("{")

    if start == -1:
        raise ValueError(
            f"LLM response does not contain JSON:\n{raw}"
        )

    try:
        data, _ = decoder.raw_decode(
            raw[start:]
        )
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"LLM returned invalid JSON:\n{raw}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            "LLM JSON root must be an object."
        )

    return data

class SecurityResearcher:

    def __init__(self, llm=None):
        self.llm = llm or OpenRouterProvider()

    def research(
        self,
        document: ResearchDocument,
        programs: list[str],
        assets: list[str],
        technologies: list[str],
        reference_contexts: list[ReferenceContext] | None = None,
        discovered_sources: list[dict] | None = None,
    ) -> ResearchResult:

        affected_versions = [
            version.model_dump()
            for version in document.affected_versions
        ]

        references = document.references[:20]

        reference_blocks = []

        for reference in reference_contexts or []:
            reference_blocks.append(
                {
                    "url": reference.source_url,
                    "source_type": reference.source_type,
                    "title": reference.title,
                    "exact_record": reference.exact_record,
                    "context_chunks": reference.context_chunks,
                }
            )

        discovered_sources = discovered_sources or []

        discovered_blocks = []

        for source in discovered_sources:
            discovered_blocks.append(
                {
                    "url": source.get("url"),
                    "source_type": source.get("source_type"),
                    "title": source.get("title"),
                    "priority": source.get("priority"),
                    "tags": source.get("tags", []),
                    "content": source.get("content", ""),
                }
            )
        prompt = f"""
You are an expert cybersecurity vulnerability researcher
working on authorized bug bounty research.

Analyze the CVE using ONLY the supplied evidence.

IMPORTANT RULES:

1. A product/technology match does NOT prove vulnerability.
2. Do not invent versions, patches, exploits, PoCs, or technical details.
3. Clearly distinguish:
   - CONFIRMED
   - UNKNOWN
   - NOT OBSERVED
4. If evidence is insufficient, use null instead of guessing.
5. Do not infer "false" merely because exploit evidence was not supplied.
6. Public exploit status must be null unless the supplied evidence establishes it.
7. Active exploitation status must be null unless the supplied evidence establishes it.
8. Nuclei candidate must be false unless there is a reliable HTTP
   request/response detection pattern supported by the evidence.
9. The observed assets listed below were already correlated by Watch
   with the observed technology. Do not say that the technology-to-asset
   mapping is unknown.
10. Explain why this CVE is or is not worth further authorized
    bug-bounty investigation.

CVE
---

ID:
{document.title}

DESCRIPTION:
{document.content}

VENDORS:
{json.dumps(document.vendor, ensure_ascii=False)}

PRODUCTS:
{json.dumps(document.products, ensure_ascii=False)}

CPES:
{json.dumps(document.cpes, ensure_ascii=False)}

CWES:
{json.dumps(document.cwes, ensure_ascii=False)}

CVSS:
{document.cvss_score}

CVSS VECTOR:
{document.cvss_vector}

AFFECTED VERSIONS:
{json.dumps(affected_versions, ensure_ascii=False)}

WATCH EVIDENCE
--------------

PROGRAMS:
{json.dumps(programs, ensure_ascii=False)}

ASSETS:
{json.dumps(assets, ensure_ascii=False)}

TECHNOLOGIES:
{json.dumps(technologies, ensure_ascii=False)}

REFERENCE MATERIAL
------------------

{json.dumps(reference_blocks, ensure_ascii=False)}

REFERENCE URLS:
{json.dumps(references, ensure_ascii=False)}

IMPORTANT OUTPUT FORMAT RULES:

- evidence MUST be an array of strings.
- affected_versions MUST be an array of strings.
- Do not use objects inside these arrays.
- Do not write any explanation before or after the JSON object.
- The response must end immediately after the closing .
- Treat independently discovered sources as secondary evidence.
- Do not treat a GitHub issue/repository as proof of a public exploit
  unless its contents actually demonstrate exploit code, a PoC,
  a reproducer, or another concrete exploitation artifact.
- Do not infer active exploitation from EPSS or severity alone.
- When sources disagree, prefer the vendor advisory and explicitly
  report the disagreement.

SOURCE TRUST RULES

- Vendor advisories are PRIMARY evidence.
- NVD metadata is PRIMARY evidence for CVE metadata.
- Independent GitHub/security research is SECONDARY evidence.
- Secondary sources may contain analyst speculation, automation output,
  stale data, or errors.
- Treat statements marked with terms equivalent to "estimated",
  "suspected", "inferred", "[추정]", "likely", or "may be" as UNVERIFIED.
- Never promote a speculative secondary-source claim into a confirmed fact
  unless supported by primary evidence.
- Preserve disagreements between sources.

Return ONLY valid JSON matching this schema:

{{
  "title": "string",
  "summary": "string",
  "vulnerability_type": "string or null",
  "severity": "string or null",
  "cve_ids": [],
  "affected_products": [],
  "affected_versions": [],
  "attack_requirements": [],
  "root_cause": "string or null",
  "impact": [],
  "public_exploit": true,
  "actively_exploited": false,
  "bug_bounty_relevance": 0,
  "detection_ideas": [],
  "nuclei_candidate": false,
  "nuclei_reason": "string or null",
  "references": [],
  "evidence": []
}}

DISCOVERED SECURITY RESEARCH
----------------------------

These are independently discovered public sources.
They are useful research material, but their claims
must not automatically be treated as verified facts.

{json.dumps(discovered_blocks, ensure_ascii=False)}

For public_exploit and actively_exploited:
- true only when established by supplied evidence
- false only when the supplied evidence explicitly establishes absence
- otherwise null

bug_bounty_relevance:
0 = no practical relevance
10 = extremely interesting for authorized bug-bounty research

Evidence must explicitly separate confirmed facts from unknowns.
- Every evidence item MUST be a string.
- Prefix each item with exactly one of:
  CONFIRMED:
  UNKNOWN:
  NOT OBSERVED:
  SECONDARY:
  
"""

        raw = self.llm.generate(prompt).strip()

        if raw.startswith("```"):
            raw = raw.replace("```json", "", 1)
            raw = raw.replace("```", "", 1)
            raw = raw.replace("```", "", 1)
            raw = raw.strip()

        data = parse_llm_json(raw)

        return ResearchResult.model_validate(data)