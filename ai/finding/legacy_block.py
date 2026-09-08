"""Legacy hard-block inventory for 5J (Phase 5J, documentation + checks).

NONE of the paths below may produce an authoritative 5J finding, reach
5J persistence, or reach the 5J notification seam. 5J input types are
unreachable from all of them: there is no shared constructor, no
adapter, and no import edge from ``ai.finding`` to any legacy finding
producer (test-enforced by AST/import-surface scans in
``ai/test_finding_pipeline.py``).

HARD-BLOCKED (must never become 5J findings):

- ``ai.verification.verifier.XSSVerifier.verify`` / ``_build_finding``
  (execute-and-judge; emits POTENTIAL findings; advisory-derived
  ``browser_verified``; raw ``payload_reference``)
- Direct ``XSSFinding(...)`` construction outside the 5I-authorized
  materializer (no version pins, free confidence/severity-adjacent
  fields, raw evidence strings)
- Direct ``NucleiFinding(...)`` construction (caller severity,
  ``matched`` bool, verbatim ``raw_output`` secret container)
- ``ai.researcher.nuclei_runner.NucleiRunner.to_findings``
  (stdout-nonempty ⇒ matched + caller severity)
- ``ai.researcher.nuclei_pipeline`` ``to_findings`` call +
  ``save_findings`` persistence (``ai_data/nuclei/findings/*.json``)
- ``watch_xss_verify.mongo_persist`` / ``mongo_already_verified`` loops
  AS PRODUCTION PATHS (the NotUniqueError-dedup PATTERN is reused; the
  World A CONTENT is blocked)
- Any API/dashboard/alert ingestion of ``XssFindings`` rows or
  ``ai_data/nuclei`` files as findings
- Arbitrary severity / confidence passthrough from Nuclei / LLM /
  researcher / caller / database / dashboard into stored findings

DEPRECATED (non-authoritative, no path to 5J): ``NucleiFinding`` +
``raw_output`` persistence; ``XSSFinding`` legacy fields
(``browser_verified``, free ``confidence``, ``payload_reference``,
raw evidence strings); ``XSSVerificationResult.findings`` as a
consumable list; ``ai_data/nuclei/findings/*.json`` as a readable
finding source.

KEPT (unchanged, outside authority): ``ai/verification/oracle.py``
pure predicates; ``xss_pipeline.py`` pass-through shape; recon
dashboards/APIs; Telegram transport; ``database/change_events.py``.
"""

from __future__ import annotations

import ast

__all__ = [
    "HARD_BLOCKED_PATHS",
    "BANNED_TOKENS",
    "BANNED_IMPORTS",
    "source_references_banned",
]

#: Dotted legacy paths that must never feed 5J (documentation +
#: test parametrization surface).
HARD_BLOCKED_PATHS: tuple[str, ...] = (
    "ai.verification.verifier.XSSVerifier.verify",
    "ai.verification.verifier.XSSVerifier._build_finding",
    "ai.schemas.xss_finding.XSSFinding",
    "ai.schemas.finding.NucleiFinding",
    "ai.researcher.nuclei_runner.NucleiRunner.to_findings",
    "ai.researcher.nuclei_pipeline.NucleiPipeline",
    "ai.researcher.nuclei_pipeline.save_findings",
    "watch_xss_verify.mongo_persist",
    "watch_xss_verify.mongo_already_verified",
    "database.db.XssFindings",
    "ai_data.nuclei.findings",
)

#: Code-level tokens that must not appear in ``ai.finding`` sources
#: (checked on AST names/attributes/imports, so prose mentions in
#: docstrings and comments do not trip the guard).
BANNED_TOKENS: tuple[str, ...] = (
    "XSSVerifier",
    "to_findings",
    "save_findings",
    "XSSFinding",
    "NucleiFinding",
    "nuclei_runner",
    "mongo_persist",
    "XssFindings",
)

#: Legacy modules that ``ai.finding`` must never import.
BANNED_IMPORTS: tuple[str, ...] = (
    "ai.verification.verifier",
    "ai.researcher.nuclei_runner",
    "ai.researcher.nuclei_pipeline",
    "ai.schemas.xss_finding",
    "ai.schemas.finding",
    "watch_xss_verify",
    "database.db",
)


def source_references_banned(source: str) -> tuple[str, ...]:
    """AST names/attributes/imports referencing banned legacy surface.

    Docstrings and comments are ignored by construction (only code
    nodes are visited). Returns the sorted offending tokens.
    """
    tree = ast.parse(source)
    hits: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for banned in BANNED_IMPORTS:
                if module == banned or module.startswith(banned + "."):
                    hits.add(banned)
            for alias in node.names:
                if alias.name in BANNED_TOKENS:
                    hits.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                for banned in BANNED_IMPORTS:
                    if alias.name == banned or alias.name.startswith(
                        banned + "."
                    ):
                        hits.add(banned)
                if alias.name in BANNED_TOKENS:
                    hits.add(alias.name)
        elif isinstance(node, ast.Name):
            if node.id in BANNED_TOKENS:
                hits.add(node.id)
        elif isinstance(node, ast.Attribute):
            if node.attr in BANNED_TOKENS:
                hits.add(node.attr)
    return tuple(sorted(hits))
