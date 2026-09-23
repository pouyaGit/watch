"""Autonomous Finding Verification & Triage v1 (bounded candidate layer).

Sits ABOVE the existing systems and never replaces them:

    RESEARCH -> CANDIDATE -> TRIAGE -> CORRELATION/DEDUP ->
    VERIFICATION OBJECTIVE -> HUNT PLANNER (existing) ->
    AUTHORIZATION (existing) -> OBSERVATION RUNTIME (existing) ->
    EVIDENCE (existing) -> VERIFICATION GATE (Evidence Gate primitives) ->
    VERIFIED / REJECTED / INCONCLUSIVE / BLOCKED -> CASE -> HANDOFF

Non-negotiables enforced structurally:
- the LLM is advisory only (finding.gate accepts no advisor input; the
  advisor outcome lives in provenance and is never read by a decision);
- VERIFIED is only reachable through the authoritative gate record
  (store re-checks ``evidence_rules_met`` on both candidate and case);
- scope is mandatory, immutable, and re-checked at every store write;
- severity stays UNASSESSED unless an authoritative KB record backs it;
- openrouter/free only (the advisor builder uses the same free-only
  guard as the analysis path; no paid fallback exists);
- bounded: cumulative budgets (Phase 21), bounded correlation history,
  bounded worker passes, wall-clock limits, honest WAITING states.
"""

from backend.research_agents.finding.models import (
    CASE_STATES,
    CASE_TERMINAL,
    CANDIDATE_STATES,
    CANDIDATE_TERMINAL,
    SEVERITY_PROVENANCE_UNASSESSED,
    SEVERITY_UNASSESSED,
    VERIFICATION_STATES,
    VERIFICATION_TERMINAL,
    CandidateFinding,
    CasePackage,
    FindingScopeError,
    FindingStateError,
    FindingStoreError,
    VerificationObjective,
)
from backend.research_agents.finding.store import FindingStore
from backend.research_agents.finding.extract import extract_candidates
from backend.research_agents.finding.triage import triage_candidate
from backend.research_agents.finding.correlate import (
    correlate_pair,
    correlate_all,
)
from backend.research_agents.finding.dedupe import canonical_of, deduplicate
from backend.research_agents.finding.quality import (
    classify_batch,
    classify_evidence,
    derive_severity,
)
from backend.research_agents.finding.gate import decide, gate_record
from backend.research_agents.finding.limits import (
    DEFAULT_LIMITS,
    BudgetExhausted,
    FindingBudget,
)
from backend.research_agents.finding.executor import (
    FindingRunSummary,
    run_findings,
)
from backend.research_agents.finding.case_package import (
    build_package,
    ensure_case,
    handoff_view,
)

__all__ = [
    "CASE_STATES", "CASE_TERMINAL", "CANDIDATE_STATES",
    "CANDIDATE_TERMINAL", "VERIFICATION_STATES", "VERIFICATION_TERMINAL",
    "SEVERITY_UNASSESSED", "SEVERITY_PROVENANCE_UNASSESSED",
    "CandidateFinding", "CasePackage", "VerificationObjective",
    "FindingScopeError", "FindingStateError", "FindingStoreError",
    "FindingStore", "extract_candidates", "triage_candidate",
    "correlate_pair", "correlate_all", "canonical_of", "deduplicate",
    "classify_evidence", "classify_batch", "derive_severity",
    "decide", "gate_record",
    "DEFAULT_LIMITS", "BudgetExhausted", "FindingBudget",
    "run_findings", "FindingRunSummary",
    "build_package", "ensure_case", "handoff_view",
]
