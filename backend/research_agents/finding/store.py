"""FindingStore — append-only JSONL persistence with flock.

Mirrors the CampaignStore pattern (never rebuilt differently): candidates,
verification objectives, correlations, case packages, transition rows and
the cumulative budget ledger are append-only JSONL under the shared
runtime base dir; the last row per id wins on read.

Invariants enforced here (Phase 1/12):
- scope is validated at model construction and re-checked on save
  (candidate scope must never change — rule 15).
- ``VERIFIED`` candidate transitions require a real gate decision
  (``gate_result`` must be ``evidence_rules_met``) — the store is the
  second gate after finding.gate, so no code path can fabricate VERIFIED.
- case packages may only be created for verification-bound candidates and
  may only reach VERIFIED when their candidate is gate-VERIFIED.
- every transition appends a transition row (Phase 16 lineage).
"""

from __future__ import annotations

import fcntl
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from backend.research_agents.finding.models import (
    CASE_TERMINAL,
    CANDIDATE_TERMINAL,
    VERIFICATION_TERMINAL,
    CandidateFinding,
    CasePackage,
    FindingStateError,
    FindingStoreError,
    VerificationObjective,
    utcnow,
    validate_case_transition,
    validate_scope_ref,
)

_FILE_CANDIDATES = "finding_candidates.jsonl"
_FILE_VERIFICATIONS = "finding_verifications.jsonl"
_FILE_CORRELATIONS = "finding_links.jsonl"
_FILE_CASES = "finding_cases.jsonl"
_FILE_TRANSITIONS = "finding_transitions.jsonl"
_FILE_BUDGET = "finding_budget.jsonl"

#: Candidate states a case package may be created for (verification-bound
#: only — ordinary candidates never become cases, Phase 12).
CASE_CREATABLE_FROM: frozenset[str] = frozenset(
    {"TRIAGED", "NEEDS_EVIDENCE", "VERIFICATION_PLANNED",
     "VERIFICATION_PENDING", "VERIFYING"})


def default_base_dir() -> Path:
    from backend.research_agents.runtime_store import runtime_base_dir
    return runtime_base_dir()


class FindingStore:
    """Append-only persistence for the finding verification layer."""

    def __init__(self, base_dir: str | Path | None = None):
        self.base = Path(base_dir) if base_dir else default_base_dir()
        self.base.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.base / ".finding.lock"

    # -- primitives --------------------------------------------------------

    def _path(self, name: str) -> Path:
        return self.base / name

    def _lines(self, name: str) -> Iterator[dict[str, Any]]:
        path = self._path(name)
        if not path.exists():
            return
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue  # corrupt tail never poisons the chain

    def _append(self, name: str, row: dict[str, Any]) -> None:
        path = self._path(name)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    @staticmethod
    def _assert_severity_provenance(row: dict[str, Any]) -> None:
        """Severity outside UNASSESSED must carry the authoritative
        knowledge-base provenance (rules 21-23: no fabricated severity)."""
        severity = str(row.get("severity") or "")
        provenance = str(row.get("severity_provenance") or "")
        from backend.research_agents.finding.models import (
            SEVERITY_UNASSESSED,
        )
        if severity and severity != SEVERITY_UNASSESSED and not \
                provenance.startswith("knowledge_base_cvss:"):
            raise FindingStoreError(
                "severity requires authoritative knowledge_base_cvss "
                f"provenance (got {severity!r}/{provenance!r})")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock_path.open("a+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    # -- candidates --------------------------------------------------------

    def get_candidate(self, candidate_id: str) -> CandidateFinding | None:
        found: CandidateFinding | None = None
        for row in self._lines(_FILE_CANDIDATES):
            if row.get("candidate_id") == candidate_id:
                found = CandidateFinding.from_dict(row)
        return found

    def list_candidates(self, *, state: str | None = None) -> list[CandidateFinding]:
        out: dict[str, CandidateFinding] = {}
        for row in self._lines(_FILE_CANDIDATES):
            cand = CandidateFinding.from_dict(row)
            out[cand.candidate_id] = cand
        items = list(out.values())
        if state:
            items = [c for c in items if c.lifecycle_state == state]
        return sorted(items, key=lambda c: c.created_at)

    def add_candidate(self, candidate: CandidateFinding) -> CandidateFinding:
        with self._locked():
            if self.get_candidate(candidate.candidate_id) is not None:
                raise FindingStoreError(
                    f"duplicate candidate: {candidate.candidate_id}")
            validate_scope_ref(candidate.scope_ref)
            self._assert_severity_provenance(candidate.to_dict())
            self._append(_FILE_CANDIDATES, candidate.to_dict())
            self._append(_FILE_TRANSITIONS, {
                "kind": "candidate", "id": candidate.candidate_id,
                "old": "", "new": candidate.lifecycle_state,
                "reason": "candidate_detected",
                "detail": f"source_job={candidate.source_job}",
                "at": candidate.created_at,
            })
        return candidate

    def save_candidate(self, candidate: CandidateFinding) -> CandidateFinding:
        """Persist a modified candidate; scope may never change (rule 15)."""
        with self._locked():
            current = self.get_candidate(candidate.candidate_id)
            if current is None:
                raise FindingStoreError(
                    f"unknown candidate: {candidate.candidate_id}")
            if candidate.scope_ref != current.scope_ref:
                raise FindingStoreError(
                    "candidate scope may never change "
                    f"({current.scope_ref} -> {candidate.scope_ref})")
            validate_scope_ref(candidate.scope_ref)
            self._assert_severity_provenance(candidate.to_dict())
            self._append(_FILE_CANDIDATES, candidate.to_dict())
        return candidate

    def transition_candidate(self, candidate_id: str, new_state: str, *,
                             reason: str = "", detail: str = "",
                             gate_result: str = "") -> CandidateFinding:
        """Audited candidate state transition.

        ``VERIFIED`` additionally requires a real gate result
        (``evidence_rules_met``) — no other caller can produce it.
        """
        with self._locked():
            candidate = self.get_candidate(candidate_id)
            if candidate is None:
                raise FindingStoreError(f"unknown candidate: {candidate_id}")
            old = candidate.lifecycle_state
            if new_state == "VERIFIED" and gate_result != "evidence_rules_met":
                raise FindingStateError(
                    "VERIFIED requires authoritative gate result "
                    "evidence_rules_met")
            candidate.transition(new_state, reason=reason, detail=detail)
            self._append(_FILE_CANDIDATES, candidate.to_dict())
            self._append(_FILE_TRANSITIONS, {
                "kind": "candidate", "id": candidate_id,
                "campaign_id": candidate.source_campaign,
                "objective_id": candidate.source_objective,
                "job_id": candidate.source_job,
                "old": old, "new": new_state,
                "reason": reason or new_state.lower(),
                "detail": str(detail or "")[:400],
                "gate_result": str(gate_result or ""),
                "at": candidate.updated_at,
            })
        return candidate

    # -- verification objectives ------------------------------------------

    def get_verification(self, verification_id: str) -> VerificationObjective | None:
        found: VerificationObjective | None = None
        for row in self._lines(_FILE_VERIFICATIONS):
            if row.get("verification_id") == verification_id:
                found = VerificationObjective.from_dict(row)
        return found

    def list_verifications(self, *,
                           candidate_id: str | None = None,
                           state: str | None = None,
                           ) -> list[VerificationObjective]:
        out: dict[str, VerificationObjective] = {}
        for row in self._lines(_FILE_VERIFICATIONS):
            ver = VerificationObjective.from_dict(row)
            out[ver.verification_id] = ver
        items = list(out.values())
        if candidate_id:
            items = [v for v in items if v.candidate_id == candidate_id]
        if state:
            items = [v for v in items if v.state == state]
        return sorted(items, key=lambda v: v.created_at)

    def add_verification(self, ver: VerificationObjective) -> VerificationObjective:
        with self._locked():
            if self.get_verification(ver.verification_id) is not None:
                raise FindingStoreError(
                    f"duplicate verification: {ver.verification_id}")
            validate_scope_ref(ver.scope_ref)
            candidate = self.get_candidate(ver.candidate_id)
            if candidate is None:
                raise FindingStoreError(
                    f"unknown candidate: {ver.candidate_id}")
            if candidate.is_terminal:
                raise FindingStoreError(
                    f"candidate {ver.candidate_id} is terminal "
                    f"({candidate.lifecycle_state}); no new verification")
            if candidate.lifecycle_state == "DUPLICATE":
                raise FindingStoreError(
                    f"duplicate candidate {ver.candidate_id} may never be "
                    "verified (canonical only) — rule 24/Phase 5")
            if ver.scope_ref != candidate.scope_ref:
                raise FindingStoreError(
                    "verification scope must equal candidate scope")
            if ver.vulnerability_class != candidate.vulnerability_class:
                raise FindingStoreError(
                    "verification class must equal candidate class")
            self._append(_FILE_VERIFICATIONS, ver.to_dict())
            self._append(_FILE_TRANSITIONS, {
                "kind": "verification", "id": ver.verification_id,
                "candidate_id": ver.candidate_id,
                "old": "", "new": ver.state,
                "reason": "verification_created", "detail": "",
                "at": ver.created_at,
            })
        return ver

    def save_verification(self, ver: VerificationObjective) -> VerificationObjective:
        with self._locked():
            current = self.get_verification(ver.verification_id)
            if current is None:
                raise FindingStoreError(
                    f"unknown verification: {ver.verification_id}")
            if ver.scope_ref != current.scope_ref:
                raise FindingStoreError(
                    "verification scope may never change")
            self._append(_FILE_VERIFICATIONS, ver.to_dict())
        return ver

    def transition_verification(self, verification_id: str, new_state: str, *,
                                reason: str = "", detail: str = "",
                                ) -> VerificationObjective:
        with self._locked():
            ver = self.get_verification(verification_id)
            if ver is None:
                raise FindingStoreError(
                    f"unknown verification: {verification_id}")
            old = ver.state
            if new_state == "VERIFIED" and ver.gate_reason != "evidence_rules_met":
                raise FindingStateError(
                    "verification VERIFIED requires gate reason "
                    "evidence_rules_met")
            ver.transition(new_state, reason=reason, detail=detail)
            self._append(_FILE_VERIFICATIONS, ver.to_dict())
            self._append(_FILE_TRANSITIONS, {
                "kind": "verification", "id": verification_id,
                "candidate_id": ver.candidate_id,
                "old": old, "new": new_state,
                "reason": reason or new_state.lower(),
                "detail": str(detail or "")[:400],
                "at": ver.updated_at,
            })
        return ver

    # -- correlations (append-only evidence of dedupe work) ----------------

    def record_correlation(self, row: dict[str, Any]) -> dict[str, Any]:
        with self._locked():
            payload = {
                "at": utcnow(),
                "relation": "",       # SAME_CANDIDATE|RELATED|POSSIBLE_DUPLICATE|INDEPENDENT
                "reasons": [],
                "provenance": {},
                **row,
            }
            payload["at"] = payload.get("at") or utcnow()
            self._append(_FILE_CORRELATIONS, payload)
            self._append(_FILE_TRANSITIONS, {
                "kind": "correlation",
                "id": str(payload.get("canonical_id")
                          or payload.get("left_id") or ""),
                "old": str(payload.get("left_id") or ""),
                "new": str(payload.get("right_id") or ""),
                "reason": str(payload.get("relation") or "correlated"),
                "detail": ",".join(
                    str(x) for x in (payload.get("reasons") or [])[:8]),
                "at": payload["at"],
            })
        return payload

    def list_correlations(self, *,
                          candidate_id: str | None = None) -> list[dict[str, Any]]:
        rows = list(self._lines(_FILE_CORRELATIONS))
        if candidate_id:
            rows = [r for r in rows
                    if candidate_id in (str(r.get("left_id") or ""),
                                        str(r.get("right_id") or ""),
                                        str(r.get("canonical_id") or ""))]
        return rows

    # -- case packages -----------------------------------------------------

    def get_case(self, case_id: str) -> CasePackage | None:
        found: CasePackage | None = None
        for row in self._lines(_FILE_CASES):
            if row.get("case_id") == case_id:
                found = CasePackage.from_dict(row)
        return found

    def cases_for_candidate(self, candidate_id: str) -> CasePackage | None:
        found: CasePackage | None = None
        for row in self._lines(_FILE_CASES):
            if row.get("candidate_id") == candidate_id:
                found = CasePackage.from_dict(row)
        return found

    def list_cases(self) -> list[CasePackage]:
        out: dict[str, CasePackage] = {}
        for row in self._lines(_FILE_CASES):
            case = CasePackage.from_dict(row)
            out[case.case_id] = case
        return sorted(out.values(), key=lambda c: c.created_at)

    def add_case(self, case: CasePackage) -> CasePackage:
        """Create a case package — only for verification-bound candidates."""
        with self._locked():
            if self.get_case(case.case_id) is not None:
                raise FindingStoreError(f"duplicate case: {case.case_id}")
            validate_scope_ref(case.scope_ref)
            self._assert_severity_provenance(case.to_dict())
            candidate = self.get_candidate(case.candidate_id)
            if candidate is None:
                raise FindingStoreError(
                    f"unknown candidate: {case.candidate_id}")
            if candidate.lifecycle_state not in CASE_CREATABLE_FROM:
                raise FindingStoreError(
                    f"case may only be created for verification-bound "
                    f"candidates (state {candidate.lifecycle_state})")
            if case.scope_ref != candidate.scope_ref:
                raise FindingStoreError("case scope must equal candidate scope")
            if self.cases_for_candidate(case.candidate_id) is not None:
                raise FindingStoreError(
                    f"candidate {case.candidate_id} already has a case")
            self._append(_FILE_CASES, case.to_dict())
            self._append(_FILE_TRANSITIONS, {
                "kind": "case", "id": case.case_id,
                "candidate_id": case.candidate_id,
                "old": "", "new": case.state,
                "reason": "case_created", "detail": case.title[:200],
                "at": case.created_at,
            })
            # link back onto the candidate
            candidate.case_id = case.case_id
            candidate.updated_at = utcnow()
            self._append(_FILE_CANDIDATES, candidate.to_dict())
        return case

    def transition_case(self, case_id: str, new_state: str, *,
                        reason: str = "", gate_result: str = "",
                        ) -> CasePackage:
        with self._locked():
            case = self.get_case(case_id)
            if case is None:
                raise FindingStoreError(f"unknown case: {case_id}")
            old = case.state
            if new_state == "VERIFIED":
                # second gate: candidate must be gate-VERIFIED first
                candidate = self.get_candidate(case.candidate_id)
                if candidate is None or candidate.lifecycle_state != "VERIFIED":
                    raise FindingStateError(
                        "case VERIFIED requires a gate-VERIFIED candidate")
                if gate_result != "evidence_rules_met":
                    raise FindingStateError(
                        "case VERIFIED requires gate result evidence_rules_met")
            validate_case_transition(old, new_state)
            case.transition(new_state, reason=reason)
            if new_state == "VERIFIED":
                case.gate_result = "evidence_rules_met"
            self._append(_FILE_CASES, case.to_dict())
            self._append(_FILE_TRANSITIONS, {
                "kind": "case", "id": case_id,
                "candidate_id": case.candidate_id,
                "old": old, "new": new_state,
                "reason": reason or new_state.lower(),
                "detail": str(gate_result or "")[:200],
                "at": case.updated_at,
            })
        return case

    def save_case(self, case: CasePackage) -> CasePackage:
        with self._locked():
            current = self.get_case(case.case_id)
            if current is None:
                raise FindingStoreError(f"unknown case: {case.case_id}")
            if case.scope_ref != current.scope_ref:
                raise FindingStoreError("case scope may never change")
            self._assert_severity_provenance(case.to_dict())
            self._append(_FILE_CASES, case.to_dict())
        return case

    # -- budget ledger (cumulative, Phase 21) ------------------------------

    def record_budget(self, *, resource: str, delta: int, before: int,
                      after: int, reason: str,
                      verification_id: str = "") -> None:
        with self._locked():
            self._append(_FILE_BUDGET, {
                "resource": str(resource),
                "delta": int(delta), "before": int(before),
                "after": int(after), "reason": str(reason)[:200],
                "verification_id": str(verification_id),
                "at": utcnow(),
            })

    def budget_used(self) -> dict[str, int]:
        used: dict[str, int] = {}
        for row in self._lines(_FILE_BUDGET):
            res = str(row.get("resource") or "")
            used[res] = int(used.get(res, 0)) + int(row.get("delta") or 0)
        return used

    def budget_ledger(self) -> list[dict[str, Any]]:
        return list(self._lines(_FILE_BUDGET))

    # -- lineage query (SOC + tests) ---------------------------------------

    def lineage_for(self, candidate_id: str) -> list[dict[str, Any]]:
        return [r for r in self._lines(_FILE_TRANSITIONS)
                if str(r.get("candidate_id") or "") == candidate_id
                or str(r.get("id") or "") == candidate_id]

    def all_transitions(self) -> list[dict[str, Any]]:
        return list(self._lines(_FILE_TRANSITIONS))
