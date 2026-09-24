"""EPIC12 — verification action/observation persistence.

Append-only JSONL in the same runtime base directory the finding layer uses, with
the same flock + last-wins fold semantics (a record's newest row is its state).
The verification layer adds three files and never rewrites an existing one:

``verification_actions.jsonl``
    Every typed action, with its state transitions (last row wins).
``verification_chain_observations.jsonl``
    Structured observations produced by actions.
``verification_loops.jsonl``
    One bounded loop run per objective: chain state in, termination out.

Nothing here mutates the EPIC11 finding store; the two stores only share a
directory and a locking convention.
"""

from __future__ import annotations

import fcntl
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from backend.research_agents.finding.store import default_base_dir

ACTIONS_FILE = "verification_actions.jsonl"
OBSERVATIONS_FILE = "verification_chain_observations.jsonl"
LOOPS_FILE = "verification_loops.jsonl"
BUDGET_FILE = "verification_budget.jsonl"

STORE_RULE_VERSION = "epic12-verification-store-1"


class VerificationStoreError(ValueError):
    pass


class VerificationActionStore:
    """Append-only persistence for verification actions/observations/loops."""

    def __init__(self, base_dir: str | Path | None = None):
        self.base = Path(base_dir) if base_dir else default_base_dir()
        self.base.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.base / ".verification.lock"

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
                    continue  # a corrupt tail never poisons the chain

    def _append(self, name: str, row: dict[str, Any]) -> None:
        path = self._path(name)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock_path.open("a+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    # -- actions -----------------------------------------------------------

    def record_action(self, action: Any) -> dict[str, Any]:
        """Append the action's current state (last row wins on read)."""
        row = action.to_dict() if hasattr(action, "to_dict") else dict(action)
        row.setdefault("rule_version", STORE_RULE_VERSION)
        if not str(row.get("action_id") or "").strip():
            raise VerificationStoreError("action_id is required")
        with self._locked():
            self._append(ACTIONS_FILE, row)
        return row

    def list_action_rows(self) -> list[dict[str, Any]]:
        """Every action, folded last-wins by ``action_id``."""
        folded: dict[str, dict[str, Any]] = {}
        for row in self._lines(ACTIONS_FILE):
            aid = str(row.get("action_id") or "")
            if aid:
                folded[aid] = row
        return list(folded.values())

    def list_actions(self, *, candidate_id: str = "", objective_id: str = "",
                     state: str = "") -> list[dict[str, Any]]:
        rows = self.list_action_rows()
        if candidate_id:
            rows = [r for r in rows if r.get("candidate_id") == candidate_id]
        if objective_id:
            rows = [r for r in rows if r.get("objective_id") == objective_id]
        if state:
            rows = [r for r in rows if r.get("state") == state]
        return sorted(rows, key=lambda r: (str(r.get("created_at") or ""),
                                           str(r.get("action_id") or "")))

    def get_action(self, action_id: str) -> dict[str, Any] | None:
        for row in reversed(self.list_actions()):
            if row.get("action_id") == action_id:
                return row
        return None

    def actions_for_candidate(self, candidate_id: str) -> list[dict[str, Any]]:
        return self.list_actions(candidate_id=candidate_id)

    # -- observations ------------------------------------------------------

    def record_observation(self, observation: Any) -> dict[str, Any]:
        row = (observation.to_dict() if hasattr(observation, "to_dict")
               else dict(observation))
        row.setdefault("rule_version", STORE_RULE_VERSION)
        if not str(row.get("observation_id") or "").strip():
            raise VerificationStoreError("observation_id is required")
        with self._locked():
            self._append(OBSERVATIONS_FILE, row)
        return row

    def list_observations(self, *, candidate_id: str = "",
                          objective_id: str = "", action_id: str = ""
                          ) -> list[dict[str, Any]]:
        rows = list(self._lines(OBSERVATIONS_FILE))
        if candidate_id:
            rows = [r for r in rows if r.get("candidate_id") == candidate_id]
        if objective_id:
            rows = [r for r in rows if r.get("objective_id") == objective_id]
        if action_id:
            rows = [r for r in rows if r.get("action_id") == action_id]
        return rows

    def observations_for_candidate(self, candidate_id: str
                                   ) -> list[dict[str, Any]]:
        """The candidate's observations, folded to one row per observation id.

        The log is append-only and a re-run may re-derive the same
        deterministic observation; the read path therefore keeps the LAST row
        for each id (the same last-wins fold the finding store uses), so a
        re-run can never look like new evidence.
        """
        folded: dict[str, dict[str, Any]] = {}
        for row in self.list_observations(candidate_id=candidate_id):
            key = str(row.get("observation_id") or row.get("id") or "")
            if key:
                folded[key] = row
        return list(folded.values())

    def evidence_rows_for_candidate(self, candidate_id: str
                                    ) -> list[dict[str, Any]]:
        """Observations projected as EPIC11-consumable evidence rows."""
        out: list[dict[str, Any]] = []
        for row in self.observations_for_candidate(candidate_id):
            out.append({
                "id": row.get("id"),
                "type": row.get("type"),
                "signal": row.get("signal"),
                "category": row.get("category"),
                "confidence": row.get("confidence"),
                "observation_ref": row.get("observation_ref"),
                "observed_at": row.get("observed_at"),
                "detail": row.get("detail"),
                "evidence_type": row.get("evidence_type"),
                "negative": row.get("negative"),
                "not_tested": row.get("not_tested"),
                "what_happened": row.get("what_happened"),
                "where": row.get("where"),
                "under_input": row.get("under_input"),
                "under_request": row.get("under_request"),
                "observed": row.get("observed"),
                "not_observed": row.get("not_observed"),
                "context": row.get("context"),
                "marker": row.get("marker"),
                "request_ref": row.get("request_ref"),
                "response_ref": row.get("response_ref"),
                "action_id": row.get("action_id"),
                "objective_id": row.get("objective_id"),
                "evidence_type": row.get("evidence_type"),
                "job_id": row.get("job_id"),
                "provenance": row.get("provenance"),
            })
        return out

    # -- loops -------------------------------------------------------------

    def record_loop(self, row: dict[str, Any]) -> dict[str, Any]:
        payload = dict(row)
        payload.setdefault("rule_version", STORE_RULE_VERSION)
        if not str(payload.get("objective_id") or "").strip():
            raise VerificationStoreError("loop row requires objective_id")
        with self._locked():
            self._append(LOOPS_FILE, payload)
        return payload

    def list_loops(self, *, candidate_id: str = "") -> list[dict[str, Any]]:
        rows = list(self._lines(LOOPS_FILE))
        if candidate_id:
            rows = [r for r in rows if r.get("candidate_id") == candidate_id]
        return rows

    def latest_loop(self, candidate_id: str) -> dict[str, Any] | None:
        rows = self.list_loops(candidate_id=candidate_id)
        return rows[-1] if rows else None

    # -- budget ledger -----------------------------------------------------

    def record_budget(self, *, resource: str, delta: int, before: int,
                      after: int, reason: str = "",
                      objective_id: str = "") -> dict[str, Any]:
        row = {
            "resource": str(resource),
            "delta": int(delta),
            "before": int(before),
            "after": int(after),
            "reason": str(reason or "")[:200],
            "objective_id": str(objective_id or ""),
            "rule_version": STORE_RULE_VERSION,
        }
        with self._locked():
            self._append(BUDGET_FILE, row)
        return row

    def budget_used(self) -> dict[str, int]:
        used: dict[str, int] = {}
        for row in self._lines(BUDGET_FILE):
            resource = str(row.get("resource") or "")
            if not resource:
                continue
            used[resource] = used.get(resource, 0) + int(row.get("delta") or 0)
        return used

    def budget_ledger(self) -> list[dict[str, Any]]:
        return list(self._lines(BUDGET_FILE))


__all__ = [
    "ACTIONS_FILE", "BUDGET_FILE", "LOOPS_FILE", "OBSERVATIONS_FILE",
    "STORE_RULE_VERSION", "VerificationActionStore", "VerificationStoreError",
]
