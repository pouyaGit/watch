"""EPIC13 §18 — duplicate and replay control.

Re-probing the same parameter without a reason is exactly the behaviour this
layer must not have.  Every acquisition is identified by a fingerprint over

    candidate · action type · request URL · parameter · scope · marker

which is stable across re-planning (the action id and the marker are
deterministic), so a second planning pass does not produce a second request.

A lookup returns a previous result only when it is still *valid*: the earlier
acquisition produced evidence (``SUCCESS`` or ``NO_REFLECTION``), the
fingerprint matches exactly, and the entry has not aged past the ledger's TTL.
Everything else — a failure, a refusal, a timeout, an inconclusive run — is not
reusable and the caller must ask again, because a failed acquisition is not
evidence and must never be replayed as if it were.

The ledger persists only detection summaries and bounded excerpts.  It never
stores a response body, a header value or a credential.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable

REPLAY_RULE_VERSION = "epic13-replay-1"

#: results whose evidence may be reused (a failure never is).
REUSABLE_RESULTS: frozenset[str] = frozenset({"SUCCESS", "NO_REFLECTION"})

#: how long a reused acquisition stays valid, in seconds (12h — the project's
#: existing recency convention).
DEFAULT_TTL_SECONDS = 12 * 3600

LEDGER_FILE = "acquisition_replay.jsonl"


@dataclass
class ReplayLedger:
    """An optional, append-only fingerprint ledger (in-memory when pathless)."""

    base_dir: str = ""
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    now_fn: Callable[[], float] = time.time
    _memory: list[dict[str, Any]] = field(default_factory=list)

    @property
    def path(self) -> str:
        if not self.base_dir:
            return ""
        return os.path.join(self.base_dir, LEDGER_FILE)

    # ------------------------------------------------------------------ read

    def entries(self) -> list[dict[str, Any]]:
        rows = list(self._memory)
        path = self.path
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    for line in handle:
                        line = line.strip()
                        if line:
                            try:
                                rows.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
            except OSError:
                return rows
        return rows

    def lookup(self, fingerprint: str) -> dict[str, Any] | None:
        """The latest *valid* entry for a fingerprint, or ``None``."""
        wanted = str(fingerprint or "")
        if not wanted:
            return None
        best: dict[str, Any] | None = None
        for row in self.entries():
            if str(row.get("fingerprint") or "") != wanted:
                continue
            if str(row.get("result") or "") not in REUSABLE_RESULTS:
                continue
            if not bool(row.get("reusable", True)):
                continue
            if self._expired(row):
                continue
            best = row
        return best

    def _expired(self, row: dict[str, Any]) -> bool:
        try:
            recorded = float(row.get("recorded_at") or 0)
        except (TypeError, ValueError):
            return True
        if recorded <= 0:
            return True
        return (float(self.now_fn()) - recorded) > float(self.ttl_seconds)

    # ----------------------------------------------------------------- write

    def record(self, *, fingerprint: str, action_id: str, result: str,
               detection: dict[str, Any] | None = None,
               context_class: str = "", response: dict[str, Any] | None = None,
               parameter: str = "", evidence_excerpt: str = "",
               marker: str = "", authorization_id: str = "",
               rule_version: str = ""
               ) -> dict[str, Any]:
        """Append one acquisition outcome (never a body, never a secret).

        ``reusable`` is decided here, at write time: only a conclusive
        positive or negative may ever spare a future request.
        """
        verdict = str(result)
        row = {
            "fingerprint": str(fingerprint),
            "action_id": str(action_id),
            "result": verdict,
            "reusable": verdict in REUSABLE_RESULTS,
            "context_class": str(context_class or ""),
            "parameter": str(parameter or ""),
            "marker": str(marker or ""),
            "authorization_id": str(authorization_id or ""),
            "recorded_at": float(self.now_fn()),
            "detection": dict(detection or {}),
            "response": self._safe_response(response),
            "evidence_excerpt": str(evidence_excerpt or "")[:256],
            "rule_version": str(rule_version or REPLAY_RULE_VERSION),
        }
        path = self.path
        if not path:
            self._memory.append(row)
            return row
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
        except OSError:
            # an unwritable ledger must not lose the evidence: keep it in memory
            self._memory.append(row)
        return row

    @staticmethod
    def _safe_response(response: dict[str, Any] | None) -> dict[str, Any]:
        """Only the auditable response metadata survives into the ledger."""
        if not response:
            return {}
        keep = ("outcome", "status_code", "truncated", "final_url",
                "response_ref", "bytes_received", "transport", "reason")
        return {k: response.get(k) for k in keep if k in response}

    def report(self) -> dict[str, Any]:
        rows = self.entries()
        reusable = [r for r in rows if str(r.get("result") or "")
                    in REUSABLE_RESULTS and not self._expired(r)]
        return {
            "rule_version": REPLAY_RULE_VERSION,
            "entries": len(rows),
            "reusable": len(reusable),
            "ttl_seconds": int(self.ttl_seconds),
            "persisted": bool(self.path),
            "reusable_results": sorted(REUSABLE_RESULTS),
        }


__all__ = [
    "DEFAULT_TTL_SECONDS", "LEDGER_FILE", "REPLAY_RULE_VERSION",
    "REUSABLE_RESULTS", "ReplayLedger",
]
