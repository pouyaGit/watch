"""backend/research_agents/runtime_store.py — Phase 2 persistent work queue.

File-backed job/result/evidence/case/knowledge/activity store with a real
inter-process lock (``fcntl.flock``), so a worker process, the API process
and the SOC read the SAME queue and claims are atomic across processes.

Consistency model: every mutation runs under the exclusive lock and
persists via write-temp + ``os.replace`` (atomic on POSIX), so a reader
either sees the previous state or the new one — never a torn file.  The
audit log is an append-only JSONL written under the same lock.

Nothing here executes work, contacts targets, or fabricates state: it is
storage, transitions and audit only.  Every transition is validated
against ``JOB_STATUS_FLOW`` from :mod:`backend.research_agents.models`.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from backend.research_agents.models import (
    ACTIVE_JOB_STATUSES,
    JOB_STATUS_FLOW,
    JobStatus,
    ResearchJob,
    ResearchResult,
)

RUNTIME_STORE_RULE_VERSION = "agent-runtime-v1-store"

_DEFAULT_BASE = Path("ai_data/research/agent/runtime")

_JOB_FIELDS_TUPLE = ("reasons", "findings", "blockers", "evidence_refs")
_RESULT_FIELDS_TUPLE = ("findings", "evidence_required", "blockers", "signals")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def runtime_base_dir() -> Path:
    """Store location; env-overridable so tests never touch ai_data."""

    env = os.environ.get("WATCH_AGENT_RUNTIME_DIR", "").strip()
    return Path(env) if env else _DEFAULT_BASE


def _job_from_dict(row: dict[str, Any]) -> ResearchJob:
    kwargs = dict(row)
    for key in _JOB_FIELDS_TUPLE:
        if key in kwargs:
            kwargs[key] = tuple(kwargs.get(key) or ())
    # only known dataclass fields survive (forward/backward compat)
    known = set(ResearchJob.__dataclass_fields__)
    return ResearchJob(**{k: v for k, v in kwargs.items() if k in known})


def _result_from_dict(row: dict[str, Any]) -> ResearchResult:
    kwargs = dict(row)
    for key in _RESULT_FIELDS_TUPLE:
        if key in kwargs:
            kwargs[key] = tuple(kwargs.get(key) or ())
    known = set(ResearchResult.__dataclass_fields__)
    return ResearchResult(**{k: v for k, v in kwargs.items() if k in known})


class TransitionError(ValueError):
    """Illegal job status transition (subclasses ValueError for callers)."""


class RuntimeStore:
    """The persistent agent work queue + runtime record stores."""

    def __init__(self, base_dir: str | Path | None = None):
        self.base = Path(base_dir) if base_dir else runtime_base_dir()
        self.state_path = self.base / "state.json"
        self.audit_path = self.base / "audit.jsonl"
        self.worker_path = self.base / "worker.json"
        self.lock_path = self.base / ".lock"
        self.base.mkdir(parents=True, exist_ok=True)

    # -- plumbing ----------------------------------------------------------

    @contextmanager
    def _locked(self) -> Iterator[dict[str, Any]]:
        with open(self.lock_path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            state = self._read_state()
            try:
                yield state
            finally:
                self._write_state(state)
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def _read_state(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        payload.setdefault("jobs", {})
        payload.setdefault("results", {})
        payload.setdefault("evidence", [])
        payload.setdefault("cases", [])
        payload.setdefault("knowledge_use", [])
        payload.setdefault("activity", [])
        return payload

    def _write_state(self, state: dict[str, Any]) -> None:
        tmp = self.state_path.with_name(
            f".state.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
        )
        tmp.write_text(json.dumps(state, indent=1, sort_keys=True),
                       encoding="utf-8")
        os.replace(tmp, self.state_path)

    def _append_audit(self, event: dict[str, Any]) -> None:
        row = {"ts": utcnow(), **event}
        with open(self.audit_path, "a", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            fh.write(json.dumps(row, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    # -- audit / activity (read side) --------------------------------------

    def audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        rows: list[dict[str, Any]] = []
        try:
            with open(self.audit_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        continue
        except OSError:
            return []
        return rows[-limit:]

    # -- jobs --------------------------------------------------------------

    def enqueue(self, job: ResearchJob) -> ResearchJob:
        with self._locked() as state:
            existing = state["jobs"].get(job.id)
            if existing is not None:
                return _job_from_dict(existing)   # idempotent by job id
            state["jobs"][job.id] = job.to_dict()
            self._append_audit({
                "event": "job_enqueued", "job_id": job.id,
                "agent": job.assigned_agent, "category": job.agent_category,
                "mode": job.execution_mode, "mission": job.mission,
            })
            self._activity(state, job, "queued",
                           job.mission or "job queued")
        return job

    def get(self, job_id: str) -> ResearchJob | None:
        state = self._read_state()
        row = state["jobs"].get(str(job_id or ""))
        return _job_from_dict(row) if row else None

    def list_jobs(self, *, status: str | None = None,
                  category: str | None = None,
                  limit: int = 100) -> list[ResearchJob]:
        state = self._read_state()
        jobs = [_job_from_dict(r) for r in state["jobs"].values()]
        if status:
            jobs = [j for j in jobs if j.status == status]
        if category:
            up = category.upper()
            jobs = [j for j in jobs if j.agent_category.upper() == up]
        jobs.sort(key=lambda j: (-int(j.priority_score or 0), j.created_at))
        return jobs[:max(0, int(limit))]

    def transition(self, job_id: str, new_status: str, *,
                   event: str = "transition", worker: str = "",
                   reason: str = "", **fields: Any) -> ResearchJob:
        with self._locked() as state:
            row = state["jobs"].get(str(job_id or ""))
            if row is None:
                raise KeyError(f"unknown job: {job_id}")
            job = _job_from_dict(row)
            allowed = JOB_STATUS_FLOW.get(job.status, ())
            if new_status not in allowed:
                raise TransitionError(
                    f"illegal transition {job.status} -> {new_status} "
                    f"(allowed: {', '.join(allowed) or 'none'})"
                )
            updated = {**row, **fields, "status": new_status,
                       "updated_at": utcnow()}
            state["jobs"][job.id] = updated
            self._append_audit({
                "event": event, "job_id": job.id, "worker": worker,
                "from": job.status, "to": new_status,
                "reason": reason, "agent": job.assigned_agent,
                "attempt": int(updated.get("attempt_count") or 0),
            })
            self._activity(state, _job_from_dict(updated), new_status.lower(),
                           reason or f"{job.status} -> {new_status}")
        return _job_from_dict(state["jobs"][job_id])

    def claim_next(self, worker_id: str, categories: tuple[str, ...],
                   *, lease_seconds: int = 30,
                   now: str | None = None) -> ResearchJob | None:
        """Atomically claim the highest-priority QUEUED job for ``categories``."""

        now = now or utcnow()
        wanted = {c.upper() for c in categories}
        with self._locked() as state:
            candidates = []
            for row in state["jobs"].values():
                if row.get("status") != JobStatus.QUEUED.value:
                    continue
                if str(row.get("agent_category", "")).upper() not in wanted:
                    continue
                candidates.append(row)
            if not candidates:
                return None
            candidates.sort(key=lambda r: (-int(r.get("priority_score") or 0),
                                           r.get("created_at") or ""))
            row = candidates[0]
            attempt = int(row.get("attempt_count") or 0) + 1
            lease_expires = datetime.fromtimestamp(
                datetime.now(timezone.utc).timestamp() + int(lease_seconds),
                tz=timezone.utc,
            ).isoformat()
            updated = {
                **row,
                "status": JobStatus.CLAIMED.value,
                "lease_owner": worker_id,
                "lease_expires_at": lease_expires,
                "heartbeat_at": now,
                "claimed_at": now,
                "attempt_count": attempt,
                "updated_at": now,
                "error": "",
            }
            state["jobs"][updated["id"]] = updated
            self._append_audit({
                "event": "job_claimed", "job_id": updated["id"],
                "worker": worker_id, "attempt": attempt,
                "lease_seconds": int(lease_seconds),
                "category": updated.get("agent_category"),
            })
            self._activity(state, _job_from_dict(updated), "claimed",
                           f"worker {worker_id} claimed (attempt {attempt})")
        return _job_from_dict(state["jobs"][updated["id"]])

    def heartbeat(self, job_id: str, worker_id: str, *,
                  lease_seconds: int = 30) -> str | None:
        """Renew the lease; returns new expiry, or None if the lease was lost."""

        now = utcnow()
        with self._locked() as state:
            row = state["jobs"].get(str(job_id or ""))
            if row is None:
                return None
            if row.get("lease_owner") != worker_id:
                return None
            if row.get("status") not in (
                JobStatus.CLAIMED.value, JobStatus.RUNNING.value,
                JobStatus.WAITING_EVIDENCE.value,
            ):
                return None
            lease_expires = datetime.fromtimestamp(
                datetime.now(timezone.utc).timestamp() + int(lease_seconds),
                tz=timezone.utc,
            ).isoformat()
            state["jobs"][row["id"]] = {
                **row, "heartbeat_at": now,
                "lease_expires_at": lease_expires, "updated_at": now,
            }
            return lease_expires

    def release(self, job_id: str, worker_id: str, *,
                to_status: str = JobStatus.QUEUED.value,
                reason: str = "released before start") -> bool:
        """Release a CLAIMED job back to the queue (owner-checked)."""

        row = self._read_state()["jobs"].get(str(job_id or ""))
        if not row or row.get("lease_owner") != worker_id:
            return False
        if row.get("status") != JobStatus.CLAIMED.value:
            return False
        self.transition(job_id, to_status, event="job_released",
                        worker=worker_id, reason=reason,
                        lease_owner="", lease_expires_at=None)
        return True

    def sweep(self, now_ts: float | None = None) -> dict[str, int]:
        """Recover orphans: expired CLAIMED/leases, per the flow contract."""

        now_ts = now_ts if now_ts is not None else time.time()
        swept = {"expired": 0, "lease_lost": 0, "requeued": 0,
                 "terminal": 0}
        state_snap = self._read_state()
        for row in list(state_snap["jobs"].values()):
            status = row.get("status")
            if status not in (JobStatus.CLAIMED.value,
                              JobStatus.RUNNING.value):
                continue
            expiry = row.get("lease_expires_at")
            if not expiry:
                continue
            try:
                expiry_ts = datetime.fromisoformat(expiry).timestamp()
            except ValueError:
                continue
            if expiry_ts > now_ts:
                continue
            job_id = row["id"]
            attempt = int(row.get("attempt_count") or 0)
            max_attempts = int(row.get("max_attempts") or 3)
            if status == JobStatus.CLAIMED.value:
                self.transition(
                    job_id, JobStatus.EXPIRED.value, event="lease_expired",
                    worker=str(row.get("lease_owner") or ""),
                    reason="lease expired before the job started",
                    lease_owner="", lease_expires_at=None,
                )
                swept["expired"] += 1
            else:  # RUNNING with a lost lease -> failure path
                self.transition(
                    job_id, JobStatus.FAILED.value, event="lease_lost",
                    worker=str(row.get("lease_owner") or ""),
                    reason="lease expired while running (worker presumed "
                           "crashed)",
                    error="lease_lost",
                    lease_owner="", lease_expires_at=None,
                )
                swept["lease_lost"] += 1
            # recoverable? requeue while attempts remain (no orphaned jobs)
            if attempt < max_attempts:
                self.transition(
                    job_id, JobStatus.QUEUED.value, event="job_requeued",
                    reason="attempts remain after lease recovery",
                    lease_owner="", lease_expires_at=None,
                )
                swept["requeued"] += 1
            else:
                if self._read_state()["jobs"][job_id]["status"] == \
                        JobStatus.EXPIRED.value:
                    self.transition(
                        job_id, JobStatus.FAILED.value,
                        event="lease_expired",
                        reason="expired with no attempts remaining",
                        error="attempts_exhausted",
                    )
                self.transition(
                    job_id, JobStatus.TERMINAL_FAILED.value,
                    event="attempts_exhausted",
                    reason="lease recovery with no attempts remaining",
                )
                swept["terminal"] += 1
        return swept

    def cancel(self, job_id: str, *, reason: str = "cancelled by operator",
               worker: str = "") -> bool:
        row = self._read_state()["jobs"].get(str(job_id or ""))
        if not row:
            return False
        try:
            self.transition(job_id, JobStatus.CANCELLED.value,
                            event="job_cancelled", worker=worker,
                            reason=reason, lease_owner="",
                            lease_expires_at=None)
        except TransitionError:
            return False
        return True

    def retry_or_terminal(self, job_id: str, *, error: str,
                          worker: str = "") -> str:
        """Failure policy: requeue while attempts remain, else terminal."""

        row = self._read_state()["jobs"].get(str(job_id or ""))
        if row is None:
            raise KeyError(f"unknown job: {job_id}")
        attempt = int(row.get("attempt_count") or 0)
        max_attempts = int(row.get("max_attempts") or 3)
        if attempt < max_attempts:
            self.transition(job_id, JobStatus.QUEUED.value,
                            event="job_retry", worker=worker,
                            reason=f"retry after failure: {error}",
                            error=error, lease_owner="",
                            lease_expires_at=None)
            return JobStatus.QUEUED.value
        self.transition(job_id, JobStatus.TERMINAL_FAILED.value,
                        event="job_terminal_failed", worker=worker,
                        reason=f"attempts exhausted: {error}", error=error,
                        lease_owner="", lease_expires_at=None)
        return JobStatus.TERMINAL_FAILED.value

    def counts(self) -> dict[str, int]:
        state = self._read_state()
        out: dict[str, int] = {}
        for row in state["jobs"].values():
            out[row.get("status", "?")] = out.get(row.get("status", "?"), 0) + 1
        return out

    # -- results / evidence / cases / knowledge ----------------------------

    def put_result(self, result: ResearchResult) -> None:
        with self._locked() as state:
            state["results"][result.job_id] = result.to_dict()
            self._append_audit({
                "event": "result_persisted", "job_id": result.job_id,
                "confidence": result.confidence,
                "mode": result.execution_mode,
            })

    def get_result(self, job_id: str) -> ResearchResult | None:
        row = self._read_state()["results"].get(str(job_id or ""))
        return _result_from_dict(row) if row else None

    def record_evidence(self, evidence: dict[str, Any]) -> str:
        row = {"id": evidence.get("id") or f"ev-{uuid.uuid4().hex[:12]}",
               "created_at": utcnow(), **evidence}
        with self._locked() as state:
            state["evidence"].append(row)
            self._append_audit({
                "event": "evidence_recorded",
                "job_id": row.get("job_id"), "evidence_id": row["id"],
                "type": row.get("type"), "mode": row.get("execution_mode"),
            })
            job_id = row.get("job_id")
            if job_id and job_id in state["jobs"]:
                job = _job_from_dict(state["jobs"][job_id])
                refs = tuple(job.evidence_refs) + (row["id"],)
                state["jobs"][job_id] = {
                    **state["jobs"][job_id],
                    "evidence_refs": list(dict.fromkeys(refs)),
                    "updated_at": utcnow(),
                }
        return row["id"]

    def list_evidence(self, *, job_id: str | None = None) -> list[dict]:
        rows = self._read_state()["evidence"]
        if job_id:
            rows = [r for r in rows if r.get("job_id") == job_id]
        return rows

    def record_case(self, case: dict[str, Any]) -> str:
        row = {"id": case.get("id") or f"case-{uuid.uuid4().hex[:12]}",
               "status": case.get("status") or "OPEN",
               "created_at": utcnow(), **case}
        with self._locked() as state:
            state["cases"].append(row)
            self._append_audit({
                "event": "case_created", "case_id": row["id"],
                "job_id": row.get("job_id"),
                "specialist": row.get("specialist"),
                "mode": row.get("execution_mode"),
                "confidence": row.get("confidence"),
            })
            job_id = row.get("job_id")
            if job_id and job_id in state["jobs"]:
                state["jobs"][job_id] = {
                    **state["jobs"][job_id], "case_ref": row["id"],
                    "updated_at": utcnow(),
                }
        return row["id"]

    def list_cases(self) -> list[dict]:
        return self._read_state()["cases"]

    def get_case(self, case_id: str) -> dict | None:
        for row in self._read_state()["cases"]:
            if row.get("id") == case_id:
                return row
        return None

    def record_knowledge_use(self, use: dict[str, Any]) -> None:
        row = {"created_at": utcnow(), **use}
        with self._locked() as state:
            state["knowledge_use"].append(row)
            self._append_audit({
                "event": "knowledge_used", "job_id": row.get("job_id"),
                "document": row.get("document_id"),
                "title": row.get("title"),
            })

    def list_knowledge_use(self, *, job_id: str | None = None,
                           agent: str | None = None) -> list[dict]:
        rows = self._read_state()["knowledge_use"]
        if job_id:
            rows = [r for r in rows if r.get("job_id") == job_id]
        if agent:
            rows = [r for r in rows
                    if str(r.get("agent", "")).lower() == agent.lower()]
        return rows

    def _activity(self, state: dict[str, Any], job: ResearchJob,
                  action: str, detail: str) -> None:
        state["activity"].append({
            "at": utcnow(), "job_id": job.id, "agent": job.assigned_agent,
            "category": job.agent_category, "action": action,
            "detail": detail, "mode": job.execution_mode,
            "status": job.status,
        })
        state["activity"] = state["activity"][-500:]

    def record_activity(self, row: dict[str, Any]) -> None:
        with self._locked() as state:
            state["activity"].append({"at": utcnow(), **row})
            state["activity"] = state["activity"][-500:]

    def list_activity(self, limit: int = 50) -> list[dict]:
        return self._read_state()["activity"][-max(1, int(limit)):]

    # -- worker heartbeat (Phase 11) ---------------------------------------

    def heartbeat_worker(self, worker_id: str, *, mode: str = "production",
                         pid: int | None = None,
                         ttl_seconds: int = 120) -> None:
        payload = {"worker_id": worker_id, "at": utcnow(),
                   "at_ts": time.time(), "mode": mode,
                   "pid": pid if pid is not None else os.getpid(),
                   "ttl_seconds": int(ttl_seconds)}
        tmp = self.worker_path.with_name(f".worker.{uuid.uuid4().hex[:8]}.tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, self.worker_path)

    def worker_alive(self, now_ts: float | None = None) -> dict[str, Any]:
        now_ts = now_ts if now_ts is not None else time.time()
        try:
            payload = json.loads(self.worker_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"alive": False, "reason": "no worker heartbeat recorded"}
        raw_ttl = payload.get("ttl_seconds")
        ttl = 120 if raw_ttl is None else int(raw_ttl)
        last = float(payload.get("at_ts") or 0)
        alive = (now_ts - last) <= ttl
        return {
            "alive": alive,
            "worker_id": payload.get("worker_id", ""),
            "mode": payload.get("mode", ""),
            "pid": payload.get("pid"),
            "last_heartbeat": payload.get("at", ""),
            "reason": ("heartbeat fresh" if alive else
                       "worker heartbeat stale — no live worker"),
        }

    # -- snapshot (Phase 11 observability) ---------------------------------

    def snapshot(self, now_ts: float | None = None) -> dict[str, Any]:
        state = self._read_state()
        jobs = [_job_from_dict(r) for r in state["jobs"].values()]
        counts: dict[str, int] = {}
        for job in jobs:
            counts[job.status] = counts.get(job.status, 0) + 1
        active = [j for j in jobs if j.status in ACTIVE_JOB_STATUSES
                  and j.status != JobStatus.QUEUED.value
                  and j.status != JobStatus.NEW.value]
        leases = [
            {"job_id": j.id, "worker": j.lease_owner,
             "expires": j.lease_expires_at, "status": j.status}
            for j in jobs if j.lease_owner
            and j.status in (JobStatus.CLAIMED.value,
                             JobStatus.RUNNING.value)
        ]
        completed = [j for j in jobs if j.status == JobStatus.COMPLETED.value]
        failed = [j for j in jobs
                  if j.status in (JobStatus.FAILED.value,
                                  JobStatus.TERMINAL_FAILED.value,
                                  JobStatus.TIMEOUT.value)]
        last_success = max((j.completed_at or j.updated_at
                            for j in completed), default="")
        audit = self.audit_events(limit=30)
        last_failure = ""
        for row in reversed(audit):
            if row.get("event") in ("job_terminal_failed", "lease_lost"):
                last_failure = row.get("ts", "")
                break
        retries = sum(1 for row in audit if row.get("event") == "job_retry")
        errors = [row for row in audit
                  if row.get("event") in ("job_terminal_failed",
                                          "lease_lost", "lease_expired")
                  or row.get("to") == JobStatus.TERMINAL_FAILED.value]
        return {
            "rule_version": RUNTIME_STORE_RULE_VERSION,
            "deployed": True,
            "worker": self.worker_alive(now_ts),
            "counts": counts,
            "queue": counts.get(JobStatus.QUEUED.value, 0),
            "running": len(active),
            "total": len(jobs),
            "completed": len(completed),
            "failed": len(failed),
            "retries": retries,
            "leases": leases,
            "last_success": last_success,
            "last_failure": last_failure,
            "last_activity": (state["activity"][-1]["at"]
                              if state["activity"] else ""),
            "runtime_errors": errors[-5:],
            "cases": len(state["cases"]),
            "evidence": len(state["evidence"]),
        }


_store: RuntimeStore | None = None


def default_store() -> RuntimeStore:
    """Process-wide store bound to WATCH_AGENT_RUNTIME_DIR (rebindable)."""

    global _store
    if _store is None:
        _store = RuntimeStore()
    return _store


def rebind_store(store: RuntimeStore | None) -> None:
    """Point the default store elsewhere (tests); None resets to env path."""

    global _store
    _store = store


__all__ = [
    "RuntimeStore",
    "TransitionError",
    "default_store",
    "rebind_store",
    "runtime_base_dir",
    "utcnow",
]
