"""Deterministic, bounded research scheduler (Stage R23).

The scheduler does NOT pick arbitrary targets. Its only input is the existing
R22 Research Execution Plan projection. It enforces:

- disabled by default
- a configured time window in an explicit timezone (never the system clock)
- max wall-clock runtime and max plans per run
- one plan at a time, deterministic ordering, fail-soft per plan
- a single-worker file lock (no overlapping research)
- it runs once and exits (never continuously)
"""

from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterator
from zoneinfo import ZoneInfo

from backend.ai_ops.window import (          # EPIC9: single authoritative
    DEFAULT_WINDOW as AI_DEFAULT_WINDOW,     # AI operations window
    is_open_local,
    next_open_local,
)

__all__ = [
    "SchedulerConfig",
    "ResearchScheduler",
    "RUN_STATUS_COMPLETED",
    "RUN_STATUS_PARTIAL",
    "RUN_STATUS_BLOCKED",
    "RUN_STATUS_FAILED",
    "parse_hhmm",
    "in_window",
    "next_window_start",
    "priority_rank",
    "select_plans",
    "acquire_lock",
    "load_case_contexts",
    "CASE_AWARE_DISABLED",
    "CASE_AWARE_ENABLED",
    "CASE_AWARE_ERROR",
    "CASE_AWARE_STATES",
    "CASE_CONTEXT_OK",
    "CASE_CONTEXT_LOADER_FAILED",
    "CASE_CONTEXT_DIRECTORY_MISSING",
    "CASE_CONTEXT_ALL_MALFORMED",
]

RUN_STATUS_COMPLETED = "RESEARCH_COMPLETED"
RUN_STATUS_PARTIAL = "RESEARCH_PARTIAL"
RUN_STATUS_BLOCKED = "RESEARCH_BLOCKED"
RUN_STATUS_FAILED = "RESEARCH_FAILED"

# Stage R93: explicit, inspectable case-aware runtime activation states.
CASE_AWARE_DISABLED = "CASE_AWARE_DISABLED"
CASE_AWARE_ENABLED = "CASE_AWARE_ENABLED"
CASE_AWARE_ERROR = "CASE_AWARE_ERROR"
CASE_AWARE_STATES = (CASE_AWARE_DISABLED, CASE_AWARE_ENABLED, CASE_AWARE_ERROR)

# Stage R93: closed, bounded case-context load error codes (fail closed).
CASE_CONTEXT_OK = ""
CASE_CONTEXT_LOADER_FAILED = "context_loader_failed"
CASE_CONTEXT_DIRECTORY_MISSING = "cases_directory_missing"
CASE_CONTEXT_ALL_MALFORMED = "all_case_contexts_malformed"

_PRIORITY_RANK = {
    "CRITICAL_RESEARCH": 0,
    "HIGH_RESEARCH": 1,
    "MEDIUM_RESEARCH": 2,
    "LOW_RESEARCH": 3,
    "INSUFFICIENT_DATA": 4,
}

PLAN_COMPLETED = "RESEARCH_PLAN_COMPLETED"


def _parse_int(value: str | None, default: int) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return parsed


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def parse_hhmm(value: str) -> int:
    """EPIC9: delegation point — time-of-day parsing has ONE authority
    (``backend.ai_ops.window``) shared with the AI operations
    dispatcher, so no module restates the semantics."""
    from backend.ai_ops.window import parse_hhmm as _parse_hhmm
    return _parse_hhmm(value)


def in_window(
    now: datetime, window_start: str, window_end: str
) -> bool:
    """True when ``now`` (already in the configured tz) is inside the window.

    Supports windows crossing midnight (e.g. 12:00 -> 00:00 or 22:00 -> 06:00).
    A zero-length window (start == end) is always closed.
    """
    # EPIC9: single authority — identical semantics for every caller.
    return is_open_local(now, window_start, window_end)


def next_window_start(
    now: datetime, window_start: str, window_end: str
) -> datetime:
    """Next occurrence of the window start at/after ``now`` (same tz)."""
    # EPIC9: single authority (backend.ai_ops.window).
    return next_open_local(now, window_start, window_end)


def priority_rank(priority_level: str | None) -> int:
    return _PRIORITY_RANK.get(str(priority_level or ""), 5)


def select_plans(plans: list[dict], max_plans: int) -> list[dict]:
    """Deterministic bounded plan selection (never arbitrary).

    Priority classes first (CRITICAL > HIGH > MEDIUM > LOW > other), then
    within a class: R22 recommended_start, relevance score (desc),
    priority score (desc), CVE, program. Completed plans are excluded.
    """
    if not plans:
        return []
    eligible = [
        plan
        for plan in plans
        if isinstance(plan, dict) and plan.get("status") != PLAN_COMPLETED
    ]

    def _key(plan: dict):
        meta = plan.get("metadata") or {}
        return (
            priority_rank(meta.get("priority_level")),
            str(plan.get("recommended_start") or ""),
            -_parse_int(plan.get("relevance_score"), 0),
            -_parse_int(plan.get("priority_score"), 0),
            str(plan.get("cve_id") or ""),
            str(plan.get("program") or ""),
            str(plan.get("plan_id") or ""),
        )

    eligible.sort(key=_key)
    return eligible[: max(int(max_plans), 0)]


@contextmanager
def acquire_lock(path: str | Path) -> Iterator[bool]:
    """Non-blocking exclusive file lock. Yields False when unavailable."""
    lock_path = Path(path)
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    except OSError:
        yield False
        return
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        try:
            yield True
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        os.close(fd)


@dataclass
class SchedulerConfig:
    enabled: bool = False
    window_start: str = AI_DEFAULT_WINDOW.start
    window_end: str = AI_DEFAULT_WINDOW.end
    max_minutes: int = 300
    max_plans: int = 5
    timezone: str = AI_DEFAULT_WINDOW.timezone
    # Bounded public research fetching is on by default (the agent's purpose);
    # disable with WATCH_RESEARCH_NETWORK=false or --no-network. Dry-run is
    # always zero-network regardless.
    network: bool = True
    llm: bool = False
    max_sources: int = 12
    kb_ingest: bool = False
    lock_path: str = "/run/watch-research.lock"
    agent_dir: str = "ai_data/research/agent"
    research_dir: str = "ai_data/research"
    # Stage R24.8: opt-in public-source discovery. Disabled by default; when
    # false the R23 agent path is used and NO R24 discovery network traffic
    # occurs. The initial production envelope is deliberately tiny.
    discovery: bool = False
    discovery_max_plans: int = 1
    discovery_max_rounds: int = 1
    discovery_max_queries_per_plan: int = 3
    discovery_max_discovered: int = 5
    discovery_max_fetched: int = 3
    discovery_max_bytes_per_source: int = 2_000_000
    discovery_max_bytes_per_run: int = 4_000_000
    discovery_max_llm_calls: int = 1
    discovery_deadline_seconds: int = 120
    # Stage R24.11: optional LLM reliability configuration. Defaults are safe:
    # no fallback model, no retries, structured JSON response format.
    llm_model: str = ""
    llm_fallback_model: str = ""
    llm_max_retries: int = 0
    llm_response_format: str = "json"
    # Stage R92: opt-in case-aware scheduling. Disabled by default; when
    # false (and no explicit case_context_loader is injected) selection
    # semantics are byte-identical to the R23 baseline.
    case_aware: bool = False

    @classmethod
    def from_env(cls, env: dict | None = None) -> "SchedulerConfig":
        source = os.environ if env is None else env

        def get(name: str, default: str | None = None):
            return source.get(name, default)

        return cls(
            enabled=_parse_bool(get("WATCH_RESEARCH_ENABLED"), False),
            window_start=str(get("WATCH_RESEARCH_WINDOW_START",
                                 AI_DEFAULT_WINDOW.start)),
            window_end=str(get("WATCH_RESEARCH_WINDOW_END",
                               AI_DEFAULT_WINDOW.end)),
            max_minutes=_parse_int(get("WATCH_RESEARCH_MAX_MINUTES"), 300),
            max_plans=_parse_int(get("WATCH_RESEARCH_MAX_PLANS"), 5),
            timezone=str(get("WATCH_RESEARCH_TIMEZONE",
                             AI_DEFAULT_WINDOW.timezone)),
            network=_parse_bool(get("WATCH_RESEARCH_NETWORK"), True),
            llm=_parse_bool(get("WATCH_RESEARCH_LLM"), False),
            max_sources=_parse_int(get("WATCH_RESEARCH_MAX_SOURCES"), 12),
            kb_ingest=_parse_bool(get("WATCH_RESEARCH_KB_INGEST"), False),
            lock_path=str(get("WATCH_RESEARCH_LOCK", "/run/watch-research.lock")),
            agent_dir=str(
                get("WATCH_RESEARCH_AGENT_DIR", "ai_data/research/agent")
            ),
            research_dir=str(
                get("WATCH_RESEARCH_RESEARCH_DIR", "ai_data/research")
            ),
            discovery=_parse_bool(get("WATCH_RESEARCH_DISCOVERY"), False),
            discovery_max_plans=_parse_int(
                get("WATCH_RESEARCH_DISCOVERY_MAX_PLANS"), 1
            ),
            discovery_max_rounds=_parse_int(
                get("WATCH_RESEARCH_DISCOVERY_MAX_ROUNDS"), 1
            ),
            discovery_max_queries_per_plan=_parse_int(
                get("WATCH_RESEARCH_DISCOVERY_MAX_QUERIES_PER_PLAN"), 3
            ),
            discovery_max_discovered=_parse_int(
                get("WATCH_RESEARCH_DISCOVERY_MAX_DISCOVERED"), 5
            ),
            discovery_max_fetched=_parse_int(
                get("WATCH_RESEARCH_DISCOVERY_MAX_FETCHED"), 3
            ),
            discovery_max_bytes_per_source=_parse_int(
                get("WATCH_RESEARCH_DISCOVERY_MAX_BYTES_PER_SOURCE"), 2_000_000
            ),
            discovery_max_bytes_per_run=_parse_int(
                get("WATCH_RESEARCH_DISCOVERY_MAX_BYTES_PER_RUN"), 4_000_000
            ),
            discovery_max_llm_calls=_parse_int(
                get("WATCH_RESEARCH_DISCOVERY_MAX_LLM_CALLS"), 1
            ),
            discovery_deadline_seconds=_parse_int(
                get("WATCH_RESEARCH_DISCOVERY_DEADLINE_SECONDS"), 120
            ),
            llm_model=str(get("WATCH_RESEARCH_LLM_MODEL", "") or ""),
            llm_fallback_model=str(
                get("WATCH_RESEARCH_LLM_FALLBACK_MODEL", "") or ""
            ),
            llm_max_retries=_parse_int(
                get("WATCH_RESEARCH_LLM_MAX_RETRIES"), 0
            ),
            llm_response_format=str(
                get("WATCH_RESEARCH_LLM_RESPONSE_FORMAT", "json") or "json"
            ),
            case_aware=_parse_bool(get("WATCH_RESEARCH_CASE_AWARE"), False),
        )

    @property
    def tzinfo(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    def window_label(self) -> str:
        return f"{self.window_start}-{self.window_end} {self.timezone}"


def _default_plan_loader() -> list[dict]:
    try:
        from backend import research_execution

        return research_execution.build_plans()
    except Exception:
        return []


def load_case_contexts(cases_dir: str | Path) -> list[dict]:
    """Read-only R92 scheduling contexts for persisted case artifacts.

    Fail-soft per artifact and never writes: a readable artifact is projected
    through the existing R91 ledger and the R92 context builder; a malformed
    artifact yields an explicit ``malformed`` marker (never a fabricated
    fact); an unreadable directory yields ``[]`` (case-aware mode then fails
    closed). No network, no Mongo, no LLM, no target interaction.
    """

    from ai.research_agent.case_scheduling import (
        RULE_VERSION,
        build_case_scheduling_context,
    )
    from ai.knowledge.research_acquisition_ledger import (
        build_case_acquisition_ledger,
    )

    contexts: list[dict] = []
    directory = Path(cases_dir)
    if not directory.is_dir():
        return contexts
    try:
        from ai.research_agent.case_evidence import load_case_artifact
    except Exception:
        return contexts
    for path in sorted(directory.glob("*.json")):
        if path.name.endswith(".tmp"):
            continue
        try:
            artifact = load_case_artifact(path)
            workspace = artifact.get("research_case_workspace")
            cases = (
                workspace.get("cases")
                if isinstance(workspace, dict)
                else None
            )
            case = (
                cases[0]
                if isinstance(cases, list) and cases and isinstance(cases[0], dict)
                else None
            )
            if case is None:
                raise ValueError("case workspace is missing")
            ledger = build_case_acquisition_ledger(
                case,
                acquisition_plan=artifact.get("acquisition_plan"),
                readiness_plan=artifact.get("readiness_plan"),
                evidence_provenance=artifact.get("evidence_provenance"),
                evidence_completion=artifact.get("evidence_completion"),
                evidence_acquisition=artifact.get("evidence_acquisition"),
            )
            result = artifact.get("result")
            result = result if isinstance(result, dict) else {}
            contexts.append(
                build_case_scheduling_context(
                    case,
                    acquisition_ledger=ledger,
                    source_plan_ref=result.get("plan_id") or "",
                    source_cve=result.get("cve_id") or "",
                )
            )
        except Exception:
            contexts.append(
                {
                    "context_version": RULE_VERSION,
                    "case_ref": "",
                    "artifact": path.name,
                }
            )
    return contexts


def _bounded_scheduling(selection: object, cap: object = 0) -> dict:
    """Compact, serializable scheduling projection for status/run records."""

    block = selection if isinstance(selection, dict) else {}
    reasons: dict[str, int] = {}
    for decision in block.get("decisions") or []:
        if not isinstance(decision, dict):
            continue
        code = decision.get("reason_code") or "ELIGIBLE"
        reasons[code] = reasons.get(code, 0) + 1
    try:
        bounded_cap = max(int(cap), 0)
    except (TypeError, ValueError):
        bounded_cap = 0
    return {
        "rule_version": block.get("rule_version", ""),
        "summary": dict(block.get("summary") or {}),
        "case_attention": list(block.get("case_attention") or []),
        "eligible_plan_ids": list(block.get("eligible_plan_ids") or []),
        "reason_counts": {key: reasons[key] for key in sorted(reasons)},
        "cap": bounded_cap,
    }


def _case_context_block(selection: object, error: str) -> dict:
    """Bounded case-portfolio projection (counts and a closed error code)."""

    block = selection if isinstance(selection, dict) else {}
    summary = block.get("summary")
    summary = summary if isinstance(summary, dict) else {}
    try:
        valid = max(int(summary.get("contexts") or 0), 0)
        malformed = max(int(summary.get("malformed_contexts") or 0), 0)
    except (TypeError, ValueError):
        valid, malformed = 0, 0
    return {
        "artifacts": valid + malformed,
        "valid": valid,
        "malformed": malformed,
        "error": str(error or ""),
    }


def _run_id_for(now: datetime) -> str:
    return "run-" + now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class ResearchScheduler:
    """One-shot, bounded, deterministic scheduler over R22 plans."""

    def __init__(
        self,
        config: SchedulerConfig | None = None,
        *,
        agent: object | None = None,
        plan_loader: Callable[[], list[dict]] | None = None,
        now_fn: Callable[[], datetime] | None = None,
        monotonic_fn: Callable[[], float] | None = None,
        case_context_loader: Callable[[], list[dict]] | None = None,
    ) -> None:
        self.config = config or SchedulerConfig.from_env()
        self.agent = agent
        self.plan_loader = plan_loader or _default_plan_loader
        self._now_fn = now_fn
        self._monotonic = monotonic_fn or (lambda: __import__("time").monotonic())
        # R92: an explicit loader is itself an opt-in (test/CLI injection);
        # otherwise ``WATCH_RESEARCH_CASE_AWARE`` controls the mode.
        self.case_context_loader = case_context_loader
        self._case_aware = bool(
            self.config.case_aware or case_context_loader is not None
        )

    # -- R92/R93 case awareness --------------------------------------------
    def _case_contexts_loaded(self) -> tuple[list[dict], str]:
        """Read-only case scheduling contexts plus a closed error code.

        R93: the loader never raises and never falls back to unfiltered
        scheduling. An injected loader failure or a missing default cases
        directory yields an explicit error code and zero contexts; the R92
        selector then produces zero eligible plans (fail closed).
        """

        loader = self.case_context_loader
        if loader is not None:
            try:
                contexts = loader()
            except Exception:
                return [], CASE_CONTEXT_LOADER_FAILED
            if not isinstance(contexts, list):
                return [], CASE_CONTEXT_LOADER_FAILED
            return contexts, CASE_CONTEXT_OK
        directory = Path(self.config.research_dir) / "cases"
        if not directory.is_dir():
            return [], CASE_CONTEXT_DIRECTORY_MISSING
        try:
            contexts = load_case_contexts(directory)
        except Exception:
            return [], CASE_CONTEXT_LOADER_FAILED
        if not isinstance(contexts, list):
            return [], CASE_CONTEXT_LOADER_FAILED
        return contexts, CASE_CONTEXT_OK

    def _case_state(
        self,
        selection: object,
        context_error: str,
        *,
        active: bool | None = None,
    ) -> tuple[str, str]:
        """Derive the bounded activation state from a real R92 evaluation."""

        is_active = self._case_aware if active is None else bool(active)
        if not is_active:
            return CASE_AWARE_DISABLED, CASE_CONTEXT_OK
        block = selection if isinstance(selection, dict) else {}
        summary = block.get("summary")
        summary = summary if isinstance(summary, dict) else {}
        try:
            valid = max(int(summary.get("contexts") or 0), 0)
            malformed = max(int(summary.get("malformed_contexts") or 0), 0)
        except (TypeError, ValueError):
            return CASE_AWARE_ERROR, CASE_CONTEXT_LOADER_FAILED
        if context_error:
            return CASE_AWARE_ERROR, str(context_error)
        if valid == 0 and malformed > 0:
            return CASE_AWARE_ERROR, CASE_CONTEXT_ALL_MALFORMED
        return CASE_AWARE_ENABLED, CASE_CONTEXT_OK

    def _case_evaluation(
        self, plans: list[dict], cap: int
    ) -> tuple[list[dict], dict, str, dict]:
        """(scheduled plans, full selection, state, case context) under R92."""

        from ai.research_agent.case_scheduling import (
            select_case_aware_plans,
        )

        contexts, context_error = self._case_contexts_loaded()
        selection = select_case_aware_plans(plans, contexts)
        eligible_ids = set(selection.get("eligible_plan_ids") or [])
        eligible = [
            plan
            for plan in plans
            if isinstance(plan, dict) and plan.get("plan_id") in eligible_ids
        ]
        state, context_error = self._case_state(selection, context_error)
        return (
            select_plans(eligible, cap),
            selection,
            state,
            _case_context_block(selection, context_error),
        )

    # -- time -------------------------------------------------------------
    def _now(self) -> datetime:
        if self._now_fn is not None:
            now = self._now_fn()
            if now.tzinfo is None:
                now = now.replace(tzinfo=self.config.tzinfo)
            return now.astimezone(self.config.tzinfo)
        return datetime.now(self.config.tzinfo)

    def in_window(self, now: datetime | None = None) -> bool:
        moment = now or self._now()
        return in_window(moment, self.config.window_start, self.config.window_end)

    def next_run(self, now: datetime | None = None) -> str:
        moment = now or self._now()
        return next_window_start(
            moment, self.config.window_start, self.config.window_end
        ).isoformat()

    def _discovery_budget(self) -> dict:
        cfg = self.config
        return {
            "max_plans": cfg.discovery_max_plans,
            "max_rounds": cfg.discovery_max_rounds,
            "max_queries_per_plan": cfg.discovery_max_queries_per_plan,
            "max_discovered": cfg.discovery_max_discovered,
            "max_fetched": cfg.discovery_max_fetched,
            "max_bytes_per_source": cfg.discovery_max_bytes_per_source,
            "max_bytes_per_run": cfg.discovery_max_bytes_per_run,
            "max_llm_calls": cfg.discovery_max_llm_calls,
            "deadline_seconds": cfg.discovery_deadline_seconds,
        }

    # -- read-only preview ------------------------------------------------
    def _read_only_selection(
        self, plans: list[dict], cap: int
    ) -> tuple[list[dict], dict | None, str, dict | None]:
        if not self._case_aware:
            return select_plans(plans, cap), None, CASE_AWARE_DISABLED, None
        selected, selection, state, context = self._case_evaluation(plans, cap)
        return selected, selection, state, context

    def status(self, now: datetime | None = None) -> dict:
        moment = now or self._now()
        plans = self.plan_loader() or []
        eligible, selection, case_state, case_context = (
            self._read_only_selection(plans, self.config.max_plans)
        )
        info = {
            "enabled": self.config.enabled,
            "window": self.config.window_label(),
            "window_start": self.config.window_start,
            "window_end": self.config.window_end,
            "timezone": self.config.timezone,
            "in_window": in_window(
                moment, self.config.window_start, self.config.window_end
            ),
            "max_minutes": self.config.max_minutes,
            "max_plans": self.config.max_plans,
            "network": self.config.network,
            "llm": self.config.llm,
            "discovery": self.config.discovery,
            "discovery_budget": self._discovery_budget(),
            "eligible_plans": eligible,
            "eligible_count": len(eligible),
            "total_plans": len(plans),
            "next_run": self.next_run(moment),
            "now": moment.isoformat(),
            "case_aware_state": case_state,
        }
        if selection is not None:
            info["case_aware"] = True
            info["case_scheduling"] = _bounded_scheduling(
                selection, self.config.max_plans
            )
            info["case_context"] = case_context
        return info

    def preview(
        self,
        *,
        now: datetime | None = None,
        plan_id: str | None = None,
        limit: int | None = None,
    ) -> dict:
        moment = now or self._now()
        plans = self.plan_loader() or []
        if plan_id:
            plans = [p for p in plans if p.get("plan_id") == plan_id]
        cap = self.config.max_plans if limit is None else max(int(limit), 0)
        selected, selection, case_state, case_context = (
            self._read_only_selection(plans, cap)
        )
        result = {
            "enabled": self.config.enabled,
            "in_window": in_window(
                moment, self.config.window_start, self.config.window_end
            ),
            "window": self.config.window_label(),
            "network": self.config.network,
            "llm": self.config.llm,
            "discovery": self.config.discovery,
            "discovery_budget": self._discovery_budget(),
            "plans": selected,
            "case_aware_state": case_state,
        }
        if selection is not None:
            result["case_aware"] = True
            result["case_scheduling"] = _bounded_scheduling(selection, cap)
            result["case_context"] = case_context
        return result

    def schedule_preview(
        self,
        *,
        plan_id: str | None = None,
        limit: int | None = None,
        case_id: str | None = None,
    ) -> dict:
        """Read-only R92 case-aware scheduling preview.

        Consumes the persisted case contexts (R76 + R91) and candidate R22
        plans and returns per-case attention plus one SELECT/SKIP decision per
        (plan, bound case). Performs no network activity, executes no plan,
        writes nothing and never authorizes execution.
        """

        from ai.research_agent.case_scheduling import (
            select_case_aware_plans,
        )

        plans = self.plan_loader() or []
        if plan_id:
            plans = [p for p in plans if p.get("plan_id") == plan_id]
        contexts, context_error = self._case_contexts_loaded()
        wanted = str(case_id or "").strip()
        case_known: bool | None = None
        if wanted:
            filtered = [
                context
                for context in contexts
                if isinstance(context, dict)
                and str(context.get("case_ref") or "") == wanted
            ]
            case_known = bool(filtered)
            contexts = filtered
        selection = select_case_aware_plans(plans, contexts)
        case_state, context_error = self._case_state(
            selection, context_error, active=True
        )
        eligible_ids = set(selection.get("eligible_plan_ids") or [])
        eligible = [
            plan
            for plan in plans
            if isinstance(plan, dict) and plan.get("plan_id") in eligible_ids
        ]
        cap = self.config.max_plans if limit is None else max(int(limit), 0)
        return {
            "enabled": self.config.enabled,
            "in_window": self.in_window(),
            "window": self.config.window_label(),
            "network": self.config.network,
            "llm": self.config.llm,
            "discovery": self.config.discovery,
            "case_aware": True,
            "case_aware_state": case_state,
            "case_context": _case_context_block(selection, context_error),
            "case_ref": wanted,
            "case_known": case_known,
            "plans": select_plans(eligible, cap),
            "case_scheduling": selection,
        }

    # -- execution --------------------------------------------------------
    def _execution_gate(
        self, record: dict, *, lock_acquired: bool, executed: bool = False
    ) -> dict:
        """Bounded projection of the existing execution gates (R93).

        This is observability only: it reports the gates that already exist
        (configuration, window, lock, agent, dry-run) and never changes them.
        A case-aware SELECT decision never appears here as an authorization.
        """

        return {
            "scheduler_enabled": bool(record.get("enabled")),
            "in_window": bool(record.get("in_window")),
            "lock_acquired": bool(lock_acquired),
            "agent_configured": self.agent is not None,
            "dry_run": bool(record.get("dry_run")),
            "executed": bool(executed),
        }

    def run_once(
        self,
        *,
        now: datetime | None = None,
        plan_id: str | None = None,
        limit: int | None = None,
        force: bool = False,
        dry_run: bool = False,
        network: bool | None = None,
    ) -> dict:
        moment = now or self._now()
        started_at = moment.isoformat()
        run_id = _run_id_for(moment)
        record: dict = {
            "run_id": run_id,
            "started_at": started_at,
            "completed_at": started_at,
            "dry_run": bool(dry_run),
            "forced": bool(force),
            "enabled": self.config.enabled,
            "in_window": in_window(
                moment, self.config.window_start, self.config.window_end
            ),
            "window": self.config.window_label(),
            "network": self.config.network if network is None else bool(network),
            "llm": self.config.llm,
            "plans_selected": 0,
            "plans_processed": 0,
            "result_ids": [],
            "results": [],
            "failures": [],
            "status": RUN_STATUS_BLOCKED,
            "skipped": None,
            "case_aware_state": (
                CASE_AWARE_ENABLED if self._case_aware else CASE_AWARE_DISABLED
            ),
        }

        if not force:
            if not self.config.enabled:
                record["skipped"] = "disabled"
                record["execution_gate"] = self._execution_gate(
                    record, lock_acquired=False
                )
                record["completed_at"] = (now or self._now()).isoformat()
                return record
            if not in_window(moment, self.config.window_start, self.config.window_end):
                record["skipped"] = "outside_window"
                record["execution_gate"] = self._execution_gate(
                    record, lock_acquired=False
                )
                record["completed_at"] = (now or self._now()).isoformat()
                return record

        with acquire_lock(self.config.lock_path) as locked:
            if not locked:
                record["skipped"] = "locked"
                record["execution_gate"] = self._execution_gate(
                    record, lock_acquired=False
                )
                record["completed_at"] = (now or self._now()).isoformat()
                return record

            plans = self.plan_loader() or []
            if plan_id:
                plans = [p for p in plans if p.get("plan_id") == plan_id]
            cap = self.config.max_plans if limit is None else max(int(limit), 0)
            selection = None
            if self._case_aware:
                selected, selection, case_state, case_context = (
                    self._case_evaluation(plans, cap)
                )
                record["case_aware"] = True
                record["case_aware_state"] = case_state
                record["case_context"] = case_context
                record["case_scheduling"] = _bounded_scheduling(selection, cap)
            else:
                selected = select_plans(plans, cap)
            record["plans_selected"] = len(selected)

            if dry_run:
                record["status"] = (
                    RUN_STATUS_BLOCKED if not selected else RUN_STATUS_COMPLETED
                )
                record["skipped"] = "dry_run"
                record["results"] = [
                    {
                        "plan_id": p.get("plan_id"),
                        "cve_id": p.get("cve_id"),
                        "program": p.get("program"),
                    }
                    for p in selected
                ]
                record["execution_gate"] = self._execution_gate(
                    record, lock_acquired=True
                )
                record["completed_at"] = (now or self._now()).isoformat()
                # dry-run never writes (no results, no run record)
                return record

            if not selected:
                record["status"] = RUN_STATUS_BLOCKED
                record["execution_gate"] = self._execution_gate(
                    record, lock_acquired=True
                )
                record["completed_at"] = (now or self._now()).isoformat()
                from ai.research_agent import storage
                storage.store_run(record, base=self.config.agent_dir)
                return record

            if self.agent is None:
                record["status"] = RUN_STATUS_FAILED
                record["failures"].append({"error": "no agent configured"})
                record["execution_gate"] = self._execution_gate(
                    record, lock_acquired=True
                )
                record["completed_at"] = (now or self._now()).isoformat()
                from ai.research_agent import storage
                storage.store_run(record, base=self.config.agent_dir)
                return record

            deadline = self._monotonic() + max(self.config.max_minutes, 0) * 60

            def _expired() -> bool:
                return self._monotonic() >= deadline

            try:
                results, failures = self.agent.run_plans(
                    selected,
                    run_id=run_id,
                    deadline=deadline,
                    dry_run=False,
                    network=network,
                    persist=True,
                    per_plan_timeout=_expired,
                )
            except Exception as exc:  # never propagate; a run is fail-soft
                record["status"] = RUN_STATUS_FAILED
                record["failures"].append({"error": type(exc).__name__})
                record["execution_gate"] = self._execution_gate(
                    record, lock_acquired=True
                )
                record["completed_at"] = (now or self._now()).isoformat()
                from ai.research_agent import storage
                storage.store_run(record, base=self.config.agent_dir)
                return record

            record["failures"] = failures
            record["plans_processed"] = len(results)
            record["results"] = [
                {
                    "plan_id": r.plan_id,
                    "result_id": r.result_id,
                    "cve_id": r.cve_id,
                    "program": r.program,
                    "status": r.status,
                    "evidence": len(r.evidence),
                    "sources": len(r.sources),
                }
                for r in results
            ]
            record["result_ids"] = [r.result_id for r in results]
            if failures and results:
                record["status"] = RUN_STATUS_PARTIAL
            elif failures and not results:
                record["status"] = RUN_STATUS_FAILED
            else:
                record["status"] = RUN_STATUS_COMPLETED
            record["execution_gate"] = self._execution_gate(
                record, lock_acquired=True, executed=bool(results)
            )
            record["completed_at"] = (now or self._now()).isoformat()
            from ai.research_agent import storage
            storage.store_run(record, base=self.config.agent_dir)
            return record
