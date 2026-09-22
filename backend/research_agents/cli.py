"""backend/research_agents/cli.py — bounded Agent Runtime v1 worker CLI (Phase 10).

Operational entry point, deliberately conservative:

* bounded work per invocation (``--max-jobs``, default from RuntimeConfig)
* single worker identity per process, graceful SIGTERM/SIGINT handling
* no process spawning, no unbounded loop: ``run`` exits when the queue is
  drained, the budget is spent, or shutdown is requested
* ``status`` prints the observability snapshot (Phase 11) as JSON

Deployment model (recorded in
``agent-reports/WATCH-AI-AGENT-RUNTIME-V1-DISCOVERY.md``): extend the
existing watch-research one-shot service pattern — invocation looks like
``python -m backend.research_agents.cli run --max-jobs 3`` under the same
flock/window discipline, NOT a new always-on high-concurrency service.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import uuid
from typing import Any

from backend.research_agents.models import JobStatus, ResearchJob
from backend.research_agents.runtime import (
    RuntimeConfig,
    RuntimeStore,
    AgentWorker,
    runtime_snapshot,
)
from backend.research_agents.runtime_store import default_store, utcnow

EXIT_OK = 0
EXIT_USAGE = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="backend.research_agents.cli",
        description="AI Agent Runtime v1 worker (bounded, fail-closed).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="drain the queue (bounded)")
    run.add_argument("--max-jobs", type=int, default=5,
                     help="jobs to process this invocation (default 5)")
    run.add_argument("--worker-id", default="",
                     help="worker identity (default agent-worker-<pid>)")
    run.add_argument("--mode", choices=("production", "fixture"),
                     default="production",
                     help="execution mode stamp for jobs this worker runs")
    run.add_argument("--llm", default="",
                     help="explicit provider kind (e.g. OPENROUTER); empty "
                          "= deterministic analysis only")
    run.add_argument("--model", default="", help="model id for --llm")
    run.add_argument("--lease", type=int, default=30,
                     help="lease seconds (default 30)")
    run.add_argument("--timeout", type=int, default=120,
                     help="per-job wall-clock timeout seconds (default 120)")
    run.add_argument("--hunt", action="store_true",
                     help="enable the bounded autonomous hunt planner loop")
    run.add_argument("--hunt-plans", type=int, default=0,
                     help="max hunt plans per objective (0 = disabled; "
                          "--hunt defaults this to 3)")
    run.add_argument("--hunt-observations", type=int, default=6,
                     help="max hunt observation executions per objective")
    run.add_argument("--hunt-iterations", type=int, default=4,
                     help="max hunt planning iterations per objective")
    run.add_argument("--hunt-llm-plans", type=int, default=2,
                     help="max LLM planning-advisor calls per objective")
    run.add_argument("--hunt-seconds", type=int, default=60,
                     help="max hunt wall-clock seconds per objective")

    sub.add_parser("status", help="observability snapshot as JSON")

    enqueue = sub.add_parser("enqueue", help="enqueue one research job")
    enqueue.add_argument("--category", required=True,
                         help="canonical category (XSS, SSRF, ...)")
    enqueue.add_argument("--agent", required="", default="",
                         help="specialist agent name")
    enqueue.add_argument("--program", default="")
    enqueue.add_argument("--subdomain", default="")
    enqueue.add_argument("--url", default="")
    enqueue.add_argument("--mission", default="authorized research review")
    enqueue.add_argument("--scope", default="",
                         help="authorization scope token "
                              "(watch:scope:<program>/<subdomain> or "
                              "fixture:<token>)")
    enqueue.add_argument("--mode", choices=("production", "fixture"),
                         default="production")
    enqueue.add_argument("--priority", type=int, default=50)
    enqueue.add_argument("--timeout", type=int, default=120)

    cancel = sub.add_parser("cancel", help="cancel a queued/claimed job")
    cancel.add_argument("job_id")
    return parser


def _install_shutdown(flag: dict[str, bool]) -> None:
    def handler(signum: int, frame: Any) -> None:  # pragma: no cover
        flag["stop"] = True
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, handler)
        except ValueError:  # non-main thread (tests)
            pass


def cmd_run(args: argparse.Namespace) -> int:
    hunt_plans = int(args.hunt_plans)
    if args.hunt and hunt_plans <= 0:
        hunt_plans = 3
    config = RuntimeConfig(
        lease_seconds=args.lease,
        job_timeout=args.timeout,
        max_jobs_per_run=max(1, args.max_jobs),
        worker_id=args.worker_id,
        execution_mode=args.mode,
        llm_provider_kind=args.llm,
        llm_model=args.model,
        hunt_max_plans=max(0, hunt_plans),
        hunt_max_observations=max(1, args.hunt_observations),
        hunt_max_iterations=max(1, args.hunt_iterations),
        hunt_max_llm_plans=max(0, args.hunt_llm_plans),
        hunt_max_seconds=max(5, args.hunt_seconds),
    )
    worker = AgentWorker(config=config, store=default_store())
    flag = {"stop": False}
    _install_shutdown(flag)
    stats = worker.run(max_jobs=config.max_jobs_per_run,
                       stop=lambda: flag["stop"])
    print(json.dumps({"ok": True, "worker_id": worker.worker_id,
                      "mode": config.execution_mode,
                      "llm": config.llm_provider_kind or "not_configured",
                      **stats}, sort_keys=True))
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    print(json.dumps(runtime_snapshot(default_store()), indent=1,
                     sort_keys=True))
    return EXIT_OK


def cmd_enqueue(args: argparse.Namespace) -> int:
    store = default_store()
    category = args.category.strip().upper()
    scope = args.scope or (
        f"fixture:test/{args.subdomain or args.program}"
        if args.mode == "fixture" else
        f"watch:scope:{args.program}/{args.subdomain}"
    )
    job = ResearchJob(
        id=f"job-{category.lower()}-{uuid.uuid4().hex[:10]}",
        candidate_id="cli",
        category=category,
        endpoint=args.url or args.subdomain,
        parameter="",
        priority_score=args.priority,
        status=JobStatus.QUEUED.value,
        assigned_agent=args.agent or category.lower(),
        created_at=utcnow(),
        updated_at=utcnow(),
        agent_category=category,
        reasons=("manual enqueue via agent runtime cli",),
        program=args.program,
        subdomain=args.subdomain,
        url=args.url,
        mission=args.mission,
        authorization_ref=scope,
        timeout_seconds=args.timeout,
        execution_mode=args.mode,
    )
    stored = store.enqueue(job)
    print(json.dumps({"ok": True, "job_id": stored.id,
                      "status": stored.status}, sort_keys=True))
    return EXIT_OK


def cmd_cancel(args: argparse.Namespace) -> int:
    ok = default_store().cancel(args.job_id,
                                reason="cancelled via agent runtime cli")
    print(json.dumps({"ok": ok, "job_id": args.job_id}))
    return EXIT_OK if ok else EXIT_USAGE


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "run":
        return cmd_run(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "enqueue":
        return cmd_enqueue(args)
    if args.command == "cancel":
        return cmd_cancel(args)
    return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
