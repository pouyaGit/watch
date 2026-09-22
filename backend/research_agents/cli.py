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

    # ---- Campaign Orchestrator (Phase 8) --------------------------------
    camp = sub.add_parser(
        "campaign",
        help="bounded security campaign orchestration (fail-closed)")
    camp_sub = camp.add_subparsers(dest="campaign_command", required=True)

    c_create = camp_sub.add_parser(
        "create", help="create a campaign (explicit scope required)")
    c_create.add_argument("--campaign-id", default="",
                          help="optional explicit id (default camp-<hex>)")
    c_create.add_argument("--program", required=True)
    c_create.add_argument("--subdomain", required=True)
    c_create.add_argument("--url", default="")
    c_create.add_argument("--objective", required=True,
                          help="campaign objective (research goal text)")
    c_create.add_argument("--scope", default="",
                          help="authorization scope token; default "
                               "watch:scope:<program>/<subdomain>")
    c_create.add_argument("--mode", choices=("production", "fixture"),
                          default="production")
    c_create.add_argument("--priority", type=int, default=50)
    c_create.add_argument("--specialists", default="",
                          help="comma-separated participating specialists "
                               "(informational; capabilities stay closed)")
    c_create.add_argument("--limit", action="append", default=[],
                          metavar="KEY=VAL",
                          help="override a cumulative budget limit "
                               "(e.g. --limit max_objectives=4)")

    c_obj = camp_sub.add_parser(
        "add-objective", help="add a research objective to a campaign")
    c_obj.add_argument("--campaign-id", required=True)
    c_obj.add_argument("--objective-id", default="",
                       help="optional explicit id (default obj-<hex>)")
    c_obj.add_argument("--category", required=True,
                       help="canonical specialist category (XSS, "
                            "CVE_RESEARCH, ...)")
    c_obj.add_argument("--research", required=True,
                       help="research question")
    c_obj.add_argument("--hypothesis", default="")
    c_obj.add_argument("--specialist", default="",
                       help="optional declared specialist (must match the "
                            "capability for --category)")
    c_obj.add_argument("--priority", type=int, default=50)
    c_obj.add_argument("--depends", action="append", default=[],
                       metavar="OBJID[:KIND]",
                       help="dependency on another objective "
                            "(KIND=REQUIRED|OPTIONAL|INFORMATIONAL, "
                            "default REQUIRED)")
    c_obj.add_argument("--evidence-min", type=int, default=0,
                       help="min evidence refs for this objective")

    c_run = camp_sub.add_parser(
        "run",
        help="run the bounded orchestration loop for one campaign")
    c_run.add_argument("--campaign-id", required=True)
    c_run.add_argument("--max-objectives", type=int, default=2,
                       help="objectives to execute this invocation "
                            "(default 2; cumulative budget still bounds)")
    c_run.add_argument("--llm", default="",
                       help="explicit provider kind (e.g. OPENROUTER); "
                            "empty = deterministic prioritization only")
    c_run.add_argument("--model", default="", help="model id for --llm")
    c_run.add_argument("--mode", choices=("production", "fixture"),
                       default="production")
    c_run.add_argument("--lease", type=int, default=30)
    c_run.add_argument("--timeout", type=int, default=120)
    c_run.add_argument("--hunt", action="store_true",
                       help="enable the bounded hunt planner for each "
                            "objective job (campaigns run WITH hunt)")
    c_run.add_argument("--hunt-plans", type=int, default=0)
    c_run.add_argument("--hunt-observations", type=int, default=6)
    c_run.add_argument("--hunt-iterations", type=int, default=4)
    c_run.add_argument("--hunt-llm-plans", type=int, default=2)
    c_run.add_argument("--hunt-seconds", type=int, default=60)

    c_status = camp_sub.add_parser(
        "status", help="campaign + objectives + budget as JSON")
    c_status.add_argument("--campaign-id", required=True)

    c_pause = camp_sub.add_parser(
        "pause", help="pause a campaign (stops new objective execution)")
    c_pause.add_argument("--campaign-id", required=True)

    c_resume = camp_sub.add_parser(
        "resume",
        help="resume: revalidate scope+deps+budget, then READY")
    c_resume.add_argument("--campaign-id", required=True)

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


# ---- Campaign Orchestrator commands (Phase 8) ----------------------------

def cmd_campaign(args: argparse.Namespace) -> int:
    from backend.research_agents.campaign.models import (
        Campaign, CampaignObjective, Dependency, new_id,
    )
    from backend.research_agents.campaign.store import (
        CampaignStore, CampaignStoreError,
    )
    from backend.research_agents.campaign.models import (
        CampaignStateError,
    )
    from backend.research_agents.campaign.dependencies import (
        DependencyCycleError,
    )

    sub = args.campaign_command
    store = default_store()
    cs = CampaignStore(store.base)

    if sub == "create":
        scope = args.scope or (
            f"fixture:test/{args.subdomain}"
            if args.mode == "fixture" else
            f"watch:scope:{args.program}/{args.subdomain}")
        limits: dict[str, int] = {}
        for raw in args.limit:
            if "=" not in raw:
                print(json.dumps({"ok": False,
                                  "error": f"bad --limit {raw!r}"}))
                return EXIT_USAGE
            key, val = raw.split("=", 1)
            if not key.startswith("max_"):
                print(json.dumps({"ok": False,
                                  "error": f"limit key must start with "
                                           f"max_: {key!r}"}))
                return EXIT_USAGE
            try:
                limits[key] = int(val)
            except ValueError:
                print(json.dumps({"ok": False,
                                  "error": f"limit value not int: {val!r}"}))
                return EXIT_USAGE
        try:
            campaign = Campaign(
                campaign_id=args.campaign_id or new_id("camp"),
                program=args.program,
                scope_ref=scope,
                campaign_objective=args.objective,
                target_context={
                    "program": args.program,
                    "subdomain": args.subdomain,
                    "url": args.url or f"https://{args.subdomain}",
                    "execution_mode": args.mode,
                },
                participating_specialists=tuple(
                    s.strip() for s in args.specialists.split(",") if s.strip()),
                priority=args.priority,
                state="DRAFT",
                limits=limits,
                provenance={"created_via": "cli",
                            "mode": args.mode},
            )
            cs.create_campaign(campaign)
        except (CampaignStoreError, ValueError) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}))
            return EXIT_USAGE
        print(json.dumps({"ok": True,
                          "campaign_id": campaign.campaign_id,
                          "state": campaign.state,
                          "scope_ref": campaign.scope_ref},
                         sort_keys=True))
        return EXIT_OK

    if sub == "add-objective":
        campaign = cs.get_campaign(args.campaign_id)
        if campaign is None:
            print(json.dumps({"ok": False,
                              "error": "unknown campaign"}))
            return EXIT_USAGE
        deps: list[Dependency] = []
        for raw in args.depends:
            kind = "REQUIRED"
            oid = raw
            if ":" in raw:
                oid, kind = raw.rsplit(":", 1)
                kind = kind.upper()
            deps.append(Dependency(objective_id=args.objective_id or "pending",
                                   depends_on=oid.strip(), kind=kind))
        # objective_id needed before deps reference it
        objective_id = args.objective_id or new_id("obj")
        for dep in deps:
            dep.objective_id = objective_id
        evidence: dict[str, Any] = {}
        if args.evidence_min:
            evidence = {"min_evidence_refs": int(args.evidence_min),
                        "required_types": ["observation"]}
        try:
            objective = CampaignObjective(
                objective_id=objective_id,
                campaign_id=campaign.campaign_id,
                category=args.category.strip().upper(),
                scope_ref=campaign.scope_ref,   # ALWAYS campaign scope
                research_question=args.research,
                hypothesis=args.hypothesis or args.research,
                specialist=args.specialist.strip(),
                priority=args.priority,
                evidence_requirements=evidence,
                dependencies=deps,
                provenance={"created_via": "cli"},
            )
            # cycle check against existing objectives BEFORE persisting
            from backend.research_agents.campaign.dependencies import (
                assert_acyclic,
            )
            existing = cs.objectives_for_campaign(campaign.campaign_id)
            assert_acyclic([*existing, objective])
            cs.add_objective(objective, campaign)
        except (CampaignStoreError, CampaignStateError,
                DependencyCycleError, ValueError) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}))
            return EXIT_USAGE
        print(json.dumps({"ok": True,
                          "objective_id": objective.objective_id,
                          "campaign_id": objective.campaign_id,
                          "state": objective.state,
                          "dependencies": [d.to_dict()
                                           for d in objective.dependencies]},
                         sort_keys=True))
        return EXIT_OK

    if sub == "run":
        from backend.research_agents.campaign.executor import (
            execute_campaign,
        )
        hunt_plans = int(args.hunt_plans)
        if args.hunt and hunt_plans <= 0:
            hunt_plans = 3
        config = RuntimeConfig(
            lease_seconds=args.lease,
            job_timeout=args.timeout,
            max_jobs_per_run=1,
            execution_mode=args.mode,
            llm_provider_kind=args.llm,
            llm_model=args.model,
            hunt_max_plans=max(0, hunt_plans),
            hunt_max_observations=max(1, args.hunt_observations),
            hunt_max_iterations=max(1, args.hunt_iterations),
            hunt_max_llm_plans=max(0, args.hunt_llm_plans),
            hunt_max_seconds=max(5, args.hunt_seconds),
        )
        advisor_fn = None
        if args.llm:
            advisor_fn = _build_campaign_advisor(config)
        summary = execute_campaign(
            args.campaign_id,
            config=config,
            advisor_fn=advisor_fn,
            store=store,
            campaign_store=cs,
            max_objectives=max(1, args.max_objectives),
        )
        payload = summary.to_dict()
        print(json.dumps(payload, sort_keys=True))
        return EXIT_OK if summary.ok else EXIT_USAGE

    if sub == "status":
        from backend.research_agents.campaign.budget import CampaignBudget
        campaign = cs.get_campaign(args.campaign_id)
        if campaign is None:
            print(json.dumps({"ok": False,
                              "error": "unknown campaign"}))
            return EXIT_USAGE
        objectives = cs.objectives_for_campaign(args.campaign_id)
        budget = CampaignBudget(cs, campaign)
        budget.sync_from_objectives(objectives)
        print(json.dumps({
            "ok": True,
            "campaign": campaign.to_dict(),
            "objectives": [o.to_dict() for o in objectives],
            "budget": budget.report().to_dict(),
            "context_items": len(cs.context_for(args.campaign_id,
                                                limit=50)),
        }, sort_keys=True))
        return EXIT_OK

    if sub == "pause":
        from backend.research_agents.campaign.models import (
            validate_campaign_transition,
        )
        campaign = cs.get_campaign(args.campaign_id)
        if campaign is None:
            print(json.dumps({"ok": False,
                              "error": "unknown campaign"}))
            return EXIT_USAGE
        try:
            validate_campaign_transition(campaign.state, "PAUSED")
            cs.transition_campaign(args.campaign_id, "PAUSED",
                                   reason="paused_via_cli")
            cs.release_lease(args.campaign_id, campaign.lease_owner or "")
        except (CampaignStateError, CampaignStoreError) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}))
            return EXIT_USAGE
        store.record_audit_event({"event": "campaign_paused",
                                  "campaign_id": args.campaign_id,
                                  "reason": "paused_via_cli"})
        print(json.dumps({"ok": True, "state": "PAUSED"}, sort_keys=True))
        return EXIT_OK

    if sub == "resume":
        from backend.research_agents.campaign.budget import CampaignBudget
        from backend.research_agents.campaign.dependencies import (
            DependencyCycleError, resolve_all,
        )
        campaign = cs.get_campaign(args.campaign_id)
        if campaign is None:
            print(json.dumps({"ok": False,
                              "error": "unknown campaign"}))
            return EXIT_USAGE
        if campaign.state not in ("PAUSED", "WAITING"):
            print(json.dumps({"ok": False,
                              "error": f"resume requires PAUSED or "
                                       f"WAITING, campaign is "
                                       f"{campaign.state}"}))
            return EXIT_USAGE
        # Phase 12: revalidate scope + deps + budget BEFORE resuming
        problems: list[str] = []
        objectives = cs.objectives_for_campaign(args.campaign_id)
        for obj in objectives:
            if not campaign.scope_matches(obj.scope_ref):
                problems.append(f"scope drift: {obj.objective_id}")
        try:
            resolve_all(objectives)
        except DependencyCycleError as exc:
            problems.append(str(exc))
        budget = CampaignBudget(cs, campaign)
        budget.sync_from_objectives(objectives)
        if budget.is_exhausted("objectives"):
            problems.append("max_objectives budget exhausted")
        if problems:
            print(json.dumps({"ok": False,
                              "revalidation_failed": problems}))
            return EXIT_USAGE
        try:
            cs.transition_campaign(args.campaign_id, "READY",
                                   reason="resumed_via_cli",
                                   detail="scope+deps+budget revalidated")
        except (CampaignStateError, CampaignStoreError) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}))
            return EXIT_USAGE
        store.record_audit_event({
            "event": "campaign_resumed",
            "campaign_id": args.campaign_id,
            "reason": "scope+deps+budget revalidated",
            "budget": budget.report().to_dict(),
        })
        print(json.dumps({"ok": True, "state": "READY",
                          "budget": budget.report().to_dict()},
                         sort_keys=True))
        return EXIT_OK

    return EXIT_USAGE


def _build_campaign_advisor(config: RuntimeConfig) -> Any:
    """Free-only campaign advisor through the existing provider layer.

    The free-only guard runs FIRST (before any provider construction);
    paid/unknown models fail closed inside the same guard the analysis
    path uses.  Any failure degrades to deterministic prioritization.
    """

    from backend.research_agents.llm_guard import resolve_free_config
    from ai.providers.provider_registry import select_provider

    def advisor_fn(request: dict) -> tuple[Any, dict[str, Any]]:
        import time as _time
        guard = resolve_free_config(
            config.llm_provider_kind or "OPENROUTER",
            config.llm_model or "",
            config.llm_timeout,
        )
        provider = select_provider(
            guard["provider_kind"],
            model=guard["requested_model"],
            timeout_seconds=guard["timeout_seconds"],
            max_retries=0,
            retry_backoff_seconds=0,
        )
        t0 = _time.monotonic()
        status_call = getattr(provider, "complete_with_status", None)
        outcome = (status_call(request) if callable(status_call)
                   else provider.complete(request))
        elapsed = int((_time.monotonic() - t0) * 1000)
        if not isinstance(outcome, dict):
            raise RuntimeError("unexpected advisor outcome type "
                               f"{type(outcome).__name__}")
        if ("summary" in outcome or "insights" in outcome) \
                and "response" not in outcome:
            response, err, telemetry = outcome, None, {}
        else:
            err = outcome.get("error")
            response = outcome.get("response")
            telemetry = (outcome.get("telemetry")
                         if isinstance(outcome.get("telemetry"), dict)
                         else {})
        if err is not None or response is None:
            exc = outcome.get("_exception")
            raise RuntimeError(
                f"advisor provider error: {str(err or exc)[:200]}")
        resolved = ""
        try:
            resolved = str(
                (telemetry.get("model") if telemetry else "")
                or (response.get("model")
                    if isinstance(response, dict) else "")
                or "")
        except Exception:  # noqa: BLE001
            resolved = ""
        return response, {
            "model_requested": guard["requested_model"],
            "model_resolved": str(config.llm_model or "")[:80]
            or resolved[:80] or "openrouter/free",
            "latency_ms": elapsed,
        }

    return advisor_fn


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
    if args.command == "campaign":
        return cmd_campaign(args)
    return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
