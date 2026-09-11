"""Stage R24.8 — scheduler adapter for the R24 discovery/research pipeline.

Bridges the existing R23 :class:`~ai.research_agent.scheduler.ResearchScheduler`
to the R24.6 LLM research loop without creating a second scheduler or lock.

When ``WATCH_RESEARCH_DISCOVERY`` is enabled, ``research_cli._build_research_agent``
returns a :class:`DiscoveryResearchAgent` in place of the R23 ``ResearchAgent``.
The scheduler is unchanged: it still owns the window, lock, deadline, plan
selection and fail-soft run loop, and simply calls ``run_plans`` on this
adapter. When discovery is disabled the R23 agent is used and no R24 network
activity occurs.

All traffic (provider discovery and source-body fetching) is routed through the
R24.3 netguard when the components are built from a transport. Tests inject fake
registries/fetchers/LLMs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from ai.collectors.body_extraction import extract_body, sniff_content_type
from ai.research_agent import storage
from ai.research_agent.evidence import DiscoveryBlock
from ai.research_agent.llm_loop import (
    BudgetTracker,
    FetchedSource,
    LLMResearchLoopResult,
    LoopBudgets,
    run_llm_research_loop,
)
from ai.research_agent.queries import CVEResearchMetadata

__all__ = [
    "DiscoveryPlanResult",
    "DiscoveryResearchAgent",
    "load_cve_metadata",
    "build_discovery_registry",
    "build_netguard_fetcher",
]

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def load_cve_metadata(
    cve_id: str, research_dir: str | Path = "ai_data/research"
) -> CVEResearchMetadata:
    """Deterministically derive R24 query metadata from the persisted CVE JSON.

    Reads only public CVE metadata (id/product/version/cwe/type). Never reads
    target/program/asset fields. Falls back to a CVE-id-only metadata object.
    """
    cve_id = str(cve_id or "").strip().upper()
    meta = CVEResearchMetadata(cve_id=cve_id)
    path = Path(research_dir) / f"{cve_id}.cli.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return meta
    if not isinstance(payload, dict):
        return meta
    cve = payload.get("cve") or {}
    research = payload.get("research") or {}
    products = [str(p) for p in (cve.get("products") or []) if p]
    affected = [str(p) for p in (research.get("affected_products") or []) if p]
    versions = [str(v) for v in (research.get("affected_versions") or []) if v]
    cwes = [str(c) for c in (cve.get("cwes") or []) if c]
    vuln_type = str(research.get("vulnerability_type") or "")
    if not cwes:
        match = _CWE_RE.search(vuln_type) or _CWE_RE.search(str(research.get("title") or ""))
        if match:
            cwes = [match.group(0).upper()]
    return CVEResearchMetadata(
        cve_id=cve_id or str(cve.get("id") or ""),
        product=(products[0] if products else (affected[0] if affected else "")),
        component="",
        parameter="",
        version=(versions[0] if versions else ""),
        cwe=(cwes[0] if cwes else ""),
        vulnerability_type=vuln_type,
    )


@dataclass
class DiscoveryPlanResult:
    """Scheduler-facing result shape (matches the R23 agent result contract)."""

    plan_id: str
    result_id: str
    cve_id: str
    program: str
    status: str
    evidence: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    loop_result: LLMResearchLoopResult | None = None
    report_path: str | None = None
    production_finding: bool = False


def build_discovery_registry(
    transport: Any,
    *,
    forbidden_tokens: Iterable[str] = (),
    forbidden_hosts: Iterable[str] | None = None,
    resolver: Any = None,
    max_redirects: int | None = None,
    total_timeout: float | None = None,
):
    """Build the R24.2 registry whose client routes EVERY call via netguard."""
    from ai.research_agent.provider_base import (
        BoundedHTTPClient,
        build_default_registry,
    )

    tokens = tuple(str(t) for t in forbidden_tokens if t)
    kwargs: dict = {}
    if total_timeout is not None:
        kwargs["timeout"] = total_timeout
    client = BoundedHTTPClient(
        transport=transport,
        forbidden_tokens=tokens,
        forbidden_hosts=forbidden_hosts,
        resolver=resolver,
        max_redirects=max_redirects,
        route_through_netguard=True,
        **kwargs,
    )
    return build_default_registry(http_client=client, forbidden_tokens=tokens)


def build_netguard_fetcher(
    transport: Any,
    *,
    program: str | None = None,
    forbidden_hosts: Iterable[str] | None = None,
    resolver: Any = None,
    max_bytes: int = 2_000_000,
    timeout: float = 20.0,
    max_redirects: int = 3,
) -> Callable[[str], FetchedSource | None]:
    """Build a bounded, netguard-validated source-body fetcher."""
    from ai.research_agent.netguard import safe_fetch_with_redirects

    forbidden = set(h for h in (forbidden_hosts or ()) if h)

    def fetcher(url: str) -> FetchedSource | None:
        result = safe_fetch_with_redirects(
            url,
            transport=transport,
            resolver=resolver,
            timeout=timeout,
            max_bytes=max_bytes,
            max_redirects=max_redirects,
            program=program or None,
            forbidden_hosts=forbidden or None,
        )
        if result.error or not result.body:
            return None
        text = result.body
        try:
            raw = result.body.encode("utf-8", errors="replace")
            fmt = sniff_content_type(result.content_type or "", result.final_url or url, raw)
            if fmt == "text/html":
                extracted = extract_body(raw, "text/html", "utf-8")
                if extracted.text:
                    text = extracted.text
        except Exception:
            pass
        return FetchedSource(
            url=result.url,
            content=text,
            final_url=result.final_url,
            redirect_chain=tuple(result.redirect_chain or ()),
            extraction_method=result.content_type or "text",
        )

    return fetcher


class DiscoveryResearchAgent:
    """R23-scheduler-compatible adapter over the R24.6 research loop."""

    def __init__(
        self,
        *,
        transport: Any = None,
        registry: Any = None,
        fetcher: Callable[..., Any] | None = None,
        llm: Any = None,
        llm_enabled: bool = False,
        llm_fallback: Any = None,
        llm_max_retries: int = 0,
        budgets: LoopBudgets | None = None,
        agent_dir: str | Path = storage.DEFAULT_AGENT_DIR,
        research_dir: str | Path = "ai_data/research",
        deadline_seconds: int = 120,
        max_plans: int = 1,
        metadata_loader: Callable[[str], CVEResearchMetadata] | None = None,
    ) -> None:
        self.transport = transport
        self.registry = registry
        self.fetcher = fetcher
        self.llm = llm
        self.llm_enabled = bool(llm_enabled)
        self.llm_fallback = llm_fallback
        self.llm_max_retries = max(0, int(llm_max_retries or 0))
        self.budgets = budgets or LoopBudgets(
            max_rounds=1,
            max_queries_per_plan=3,
            round2_reserve=0,
            max_queries_per_run=3,
            max_discovered=5,
            max_fetched_per_plan=3,
            max_fetched_per_run=3,
            max_bytes_per_run=4_000_000,
            max_llm_calls_per_plan=1,
            max_llm_calls_per_run=1,
        )
        self.agent_dir = Path(agent_dir)
        self.research_dir = Path(research_dir)
        self.deadline_seconds = max(int(deadline_seconds), 1)
        self.max_plans = max(int(max_plans), 0)
        self.metadata_loader = metadata_loader or (
            lambda cve: load_cve_metadata(cve, self.research_dir)
        )
        self.last_kb_ids: list[str] = []

    # -- component resolution --------------------------------------------
    def _components(self, program: str):
        forbidden_tokens = tuple(t for t in (program,) if t)
        if self.registry is not None:
            registry = self.registry
        else:
            registry = build_discovery_registry(
                self.transport, forbidden_tokens=forbidden_tokens
            )
        if self.fetcher is not None:
            fetcher = self.fetcher
        else:
            fetcher = build_netguard_fetcher(
                self.transport,
                program=program or None,
                max_bytes=self.budgets.max_bytes_per_source,
            )
        return registry, fetcher, forbidden_tokens

    def run_plan(
        self,
        plan: Mapping[str, Any],
        *,
        run_id: str,
        deadline: float | None = None,
        dry_run: bool = False,
        network: bool | None = None,
        persist: bool = True,
    ) -> DiscoveryPlanResult:
        plan_id = str(plan.get("plan_id") or "")
        cve_id = str(plan.get("cve_id") or "")
        program = str(plan.get("program") or "")

        if dry_run:
            return DiscoveryPlanResult(
                plan_id=plan_id,
                result_id="",
                cve_id=cve_id,
                program=program,
                status="RESEARCH_BLOCKED",
            )

        metadata = self.metadata_loader(cve_id)
        registry, fetcher, forbidden_tokens = self._components(program)
        result = run_llm_research_loop(
            plan=dict(plan),
            metadata=metadata,
            registry=registry,
            fetcher=fetcher,
            llm=self.llm,
            llm_enabled=self.llm_enabled,
            llm_fallback=self.llm_fallback,
            llm_max_retries=self.llm_max_retries,
            forbidden_tokens=forbidden_tokens,
            budgets=self.budgets,
        )
        if persist:
            try:
                storage.store_research_loop(result, base=self.agent_dir)
            except Exception:
                pass
        evidence = [e for r in result.rounds for e in r.discovery.evidence]
        sources = [s for r in result.rounds for s in r.discovery.sources]
        return DiscoveryPlanResult(
            plan_id=plan_id,
            result_id=result.result_id,
            cve_id=cve_id,
            program=program,
            status=result.status,
            evidence=evidence,
            sources=sources,
            loop_result=result,
        )

    def run_plans(
        self,
        plans: list[dict],
        *,
        run_id: str,
        deadline: float | None = None,
        dry_run: bool = False,
        network: bool | None = None,
        persist: bool = True,
        per_plan_timeout: Callable[[], bool] | None = None,
    ) -> tuple[list[DiscoveryPlanResult], list[dict]]:
        results: list[DiscoveryPlanResult] = []
        failures: list[dict] = []
        for plan in list(plans or [])[: self.max_plans]:
            if per_plan_timeout is not None and per_plan_timeout():
                failures.append(
                    {"plan_id": plan.get("plan_id"), "error": "time budget expired"}
                )
                break
            if deadline is not None:
                try:
                    import time

                    if time.monotonic() >= float(deadline):
                        failures.append(
                            {
                                "plan_id": plan.get("plan_id"),
                                "error": "time budget expired",
                            }
                        )
                        break
                except Exception:
                    pass
            try:
                results.append(
                    self.run_plan(
                        plan,
                        run_id=run_id,
                        deadline=deadline,
                        dry_run=dry_run,
                        network=network,
                        persist=persist,
                    )
                )
            except Exception as exc:
                failures.append(
                    {"plan_id": plan.get("plan_id"), "error": type(exc).__name__}
                )
        return results, failures
