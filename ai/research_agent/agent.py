"""R23 autonomous research agent (research-only, bounded, fail-soft).

Consumes one R22 Research Execution Plan and produces a
:class:`~ai.schemas.research_agent.ResearchAgentResult`.

The agent may only research public information:

- read existing stored CVE references (offline)
- optionally fetch validated public research URLs (bounded, SSRF-guarded)
- optionally ask the configured LLM provider to synthesize supplied documents

It never interacts with the target/program, never scans, never runs Nuclei,
never performs active validation, and never creates a production finding.
LLM output is never authoritative: evidence is only accepted when grounded in
a supplied, hash-verified source document.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ai.research_agent import storage
from ai.research_agent.prompts import build_research_prompt
from ai.research_agent.sources import ResearchSourceCollector, classify_source
from ai.schemas.research_agent import (
    MAX_CLAIMS,
    MAX_INFERENCES,
    MAX_NUCLEI_CANDIDATES,
    MAX_UNKNOWNS,
    RESEARCH_AGENT_RULE_VERSION,
    SOURCE_AVAILABLE,
    STATUS_BLOCKED,
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    ResearchAgentEvidence,
    ResearchAgentInference,
    ResearchAgentNucleiCandidate,
    ResearchAgentResult,
    find_forbidden_terms,
    result_id_for,
)

__all__ = ["ResearchAgent", "ResearchAgentError"]

DEFAULT_AGENT_DIR = storage.DEFAULT_AGENT_DIR


class ResearchAgentError(RuntimeError):
    """Raised when a plan cannot be processed at all."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_intel_loader(cve: str) -> dict:
    try:
        from backend import research_data as rd

        return rd.cve_intelligence(cve)
    except Exception:
        return {"cve": cve, "available": False, "relevance": [], "exploitability": {}}


def _default_payload_loader(cve: str) -> dict:
    try:
        from backend import research_data as rd

        payload, _ = rd._research_payload(cve)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _default_lead_loader(lead_id: str) -> dict:
    try:
        from backend import research_leads

        return research_leads.get_lead(lead_id)
    except Exception:
        return {}


class ResearchAgent:
    """Bounded research agent over R22 plans."""

    def __init__(
        self,
        *,
        sources: ResearchSourceCollector | None = None,
        llm: Any = None,
        llm_enabled: bool = False,
        network_enabled: bool = False,
        agent_dir: str | Path | None = None,
        research_dir: str | Path | None = None,
        forbidden_hosts: set[str] | None = None,
        intel_loader: Callable[[str], dict] | None = None,
        payload_loader: Callable[[str], dict] | None = None,
        lead_loader: Callable[[str], dict] | None = None,
        kb_ingest: bool = False,
        kb_store: Any = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.agent_dir = Path(agent_dir) if agent_dir is not None else DEFAULT_AGENT_DIR
        self.sources = sources or ResearchSourceCollector(
            research_dir=research_dir or "ai_data/research",
            clock=clock,
        )
        self.llm = llm
        self.llm_enabled = bool(llm_enabled)
        self.network_enabled = bool(network_enabled)
        self.forbidden_hosts = forbidden_hosts or set()
        self.intel_loader = intel_loader or _default_intel_loader
        self.payload_loader = payload_loader or _default_payload_loader
        self.lead_loader = lead_loader or _default_lead_loader
        self.kb_ingest = bool(kb_ingest)
        self.kb_store = kb_store
        self.clock = clock
        self.last_kb_ids: list[str] = []

    # -- context ----------------------------------------------------------
    def _context(self, plan: dict) -> dict:
        cve = str(plan.get("cve_id") or "")
        program = str(plan.get("program") or "")
        intel = self.intel_loader(cve) if cve else {}
        payload = self.payload_loader(cve) if cve else {}
        research = payload.get("research") if isinstance(payload, dict) else {}
        if not isinstance(research, dict):
            research = {}
        exploitability = (intel or {}).get("exploitability") or {}
        relevance = {}
        for row in (intel or {}).get("relevance") or []:
            if isinstance(row, dict) and row.get("program") == program:
                relevance = row
                break
        lead = {}
        lead_id = plan.get("lead_id")
        if lead_id:
            lead = self.lead_loader(str(lead_id)) or {}
        if not lead:
            meta = plan.get("metadata") or {}
            lead = {
                "priority_level": meta.get("priority_level"),
                "relevance_level": meta.get("relevance_level"),
                "recommended_next_step": meta.get("recommended_next_step"),
                "blockers": list(plan.get("blockers") or []),
            }
        return {
            "cve_id": cve,
            "program": program,
            "vulnerability_type": research.get("vulnerability_type"),
            "severity": research.get("severity"),
            "exploitability": exploitability,
            "priority": {
                "level": (plan.get("metadata") or {}).get("priority_level"),
                "score": plan.get("priority_score"),
            },
            "relevance": relevance,
            "lead": lead,
            "plan": plan,
            "research": research,
            "intel": intel,
        }

    # -- deterministic pieces --------------------------------------------
    @staticmethod
    def _exploitability_summary(exploitability: dict) -> str:
        if not isinstance(exploitability, dict) or not exploitability:
            return "No positive exploitability signal"
        positives = []
        if exploitability.get("public_poc") == "true":
            positives.append("Public PoC available")
        if exploitability.get("exploit_available") == "true":
            positives.append("Exploit available")
        if exploitability.get("authentication_required") == "false":
            positives.append("Unauthenticated")
        if exploitability.get("user_interaction_required") == "false":
            positives.append("No user interaction required")
        if exploitability.get("exploit_complexity") == "low":
            positives.append("Low attack complexity")
        return "; ".join(positives) if positives else "No positive exploitability signal"

    @staticmethod
    def _deterministic_inferences(context: dict) -> list[ResearchAgentInference]:
        plan = context.get("plan") or {}
        exploitability = context.get("exploitability") or {}
        out: list[ResearchAgentInference] = []
        start = plan.get("recommended_start")
        if start:
            out.append(
                ResearchAgentInference(
                    statement=f"R22 recommends starting with {start} for this plan.",
                    basis="R22 Research Execution Plan (deterministic projection)",
                    confidence="HIGH",
                    model_generated=False,
                )
            )
        if exploitability:
            out.append(
                ResearchAgentInference(
                    statement=ResearchAgent._exploitability_summary(exploitability),
                    basis="R15 exploitability projection",
                    confidence="MEDIUM",
                    model_generated=False,
                )
            )
        return out[:MAX_INFERENCES]

    @staticmethod
    def _deterministic_unknowns(context: dict) -> list[str]:
        out: list[str] = []
        plan = context.get("plan") or {}
        for item in plan.get("unknowns") or []:
            text = str(item).strip()
            if text and text not in out:
                out.append(text)
        for item in (context.get("lead") or {}).get("blockers") or []:
            text = f"blocker: {item}".strip()
            if text and text not in out:
                out.append(text)
        return out[:MAX_UNKNOWNS]

    @staticmethod
    def _nuclei_candidates(research: dict, model_candidates: list) -> list:
        out: list[ResearchAgentNucleiCandidate] = []
        if isinstance(research, dict) and research.get("nuclei_candidate") is True:
            out.append(
                ResearchAgentNucleiCandidate(
                    product=str((research.get("affected_products") or [""])[0] or ""),
                    template_source="research:persisted_projection",
                    request_shape=None,
                    matcher_logic=str(research.get("nuclei_reason") or "") or None,
                )
            )
        for item in model_candidates or []:
            if not isinstance(item, dict):
                continue
            product = str(item.get("product") or "").strip()
            if find_forbidden_terms(product):
                continue
            out.append(
                ResearchAgentNucleiCandidate(
                    product=product,
                    template_source=(
                        str(item.get("template_source")).strip()
                        if item.get("template_source")
                        else None
                    ),
                    request_shape=(
                        str(item.get("request_shape")).strip()
                        if item.get("request_shape")
                        else None
                    ),
                    matcher_logic=(
                        str(item.get("matcher_logic")).strip()
                        if item.get("matcher_logic")
                        else None
                    ),
                )
            )
            if len(out) >= MAX_NUCLEI_CANDIDATES:
                break
        return out[:MAX_NUCLEI_CANDIDATES]

    # -- LLM grounding ----------------------------------------------------
    def _apply_llm(
        self,
        context: dict,
        sources: list,
        data: dict,
        unknowns: list[str],
    ) -> tuple[list[ResearchAgentEvidence], list[ResearchAgentInference]]:
        hash_by_url: dict[str, str] = {}
        for source in sources:
            if source.content_hash:
                hash_by_url[source.url] = source.content_hash
        evidence: list[ResearchAgentEvidence] = []
        inferences: list[ResearchAgentInference] = []

        raw_evidence = data.get("evidence")
        if not isinstance(raw_evidence, list):
            raw_evidence = []
        for item in raw_evidence:
            if not isinstance(item, dict):
                continue
            claim = str(item.get("claim") or "").strip()
            source_url = str(item.get("source_url") or "").strip()
            if not claim:
                continue
            if find_forbidden_terms(claim) or find_forbidden_terms(
                str(item.get("quote") or "")
            ):
                unknowns.append(
                    "Model produced unsupported verdict language in an evidence "
                    "claim; dropped."
                )
                continue
            content_hash = hash_by_url.get(source_url)
            if not content_hash:
                unknowns.append(
                    f"Model cited a source that was not supplied/hashed: "
                    f"{source_url or '<missing>'}"
                )
                continue
            evidence.append(
                ResearchAgentEvidence(
                    evidence_id="ev-"
                    + hashlib.sha256(
                        f"{source_url}\n{claim}".encode("utf-8")
                    ).hexdigest()[:16],
                    source_url=source_url,
                    source_type=classify_source(source_url),
                    claim=claim[:1000],
                    confidence=str(item.get("confidence") or "LOW").upper(),
                    knowledge_ids=[],
                    quote=str(item.get("quote") or "")[:1000],
                    content_hash=content_hash,
                )
            )
            if len(evidence) >= MAX_CLAIMS:
                break

        raw_inferences = data.get("inferences")
        if not isinstance(raw_inferences, list):
            raw_inferences = []
        for item in raw_inferences:
            if not isinstance(item, dict):
                continue
            statement = str(item.get("statement") or "").strip()
            if not statement:
                continue
            if find_forbidden_terms(statement):
                unknowns.append(
                    "Model inference asserted a forbidden verdict; dropped."
                )
                continue
            inferences.append(
                ResearchAgentInference(
                    statement=statement[:1000],
                    basis=str(item.get("basis") or "")[:500],
                    confidence=str(item.get("confidence") or "LOW").upper(),
                    model_generated=True,
                )
            )
            if len(inferences) >= MAX_INFERENCES:
                break
        return evidence, inferences

    def _run_llm(self, context: dict, sources: list, prompt_docs: list) -> tuple[dict, str | None]:
        """Return (parsed_data, error). Never raises."""
        if not self.llm_enabled:
            return {}, None
        if self.llm is None:
            return {}, "LLM enabled but no provider configured"
        try:
            from ai.researcher.researcher import parse_llm_json
        except Exception as exc:  # pragma: no cover - import guard
            return {}, f"LLM parser unavailable: {type(exc).__name__}"

        prompt = build_research_prompt(context, prompt_docs)
        try:
            raw = self.llm.generate(prompt)
        except Exception as exc:
            # Surface the provider's own (key-free) reason, bounded, so a
            # fail-soft result reports the exact cause.
            reason = " ".join(str(exc).split())[:200]
            detail = f"{type(exc).__name__}: {reason}" if reason else type(exc).__name__
            return {}, f"LLM provider error: {detail}"
        try:
            data = parse_llm_json(raw or "")
        except Exception:
            return {}, "LLM returned invalid JSON"
        return data, None

    # -- KB ingestion (optional) -----------------------------------------
    def _maybe_ingest_kb(self, result: ResearchAgentResult) -> None:
        self.last_kb_ids = []
        if not self.kb_ingest or self.kb_store is None:
            return
        try:
            from ai.schemas.knowledge import KnowledgeDocument
        except Exception:
            return
        try:
            deterministic = result.model_dump(mode="json")
            # KB content must be deterministic across runs: drop run-scoped and
            # wall-clock metadata so re-ingestion dedupes by content hash.
            deterministic["run_id"] = ""
            deterministic["report_path"] = None
            deterministic["started_at"] = ""
            deterministic["completed_at"] = ""
            content = storage.render_result_markdown(deterministic)
            doc = KnowledgeDocument(
                knowledge_id="pending",
                title=f"Research Agent: {result.cve_id} -> {result.program}",
                source_url=f"watch-research-agent:{result.result_id}",
                source_type="research_agent",
                content=content,
                summary=result.exploitability_summary,
                evidence_quality="SECONDARY",
                confidence=0.0,
                tags=[
                    f"cve:{result.cve_id}",
                    f"program:{result.program}",
                    "research_agent",
                ],
            )
            stored, _created = self.kb_store.ingest(doc)
            self.last_kb_ids = [stored.knowledge_id]
        except Exception:
            self.last_kb_ids = []

    # -- main -------------------------------------------------------------
    def run_plan(
        self,
        plan: dict,
        *,
        run_id: str,
        deadline: float | None = None,
        dry_run: bool = False,
        network: bool | None = None,
        persist: bool = True,
    ) -> ResearchAgentResult:
        """Run the agent for one R22 plan and (optionally) persist the result."""
        if not isinstance(plan, dict) or not plan.get("plan_id"):
            raise ResearchAgentError("plan must be a dict with a plan_id")

        started_at = _utc_now()
        context = self._context(plan)
        cve = context["cve_id"]
        program = context["program"]
        research = context.get("research") or {}
        references = research.get("references") or []

        unknowns = self._deterministic_unknowns(context)
        network_on = self.network_enabled if network is None else bool(network)
        if dry_run:
            network_on = False

        # 1. stored references (offline)
        try:
            sources = self.sources.collect_stored(cve, references)
        except Exception:
            sources = []
        sources = list(sources)[: self.sources.max_sources]

        # 2. bounded fetching of validated URLs (never in dry-run)
        if network_on and not dry_run:
            sources = self.sources.fetch_sources(
                sources,
                program=program,
                forbidden_hosts=self.forbidden_hosts,
                deadline=deadline,
            )

        # 3. prompt documents (only sources with trusted content)
        prompt_docs = [
            {
                "url": source.url,
                "source_type": source.source_type,
                "title": source.title,
                "content": self.sources.content_for(source),
                "content_hash": source.content_hash,
            }
            for source in sources
        ]

        # 4. optional LLM synthesis
        data: dict = {}
        llm_error = None
        if not dry_run:
            data, llm_error = self._run_llm(context, sources, prompt_docs)
        evidence: list[ResearchAgentEvidence] = []
        inferences = self._deterministic_inferences(context)
        if data:
            model_evidence, model_inferences = self._apply_llm(
                context, sources, data, unknowns
            )
            evidence.extend(model_evidence)
            inferences = model_inferences + inferences
        if llm_error:
            unknowns.append(f"LLM synthesis unavailable: {llm_error}")

        # model-provided unknowns (scrubbed: model text must never carry a
        # forbidden verdict term, even inside an "unknown" question).
        for item in data.get("unknowns") or []:
            text = str(item).strip()
            if not text:
                continue
            if find_forbidden_terms(text):
                note = (
                    "Model produced an unknown containing unsupported verdict "
                    "language; dropped."
                )
                if note not in unknowns:
                    unknowns.append(note)
                continue
            if text not in unknowns:
                unknowns.append(text)
        unknowns = unknowns[:MAX_UNKNOWNS]

        # 5. affected facts (plan/research + model output, bounded)
        def _bounded(values, limit=20):
            out: list[str] = []
            for value in values or []:
                text = str(value).strip()
                if text and not find_forbidden_terms(text) and text not in out:
                    out.append(text)
                if len(out) >= limit:
                    break
            return out

        affected_versions = _bounded(
            (research.get("affected_versions") or [])
            + (data.get("affected_versions") or [])
        )
        affected_components = _bounded(
            (data.get("affected_components") or [])
            + (research.get("components") or [])
            + (research.get("affected_products") or [])
        )
        affected_parameters = _bounded(
            (data.get("affected_parameters") or [])
            + (research.get("parameters") or [])
        )

        # 6. nuclei research candidates (never executed)
        nuclei_candidates = self._nuclei_candidates(
            research, data.get("nuclei_candidates") or []
        )

        # 7. recommended next step
        recommended = (
            str(data.get("recommended_next_step") or "").strip()
            or str((context.get("lead") or {}).get("recommended_next_step") or "").strip()
            or str(plan.get("recommended_start") or "").strip()
            or "REVIEW_REFERENCES"
        )
        if find_forbidden_terms(recommended):
            recommended = "REVIEW_REFERENCES"

        model_summary = str(data.get("exploitability_summary") or "").strip()
        if find_forbidden_terms(model_summary):
            model_summary = ""
        exploitability_summary = model_summary or self._exploitability_summary(
            context.get("exploitability") or {}
        )

        # 8. status derivation (fail-soft, research-only)
        if not sources:
            status = STATUS_BLOCKED
        elif any(
            getattr(source, "status", "") not in (SOURCE_AVAILABLE, "STORED_ONLY")
            for source in sources
        ):
            status = STATUS_PARTIAL
        elif not any(source.content_hash for source in sources):
            # references known but no source body/hash -> research incomplete
            status = STATUS_PARTIAL
        elif llm_error:
            status = STATUS_PARTIAL
        else:
            status = STATUS_COMPLETED

        completed_at = _utc_now()
        result = ResearchAgentResult(
            result_id=result_id_for(plan["plan_id"]),
            run_id=run_id,
            plan_id=plan["plan_id"],
            lead_id=str(plan.get("lead_id") or ""),
            cve_id=cve,
            program=program,
            started_at=started_at,
            completed_at=completed_at,
            status=status,
            sources=sources,
            evidence=evidence,
            inferences=inferences,
            unknowns=unknowns,
            affected_versions=affected_versions,
            affected_components=affected_components,
            affected_parameters=affected_parameters,
            exploitability_summary=exploitability_summary,
            nuclei_candidates=nuclei_candidates,
            recommended_next_step=recommended,
            report_path=None,
            rule_version=RESEARCH_AGENT_RULE_VERSION,
        )

        if persist and not dry_run:
            report_file, _ = storage.write_report(result, base=self.agent_dir)
            result = result.model_copy(update={"report_path": str(report_file)})
            storage.store_result(result, base=self.agent_dir)
            self._maybe_ingest_kb(result)
        return result

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
    ) -> tuple[list[ResearchAgentResult], list[dict]]:
        """Run several plans one at a time; fail-soft per plan.

        Returns ``(results, failures)``. ``per_plan_timeout`` (if given) is
        consulted before each plan; when True the loop stops cleanly.
        """
        results: list[ResearchAgentResult] = []
        failures: list[dict] = []
        for plan in plans:
            if per_plan_timeout is not None and per_plan_timeout():
                failures.append(
                    {"plan_id": plan.get("plan_id"), "error": "time budget expired"}
                )
                break
            try:
                result = self.run_plan(
                    plan,
                    run_id=run_id,
                    deadline=deadline,
                    dry_run=dry_run,
                    network=network,
                    persist=persist,
                )
                results.append(result)
            except Exception as exc:
                failures.append(
                    {"plan_id": plan.get("plan_id"), "error": type(exc).__name__}
                )
        return results, failures
