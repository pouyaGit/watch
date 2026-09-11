"""Stage R24.6 — bounded, evidence-grounded LLM research loop.

Orchestrates at most two deterministic discovery rounds around one optional
LLM analysis call per round::

    DISCOVER -> RANK -> DEDUP -> FETCH -> INTEGRATE EVIDENCE
             -> LLM ANALYSIS -> GAP DETECTION
             -> (optionally ONE bounded second round) -> RESULT

Safety / determinism:

- Everything except the LLM response is deterministic and sorted.
- The LLM receives only the sanitized :class:`ResearchLLMContext` (public
  research only; no target/program/asset data). It never receives a target
  URL/host/IP, endpoint, response, credential, cookie or header.
- LLM output never becomes evidence and can never upgrade a source's
  deterministic trust tier/category. Model-suggested queries are validated by
  the R24.1 constraints and mapped to approved templates; the model never
  executes a query directly.
- Every external component fails soft: provider/fetch/DNS/LLM failures leave
  the deterministic result intact. No evidence is fabricated.
- ``production_finding`` is forced ``False``; the result is public-research-only.
- No network is performed by this module itself: providers, the fetcher and the
  LLM are injected. Tests use fakes; no live network is required.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from pydantic import BaseModel, Field, field_validator

from ai.research_agent.dedup import canonical_url, dedup_discovered_sources, with_content_hash
from ai.research_agent.fetch_priority import order_for_fetch
from ai.research_agent.discovery_contract import (
    DiscoveredSource,
    DiscoveryQuery,
)
from ai.research_agent.evidence import (
    DISCOVERY_RULE_VERSION,
    DiscoveryBlock,
    integrate_discovery,
)
from ai.research_agent.llm_research import (
    LLM_ANALYSIS_RULE_VERSION,
    MAX_CONTEXT_CHARS,
    PROMPT_RULE_VERSION,
    LLMAnalysis,
    build_llm_context,
    build_research_analysis_prompt,
    map_suggestion_to_discovery_query,
    parse_llm_analysis,
    validate_and_sanitize_analysis,
)
from ai.research_agent.llm_reliability import (
    LLM_MALFORMED_RESPONSE,
    LLM_SUCCESS,
    LLM_UNKNOWN_ERROR,
    LLMOutcome,
    call_llm,
    is_fallback_eligible,
    is_retry_eligible,
    sanitize_llm_error,
)
from ai.research_agent.queries import (
    CVEResearchMetadata,
    QueryBuilder,
)
from ai.research_agent.ranking import rank_sources
from ai.schemas.research_agent import SOURCE_FAILED

__all__ = [
    "STATUS_COMPLETED",
    "STATUS_PARTIAL",
    "STATUS_BLOCKED",
    "STATUS_FAILED",
    "LOOP_RULE_VERSION",
    "MAX_ROUNDS",
    "MAX_QUERIES_PER_PLAN",
    "MAX_QUERIES_PER_RUN",
    "MAX_DISCOVERED",
    "MAX_FETCHED_PER_PLAN",
    "MAX_FETCHED_PER_RUN",
    "MAX_BYTES_PER_SOURCE",
    "MAX_BYTES_PER_RUN",
    "MAX_LLM_CALLS_PER_PLAN",
    "MAX_LLM_CALLS_PER_RUN",
    "LoopBudgets",
    "BudgetTracker",
    "FetchedSource",
    "LoopRound",
    "LLMResearchLoopResult",
    "loop_result_id_for",
    "run_llm_research_loop",
]

STATUS_COMPLETED = "RESEARCH_COMPLETED"
STATUS_PARTIAL = "RESEARCH_PARTIAL"
STATUS_BLOCKED = "RESEARCH_BLOCKED"
STATUS_FAILED = "RESEARCH_FAILED"

LOOP_RULE_VERSION = "r24-loop-1"

MAX_ROUNDS = 2
MAX_QUERIES_PER_PLAN = 12
MAX_QUERIES_PER_RUN = 40
MAX_DISCOVERED = 40
MAX_FETCHED_PER_PLAN = 12
MAX_FETCHED_PER_RUN = 40
MAX_BYTES_PER_SOURCE = 2_000_000
MAX_BYTES_PER_RUN = 8_000_000
MAX_LLM_CALLS_PER_PLAN = 2
MAX_LLM_CALLS_PER_RUN = 3


@dataclass(frozen=True)
class LoopBudgets:
    """Hard, bounded limits (R24 scope §9)."""

    max_rounds: int = MAX_ROUNDS
    max_queries_per_plan: int = MAX_QUERIES_PER_PLAN
    # Round-1 query cap is reduced by this reserve (when a round 2 is
    # permitted) so a gap-directed second round can still run without ever
    # exceeding ``max_queries_per_plan`` in total.
    round2_reserve: int = 4
    max_queries_per_run: int = MAX_QUERIES_PER_RUN
    max_discovered: int = MAX_DISCOVERED
    max_fetched_per_plan: int = MAX_FETCHED_PER_PLAN
    max_fetched_per_run: int = MAX_FETCHED_PER_RUN
    max_bytes_per_source: int = MAX_BYTES_PER_SOURCE
    max_bytes_per_run: int = MAX_BYTES_PER_RUN
    max_llm_calls_per_plan: int = MAX_LLM_CALLS_PER_PLAN
    max_llm_calls_per_run: int = MAX_LLM_CALLS_PER_RUN

    def as_dict(self) -> dict:
        return {
            "max_rounds": self.max_rounds,
            "max_queries_per_plan": self.max_queries_per_plan,
            "round2_reserve": self.round2_reserve,
            "max_queries_per_run": self.max_queries_per_run,
            "max_discovered": self.max_discovered,
            "max_fetched_per_plan": self.max_fetched_per_plan,
            "max_fetched_per_run": self.max_fetched_per_run,
            "max_bytes_per_source": self.max_bytes_per_source,
            "max_bytes_per_run": self.max_bytes_per_run,
            "max_llm_calls_per_plan": self.max_llm_calls_per_plan,
            "max_llm_calls_per_run": self.max_llm_calls_per_run,
        }


@dataclass
class BudgetTracker:
    """Mutable run-level accounting shared across plans in one run."""

    budgets: LoopBudgets = field(default_factory=LoopBudgets)
    queries_used: int = 0
    discovered_used: int = 0
    fetched_used: int = 0
    bytes_used: int = 0
    llm_calls_used: int = 0

    def can_use_query(self) -> bool:
        return self.queries_used < self.budgets.max_queries_per_run

    def consume_query(self) -> None:
        self.queries_used += 1

    def can_discover(self) -> bool:
        return self.discovered_used < self.budgets.max_discovered

    def consume_discovered(self, count: int = 1) -> None:
        self.discovered_used += max(0, int(count))

    def can_fetch(self) -> bool:
        return self.fetched_used < self.budgets.max_fetched_per_run

    def consume_fetch(self, nbytes: int = 0) -> None:
        self.fetched_used += 1
        self.bytes_used += max(0, int(nbytes or 0))

    def can_spend_bytes(self, nbytes: int) -> bool:
        return (self.bytes_used + max(0, int(nbytes or 0))) <= self.budgets.max_bytes_per_run

    def can_call_llm(self) -> bool:
        return self.llm_calls_used < self.budgets.max_llm_calls_per_run

    def llm_calls_remaining(self) -> int:
        return max(0, self.budgets.max_llm_calls_per_run - self.llm_calls_used)

    def consume_llm(self, count: int = 1) -> None:
        self.llm_calls_used += max(0, int(count))


@dataclass(frozen=True)
class FetchedSource:
    """Bounded, already-materialized public content for one URL.

    This is the ONLY fetcher return type. It carries no target data and no
    credentials; the loop never fetches on its own.
    """

    url: str
    content: str = ""
    final_url: str = ""
    redirect_chain: tuple[str, ...] = ()
    extraction_method: str = "text"


Fetcher = Callable[[str], "FetchedSource | None"]


# ---------------------------------------------------------------------------
# Result models (additive, serializable)
# ---------------------------------------------------------------------------
class LoopRound(BaseModel):
    round_number: int = 1
    queries: list[str] = Field(default_factory=list)
    query_provenance: list[dict] = Field(default_factory=list)
    provider_failures: list[dict] = Field(default_factory=list)
    discovered_sources: int = 0
    fetched_sources: int = 0
    relevant_sources: int = 0
    evidence_count: int = 0
    discovery: DiscoveryBlock = Field(default_factory=DiscoveryBlock)
    analysis: LLMAnalysis | None = None
    gaps: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    llm_status: str = "disabled"
    llm_error: str | None = None
    llm_model: str | None = None
    # R24.11 deterministic failure class (None on success/disabled).
    llm_failure_kind: str | None = None
    production_finding: bool = False

    @field_validator("production_finding")
    @classmethod
    def _never_finding(cls, value: bool) -> bool:
        if value:
            raise ValueError("loop rounds are never production findings")
        return False


class LLMResearchLoopResult(BaseModel):
    """Deterministic, additive R24.6 research-loop artifact."""

    rule_version: str = DISCOVERY_RULE_VERSION
    loop_rule_version: str = LOOP_RULE_VERSION
    prompt_rule_version: str = PROMPT_RULE_VERSION
    analysis_rule_version: str = LLM_ANALYSIS_RULE_VERSION
    result_id: str = ""
    plan_id: str = ""
    cve_id: str = ""
    status: str = STATUS_PARTIAL
    rounds: list[LoopRound] = Field(default_factory=list)
    analysis: LLMAnalysis | None = None
    llm_status: str = "disabled"
    llm_error: str | None = None
    llm_model: str | None = None
    llm_failure_kind: str | None = None
    gaps: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    provider_failures: list[dict] = Field(default_factory=list)
    budgets: dict = Field(default_factory=dict)
    public_research_only: bool = True
    production_finding: bool = False

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in (STATUS_COMPLETED, STATUS_PARTIAL, STATUS_BLOCKED, STATUS_FAILED):
            raise ValueError(f"invalid research-loop status: {value!r}")
        return text

    @field_validator("public_research_only")
    @classmethod
    def _public_only(cls, value: bool) -> bool:
        if not value:
            raise ValueError("research-loop results are public-research-only")
        return True

    @field_validator("production_finding")
    @classmethod
    def _never_finding(cls, value: bool) -> bool:
        if value:
            raise ValueError("research-loop results are never production findings")
        return False


def loop_result_id_for(plan_id: str, cve_id: str) -> str:
    basis = "\n".join([LOOP_RULE_VERSION, str(plan_id or ""), str(cve_id or "")])
    return "loop-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Loop internals
# ---------------------------------------------------------------------------
def _safe_error(exc: BaseException) -> str:
    reason = " ".join(str(exc).split())[:200]
    return f"{type(exc).__name__}: {reason}" if reason else type(exc).__name__


def _dedup_queries(queries: Sequence[DiscoveryQuery]) -> list[DiscoveryQuery]:
    seen: set[str] = set()
    out: list[DiscoveryQuery] = []
    for query in queries:
        if query.query_id in seen:
            continue
        seen.add(query.query_id)
        out.append(query)
    return out


def _discover(
    queries: Sequence[DiscoveryQuery],
    *,
    registry: Any,
    tracker: BudgetTracker,
    failures: list[dict],
) -> list[DiscoveredSource]:
    collected: list[DiscoveredSource] = []
    for query in queries:
        if not tracker.can_use_query() or not tracker.can_discover():
            break
        tracker.consume_query()
        try:
            results = registry.discover(query.provider, query)
        except Exception as exc:  # provider fail-soft
            failures.append(
                {
                    "provider": query.provider,
                    "template_id": query.template_id,
                    "error": _safe_error(exc),
                }
            )
            continue
        for item in results or ():
            if not isinstance(item, DiscoveredSource):
                continue
            if not tracker.can_discover():
                break
            if not str(item.url or "").strip():
                continue
            tracker.consume_discovered()
            collected.append(item)
    return collected


def _fetch_sources(
    sources: Sequence[DiscoveredSource],
    *,
    fetcher: Fetcher | None,
    content_by_source_id: Mapping[str, str],
    tracker: BudgetTracker,
    budgets: LoopBudgets,
) -> tuple[list[DiscoveredSource], dict[str, str], int]:
    """Attach materialized content/hash to sources (bounded, fail-soft)."""
    out: list[DiscoveredSource] = []
    content_map: dict[str, str] = {}
    fetched = 0
    for source in sources:
        sid = str(source.source_id or "")
        canonical = canonical_url(source)

        # Pre-materialized content (no fetch) takes precedence.
        provided = content_by_source_id.get(sid) or content_by_source_id.get(canonical)
        if provided:
            updated = with_content_hash(source, provided)
            content_map[updated.source_id] = str(provided)[:MAX_CONTEXT_CHARS]
            out.append(updated)
            continue

        if source.content_hash:
            out.append(source)
            continue

        if (
            fetcher is None
            or fetched >= budgets.max_fetched_per_plan
            or not tracker.can_fetch()
        ):
            out.append(source)
            continue

        try:
            result = fetcher(source.final_url or source.url)
        except Exception:
            result = None
        if result is None or not getattr(result, "content", ""):
            out.append(source.model_copy(update={"status": SOURCE_FAILED}))
            continue

        body = str(result.content)[: budgets.max_bytes_per_source]
        if not tracker.can_spend_bytes(len(body)):
            out.append(source.model_copy(update={"status": SOURCE_FAILED}))
            continue
        tracker.consume_fetch(len(body))
        fetched += 1

        updated = with_content_hash(source, body)
        redirect_chain = list(getattr(result, "redirect_chain", ()) or [])
        final_url = str(getattr(result, "final_url", "") or "") or updated.final_url
        updated = updated.model_copy(
            update={
                "final_url": final_url or updated.final_url,
                "redirect_chain": redirect_chain or updated.redirect_chain,
            }
        )
        content_map[updated.source_id] = body[:MAX_CONTEXT_CHARS]
        out.append(updated)
    return out, content_map, fetched


def _evaluate_llm_attempt(
    provider: Any,
    prompt: str,
    context: Any,
    forbidden_tokens: tuple[str, ...],
) -> tuple[LLMOutcome, Any]:
    """One provider attempt + parse/validate. Never raises."""
    outcome = call_llm(provider, prompt)
    if outcome.kind != LLM_SUCCESS:
        return outcome, None
    try:
        parsed = parse_llm_analysis(outcome.content)
        validation = validate_and_sanitize_analysis(
            parsed, context, forbidden_tokens=forbidden_tokens
        )
    except Exception as exc:
        return (
            LLMOutcome(
                kind=LLM_MALFORMED_RESPONSE,
                error=sanitize_llm_error(exc),
                model=outcome.model,
            ),
            None,
        )
    return outcome, validation


def _attempt_llm_sequence(
    *,
    primary: Any,
    fallback: Any,
    prompt: str,
    context: Any,
    forbidden_tokens: tuple[str, ...],
    budget_remaining: int,
    max_retries: int,
) -> tuple[LLMOutcome, Any, int]:
    """Bounded primary → fallback → retry sequence.

    Every attempt (primary, fallback, retry) consumes exactly one unit of the
    shared LLM budget; the total number of attempts never exceeds
    ``budget_remaining``. Authentication/configuration failures are never
    retried or failed over.
    """
    providers = [p for p in (primary, fallback) if p is not None]
    attempts = 0
    last = LLMOutcome(kind=LLM_UNKNOWN_ERROR, error="no provider attempt made")
    for provider in providers:
        retries = 0
        while attempts < budget_remaining:
            outcome, validation = _evaluate_llm_attempt(
                provider, prompt, context, forbidden_tokens
            )
            attempts += 1
            last = outcome
            if validation is not None:
                return outcome, validation, attempts
            if retries < max_retries and is_retry_eligible(outcome.kind):
                retries += 1
                continue
            break
        if attempts >= budget_remaining:
            break
        if not is_fallback_eligible(last.kind):
            break
    return last, None, attempts


def _run_round(
    *,
    round_number: int,
    queries: Sequence[DiscoveryQuery],
    registry: Any,
    fetcher: Fetcher | None,
    metadata: CVEResearchMetadata,
    content_by_source_id: Mapping[str, str],
    tracker: BudgetTracker,
    budgets: LoopBudgets,
    plan_id: str,
    result_id: str,
    forbidden_tokens: tuple[str, ...],
    llm: Any,
    llm_enabled: bool,
    llm_calls_used: int,
    llm_fallback: Any = None,
    llm_max_retries: int = 0,
) -> tuple[LoopRound, int]:
    failures: list[dict] = []
    collected = _discover(queries, registry=registry, tracker=tracker, failures=failures)
    ranked = rank_sources(collected, metadata)
    deduped = dedup_discovered_sources(ranked)
    # R24.10: spend the bounded fetch budget on CVE-specific/structured sources
    # first; generic search/landing pages are fetched last (and never starve a
    # high-value TRUSTED source). Ranking scores are unchanged — only the fetch
    # order is affected.
    fetched_sources, content_map, fetched_count = _fetch_sources(
        order_for_fetch(deduped, metadata),
        fetcher=fetcher,
        content_by_source_id=content_by_source_id,
        tracker=tracker,
        budgets=budgets,
    )
    required_tokens = [metadata.cve_id] if metadata.cve_id else None
    block = integrate_discovery(
        fetched_sources,
        content_map,
        discovery_enabled=True,
        plan_id=plan_id,
        result_id=result_id,
        required_content_tokens=required_tokens,
    )

    analysis: LLMAnalysis | None = None
    llm_status = "disabled"
    llm_error: str | None = None
    llm_model: str | None = None
    llm_failure_kind: str | None = None
    llm_calls_made = 0
    gaps: list[str] = list(block.unknowns)

    # R24.11: the shared budget bounds primary + fallback + retries. A budget of
    # 1 therefore means exactly one provider attempt.
    plan_remaining = max(0, budgets.max_llm_calls_per_plan - llm_calls_used)
    budget_remaining = min(plan_remaining, tracker.llm_calls_remaining())

    if llm_enabled and llm is not None and budget_remaining > 0:
        context = build_llm_context(
            block,
            metadata,
            content_by_source_id=content_map,
            forbidden_tokens=forbidden_tokens,
        )
        prompt = build_research_analysis_prompt(context)
        outcome, validation, llm_calls_made = _attempt_llm_sequence(
            primary=llm,
            fallback=llm_fallback,
            prompt=prompt,
            context=context,
            forbidden_tokens=forbidden_tokens,
            budget_remaining=budget_remaining,
            max_retries=max(0, int(llm_max_retries or 0)),
        )
        tracker.consume_llm(llm_calls_made)
        llm_model = outcome.model or getattr(llm, "model", None)
        if validation is not None:
            analysis = validation.analysis
            llm_status = "ok"
            for item in validation.dropped:
                if item not in block.unknowns:
                    block.unknowns.append(item)
            block.unknown_count = len(block.unknowns)
            gaps = list(dict.fromkeys(list(analysis.gaps) + list(block.unknowns)))
        else:
            llm_status = "failed"
            llm_failure_kind = outcome.kind
            llm_error = outcome.error or outcome.kind
    elif llm_enabled and llm is None:
        llm_status = "unavailable"
        llm_error = "LLM enabled but no provider configured"

    return LoopRound(
        round_number=round_number,
        queries=[q.query for q in queries],
        query_provenance=[
            {
                "query_id": q.query_id,
                "template_id": q.template_id,
                "provider": q.provider,
            }
            for q in queries
        ],
        provider_failures=failures,
        discovered_sources=block.discovered_sources,
        fetched_sources=block.fetched_sources,
        relevant_sources=block.relevant_sources,
        evidence_count=block.evidence_count,
        discovery=block,
        analysis=analysis,
        gaps=gaps[:40],
        unknowns=list(block.unknowns),
        llm_status=llm_status,
        llm_error=llm_error,
        llm_model=llm_model,
        llm_failure_kind=llm_failure_kind,
    ), llm_calls_made


def _round2_queries(
    *,
    analysis: LLMAnalysis | None,
    metadata: CVEResearchMetadata,
    used_template_ids: set[str],
    forbidden_tokens: tuple[str, ...],
    remaining_queries: int,
) -> list[DiscoveryQuery]:
    """Deterministically build gap-directed round-2 queries.

    Model suggestions are only used to *select* among approved templates and
    only after passing the R24.1 safety constraints. If none are usable, the
    remaining unused templates are used, in fixed order.
    """
    out: list[DiscoveryQuery] = []
    seen: set[str] = set()
    builder = QueryBuilder(forbidden_tokens=forbidden_tokens)
    approved = builder.build_queries(metadata)

    suggestions = list(analysis.suggested_queries) if analysis else []
    for suggestion in suggestions:
        query = map_suggestion_to_discovery_query(
            suggestion, metadata, forbidden_tokens=forbidden_tokens
        )
        if query is None or query.query_id in seen:
            continue
        if used_template_ids and query.template_id in used_template_ids:
            continue
        seen.add(query.query_id)
        out.append(query)
        if len(out) >= remaining_queries:
            return out

    for query in approved:
        if len(out) >= remaining_queries:
            break
        if query.query_id in seen:
            continue
        if query.template_id in used_template_ids:
            continue
        seen.add(query.query_id)
        out.append(query)
    return out


def run_llm_research_loop(
    *,
    plan: Mapping[str, Any],
    metadata: CVEResearchMetadata,
    registry: Any,
    fetcher: Fetcher | None = None,
    llm: Any = None,
    llm_enabled: bool = False,
    llm_fallback: Any = None,
    llm_max_retries: int = 0,
    forbidden_tokens: Iterable[str] = (),
    content_by_source_id: Mapping[str, str] | None = None,
    budgets: LoopBudgets | None = None,
    tracker: BudgetTracker | None = None,
) -> LLMResearchLoopResult:
    """Run the bounded R24.6 research loop for one R22 plan.

    ``registry`` is an R24.2 provider registry, ``fetcher`` materializes public
    content, and ``llm`` is the existing OpenRouter-compatible provider. All
    three are injected; this function performs no network itself.
    """
    budgets = budgets or LoopBudgets()
    tracker = tracker or BudgetTracker(budgets=budgets)
    forbidden = tuple(sorted({str(t).strip().lower() for t in forbidden_tokens if t}))
    plan_id = str(plan.get("plan_id") or "")
    cve_id = str(plan.get("cve_id") or metadata.cve_id or "")
    result_id = loop_result_id_for(plan_id, cve_id)
    seed_content = dict(content_by_source_id or {})

    rounds: list[LoopRound] = []
    used_templates: set[str] = set()
    all_failures: list[dict] = []
    llm_calls_used = 0

    # Round 1: full deterministic template set, bounded by plan + run budgets.
    # When a round 2 is permitted, reserve a few query slots for gaps.
    reserve = budgets.round2_reserve if budgets.max_rounds >= 2 else 0
    round1_cap = max(1, budgets.max_queries_per_plan - max(0, reserve))
    round1 = QueryBuilder(forbidden_tokens=forbidden).build_queries(metadata)
    round1 = _dedup_queries(round1)[:round1_cap]
    first, first_calls = _run_round(
        round_number=1,
        queries=round1,
        registry=registry,
        fetcher=fetcher,
        metadata=metadata,
        content_by_source_id=seed_content,
        tracker=tracker,
        budgets=budgets,
        plan_id=plan_id,
        result_id=result_id,
        forbidden_tokens=forbidden,
        llm=llm,
        llm_enabled=llm_enabled,
        llm_calls_used=llm_calls_used,
        llm_fallback=llm_fallback,
        llm_max_retries=llm_max_retries,
    )
    rounds.append(first)
    used_templates.update(q.template_id for q in round1)
    llm_calls_used += first_calls

    # Optional single gap-directed round 2.
    remaining_plan_queries = max(0, budgets.max_queries_per_plan - len(round1))
    if (
        budgets.max_rounds >= 2
        and first.gaps
        and remaining_plan_queries > 0
        and tracker.can_use_query()
        and tracker.can_discover()
    ):
        round2_queries = _round2_queries(
            analysis=first.analysis,
            metadata=metadata,
            used_template_ids=used_templates,
            forbidden_tokens=forbidden,
            remaining_queries=min(remaining_plan_queries, budgets.max_queries_per_plan),
        )
        if round2_queries:
            second, second_calls = _run_round(
                round_number=2,
                queries=round2_queries,
                registry=registry,
                fetcher=fetcher,
                metadata=metadata,
                content_by_source_id=seed_content,
                tracker=tracker,
                budgets=budgets,
                plan_id=plan_id,
                result_id=result_id,
                forbidden_tokens=forbidden,
                llm=llm,
                llm_enabled=llm_enabled,
                llm_calls_used=llm_calls_used,
                llm_fallback=llm_fallback,
                llm_max_retries=llm_max_retries,
            )
            rounds.append(second)
            llm_calls_used += second_calls

    final = rounds[-1]
    for round_result in rounds:
        all_failures.extend(round_result.provider_failures)

    total_discovered = sum(r.discovered_sources for r in rounds)
    total_evidence = sum(r.evidence_count for r in rounds)
    llm_status = final.llm_status
    if llm_enabled and any(r.llm_status == "ok" for r in rounds):
        llm_status = "ok"

    if total_discovered == 0:
        status = STATUS_BLOCKED
    elif total_evidence > 0 and llm_status in ("ok", "disabled"):
        status = STATUS_COMPLETED
    else:
        status = STATUS_PARTIAL

    return LLMResearchLoopResult(
        result_id=result_id,
        plan_id=plan_id,
        cve_id=cve_id,
        status=status,
        rounds=rounds,
        analysis=final.analysis,
        llm_status=llm_status,
        llm_error=final.llm_error,
        llm_model=final.llm_model,
        llm_failure_kind=final.llm_failure_kind,
        gaps=list(final.gaps),
        unknowns=list(final.unknowns),
        provider_failures=all_failures,
        budgets=budgets.as_dict(),
    )
