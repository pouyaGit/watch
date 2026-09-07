"""Research-only batch CVE research orchestration.

Thin orchestration over the existing validated single-CVE flow and the
existing Nuclei components. This module contains no scanning, no live
HTTP, no browser, no DNS, no subprocess, and no finding logic of its
own:

- Per-CVE research reuses ``ai.research_cli._research_single_cve``
  (CVE collection -> reference discovery -> reference collection ->
  research/correlation), injectable for offline tests.
- The Nuclei candidate lane reuses ``NucleiDecisionEngine``,
  ``DetectionSpecExtractor``, and ``NucleiPipeline.prepare_offline``
  only. ``prepare_for_watch`` is never referenced here on purpose:
  batch research performs no Watch target selection and no asset
  fingerprinting. The offline selection is always empty
  (candidate_count=0, no targets), so no Watch asset is contacted and
  the dry-run artifact records zero executed commands.
- No SealedFinding / 5J / CONFIRMED materialization exists anywhere
  in this lane; results are marked ``authoritative=False``.

One failing CVE never aborts the batch: every per-CVE step is guarded
and recorded as a structured result.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

BATCH_VERSION = "cve-batch-1"

DEFAULT_RESEARCH_DIR = Path("ai_data/research")
DEFAULT_TEMPLATE_DIR = Path("ai_data/nuclei/generated")
DEFAULT_REPORT_DIR = Path("agent-reports")

# Fixed per-CVE result keys (insertion order is the serialized order).
RESULT_KEYS = (
    "cve",
    "research_status",
    "nuclei_candidate",
    "decision",
    "decision_confidence",
    "template_generated",
    "semantic_validation",
    "offline_preparation",
    "artifacts",
    "authoritative",
    "nuclei_error",
    "error",
    "reference_quality",
)


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------


def parse_cve_list(raw: str) -> list[str]:
    """Parse a comma/whitespace-separated CVE string (deterministic)."""
    parts = re.split(r"[,\s]+", (raw or "").strip().upper())
    return [part for part in parts if part]


def load_cve_list_file(path: str | Path) -> list[str]:
    """Load CVE IDs from a file (one per line, ``#`` comments ignored)."""
    cves: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip().upper()
        if not line or line.startswith("#"):
            continue
        # Allow trailing comments and comma-separated entries per line.
        line = line.split("#", 1)[0]
        cves.extend(parse_cve_list(line))
    return cves


# ---------------------------------------------------------------------------
# Offline Nuclei stage (reuses existing components, no duplication)
# ---------------------------------------------------------------------------


def build_offline_selection(cve_id: str):
    """Empty caller-provided selection: no assets, no fingerprinting."""
    from ai.correlator.watch_targets import WatchTargetSelection

    return WatchTargetSelection(
        cve_id=cve_id,
        targets=[],
        excluded=[],
        candidate_count=0,
    )


def _make_cached_research_fn(reference_cache, quality_sink=None):
    """Build a per-batch ``research_fn`` that consults ``reference_cache``.

    The wrapper re-orchestrates the existing reference discovery
    + fetch + context-building + LLM call components so that
    every per-URL ``ReferenceCollector.fetch`` invocation goes
    through the shared ``BatchReferenceCache``. Each cache miss
    is the first fetch of a URL in this batch; each cache hit
    is a reuse of the already-fetched ``ReferenceDocument``.
    Reused documents are still ranked per-CVE by the existing
    ``build_research_contexts`` pipeline — CVE-specific LLM
    conclusions are never shared across distinct CVEs.

    Before ``SecurityResearcher`` receives the contexts, the
    deterministic ``gate_reference_contexts`` quality gate filters
    them (invalid entries removed, order preserved, nothing
    fabricated). When ``quality_sink`` is provided it receives
    exactly one boolean per gated CVE: True when the gate removed
    at least one entry from a non-empty context list.

    The returned per-CVE payload also carries its own counts-only
    ``reference_quality`` (``{"checked": 1, "rejected": 0|1}``)
    derived from the SAME gate result — the observability source
    of truth consumed by ``research_one_cve`` (no recalculation
    downstream). ``checked`` is always 1 (one gated CVE);
    ``rejected`` mirrors the sink boolean.
    """

    def research_fn(cve_id: str, skip_llm: bool = False) -> dict:
        from ai.collectors.cve import CVECollector
        from ai.collectors.discovery import ReferenceDiscovery
        from ai.correlator.assessment import assess_asset
        from ai.correlator.candidates import candidate_assets
        from ai.researcher.research_context import build_research_contexts
        from ai.researcher.researcher import SecurityResearcher
        from ai.schemas.reference import ReferenceContext

        from ai.research_cli import _load_assets

        assets, index = _load_assets()
        found = CVECollector().get_by_ids([cve_id])
        lookup = {cve.title: cve for cve in found}
        cve = lookup.get(cve_id)
        if cve is None:
            raise RuntimeError(f"CVE not found via NVD: {cve_id}")

        candidates = candidate_assets(cve, index)
        items = []
        for asset in candidates:
            items.extend(assess_asset(asset=asset, cve=cve))

        programs = sorted({item.program_name for item in items})
        asset_names = sorted({item.subdomain for item in items})
        technologies = sorted({item.technology for item in items})

        with ReferenceDiscovery() as discovery:
            discovered = discovery.discover(cve, limit=5)
        # Per-URL fetch through the shared cache. ``cache.fetch``
        # returns the cached ``ReferenceDocument`` on a hit, or
        # invokes ``ReferenceCollector.fetch`` (the existing
        # primitive) on a miss. Hard misses (``None``) are never
        # cached, matching the spec's "successful deterministic
        # reference material only" policy.
        selected = discovered.sources[:5]
        discovered_documents: list[dict] = []
        for source in selected:
            document = reference_cache.fetch(source.url)
            if document is None:
                continue
            discovered_documents.append(
                {
                    "url": document.url,
                    "source_type": source.source_type,
                    "title": document.title or source.title,
                    "priority": source.priority,
                    "tags": source.tags,
                    # Ephemeral discovery provenance (in-memory only;
                    # never persisted, never added to schemas or
                    # telemetry). See ``fetch_discovered_sources``.
                    "discovery_tags": list(source.tags),
                    "discovery_query": source.query,
                    "content": document.content,
                }
            )

        contexts_raw = build_research_contexts(
            documents=discovered_documents,
            cve_id=cve.title,
            keywords=[cve.title, *cve.vendor, *cve.products],
        )
        # Deterministic quality gate (research-only, offline, no
        # LLM): validates the existing pipeline's contexts for THIS
        # CVE before SecurityResearcher receives them. Filters
        # invalid entries only — never reorders, never mutates,
        # never fabricates. An all-invalid list becomes empty and
        # the existing pipeline proceeds conservatively on CVE
        # metadata alone.
        from ai.researcher.reference_quality import gate_reference_contexts

        gate_result = gate_reference_contexts(
            contexts_raw,
            cve_id=cve.title,
            known_urls={item["url"] for item in discovered_documents},
        )
        if quality_sink is not None:
            quality_sink.append(bool(gate_result.rejected))
        contexts_raw = gate_result.contexts
        # Per-CVE observability: counts only, derived from the SAME
        # gate result above (never recalculated). Mirrors the
        # single-CVE ``reference_quality`` payload field exactly.
        reference_quality = {
            "checked": 1,
            "rejected": 1 if gate_result.rejected else 0,
        }
        reference_contexts = [
            ReferenceContext(
                source_url=context["url"],
                source_type=context["source_type"],
                title=context.get("title"),
                exact_record=context.get("exact_record"),
                context_chunks=context.get("context_chunks", []),
            )
            for context in contexts_raw
        ]

        if skip_llm:
            research_payload: dict = {
                "skipped": True,
                "reason": "LLM research skipped by --skip-llm",
            }
            llm_status = "skipped"
            llm_error: str | None = None
            research_status = "completed"
            outage_bucket: str | None = None
            outage_events: list[str] = []
            retry_attempted = False
            retry_succeeded: bool | None = None
        else:
            researcher = SecurityResearcher()

            def _do_research():
                return researcher.research(
                    document=cve,
                    programs=programs,
                    assets=asset_names,
                    technologies=technologies,
                    reference_contexts=reference_contexts,
                    discovered_sources=discovered_documents,
                )

            try:
                result = _do_research()
            except Exception as exc:
                from ai.researcher.degraded import (
                    build_degraded_research_from_document,
                )
                from ai.researcher.provider_errors import (
                    classify_provider_failure,
                    outage_bucket_for_info,
                )
                from ai.researcher.retry_policy import (
                    is_retryable_429,
                    sleep_before_429_retry,
                )

                info = classify_provider_failure(exc)
                if not info.transient:
                    raise
                initial_bucket = outage_bucket_for_info(info)
                retry_attempted = is_retryable_429(info)
                retry_succeeded = None
                second_bucket: str | None = None
                if retry_attempted:
                    sleep_before_429_retry()
                    try:
                        result = _do_research()
                    except Exception as retry_exc:
                        retry_context = retry_exc.__context__
                        retry_exc.__context__ = None
                        try:
                            retry_info = classify_provider_failure(
                                retry_exc
                            )
                        finally:
                            retry_exc.__context__ = retry_context
                        if not retry_info.transient:
                            raise
                        retry_succeeded = False
                        second_bucket = outage_bucket_for_info(retry_info)
                        info = retry_info
                    else:
                        retry_succeeded = True
                if retry_succeeded is True:
                    research_payload = result.model_dump()
                    research_payload["llm_status"] = "ok"
                    research_payload["llm_error"] = None
                    llm_status = "ok"
                    llm_error = None
                    research_status = "completed"
                    outage_bucket = initial_bucket
                    outage_events = [
                        bucket
                        for bucket in (initial_bucket,)
                        if bucket
                    ]
                else:
                    degraded = build_degraded_research_from_document(
                        cve, llm_error=info.public_message
                    )
                    research_payload = degraded.model_dump()
                    research_payload["llm_status"] = "unavailable"
                    research_payload["llm_error"] = info.public_message
                    llm_status = "unavailable"
                    llm_error = info.public_message
                    research_status = "completed_degraded"
                    outage_bucket = initial_bucket
                    outage_events = [
                        bucket
                        for bucket in (initial_bucket, second_bucket)
                        if bucket
                    ]
            else:
                research_payload = result.model_dump()
                research_payload["llm_status"] = "ok"
                research_payload["llm_error"] = None
                llm_status = "ok"
                llm_error = None
                research_status = "completed"
                outage_bucket = None
                outage_events = []
                retry_attempted = False
                retry_succeeded = None

        from datetime import datetime, timezone

        payload = {
            "research_version": "cli-1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "research-only",
            "authoritative": False,
            "research_only": True,
            "research_status": research_status,
            "llm_status": llm_status,
            "llm_error": llm_error,
            "outage_bucket": outage_bucket,
            "outage_events": outage_events,
            "retry_attempted": retry_attempted,
            "retry_succeeded": retry_succeeded,
            # Per-CVE reference-context quality-gate outcome. Counts
            # only (one gated CVE); no URLs, no contents, no CVE IDs,
            # no error payloads. Always present on this flow —
            # including skip-llm (gate runs on the already-built
            # contexts before the skip branch) and degraded outcomes
            # (survives fail-soft and both retry outcomes).
            "reference_quality": reference_quality,
            "provenance": {
                "deterministic": ["nvd", "reference"],
                "llm": llm_status,
                "authoritative": False,
            },
            "cve": {
                "id": cve.title,
                "vendor": cve.vendor,
                "products": cve.products,
                "cvss_score": cve.cvss_score,
                "cvss_vector": cve.cvss_vector,
            },
            "metadata": {
                "programs": programs,
                "assets": asset_names,
                "technologies": technologies,
                "assessment_count": len(items),
                "discovered_source_count": len(discovered.sources),
                "fetched_source_count": len(discovered_documents),
                "reference_context_count": len(reference_contexts),
            },
            "research": research_payload,
        }
        return payload

    return research_fn


def _cve_namespace(payload: dict, research) -> SimpleNamespace:
    cve_info = payload.get("cve", {})
    return SimpleNamespace(
        title=cve_info.get("id", ""),
        vendor=cve_info.get("vendor", []),
        products=cve_info.get("products", []),
        content=" ".join(
            part
            for part in (
                research.summary or "",
                research.root_cause or "",
            )
            if part
        ),
        affected_versions=research.affected_versions,
    )


def _severity_for(research) -> str:
    severity = (research.severity or "high").lower()
    return severity if severity in ("info", "low", "medium", "high", "critical") else "high"


def run_nuclei_offline_stage(
    payload: dict,
    *,
    pipeline_factory=None,
    template_dir: str | Path = DEFAULT_TEMPLATE_DIR,
) -> dict:
    """Run the research-only Nuclei candidate lane for one researched CVE.

    Returns the nuclei portion of the structured per-CVE result. Uses
    ``NucleiPipeline.prepare_offline`` when a source template exists for
    the CVE; otherwise falls back to an offline extractor + decision
    (no generation, no dry-run). Never touches ``prepare_for_watch``.
    """
    from ai.correlator.detection import DetectionSpecExtractor
    from ai.correlator.nuclei_decision import NucleiDecisionEngine
    from ai.schemas.research import ResearchResult

    cve_id = payload.get("cve", {}).get("id", "")
    research_dict = payload.get("research", {})

    stage = {
        "nuclei_candidate": False,
        "decision": None,
        "decision_confidence": None,
        "template_generated": False,
        "semantic_validation": None,
        "offline_preparation": None,
        "nuclei_error": None,
        "artifacts": {},
    }

    if research_dict.get("skipped"):
        stage["nuclei_error"] = "nuclei lane skipped: LLM research skipped"
        return stage

    try:
        research = ResearchResult(**research_dict)
        cve = _cve_namespace(payload, research)
        source_template = Path(template_dir) / f"{cve_id}.yaml"

        if source_template.exists():
            if pipeline_factory is None:
                from ai.researcher.nuclei_pipeline import NucleiPipeline

                pipeline = NucleiPipeline()
            else:
                pipeline = pipeline_factory()
            # Research-only offline preparation: empty selection means no
            # asset contact, no fingerprinting, no subprocess, dry-run
            # command construction only.
            result = pipeline.prepare_offline(
                cve=cve,
                research=research,
                source_template=source_template,
                selection=build_offline_selection(cve_id),
                name=research.title,
                severity=_severity_for(research),
                description=(research.summary or "")[:500],
                tags=None,
            )
            stage["decision"] = result.get("decision")
            stage["decision_confidence"] = result.get("decision_confidence")
            stage["nuclei_candidate"] = bool(research.nuclei_candidate) and (
                result.get("decision") == "GOOD_CANDIDATE"
            )
            stage["template_generated"] = bool(result.get("generated"))
            stage["semantic_validation"] = {
                "valid": bool(result.get("semantic_valid")),
                "errors": list(result.get("errors", [])),
            }
            stage["offline_preparation"] = result
            artifacts = dict(stage["artifacts"])
            if result.get("template_path"):
                artifacts["template"] = result["template_path"]
            if result.get("findings_path"):
                artifacts["findings"] = result["findings_path"]
            stage["artifacts"] = artifacts
        else:
            # No prior-art template: offline decision only, no generation.
            detection = DetectionSpecExtractor().extract(cve, research)
            decision = NucleiDecisionEngine().decide(
                cve=cve,
                research=research,
                detection=detection,
            )
            stage["decision"] = decision.decision
            stage["decision_confidence"] = decision.confidence
            stage["nuclei_candidate"] = bool(research.nuclei_candidate) and (
                decision.decision == "GOOD_CANDIDATE"
            )
            stage["semantic_validation"] = {"valid": False, "errors": []}
            stage["nuclei_error"] = (
                f"no source template for {cve_id}: decision only, "
                "no generation"
            )
    except Exception as exc:
        stage["nuclei_error"] = f"{type(exc).__name__}: {exc}"

    return stage


# ---------------------------------------------------------------------------
# Provider outage telemetry (aggregate counts only)
# ---------------------------------------------------------------------------


def _fallback_outage_bucket(llm_error) -> str | None:
    """Derive a bucket from an unstamped degraded payload's message.

    Uses the SAME provider classifier by re-wrapping the recorded
    message in the provider error type the real flow uses. Only
    reached for degraded payloads that predate the ``outage_bucket``
    stamp (or hand-rolled payloads); stamped payloads never reach
    here, so a single CVE failure is still tallied exactly once.
    Counts only — the message itself is never stored.
    """
    if not llm_error:
        return None
    try:
        from ai.llm.openrouter import OpenRouterProviderError
        from ai.researcher.provider_errors import (
            classify_provider_failure,
            outage_bucket_for_info,
        )
    except Exception:
        return None
    try:
        info = classify_provider_failure(
            OpenRouterProviderError(str(llm_error))
        )
    except Exception:
        return None
    return outage_bucket_for_info(info)


# ---------------------------------------------------------------------------
# Per-CVE and batch orchestration
# ---------------------------------------------------------------------------


def _per_cve_reference_quality(payload: dict) -> dict | None:
    """Extract counts-only per-CVE quality from a research payload.

    Observability-only copy (never recalculated): returns exactly
    ``{"checked": int, "rejected": int}`` when the payload carries a
    well-formed ``reference_quality`` object (the single-CVE / batch
    gate result, the source of truth), else ``None``. ``None`` means
    "not derivable" (legacy custom ``research_fn`` payloads, or
    batch-layer degraded paths built without gating) — it is never
    backfilled with invented counts. Only the two integer counts
    are copied; no URLs, contents, IDs, or error text can pass
    through (booleans are rejected as non-integers on purpose).
    """
    quality = payload.get("reference_quality")
    if not isinstance(quality, dict):
        return None
    checked = quality.get("checked")
    rejected = quality.get("rejected")
    if (
        isinstance(checked, bool)
        or not isinstance(checked, int)
        or isinstance(rejected, bool)
        or not isinstance(rejected, int)
    ):
        return None
    return {"checked": checked, "rejected": rejected}


def research_one_cve(
    cve_id: str,
    *,
    skip_llm: bool = False,
    research_fn=None,
    pipeline_factory=None,
    template_dir: str | Path = DEFAULT_TEMPLATE_DIR,
    outage_sink: list | None = None,
    retry_sink: list | None = None,
    retry_sleep_fn=None,
    retry_429_delay=None,
) -> dict:
    """Execute the full batch lane for one CVE; never raises.

    ``research_fn`` defaults to the existing single-CVE CLI flow
    (lazy import avoids a module cycle with ``ai.research_cli``).

    ``outage_sink``, when provided, receives one entry per outage
    event for this CVE (usually zero or one; two when a 429 retry
    also fails). ``run_cve_batch`` tallies the sink into the
    aggregate ``provider_outages`` histogram. Fail-soft semantics
    are unchanged.

    ``retry_sink``, when provided, receives exactly one entry per
    CVE: ``True`` when the single allowed 429 retry converted the
    CVE to ``completed``, ``False`` when a retry was attempted but
    did not produce successful research (exhausted), or ``None``
    when no retry was attempted. ``retry_sleep_fn`` /
    ``retry_429_delay`` inject the single backoff (tests must never
    sleep); ``None`` uses the small capped production default.

    Observability: when the returned research payload carries the
    counts-only ``reference_quality`` gate outcome (default flow
    and single-CVE flow always do), it is copied verbatim onto the
    per-CVE result item (``result["reference_quality"]``). Paths
    with no research payload to derive from (invalid CVE format,
    non-transient failure, batch-layer degraded payloads built
    without gating) leave it as ``None`` — never invented.
    Fail-soft semantics are unchanged.
    """

    def _record_outage(bucket: str | None) -> None:
        if outage_sink is not None:
            outage_sink.append(bucket)

    def _record_retry(outcome: bool | None) -> None:
        if retry_sink is not None:
            retry_sink.append(outcome)

    def _tally_payload_outages(payload: dict) -> None:
        """Tally a returned payload's outage events (counts only)."""
        from ai.researcher.provider_errors import OUTAGE_BUCKETS

        events = payload.get("outage_events")
        if (
            isinstance(events, list)
            and events
            and all(event in OUTAGE_BUCKETS for event in events)
        ):
            for event in events:
                _record_outage(event)
            return
        stamped = payload.get("outage_bucket")
        if stamped in OUTAGE_BUCKETS:
            _record_outage(stamped)
            return
        if (
            payload.get("research_status") == "completed_degraded"
            or payload.get("llm_status") == "unavailable"
        ):
            _record_outage(
                _fallback_outage_bucket(payload.get("llm_error"))
            )
        else:
            _record_outage(None)

    def _tally_payload_retry(payload: dict) -> None:
        """Tally a returned payload's CLI-side retry outcome."""
        if payload.get("retry_attempted") is True:
            _record_retry(bool(payload.get("retry_succeeded")))
        else:
            _record_retry(None)
    if research_fn is None:
        from ai.research_cli import _research_single_cve

        research_fn = _research_single_cve

    result: dict = {key: None for key in RESULT_KEYS}
    result.update(
        {
            "cve": cve_id,
            "research_status": "failed",
            "nuclei_candidate": False,
            "template_generated": False,
            "artifacts": {},
            "authoritative": False,
        }
    )

    if not CVE_PATTERN.match(cve_id):
        result["error"] = f"invalid CVE format: {cve_id!r}"
        _record_outage(None)
        _record_retry(None)
        return result

    # Batch-level retry outcome for THIS layer only: True (retry
    # converted to completed), False (exhausted), None (no retry).
    # The real CLI never propagates 429 (it converts to a payload),
    # so this layer only ever retries injected research_fn failures
    # and the two layers can never stack on one CVE.
    batch_retry_outcome: bool | None = None

    try:
        payload = research_fn(cve_id, skip_llm=skip_llm)
    except Exception as exc:
        from ai.researcher.degraded import build_degraded_research
        from ai.researcher.provider_errors import (
            classify_provider_failure,
            outage_bucket_for_info,
        )
        from ai.researcher.retry_policy import (
            is_retryable_429,
            sleep_before_429_retry,
        )

        info = classify_provider_failure(exc)
        if not info.transient:
            result["error"] = f"{type(exc).__name__}: {exc}"
            _record_outage(None)
            _record_retry(None)
            return result
        if not is_retryable_429(info):
            # 402/5xx/network: NEVER retry, degrade immediately.
            degraded = build_degraded_research(
                cve_id, llm_error=info.public_message
            )
            degraded_payload = {
                "research_version": BATCH_VERSION,
                "mode": "research-only",
                "authoritative": False,
                "cve": {
                    "id": cve_id,
                    "vendor": [],
                    "products": [],
                    "cvss_score": None,
                    "cvss_vector": None,
                },
                "research": {
                    **degraded.model_dump(),
                    "llm_status": "unavailable",
                    "llm_error": info.public_message,
                },
            }
            result["research_status"] = "completed_degraded"
            result["error"] = f"degraded: {info.public_message}"
            _record_outage(outage_bucket_for_info(info))
            _record_retry(None)
            stage = run_nuclei_offline_stage(
                degraded_payload,
                pipeline_factory=pipeline_factory,
                template_dir=template_dir,
            )
            result["nuclei_candidate"] = False
            result["decision"] = stage["decision"]
            result["decision_confidence"] = stage["decision_confidence"]
            result["template_generated"] = False
            result["semantic_validation"] = stage["semantic_validation"]
            result["offline_preparation"] = stage["offline_preparation"]
            result["nuclei_error"] = stage["nuclei_error"]
            return result
        # Bounded 429-only retry: exactly one additional research_fn
        # call after a small capped backoff. No loop.
        _record_outage(outage_bucket_for_info(info))
        sleep_before_429_retry(
            delay=retry_429_delay, sleep_fn=retry_sleep_fn
        )
        try:
            payload = research_fn(cve_id, skip_llm=skip_llm)
        except Exception as retry_exc:
            # Classify the retry outcome on its own signal only: the
            # retry was raised inside the initial-failure handler, so
            # Python attached the initial 429 as implicit
            # ``__context__``. The classifier follows that chain for
            # status extraction, which would misattribute (e.g. a
            # retry network error would look like a second 429).
            # Detach it for classification, then restore.
            retry_context = retry_exc.__context__
            retry_exc.__context__ = None
            try:
                retry_info = classify_provider_failure(retry_exc)
            finally:
                retry_exc.__context__ = retry_context
            if not retry_info.transient:
                result["error"] = (
                    f"{type(retry_exc).__name__}: {retry_exc}"
                )
                _record_retry(False)
                return result
            degraded = build_degraded_research(
                cve_id, llm_error=retry_info.public_message
            )
            degraded_payload = {
                "research_version": BATCH_VERSION,
                "mode": "research-only",
                "authoritative": False,
                "cve": {
                    "id": cve_id,
                    "vendor": [],
                    "products": [],
                    "cvss_score": None,
                    "cvss_vector": None,
                },
                "research": {
                    **degraded.model_dump(),
                    "llm_status": "unavailable",
                    "llm_error": retry_info.public_message,
                },
            }
            result["research_status"] = "completed_degraded"
            result["error"] = f"degraded: {retry_info.public_message}"
            _record_outage(outage_bucket_for_info(retry_info))
            _record_retry(False)
            stage = run_nuclei_offline_stage(
                degraded_payload,
                pipeline_factory=pipeline_factory,
                template_dir=template_dir,
            )
            result["nuclei_candidate"] = False
            result["decision"] = stage["decision"]
            result["decision_confidence"] = stage["decision_confidence"]
            result["template_generated"] = False
            result["semantic_validation"] = stage["semantic_validation"]
            result["offline_preparation"] = stage["offline_preparation"]
            result["nuclei_error"] = stage["nuclei_error"]
            return result
        # Retry returned a payload: converted to completed counts as
        # success, anything else as exhausted. Outage events are
        # tallied by the shared payload handling below.
        batch_retry_outcome = (
            payload.get("research_status", "completed") == "completed"
        )

    payload_status = payload.get("research_status", "completed")
    if payload_status == "completed_degraded" or payload.get("llm_status") == "unavailable":
        result["research_status"] = "completed_degraded"
        llm_error = payload.get("llm_error") or "LLM unavailable"
        result["error"] = f"degraded: {llm_error}"
        # Single tally for this CVE's outage events (initial failure
        # plus an exhausted-retry failure, if any). A batch-level
        # retry that returned this payload already recorded the
        # initial failure above; the payload's own events are the
        # additional distinct failures.
        _tally_payload_outages(payload)
    else:
        result["research_status"] = "completed"
        _tally_payload_outages(payload)
    # Batch-level retry outcome wins when this layer retried;
    # otherwise tally the CLI-side retry outcome (if any).
    if batch_retry_outcome is not None:
        _record_retry(batch_retry_outcome)
    else:
        _tally_payload_retry(payload)
    # Per-CVE observability: copy the payload's gate outcome (source
    # of truth) onto this result item. Counts only; None when the
    # payload carries nothing derivable (legacy custom flows).
    result["reference_quality"] = _per_cve_reference_quality(payload)
    artifacts = dict(result["artifacts"])
    if payload.get("output_path"):
        artifacts["research"] = payload["output_path"]

    stage = run_nuclei_offline_stage(
        payload,
        pipeline_factory=pipeline_factory,
        template_dir=template_dir,
    )
    result["nuclei_candidate"] = stage["nuclei_candidate"]
    result["decision"] = stage["decision"]
    result["decision_confidence"] = stage["decision_confidence"]
    result["template_generated"] = stage["template_generated"]
    result["semantic_validation"] = stage["semantic_validation"]
    result["offline_preparation"] = stage["offline_preparation"]
    result["nuclei_error"] = stage["nuclei_error"]
    artifacts.update(stage["artifacts"])
    result["artifacts"] = artifacts
    return result


def write_batch_markdown(aggregate: dict) -> str:
    """Render a small human-readable aggregate batch summary."""
    outages = aggregate.get("provider_outages") or {}
    outage_line = (
        "- provider_outages: "
        f"http_402={outages.get('http_402', 0)} "
        f"http_429={outages.get('http_429', 0)} "
        f"http_5xx={outages.get('http_5xx', 0)} "
        f"network={outages.get('network', 0)}"
    )
    retries = aggregate.get("provider_retries") or {}
    retry_line = (
        "- provider_retries: "
        f"attempted={retries.get('attempted', 0)} "
        f"succeeded={retries.get('succeeded', 0)} "
        f"exhausted={retries.get('exhausted', 0)}"
    )
    cache = aggregate.get("provider_cache") or {}
    cache_line = (
        f"- provider_cache: hits={cache.get('hits', 0)}"
    )
    ref_cache = aggregate.get("reference_cache") or {}
    ref_cache_line = (
        f"- reference_cache: hits={ref_cache.get('hits', 0)}"
    )
    ref_quality = aggregate.get("reference_quality") or {}
    ref_quality_line = (
        f"- reference_quality: checked={ref_quality.get('checked', 0)} "
        f"rejected={ref_quality.get('rejected', 0)}"
    )
    lines = [
        "# Batch CVE Research Report (research-only, dry-run)",
        "",
        f"- batch_version: {aggregate['batch_version']}",
        f"- generated_at: {aggregate['generated_at']}",
        "- mode: research-only (authoritative=False, no live execution)",
        f"- requested: {len(aggregate['cves_requested'])}",
        f"- processed: {aggregate['processed']} failed: {aggregate['failed']}",
        f"- completed: {aggregate.get('completed', aggregate['processed'])} "
        f"completed_degraded: {aggregate.get('completed_degraded', 0)}",
        outage_line,
        retry_line,
        cache_line,
        ref_cache_line,
        ref_quality_line,
        "",
        "| CVE | research_status | nuclei_candidate | "
        "decision | template_generated | error |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in aggregate["results"]:
        lines.append(
            f"| {item['cve']} | {item['research_status']} | "
            f"{item['nuclei_candidate']} | {item['decision']} | "
            f"{item['template_generated']} | {item['error'] or ''} |"
        )
    return "\n".join(lines) + "\n"


def run_cve_batch(
    cve_ids: list[str],
    *,
    skip_llm: bool = False,
    research_fn=None,
    pipeline_factory=None,
    research_dir: str | Path = DEFAULT_RESEARCH_DIR,
    template_dir: str | Path = DEFAULT_TEMPLATE_DIR,
    report_dir: str | Path = DEFAULT_REPORT_DIR,
    retry_sleep_fn=None,
    retry_429_delay=None,
    reference_cache=None,
    reference_fetch_fn=None,
) -> dict:
    """Research a list of CVEs; one failure never aborts the batch.

    ``reference_cache`` is an optional ``BatchReferenceCache``
    instance used to coalesce repeated reference fetches across
    distinct CVEs in the same batch. When omitted, a fresh
    per-batch cache is created (so the optimization applies to
    the default ``_research_single_cve`` flow) and destroyed
    on return. ``reference_fetch_fn`` overrides the per-URL
    fetch primitive used by the cache (``ReferenceCollector.fetch``
    by default). When the caller injects its own ``research_fn``,
    the cache is still created and exposed via the aggregate
    output for telemetry, but the optimization only takes effect
    when the wrapper below is in use.
    """
    research_dir = Path(research_dir)
    report_dir = Path(report_dir)
    research_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    # Normalize every input CVE once (deterministic, same rule as the
    # existing parser); preserve the full requested order so duplicate
    # CVE entries still surface in ``cves_requested`` /
    # ``results`` per the documented A semantics. The in-batch
    # coalescing cache (below) is what avoids duplicate provider
    # research — the existing per-input dedup is removed in favor of
    # the cache hit.
    requested_full: list[str] = []
    for raw in cve_ids:
        cve_id = (raw or "").strip().upper()
        if not cve_id:
            continue
        requested_full.append(cve_id)

    from ai.researcher.provider_errors import empty_outage_histogram
    from ai.researcher.retry_policy import empty_retry_histogram
    from ai.researcher.reference_cache import (
        BatchReferenceCache,
        empty_reference_cache_histogram,
    )
    from ai.researcher.reference_quality import (
        empty_reference_quality_histogram,
    )

    # Per-batch in-memory reference URL cache. Created here when
    # the caller did not provide one, dropped on return. The
    # default ``_research_single_cve`` flow does not consult the
    # cache directly; instead, when the caller uses the default
    # ``research_fn`` (i.e. the real CLI path), the batch wraps
    # it via ``_make_cached_research_fn`` so URL fetches go
    # through the cache. When the caller injects a custom
    # ``research_fn`` the cache is still created and the hit
    # counter is exposed in the aggregate output, but the cache
    # is only consulted if the injected function calls it
    # explicitly (the optimization is opt-in for custom flows).
    owns_cache = reference_cache is None
    if owns_cache:
        reference_cache = BatchReferenceCache()
    if reference_fetch_fn is not None:
        reference_cache.fetch_fn = reference_fetch_fn
    elif reference_cache.fetch_fn is None:
        from ai.collectors.reference import ReferenceCollector

        def _default_fetch(url: str):
            with ReferenceCollector() as collector:
                return collector.fetch(url)

        reference_cache.fetch_fn = _default_fetch

    # One quality-gate entry per gated CVE (first occurrences only;
    # duplicates reuse the provider-cache outcome and are never
    # re-gated): True when the gate removed at least one entry from
    # a non-empty context list, False otherwise. Created here,
    # dropped on return — same per-batch lifetime as the caches.
    quality_events: list = []

    if research_fn is None:
        research_fn = _make_cached_research_fn(
            reference_cache, quality_sink=quality_events
        )

    # One outage entry per outage EVENT (a CVE contributes zero, one,
    # or two entries: initial failure plus an exhausted-retry
    # failure). Tallied once each into the aggregate histogram, so
    # every provider failure is counted and none is double-counted.
    outage_events: list = []
    # Exactly one retry entry per CVE: True (retry converted to
    # completed), False (retry attempted but exhausted), None (no
    # retry attempted). At most one attempted increment per CVE.
    retry_events: list = []
    # Per-batch in-memory coalescing cache. NOT a module global;
    # created here, dropped when run_cve_batch returns. Stores
    # terminal research outcomes (completed / completed_degraded)
    # only — a programming/non-transient failure is intentionally
    # NOT cached so it can never poison the batch (a duplicate of a
    # failed CVE simply re-runs the normal research flow). Key is
    # the normalized CVE identifier. One entry per unique CVE that
    # produced a cacheable outcome.
    cache: dict[str, dict] = {}
    cache_hits = 0
    results: list[dict] = []
    for cve_id in requested_full:
        cached = cache.get(cve_id)
        if cached is not None:
            cache_hits += 1
            # Reuse the original result as-is so duplicated CVE
            # entries share the same semantic status,
            # nuclei_candidate, and artifact reference (no duplicate
            # research artifact is written for the hit). The cached
            # value's ``artifacts`` dict is shallow-copied to avoid
            # any accidental cross-entry mutation in downstream
            # consumers that may write to ``item['artifacts']``.
            # The ``reference_quality`` counts dict is likewise
            # copied when present so duplicate items expose the
            # same values without sharing mutable state.
            hit = {**cached, "artifacts": dict(cached["artifacts"])}
            if isinstance(cached.get("reference_quality"), dict):
                hit["reference_quality"] = dict(cached["reference_quality"])
            results.append(hit)
            continue
        # First occurrence of this CVE in the requested order:
        # execute the normal research flow and cache the terminal
        # outcome (completed / completed_degraded) so subsequent
        # duplicates can reuse it.
        item = research_one_cve(
            cve_id,
            skip_llm=skip_llm,
            research_fn=research_fn,
            pipeline_factory=pipeline_factory,
            template_dir=template_dir,
            outage_sink=outage_events,
            retry_sink=retry_events,
            retry_sleep_fn=retry_sleep_fn,
            retry_429_delay=retry_429_delay,
        )
        results.append(item)
        if item["research_status"] in ("completed", "completed_degraded"):
            cache[cve_id] = item

    for item in results:
        (research_dir / f"{item['cve']}.batch.json").write_text(
            json.dumps(item, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    provider_outages = empty_outage_histogram()
    for bucket in outage_events:
        if bucket in provider_outages:
            provider_outages[bucket] += 1

    # Retry telemetry: counts only, always present (zeroed when no
    # retry occurred). attempted <= number of CVEs by construction.
    provider_retries = empty_retry_histogram()
    for outcome in retry_events:
        if outcome is None:
            continue
        provider_retries["attempted"] += 1
        if outcome is True:
            provider_retries["succeeded"] += 1
        else:
            provider_retries["exhausted"] += 1

    aggregate = {
        "batch_version": BATCH_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "research-only",
        "authoritative": False,
        "cves_requested": requested_full,
        "completed": sum(
            1 for item in results if item["research_status"] == "completed"
        ),
        "completed_degraded": sum(
            1
            for item in results
            if item["research_status"] == "completed_degraded"
        ),
        "processed": sum(
            1
            for item in results
            if item["research_status"]
            in ("completed", "completed_degraded")
        ),
        "failed": sum(
            1 for item in results if item["research_status"] == "failed"
        ),
        # Aggregate counts only: no exception payloads, no response
        # bodies, no secrets, no CVE-specific text. Always present
        # (zeroed when no outage occurred) for a stable schema.
        "provider_outages": provider_outages,
        # Bounded-retry telemetry (429-only, at most one attempt per
        # CVE). Same counts-only, always-present guarantees.
        "provider_retries": provider_retries,
        # Per-batch coalescing telemetry. One hit per duplicate CVE
        # that reused a cached outcome (and therefore made zero
        # additional provider research calls). ``provider_outages`` /
        # ``provider_retries`` continue to count only first-occurrence
        # research — a cache hit is not a provider event.
        "provider_cache": {"hits": cache_hits},
        # Per-batch reference context reuse telemetry. One hit per
        # time a later CVE reused a previously-fetched reference
        # document instead of performing a fresh fetch of the same
        # URL. Counts only; no URLs, no CVE IDs, no payloads.
        # Overwritten with the live counter below (always present,
        # zeroed when no reuse occurred; attempted-fetch semantics
        # are explicit — each reuse is one hit, the first fetch
        # is not a hit).
        "reference_cache": empty_reference_cache_histogram(),
        # Per-CVE reference-context quality-gate telemetry. Counts
        # only; no CVE IDs, no URLs, no contents, no error payloads.
        # ``checked`` counts gated first-occurrence CVEs;
        # ``rejected`` counts those where the gate removed at least
        # one entry. Always present, zeroed when the default flow
        # is not in use (custom research_fn) or nothing was gated.
        "reference_quality": empty_reference_quality_histogram(),
        "results": results,
        "artifacts": {},
    }

    aggregate["reference_cache"] = {"hits": reference_cache.hits}
    aggregate["reference_quality"] = {
        "checked": len(quality_events),
        "rejected": sum(1 for event in quality_events if event),
    }

    stamp = aggregate["generated_at"].replace("+00:00", "Z").replace(":", "")
    aggregate_path = research_dir / f"batch-{stamp}.json"
    aggregate_path.write_text(
        json.dumps(aggregate, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    aggregate["artifacts"] = {"aggregate": str(aggregate_path)}

    report_path = report_dir / f"cve-batch-run-{stamp}.md"
    report_path.write_text(write_batch_markdown(aggregate), encoding="utf-8")
    aggregate["artifacts"]["report"] = str(report_path)

    # Persist the artifact paths inside the aggregate file as well.
    aggregate_path.write_text(
        json.dumps(aggregate, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return aggregate
