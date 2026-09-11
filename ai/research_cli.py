"""Research-only CLI for the Watch AI security research track.

This is the supported entry point for running the research agent on
this machine. It is intentionally research-only and non-authoritative:

- CVE collection, reference discovery/collection, research/correlation,
  candidate Nuclei template generation/validation, and dry-run
  Nuclei preparation only.
- NEVER enables LIVE_HTTP / LIVE_NUCLEI / live browser execution.
- NEVER bypasses 5B/5C/5D authorization/scope controls.
- NEVER materializes research into authoritative 5J findings and
  NEVER emits CONFIRMED findings from research alone.
- Research outputs go to ``ai_data/research/`` and
  ``ai_data/nuclei/{generated,results,findings}/`` only.

Usage::

    python -m ai.research_cli check
    python -m ai.research_cli research --cve CVE-2026-1557
    python -m ai.research_cli research --cve CVE-2026-1557 --skip-llm
    python -m ai.research_cli batch --days 7 --limit 5
    python -m ai.research_cli batch --cves CVE-2026-1557,CVE-2026-0001
    python -m ai.research_cli batch --file cves.txt
    python -m ai.research_cli kb list
    python -m ai.research_cli kb show <knowledge_id>
    python -m ai.research_cli kb search --xss-type reflected
    python -m ai.research_cli validate-live --cve CVE-2026-1557 --target https://example.com

``check`` is fully offline except for a localhost MongoDB ping and
performs no LLM or NVD calls. ``validate-live`` is an offline dry-run
by default (zero network); ``--live`` additionally requires
``WATCH_AI_LIVE_VALIDATION=true`` or the lane blocks at the config
gate before any execution.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from ai.schemas.hunt_queue import HUNT_PRIORITIES
from ai.schemas.research_outcome import OUTCOME_SOURCES, OUTCOME_STATUSES

RESEARCH_DIR = Path("ai_data/research")
NUCLEI_DIRS = (
    Path("ai_data/nuclei/generated"),
    Path("ai_data/nuclei/results"),
    Path("ai_data/nuclei/findings"),
)

REFERENCE_ARCHIVE_VERSION = "references-1"


def write_reference_archive(
    cve_id: str,
    reference_contexts,
    discovered_documents=None,
) -> Path:
    """Persist already-built ReferenceContext material (Stage R1).

    Writes ``ai_data/research/<CVE>.references.json`` with one record
    per :class:`ReferenceContext`: ``source_url``, ``source_type``,
    ``title``, ``exact_record``, ``context_chunks``, plus
    ``content_hash`` where the fetched-document material carries one
    (``None`` otherwise -- never invented). The existing research JSON
    schema is untouched; reference fetching behavior is untouched; no
    fetch is performed here.

    The write is atomic (temp file + rename) and deterministic
    (sorted keys), matching the knowledge-store persistence pattern.
    """

    hash_by_url: dict[str, str] = {}
    body_by_url: dict[str, dict] = {}

    for item in discovered_documents or []:
        url = item.get("url")
        content_hash = item.get("content_hash")

        if url and content_hash and url not in hash_by_url:
            hash_by_url[url] = content_hash

        if url and url not in body_by_url:
            body_by_url[url] = {
                "body": item.get("content") or "",
                "raw_content_hash": item.get("raw_content_hash"),
                "extraction_format": item.get("extraction_format"),
                "extraction_status": item.get("extraction_status"),
            }

    records = []

    for context in reference_contexts:
        provenance = body_by_url.get(context.source_url, {})
        records.append(
            {
                "source_url": context.source_url,
                "source_type": context.source_type,
                "title": context.title,
                "exact_record": context.exact_record,
                "context_chunks": list(context.context_chunks),
                "content_hash": hash_by_url.get(context.source_url),
                # Stage R13 additive: normalized extracted body plus
                # extraction provenance (absent/None for legacy
                # records; never fabricated on failure).
                "body": provenance.get("body") or "",
                "raw_content_hash": provenance.get("raw_content_hash"),
                "extraction_format": provenance.get("extraction_format"),
                "extraction_status": provenance.get("extraction_status"),
            }
        )

    archive = {
        "archive_version": REFERENCE_ARCHIVE_VERSION,
        "cve_id": cve_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "record_count": len(records),
        "records": records,
    }

    RESEARCH_DIR.mkdir(parents=True, exist_ok=True)
    path = RESEARCH_DIR / f"{cve_id}.references.json"
    temp_path = path.with_name(f"{path.name}.tmp")
    temp_path.write_text(
        json.dumps(
            archive,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    os.replace(temp_path, path)
    return path


def refresh_reference_archive(
    cve_id: str,
    collector=None,
) -> dict:
    """Re-fetch archived reference URLs and update bodies (Stage R13).

    Reads ``ai_data/research/<CVE>.references.json``, re-fetches each
    ``source_url`` once through :class:`ReferenceCollector`, and
    updates in place: ``body``, ``content_hash``, ``raw_content_hash``,
    ``extraction_format``, ``extraction_status``. URLs that now fail,
    are unsupported, or yield no extractable body are recorded with an
    empty body and ``content_hash=None`` (fail-soft; never fabricated).
    Titles, ``exact_record`` and ``context_chunks`` are preserved.
    The write is atomic and deterministic. Returns a summary dict.
    """

    cve_id = cve_id.strip().upper()
    path = RESEARCH_DIR / f"{cve_id}.references.json"
    if not path.exists():
        raise FileNotFoundError(f"references archive not found: {path}")

    archive = json.loads(path.read_text(encoding="utf-8"))
    records = archive.get("records")
    if not isinstance(records, list):
        raise ValueError(f"invalid references archive records: {path}")

    owned = collector is None
    if owned:
        from ai.collectors.reference import ReferenceCollector

        collector = ReferenceCollector()

    updated = 0
    try:
        for record in records:
            if not isinstance(record, dict):
                continue
            url = str(record.get("source_url") or "").strip()
            if not url:
                continue
            document = collector.fetch(url)
            if (
                document is None
                or document.extraction_status != "ok"
                or not document.content
            ):
                record["body"] = ""
                record["content_hash"] = None
                record["raw_content_hash"] = (
                    getattr(document, "raw_content_hash", None)
                    if document is not None
                    else None
                )
                record["extraction_format"] = (
                    getattr(document, "extraction_format", None)
                    if document is not None
                    else None
                )
                record["extraction_status"] = (
                    getattr(document, "extraction_status", None) or "failed"
                    if document is not None
                    else "failed"
                )
                continue
            record["body"] = document.content
            record["content_hash"] = document.content_hash
            record["raw_content_hash"] = document.raw_content_hash
            record["extraction_format"] = document.extraction_format
            record["extraction_status"] = document.extraction_status
            updated += 1
    finally:
        if owned:
            collector.close()

    archive["record_count"] = len(
        [r for r in records if isinstance(r, dict)]
    )
    archive["generated_at"] = datetime.now(timezone.utc).isoformat()

    RESEARCH_DIR.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f"{path.name}.tmp")
    temp_path.write_text(
        json.dumps(archive, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    os.replace(temp_path, path)

    return {
        "cve_id": cve_id,
        "path": str(path),
        "records": len(records),
        "updated": updated,
    }


def run_references_refresh(args: argparse.Namespace) -> int:
    """CLI handler for ``references refresh`` (Stage R13)."""

    try:
        summary = refresh_reference_archive(args.cve)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"REFRESHED: {summary['cve_id']} -> {summary['path']}")
    print(f"  records: {summary['records']}  bodies-updated: {summary['updated']}")
    print("MODE: research-only re-fetch (no LLM, no execution, no retries)")
    return 0


# ---------------------------------------------------------------------------
# Offline safety / readiness check
# ---------------------------------------------------------------------------


def run_check() -> int:
    """Verify the research agent can run. No LLM/NVD calls. No secrets printed."""
    from dotenv import load_dotenv

    load_dotenv()

    import os

    errors: list[str] = []
    notes: list[str] = []

    provider = os.getenv("AI_PROVIDER", "openrouter")
    notes.append(f"AI_PROVIDER={provider}")

    if provider == "openrouter":
        if not os.getenv("OPENROUTER_API_KEY"):
            errors.append("OPENROUTER_API_KEY is not configured")
        else:
            notes.append("OPENROUTER_API_KEY is set")
        notes.append(
            "OPENROUTER_MODEL="
            + (os.getenv("OPENROUTER_MODEL") or "(default)")
        )
    elif provider == "avalai":
        if not os.getenv("AVALAI_API_KEY"):
            errors.append("AVALAI_API_KEY is not configured")
        else:
            notes.append("AVALAI_API_KEY is set")
    else:
        errors.append(f"unknown AI_PROVIDER: {provider!r}")

    mongo_uri = os.getenv("WATCH_MONGO_URI", "")
    if not mongo_uri:
        errors.append("WATCH_MONGO_URI is not configured")
    else:
        try:
            from pymongo import MongoClient

            client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            client.admin.command("ping")
            count = client["watch"]["http"].count_documents({})
            notes.append(f"MongoDB reachable (http assets: {count})")
            client.close()
        except Exception as exc:
            errors.append(f"MongoDB ping failed: {type(exc).__name__}")

    for path in (RESEARCH_DIR, *NUCLEI_DIRS):
        try:
            path.mkdir(parents=True, exist_ok=True)
            notes.append(f"writable: {path}")
        except Exception as exc:
            errors.append(f"cannot prepare {path}: {type(exc).__name__}")

    # Research track imports (fails loudly if deps are missing).
    try:
        import ai.collectors.cve  # noqa: F401
        import ai.collectors.discovery  # noqa: F401
        import ai.collectors.reference  # noqa: F401
        import ai.correlator.index  # noqa: F401
        import ai.researcher.nuclei_pipeline  # noqa: F401
        import ai.researcher.researcher  # noqa: F401

        notes.append("research track imports OK")
    except Exception as exc:
        errors.append(f"research track import failed: {type(exc).__name__}: {exc}")

    # Live-execution gates must stay absent/closed in this track: the
    # dry-run runner is the only Nuclei execution surface used here,
    # and it refuses live runs unless a target is READY_FOR_SCAN.
    try:
        from ai.researcher.nuclei_runner import NucleiRunner

        assert hasattr(NucleiRunner, "dry_run")
        notes.append("NucleiRunner dry-run surface present; live gates untouched")
    except Exception as exc:
        errors.append(f"dry-run surface check failed: {type(exc).__name__}: {exc}")

    print("WATCH RESEARCH AGENT CHECK")
    print("=" * 60)
    for note in notes:
        print(f"  ok:   {note}")
    for error in errors:
        print(f"  FAIL: {error}")
    print("=" * 60)
    if errors:
        print("RESULT: NOT RUNNABLE")
        return 1
    print("RESULT: RUNNABLE (research-only, dry-run)")
    return 0


def run_validate_live(args: argparse.Namespace) -> int:
    """Run the CVE-2026-1557 controlled live-validation lane.

    Default is an offline dry-run: every pre-execution gate runs
    (config/target/candidate/template/authorization/scope) but network
    execution is NOT_PERFORMED -- zero traffic. Live execution
    additionally requires BOTH WATCH_AI_LIVE_VALIDATION=true AND
    --live; otherwise the lane blocks before any request.
    """
    from ai.live_validation.lane import ControlledLiveValidationLane

    mode = "live" if getattr(args, "live", False) else "dry_run"
    lane = ControlledLiveValidationLane()
    result = lane.run(args.cve, args.target, mode=mode)

    print("CONTROLLED LIVE VALIDATION REPORT")
    print("=" * 60)
    print(f"MODE: {'LIVE' if mode == 'live' else 'DRY_RUN'}")
    print(f"CVE: {result.cve_id}")
    print(f"TARGET: {result.target or '(none)'}")
    print(f"STATUS: {result.status}")
    for gate in result.gates:
        print(f"  {gate.gate.upper()}: {gate.decision} {gate.reason}")
    if result.blocked_reason:
        print(f"BLOCKED: {result.blocked_reason}")
    if result.execution is not None:
        print(f"EXECUTION_ID: {result.execution.execution_id}")
        print(f"EVIDENCE_ID: {result.execution.evidence_id}")
        print(f"TEMPLATE_HASH: {result.execution.template_hash}")
    if result.verification is not None:
        print(
            f"VERIFIER: {result.verification.verifier_version} "
            f"{result.verification.reason_code}"
        )
    print("=" * 60)
    print(
        "NETWORK_EXECUTION: NOT_PERFORMED"
        if mode == "dry_run"
        else f"NETWORK_EXECUTION: {result.status}"
    )
    print("MODE: research-only (authoritative=False, dry-run default)")
    return 0


# ---------------------------------------------------------------------------
# Research helpers (reuse existing architecture, no duplication)
# ---------------------------------------------------------------------------


def _load_assets():
    from ai.collectors.http import HTTPCollector
    from ai.config import require_mongo_uri
    from ai.correlator.index import TechnologyIndex

    http = HTTPCollector(require_mongo_uri())
    try:
        assets = http.all()
    finally:
        http.close()
    return assets, TechnologyIndex(assets)


def _research_single_cve(cve_id: str, skip_llm: bool = False) -> dict:
    from ai.collectors.cve import CVECollector
    from ai.collectors.discovery import ReferenceDiscovery
    from ai.collectors.discovery_fetch import fetch_discovered_sources
    from ai.correlator.assessment import assess_asset
    from ai.correlator.candidates import candidate_assets
    from ai.researcher.research_context import build_research_contexts
    from ai.researcher.researcher import SecurityResearcher
    from ai.schemas.reference import ReferenceContext

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
    discovered_documents = fetch_discovered_sources(discovered, limit=5)
    contexts_raw = build_research_contexts(
        documents=discovered_documents,
        cve_id=cve.title,
        keywords=[cve.title, *cve.vendor, *cve.products],
    )
    # Deterministic Reference Context Quality Gate (research-only,
    # offline, no LLM): same shared gate as the batch path. Filters
    # invalid entries only — never reorders, never mutates, never
    # fabricates. Runs before SecurityResearcher receives context;
    # an all-invalid list becomes empty and research proceeds
    # conservatively on CVE metadata alone.
    from ai.researcher.reference_quality import gate_reference_contexts

    gate_result = gate_reference_contexts(
        contexts_raw,
        cve_id=cve.title,
        known_urls={item["url"] for item in discovered_documents},
    )
    contexts_raw = gate_result.contexts
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

    # Stage R1: persist the already-built ReferenceContext material
    # alongside (never inside) the existing research JSON. No fetch,
    # no schema change to the research payload, no secrets.
    write_reference_archive(
        cve.title,
        reference_contexts,
        discovered_documents,
    )

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
            # Bounded 429-only retry: exactly one additional attempt
            # after a small capped backoff. 402/5xx/network fall
            # through to immediate degradation below. No loop.
            retry_attempted = is_retryable_429(info)
            retry_succeeded = None
            second_bucket: str | None = None
            if retry_attempted:
                sleep_before_429_retry()
                try:
                    result = _do_research()
                except Exception as retry_exc:
                    # Classify the retry outcome on its own signal
                    # only: the retry was raised inside the
                    # initial-failure handler, so Python attached the
                    # initial 429 as implicit ``__context__``, which
                    # the classifier would follow for status
                    # extraction (e.g. a retry network error would
                    # look like a second 429). Detach for
                    # classification, then restore.
                    retry_context = retry_exc.__context__
                    retry_exc.__context__ = None
                    try:
                        retry_info = classify_provider_failure(retry_exc)
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
                    bucket for bucket in (initial_bucket,) if bucket
                ]
            else:
                # Fail-soft: classified transient provider failure ->
                # deterministic fallback. Degrade quickly.
                degraded = build_degraded_research_from_document(
                    cve, llm_error=info.public_message
                )
                research_payload = degraded.model_dump()
                research_payload["llm_status"] = "unavailable"
                research_payload["llm_error"] = info.public_message
                llm_status = "unavailable"
                llm_error = info.public_message
                research_status = "completed_degraded"
                # Single machine-readable outage stamp (first
                # failure), derived from the same classifier result
                # (no second classification). The batch layer tallies
                # the full event list; the CLI never aggregates.
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

    payload = {
        "research_version": "cli-1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "research-only",
        "authoritative": False,
        "research_only": True,
        "research_status": research_status,
        "llm_status": llm_status,
        "llm_error": llm_error,
        # Machine-readable outage class for aggregate telemetry
        # (single stamp per CVE; tallied once by the batch layer).
        "outage_bucket": outage_bucket,
        # Full ordered outage event list (initial + exhausted-retry
        # failure, if any) plus the single-retry outcome. Tallied
        # once per event by the batch layer; the CLI never aggregates.
        "outage_events": outage_events,
        "retry_attempted": retry_attempted,
        "retry_succeeded": retry_succeeded,
        # Per-CVE reference-context quality-gate outcome. Counts
        # only (one gated CVE); no URLs, no contents, no CVE IDs,
        # no error payloads. Always present, including skip-llm
        # (gate runs on the already-built contexts before the
        # skip branch) and degraded outcomes (survives fail-soft
        # and both retry outcomes — no additional provider call).
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
            # Stage R12: verbatim NVD weakness identifiers (already
            # collected by CVECollector); empty when NVD names none.
            "cwes": sorted(set(getattr(cve, "cwes", None) or [])),
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

    RESEARCH_DIR.mkdir(parents=True, exist_ok=True)
    output_path = RESEARCH_DIR / f"{cve_id}.cli.json"
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    payload["output_path"] = str(output_path)
    return payload


def run_research(args: argparse.Namespace) -> int:
    try:
        payload = _research_single_cve(args.cve, skip_llm=args.skip_llm)
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"RESEARCHED: {payload['cve']['id']}")
    print(f"SAVED: {payload['output_path']}")
    print(f"MODE: research-only (authoritative=False, no live execution)")
    return 0


def run_batch(args: argparse.Namespace) -> int:
    # Explicit CVE-list mode: safe batch research flow. One failing CVE
    # never aborts the batch; per-CVE structured results plus an
    # aggregate JSON (ai_data/research/) and a markdown summary
    # (agent-reports/) are written by ai.researcher.cve_batch.
    cve_ids: list[str] = []
    if getattr(args, "cves", None):
        from ai.researcher.cve_batch import parse_cve_list

        cve_ids.extend(parse_cve_list(args.cves))
    if getattr(args, "file", None):
        from ai.researcher.cve_batch import load_cve_list_file

        try:
            cve_ids.extend(load_cve_list_file(args.file))
        except Exception as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
    if cve_ids:
        from ai.researcher.cve_batch import run_cve_batch

        try:
            aggregate = run_cve_batch(
                cve_ids, skip_llm=getattr(args, "skip_llm", False)
            )
        except Exception as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        for item in aggregate["results"]:
            status = item["research_status"]
            print(f"  {item['cve']}: {status}")
            if item["error"]:
                print(f"    ERROR: {item['error']}")
        print(
            f"BATCH DONE: processed={aggregate['processed']} "
            f"failed={aggregate['failed']}"
        )
        print(f"AGGREGATE: {aggregate['artifacts']['aggregate']}")
        print(f"REPORT: {aggregate['artifacts']['report']}")
        print("MODE: research-only (authoritative=False, no live execution)")
        return 0 if aggregate["failed"] == 0 else 1

    # Legacy mode: research recent correlated CVEs (unchanged).
    from ai.collectors.cve import CVECollector
    from ai.correlator.assessment import assess_asset
    from ai.correlator.candidates import candidate_assets

    try:
        assets, index = _load_assets()
        cves = CVECollector().latest(days=args.days)
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    scored = []
    for cve in cves:
        candidates = candidate_assets(cve, index)
        if not candidates:
            continue
        scored.append((cve.cvss_score or 0, cve))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    processed, failed = 0, 0
    for _, cve in scored[: args.limit]:
        try:
            payload = _research_single_cve(cve.title)
            print(f"  SAVED: {payload['output_path']}")
            processed += 1
        except Exception as exc:
            print(f"  ERROR {cve.title}: {type(exc).__name__}: {exc}")
            failed += 1

    print(f"BATCH DONE: processed={processed} failed={failed}")
    return 0 if failed == 0 else 1


# ---------------------------------------------------------------------------
# Read-only knowledge-base inspection (Stage R1)
#
# Wraps the EXISTING KnowledgeStore APIs only (retrieve / get_by_id).
# No new search semantics: filters map 1:1 onto
# KnowledgeStore.retrieve() exact-match fields. No mutation, no
# ingestion, no network, no LLM.
# ---------------------------------------------------------------------------


def _kb_store():
    from ai.knowledge.store import KnowledgeStore

    return KnowledgeStore()


# (cli flag, retrieve kwarg) pairs. Order is fixed for determinism.
KB_SEARCH_FIELDS: tuple[tuple[str, str], ...] = (
    ("technology", "technologies"),
    ("xss_type", "xss_types"),
    ("context", "contexts"),
    ("waf", "wafs"),
    ("technique", "techniques"),
    ("source_type", "source_types"),
    ("evidence_quality", "evidence_quality"),
    ("tag", "tags"),
)


def _kb_search_kwargs(args: argparse.Namespace) -> dict:
    kwargs = {}

    for _, kwarg in KB_SEARCH_FIELDS:
        values = getattr(args, kwarg, None)

        if values:
            kwargs[kwarg] = values

    return kwargs


def run_kb_list(args: argparse.Namespace, store=None) -> int:
    store = store if store is not None else _kb_store()

    try:
        documents = store.retrieve()
    except ValueError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if getattr(args, "json", False):
        print(
            json.dumps(
                [
                    document.model_dump(mode="json")
                    for document in documents
                ],
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for document in documents:
            print(f"{document.knowledge_id} | {document.title}")
        print(f"KB DOCS: {len(documents)}")

    return 0


def run_kb_show(args: argparse.Namespace, store=None) -> int:
    store = store if store is not None else _kb_store()

    try:
        document = store.get_by_id(args.knowledge_id)
    except ValueError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if document is None:
        print(
            f"ERROR: unknown knowledge_id: {args.knowledge_id}",
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            document.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def run_kb_search(args: argparse.Namespace, store=None) -> int:
    store = store if store is not None else _kb_store()

    try:
        documents = store.retrieve(**_kb_search_kwargs(args))
    except ValueError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if getattr(args, "json", False):
        print(
            json.dumps(
                [
                    document.model_dump(mode="json")
                    for document in documents
                ],
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for document in documents:
            print(f"{document.knowledge_id} | {document.title}")
        print(f"MATCHES: {len(documents)}")

    return 0


def run_kb(args: argparse.Namespace) -> int:
    if args.kb_command == "list":
        return run_kb_list(args)
    if args.kb_command == "show":
        return run_kb_show(args)
    if args.kb_command == "search":
        return run_kb_search(args)
    if args.kb_command == "ingest":
        return run_kb_ingest(args)
    return 2


def _document_cve(document) -> str:
    for tag in document.tags:
        if tag.startswith("cve:"):
            return tag[4:]
    return ""


def _priority_for_document(document):
    """Recompute R16 research priority from a persisted KB document."""

    from ai.knowledge.intelligence import summarize_research_priority

    return summarize_research_priority(
        document.intelligence_evidence,
        vulnerability_types=document.vulnerability_types,
        cwes=document.cwes,
        components=document.components,
        parameters=document.parameters,
    )


def run_priority(args: argparse.Namespace, store=None) -> int:
    """Deterministic, read-only research prioritization (Stage R16).

    Recomputes the priority projection from persisted intelligence for each
    CVE synthesis document. No writes, no network, no LLM, no execution.
    """

    store = store if store is not None else _kb_store()
    try:
        if getattr(args, "cve", None):
            documents = store.retrieve(tags=[f"cve:{args.cve}"])
        else:
            documents = store.retrieve()
    except ValueError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    rows = []
    for document in documents:
        # A CVE's own priority lives on its synthesis document; per-reference
        # documents are excluded from the ranking.
        if not document.source_url.endswith(".cli.json"):
            continue
        priority = _priority_for_document(document)
        rows.append(
            (
                _document_cve(document) or document.knowledge_id,
                document,
                priority,
            )
        )
    rows.sort(key=lambda row: (-row[2].score, row[0]))

    if getattr(args, "json", False):
        print(
            json.dumps(
                [
                    {
                        "cve": cve,
                        "knowledge_id": document.knowledge_id,
                        "priority": priority.priority,
                        "score": priority.score,
                        "reasons": list(priority.reasons),
                        "negative_factors": list(priority.negative_factors),
                        "unknown_factors": list(priority.unknown_factors),
                        "rule_version": priority.rule_version,
                    }
                    for cve, document, priority in rows
                ],
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if not rows:
        print("PRIORITY: no matching CVE synthesis documents")
        return 0

    for cve, _document, priority in rows:
        print(f"{cve} | score={priority.score} | {priority.priority}")
        if priority.reasons:
            print(f"    reasons: {'; '.join(priority.reasons)}")
        if priority.negative_factors:
            print(f"    negative: {'; '.join(priority.negative_factors)}")
        if priority.unknown_factors:
            print(f"    unknown: {'; '.join(priority.unknown_factors)}")
    print(f"PRIORITY DOCS: {len(rows)}")
    return 0


def _programs_dir_default(programs_dir):
    if programs_dir is not None:
        return programs_dir
    return Path(__file__).resolve().parent.parent / "programs"


def run_relevance(
    args: argparse.Namespace,
    store=None,
    research_dir=None,
    programs_dir=None,
) -> int:
    """Deterministic, read-only asset/program relevance (Stage R17).

    Uses the local KnowledgeStore + local research payloads + local program
    definitions. No writes, no network, no LLM, no active validation.
    """

    from ai.knowledge.queue import (
        local_cve_context,
        relevance_inputs,
        vulnerability_profile,
    )
    from ai.knowledge.relevance import assess_asset_relevance, load_asset_snapshot

    store = store if store is not None else _kb_store()
    research_dir = research_dir if research_dir is not None else RESEARCH_DIR
    programs_dir = _programs_dir_default(programs_dir)
    cve_filter = getattr(args, "cve", None)
    override_assets = getattr(args, "assets", None)

    try:
        contexts = local_cve_context(
            store, research_dir, programs_dir, cve=cve_filter
        )
    except ValueError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    rows = []
    for context in contexts:
        cve = context["cve"]
        if cve_filter and cve and cve != cve_filter:
            continue
        profile = vulnerability_profile(
            context["document"], context["payload"], cve
        )
        assets = (
            load_asset_snapshot(override_assets)
            if override_assets
            else context["assets"]
        )
        relevance = assess_asset_relevance(
            assets=assets, **relevance_inputs(profile)
        )
        rows.append(
            (cve or context["document"].knowledge_id, context["document"], relevance)
        )
    rows.sort(key=lambda row: (-row[2].score, row[0]))

    if getattr(args, "json", False):
        print(
            json.dumps(
                [
                    {
                        "cve": cve,
                        "priority": document.research_priority.priority,
                        "relevance": relevance.relevance,
                        "score": relevance.score,
                        "reasons": list(relevance.reasons),
                        "matched_assets": list(relevance.matched_assets),
                        "matched_programs": list(relevance.matched_programs),
                        "unknown_factors": list(relevance.unknown_factors),
                        "rule_version": relevance.rule_version,
                    }
                    for cve, document, relevance in rows
                ],
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if not rows:
        print("RELEVANCE: no matching CVE synthesis documents")
        return 0

    for cve, document, relevance in rows:
        print(
            f"{cve} | priority={document.research_priority.priority} | "
            f"relevance={relevance.relevance} | score={relevance.score}"
        )
        if relevance.matched_programs:
            print(f"    programs: {'; '.join(relevance.matched_programs)}")
        if relevance.matched_assets:
            print(f"    assets: {'; '.join(relevance.matched_assets)}")
        if relevance.reasons:
            print(f"    reasons: {'; '.join(relevance.reasons)}")
        if relevance.unknown_factors:
            print(f"    unknown: {'; '.join(relevance.unknown_factors)}")
    print(f"RELEVANCE DOCS: {len(rows)}")
    return 0


def run_queue(
    args: argparse.Namespace,
    store=None,
    research_dir=None,
    programs_dir=None,
) -> int:
    """Deterministic, read-only research queue (Stage R18).

    Combines R16 priority with R17 asset relevance per CVE x program. No
    writes, no network, no LLM, no active validation. Items are research
    attention only; they never assert a target is vulnerable.
    """

    from ai.knowledge.queue import build_local_research_queue

    store = store if store is not None else _kb_store()
    research_dir = research_dir if research_dir is not None else RESEARCH_DIR
    programs_dir = _programs_dir_default(programs_dir)

    try:
        items = build_local_research_queue(
            store, research_dir, programs_dir, cve=getattr(args, "cve", None)
        )
    except ValueError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    limit = getattr(args, "limit", None)
    if limit is not None and limit >= 0:
        items = items[:limit]

    if getattr(args, "json", False):
        print(
            json.dumps(
                [
                    {
                        "rank": item.rank,
                        "queue_id": item.queue_id,
                        "cve": item.cve,
                        "program": item.program,
                        "priority_class": item.priority_class,
                        "priority_score": item.priority_score,
                        "relevance": item.relevance,
                        "relevance_score": item.relevance_score,
                        "queue_score": item.queue_score,
                        "reasons": list(item.reasons),
                        "blockers": list(item.blockers),
                        "unknown_factors": list(item.unknown_factors),
                        "rule_version": item.rule_version,
                    }
                    for item in items
                ],
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if not items:
        print("QUEUE: no deterministic CVE/program candidates")
        return 0

    for item in items:
        print(
            f"#{item.rank}  {item.cve} -> {item.program}  "
            f"queue_score={item.queue_score}  "
            f"(priority={item.priority_class}/{item.priority_score}, "
            f"relevance={item.relevance}/{item.relevance_score})"
        )
        if item.reasons:
            print(f"    reasons: {'; '.join(item.reasons)}")
        if item.blockers:
            print(f"    blockers: {'; '.join(item.blockers)}")
        if item.unknown_factors:
            print(f"    unknown: {'; '.join(item.unknown_factors)}")
    print(f"QUEUE ITEMS: {len(items)}")
    return 0


def run_leads(
    args: argparse.Namespace,
    store=None,
    research_dir=None,
    programs_dir=None,
) -> int:
    """Deterministic, read-only research leads (Stage R21).

    Projects existing R15-R20 intelligence into actionable research leads.
    No network, no LLM, no subprocess, no active validation. A lead is
    research planning only — never a confirmed finding.
    """

    from backend import research_leads

    limit = getattr(args, "limit", None)
    if limit is None or limit < 0:
        limit = research_leads.MAX_LEADS
    try:
        data = research_leads.list_leads(
            limit=limit,
            offset=0,
            cve=getattr(args, "cve", None),
            program=getattr(args, "program", None),
        )
    except ValueError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    leads = data["items"]
    if not leads:
        print("RESEARCH LEADS: none (no R18 queue candidates match)")
        return 0

    if getattr(args, "json", False):
        print(json.dumps(leads, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    print("Research Leads")
    print("==============")
    print()
    for index, lead in enumerate(leads, start=1):
        print(f"#{index} {lead['cve_id']} → {lead['program']}")
        print(f"Priority: {lead['priority_score']} / {lead['priority_level']}")
        print(f"Relevance: {lead['relevance_score']} / {lead['relevance_level']}")
        print(f"Status: {lead['status']}")
        print(f"Lead id: {lead['lead_id']}")
        print("Why investigate:")
        for reason in lead["reasons"]:
            print(f"  ✓ {reason['text']} ({reason['code']})")
        if lead["blockers"]:
            print("Blockers:")
            for blocker in lead["blockers"]:
                print(f"  ✗ {blocker}")
        print("Next action:")
        print(f"  {lead['recommended_next_step']}")
        print()
    print(f"RESEARCH LEADS: {len(leads)}")
    return 0


def run_research_plan(args: argparse.Namespace) -> int:
    """Deterministic, read-only research execution plan (Stage R22).

    Projects R21 leads into ordered execution steps, evidence targets and
    preserved unknowns. No network, no LLM, no subprocess, no active
    validation. A plan is research guidance only.
    """
    from backend import research_execution

    limit = getattr(args, "limit", None)
    if limit is None or limit < 0:
        limit = research_execution.MAX_PLANS
    try:
        data = research_execution.list_plans(
            limit=limit,
            offset=0,
            cve=getattr(args, "cve", None),
            program=getattr(args, "program", None),
            lead=getattr(args, "lead", None),
        )
    except ValueError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    plans = data["items"]
    if not plans:
        print("RESEARCH PLAN: none (no R21 lead / R18 candidate match)")
        return 0

    if getattr(args, "json", False):
        print(json.dumps(plans, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    # Compact human output
    print("Research Execution Plan")
    print("=======================")
    print()
    for idx, plan in enumerate(plans, start=1):
        print(f"#{idx} {plan['cve_id']} -> {plan['program']}")
        print(f"Plan: {plan['plan_id']}")
        print(f"Lead: {plan['lead_id']}")
        print(f"Status: {plan['status']}")
        if plan.get("recommended_start"):
            print("Recommended start:")
            print(f"  {plan['recommended_start']}")
        print("Steps:")
        for step in plan["steps"]:
            print(f"  {step['order']}. {step['title']} [{step['code']}]")
        if plan["evidence_targets"]:
            print("Evidence targets:")
            for target in plan["evidence_targets"]:
                print(f"  - {target['code']}")
        if plan["unknowns"]:
            print("Unknowns:")
            for unknown in plan["unknowns"]:
                print(f"  - {unknown}")
        if plan["blockers"]:
            print("Blockers:")
            for blocker in plan["blockers"]:
                print(f"  - {blocker}")
        print()
    print(f"RESEARCH PLANS: {len(plans)}")
    return 0


def _fmt_rate(rate: Any) -> str:
    if rate is None:
        return "n/a"
    return f"{rate}"


def run_hunt(args: argparse.Namespace) -> int:
    """Stage R29.1 personal bug-bounty hunt queue (read-only).

    Deterministic ordering of the existing action queue for personal research
    time. No execution, no network, no automatic research; research-only.
    """

    from backend import hunt_queue

    limit = getattr(args, "limit", None)
    if limit is None or limit < 0:
        limit = hunt_queue.MAX_HUNT_ITEMS
    try:
        data = hunt_queue.list_hunt_items(
            limit=limit,
            offset=0,
            cve=getattr(args, "cve", None),
            program=getattr(args, "program", None),
            priority=getattr(args, "priority", None),
            opportunity_class=getattr(args, "class_filter", None),
            status=getattr(args, "status", None),
        )
    except ValueError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    items = data["items"]
    if getattr(args, "json", False):
        print(json.dumps(items, ensure_ascii=False, indent=2,
                         sort_keys=True))
        return 0

    if not items:
        print("PERSONAL HUNT QUEUE: none (no action candidates match)")
        return 0

    print("PERSONAL HUNT QUEUE")
    print()
    for index, item in enumerate(items, start=1):
        priority_short = str(item["money_priority"] or "").split("_")[0]
        print(f"#{index} {item['hunt_priority']}")
        print(f"{item['cve_id']} → {item['program']}")
        print(f"Money: {item['money_score']} / {priority_short}")
        print(f"Confidence: {item['confidence']}")
        print(f"Evidence: {item['evidence_quality']}")
        print(f"Time box: {item['recommended_time_box']}")
        print()
        print("WHY:")
        print(item["hunt_reason"])
        print()
        print("NEXT:")
        print(item["next_step"])
        print()
    print(f"HUNT ITEMS: {len(items)}")
    return 0


# Order used to render the MATCHES block (strongest first).
_MATCH_DISPLAY_ORDER: tuple[str, ...] = (
    "COMPONENT",
    "PLUGIN",
    "PRODUCT",
    "VERSION",
    "TECHNOLOGY",
    "PARAMETER",
    "PATH",
    "VULNERABILITY_TYPE",
)


def _print_match_block(item: dict) -> None:
    """Render one program's asset <-> CVE match (no raw target hostnames)."""

    matched = {
        row["match_type"]: row for row in (item.get("all_matches") or [])
    }
    expected = set(matched) | set(item.get("missing") or [])
    print(f"{item['cve_id']} → {item['program']}")
    print()
    strongest = item.get("strongest_match")
    print("STRONGEST MATCH")
    print(item.get("strongest_match_type") or "NONE")
    print(f"Confidence: {item.get('strongest_confidence') or 'NONE'}")
    print()
    print("MATCHES")
    print()
    for match_type in _MATCH_DISPLAY_ORDER:
        if match_type not in expected:
            continue
        row = matched.get(match_type)
        if row is not None:
            print(f"✓ {match_type}")
            print(f"  {row['matched_value']}")
            print(f"  Source: {row['source']}")
        elif match_type == "VERSION":
            print(f"✗ {match_type}")
            print("  Unknown")
        else:
            print(f"✗ {match_type}")
            print("  Not observed")
        print()
    print("BLOCKERS")
    print()
    remaining = item.get("remaining_blockers") or []
    if remaining:
        for code in remaining:
            print(code)
    else:
        print("None")
    print()
    print("RESEARCH STATUS")
    print()
    print(item.get("research_status") or "NOT YET SUFFICIENT")
    print()


def run_match(args: argparse.Namespace) -> int:
    """Stage R30.1 asset <-> CVE match intelligence (read-only).

    Deterministic projection over existing CVE metadata and observed asset
    inventory. No execution, no network, no target interaction; research-only.
    """

    if getattr(args, "match_command", None) != "cve":
        return 2
    from backend import asset_cve_matching

    try:
        data = asset_cve_matching.build_matches(
            cve=getattr(args, "cve", None),
            program=getattr(args, "program", None),
        )
    except ValueError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if getattr(args, "json", False):
        print(json.dumps(data, ensure_ascii=False, indent=2,
                         sort_keys=True))
        return 0

    print("ASSET ↔ CVE MATCH")
    print()
    items = data["items"]
    if not items:
        print(f"{data['cve']}: no deterministic asset match.")
        print()
        print("No target testing was performed.")
        return 0
    for item in items:
        _print_match_block(item)
    print("No target testing was performed.")
    return 0


_INVENTORY_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("technologies", "TECHNOLOGIES"),
    ("products", "PRODUCTS"),
    ("components", "COMPONENTS"),
    ("plugins", "PLUGINS"),
    ("versions", "VERSIONS"),
    ("parameters", "PARAMETERS"),
)


def _print_inventory_block(item: dict) -> None:
    """Render one program's observed inventory (no raw target identifiers)."""

    print(item["program"])
    print()
    for key, heading in _INVENTORY_CATEGORIES:
        print(heading)
        values = [row.get("value") for row in item.get(key) or []]
        if values:
            for value in values:
                print(f"✓ {value}")
        else:
            print("none")
        print()
    paths = item.get("paths") or []
    print("PATHS")
    print(f"{len(paths)} available records")
    print()
    sources = item.get("sources") or []
    print("Sources:")
    if sources:
        for source in sources:
            print(source)
    else:
        print("none")
    print()
    print(f"Research-only: {str(item.get('research_only')).lower()}")
    print()


def run_inventory(args: argparse.Namespace) -> int:
    """Stage R30.2 observed asset inventory (read-only, research-only)."""

    from backend import observed_inventory

    try:
        data = observed_inventory.build_inventory(
            program=getattr(args, "program", None)
        )
    except ValueError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if getattr(args, "json", False):
        if getattr(args, "program", None):
            payload = data[0] if data else None
        else:
            payload = {
                "total": len(data),
                "items": data,
                "rule_version": observed_inventory.RULE_VERSION,
                "research_only": True,
            }
        print(json.dumps(payload, ensure_ascii=False, indent=2,
                         sort_keys=True))
        return 0

    print("OBSERVED ASSET INVENTORY")
    print()
    if not data:
        print("none (no known programs)")
        print()
        print("Research-only: true")
        return 0
    for item in data:
        _print_inventory_block(item)
    print("No target testing was performed.")
    return 0


def run_product_opportunities(args: argparse.Namespace) -> int:
    """Stage R28.1 local projection of the v1 product API (read-only).

    Same response schema as GET /api/v1/opportunities; no network calls
    are made by this command (it reads the same local projections).
    """

    from backend import product_api

    limit = getattr(args, "limit", None)
    if limit is None or limit < 0:
        limit = product_api.MAX_ITEMS
    try:
        data = product_api.list_product_opportunities(
            limit=limit,
            offset=0,
            cve=getattr(args, "cve", None),
            program=getattr(args, "program", None),
        )
    except ValueError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    items = data["items"]
    if not items:
        print("PRODUCT OPPORTUNITIES: none (no R26 candidates match)")
        return 0

    if getattr(args, "json", False):
        print(json.dumps(items, ensure_ascii=False, indent=2,
                         sort_keys=True))
        return 0

    print("PRODUCT OPPORTUNITIES")
    print()
    for index, item in enumerate(items, start=1):
        print(f"#{index} {item['opportunity_class']}")
        print(f"{item['cve_id']} → {item['program']}")
        print(f"Money: {item['money_score']} / "
              f"{item['money_priority'][:2]}")
        print(f"Confidence: {item['confidence']}")
        print(f"Action: {item['recommended_action']}")
        print()
        print("Next:")
        print(item["next_step"])
        print()
    print(f"PRODUCT OPPORTUNITIES: {len(items)}")
    return 0


def run_product_remote_opportunities(args: argparse.Namespace) -> int:
    """Stage R28.2 external consumption proof: consume Product API v1 via HTTP.

    This command talks to the public API only through the external
    ``clients.product_api_client`` (stdlib HTTP). It performs no local
    projection and has no fallback to internal functions.
    """

    from clients.product_api_client import (
        ProductAPIClient,
        ProductAPIClientError,
    )

    api_key_env = getattr(args, "api_key_env", "WATCH_PRODUCT_API_KEY")
    try:
        client = ProductAPIClient(
            base_url=getattr(args, "base_url", ""),
            api_key_env=api_key_env,
            timeout=getattr(args, "timeout", 10.0),
        )
        envelope = client.list_opportunities(
            limit=getattr(args, "limit", 50),
            offset=getattr(args, "offset", 0),
            cve=getattr(args, "cve", None),
            program=getattr(args, "program", None),
            opportunity_class=getattr(args, "class_filter", None),
            action=getattr(args, "action", None),
            status=getattr(args, "status", None),
            min_money_score=getattr(args, "min_money_score", None),
        )
    except ProductAPIClientError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except (ValueError, TypeError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if getattr(args, "json", False):
        print(json.dumps(envelope, ensure_ascii=False, indent=2,
                         sort_keys=True))
        return 0

    items = envelope["items"]
    if not items:
        print("REMOTE PRODUCT OPPORTUNITIES: none (no v1 items match)")
        return 0

    print("REMOTE PRODUCT OPPORTUNITIES")
    print()
    for index, item in enumerate(items, start=1):
        print(f"#{index} {item['opportunity_class']}")
        print(f"{item['cve_id']} → {item['program']}")
        print(f"Money: {item['money_score']} / {item['money_priority']}")
        print(f"Confidence: {item['confidence']}")
        print(f"Action: {item['recommended_action']}")
        print()
        print("NEXT:")
        print(item["next_step"])
        print()
    print(f"REMOTE PRODUCT OPPORTUNITIES: {len(items)} "
          f"(api {envelope['api_version']}, research_only="
          f"{str(envelope['research_only']).lower()})")
    return 0


def run_product(args: argparse.Namespace) -> int:
    """Stage R27.1 product validation audit (read-only, no new score).

    Reports deterministic product metrics and hypothesis statuses over
    existing R25/R26 data. No statistical significance is claimed, no
    payout data is used, nothing is executed or persisted.
    """

    from backend import product_validation

    command = getattr(args, "product_command", None)
    if command == "opportunities":
        return run_product_opportunities(args)
    if command == "remote-opportunities":
        return run_product_remote_opportunities(args)
    if command != "validation":
        return 2

    try:
        report = product_validation.build_product_validation_report(
            min_sessions=getattr(args, "min_sessions", 20),
            min_outcomes=getattr(args, "min_outcomes", 20),
            min_leads=getattr(args, "min_leads", 10),
            cve=getattr(args, "cve", None),
            program=getattr(args, "program", None),
        )
    except (ValueError, OSError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if getattr(args, "json", False):
        print(json.dumps(report, ensure_ascii=False, indent=2,
                         sort_keys=True))
        return 0

    totals = report["totals"]
    actionability = report["actionability"]
    follow = report["follow_through"]
    conversion = report["conversion"]
    timing = report["time_efficiency"]
    blockers = report["blocker_resolution"]

    print("WATCH PRODUCT VALIDATION")
    print()
    print(f"Leads: {totals['leads']}")
    print(f"Sessions: {totals['sessions']}")
    print(f"Terminal outcomes: {totals['terminal_outcomes']}")
    print()
    print("ACTIONABILITY")
    print(f"Ready: {actionability['ready']['value']}")
    print(f"Blocked: {actionability['blocked']['value']}")
    print(f"In progress: {actionability['in_progress']['value']}")
    print()
    print("FOLLOW-THROUGH")
    print(f"Sessions started: {follow['sessions_started']['value']}")
    print(f"Sessions completed: {follow['sessions_completed']['value']}")
    print(f"Sessions abandoned: {follow['sessions_abandoned']['value']}")
    print(f"Outcome records: {follow['outcome_records_created']['value']}")
    print()
    print("CONVERSION (rate over stated denominator)")
    print(f"ready -> session: "
          f"{_fmt_rate(conversion['ready_to_session']['rate'])} "
          f"(of {conversion['ready_to_session']['denominator']} "
          f"{conversion['ready_to_session']['denominator_label']})")
    print(f"session -> completed: "
          f"{_fmt_rate(conversion['session_to_completed']['rate'])} "
          f"(of {conversion['session_to_completed']['denominator']} "
          f"{conversion['session_to_completed']['denominator_label']})")
    print(f"completed -> terminal: "
          f"{_fmt_rate(conversion['completed_to_terminal_outcome']['rate'])}")
    print(f"terminal -> accepted: "
          f"{_fmt_rate(conversion['terminal_to_accepted']['rate'])}")
    print()
    print("TIME EFFICIENCY")
    print(f"Planned: {timing['planned_minutes']['value']} min")
    print(f"Actual: {timing['actual_minutes']['value']} min")
    print(f"Variance: {timing['variance_minutes']['value']} min")
    print(f"Average actual: "
          f"{_fmt_rate(timing['average_actual_minutes']['value'])} min")
    print(f"Accepted outcome time: "
          f"{_fmt_rate(timing['accepted_outcome_time']['value'])} min")
    print()
    print("BLOCKERS")
    print(f"Blocked leads: {blockers['blocked_leads']['value']}")
    print(f"Blocked -> session: "
          f"{_fmt_rate(blockers['blocked_to_session']['rate'])}")
    print(f"Blocked -> outcome: "
          f"{_fmt_rate(blockers['blocked_to_outcome']['rate'])}")
    print(f"Blocked -> ready: "
          f"{_fmt_rate(blockers['blocked_became_ready']['rate'])} "
          f"({blockers['blocked_became_ready']['note'] or 'no history'})")
    print()
    print("HYPOTHESES")
    print()
    for hypothesis in report["hypotheses"]:
        print(f"{hypothesis['hypothesis_id']}  {hypothesis['status']}  "
              f"(sample {hypothesis['sample_size']}/"
              f"{hypothesis['required_sample']})")
    print()
    if report["supported_hypotheses"]:
        print("Supported hypotheses (product signal, not proof): "
              + ", ".join(report["supported_hypotheses"]))
    else:
        print("No product hypothesis is currently supported.")
    print()
    print(f"PRODUCT DECISION: {report['product_decision']}")
    print(report["decision_reason"])
    return 0


def _load_workflow_document(path: str) -> object:
    """Read one caller-supplied workflow JSON file (never writes it)."""

    file_path = Path(str(path))
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    try:
        return json.loads(text)
    except ValueError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc


def run_workflow(args: argparse.Namespace) -> int:
    """Stage R26.3 daily research workflow + offline diff (read-only).

    The daily workflow is a derived presentation of the R26.2 Action Queue.
    `workflow diff` reads two caller-supplied JSON files as INPUTS only:
    it never modifies them and never persists anything.
    """

    from backend import daily_research

    command = getattr(args, "workflow_command", None)

    if command == "daily":
        try:
            workflow = daily_research.build_daily_workflow(
                top_n=getattr(args, "limit", 5),
                cve=getattr(args, "cve", None),
                program=getattr(args, "program", None),
                opportunity_class=getattr(args, "class_filter", None),
                status=getattr(args, "status", None),
            )
        except ValueError as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(workflow, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        print("DAILY RESEARCH WORKFLOW")
        print()
        print(f"READY: {workflow['ready']}")
        print(f"BLOCKED: {workflow['blocked']}")
        print(f"IN PROGRESS: {workflow['in_progress']}")
        if workflow["deferred"]:
            print(f"DEFERRED: {workflow['deferred']}")
        if workflow["completed"]:
            print(f"COMPLETED: {workflow['completed']}")
        print()

        if workflow["top_actions"]:
            print("TODAY'S PLAN")
            print()
            for index, plan in enumerate(workflow["top_actions"], start=1):
                print(f"#{index} {plan['cve_id']} → {plan['program']}")
                print(f"    Action: {plan['recommended_action']} "
                      f"({plan['estimated_minutes']} min)")
                print(f"    NEXT: {plan['next_step']}")
                print()

        print("TOP OPPORTUNITIES")
        print()
        for index, item in enumerate(workflow["top_opportunities"],
                                     start=1):
            print(f"#{index} {item['opportunity_class']}")
            print(f"    {item['cve_id']} → {item['program']}")
            print(f"    Money: {item['money_score']} / "
                  f"{item.get('priority') or ''}".rstrip())
            print(f"    Action: {item['recommended_action']}")
            if item["next_step"]:
                print()
                print("    NEXT:")
                print(f"    {item['next_step']}")
            print()

        if workflow["blocked_items"]:
            print("BLOCKED WORK")
            print()
            for index, item in enumerate(workflow["blocked_items"],
                                         start=1):
                print(f"#{index} {item['cve_id']} → {item['program']}")
                for entry in item["blocker_explanations"]:
                    print(f"   {entry['code']}")
                print()

        if workflow["in_progress_items"]:
            print("IN PROGRESS")
            print()
            for item in workflow["in_progress_items"]:
                print(f"{item['cve_id']} → {item['program']}  "
                      f"session={item['session_id']}  "
                      f"planned={item['planned_minutes']}m  "
                      f"actual={item['actual_minutes']}m")
            print()

        print("RECOMMENDATION")
        print()
        for recommendation in workflow["recommendations"]:
            print(recommendation)
        return 0

    if command == "diff":
        try:
            previous = _load_workflow_document(getattr(args, "previous", ""))
            current = _load_workflow_document(getattr(args, "current", ""))
            changes = daily_research.compare_daily_workflows(previous, current)
        except ValueError as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(changes, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        print("WORKFLOW CHANGES")
        if not changes:
            print()
            print("none")
            return 0
        current_type = None
        for change in changes:
            change_type = str(change.get("change_type") or "")
            cve = str(change.get("cve_id") or "")
            program = str(change.get("program") or "")
            if change_type != current_type:
                print()
                print(change_type)
                current_type = change_type
            print(f"  {cve} → {program}")
            if change_type not in ("NEW", "REMOVED"):
                print(f"  {change.get('before')} → {change.get('after')}")
        return 0

    return 2


def run_opportunity(args: argparse.Namespace) -> int:
    """Stage R26.1 read-only opportunity intelligence (no new scoring).

    Composes R18/R21/R22/R23/R24/R25.2/R25.5/R25.7 into a researcher-oriented
    opportunity view. The Money Score is copied verbatim; nothing is executed,
    fetched, tuned or predicted.
    """

    from backend import research_opportunities

    command = getattr(args, "opportunity_command", None)

    if command == "list":
        limit = getattr(args, "limit", None)
        if limit is None or limit < 0:
            limit = research_opportunities.MAX_OPPORTUNITIES
        try:
            data = research_opportunities.list_opportunities(
                limit=limit,
                offset=0,
                cve=getattr(args, "cve", None),
                program=getattr(args, "program", None),
            )
        except ValueError as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        items = data["items"]
        if not items:
            print("OPPORTUNITY QUEUE: none (no R18/R25 candidates match)")
            return 0
        if getattr(args, "json", False):
            print(json.dumps(items, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        print("OPPORTUNITY QUEUE")
        print()
        for index, item in enumerate(items, start=1):
            print(f"#{index} {item['opportunity_class']}")
            print(f"    {item['cve_id']} → {item['program']}")
            print(f"    Money: {item['money_score']} / "
                  f"{item['money_priority']}")
            print(f"    Confidence: {item['confidence']}")
            print(f"    Evidence: {item['evidence_quality']}")
            print(f"    Effort: {item['estimated_minutes']} min")
            print(f"    Action: {item['recommended_action']}")
            if item["why_now"]:
                print()
                print("    Why now:")
                for code in item["why_now"]:
                    print(f"      {code}")
            print()
        print(f"OPPORTUNITIES: {len(items)}")
        return 0

    if command == "show":
        try:
            item = research_opportunities.get_opportunity(
                getattr(args, "lead_id", "")
            )
        except (ValueError, OSError) as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(item, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        print("Opportunity Intelligence")
        print("========================")
        print(f"Class:      {item['opportunity_class']}")
        print(f"Lead:       {item['lead_id']} "
              f"({item['cve_id']} → {item['program']})")
        print(f"Money:      {item['money_score']} / "
              f"{item['money_priority']}")
        print(f"Confidence: {item['confidence']}")
        print(f"Evidence:   {item['evidence_quality']}")
        print(f"Action:     {item['recommended_action']}")
        if item["why_now"]:
            print("Why now:")
            for code in item["why_now"]:
                print(f"  {code}")
        if item["blockers"]:
            print("Blockers:")
            for blocker in item["blockers"]:
                print(f"  - {blocker}")
        return 0

    if command == "summary":
        summary = research_opportunities.opportunity_summary()
        if getattr(args, "json", False):
            print(json.dumps(summary, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        print("Opportunity Summary")
        print("===================")
        print(f"Total: {summary['total']}")
        for name, count in summary["by_class"].items():
            print(f"  {name}: {count}")
        return 0

    if command == "action-list":
        return _opportunity_action_list(args)
    if command == "action-show":
        return _opportunity_action_show(args)
    if command == "action-summary":
        return _opportunity_action_summary(args)

    return 2


def _action_human_label(action: str) -> str:
    return {
        "VERIFY_ASSET_MATCH": "VERIFY ASSET",
        "GATHER_EVIDENCE": "GATHER EVIDENCE",
        "START_RESEARCH": "START RESEARCH",
        "CONTINUE_RESEARCH": "CONTINUE",
        "REVIEW_OUTCOME": "REVIEW OUTCOME",
        "DEFER": "DEFER",
    }.get(action, action)


def _opportunity_action_list(args: argparse.Namespace) -> int:
    """Stage R26.2 read-only Action Queue (no execution)."""

    from backend import research_action_queue

    try:
        data = research_action_queue.list_actions(
            limit=getattr(args, "limit", 50) or 50,
            offset=0,
            opportunity_class=getattr(args, "class_filter", None),
            status=getattr(args, "status", None),
            cve=getattr(args, "cve", None),
            program=getattr(args, "program", None),
        )
    except ValueError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    items = data["items"]
    if not items:
        print("ACTION QUEUE: none (no R18 / R26 candidates match)")
        return 0

    if getattr(args, "json", False):
        print(json.dumps(items, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    print("ACTION QUEUE")
    print()
    for index, item in enumerate(items, start=1):
        print(f"#{index} {item['current_status']}")
        print(f"    {item['cve_id']} → {item['program']}")
        money = item.get("money_score")
        priority = item.get("priority") or ""
        print(
            f"    Money: {money} / "
            f"{priority.split('_', 1)[0] if priority else '—'}"
        )
        print(f"    Confidence: {item['confidence']}")
        print(
            f"    Action: {item['recommended_action']} "
            f"({_action_human_label(item['recommended_action'])})"
        )
        if item.get("blockers"):
            print()
            print("    Blocker:")
            for blocker in item["blockers"]:
                print(f"      {blocker}")
        print()
        print("    Next:")
        print(f"      {item['next_step']}")
        print()
    print(f"ACTIONS: {len(items)}")
    return 0


def _opportunity_action_show(args: argparse.Namespace) -> int:
    """Stage R26.2 one action by lead id (read-only)."""

    from backend import research_action_queue

    try:
        item = research_action_queue.get_action(
            getattr(args, "lead_id", "")
        )
    except (ValueError, OSError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        print(json.dumps(item, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    print("Opportunity Action")
    print("==================")
    print(f"Status:    {item['current_status']}")
    print(
        f"Lead:      {item['lead_id']} "
        f"({item['cve_id']} → {item['program']})"
    )
    print(f"Class:     {item['opportunity_class']}")
    print(
        f"Money:     {item['money_score']} / "
        f"{(item.get('priority') or '—').split('_', 1)[0]}"
    )
    print(f"Confidence: {item['confidence']}")
    print(
        f"Action:    {item['recommended_action']} "
        f"({_action_human_label(item['recommended_action'])})"
    )
    print(f"Why:       {item['action_reason']}")
    if item.get("blockers"):
        print("Blocker:")
        for blocker in item["blockers"]:
            print(f"  - {blocker}")
    print()
    print("Next:")
    print(f"  {item['next_step']}")
    return 0


def _opportunity_action_summary(args: argparse.Namespace) -> int:
    """Stage R26.2 compact action counts + top action (read-only)."""

    from backend import research_action_queue

    summary = research_action_queue.action_summary()
    if getattr(args, "json", False):
        print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    print("Action Queue Summary")
    print("====================")
    print(f"Total:      {summary['total']}")
    print(f"Ready:      {summary['ready']}")
    print(f"Blocked:    {summary['blocked']}")
    print(f"In progress:{summary['in_progress']}")
    print(f"Deferred:   {summary['deferred']}")
    print(f"Completed:  {summary['completed']}")
    if summary.get("top_action"):
        print()
        print(f"Top action: {summary['top_action']}")
        print(f"Top lead:   {summary.get('top_lead') or '—'}")
        print(f"Top program:{summary.get('top_program') or '—'}")
        print(f"Top reason: {summary.get('top_reason') or '—'}")
    return 0


def run_economics(args: argparse.Namespace) -> int:
    """Deterministic, read-only Money Score queue (Stage R25.3).

    Projects R18 queue -> R21 leads -> R22 plans -> R15/R16 intelligence ->
    persisted CVE payload -> R20 task state -> R23 result -> R24 loop result
    through the R25.2 economic engine. No network, no LLM, no subprocess,
    no active validation. A projection is research planning only — never a
    confirmed finding.
    """
    if getattr(args, "economics_command", None) == "outcome":
        return run_economics_outcome(args)
    if getattr(args, "economics_command", None) == "calibration":
        return run_economics_calibration(args)
    if getattr(args, "economics_command", None) == "session":
        return run_economics_session(args)

    from backend import research_economics

    limit = getattr(args, "limit", None)
    if limit is None or limit < 0:
        limit = research_economics.MAX_ECONOMICS
    try:
        data = research_economics.list_research_economics(
            limit=limit,
            offset=0,
            cve=getattr(args, "cve", None),
            program=getattr(args, "program", None),
        )
    except ValueError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    items = data["items"]
    if not items:
        print("MONEY QUEUE: none (no R18 queue candidates match)")
        return 0

    if getattr(args, "json", False):
        print(json.dumps(items, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    # Concise researcher-first output: which lead deserves time first.
    print("MONEY QUEUE")
    print()
    for index, item in enumerate(items, start=1):
        print(f"#{index}  {item['money_score']}  {item['priority']}")
        print(f"    {item['cve_id']} → {item['program']}")
        print(f"    Confidence: {item['confidence']}")
        print(f"    Effort: {item['effort_estimate']}")
        print(f"    Action: {item['recommended_action']}")
        print()
    print(f"MONEY QUEUE: {len(items)}")
    return 0


def run_economics_outcome(args: argparse.Namespace) -> int:
    """Stage R25.5 economic outcome capture (append-only, research-only).

    Records what happened when a researcher acted on an R25 lead so a future
    R25.6 calibration stage can be data-driven. No payout fields, no LLM,
    no network, no execution, no Money Score changes.
    """

    from backend import research_outcomes

    command = getattr(args, "outcome_command", None)

    if command == "add":
        try:
            result = research_outcomes.record_outcome(
                lead_id=getattr(args, "lead_id", ""),
                status=getattr(args, "status", ""),
                time_spent_minutes=getattr(args, "time_minutes", 0),
                note=getattr(args, "note", ""),
                source=getattr(args, "source", "MANUAL"),
            )
        except (ValueError, OSError) as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        outcome = result["outcome"]
        if getattr(args, "json", False):
            print(json.dumps(result, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        print("Outcome recorded")
        print("================")
        print(f"Id:      {outcome['outcome_id']}")
        print(f"Lead:    {outcome['lead_id']} "
              f"({outcome['cve_id']} → {outcome['program']})")
        print(f"Status:  {outcome['status']}")
        print(f"Time:    {outcome['time_spent_minutes']} min")
        print(f"Source:  {outcome['source']}")
        print(f"Created: {str(result['created']).lower()}")
        return 0

    if command == "list":
        try:
            data = research_outcomes.list_outcomes(
                limit=getattr(args, "limit", 50),
                offset=getattr(args, "offset", 0),
                lead_id=getattr(args, "lead_id", None),
                cve=getattr(args, "cve", None),
                program=getattr(args, "program", None),
                status=getattr(args, "status", None),
            )
        except ValueError as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(data, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        items = data["items"]
        if not items:
            print("RESEARCH OUTCOMES: none recorded")
            return 0
        print("RESEARCH OUTCOMES")
        print()
        for item in items:
            print(f"{item['outcome_id']}  {item['status']}  "
                  f"{item['cve_id']} → {item['program']}  "
                  f"{item['time_spent_minutes']} min")
        print()
        print(f"OUTCOMES: {len(items)}")
        return 0

    if command == "show":
        try:
            outcome = research_outcomes.get_outcome(
                getattr(args, "outcome_id", "")
            )
        except (ValueError, OSError) as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(outcome, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        print("Research Outcome")
        print("================")
        print(f"Id:      {outcome['outcome_id']}")
        print(f"Lead:    {outcome['lead_id']} "
              f"({outcome['cve_id']} → {outcome['program']})")
        print(f"Status:  {outcome['status']}")
        print(f"Time:    {outcome['time_spent_minutes']} min")
        print(f"Source:  {outcome['source']}")
        print(f"When:    {outcome['timestamp']}")
        if outcome.get("researcher_note"):
            print(f"Note:    {outcome['researcher_note']}")
        return 0

    if command == "summary":
        try:
            lead_id = getattr(args, "lead_id", None)
            data = (
                research_outcomes.summarize_lead_outcomes(lead_id)
                if lead_id
                else research_outcomes.summarize_economic_outcomes()
            )
        except (ValueError, OSError) as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(data, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        print("Research Outcome Summary")
        print("========================")
        if lead_id:
            print(f"Lead:             {lead_id}")
        print(f"Attempts:         {data['attempts']}")
        print(f"Accepted:         {data['accepted']}")
        print(f"Duplicate:        {data['duplicate']}")
        print(f"Rejected:         {data['rejected']}")
        print(f"Not applicable:   {data['not_applicable']}")
        print(f"Wasted time:      {data['wasted_time']}")
        print(f"In progress:      {data['in_progress']}")
        print(f"Total time:       {data['total_time_spent_minutes']} min")
        print(f"Average time:     {data['average_time_spent_minutes']} min")
        print(f"Data quality:     {data['data_quality']}")
        return 0

    return 2


def run_economics_calibration(args: argparse.Namespace) -> int:
    """Stage R25.6 offline calibration audit (read-only, no weight changes).

    Joins the R25 economic projections with R25.5 outcomes and reports whether
    the r25-1 ordering appears economically useful. Never changes weights,
    never self-tunes, never predicts payouts.
    """

    from backend import research_calibration

    try:
        report = research_calibration.build_report(
            min_samples=getattr(args, "min_samples", 10),
            cve=getattr(args, "cve", None),
            program=getattr(args, "program", None),
        )
    except (ValueError, OSError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if getattr(args, "json", False):
        print(json.dumps(report, ensure_ascii=False, indent=2,
                         sort_keys=True))
        return 0

    print("ECONOMIC CALIBRATION")
    print()
    print(f"Rule: {report['rule_version']}")
    print(f"Minimum sample: {report['minimum_terminal_outcomes']}")
    print(f"Leads: {report['total_leads']}")
    print(f"Terminal outcomes: {report['total_terminal_outcomes']}")
    print()
    populated = {band["band"]: band for band in report["bands"]}
    for name, _lo, _hi in (("P1", 85, 100), ("P2", 65, 84), ("P3", 45, 64),
                           ("P4", 30, 44), ("P5", 0, 29)):
        band = populated.get(name)
        if band is None:
            print(f"{name}: no leads")
            continue
        print(
            f"{name}: leads={band['leads']} "
            f"terminal={band['terminal_outcomes']} "
            f"accept={band['acceptance_rate']:.2f} "
            f"duplicate={band['duplicate_rate']:.2f} "
            f"wasted={band['wasted_rate']:.2f} "
            f"avg_time={band['average_time_spent_minutes']}m "
            f"[{band['sample_status']}]"
        )
    print()
    print(f"Recommendation: {report['recommendation']}")
    for reason in report["recommendation_reasons"]:
        print(f"  - {reason}")
    print("Money Score weights: UNCHANGED")
    return 0


def _print_session(session: dict) -> None:
    print(f"Session:  {session['session_id']}")
    print(f"Lead:     {session['lead_id']} "
          f"({session['cve_id']} → {session['program']})")
    print(f"Status:   {session['status']}")
    print(f"Planned:  {session['planned_minutes']} min")
    print(f"Actual:   {session['actual_minutes']} min")
    if session.get("started_at"):
        print(f"Started:  {session['started_at']}")
    if session.get("ended_at"):
        print(f"Ended:    {session['ended_at']}")
    if session.get("variance_minutes") is not None:
        print(f"Variance: {session['variance_minutes']} min")
    if session.get("efficiency_ratio") is not None:
        print(f"Efficiency: {session['efficiency_ratio']}")
    if session.get("outcome_id"):
        print(f"Outcome:  {session['outcome_id']}")
    if session.get("notes"):
        print(f"Notes:    {session['notes']}")


def run_economics_session(args: argparse.Namespace) -> int:
    """Stage R25.7 research session time accounting (no execution).

    Human time-tracking only: create/start/complete/abandon, optional R25.5
    outcome link, and read-only summaries. Never executes security testing,
    never contacts targets, never creates outcomes or adjusts scores.
    """

    from backend import research_sessions

    command = getattr(args, "session_command", None)

    if command == "start":
        try:
            result = research_sessions.begin_session(
                lead_id=getattr(args, "lead_id", ""),
                planned_minutes=getattr(args, "planned_minutes", 0),
                note=getattr(args, "note", ""),
            )
        except (ValueError, OSError) as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(result, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        print("Research session started")
        print("========================")
        _print_session(result["session"])
        return 0

    if command == "complete":
        try:
            result = research_sessions.complete_session(
                session_id=getattr(args, "session_id", ""),
                actual_minutes=getattr(args, "actual_minutes", None),
                outcome_id=getattr(args, "outcome_id", ""),
                note=getattr(args, "note", ""),
            )
        except (ValueError, OSError) as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(result, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        print("Research session completed")
        print("==========================")
        _print_session(result["session"])
        return 0

    if command == "abandon":
        try:
            result = research_sessions.abandon_session(
                session_id=getattr(args, "session_id", ""),
                actual_minutes=getattr(args, "actual_minutes", None),
                note=getattr(args, "note", ""),
            )
        except (ValueError, OSError) as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(result, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        print("Research session abandoned")
        print("==========================")
        _print_session(result["session"])
        return 0

    if command == "list":
        try:
            data = research_sessions.list_sessions(
                limit=getattr(args, "limit", 50),
                offset=getattr(args, "offset", 0),
                lead_id=getattr(args, "lead_id", None),
                cve=getattr(args, "cve", None),
                program=getattr(args, "program", None),
                status=getattr(args, "status", None),
            )
        except ValueError as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(data, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        items = data["items"]
        if not items:
            print("RESEARCH SESSIONS: none recorded")
            return 0
        print("RESEARCH SESSIONS")
        print()
        for item in items:
            print(f"{item['session_id']}  {item['status']}  "
                  f"{item['cve_id']} → {item['program']}  "
                  f"planned={item['planned_minutes']}m "
                  f"actual={item['actual_minutes']}m")
        print()
        print(f"SESSIONS: {len(items)}")
        return 0

    if command == "show":
        try:
            session = research_sessions.get_session(
                getattr(args, "session_id", "")
            )
        except (ValueError, OSError) as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(session, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        print("Research Session")
        print("================")
        _print_session(session)
        return 0

    if command == "summary":
        try:
            summary = research_sessions.lead_execution_performance(
                getattr(args, "lead_id", "")
            )
        except (ValueError, OSError) as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(summary, ensure_ascii=False, indent=2,
                             sort_keys=True))
            return 0
        print("Research Execution Performance")
        print("==============================")
        print(f"Lead:              {summary['lead_id']} "
              f"({summary['cve_id']} → {summary['program']})")
        print(f"Money Score:       {summary['money_score']} "
              f"({summary['priority']})")
        print(f"Sessions:          {summary['total_sessions']} "
              f"(completed={summary['completed_sessions']}, "
              f"abandoned={summary['abandoned_sessions']})")
        print(f"Planned time:      {summary['planned_time']} min")
        print(f"Actual time:       {summary['actual_time']} min")
        print(f"Avg actual:        {summary['average_actual_minutes']} min")
        print(f"Est/actual delta:  {summary['estimated_vs_actual_delta']} min")
        print(f"Accepted:          {summary['accepted']}")
        print(f"Duplicate:         {summary['duplicate']}")
        print(f"Wasted time:       {summary['wasted_time']}")
        if summary.get("time_to_outcome") is not None:
            print(f"Time to outcome:   {summary['time_to_outcome']} min "
                  f"({summary['time_to_outcome_samples']} sample(s))")
        return 0

    return 2


def run_kb_ingest(
    args: argparse.Namespace, store=None, research_dir=None
) -> int:
    """Ingest persisted research artifacts (Stage R4).

    Local-only deterministic write path under ``kb`` (the historical
    read-only commands above are unchanged): builds KnowledgeDocuments
    from ``<CVE>.cli.json`` (+ ``<CVE>.references.json`` when present)
    and persists via ``KnowledgeStore.ingest``. ``--dry-run`` builds
    without writing. No network, no LLM, no subprocess.
    """
    from ai.knowledge.ingestion import (
        ResearchIngestionError,
        ingest_research,
    )

    store = store if store is not None else _kb_store()
    kwargs: dict = {}
    if research_dir is not None:
        kwargs["research_dir"] = research_dir
    try:
        result = ingest_research(
            args.cve,
            store,
            dry_run=bool(getattr(args, "dry_run", False)),
            references_only=bool(getattr(args, "references_only", False)),
            **kwargs,
        )
    except ResearchIngestionError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if result.dry_run:
        print(f"DRY-RUN: {result.cve_id} (no writes performed)")
    else:
        print(f"INGESTED: {result.cve_id}")
    for knowledge_id in result.knowledge_ids:
        state = (
            "present"
            if knowledge_id in result.existing
            else ("would-create" if result.dry_run else "created")
        )
        print(f"  {knowledge_id} {state}")
    for note in result.notes:
        print(f"  note: {note}")
    print("MODE: local-only ingestion (no network, no LLM, no execution)")
    return 0


# ---------------------------------------------------------------------------
# Stage R23: autonomous research agent CLI.
#
# Research-only, bounded, fail-soft. `dry-run` performs zero network and zero
# LLM activity; `run` enforces the scheduler window/enabled policy unless
# --force is given. No target interaction, no Nuclei, no findings.
# ---------------------------------------------------------------------------


def _build_llm_provider():
    """Build the existing OpenRouter provider (never a new provider).

    Honors WATCH_LLM_PROVIDER / WATCH_LLM_MODEL when present while leaving the
    existing OPENROUTER_* configuration authoritative (the provider falls back
    to OPENROUTER_MODEL/OPENROUTER_API_KEY when WATCH_LLM_MODEL is unset).
    """
    from dotenv import load_dotenv

    load_dotenv()
    provider = (
        os.getenv("WATCH_LLM_PROVIDER", "").strip()
        or os.getenv("AI_PROVIDER", "").strip()
        or "openrouter"
    )
    if provider != "openrouter":
        raise RuntimeError(
            f"unsupported WATCH_LLM_PROVIDER: {provider!r} "
            "(only the existing 'openrouter' provider is supported)"
        )
    from ai.llm.openrouter import OpenRouterProvider

    model = os.getenv("WATCH_LLM_MODEL", "").strip() or None
    return OpenRouterProvider(model=model) if model else OpenRouterProvider()


def _build_discovery_llm_provider(model, *, response_format_json: bool = True):
    """Build an OpenRouter provider for the R24 discovery path only.

    Does not change ``_build_llm_provider`` (the shared R23 path). ``model`` may
    be ``None`` to use the existing OPENROUTER_MODEL configuration.
    """
    from dotenv import load_dotenv

    load_dotenv()
    from ai.llm.openrouter import OpenRouterProvider

    return OpenRouterProvider(model=model, response_format_json=response_format_json)


def _build_discovery_agent(config):
    """Build the R24.8 discovery adapter (netguard-routed, bounded).

    LLM is used only when ``WATCH_RESEARCH_LLM`` is enabled (unchanged R23
    policy). The transport is the single real R24.8 adapter; both provider
    discovery and source-body fetching pass through R24.3 netguard.
    """
    from ai.research_agent.discovery_runner import DiscoveryResearchAgent
    from ai.research_agent.llm_loop import LoopBudgets
    from ai.research_agent.transport import HTTPTransport

    transport = HTTPTransport(
        max_bytes=config.discovery_max_bytes_per_source,
        total_timeout=float(config.discovery_deadline_seconds),
    )
    budgets = LoopBudgets(
        max_rounds=config.discovery_max_rounds,
        max_queries_per_plan=config.discovery_max_queries_per_plan,
        round2_reserve=0,
        max_queries_per_run=config.discovery_max_queries_per_plan,
        max_discovered=config.discovery_max_discovered,
        max_fetched_per_plan=config.discovery_max_fetched,
        max_fetched_per_run=config.discovery_max_fetched,
        max_bytes_per_source=config.discovery_max_bytes_per_source,
        max_bytes_per_run=config.discovery_max_bytes_per_run,
        max_llm_calls_per_plan=config.discovery_max_llm_calls,
        max_llm_calls_per_run=config.discovery_max_llm_calls,
    )
    # R24.11: primary provider + optional explicitly-configured fallback model.
    # Fallback is disabled unless WATCH_RESEARCH_LLM_FALLBACK_MODEL is set, and
    # every attempt (primary/fallback/retry) shares the same LLM call budget.
    llm = None
    llm_fallback = None
    if config.llm:
        response_format_json = (
            str(getattr(config, "llm_response_format", "json") or "json").lower()
            != "text"
        )
        llm = _build_discovery_llm_provider(
            getattr(config, "llm_model", "") or None,
            response_format_json=response_format_json,
        )
        fallback_model = getattr(config, "llm_fallback_model", "") or ""
        if fallback_model:
            llm_fallback = _build_discovery_llm_provider(
                fallback_model, response_format_json=response_format_json
            )
    return DiscoveryResearchAgent(
        transport=transport,
        llm=llm,
        llm_enabled=config.llm,
        llm_fallback=llm_fallback,
        llm_max_retries=int(getattr(config, "llm_max_retries", 0) or 0),
        budgets=budgets,
        agent_dir=config.agent_dir,
        research_dir=config.research_dir,
        deadline_seconds=config.discovery_deadline_seconds,
        max_plans=config.discovery_max_plans,
    )


def _build_research_agent(config):
    if getattr(config, "discovery", False):
        return _build_discovery_agent(config)

    from ai.research_agent.agent import ResearchAgent
    from ai.research_agent.sources import ResearchSourceCollector

    sources = ResearchSourceCollector(
        research_dir=config.research_dir,
        max_sources=config.max_sources,
    )
    llm = _build_llm_provider() if config.llm else None
    kb_store = None
    if config.kb_ingest:
        from ai.knowledge.store import KnowledgeStore

        kb_store = KnowledgeStore()
    return ResearchAgent(
        sources=sources,
        llm=llm,
        llm_enabled=config.llm,
        network_enabled=config.network,
        agent_dir=config.agent_dir,
        research_dir=config.research_dir,
        kb_ingest=config.kb_ingest,
        kb_store=kb_store,
    )


def run_agent_status(args: argparse.Namespace) -> int:
    from ai.research_agent.scheduler import ResearchScheduler, SchedulerConfig

    config = SchedulerConfig.from_env()
    scheduler = ResearchScheduler(config)
    info = scheduler.status()
    if getattr(args, "json", False):
        print(json.dumps(info, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    print("Research Agent")
    print("==============")
    print()
    print(f"Enabled: {str(info['enabled']).lower()}")
    print(f"Window: {info['window']}")
    print(f"In window: {str(info['in_window']).lower()}")
    print(f"Max runtime: {info['max_minutes']}m")
    print(f"Max plans: {info['max_plans']}")
    print(f"Network: {'enabled' if info['network'] else 'disabled'}")
    print(f"LLM: {'enabled' if info['llm'] else 'disabled'}")
    print(f"R24 discovery: {'enabled' if info.get('discovery') else 'disabled'}")
    if info.get("discovery"):
        budget = info.get("discovery_budget") or {}
        print(
            "  discovery budget: "
            f"plans={budget.get('max_plans')} rounds={budget.get('max_rounds')} "
            f"queries/plan={budget.get('max_queries_per_plan')} "
            f"discovered={budget.get('max_discovered')} "
            f"fetched={budget.get('max_fetched')} "
            f"llm_calls={budget.get('max_llm_calls')} "
            f"deadline={budget.get('deadline_seconds')}s"
        )
    print(f"Next run: {info['next_run']}")
    print()
    print(f"Eligible plans ({info['eligible_count']}):")
    for index, plan in enumerate(info["eligible_plans"], start=1):
        print(f"  #{index} {plan.get('cve_id')} -> {plan.get('program')}")
    return 0


def run_agent_dry_run(args: argparse.Namespace) -> int:
    """Preview eligible plans with ZERO network and ZERO LLM activity."""
    from ai.research_agent.scheduler import ResearchScheduler, SchedulerConfig

    config = SchedulerConfig.from_env()
    # No agent is constructed: no provider, no fetcher.
    scheduler = ResearchScheduler(config)
    preview = scheduler.preview(
        plan_id=getattr(args, "plan", None),
        limit=getattr(args, "limit", None),
    )
    if getattr(args, "json", False):
        print(json.dumps(preview, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    print("Research Agent")
    print("==============")
    print()
    print(f"Enabled: {str(preview['enabled']).lower()}")
    print(f"Window: {preview['window']}")
    print(f"Network: {'enabled' if preview['network'] else 'disabled'}")
    print(f"LLM: {'enabled' if preview['llm'] else 'disabled'}")
    print(f"R24 discovery: {'enabled' if preview.get('discovery') else 'disabled'}")
    print()
    print("Eligible plans:")
    if not preview["plans"]:
        print("  (none)")
    for index, plan in enumerate(preview["plans"], start=1):
        print(f"  #{index} {plan.get('cve_id')} -> {plan.get('program')}")
    print()
    print("MODE: dry-run (no network, no LLM, no writes)")
    return 0


def run_agent_run(args: argparse.Namespace) -> int:
    from ai.research_agent.scheduler import ResearchScheduler, SchedulerConfig

    config = SchedulerConfig.from_env()
    network = None
    if getattr(args, "no_network", False):
        network = False
    elif getattr(args, "network", False):
        network = True

    scheduler = ResearchScheduler(config, agent=_build_research_agent(config))
    record = scheduler.run_once(
        plan_id=getattr(args, "plan", None),
        limit=getattr(args, "limit", None),
        force=bool(getattr(args, "force", False)),
        dry_run=False,
        network=network,
    )
    if getattr(args, "json", False):
        print(json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    print(f"RUN: {record['run_id']}")
    print(f"STATUS: {record['status']}")
    if record.get("skipped"):
        print(f"SKIPPED: {record['skipped']}")
    print(f"Plans selected: {record['plans_selected']}")
    print(f"Plans processed: {record['plans_processed']}")
    for item in record.get("results", []):
        print(
            f"  {item.get('plan_id')} {item.get('cve_id')} -> "
            f"{item.get('program')} [{item.get('status')}] "
            f"evidence={item.get('evidence')} sources={item.get('sources')}"
        )
    for failure in record.get("failures", []):
        print(f"  failure: {failure}")
    print("MODE: research-only (no target interaction, no Nuclei, no findings)")
    return 0


def run_agent_report(args: argparse.Namespace) -> int:
    from ai.research_agent import storage
    from ai.research_agent.scheduler import SchedulerConfig

    config = SchedulerConfig.from_env()
    results = storage.list_results(base=config.agent_dir)
    plan_id = getattr(args, "plan", None)
    if plan_id:
        results = [r for r in results if r.get("plan_id") == plan_id]
    if getattr(args, "json", False):
        print(json.dumps(results, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if not results:
        print("RESEARCH AGENT RESULTS: none")
        return 0
    print("Research Agent Results")
    print("======================")
    for result in results:
        print(
            f"{result.get('result_id')} | {result.get('cve_id')} -> "
            f"{result.get('program')} | {result.get('status')} | "
            f"evidence={len(result.get('evidence') or [])} "
            f"sources={len(result.get('sources') or [])}"
        )
        if result.get("report_path"):
            print(f"  report: {result['report_path']}")
    print(f"RESULTS: {len(results)}")
    return 0


def run_agent(args: argparse.Namespace) -> int:
    command = getattr(args, "agent_command", None)
    if command == "status":
        return run_agent_status(args)
    if command == "run":
        return run_agent_run(args)
    if command == "dry-run":
        return run_agent_dry_run(args)
    if command == "report":
        return run_agent_report(args)
    return 2


# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Watch AI research agent (research-only, dry-run).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="offline readiness check (no LLM/NVD calls)")

    # Top-level "research" handles both legacy single-CVE research and the
    # Stage R22 execution-plan subcommand "research plan". --cve is optional
    # at the argparse level so "research plan" parses; the main() dispatcher
    # enforces required args per mode.
    research = sub.add_parser(
        "research",
        help="research a single CVE or render execution plans (see 'research plan --help')",
    )
    research.add_argument("--cve", required=False, default=None, help="e.g. CVE-2026-1557")
    research.add_argument(
        "--skip-llm",
        action="store_true",
        help="collect/correlate only, skip the LLM call (single-CVE mode)",
    )
    research_sub = research.add_subparsers(dest="research_command", required=False)
    plan_parser = research_sub.add_parser(
        "plan",
        help="render a deterministic research execution plan for a CVE/program lead (read-only, no network)",
    )
    plan_parser.add_argument("--cve", default=None, help="filter by CVE, e.g. CVE-2026-1557")
    plan_parser.add_argument("--program", default=None, help="filter by program, e.g. dell")
    plan_parser.add_argument("--lead", default=None, help="filter by lead id, e.g. rl-... or plan id r22-...")
    plan_parser.add_argument("--limit", type=int, default=None, help="show at most this many plans")
    plan_parser.add_argument("--json", action="store_true", help="emit plans as JSON")

    batch = sub.add_parser("batch", help="research recent correlated CVEs")
    batch.add_argument("--days", type=int, default=7)
    batch.add_argument("--limit", type=int, default=5)
    batch.add_argument(
        "--cves",
        default=None,
        help="comma-separated CVE IDs for batch research, "
        "e.g. CVE-2026-1557,CVE-2026-0001",
    )
    batch.add_argument(
        "--file",
        default=None,
        help="file with one CVE ID per line for batch research",
    )
    batch.add_argument(
        "--skip-llm",
        action="store_true",
        help="collect/correlate only, skip the LLM call (batch CVE-list mode)",
    )

    validate = sub.add_parser(
        "validate-live",
        help="controlled live validation lane for CVE-2026-1557 "
        "(offline dry-run by default)",
    )
    validate.add_argument(
        "--cve", required=True, help="CVE id (hard-scoped to CVE-2026-1557)"
    )
    validate.add_argument(
        "--target",
        default=None,
        help="explicit target (required for execution; dry-run reports "
        "the gate chain without network)",
    )
    validate.add_argument(
        "--live",
        action="store_true",
        help="attempt live execution; also requires "
        "WATCH_AI_LIVE_VALIDATION=true or the lane blocks at config",
    )

    kb = sub.add_parser(
        "kb",
        help="read-only knowledge-base inspection (no writes)",
    )
    kb_sub = kb.add_subparsers(dest="kb_command", required=True)

    kb_list = kb_sub.add_parser(
        "list", help="list all KB documents (deterministic order)"
    )
    kb_list.add_argument(
        "--json",
        action="store_true",
        help="emit full documents as JSON",
    )

    kb_show = kb_sub.add_parser(
        "show", help="show one KB document by knowledge_id"
    )
    kb_show.add_argument(
        "knowledge_id", help="e.g. kb-0123456789abcdef"
    )

    kb_search = kb_sub.add_parser(
        "search",
        help="exact-match metadata search "
        "(same filters as KnowledgeStore.retrieve)",
    )
    kb_search.add_argument(
        "--technology",
        dest="technologies",
        action="append",
        default=None,
    )
    kb_search.add_argument(
        "--xss-type",
        dest="xss_types",
        action="append",
        default=None,
    )
    kb_search.add_argument(
        "--context",
        dest="contexts",
        action="append",
        default=None,
    )
    kb_search.add_argument(
        "--waf", dest="wafs", action="append", default=None
    )
    kb_search.add_argument(
        "--technique",
        dest="techniques",
        action="append",
        default=None,
    )
    kb_search.add_argument(
        "--source-type",
        dest="source_types",
        action="append",
        default=None,
    )
    kb_search.add_argument(
        "--evidence-quality",
        dest="evidence_quality",
        action="append",
        default=None,
    )
    kb_search.add_argument(
        "--tag", dest="tags", action="append", default=None
    )
    kb_search.add_argument(
        "--json",
        action="store_true",
        help="emit full documents as JSON",
    )

    kb_ingest = kb_sub.add_parser(
        "ingest",
        help="ingest persisted research artifacts into the local "
        "KnowledgeStore (deterministic, idempotent, no network, no LLM)",
    )
    kb_ingest.add_argument("--cve", required=True, help="e.g. CVE-2026-1557")
    kb_ingest.add_argument(
        "--dry-run",
        action="store_true",
        help="build documents without writing to the store",
    )
    kb_ingest.add_argument(
        "--references-only",
        action="store_true",
        help="ingest only the references archive",
    )

    # Stage R16: deterministic, read-only research prioritization.
    priority = sub.add_parser(
        "priority",
        help="deterministic research prioritization over the local "
        "KnowledgeStore (read-only, no network, no LLM)",
    )
    priority.add_argument(
        "--cve",
        default=None,
        help="rank one CVE, e.g. CVE-2026-1557",
    )
    priority.add_argument(
        "--all",
        action="store_true",
        help="rank every CVE synthesis document (default when --cve is absent)",
    )
    priority.add_argument(
        "--json",
        action="store_true",
        help="emit the ranking as JSON",
    )

    # Stage R17: deterministic, read-only asset/program relevance.
    relevance = sub.add_parser(
        "relevance",
        help="deterministic asset/program relevance over the local "
        "KnowledgeStore (read-only, no network, no LLM, no validation)",
    )
    relevance.add_argument(
        "--cve",
        default=None,
        help="evaluate one CVE, e.g. CVE-2026-1557",
    )
    relevance.add_argument(
        "--all",
        action="store_true",
        help="evaluate every CVE synthesis document (default when --cve absent)",
    )
    relevance.add_argument(
        "--assets",
        default=None,
        help="path to a local asset-snapshot JSON (overrides local programs)",
    )
    relevance.add_argument(
        "--json",
        action="store_true",
        help="emit the results as JSON",
    )

    # Stage R18: deterministic, read-only research queue.
    queue = sub.add_parser(
        "queue",
        help="deterministic research queue combining R16 priority and R17 "
        "relevance (read-only, no network, no LLM, no validation)",
    )
    queue.add_argument(
        "--cve",
        default=None,
        help="limit to one CVE, e.g. CVE-2026-1557",
    )
    queue.add_argument(
        "--limit",
        type=int,
        default=None,
        help="show at most this many ranked items",
    )
    queue.add_argument(
        "--json",
        action="store_true",
        help="emit the queue as JSON",
    )

    # Stage R21: deterministic, read-only actionable research leads.
    leads = sub.add_parser(
        "leads",
        help="deterministic actionable research leads projecting R15-R20 "
        "intelligence (read-only, no network, no LLM, no validation)",
    )
    leads.add_argument(
        "--cve",
        default=None,
        help="limit leads to one CVE, e.g. CVE-2026-1557",
    )
    leads.add_argument(
        "--program",
        default=None,
        help="limit leads to one program, e.g. dell",
    )
    leads.add_argument(
        "--limit",
        type=int,
        default=None,
        help="show at most this many leads",
    )
    leads.add_argument(
        "--json",
        action="store_true",
        help="emit the leads as JSON",
    )

    # Stage R26.1: read-only opportunity intelligence (Money Score copied).
    opportunity = sub.add_parser(
        "opportunity",
        help="read-only economic opportunity queue composing R18-R25 "
        "signals (no new scoring, no execution, no payouts)",
    )
    opportunity_sub = opportunity.add_subparsers(
        dest="opportunity_command", required=True)

    opportunity_list = opportunity_sub.add_parser(
        "list", help="ranked opportunity queue (read-only)")
    opportunity_list.add_argument("--limit", type=int, default=50,
                                  help="show at most this many opportunities")
    opportunity_list.add_argument("--cve", default=None,
                                  help="filter by CVE, e.g. CVE-2026-1557")
    opportunity_list.add_argument("--program", default=None,
                                  help="filter by program, e.g. dell")
    opportunity_list.add_argument("--json", action="store_true",
                                  help="emit the opportunities as JSON")

    opportunity_show = opportunity_sub.add_parser(
        "show", help="one opportunity by lead id (read-only)")
    opportunity_show.add_argument("--lead-id", required=True,
                                  help="R21 lead id, e.g. rl-...")
    opportunity_show.add_argument("--json", action="store_true",
                                  help="emit the opportunity as JSON")

    opportunity_summary = opportunity_sub.add_parser(
        "summary", help="compact class counts + top opportunities")
    opportunity_summary.add_argument("--json", action="store_true",
                                     help="emit the summary as JSON")

    # Stage R26.2: read-only researcher Action Queue.
    opportunity_action_list = opportunity_sub.add_parser(
        "action-list",
        help="ranked researcher Action Queue (read-only, no new score)",
    )
    opportunity_action_list.add_argument(
        "--class", dest="class_filter", default=None,
        help="filter by opportunity class, e.g. BLOCKED or HIGH_VALUE",
    )
    opportunity_action_list.add_argument(
        "--status", default=None,
        help="filter by current_status, e.g. BLOCKED / READY / IN_PROGRESS",
    )
    opportunity_action_list.add_argument(
        "--cve", default=None, help="filter by CVE, e.g. CVE-2026-1557",
    )
    opportunity_action_list.add_argument(
        "--program", default=None, help="filter by program, e.g. dell",
    )
    opportunity_action_list.add_argument(
        "--limit", type=int, default=50,
        help="show at most this many actions (default 50)",
    )
    opportunity_action_list.add_argument(
        "--json", action="store_true", help="emit the actions as JSON",
    )

    opportunity_action_show = opportunity_sub.add_parser(
        "action-show", help="one action by lead id (read-only)")
    opportunity_action_show.add_argument(
        "--lead-id", required=True,
        help="R21 lead id, e.g. rl-...",
    )
    opportunity_action_show.add_argument(
        "--json", action="store_true", help="emit the action as JSON",
    )

    opportunity_action_summary = opportunity_sub.add_parser(
        "action-summary",
        help="compact action counts + top action (read-only)",
    )
    opportunity_action_summary.add_argument(
        "--json", action="store_true", help="emit the summary as JSON",
    )

    # Stage R27.1: product validation audit (read-only, no new score).
    product = sub.add_parser(
        "product",
        help="product validation over existing R25/R26 data "
        "(read-only, no execution, no payouts)",
    )
    product_sub = product.add_subparsers(
        dest="product_command", required=True)
    product_validation = product_sub.add_parser(
        "validation",
        help="does Watch help researchers choose better opportunities? "
        "(metrics + hypotheses; no statistical claims)",
    )
    product_validation.add_argument("--cve", default=None,
                                    help="filter by CVE")
    product_validation.add_argument("--program", default=None,
                                    help="filter by program")
    product_validation.add_argument("--min-sessions", type=int, default=20,
                                    help="minimum started sessions (default 20)")
    product_validation.add_argument("--min-outcomes", type=int, default=20,
                                    help="minimum terminal outcomes (default 20)")
    product_validation.add_argument("--min-leads", type=int, default=10,
                                    help="minimum leads (default 10)")
    product_validation.add_argument("--json", action="store_true",
                                    help="emit the validation report as JSON")
    product_opportunities = product_sub.add_parser(
        "opportunities",
        help="local projection of the v1 research-opportunity API "
        "(read-only, no execution, no payouts)",
    )
    product_opportunities.add_argument("--cve", default=None,
                                       help="filter by CVE")
    product_opportunities.add_argument("--program", default=None,
                                       help="filter by program")
    product_opportunities.add_argument("--limit", type=int, default=50,
                                       help="show at most this many (1-100)")
    product_opportunities.add_argument("--json", action="store_true",
                                       help="emit v1 items as JSON")
    product_remote = product_sub.add_parser(
        "remote-opportunities",
        help="consume the public Product API v1 over HTTP (read-only; "
        "external client, no local fallback)",
    )
    product_remote.add_argument("--base-url", required=True,
                                help="API base URL, e.g. https://watch.local")
    product_remote.add_argument("--api-key-env",
                                default="WATCH_PRODUCT_API_KEY",
                                help="environment variable holding the API key")
    product_remote.add_argument("--limit", type=int, default=50)
    product_remote.add_argument("--offset", type=int, default=0)
    product_remote.add_argument("--cve", default=None)
    product_remote.add_argument("--program", default=None)
    product_remote.add_argument("--class", dest="class_filter", default=None)
    product_remote.add_argument("--action", default=None)
    product_remote.add_argument("--status", default=None)
    product_remote.add_argument("--min-money-score", type=int, default=None)
    product_remote.add_argument("--timeout", type=float, default=10.0,
                                help="request timeout in seconds")
    product_remote.add_argument("--json", action="store_true",
                                help="emit the raw v1 list envelope as JSON")

    # Stage R29.1: personal bug-bounty hunt queue (read-only, no execution).
    hunt = sub.add_parser(
        "hunt",
        help="personal bug-bounty hunt queue over the R26.2 action queue "
        "(read-only, research-only, no execution)",
    )
    hunt.add_argument("--limit", type=int, default=50,
                      help="show at most this many hunt items (1-100)")
    hunt.add_argument("--cve", default=None, help="filter by CVE")
    hunt.add_argument("--program", default=None, help="filter by program")
    hunt.add_argument("--priority", default=None, choices=list(HUNT_PRIORITIES),
                      help="filter by hunt priority tier")
    hunt.add_argument("--class", dest="class_filter", default=None,
                      help="filter by opportunity class")
    hunt.add_argument("--status", default=None,
                      help="filter by current_status")
    hunt.add_argument("--json", action="store_true",
                      help="emit hunt items as JSON")

    # Stage R30.1: deterministic asset <-> CVE matching intelligence
    # (read-only, research-only, no execution, no target interaction).
    match = sub.add_parser(
        "match",
        help="asset <-> CVE matching intelligence over existing recon data "
        "(read-only, research-only, no execution)",
    )
    match_sub = match.add_subparsers(dest="match_command", required=True)
    match_cve = match_sub.add_parser(
        "cve", help="match one CVE against known assets/programs")
    match_cve.add_argument("--cve", required=True,
                           help="CVE id, e.g. CVE-2026-1557")
    match_cve.add_argument("--program", default=None,
                           help="limit to one program, e.g. dell")
    match_cve.add_argument("--json", action="store_true",
                           help="emit the match projection as JSON")

    # Stage R30.2: observed asset inventory derived from existing Watch data
    # (read-only, research-only, no execution, no target interaction).
    inventory = sub.add_parser(
        "inventory",
        help="observed asset inventory derived from existing Watch recon data "
        "(read-only, research-only, no execution)",
    )
    inventory.add_argument("--program", default=None,
                           help="limit to one program, e.g. dell")
    inventory.add_argument("--json", action="store_true",
                           help="emit the observed inventory as JSON")

    # Stage R26.3: daily research workflow + offline workflow diff.
    workflow = sub.add_parser(
        "workflow",
        help="daily research workflow derived from the R26.2 Action Queue "
        "(read-only, no persistence, no execution)",
    )
    workflow_sub = workflow.add_subparsers(
        dest="workflow_command", required=True)

    workflow_daily = workflow_sub.add_parser(
        "daily", help="today's deterministic research workflow (read-only)")
    workflow_daily.add_argument("--limit", type=int, default=5,
                                help="top-N opportunities (default 5)")
    workflow_daily.add_argument("--class", dest="class_filter", default=None,
                                help="filter by opportunity class")
    workflow_daily.add_argument("--status", default=None,
                                help="filter by current_status")
    workflow_daily.add_argument("--cve", default=None,
                                help="filter by CVE, e.g. CVE-2026-1557")
    workflow_daily.add_argument("--program", default=None,
                                help="filter by program, e.g. dell")
    workflow_daily.add_argument("--json", action="store_true",
                                help="emit the workflow as JSON")

    workflow_diff = workflow_sub.add_parser(
        "diff",
        help="offline compare two workflow JSON files (inputs only; "
        "never modified, never persisted)",
    )
    workflow_diff.add_argument("--previous", required=True,
                               help="previous workflow JSON file (input only)")
    workflow_diff.add_argument("--current", required=True,
                               help="current workflow JSON file (input only)")
    workflow_diff.add_argument("--json", action="store_true",
                               help="emit the changes as JSON")

    economics = sub.add_parser(
        "economics",
        help="deterministic Money Score queue projecting R15-R24 "
        "intelligence (read-only, no network, no LLM, no validation)",
    )
    economics.add_argument(
        "--cve",
        default=None,
        help="limit projections to one CVE, e.g. CVE-2026-1557",
    )
    economics.add_argument(
        "--program",
        default=None,
        help="limit projections to one program, e.g. dell",
    )
    economics.add_argument(
        "--limit",
        type=int,
        default=None,
        help="show at most this many projections",
    )
    economics.add_argument(
        "--json",
        action="store_true",
        help="emit the projections as JSON",
    )

    # Stage R25.5: economic research outcome capture (append-only, local).
    economics_sub = economics.add_subparsers(dest="economics_command")
    outcome = economics_sub.add_parser(
        "outcome",
        help="record/list economic research outcomes for Money Score leads "
        "(append-only, no payouts, no execution)",
    )
    outcome_sub = outcome.add_subparsers(dest="outcome_command", required=True)

    outcome_add = outcome_sub.add_parser(
        "add", help="append one research outcome (idempotent)"
    )
    outcome_add.add_argument("--lead-id", required=True,
                             help="R21 lead id, e.g. rl-0123456789abcdef")
    outcome_add.add_argument("--status", required=True,
                             choices=OUTCOME_STATUSES,
                             help="research outcome status")
    outcome_add.add_argument("--time-minutes", type=int, default=0,
                             help="researcher time spent in minutes")
    outcome_add.add_argument("--note", default="",
                             help="bounded researcher note")
    outcome_add.add_argument("--source", default="MANUAL",
                             choices=list(OUTCOME_SOURCES),
                             help="outcome source")
    outcome_add.add_argument("--json", action="store_true",
                             help="emit the stored outcome as JSON")

    outcome_list = outcome_sub.add_parser(
        "list", help="list recorded outcomes (read-only)"
    )
    outcome_list.add_argument("--lead-id", default=None,
                              help="filter by R21 lead id")
    outcome_list.add_argument("--cve", default=None,
                              help="filter by CVE, e.g. CVE-2026-1557")
    outcome_list.add_argument("--program", default=None,
                              help="filter by program, e.g. dell")
    outcome_list.add_argument("--status", default=None,
                              choices=list(OUTCOME_STATUSES),
                              help="filter by outcome status")
    outcome_list.add_argument("--limit", type=int, default=50,
                              help="show at most this many outcomes")
    outcome_list.add_argument("--offset", type=int, default=0)
    outcome_list.add_argument("--json", action="store_true",
                              help="emit the list envelope as JSON")

    outcome_show = outcome_sub.add_parser(
        "show", help="show one recorded outcome (read-only)"
    )
    outcome_show.add_argument("--outcome-id", required=True,
                              help="outcome id, e.g. ro-0123456789abcdef")
    outcome_show.add_argument("--json", action="store_true",
                              help="emit the outcome as JSON")

    outcome_summary = outcome_sub.add_parser(
        "summary", help="bounded outcome aggregation (read-only)"
    )
    outcome_summary.add_argument("--lead-id", default=None,
                                 help="one lead summary (omit for all leads)")
    outcome_summary.add_argument("--json", action="store_true",
                                 help="emit the summary as JSON")

    # Stage R25.6: read-only Money Score calibration audit (no weight changes).
    calibration = economics_sub.add_parser(
        "calibration",
        help="offline read-only calibration of the r25-1 Money Score against "
        "observed research outcomes (never changes weights)",
    )
    calibration.add_argument(
        "--min-samples", type=int, default=10,
        help="minimum terminal outcomes per band for a sufficient sample "
        "(default 10)",
    )
    calibration.add_argument("--cve", default=None,
                             help="limit the calibration to one CVE")
    calibration.add_argument("--program", default=None,
                             help="limit the calibration to one program")
    calibration.add_argument("--json", action="store_true",
                             help="emit the calibration report as JSON")

    # Stage R25.7: research session time accounting (no execution/targets).
    session = economics_sub.add_parser(
        "session",
        help="research time-accounting sessions for R25 leads "
        "(no execution, no targets, no payouts)",
    )
    session_sub = session.add_subparsers(dest="session_command", required=True)

    session_start = session_sub.add_parser(
        "start", help="explicitly create+start a research session"
    )
    session_start.add_argument("--lead-id", required=True,
                               help="R21 lead id, e.g. rl-0123456789abcdef")
    session_start.add_argument("--planned-minutes", type=int, default=0,
                               help="planned research minutes")
    session_start.add_argument("--note", default="",
                               help="bounded session note")
    session_start.add_argument("--json", action="store_true",
                               help="emit the session as JSON")

    session_complete = session_sub.add_parser(
        "complete", help="complete an in-progress session"
    )
    session_complete.add_argument("--session-id", required=True,
                                  help="session id, e.g. rs-0123456789abcdef")
    session_complete.add_argument("--actual-minutes", type=int, default=None,
                                  help="actual minutes (derived from "
                                  "timestamps when omitted)")
    session_complete.add_argument("--outcome-id", default="",
                                  help="optional existing R25.5 outcome id "
                                  "for the same lead")
    session_complete.add_argument("--note", default="")
    session_complete.add_argument("--json", action="store_true")

    session_abandon = session_sub.add_parser(
        "abandon", help="abandon a planned/in-progress session"
    )
    session_abandon.add_argument("--session-id", required=True,
                                 help="session id, e.g. rs-0123456789abcdef")
    session_abandon.add_argument("--actual-minutes", type=int, default=None,
                                 help="actual minutes (optional)")
    session_abandon.add_argument("--note", default="")
    session_abandon.add_argument("--json", action="store_true")

    session_list = session_sub.add_parser(
        "list", help="list sessions (read-only)"
    )
    session_list.add_argument("--lead-id", default=None)
    session_list.add_argument("--cve", default=None)
    session_list.add_argument("--program", default=None)
    session_list.add_argument("--status", default=None,
                              choices=["PLANNED", "IN_PROGRESS",
                                       "COMPLETED", "ABANDONED"])
    session_list.add_argument("--limit", type=int, default=50)
    session_list.add_argument("--offset", type=int, default=0)
    session_list.add_argument("--json", action="store_true")

    session_show = session_sub.add_parser(
        "show", help="show one session (read-only)"
    )
    session_show.add_argument("--session-id", required=True)
    session_show.add_argument("--json", action="store_true")

    session_summary = session_sub.add_parser(
        "summary", help="per-lead session/economic summary (read-only)"
    )
    session_summary.add_argument("--lead-id", required=True)
    session_summary.add_argument("--json", action="store_true")

    # Stage R23: autonomous research scheduler/agent (research-only).
    agent = sub.add_parser(
        "agent",
        help="autonomous research agent over R22 plans (bounded, "
        "research-only; disabled by default)",
    )
    agent_sub = agent.add_subparsers(dest="agent_command", required=True)

    agent_status = agent_sub.add_parser(
        "status", help="show scheduler configuration and eligible plans"
    )
    agent_status.add_argument(
        "--json", action="store_true", help="emit status as JSON"
    )

    agent_run = agent_sub.add_parser(
        "run",
        help="run one bounded research pass (respects enabled/window "
        "unless --force)",
    )
    agent_run.add_argument(
        "--plan", default=None, help="run only this plan id, e.g. r22-..."
    )
    agent_run.add_argument(
        "--limit", type=int, default=None, help="process at most this many plans"
    )
    agent_run.add_argument(
        "--force",
        action="store_true",
        help="ignore disabled/window policy for a manual run",
    )
    agent_run.add_argument(
        "--network",
        action="store_true",
        help="enable bounded public research fetching for this run",
    )
    agent_run.add_argument(
        "--no-network",
        action="store_true",
        help="force offline for this run (overrides --network)",
    )
    agent_run.add_argument(
        "--json", action="store_true", help="emit the run record as JSON"
    )

    agent_dry = agent_sub.add_parser(
        "dry-run",
        help="preview eligible plans with zero network/LLM activity",
    )
    agent_dry.add_argument(
        "--plan", default=None, help="preview only this plan id"
    )
    agent_dry.add_argument(
        "--limit", type=int, default=None, help="preview at most this many plans"
    )
    agent_dry.add_argument(
        "--json", action="store_true", help="emit the preview as JSON"
    )

    agent_report = agent_sub.add_parser(
        "report",
        help="show stored research results (read-only)",
    )
    agent_report.add_argument(
        "--plan", default=None, help="filter to one plan id"
    )
    agent_report.add_argument(
        "--json", action="store_true", help="emit results as JSON"
    )

    # Stage R13: re-fetch persisted reference archives and update the
    # extracted body + provenance in place (research-only, fail-soft).
    references = sub.add_parser(
        "references",
        help="reference archive maintenance (Stage R13)",
    )
    references_sub = references.add_subparsers(
        dest="references_command", required=True
    )
    references_refresh = references_sub.add_parser(
        "refresh",
        help="re-fetch archived reference URLs and persist extracted "
        "body + provenance (no LLM, no execution, no retries)",
    )
    references_refresh.add_argument(
        "--cve", required=True, help="e.g. CVE-2024-5376"
    )

    report = sub.add_parser(
        "report",
        help="render a deterministic Markdown research report "
        "from persisted artifacts (no network, no LLM, no Nuclei, "
        "no Mongo)",
    )
    report.add_argument("--cve", required=True, help="e.g. CVE-2026-1557")
    report.add_argument(
        "--output",
        default=None,
        help="override output path "
        "(default: ai_data/reports/<CVE>.md)",
    )

    xss = sub.add_parser(
        "xss",
        help="deterministic XSS research agent MVP "
        "(seeded KB only; no network, no LLM, no execution)",
    )
    xss_sub = xss.add_subparsers(dest="xss_command", required=True)

    xss_sub.add_parser(
        "list", help="list persisted XSS research candidates"
    )

    xss_search = xss_sub.add_parser(
        "search",
        help="rank seeded KB documents for a query (no persistence)",
    )
    xss_search.add_argument("--query", required=True)
    xss_search.add_argument("--xss-type", default=None)
    xss_search.add_argument("--context", default=None)
    xss_search.add_argument(
        "--technology", dest="technologies", action="append", default=None
    )
    xss_search.add_argument(
        "--technique", dest="techniques", action="append", default=None
    )
    xss_search.add_argument("--limit", type=int, default=10)
    xss_search.add_argument(
        "--json", action="store_true", help="emit matches as JSON"
    )

    xss_research = xss_sub.add_parser(
        "research",
        help="build and persist one XSS research candidate",
    )
    xss_research.add_argument("--query", required=True)
    xss_research.add_argument("--xss-type", default=None)
    xss_research.add_argument("--context", default=None)
    xss_research.add_argument(
        "--technology", dest="technologies", action="append", default=None
    )
    xss_research.add_argument(
        "--technique", dest="techniques", action="append", default=None
    )
    xss_research.add_argument(
        "--output",
        default=None,
        help="override output path "
        "(default: ai_data/research/xss/<candidate_id>.json)",
    )

    xss_show = xss_sub.add_parser(
        "show", help="show one persisted XSS research candidate"
    )
    xss_show.add_argument("candidate_id", help="e.g. xss-0123456789abcdef")
    xss_show.add_argument(
        "--json", action="store_true", help="emit the candidate as JSON"
    )

    xss_llm = xss_sub.add_parser(
        "llm-research",
        help="run the LLM research assistant over one persisted "
        "candidate (optional; requires OPENROUTER_API_KEY; the "
        "deterministic candidate stays authoritative)",
    )
    xss_llm.add_argument(
        "candidate_id", help="e.g. xss-0123456789abcdef"
    )
    xss_llm.add_argument(
        "--output",
        default=None,
        help="override output path "
        "(default: ai_data/research/xss/llm/<candidate_id>.json)",
    )
    return parser


def run_report(args: argparse.Namespace) -> int:
    from ai.reports.renderer import (
        ReportError,
        build_report_for_cve,
    )

    output = getattr(args, "output", None)

    try:
        path = build_report_for_cve(
            args.cve,
            output=output,
        )
    except ReportError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(f"REPORTED: {args.cve}")
    print(f"SAVED: {path}")
    print("MODE: read-only render (no network, no LLM, no execution)")
    return 0


# ---------------------------------------------------------------------------
# Deterministic XSS research agent MVP (Stage R3).
#
# Thin CLI over ai.researcher.xss_agent only: seeded/local KB matching,
# candidate persistence under ai_data/research/xss/. No network, no LLM,
# no subprocess, no browser, no Nuclei, no verifier, no findings, no
# alerts. ``store`` / ``research_dir`` overrides exist for offline tests.
# ---------------------------------------------------------------------------


def _xss_store():
    from ai.knowledge.store import KnowledgeStore

    return KnowledgeStore()


def run_xss_list(args: argparse.Namespace, research_dir=None) -> int:
    from ai.researcher.xss_agent import list_candidates

    items = list_candidates(
        **({"research_dir": research_dir} if research_dir is not None else {})
    )
    for item in items:
        print(f"{item['candidate_id']} | {item['status']} | {item['query']}")
    print(f"CANDIDATES: {len(items)}")
    return 0


def run_xss_search(args: argparse.Namespace, store=None) -> int:
    from ai.researcher.xss_agent import XSSAgentError, rank_documents

    store = store if store is not None else _xss_store()
    try:
        ranked, _signals = rank_documents(
            args.query,
            store=store,
            xss_type=getattr(args, "xss_type", None),
            context=getattr(args, "context", None),
            technologies=getattr(args, "technologies", None),
            techniques=getattr(args, "techniques", None),
        )
    except XSSAgentError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    ranked = ranked[: max(getattr(args, "limit", 10) or 10, 0)]
    if getattr(args, "json", False):
        print(
            json.dumps(
                [
                    {
                        "knowledge_id": m["knowledge_id"],
                        "title": m["title"],
                        "score": m["score"],
                        "reasons": m["reasons"],
                    }
                    for m in ranked
                ],
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for match in ranked:
            print(f"{match['knowledge_id']} | score={match['score']} | {match['title']}")
            for reason in match["reasons"]:
                print(f"    - {reason}")
        print(f"MATCHES: {len(ranked)}")
    return 0


def run_xss_research(
    args: argparse.Namespace, store=None, research_dir=None
) -> int:
    from ai.researcher.xss_agent import XSSAgentError, research_and_persist

    store = store if store is not None else _xss_store()
    kwargs: dict = {}
    if research_dir is not None:
        kwargs["research_dir"] = research_dir
    try:
        candidate, path = research_and_persist(
            args.query,
            store=store,
            xss_type=getattr(args, "xss_type", None),
            context=getattr(args, "context", None),
            technologies=getattr(args, "technologies", None),
            techniques=getattr(args, "techniques", None),
            output_path=getattr(args, "output", None),
            **kwargs,
        )
    except XSSAgentError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"CANDIDATE: {candidate.candidate_id} ({candidate.status})")
    print(f"SAVED: {path}")
    print("MODE: research-only (no network, no LLM, no execution)")
    return 0


def run_xss_show(args: argparse.Namespace, research_dir=None) -> int:
    from ai.researcher.xss_agent import XSSAgentError, load_candidate

    try:
        payload = load_candidate(
            args.candidate_id,
            **({"research_dir": research_dir} if research_dir is not None else {}),
        )
    except XSSAgentError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        print(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        )
    else:
        print(f"CANDIDATE: {payload.get('candidate_id')}")
        print(f"STATUS: {payload.get('status')}")
        print(f"QUERY: {payload.get('query')}")
        print(f"TYPE/CONTEXT: {payload.get('xss_type')}/{payload.get('context')}")
        print(f"CONFIDENCE: {payload.get('confidence')}")
        for item in payload.get("source_evidence", []):
            print(f"  {item.get('knowledge_id')} | score={item.get('score')}")
        print(f"DISCLAIMER: {payload.get('disclaimer')}")
    return 0


def run_xss_llm_research(
    args: argparse.Namespace,
    store=None,
    research_dir=None,
    llm=None,
) -> int:
    """LLM research assistant over one persisted candidate (Stage R7).

    Deterministic candidate stays authoritative (status/confidence
    cannot change). The LLM is a research/synthesis assistant only.
    Provider (OpenRouter) is built from env unless an ``llm`` override
    is supplied (offline tests). No automatic LLM call: this is an
    explicit subcommand only.
    """
    from ai.researcher.xss_agent import XSSAgentError, load_candidate
    from ai.researcher.xss_llm_assistant import (
        XSSLLMResearchError,
        XSSLLMResearchAssistant,
        persist_research,
    )
    # Imported lazily (same convention as OpenRouterProvider below) so the
    # CLI module stays import-light and the provider remains injected.
    # R9.1: in-flight provider failures raise OpenRouterProviderError
    # (a RuntimeError, NOT an XSSLLMResearchError). Without catching it
    # here the raw traceback — including chained provider metadata such
    # as an OpenRouter user_id — propagates to stderr.
    from ai.llm.openrouter import OpenRouterProviderError

    research_kwargs = {}
    if research_dir is not None:
        research_kwargs["research_dir"] = research_dir

    try:
        candidate = load_candidate(args.candidate_id, **research_kwargs)
    except XSSAgentError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    store = store if store is not None else _xss_store()
    if llm is None:
        try:
            from dotenv import load_dotenv

            load_dotenv()
            from ai.llm.openrouter import OpenRouterProvider

            llm = OpenRouterProvider()
        except Exception as exc:
            print(
                f"ERROR: provider not configured: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return 1

    assistant = XSSLLMResearchAssistant(llm)
    try:
        result = assistant.research(candidate, store)
        llm_dir = (
            Path(research_dir) / "llm"
            if research_dir is not None
            else None
        )
        path = persist_research(
            result,
            output_path=getattr(args, "output", None),
            research_dir=llm_dir or None,
        )
    except (XSSLLMResearchError, OpenRouterProviderError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(f"LLM-RESEARCH: {result.candidate_id} ({result.status})")
    print(f"SAVED: {path}")
    print(
        "MODE: LLM research assistant (deterministic candidate remains "
        "authoritative; no execution, no network beyond provider)"
    )
    return 0


def run_xss(args: argparse.Namespace) -> int:
    if args.xss_command == "list":
        return run_xss_list(args)
    if args.xss_command == "search":
        return run_xss_search(args)
    if args.xss_command == "research":
        return run_xss_research(args)
    if args.xss_command == "show":
        return run_xss_show(args)
    if args.xss_command == "llm-research":
        return run_xss_llm_research(args)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "check":
        return run_check()
    if args.command == "research":
        # Stage R22 uses the same top-level command with a subcommand (research plan).
        # Legacy single-CVE research keeps its --cve flag without a subcommand.
        if getattr(args, "research_command", None) == "plan":
            return run_research_plan(args)
        if getattr(args, "research_command", None) is None:
            if getattr(args, "cve", None):
                return run_research(args)
            # Missing required --cve for single-CVE mode
            print("ERROR: --cve is required for 'research' (or use 'research plan')", file=sys.stderr)
            return 2
        return 2
    if args.command == "batch":
        return run_batch(args)
    if args.command == "kb":
        return run_kb(args)
    if args.command == "priority":
        return run_priority(args)
    if args.command == "relevance":
        return run_relevance(args)
    if args.command == "queue":
        return run_queue(args)
    if args.command == "leads":
        return run_leads(args)
    if args.command == "opportunity":
        return run_opportunity(args)
    if args.command == "workflow":
        return run_workflow(args)
    if args.command == "hunt":
        return run_hunt(args)
    if args.command == "match":
        return run_match(args)
    if args.command == "inventory":
        return run_inventory(args)
    if args.command == "product":
        return run_product(args)
    if args.command == "economics":
        return run_economics(args)
    if args.command == "agent":
        return run_agent(args)
    if args.command == "report":
        return run_report(args)
    if args.command == "references":
        return run_references_refresh(args)
    if args.command == "xss":
        return run_xss(args)
    if args.command == "validate-live":
        return run_validate_live(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
