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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Watch AI research agent (research-only, dry-run).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="offline readiness check (no LLM/NVD calls)")

    research = sub.add_parser("research", help="research a single CVE")
    research.add_argument("--cve", required=True, help="e.g. CVE-2026-1557")
    research.add_argument(
        "--skip-llm",
        action="store_true",
        help="collect/correlate only, skip the LLM call",
    )

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
        return run_research(args)
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
