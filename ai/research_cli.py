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

    for item in discovered_documents or []:
        url = item.get("url")
        content_hash = item.get("content_hash")

        if url and content_hash and url not in hash_by_url:
            hash_by_url[url] = content_hash

    records = []

    for context in reference_contexts:
        records.append(
            {
                "source_url": context.source_url,
                "source_type": context.source_type,
                "title": context.title,
                "exact_record": context.exact_record,
                "context_chunks": list(context.context_chunks),
                "content_hash": hash_by_url.get(context.source_url),
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
    return 2


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
    if args.command == "report":
        return run_report(args)
    if args.command == "validate-live":
        return run_validate_live(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
