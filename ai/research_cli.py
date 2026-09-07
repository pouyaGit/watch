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

``check`` is fully offline except for a localhost MongoDB ping and
performs no LLM or NVD calls.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

RESEARCH_DIR = Path("ai_data/research")
NUCLEI_DIRS = (
    Path("ai_data/nuclei/generated"),
    Path("ai_data/nuclei/results"),
    Path("ai_data/nuclei/findings"),
)


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "check":
        return run_check()
    if args.command == "research":
        return run_research(args)
    if args.command == "batch":
        return run_batch(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
