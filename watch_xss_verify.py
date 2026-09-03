#!/usr/bin/env python3
"""
watch_xss_verify.py -- Production XSS verification job (Watch layer).

Production position (scheduler wiring happens later; this file does
NOT touch systemd/timers):

    watch-param-discovery
          |
    Endpoints.param_records (x8_checked=True)
          |
    watch_xss_verify.py     <-- this job
          |
    XSSCaseBuilder (scope + method/location/parameter eligibility)
          |
    XSSVerificationPipeline
          |
    XSSFinding
          |
    XssFindings MongoDB collection

Composition (all components are reused, none are duplicated):

    XSSCaseBuilder                 (ai.verification.xss_case_builder)
    XSSOrchestrator                (ai.researcher.xss_orchestrator)
      |-- XSSResearcher            (KnowledgeStore retrieval first)
      |-- XSSLLMResearcher         (LLM provider from environment)
    XSSVerificationPipeline        (ai.verification.xss_pipeline)
    build_default_verifier
      |-- CompositeVerificationExecutor
      |     |-- HTTPEvidenceExecutor
      |     |-- BrowserEvidenceExecutor (POST/PUT limitation unchanged)

Safety properties:

- Scope safety is delegated entirely to XSSCaseBuilder, which
  mirrors the existing Watch semantics exactly (unknown/missing
  program, out-of-scope and ooscopes hosts produce NO cases).
- Methods and parameter locations come from Endpoints.param_records
  provenance. POST/PUT body cases are verified as POST/PUT; nothing
  is ever downgraded to GET.
- Duplicate prevention: a deterministic case_id is produced by
  XSSCaseBuilder; if XssFindings already contains that case_id the
  case is skipped. Persistence is idempotent (unique case_id).
- Failure isolation: one case failing (analysis, verification, or
  persistence) is logged and the job continues with the next case.
- Bounds: --max-cases stops after N newly verified cases;
  --max-minutes stops when the elapsed time budget is exhausted.
  Both bounds are checked BEFORE starting each new case, so the job
  always stops cleanly between cases.
- Memory: the Endpoints collection is streamed with a lazy,
  deterministically ordered cursor (never loaded into memory);
  cases are processed and persisted one at a time.

Credentials come from the environment only (OPENROUTER_API_KEY /
OPENROUTER_MODEL or AVALAI_API_KEY / AVALAI_MODEL via AI_PROVIDER).
Secrets are never logged.

Usage:
  python3 watch_xss_verify.py --max-cases 50 --max-minutes 120
  python3 watch_xss_verify.py --filter example.com --max-cases 5   # test
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import time
from datetime import datetime

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__)))
)

from ai.config import AI_PROVIDER
from ai.knowledge.store import KnowledgeStore
from ai.researcher.xss_llm_researcher import XSSLLMResearcher
from ai.researcher.xss_orchestrator import XSSOrchestrator
from ai.researcher.xss_researcher import XSSResearcher
from ai.verification import (
    XSSCaseBuilder,
    XSSVerificationPipeline,
    build_default_verifier,
)
from ai.verification.browser_executor import BrowserEvidenceExecutor
from ai.verification.http_executor import HTTPEvidenceExecutor
from config import config

DEFAULT_MAX_CASES = 50
FINDING_DOCUMENT_LIMIT = 20
DISCOVERY_EVIDENCE_LIMIT = 32
RUNNER_NAME = "watch_xss_verify"

START_TIME = time.monotonic()


def log(msg):
    print(
        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}",
        flush=True,
    )


def elapsed_minutes():
    return (time.monotonic() - START_TIME) / 60


# ----------------------------------------------------------------------
# Case-level status (persistence bookkeeping only).
#
# The verifier is the ONLY component that classifies attempts and
# produces XSSFinding statuses. This helper merely aggregates the
# already-produced finding statuses into one document field using the
# verifier's own vocabulary. No verdict is invented here.
# ----------------------------------------------------------------------

def case_status(findings) -> str:
    statuses = {f.status for f in findings}
    if "CONFIRMED" in statuses:
        return "CONFIRMED"
    if "POTENTIAL" in statuses:
        return "POTENTIAL"
    return "INCONCLUSIVE"


def _finding_document_values(
    case,
    result,
    *,
    runner: str = RUNNER_NAME,
) -> dict:
    """
    Build the kwargs for one XssFindings document from a case and
    its XSSVerificationResult. Pure data mapping; no I/O. Findings
    are serialized with their full evidence payload for later
    reporting.
    """

    findings = list(result.findings)[:FINDING_DOCUMENT_LIMIT]
    status = case_status(findings)
    confidence = max(
        (float(f.confidence) for f in findings),
        default=0.0,
    )

    return {
        "case_id": case.case_id,
        "finding_id": findings[0].finding_id if findings else None,
        "finding_ids": [f.finding_id for f in findings],
        "program_name": _evidence_value(
            case.discovery_evidence, "program_name"
        ),
        "subdomain": _evidence_value(
            case.discovery_evidence, "endpoint_subdomain"
        ),
        "path": _evidence_value(
            case.discovery_evidence, "endpoint_path"
        ),
        "endpoint": case.endpoint,
        "method": case.method,
        "parameter": case.parameter or "",
        "parameter_location": case.parameter_location,
        "status": status,
        "confidence": confidence,
        "finding_count": len(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
        "verification_audit": result.audit.model_dump(mode="json"),
        "discovery_evidence": list(
            case.discovery_evidence or []
        )[:DISCOVERY_EVIDENCE_LIMIT],
        "runner": runner,
    }


def _evidence_value(entries, key: str) -> str:
    """Extract `key:value` from bounded discovery-evidence entries."""

    prefix = f"{key}:"
    for entry in entries or []:
        if isinstance(entry, str) and entry.startswith(prefix):
            return entry[len(prefix):]
    return ""


# ----------------------------------------------------------------------
# Production composition (Watch layer). These functions exist so the
# run loop itself stays injectable and unit-testable.
# ----------------------------------------------------------------------

def build_llm_provider(provider_name=None):
    """
    Construct the LLM provider from the environment. Credentials
    are read by the providers themselves; they are never passed
    through, logged, or stored here.
    """

    name = (provider_name or AI_PROVIDER or "openrouter").strip().lower()
    if name == "avalai":
        from ai.llm.avalai import AvalAIProvider

        return AvalAIProvider()
    from ai.llm.openrouter import OpenRouterProvider

    return OpenRouterProvider()


def build_orchestrator(provider_name=None, knowledge_root=None) -> XSSOrchestrator:
    """
    Knowledge retrieval first, LLM reasoning second (the existing
    XSSOrchestrator contract). The KnowledgeStore root is anchored
    to the Watch directory so the job does not depend on the
    current working directory.
    """

    root = knowledge_root or os.path.join(
        config().get("WATCH_DIR") or os.path.dirname(__file__),
        "ai_data",
        "knowledge",
    )
    store = KnowledgeStore(root)
    knowledge_researcher = XSSResearcher(store)
    llm_researcher = XSSLLMResearcher(
        build_llm_provider(provider_name)
    )
    return XSSOrchestrator(
        knowledge_researcher=knowledge_researcher,
        llm_researcher=llm_researcher,
    )


def build_production_pipeline(provider_name=None, knowledge_root=None):
    """
    Wire the production pipeline exactly once:

        HTTPEvidenceExecutor ---|
                                |--> CompositeVerificationExecutor
        BrowserEvidenceExecutor-|           |
                                            v
        XSSOrchestrator --> XSSVerifier --> XSSVerificationPipeline

    A single fresh execution-oracle ``run_salt`` is generated for
    this verification run and injected into the verifier. It is
    NEVER persisted on attempts/evidence/findings and NEVER exposed
    to the LLM; it exists only for the lifetime of this pipeline.
    """

    orchestrator = build_orchestrator(
        provider_name=provider_name,
        knowledge_root=knowledge_root,
    )
    http_executor = HTTPEvidenceExecutor()
    browser_executor = BrowserEvidenceExecutor()
    verifier = build_default_verifier(
        http_executor=http_executor,
        browser_executor=browser_executor,
        run_salt=secrets.token_hex(32),
    )
    return XSSVerificationPipeline(
        orchestrator=orchestrator,
        verifier=verifier,
    )


def iter_pending_endpoints(filter_arg=None):
    """
    Lazy, deterministically ordered cursor over pending endpoints.

    Same eligibility pre-filter as the XSSCaseBuilder production
    default (x8_checked=True, params and example_url present) plus
    a field projection. The QuerySet streams from MongoDB in
    batches; the collection is NEVER materialized in memory.
    Final per-case eligibility is still decided by
    XSSCaseBuilder.build (scope, URL, method/location/parameter).
    """

    from database.db import Endpoints

    query = (
        Endpoints.objects(
            example_url__ne=None,
            params__ne=[],
            x8_checked=True,
        )
        .order_by("+program_name", "+subdomain", "+path")
        .only(
            "program_name",
            "subdomain",
            "path",
            "example_url",
            "params",
            "param_records",
        )
    )
    if filter_arg:
        query = query.filter(subdomain__icontains=filter_arg.lower())
    return query


def mongo_already_verified(case_id: str) -> bool:
    from database.db import XssFindings

    return (
        XssFindings.objects(case_id=case_id).only("id").first()
        is not None
    )


def mongo_persist(case, result) -> bool:
    """
    Persist one case result. Idempotent: the unique case_id index
    turns a concurrent/repeated write into a benign skip.
    """

    from database.db import XssFindings
    from mongoengine.errors import NotUniqueError

    values = _finding_document_values(case, result)
    try:
        XssFindings(**values).save()
        return True
    except NotUniqueError:
        return False


# ----------------------------------------------------------------------
# Run loop
# ----------------------------------------------------------------------

def run_job(
    *,
    builder=None,
    pipeline=None,
    endpoints=None,
    max_cases: int = DEFAULT_MAX_CASES,
    max_minutes: float | None = None,
    filter_arg: str | None = None,
    already_verified=None,
    persist=None,
    clock=time.monotonic,
    log_fn=log,
) -> dict:
    """
    Run the verification loop.

    All collaborators are injectable. Production defaults are
    resolved lazily so importing this module never opens MongoDB,
    never builds an LLM provider, and never touches the network.

    Bounds: --max-cases limits NEWLY verified cases; --max-minutes
    bounds wall-clock time. Both are checked BEFORE each case, so
    the loop always stops cleanly between cases.
    """

    if max_cases is None or max_cases <= 0:
        max_cases = DEFAULT_MAX_CASES

    builder = builder or XSSCaseBuilder()
    pipeline = pipeline or build_production_pipeline()
    already_verified = already_verified or mongo_already_verified
    persist = persist or mongo_persist
    endpoints = (
        endpoints
        if endpoints is not None
        else iter_pending_endpoints(filter_arg)
    )

    start = clock()
    verified = 0
    skipped = 0
    failed = 0
    stopped = "endpoints_exhausted"

    for endpoint in endpoints:
        for case in builder.build(endpoint):
            if verified >= max_cases:
                stopped = "max_cases"
                break
            if max_minutes is not None and (
                (clock() - start) / 60 >= max_minutes
            ):
                stopped = "max_minutes"
                break

            identifiers = (
                f"program={endpoint.program_name} "
                f"endpoint={case.endpoint} "
                f"method={case.method} "
                f"parameter={case.parameter} "
                f"location={case.parameter_location} "
                f"case_id={case.case_id}"
            )

            try:
                if already_verified(case.case_id):
                    skipped += 1
                    log_fn(f"[skip] {identifiers} reason=already_verified")
                    continue

                result = pipeline.run(case)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                log_fn(
                    f"[fail] {identifiers} "
                    f"error={type(exc).__name__}: {exc}"[:500]
                )
                continue

            try:
                persisted = persist(case, result)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                log_fn(
                    f"[fail] {identifiers} stage=persist "
                    f"error={type(exc).__name__}: {exc}"[:500]
                )
                continue

            if not persisted:
                skipped += 1
                log_fn(f"[skip] {identifiers} reason=persist_race")
                continue

            verified += 1
            log_fn(
                f"[case] {identifiers} "
                f"status={case_status(result.findings)} "
                f"findings={len(result.findings)}"
            )

        if stopped != "endpoints_exhausted":
            break

    summary = {
        "verified": verified,
        "skipped": skipped,
        "failed": failed,
        "stopped": stopped,
        "elapsed_minutes": (clock() - start) / 60,
    }
    log_fn(
        f"=== XSS verification run finished | "
        f"verified={verified} skipped={skipped} failed={failed} | "
        f"stopped={stopped} | "
        f"elapsed={summary['elapsed_minutes']:.1f} min ==="
    )
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify pending XSS cases against the Watch "
        "endpoint inventory and persist findings."
    )
    parser.add_argument(
        "--filter",
        default=None,
        help="only endpoints whose subdomain contains this keyword",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=DEFAULT_MAX_CASES,
        help="stop after N newly verified cases "
        f"(default: {DEFAULT_MAX_CASES})",
    )
    parser.add_argument(
        "--max-minutes",
        type=float,
        default=None,
        help="stop when this wall-clock budget is exhausted",
    )
    parser.add_argument(
        "--provider",
        default=None,
        help="LLM provider override (openrouter | avalai); "
        "defaults to AI_PROVIDER from the environment",
    )
    args = parser.parse_args(argv)

    if args.max_cases <= 0:
        parser.error("--max-cases must be a positive integer")
    if args.max_minutes is not None and args.max_minutes <= 0:
        parser.error("--max-minutes must be a positive number")

    log(
        f"=== XSS Verification Started | filter={args.filter or 'NONE'} | "
        f"max_cases={args.max_cases} | "
        f"max_minutes={args.max_minutes or 'unlimited'} ==="
    )

    try:
        pipeline = build_production_pipeline(
            provider_name=args.provider
        )
    except Exception as exc:  # noqa: BLE001
        # Provider construction errors are configuration errors
        # (e.g. missing credentials in the environment). They never
        # include the credential value itself.
        log(
            f"Pipeline construction failed: "
            f"{type(exc).__name__}: {exc}"
        )
        return 1

    run_job(
        pipeline=pipeline,
        max_cases=args.max_cases,
        max_minutes=args.max_minutes,
        filter_arg=args.filter,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
