from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from ai.collectors.cve import CVECollector
from ai.collectors.discovery import ReferenceDiscovery
from ai.collectors.discovery_fetch import fetch_discovered_sources
from ai.collectors.http import HTTPCollector

from ai.correlator.assessment import assess_asset
from ai.correlator.candidates import candidate_assets
from ai.correlator.index import TechnologyIndex

from ai.researcher.research_context import (
    build_research_contexts,
)
from ai.researcher.researcher import SecurityResearcher

from ai.schemas.reference import ReferenceContext


URI = (
    "mongodb://pouya:YourStrongPassword123@"
    "178.83.45.76:27017/?authSource=admin"
)

RESEARCH_DIR = Path("ai_data/research")


def safe_filename(value: str) -> str:
    return re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        value,
    )


def save_result(
    cve,
    result,
    metadata: dict,
    output_path: Path,
):
    payload = {
        "research_version": 3,
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "cve": {
            "id": cve.title,
            "vendor": cve.vendor,
            "products": cve.products,
            "cvss_score": cve.cvss_score,
            "cvss_vector": cve.cvss_vector,
        },
        "metadata": metadata,
        "research": result.model_dump(),
    }

    output_path.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def main():
    RESEARCH_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("Loading Watch assets...")

    http = HTTPCollector(URI)
    assets = http.all()
    http.close()

    print(
        f"HTTP assets: {len(assets)}"
    )

    index = TechnologyIndex(assets)

    print(
        f"Indexed technologies: "
        f"{len(index.technologies())}"
    )

    print("\nLoading CVEs...")

    cves = CVECollector().latest(
        days=7
    )

    print(
        f"CVEs: {len(cves)}"
    )

    # --------------------------------------------------
    # Candidate assessment
    # --------------------------------------------------

    cve_lookup = {
        cve.title: cve
        for cve in cves
    }

    grouped = {}

    for cve in cves:

        candidates = candidate_assets(
            cve,
            index,
        )

        if not candidates:
            continue

        for asset in candidates:

            results = assess_asset(
                asset=asset,
                cve=cve,
            )

            for result in results:
                grouped.setdefault(
                    cve.title,
                    [],
                ).append(result)

    print(
        f"Candidate CVEs: "
        f"{len(grouped)}"
    )

    researcher = SecurityResearcher()

    processed = 0
    skipped = 0
    failed = 0

    print("\n" + "=" * 80)
    print("BATCH RESEARCH V3")
    print("=" * 80)

    # Highest CVSS first.
    ordered_ids = sorted(
        grouped.keys(),
        key=lambda cve_id: (
            cve_lookup[cve_id].cvss_score
            or 0
        ),
        reverse=True,
    )

    # Same 10-CVE scope as our current shortlist.
    ordered_ids = ordered_ids[:10]

    for cve_id in ordered_ids:

        cve = cve_lookup[cve_id]

        output_path = (
            RESEARCH_DIR
            / f"{safe_filename(cve_id)}.v3.json"
        )

        if output_path.exists():
            print(
                f"\nSKIP {cve_id} "
                f"(V3 already exists)"
            )

            skipped += 1
            continue

        items = grouped[cve_id]

        programs = sorted(
            {
                item.program_name
                for item in items
            }
        )

        asset_names = sorted(
            {
                item.subdomain
                for item in items
            }
        )

        technologies = sorted(
            {
                item.technology
                for item in items
            }
        )

        print(
            f"\nRESEARCH {cve_id}"
        )

        print(
            f"  CVSS: {cve.cvss_score}"
        )

        print(
            f"  Programs: {programs}"
        )

        print(
            f"  Assets: {len(asset_names)}"
        )

        print(
            f"  Technologies: {technologies}"
        )

        try:

            # --------------------------------------------------
            # Discovery
            # --------------------------------------------------

            with ReferenceDiscovery() as discovery:
                discovered = discovery.discover(
                    cve,
                    limit=5,
                )

            print(
                f"  Discovered sources: "
                f"{len(discovered.sources)}"
            )

            # --------------------------------------------------
            # Fetch
            # --------------------------------------------------

            discovered_documents = (
                fetch_discovered_sources(
                    discovered,
                    limit=5,
                )
            )

            print(
                f"  Fetched sources: "
                f"{len(discovered_documents)}"
            )

            # --------------------------------------------------
            # Focused reference context
            # --------------------------------------------------

            contexts_raw = (
                build_research_contexts(
                    documents=discovered_documents,
                    cve_id=cve.title,
                    keywords=[
                        cve.title,
                        *cve.vendor,
                        *cve.products,
                        "exploit",
                        "PoC",
                        "WebLogic",
                        "T3",
                        "IIOP",
                    ],
                )
            )

            reference_contexts = [
                ReferenceContext(
                    source_url=context["url"],
                    source_type=context["source_type"],
                    title=context.get("title"),
                    exact_record=context.get(
                        "exact_record"
                    ),
                    context_chunks=context.get(
                        "context_chunks",
                        [],
                    ),
                )
                for context in contexts_raw
            ]

            # --------------------------------------------------
            # One LLM request per CVE
            # --------------------------------------------------

            result = researcher.research(
                document=cve,
                programs=programs,
                assets=asset_names,
                technologies=technologies,
                reference_contexts=reference_contexts,
                discovered_sources=discovered_documents,
            )

            metadata = {
                "programs": programs,
                "assets": asset_names,
                "technologies": technologies,
                "assessment_count": len(items),
                "version_statuses": sorted(
                    {
                        item.version_status
                        for item in items
                    }
                ),
                "discovered_source_count": len(
                    discovered.sources
                ),
                "fetched_source_count": len(
                    discovered_documents
                ),
                "reference_context_count": len(
                    reference_contexts
                ),
                "source_types": sorted(
                    {
                        source.source_type
                        for source in discovered.sources
                    }
                ),
            }

            save_result(
                cve=cve,
                result=result,
                metadata=metadata,
                output_path=output_path,
            )

            print(
                f"  SAVED: {output_path}"
            )

            processed += 1

        except Exception as exc:

            failed += 1

            print(
                f"  ERROR: "
                f"{type(exc).__name__}: {exc}"
            )

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    print(
        f"Processed: {processed}"
    )

    print(
        f"Skipped:   {skipped}"
    )

    print(
        f"Failed:    {failed}"
    )


if __name__ == "__main__":
    main()