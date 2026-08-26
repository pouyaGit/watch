from __future__ import annotations

from ai.collectors.cve import CVECollector
from ai.collectors.discovery import ReferenceDiscovery
from ai.collectors.discovery_fetch import fetch_discovered_sources
from ai.collectors.http import HTTPCollector

from ai.correlator.assessment import assess_asset
from ai.correlator.candidates import candidate_assets
from ai.correlator.index import TechnologyIndex

from ai.researcher.research_context import build_research_contexts
from ai.researcher.researcher import SecurityResearcher

from ai.schemas.reference import ReferenceContext


URI = (
    "mongodb://pouya:YourStrongPassword123@"
    "178.83.45.76:27017/?authSource=admin"
)

TARGETS = {
    "CVE-2026-60415",
    "CVE-2026-65640",
}


def main():
    http = HTTPCollector(URI)
    assets = http.all()
    http.close()

    index = TechnologyIndex(assets)

    collector = CVECollector()

    cves = collector.get_by_ids(
        sorted(TARGETS)
    )

    lookup = {
        cve.title: cve
        for cve in cves
    }

    researcher = SecurityResearcher()

    for cve_id in sorted(TARGETS):

        output_path = (
            f"ai_data/research/{cve_id}.v3.json"
        )

        if __import__("pathlib").Path(output_path).exists():
            print(f"SKIP {cve_id}")
            continue

        cve = lookup.get(cve_id)

        if cve is None:
            print(f"NOT FOUND {cve_id}")
            continue

        print("\n" + "=" * 80)
        print("RETRY", cve_id)
        print("=" * 80)

        try:
            candidates = candidate_assets(
                cve,
                index,
            )

            assessments = []

            for asset in candidates:
                assessments.extend(
                    assess_asset(
                        asset=asset,
                        cve=cve,
                    )
                )

            programs = sorted(
                {
                    item.program_name
                    for item in assessments
                }
            )

            asset_names = sorted(
                {
                    item.subdomain
                    for item in assessments
                }
            )

            technologies = sorted(
                {
                    item.technology
                    for item in assessments
                }
            )

            with ReferenceDiscovery() as discovery:
                discovered = discovery.discover(
                    cve,
                    limit=5,
                )

            documents = fetch_discovered_sources(
                discovered,
                limit=5,
            )

            contexts_raw = build_research_contexts(
                documents=documents,
                cve_id=cve.title,
                keywords=[
                    cve.title,
                    *cve.vendor,
                    *cve.products,
                    "exploit",
                    "PoC",
                    "WebLogic",
                    "WordPress",
                ],
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

            result = researcher.research(
                document=cve,
                programs=programs,
                assets=asset_names,
                technologies=technologies,
                reference_contexts=reference_contexts,
                discovered_sources=documents,
            )

            import json
            from datetime import datetime, timezone
            from pathlib import Path

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
                "metadata": {
                    "programs": programs,
                    "assets": asset_names,
                    "technologies": technologies,
                    "discovered_source_count": len(
                        discovered.sources
                    ),
                    "fetched_source_count": len(
                        documents
                    ),
                },
                "research": result.model_dump(),
            }

            Path(output_path).write_text(
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            print("SAVED:", output_path)

        except Exception as exc:
            print(
                f"FAILED {cve_id}: "
                f"{type(exc).__name__}: {exc}"
            )


if __name__ == "__main__":
    main()