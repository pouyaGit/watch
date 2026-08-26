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


def main():
    # --------------------------------------------------
    # Watch assets
    # --------------------------------------------------

    http = HTTPCollector(URI)
    assets = http.all()
    http.close()

    index = TechnologyIndex(assets)

    # --------------------------------------------------
    # CVE
    # --------------------------------------------------

    cves = CVECollector().latest(days=7)

    cve = next(
        item
        for item in cves
        if item.title == "CVE-2026-60702"
    )

    # --------------------------------------------------
    # Candidate assets
    # --------------------------------------------------

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

    # --------------------------------------------------
    # Discovery
    # --------------------------------------------------

    with ReferenceDiscovery() as discovery:
        discovered = discovery.discover(
            cve,
            limit=5,
        )

    print("=" * 80)
    print("DISCOVERED SOURCES")
    print("=" * 80)

    for source in discovered.sources:
        print(
            f"{source.priority:3} | "
            f"{source.source_type:20} | "
            f"{source.title}"
        )

    # --------------------------------------------------
    # Fetch discovered sources
    # --------------------------------------------------

    discovered_documents = (
        fetch_discovered_sources(
            discovered,
            limit=5,
        )
    )

    # --------------------------------------------------
    # Build focused contexts
    # --------------------------------------------------

    contexts_raw = build_research_contexts(
        documents=discovered_documents,
        cve_id=cve.title,
        keywords=[
            cve.title,
            *cve.vendor,
            *cve.products,
            "WebLogic",
            "T3",
            "IIOP",
            "exploit",
            "PoC",
        ],
    )

    reference_contexts = [
        ReferenceContext(
            source_url=context["url"],
            source_type=context["source_type"],
            title=context.get("title"),
            exact_record=context.get("exact_record"),
            context_chunks=context.get(
                "context_chunks",
                [],
            ),
        )
        for context in contexts_raw
    ]

    # --------------------------------------------------
    # Research
    # --------------------------------------------------

    researcher = SecurityResearcher()

    result = researcher.research(
        document=cve,
        programs=programs,
        assets=asset_names,
        technologies=technologies,
        reference_contexts=reference_contexts,
        discovered_sources=discovered_documents,
    )

    # --------------------------------------------------
    # Output
    # --------------------------------------------------

    print("\n" + "=" * 80)
    print("RESEARCH V3")
    print("=" * 80)

    print(
        result.model_dump_json(
            indent=2,
        )
    )


if __name__ == "__main__":
    main()