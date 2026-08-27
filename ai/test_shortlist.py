from ai.collectors.cve import CVECollector
from ai.collectors.http import HTTPCollector
from ai.correlator.assessment import assess_asset
from ai.correlator.candidates import candidate_assets
from ai.correlator.index import TechnologyIndex
from ai.correlator.shortlist import build_shortlist


URI = "mongodb://pouya:YourStrongPassword123@178.83.45.76:27017/?authSource=admin"


def main():
    http = HTTPCollector(URI)

    assets = http.all()

    http.close()

    index = TechnologyIndex(assets)

    cves = CVECollector().latest(days=7)

    assessments = []

    for cve in cves:
        candidates = candidate_assets(
            cve,
            index,
        )

        for asset in candidates:
            assessments.extend(
                assess_asset(
                    asset=asset,
                    cve=cve,
                )
            )

    shortlist = build_shortlist(
        cves=cves,
        assessments=assessments,
        limit=10,
    )

    print("\n" + "=" * 100)
    print("RESEARCH SHORTLIST")
    print("=" * 100)

    for rank, item in enumerate(shortlist, 1):
        print(
            f"\n#{rank} {item.cve_id}"
        )

        print(
            f"Priority: {item.priority_score:.1f}"
        )

        print(
            f"CVSS: {item.cvss_score}"
        )

        print(
            f"Vendor: {item.vendor}"
        )

        print(
            f"Products: {item.products}"
        )

        print(
            f"Programs: {', '.join(item.programs)}"
        )

        print(
            f"Assets: {item.affected_asset_count}"
        )

        print(
            f"Technologies: {', '.join(item.technologies)}"
        )

        print(
            f"Unknown versions: "
            f"{item.unknown_version_count}"
        )


if __name__ == "__main__":
    main()