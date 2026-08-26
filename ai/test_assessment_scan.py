from collections import Counter

from ai.collectors.cve import CVECollector
from ai.collectors.http import HTTPCollector
from ai.correlator.assessment import assess_asset
from ai.correlator.candidates import candidate_assets
from ai.correlator.index import TechnologyIndex


URI = "mongodb://pouya:YourStrongPassword123@178.83.45.76:27017/?authSource=admin"


def main():
    http = HTTPCollector(URI)

    assets = http.all()

    http.close()

    index = TechnologyIndex(assets)

    cves = CVECollector().latest(days=7)

    counts = Counter()

    assessments = []

    for cve in cves:

        candidates = candidate_assets(
            cve,
            index,
        )

        for asset in candidates:

            results = assess_asset(
                asset=asset,
                cve=cve,
            )

            for result in results:
                counts[result.version_status] += 1
                assessments.append(result)

    print("\n" + "=" * 90)
    print("ASSESSMENT SUMMARY")
    print("=" * 90)

    for status, count in counts.most_common():
        print(f"{status:20} {count}")

    print("\n" + "=" * 90)
    print("DETAILS")
    print("=" * 90)

    for result in assessments:
        print(
            f"\n{result.cve_id}"
            f" | {result.program_name}"
            f" | {result.subdomain}"
        )

        print(
            f"Technology: {result.technology}"
        )

        print(
            f"Product match: {result.product_match}"
        )

        print(
            f"Detected version: "
            f"{result.detected_version}"
        )

        print(
            f"Version status: "
            f"{result.version_status}"
        )

        print(
            f"Confidence: "
            f"{result.confidence}"
        )

        print(
            f"Reason: "
            f"{result.reason}"
        )


if __name__ == "__main__":
    main()