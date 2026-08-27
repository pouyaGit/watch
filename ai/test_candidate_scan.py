from collections import defaultdict

from ai.collectors.cve import CVECollector
from ai.collectors.http import HTTPCollector
from ai.correlator.index import TechnologyIndex
from ai.correlator.candidates import candidate_assets


URI = "mongodb://pouya:YourStrongPassword123@178.83.45.76:27017/?authSource=admin"


def main():
    http_collector = HTTPCollector(URI)

    assets = http_collector.all()

    http_collector.close()

    index = TechnologyIndex(assets)

    cves = CVECollector().latest(days=7)

    print(f"CVEs: {len(cves)}")
    print(f"HTTP assets: {len(assets)}")
    print(f"Indexed technologies: {len(index.technologies())}")

    print("\n" + "=" * 100)
    print("PRODUCT CANDIDATES")
    print("=" * 100)

    total_assets = 0
    matched_cves = 0

    for cve in cves:
        candidates = candidate_assets(
            cve,
            index,
        )

        if not candidates:
            continue

        matched_cves += 1
        total_assets += len(candidates)

        programs = defaultdict(int)

        for asset in candidates:
            programs[asset.program_name] += 1

        print("\n" + "-" * 100)
        print("CVE:", cve.title)
        print("Vendor:", cve.vendor)
        print("Products:", cve.products)
        print("CVSS:", cve.cvss_score)
        print("Candidate assets:", len(candidates))

        print("Programs:")
        for program, count in sorted(programs.items()):
            print(f"  {program}: {count}")

        print("Assets:")
        for asset in candidates[:10]:
            print(
                f"  {asset.program_name:10} "
                f"{asset.subdomain:50} "
                f"{asset.tech}"
            )

        if len(candidates) > 10:
            print(
                f"  ... and {len(candidates) - 10} more"
            )

    print("\n" + "=" * 100)
    print("SUMMARY")
    print("=" * 100)
    print("Matched CVEs:", matched_cves)
    print("Candidate assets:", total_assets)


if __name__ == "__main__":
    main()