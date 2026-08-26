from pymongo import MongoClient

from ai.collectors.cve import CVECollector
from ai.schemas.http import HTTPAsset
from ai.correlator.cve_matcher import find_matches


URI = "mongodb://pouya:YourStrongPassword123@178.83.45.76:27017/?authSource=admin"


def load_http_assets():
    client = MongoClient(
        URI,
        serverSelectionTimeoutMS=5000,
    )

    print("MongoDB:", client.admin.command("ping"))

    db = client["watch"]
    collection = db["http"]

    assets = []

    for document in collection.find({}):
        assets.append(
            HTTPAsset.model_validate(document)
        )

    client.close()

    return assets


def main():
    print("Loading HTTP assets...")
    assets = load_http_assets()

    print(f"HTTP assets: {len(assets)}")

    print("\nLoading latest CVEs...")
    cves = CVECollector().latest(days=1)

    print(f"CVEs: {len(cves)}")

    total_matches = 0

    print("\n" + "=" * 80)
    print("CANDIDATE MATCHES")
    print("=" * 80)

    for cve in cves:
        for asset in assets:

            matches = find_matches(
                asset=asset,
                cve=cve,
            )

            for match in matches:
                total_matches += 1

                print(
                    f"\nCVE: {match['cve_id']}"
                )

                print(
                    f"Program: {match['program_name']}"
                )

                print(
                    f"Subdomain: {match['subdomain']}"
                )

                print(
                    f"Technology: {match['technology']}"
                )

                print(
                    f"Vendor: {match['vendor']}"
                )

                print(
                    f"Products: {match['products']}"
                )

                print(
                    f"Match: {match['match_type']}"
                )

                print(
                    f"Confidence: {match['confidence']}"
                )

    print("\n" + "=" * 80)
    print(f"TOTAL CANDIDATE MATCHES: {total_matches}")
    print("=" * 80)


if __name__ == "__main__":
    main()