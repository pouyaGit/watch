from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from ai.collectors.cve import CVECollector
from ai.collectors.http import HTTPCollector
from ai.collectors.reference import ReferenceCollector
from ai.collectors.reference_ranker import ReferenceRanker
from ai.correlator.assessment import assess_asset
from ai.correlator.candidates import candidate_assets
from ai.correlator.index import TechnologyIndex
from ai.researcher.researcher import SecurityResearcher


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


def build_reference_contexts(cve):
    contexts = []

    with ReferenceCollector() as collector:
        references = collector.collect(
            cve.references
        )

    ranker = ReferenceRanker()

    for reference in references:
        context = ranker.build(
            document=reference,
            cve_id=cve.title,
            keywords=[
                cve.title,
                *cve.vendor,
                *cve.products,
            ],
        )

        contexts.append(context)

    return contexts


def save_result(
    result,
    cve,
    output_path: Path,
    metadata: dict,
):
    payload = {
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

    cves = CVECollector().latest(days=7)

    print(
        f"CVEs: {len(cves)}"
    )

    # --------------------------------------------------
    # Build candidates / assessments
    # --------------------------------------------------

    assessments = []

    cve_lookup = {
        cve.title: cve
        for cve in cves
    }

    candidate_map = {}

    for cve in cves:
        candidates = candidate_assets(
            cve,
            index,
        )

        if not candidates:
            continue

        candidate_map[cve.title] = candidates

        for asset in candidates:
            assessments.extend(
                assess_asset(
                    asset=asset,
                    cve=cve,
                )
            )

    print(
        f"Candidate CVEs: "
        f"{len(candidate_map)}"
    )

    # --------------------------------------------------
    # Create one research candidate per CVE
    # --------------------------------------------------

    grouped = {}

    for assessment in assessments:
        grouped.setdefault(
            assessment.cve_id,
            [],
        ).append(assessment)

    researcher = SecurityResearcher()

    processed = 0
    skipped = 0
    failed = 0

    print("\n" + "=" * 80)
    print("BATCH RESEARCH")
    print("=" * 80)

    # High CVSS first.
    ordered_ids = sorted(
        grouped.keys(),
        key=lambda cve_id: (
            cve_lookup[cve_id].cvss_score
            or 0
        ),
        reverse=True,
    )

    for cve_id in ordered_ids[:10]:

        cve = cve_lookup[cve_id]

        output_path = (
            RESEARCH_DIR
            / f"{safe_filename(cve_id)}.json"
        )

        # --------------------------------------------------
        # Deduplication
        # --------------------------------------------------

        if output_path.exists():
            print(
                f"\nSKIP {cve_id} "
                f"(already researched)"
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
            # Fetch + rank public references
            # --------------------------------------------------

            reference_contexts = (
                build_reference_contexts(cve)
            )

            print(
                f"  References: "
                f"{len(reference_contexts)}"
            )

            # --------------------------------------------------
            # One LLM call per CVE
            # --------------------------------------------------

            result = researcher.research(
                document=cve,
                programs=programs,
                assets=asset_names,
                technologies=technologies,
                reference_contexts=reference_contexts,
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
                "reference_count": len(
                    reference_contexts
                ),
            }

            save_result(
                result=result,
                cve=cve,
                output_path=output_path,
                metadata=metadata,
            )

            print(
                f"  SAVED: {output_path}"
            )

            processed += 1

        except Exception as exc:
            failed += 1

            print(
                f"  ERROR: {type(exc).__name__}: {exc}"
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