from ai.correlator.watch_targets import (
    WatchTarget,
    WatchTargetSelection,
)
from ai.researcher.nuclei_runner import NucleiRunner


selection = WatchTargetSelection(
    cve_id="CVE-2026-1557",
    candidate_count=1,
    targets=[
        WatchTarget(
            target="fixture.example.invalid",
            program="test-program",
            technology="WordPress",
            product_match="exact",
            version_status="AFFECTED",
            presence_status="VERSION_FOUND",
            presence_version="1.0",
            scope_status="READY_FOR_SCAN",
            scope_reason=(
                "Fixture: exact product and affected "
                "version evidence."
            ),
            asset_id="fixture-1",
        )
    ],
    excluded=[],
)

runner = NucleiRunner()

results = runner.run(
    selection=selection,
    template_path=(
        "ai_data/nuclei/generated/"
        "CVE-2026-1557.yaml"
    ),
    execute=False,
)

for result in results:
    print("=" * 80)
    print("Target:", result.target)
    print("Status:", result.status)
    print(
        "Command:",
        " ".join(result.command)
    )
    print("Error:", result.error)