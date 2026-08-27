from __future__ import annotations

from dataclasses import asdict, dataclass
from urllib.parse import urlparse

from ai.correlator.assessment import assess_asset
from ai.correlator.candidates import (
    candidate_assets,
    product_matches_ecosystem,
)
from ai.correlator.http_fingerprint import (
    HTTPFingerprintRunner,
)
from ai.correlator.index import TechnologyIndex
from ai.correlator.plugin_presence import (
    WordPressPluginPresenceVerifier,
)
from ai.correlator.scope_policy import ScopePolicy
from ai.correlator.version import compare_version


@dataclass
class WatchTarget:
    target: str
    program: str
    technology: str
    product_match: str
    version_status: str

    presence_status: str
    presence_version: str | None

    scope_status: str
    scope_reason: str

    asset_id: str | None = None


@dataclass
class WatchTargetSelection:
    cve_id: str
    targets: list[WatchTarget]
    excluded: list[dict]
    candidate_count: int


class WatchAssetSelector:
    """
    Select Watch assets for a CVE and evaluate scope.

    For ecosystem-level matches, this class may perform
    limited, non-destructive HTTP fingerprint checks.

    It never executes the CVE exploit and never runs Nuclei.
    """

    def __init__(
        self,
        scope_policy: ScopePolicy | None = None,
        fingerprint_runner: HTTPFingerprintRunner | None = None,
        plugin_verifier: WordPressPluginPresenceVerifier | None = None,
    ):
        self.scope_policy = (
            scope_policy
            or ScopePolicy()
        )

        self.fingerprint_runner = (
            fingerprint_runner
            or HTTPFingerprintRunner()
        )

        self.plugin_verifier = (
            plugin_verifier
            or WordPressPluginPresenceVerifier()
        )

    def _normalize_target(
        self,
        value: str,
    ) -> str:

        value = value.strip()

        if not value:
            return value

        if "://" not in value:
            return value

        parsed = urlparse(value)

        return parsed.netloc or value

    def _fingerprint_wordpress_plugin(
        self,
        target: str,
        product: str,
    ) -> dict:

        slug = (
            self.plugin_verifier.plugin_slug(
                product
            )
        )

        if not slug:
            return {
                "status": "UNKNOWN",
                "version": None,
                "confidence": 0.0,
                "evidence": [
                    (
                        "No known WordPress plugin slug "
                        "mapping is available."
                    )
                ],
            }

        presence = (
            self.plugin_verifier.build_checks(
                target=target,
                plugin_slug=slug,
                plugin_name=product,
            )
        )

        urls = [
            check.path
            for check in presence.checks
        ]

        results = (
            self.fingerprint_runner.check(
                target=target,
                urls=urls,
            )
        )

        aggregate = (
            self.fingerprint_runner.aggregate(
                results
            )
        )

        return aggregate

    def select(
        self,
        cve,
        technology_index: TechnologyIndex,
    ) -> WatchTargetSelection:

        candidates = candidate_assets(
            cve,
            technology_index,
        )

        targets = []
        excluded = []

        seen = set()

        for asset in candidates:

            try:
                assessments = assess_asset(
                    asset=asset,
                    cve=cve,
                )
            except Exception as exc:
                excluded.append(
                    {
                        "reason": "assessment_error",
                        "target": getattr(
                            asset,
                            "subdomain",
                            None,
                        ),
                        "error": str(exc),
                    }
                )
                continue

            if not assessments:
                excluded.append(
                    {
                        "reason": "no_assessment",
                        "target": getattr(
                            asset,
                            "subdomain",
                            None,
                        ),
                    }
                )
                continue

            for assessment in assessments:

                subdomain = getattr(
                    assessment,
                    "subdomain",
                    None,
                )

                program = getattr(
                    assessment,
                    "program_name",
                    None,
                )

                technology = getattr(
                    assessment,
                    "technology",
                    None,
                )

                product_match = getattr(
                    assessment,
                    "product_match",
                    "unknown",
                )

                version_status = getattr(
                    assessment,
                    "version_status",
                    "UNKNOWN",
                )

                if not subdomain:
                    excluded.append(
                        {
                            "reason": "missing_target",
                            "program": program,
                        }
                    )
                    continue

                if not program:
                    excluded.append(
                        {
                            "reason": "missing_program",
                            "target": subdomain,
                        }
                    )
                    continue

                target = self._normalize_target(
                    subdomain
                )

                key = (
                    program,
                    target,
                    technology,
                    product_match,
                )

                if key in seen:
                    continue

                seen.add(key)

                # ------------------------------------------------
                # Default state
                # ------------------------------------------------

                presence_status = "UNKNOWN"
                presence_version = None

                # ------------------------------------------------
                # Ecosystem verification
                # ------------------------------------------------

                if product_match == "ecosystem":

                    is_wordpress = (
                        technology
                        and technology.lower()
                        == "wordpress"
                    )

                    wordpress_product = any(
                        product
                        and product_matches_ecosystem(
                            technology=technology,
                            product=product,
                        )
                        for product in cve.products
                    )

                    if (
                        is_wordpress
                        and wordpress_product
                        and cve.products
                    ):
                        try:
                            fingerprint = (
                                self._fingerprint_wordpress_plugin(
                                    target=target,
                                    product=cve.products[0],
                                )
                            )

                            presence_status = (
                                fingerprint.get(
                                    "status",
                                    "UNKNOWN",
                                )
                            )

                            presence_version = (
                                fingerprint.get(
                                    "version"
                                )
                            )

                        except Exception as exc:
                            presence_status = "UNKNOWN"
                            presence_version = None

                            excluded.append(
                                {
                                    "reason": (
                                        "fingerprint_error"
                                    ),
                                    "target": target,
                                    "error": str(exc),
                                }
                            )

                # ------------------------------------------------
                # If we found a concrete plugin version,
                # compare it with the CVE affected ranges.
                # ------------------------------------------------

                effective_version_status = (
                    version_status
                )

                if presence_status == (
                    "VERSION_FOUND"
                ):
                    version_result = compare_version(
                        presence_version,
                        cve.affected_versions,
                    )

                    effective_version_status = (
                        version_result.status
                    )

                # ------------------------------------------------
                # Scope decision
                # ------------------------------------------------

                scope = (
                    self.scope_policy.evaluate(
                        target=type(
                            "Target",
                            (),
                            {
                                "target": target,
                                "program": program,
                            },
                        )(),
                        product_match=product_match,
                        version_status=(
                            effective_version_status
                        ),
                        presence_status=(
                            presence_status
                        ),
                        presence_version=(
                            presence_version
                        ),
                    )
                )

                targets.append(
                    WatchTarget(
                        target=target,
                        program=program,
                        technology=(
                            technology
                            or "unknown"
                        ),
                        product_match=(
                            product_match
                        ),
                        version_status=(
                            effective_version_status
                        ),
                        presence_status=(
                            presence_status
                        ),
                        presence_version=(
                            presence_version
                        ),
                        scope_status=(
                            scope.status
                        ),
                        scope_reason=(
                            scope.reason
                        ),
                        asset_id=getattr(
                            asset,
                            "id",
                            None,
                        ),
                    )
                )

        return WatchTargetSelection(
            cve_id=cve.title,
            targets=targets,
            excluded=excluded,
            candidate_count=len(
                candidates
            ),
        )

    def to_dict(
        self,
        selection: WatchTargetSelection,
    ) -> dict:

        return {
            "cve_id": selection.cve_id,
            "candidate_count": (
                selection.candidate_count
            ),
            "target_count": len(
                selection.targets
            ),
            "targets": [
                asdict(target)
                for target in selection.targets
            ],
            "excluded": selection.excluded,
        }