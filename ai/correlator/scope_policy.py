from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ScopeDecision:
    target: str
    program: str
    status: str
    reason: str


class ScopePolicy:
    """
    Decide whether a target may proceed to Nuclei.

    Product/evidence states are deliberately separated from
    actual vulnerability status.
    """

    def evaluate(
        self,
        *,
        target,
        product_match: str,
        version_status: str,
        presence_status: str = "UNKNOWN",
        presence_version: str | None = None,
    ) -> ScopeDecision:

        # --------------------------------------------------
        # Plugin/product explicitly not present
        # --------------------------------------------------

        if presence_status == "NOT_PRESENT":
            return ScopeDecision(
                target=target.target,
                program=target.program,
                status="EXCLUDE",
                reason=(
                    "The specific product/plugin was not "
                    "observed on the target."
                ),
            )

        # --------------------------------------------------
        # We found the plugin/version.
        # Only an actually affected version may proceed.
        # --------------------------------------------------

        if (
            presence_status == "VERSION_FOUND"
            and presence_version
        ):

            if version_status == "AFFECTED":
                return ScopeDecision(
                    target=target.target,
                    program=target.program,
                    status="READY_FOR_SCAN",
                    reason=(
                        "Specific product/plugin was identified "
                        "and the detected version is affected."
                    ),
                )

            if version_status == "NOT_AFFECTED":
                return ScopeDecision(
                    target=target.target,
                    program=target.program,
                    status="EXCLUDE",
                    reason=(
                        "Specific product/plugin was identified, "
                        "but the detected version is not affected."
                    ),
                )

            return ScopeDecision(
                target=target.target,
                program=target.program,
                status="DRY_RUN_ONLY",
                reason=(
                    "The specific product/plugin version was "
                    "identified, but affected-version status "
                    "could not be established."
                ),
            )

        # --------------------------------------------------
        # Product/plugin presence known but version unknown.
        # --------------------------------------------------

        if presence_status == "PRESENT":
            return ScopeDecision(
                target=target.target,
                program=target.program,
                status="DRY_RUN_ONLY",
                reason=(
                    "The specific product/plugin appears to be "
                    "present, but its version is unknown."
                ),
            )

        # --------------------------------------------------
        # Only ecosystem-level match.
        # --------------------------------------------------

        if product_match == "ecosystem":
            return ScopeDecision(
                target=target.target,
                program=target.program,
                status="DRY_RUN_ONLY",
                reason=(
                    "Only ecosystem-level correlation is known; "
                    "specific product/plugin presence and "
                    "version are unverified."
                ),
            )

        # --------------------------------------------------
        # Exact product, but no version proof.
        # --------------------------------------------------

        return ScopeDecision(
            target=target.target,
            program=target.program,
            status="DRY_RUN_ONLY",
            reason=(
                "Product matched, but the affected version "
                "has not been established."
            ),
        )