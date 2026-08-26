from __future__ import annotations

import re
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version


@dataclass
class VersionMatch:
    status: str
    detected_version: str | None
    matched_version: str | None
    reason: str


def extract_version(technology: str) -> str | None:
    """
    Extract a version from technology names such as:

        Nginx:1.30.4
        PHP:5.6.40
        jQuery:3.7.1
        Drupal:10
        IIS:10.0
    """

    if not technology:
        return None

    # First handle common colon format:
    # Technology:1.2.3
    match = re.search(
        r":\s*v?(\d+(?:\.\d+){0,3}(?:[-+._][0-9A-Za-z.-]+)?)$",
        technology,
    )

    if match:
        return match.group(1)

    # Generic fallback for embedded versions.
    match = re.search(
        r"\bv?(\d+\.\d+(?:\.\d+){0,2}(?:[-+._][0-9A-Za-z.-]+)?)\b",
        technology,
    )

    if match:
        return match.group(1)

    return None


def normalize_version(value: str) -> Version | None:
    if not value:
        return None

    value = value.strip()

    try:
        return Version(value)
    except InvalidVersion:
        return None


def compare_version(
    detected_version: str | None,
    affected_versions: list,
) -> VersionMatch:

    if not detected_version:
        return VersionMatch(
            status="UNKNOWN",
            detected_version=None,
            matched_version=None,
            reason="No version was detected for the technology.",
        )

    detected = normalize_version(detected_version)

    if detected is None:
        return VersionMatch(
            status="UNKNOWN",
            detected_version=detected_version,
            matched_version=None,
            reason="Detected version could not be parsed.",
        )

    affected_seen = False

    for affected in affected_versions:
        if affected.status and affected.status != "affected":
            continue

        affected_seen = True

        version = normalize_version(
            affected.version
        )

        less_than = normalize_version(
            affected.less_than
        )

        # Exact affected version.
        if version and not less_than:
            if detected == version:
                return VersionMatch(
                    status="AFFECTED",
                    detected_version=detected_version,
                    matched_version=affected.version,
                    reason=(
                        "Detected version exactly matches an "
                        "explicitly affected version."
                    ),
                )

            continue

        # Range:
        # version <= detected < less_than
        if version and less_than:
            if version <= detected < less_than:
                return VersionMatch(
                    status="AFFECTED",
                    detected_version=detected_version,
                    matched_version=affected.version,
                    reason=(
                        f"Detected version is within the affected "
                        f"range {affected.version} <= version < "
                        f"{affected.less_than}."
                    ),
                )

    if affected_seen:
        return VersionMatch(
            status="NOT_AFFECTED",
            detected_version=detected_version,
            matched_version=None,
            reason=(
                "Detected version does not match any known "
                "affected version/range."
            ),
        )

    return VersionMatch(
        status="UNKNOWN",
        detected_version=detected_version,
        matched_version=None,
        reason="No usable affected version information was available.",
    )