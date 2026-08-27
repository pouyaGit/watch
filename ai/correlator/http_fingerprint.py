from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class FingerprintResult:
    target: str
    url: str
    status_code: int | None

    status: str
    version: str | None

    evidence: list[str]
    error: str | None = None


class HTTPFingerprintRunner:
    """
    Perform limited, non-destructive HTTP fingerprint checks.

    This runner does NOT exploit the target.
    It only requests explicitly provided public fingerprint URLs.
    """

    VERSION_PATTERNS = (
        re.compile(
            r"Stable tag:\s*([0-9][0-9A-Za-z.\-_]+)",
            re.IGNORECASE,
        ),
        re.compile(
            r"Version:\s*([0-9][0-9A-Za-z.\-_]+)",
            re.IGNORECASE,
        ),
        re.compile(
            r"Version\s*[:=]\s*([0-9][0-9A-Za-z.\-_]+)",
            re.IGNORECASE,
        ),
    )

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "WatchSecurityResearch/1.0",
    ):
        self.timeout = timeout
        self.user_agent = user_agent

    def _extract_version(
        self,
        body: str,
    ) -> str | None:

        for pattern in self.VERSION_PATTERNS:
            match = pattern.search(body)

            if match:
                return match.group(1)

        return None

    def aggregate(
        self,
        results: list[FingerprintResult],
    ) -> dict:
        """
        Aggregate multiple fingerprint checks into one
        plugin-presence verdict.
        """

        if not results:
            return {
                "status": "UNKNOWN",
                "version": None,
                "confidence": 0.0,
                "evidence": [],
            }

        versions = [
            result.version
            for result in results
            if result.version
        ]

        # A concrete version is the strongest presence signal.
        if versions:
            version = versions[0]

            return {
                "status": "VERSION_FOUND",
                "version": version,
                "confidence": 0.95,
                "evidence": [
                    evidence
                    for result in results
                    for evidence in result.evidence
                ],
            }

        # Any 200 response from a plugin-specific resource
        # is evidence of presence, even without version metadata.
        if any(
            result.status_code == 200
            for result in results
        ):
            return {
                "status": "PRESENT",
                "version": None,
                "confidence": 0.80,
                "evidence": [
                    evidence
                    for result in results
                    for evidence in result.evidence
                ],
            }

        # If everything is explicitly 404, the plugin is not present.
        if results and all(
            result.status_code == 404
            for result in results
        ):
            return {
                "status": "NOT_PRESENT",
                "version": None,
                "confidence": 0.95,
                "evidence": [
                    evidence
                    for result in results
                    for evidence in result.evidence
                ],
            }

        # 403, timeouts, mixed responses, etc. remain unknown.
        return {
            "status": "UNKNOWN",
            "version": None,
            "confidence": 0.30,
            "evidence": [
                evidence
                for result in results
                for evidence in result.evidence
            ],
        }


    def check(
        self,
        target: str,
        urls: list[str],
    ) -> list[FingerprintResult]:

        import httpx

        results = []

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/plain,text/html,*/*",
        }

        for url in urls:

            try:
                response = httpx.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    follow_redirects=True,
                )

                body = response.text[:200_000]

                version = self._extract_version(
                    body
                )

                evidence = []

                if response.status_code == 200:
                    evidence.append(
                        "Fingerprint resource returned HTTP 200."
                    )
                elif response.status_code == 403:
                    evidence.append(
                        "Fingerprint resource exists but access is forbidden."
                    )
                elif response.status_code == 404:
                    evidence.append(
                        "Fingerprint resource returned HTTP 404."
                    )
                else:
                    evidence.append(
                        f"Fingerprint resource returned "
                        f"HTTP {response.status_code}."
                    )

                if version:
                    evidence.append(
                        f"Version-like metadata found: {version}"
                    )

                # ------------------------------------------
                # Classification
                # ------------------------------------------

                if (
                    response.status_code == 200
                    and version
                ):
                    status = "VERSION_FOUND"

                elif response.status_code == 200:
                    status = "PRESENT"

                elif response.status_code == 404:
                    status = "NOT_PRESENT"

                elif response.status_code == 403:
                    status = "UNKNOWN"

                else:
                    status = "UNKNOWN"

                results.append(
                    FingerprintResult(
                        target=target,
                        url=url,
                        status_code=response.status_code,
                        status=status,
                        version=version,
                        evidence=evidence,
                    )
                )

            except (
                httpx.TimeoutException,
                httpx.ConnectError,
                httpx.RemoteProtocolError,
            ) as exc:

                results.append(
                    FingerprintResult(
                        target=target,
                        url=url,
                        status_code=None,
                        status="UNKNOWN",
                        version=None,
                        evidence=[],
                        error=(
                            f"{type(exc).__name__}: "
                            f"{exc}"
                        ),
                    )
                )

        return results