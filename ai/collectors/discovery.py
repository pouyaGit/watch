from __future__ import annotations

import re

import httpx

from ai.schemas.discovery import (
    DiscoveredSource,
    DiscoveryResult,
)


class ReferenceDiscovery:
    """
    Discover additional public research sources for a CVE.

    Discovery is intentionally conservative:
    a GitHub result is not considered an exploit merely because
    the word "exploit" appears somewhere in the issue body.
    """

    GITHUB_API = "https://api.github.com"

    def __init__(
        self,
        timeout: float = 20.0,
    ):
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": (
                    "Watch-Security-Researcher/0.1"
                ),
            },
        )

    def _github_search(
        self,
        endpoint: str,
        query: str,
        limit: int = 20,
    ) -> list[dict]:

        url = (
            f"{self.GITHUB_API}/search/{endpoint}"
        )

        try:
            response = self.client.get(
                url,
                params={
                    "q": query,
                    "per_page": limit,
                },
            )

            response.raise_for_status()

            data = response.json()

        except (
            httpx.HTTPError,
            ValueError,
        ):
            return []

        return data.get("items", [])

    def _normalize(
        self,
        value: str | None,
    ) -> str:
        if not value:
            return ""

        value = value.lower()

        return re.sub(
            r"\s+",
            " ",
            value,
        ).strip()

    def _relevance_score(
        self,
        item: dict,
        cve,
    ) -> tuple[int, list[str]]:

        title = self._normalize(
            item.get("title")
        )

        body = self._normalize(
            item.get("body")
        )

        full_name = self._normalize(
            item.get("full_name")
        )

        cve_id = self._normalize(
            cve.title
        )

        products = [
            self._normalize(product)
            for product in cve.products
        ]

        vendors = [
            self._normalize(vendor)
            for vendor in cve.vendor
        ]

        score = 0
        tags = ["github"]

        # --------------------------------------------------
        # Exact CVE in title
        # --------------------------------------------------

        if cve_id in title:
            score += 70
            tags.append("cve_in_title")

        # --------------------------------------------------
        # CVE only in body
        # --------------------------------------------------

        elif cve_id in body:
            score += 20
            tags.append("cve_in_body")

        # --------------------------------------------------
        # Product in title
        # --------------------------------------------------

        for product in products:
            if (
                product
                and product in title
            ):
                score += 35
                tags.append("product_in_title")
                break

        # --------------------------------------------------
        # Vendor in title
        # --------------------------------------------------

        for vendor in vendors:
            if (
                vendor
                and vendor in title
            ):
                score += 20
                tags.append("vendor_in_title")
                break

        # --------------------------------------------------
        # Security/research terms
        # --------------------------------------------------

        security_terms = {
            "exploit": 15,
            "poc": 15,
            "proof of concept": 20,
            "vulnerability": 10,
            "security advisory": 15,
            "reproducer": 15,
            "reproduction": 10,
            "rce": 15,
            "remote code execution": 20,
        }

        text = f"{title} {body}"

        for term, weight in security_terms.items():
            if term in text:
                score += weight

                if term in {
                    "exploit",
                    "poc",
                    "proof of concept",
                    "reproducer",
                }:
                    tags.append(
                        "security_research_signal"
                    )

        # --------------------------------------------------
        # Repository name itself can be useful
        # --------------------------------------------------

        if cve_id in full_name:
            score += 40
            tags.append("cve_in_repo_name")

        return score, sorted(set(tags))

    def _is_relevant(
        self,
        score: int,
        tags: list[str],
    ) -> bool:

        # Strongest signal: CVE in title/repo.
        if (
            "cve_in_title" in tags
            or "cve_in_repo_name" in tags
        ):
            return score >= 60

        # Product + CVE in body is weaker.
        if (
            "product_in_title" in tags
            and "cve_in_body" in tags
        ):
            return score >= 60

        return score >= 80

    def discover_github_repositories(
        self,
        cve,
    ) -> list[DiscoveredSource]:

        items = self._github_search(
            "repositories",
            f'"{cve.title}"',
        )

        sources = []

        for item in items:

            html_url = item.get(
                "html_url"
            )

            if not html_url:
                continue

            score, tags = (
                self._relevance_score(
                    item,
                    cve,
                )
            )

            if not self._is_relevant(
                score,
                tags,
            ):
                continue

            sources.append(
                DiscoveredSource(
                    url=html_url,
                    source_type="github",
                    title=item.get(
                        "full_name"
                    ),
                    query=cve.title,
                    priority=score,
                    confidence=min(
                        score / 100,
                        1.0,
                    ),
                    tags=tags,
                )
            )

        return sources

    def discover_github_issues(
        self,
        cve,
    ) -> list[DiscoveredSource]:

        # Search CVE + product instead of CVE alone.
        product = (
            cve.products[0]
            if cve.products
            else ""
        )

        query = f'"{cve.title}"'

        if product:
            query += f' "{product}"'

        items = self._github_search(
            "issues",
            query,
        )

        sources = []

        for item in items:

            html_url = item.get(
                "html_url"
            )

            if not html_url:
                continue

            score, tags = (
                self._relevance_score(
                    item,
                    cve,
                )
            )

            if not self._is_relevant(
                score,
                tags,
            ):
                continue

            if (
                "security_research_signal"
                in tags
            ):
                source_type = "github_research"
            else:
                source_type = "github_issue"

            sources.append(
                DiscoveredSource(
                    url=html_url,
                    source_type=source_type,
                    title=item.get(
                        "title"
                    ),
                    query=cve.title,
                    priority=score,
                    confidence=min(
                        score / 100,
                        1.0,
                    ),
                    tags=tags,
                )
            )

        return sources

    def from_existing_references(
        self,
        cve,
    ) -> list[DiscoveredSource]:

        sources = []

        for url in cve.references:

            lowered = url.lower()

            if "github.com" in lowered:
                source_type = "github"
                priority = 90
                tags = [
                    "nvd_reference",
                    "github",
                ]

            elif any(
                domain in lowered
                for domain in (
                    "oracle.com",
                    "microsoft.com",
                    "google.com",
                    "redhat.com",
                )
            ):
                source_type = "vendor"
                priority = 100
                tags = [
                    "nvd_reference",
                    "vendor",
                ]

            else:
                source_type = "other"
                priority = 30
                tags = [
                    "nvd_reference"
                ]

            sources.append(
                DiscoveredSource(
                    url=url,
                    source_type=source_type,
                    query=cve.title,
                    priority=priority,
                    confidence=0.95,
                    tags=tags,
                )
            )

        return sources

    def discover(
        self,
        cve,
        limit: int = 10,
    ) -> DiscoveryResult:

        sources = []

        sources.extend(
            self.from_existing_references(
                cve
            )
        )

        sources.extend(
            self.discover_github_repositories(
                cve
            )
        )

        sources.extend(
            self.discover_github_issues(
                cve
            )
        )

        # Deduplicate by URL.
        unique = {}

        for source in sources:
            unique[source.url] = source

        sources = list(
            unique.values()
        )

        sources.sort(
            key=lambda item: (
                item.priority,
                item.confidence,
            ),
            reverse=True,
        )

        return DiscoveryResult(
            cve_id=cve.title,
            sources=sources[:limit],
        )

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ):
        self.close()