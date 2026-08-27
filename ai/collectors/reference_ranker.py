from __future__ import annotations

import re

from ai.schemas.reference import ReferenceContext


class ReferenceRanker:
    """
    Extract focused research material from public references.

    Structured/vendor advisories:
        exact CVE record is useful.

    GitHub/security research:
        extract the issue/article body and keep one focused chunk.
    """

    MAX_CONTEXT_CHUNKS = 1
    FALLBACK_CONTEXT_SIZE = 5000

    CVE_PATTERN = re.compile(
        r"\bCVE-\d{4}-\d{4,7}\b",
        re.IGNORECASE,
    )

    STRUCTURED_SOURCE_TYPES = {
        "vendor",
        "advisory",
        "security_advisory",
    }

    NARRATIVE_SOURCE_TYPES = {
        "github",
        "github_issue",
        "github_research",
        "security_research",
        "bug_bounty",
        "blog",
        "writeup",
        "research",
    }

    def _normalize(self, text: str) -> str:
        return re.sub(
            r"\s+",
            " ",
            text,
        ).strip()

    # --------------------------------------------------
    # GitHub
    # --------------------------------------------------

    def _extract_github_body(
        self,
        text: str,
        cve_id: str,
    ) -> str:

        text = self._normalize(text)

        # First try to remove the obvious GitHub UI chrome.
        marker = re.search(
            r"\bDescription\b",
            text,
            flags=re.IGNORECASE,
        )

        if marker:
            body = text[marker.end():].strip()
        else:
            body = text

        # If the CVE disappeared after trimming, fall back to
        # the full document. This makes the extractor robust to
        # different GitHub page layouts.
        if cve_id.lower() not in body.lower():
            body = text

        # Remove obvious trailing footer text.
        for end_marker in (
            "Footer",
            "© 2026 GitHub",
            "© 2025 GitHub",
            "© 2024 GitHub",
        ):
            index = body.find(end_marker)

            if index != -1:
                body = body[:index]

        return self._normalize(body)

    # --------------------------------------------------
    # Exact CVE record
    # --------------------------------------------------

    def _find_exact_record(
        self,
        text: str,
        cve_id: str,
    ) -> str | None:

        matches = list(
            re.finditer(
                re.escape(cve_id),
                text,
                flags=re.IGNORECASE,
            )
        )

        if not matches:
            return None

        match = matches[0]

        start = match.start()

        next_cve = self.CVE_PATTERN.search(
            text,
            match.end(),
        )

        end = (
            next_cve.start()
            if next_cve
            else len(text)
        )

        return self._normalize(
            text[start:end]
        )

    # --------------------------------------------------
    # Narrative context
    # --------------------------------------------------

    def _narrative_context(
        self,
        text: str,
        cve_id: str,
        keywords: list[str],
    ) -> list[str]:

        matches = list(
            re.finditer(
                re.escape(cve_id),
                text,
                flags=re.IGNORECASE,
            )
        )

        if not matches:
            return []

        # GitHub page chrome usually contains the CVE in title
        # first, while later occurrences are in the actual issue body.
        match = matches[-1]

        start = max(
            0,
            match.start()
            - 1200,
        )

        end = min(
            len(text),
            match.end()
            + 5000,
        )

        chunk = self._normalize(
            text[start:end]
        )

        if not chunk:
            return []

        return [chunk]

    # --------------------------------------------------
    # Generic fallback
    # --------------------------------------------------

    def _fallback_context(
        self,
        text: str,
        keywords: list[str],
    ) -> list[str]:

        lowered = text.lower()

        for keyword in keywords:

            if not keyword:
                continue

            position = lowered.find(
                keyword.lower()
            )

            if position == -1:
                continue

            start = max(
                0,
                position
                - self.FALLBACK_CONTEXT_SIZE // 2,
            )

            end = min(
                len(text),
                position
                + self.FALLBACK_CONTEXT_SIZE // 2,
            )

            return [
                self._normalize(
                    text[start:end]
                )
            ]

        return []

    # --------------------------------------------------
    # Main
    # --------------------------------------------------

    def build(
        self,
        document,
        cve_id: str,
        keywords: list[str] | None = None,
    ) -> ReferenceContext:

        text = self._normalize(
            document.content
        )

        keywords = keywords or []

        source_type = (
            document.source_type
            or ""
        ).lower()

        # --------------------------------------------------
        # Vendor / structured advisory
        # --------------------------------------------------

        if source_type in self.STRUCTURED_SOURCE_TYPES:

            exact_record = self._find_exact_record(
                text=text,
                cve_id=cve_id,
            )

            if exact_record:
                return ReferenceContext(
                    source_url=document.url,
                    source_type=document.source_type,
                    title=document.title,
                    exact_record=exact_record,
                    context_chunks=[
                        exact_record
                    ],
                )

        # --------------------------------------------------
        # GitHub / research source
        # --------------------------------------------------

        if source_type in self.NARRATIVE_SOURCE_TYPES:

            narrative_text = text

            if source_type.startswith(
                "github"
            ):
                narrative_text = (
                    self._extract_github_body(
                        text,
                        cve_id,
                    )
                )

            contexts = self._narrative_context(
                text=narrative_text,
                cve_id=cve_id,
                keywords=keywords,
            )

            return ReferenceContext(
                source_url=document.url,
                source_type=document.source_type,
                title=document.title,
                exact_record=None,
                context_chunks=contexts,
            )

        # --------------------------------------------------
        # Generic fallback
        # --------------------------------------------------

        exact_record = self._find_exact_record(
            text=text,
            cve_id=cve_id,
        )

        if exact_record:
            return ReferenceContext(
                source_url=document.url,
                source_type=document.source_type,
                title=document.title,
                exact_record=exact_record,
                context_chunks=[
                    exact_record
                ],
            )

        contexts = self._fallback_context(
            text=text,
            keywords=keywords,
        )

        return ReferenceContext(
            source_url=document.url,
            source_type=document.source_type,
            title=document.title,
            exact_record=None,
            context_chunks=contexts,
        )