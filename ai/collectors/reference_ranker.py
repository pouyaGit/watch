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

    Provenance-gated technical GitHub fallback:
        GitHub blob/commit/issues/pull references that were directly
        discovered for the current CVE keep one bounded VERBATIM source
        slice even when the page contains no CVE identifier (source
        files and diffs rarely name their CVE). ``exact_record`` stays
        ``None``; no CVE id, severity, exploit, remediation, or trust
        claim is ever injected. Repository roots and non-technical
        GitHub pages still yield no context. See
        ``_technical_github_fallback``.
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

    # GitHub narrative types eligible for the technical fallback.
    # Other narrative types (blogs, writeups, ...) are unchanged.
    TECHNICAL_GITHUB_SOURCE_TYPES = frozenset(
        {
            "github",
            "github_issue",
            "github_research",
        }
    )

    # Full path segments that mark a pinpointed technical GitHub page
    # (source file, commit diff, issue, pull request). Matched on
    # segment boundaries, never as a naive substring, so a repository
    # named e.g. "my-blob-store" does not qualify.
    TECHNICAL_GITHUB_PATH_SEGMENTS = frozenset(
        {
            "blob",
            "commit",
            "issues",
            "pull",
        }
    )

    # Discovery tags that prove the GitHub search that found the URL
    # was correlated with the current CVE identifier.
    CVE_CORRELATED_DISCOVERY_TAGS = frozenset(
        {
            "cve_in_title",
            "cve_in_body",
            "cve_in_repo_name",
        }
    )

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
    # Provenance-gated technical GitHub fallback
    # --------------------------------------------------

    def _technical_github_fallback(
        self,
        *,
        url,
        source_type: str,
        discovery_tags,
        discovery_query,
        text: str,
        cve_id: str,
        keywords: list[str],
    ) -> list[str]:
        """Return at most one verbatim slice for technical GitHub evidence.

        Invoked ONLY when the narrative branch produced no chunks (the
        page contains no CVE identifier). Keeps directly-discovered
        blob/commit/issues/pull material from being discarded as empty
        while repository roots and boilerplate still yield ``[]``.

        All predicates are deterministic and fail closed (any ambiguity
        returns ``[]``):

        - ``source_type`` must be a GitHub narrative type.
        - The URL host must be exactly ``github.com`` (stdlib
          ``urlsplit``; ``www.github.com``, enterprise hosts, raw/gist
          hosts, and malformed URLs are denied).
        - The URL path must contain a technical segment (``blob``,
          ``commit``, ``issues``, ``pull``) on segment boundaries, at
          ``/<owner>/<repo>/<kind>/...`` depth, so repository roots
          never qualify.
        - Discovery provenance must tie the URL to THIS CVE: either an
          ``nvd_reference`` tag with ``discovery_query == cve_id``, or
          the CVE id appearing in ``discovery_query`` together with a
          CVE-correlated discovery tag. Priority, confidence, and
          ``security_research_signal`` alone confer nothing.

        On success the chunk is source text only: first the existing
        keyword-anchored fallback, else the head slice of the
        normalized text bounded by ``FALLBACK_CONTEXT_SIZE``.
        ``exact_record`` is never fabricated here (callers keep it
        ``None``); no CVE id, severity, exploit, remediation, or trust
        marker is injected.
        """
        if (source_type or "").lower() not in (
            self.TECHNICAL_GITHUB_SOURCE_TYPES
        ):
            return []

        cve_norm = (cve_id or "").strip().lower()
        if not cve_norm:
            return []

        if not isinstance(url, str) or not url.strip():
            return []

        try:
            from urllib.parse import urlsplit

            parts = urlsplit(url.strip())
        except Exception:
            return []

        host = parts.hostname or ""
        if host != "github.com":
            return []

        try:
            segments = [
                segment
                for segment in parts.path.lower().split("/")
                if segment
            ]
        except Exception:
            return []

        # /<owner>/<repo>/<kind>/... : the technical kind marker sits
        # at index 2 with at least one trailing segment.
        if len(segments) < 4:
            return []
        if segments[2] not in self.TECHNICAL_GITHUB_PATH_SEGMENTS:
            return []

        tags = discovery_tags if isinstance(discovery_tags, list) else []
        tag_set = {
            str(tag).strip().lower()
            for tag in tags
            if isinstance(tag, str) and str(tag).strip()
        }
        query_norm = (
            str(discovery_query).strip().lower()
            if isinstance(discovery_query, str)
            else ""
        )

        nvd_direct = (
            "nvd_reference" in tag_set and query_norm == cve_norm
        )
        search_correlated = (
            cve_norm in query_norm
            and bool(tag_set & self.CVE_CORRELATED_DISCOVERY_TAGS)
        )
        if not (nvd_direct or search_correlated):
            return []

        if not isinstance(text, str):
            return []

        contexts = self._fallback_context(
            text=text,
            keywords=keywords,
        )
        if contexts:
            return contexts[: self.MAX_CONTEXT_CHUNKS]

        normalized = self._normalize(text)
        if not normalized:
            return []

        return [normalized[: self.FALLBACK_CONTEXT_SIZE]]

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

            if not contexts:
                # CVE-less technical GitHub evidence (source file,
                # commit, issue, pull) that was directly discovered
                # for this CVE keeps one bounded verbatim slice
                # instead of being dropped as empty downstream.
                # Roots/boilerplate still yield [] here.
                contexts = self._technical_github_fallback(
                    url=document.url,
                    source_type=source_type,
                    discovery_tags=getattr(
                        document, "discovery_tags", None
                    ),
                    discovery_query=getattr(
                        document, "discovery_query", None
                    ),
                    text=text,
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