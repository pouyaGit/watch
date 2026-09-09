from __future__ import annotations

import hashlib
from urllib.parse import urlparse

import httpx

from ai.collectors.body_extraction import (
    BODY_EXTRACTION_RULE_VERSION,
    EXTRACTION_STATUS_EMPTY,
    EXTRACTION_STATUS_FAILED,
    EXTRACTION_STATUS_OK,
    ExtractedBody,
    HTMLTextExtractor,
    extract_body,
    looks_like_pdf_url,
    normalize_text,
    sha256_text,
    sniff_content_type,
)

from ai.schemas.reference import ReferenceDocument

__all__ = [
    "BODY_EXTRACTION_RULE_VERSION",
    "HTMLTextExtractor",
    "ReferenceCollector",
]


def _github_raw_url(url: str) -> str | None:
    """Deterministic github.com blob/raw -> raw.githubusercontent.com map.

    Conservative: only exact ``/blob/`` and ``/raw/`` GitHub paths are
    rewritten; the path (including its percent-encoding) is preserved
    verbatim. Anything else returns None.
    """

    parsed = urlparse(url)
    if "github.com" not in parsed.netloc.lower():
        return None
    segments = parsed.path.lstrip("/").split("/")
    if len(segments) < 4 or segments[2] not in {"blob", "raw"}:
        return None
    raw_path = "/".join(
        [segments[0], segments[1], *segments[3:]]
    )
    return f"https://raw.githubusercontent.com/{raw_path}"


class ReferenceCollector:
    DEFAULT_TIMEOUT = 20.0
    MAX_BYTES = 2_000_000

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.timeout = timeout

        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": (
                    "Watch-Security-Researcher/0.1 "
                    "(authorized security research)"
                )
            },
        )

    def classify_source(self, url: str) -> str:
        host = urlparse(url).netloc.lower()

        if "github.com" in host:
            return "github"

        if "oracle.com" in host:
            return "vendor"

        if "microsoft.com" in host:
            return "vendor"

        if "google.com" in host:
            return "vendor"

        if "redhat.com" in host:
            return "vendor"

        if "hackerone.com" in host:
            return "bug_bounty"

        if "bugcrowd.com" in host:
            return "bug_bounty"

        if "portswigger.net" in host:
            return "security_research"

        if "projectdiscovery.io" in host:
            return "security_research"

        return "other"

    def _extract_from_content(
        self,
        content: bytes,
        content_type: str,
        url: str,
        encoding: str | None,
        raw_hash: str,
        status_code: int | None = None,
    ) -> ReferenceDocument:
        """Run bounded body extraction and build the document."""

        content_format = sniff_content_type(content_type, url, content)
        response_url = url

        # GitHub blob/raw pages serving a PDF with unreliable headers:
        # one deterministic raw fetch (no crawling, no retries).
        if (
            content_format in (None, "text/html")
            and looks_like_pdf_url(url)
        ):
            raw_url = _github_raw_url(url)
            if raw_url:
                try:
                    raw_response = self.client.get(raw_url)
                    raw_response.raise_for_status()
                except httpx.HTTPError:
                    raw_response = None
                if raw_response is not None and raw_response.content:
                    raw_content = raw_response.content[: self.MAX_BYTES]
                    raw_hash = hashlib.sha256(raw_content).hexdigest()
                    content_format = sniff_content_type(
                        raw_response.headers.get("content-type", ""),
                        raw_url,
                        raw_content,
                    )
                    if content_format is not None:
                        content = raw_content
                        # Provenance: the original reference URL is
                        # preserved (never rewritten to the raw host).
                        encoding = raw_response.encoding
                        content_type = raw_response.headers.get(
                            "content-type", ""
                        )

        if content_format is None:
            return self._failed_document(
                response_url, raw_hash, None, "unsupported_content_type",
                status_code=status_code,
            )

        result: ExtractedBody = extract_body(
            content,
            content_format,
            encoding or "utf-8",
        )

        title = None
        if content_format == "text/html":
            # Title extraction is part of the existing HTML path.
            from ai.collectors.body_extraction import HTMLTextExtractor

            parser = HTMLTextExtractor()
            try:
                parser.feed(content.decode(encoding or "utf-8",
                                           errors="replace"))
                title = parser.title
            except Exception:
                title = None

        if result.extraction_status != EXTRACTION_STATUS_OK:
            status = (
                EXTRACTION_STATUS_EMPTY
                if result.extraction_status == EXTRACTION_STATUS_EMPTY
                else EXTRACTION_STATUS_FAILED
            )
            return self._failed_document(
                response_url,
                raw_hash,
                content_format,
                result.error or status,
                content_type=content_type or None,
                status_code=status_code,
            )

        return ReferenceDocument(
            url=response_url,
            source_type=self.classify_source(response_url),
            title=title,
            content=result.text,
            status_code=status_code,
            content_hash=result.content_hash,
            raw_content_hash=raw_hash,
            extraction_format=result.extraction_format,
            extraction_status=EXTRACTION_STATUS_OK,
            tags=[],
        )

    def _failed_document(
        self,
        url: str,
        raw_hash: str,
        extraction_format: str | None,
        error: str,
        content_type: str | None = None,
        status_code: int | None = None,
    ) -> ReferenceDocument:
        """Fail-soft document: metadata retained, no body, no hash."""

        return ReferenceDocument(
            url=url,
            source_type=self.classify_source(url),
            title=None,
            content="",
            status_code=status_code,
            content_hash=None,
            raw_content_hash=raw_hash or None,
            extraction_format=extraction_format,
            extraction_status=EXTRACTION_STATUS_FAILED,
            tags=[],
        )

    def fetch(
        self,
        url: str,
    ) -> ReferenceDocument | None:

        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            return None

        try:
            response = self.client.get(url)
            response.raise_for_status()
        except httpx.HTTPError:
            return None

        content_type = response.headers.get(
            "content-type",
            "",
        )

        content = response.content[: self.MAX_BYTES]

        if not content:
            return None

        raw_hash = hashlib.sha256(content).hexdigest()

        return self._extract_from_content(
            content=content,
            content_type=content_type,
            url=url,
            encoding=response.encoding,
            raw_hash=raw_hash,
            status_code=response.status_code,
        )

    def collect(
        self,
        urls: list[str],
    ) -> list[ReferenceDocument]:

        documents = []
        seen_urls = set()
        seen_hashes = set()

        for url in urls:
            if url in seen_urls:
                continue

            seen_urls.add(url)

            document = self.fetch(url)

            if document is None:
                continue

            # Failed/empty extractions are never returned as usable
            # references (metadata-only documents stay out of the
            # collection pipeline; provenance lives in the archive).
            if (
                document.extraction_status != EXTRACTION_STATUS_OK
                or not document.content
            ):
                continue

            if document.content_hash in seen_hashes:
                continue

            seen_hashes.add(
                document.content_hash
            )

            documents.append(document)

        return documents

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