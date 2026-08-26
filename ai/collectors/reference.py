from __future__ import annotations

import hashlib
from urllib.parse import urlparse

import httpx
from html.parser import HTMLParser

from ai.schemas.reference import ReferenceDocument


class HTMLTextExtractor(HTMLParser):
    """
    Lightweight HTML -> text extractor using only Python stdlib.
    """

    SKIP_TAGS = {
        "script",
        "style",
        "noscript",
        "svg",
        "iframe",
        "nav",
        "footer",
        "header",
    }

    def __init__(self):
        super().__init__()

        self.parts: list[str] = []
        self.skip_depth = 0
        self.title: str | None = None
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()

        if tag == "title":
            self.in_title = True

        if tag in self.SKIP_TAGS:
            self.skip_depth += 1

    def handle_endtag(self, tag):
        tag = tag.lower()

        if tag == "title":
            self.in_title = False

        if tag in self.SKIP_TAGS and self.skip_depth:
            self.skip_depth -= 1

    def handle_data(self, data):
        text = " ".join(data.split())

        if not text:
            return

        if self.in_title and self.title is None:
            self.title = text

        if self.skip_depth:
            return

        self.parts.append(text)

    def text(self) -> str:
        return "\n".join(self.parts)


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
        ).lower()

        # Ignore obvious binary content.
        if not any(
            value in content_type
            for value in (
                "text/html",
                "text/plain",
                "application/json",
            )
        ):
            return None

        content = response.content[: self.MAX_BYTES]

        if not content:
            return None

        content_hash = hashlib.sha256(
            content
        ).hexdigest()

        text = ""

        title = None

        if "text/html" in content_type:
            parser = HTMLTextExtractor()

            try:
                parser.feed(
                    content.decode(
                        response.encoding or "utf-8",
                        errors="replace",
                    )
                )
            except Exception:
                return None

            text = parser.text()
            title = parser.title

        else:
            text = content.decode(
                response.encoding or "utf-8",
                errors="replace",
            )

        text = text.strip()

        if not text:
            return None

        return ReferenceDocument(
            url=str(response.url),
            source_type=self.classify_source(
                str(response.url)
            ),
            title=title,
            content=text,
            status_code=response.status_code,
            content_hash=content_hash,
            tags=[],
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