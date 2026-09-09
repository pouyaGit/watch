"""Bounded, deterministic reference body extraction (Stage R13).

Research-only evidence acquisition. Given raw fetched bytes from a
public reference URL, detect the content type, extract the actual body
text, normalize it deterministically, and hash the exact normalized
representation that will be persisted.

Hard safety properties:

- Pure data processing: HTML/PDF/Markdown are treated strictly as
  data. No JavaScript execution, no browser, no subprocess, no
  external resource loading, no OCR, no LLM.
- Bounded: every extractor imposes explicit byte/page/character limits
  and fails soft (returns a ``failed``/``empty`` status) instead of
  consuming unbounded memory. No unbounded regex scans: every regex
  runs on already-bounded input only.
- Deterministic: the same input bytes always produce the same
  normalized text and therefore the same ``content_hash``
  (SHA-256 of the normalized UTF-8 text).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

# Extraction rule/version stamp persisted with every extracted body.
BODY_EXTRACTION_RULE_VERSION = "r13-1"

# Hard limits (conservative, research-pipeline appropriate).
MAX_DOWNLOAD_BYTES = 2_000_000
MAX_EXTRACTED_CHARS = 200_000
MAX_PDF_PAGES = 60
MAX_PDF_BYTES = 5_000_000
MAX_CONTEXT_CHUNK_CHARS = 5_000

EXTRACTION_STATUS_OK = "ok"
EXTRACTION_STATUS_FAILED = "failed"
EXTRACTION_STATUS_EMPTY = "empty"

_FORMAT_HTML = "text/html"
_FORMAT_TEXT = "text/plain"
_FORMAT_MARKDOWN = "text/markdown"
_FORMAT_PDF = "application/pdf"

_PDF_MAGIC = b"%PDF-"

# URL path suffixes recognized conservatively (never inferred for
# arbitrary binary formats).
_MARKDOWN_SUFFIXES = (".md", ".markdown", ".mdown", ".mkd")
_PDF_SUFFIXES = (".pdf",)


class HTMLTextExtractor(HTMLParser):
    """Lightweight HTML -> text extractor using only Python stdlib."""

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


@dataclass(frozen=True)
class ExtractedBody:
    """Deterministic extraction outcome for one fetched body."""

    text: str = ""
    extraction_format: str | None = None
    extraction_status: str = EXTRACTION_STATUS_FAILED
    content_hash: str | None = None
    error: str | None = None
    truncated: bool = False


def sha256_text(text: str) -> str:
    """SHA-256 of the exact normalized UTF-8 representation."""

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_text(text: str) -> str:
    """Deterministic whitespace normalization, bounded output.

    Lines are whitespace-collapsed, trimmed, blank-line runs are
    collapsed to a single blank line, and the result is hard-capped at
    ``MAX_EXTRACTED_CHARS``.
    """

    if not isinstance(text, str):
        return ""
    lines = []
    for line in text.splitlines():
        lines.append(" ".join(line.split()))
    collapsed: list[str] = []
    for line in lines:
        if line == "" and collapsed and collapsed[-1] == "":
            continue
        collapsed.append(line)
    return "\n".join(collapsed).strip()[:MAX_EXTRACTED_CHARS]


def _url_path(url: str) -> str:
    try:
        return unquote(urlsplit(url).path or "")
    except ValueError:
        return ""


def _url_path_suffix(url: str) -> str:
    path = _url_path(url)
    dot = path.rfind(".")
    if dot < 0:
        return ""
    return path[dot:].lower()


def looks_like_pdf_url(url: str) -> bool:
    """Conservative URL-shape check for PDF references."""

    return _url_path_suffix(url) in _PDF_SUFFIXES


def looks_like_markdown_url(url: str) -> bool:
    return _url_path_suffix(url) in _MARKDOWN_SUFFIXES


def sniff_content_type(
    content_type_header: str | None,
    url: str,
    data: bytes,
) -> str | None:
    """Deterministic, conservative content-type detection.

    Returns one of ``text/html``, ``text/plain``, ``text/markdown``,
    ``application/pdf`` or ``None`` (unknown/unsupported). Header
    claims win except when the magic bytes prove otherwise (e.g. a
    ``text/plain`` response whose body is actually a PDF, or a binary
    body pretending to be text).
    """

    header = (content_type_header or "").lower()

    if data[: len(_PDF_MAGIC)] == _PDF_MAGIC:
        return _FORMAT_PDF

    if "application/pdf" in header or "application/x-pdf" in header:
        return _FORMAT_PDF

    if b"\x00" in data[:1024]:
        return None

    if "text/html" in header:
        return _FORMAT_HTML

    if "text/markdown" in header or "text/x-markdown" in header:
        return _FORMAT_MARKDOWN

    if "text/plain" in header:
        if looks_like_markdown_url(url):
            return _FORMAT_MARKDOWN
        return _FORMAT_TEXT

    if "application/json" in header:
        return _FORMAT_TEXT

    if not header or "application/octet-stream" in header:
        if looks_like_markdown_url(url):
            return _FORMAT_MARKDOWN
        if looks_like_pdf_url(url):
            # URL says .pdf but headers are unreliable (GitHub raw
            # often serves application/octet-stream; the %PDF- magic
            # case is handled above, text-like payloads are left to
            # the PDF extractor to fail soft on).
            return _FORMAT_PDF
        return None

    return None


def extract_html(data: bytes, encoding: str | None = None) -> ExtractedBody:
    """Bounded HTML -> normalized text. HTML is data, never executed."""

    try:
        html = data.decode(encoding or "utf-8", errors="replace")
    except Exception:  # never propagate decode errors
        html = data.decode("utf-8", errors="replace")

    parser = HTMLTextExtractor()
    try:
        parser.feed(html)
    except Exception as exc:
        return ExtractedBody(
            extraction_format=_FORMAT_HTML,
            extraction_status=EXTRACTION_STATUS_FAILED,
            error=f"html_parse_error: {type(exc).__name__}",
        )

    text = normalize_text(parser.text())
    if not text:
        return ExtractedBody(
            extraction_format=_FORMAT_HTML,
            extraction_status=EXTRACTION_STATUS_EMPTY,
            error="empty_html_text",
        )
    return ExtractedBody(
        text=text,
        extraction_format=_FORMAT_HTML,
        extraction_status=EXTRACTION_STATUS_OK,
        content_hash=sha256_text(text),
        truncated=len(text) >= MAX_EXTRACTED_CHARS,
    )


def extract_plain_text(
    data: bytes, encoding: str | None = None
) -> ExtractedBody:
    """Bounded plain-text extraction with deterministic normalization."""

    try:
        raw = data.decode(encoding or "utf-8", errors="replace")
    except Exception:
        raw = data.decode("utf-8", errors="replace")

    text = normalize_text(raw)
    if not text:
        return ExtractedBody(
            extraction_format=_FORMAT_TEXT,
            extraction_status=EXTRACTION_STATUS_EMPTY,
            error="empty_text",
        )
    return ExtractedBody(
        text=text,
        extraction_format=_FORMAT_TEXT,
        extraction_status=EXTRACTION_STATUS_OK,
        content_hash=sha256_text(text),
        truncated=len(text) >= MAX_EXTRACTED_CHARS,
    )


def extract_pdf(data: bytes) -> ExtractedBody:
    """Bounded, deterministic PDF text extraction (pypdf).

    - page order preserved
    - strict byte/page/text limits
    - no OCR, no external link handling, no embedded-content execution
    - fail soft: parse errors yield a ``failed`` status, never
      fabricated text
    """

    if len(data) > MAX_PDF_BYTES:
        return ExtractedBody(
            extraction_format=_FORMAT_PDF,
            extraction_status=EXTRACTION_STATUS_FAILED,
            error="pdf_too_large",
        )

    try:
        import io

        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(data))
        page_count = len(reader.pages)
    except Exception as exc:
        return ExtractedBody(
            extraction_format=_FORMAT_PDF,
            extraction_status=EXTRACTION_STATUS_FAILED,
            error=f"pdf_parse_error: {type(exc).__name__}",
        )

    if page_count == 0:
        return ExtractedBody(
            extraction_format=_FORMAT_PDF,
            extraction_status=EXTRACTION_STATUS_EMPTY,
            error="pdf_no_pages",
        )

    truncated = page_count > MAX_PDF_PAGES
    parts: list[str] = []
    total = 0
    for page in reader.pages[:MAX_PDF_PAGES]:
        try:
            page_text = page.extract_text() or ""
        except Exception:
            page_text = ""
        page_text = page_text.strip()
        if page_text:
            parts.append(page_text)
            total += len(page_text) + 2
        if total >= MAX_EXTRACTED_CHARS:
            truncated = True
            break

    text = normalize_text("\n\n".join(parts))
    if not text:
        return ExtractedBody(
            extraction_format=_FORMAT_PDF,
            extraction_status=EXTRACTION_STATUS_EMPTY,
            error="pdf_no_extractable_text",
        )
    return ExtractedBody(
        text=text,
        extraction_format=_FORMAT_PDF,
        extraction_status=EXTRACTION_STATUS_OK,
        content_hash=sha256_text(text),
        error=None,
        truncated=truncated or len(text) >= MAX_EXTRACTED_CHARS,
    )


def extract_body(
    data: bytes,
    content_format: str | None,
    encoding: str | None = None,
) -> ExtractedBody:
    """Dispatch to the bounded extractor for the detected format."""

    bounded = data[:MAX_DOWNLOAD_BYTES]
    if content_format == _FORMAT_HTML:
        return extract_html(bounded, encoding)
    if content_format == _FORMAT_MARKDOWN:
        return extract_markdown(bounded, encoding)
    if content_format == _FORMAT_PDF:
        return extract_pdf(bounded)
    if content_format == _FORMAT_TEXT:
        return extract_plain_text(bounded, encoding)
    return ExtractedBody(
        extraction_format=None,
        extraction_status=EXTRACTION_STATUS_FAILED,
        error="unsupported_content_format",
    )
# ---------------------------------------------------------------------------
# Markdown (deterministic formatting strip; content is never invented)
# ---------------------------------------------------------------------------

_MD_FENCE_RE = re.compile(r"^\s*(```|~~~)")
_MD_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\([^)]*\)")
_MD_LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)\s]*)\)")
_MD_REF_DEF_RE = re.compile(r"^\s*\[[^\]]+\]:\s+\S+\s*$")
_MD_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.*)$")
_MD_EMPHASIS_RE = re.compile(r"(\*\*\*|\*\*|__|\*|_|`)")
_MD_HRULE_RE = re.compile(r"^\s{0,3}((-\s*){3,}|(\*\s*){3,}|(_\s*){3,})$")
_MD_INLINE_HTML_RE = re.compile(r"</?[A-Za-z][^>]{0,200}>")
_MD_BLOCKQUOTE_RE = re.compile(r"^\s{0,3}>\s?")


def extract_markdown(data: bytes, encoding: str | None = None) -> ExtractedBody:
    """Deterministic Markdown -> text.

    Formatting markers are stripped; headings, code/parameter names,
    list items and meaningful inline text are retained. URLs embedded
    in links are dropped (the visible text is kept); standalone URLs
    in plain text remain part of the content. Nothing is invented.
    """

    try:
        raw = data.decode(encoding or "utf-8", errors="replace")
    except Exception:
        raw = data.decode("utf-8", errors="replace")

    raw = raw[: MAX_EXTRACTED_CHARS * 2]
    out_lines: list[str] = []
    in_fence = False
    for line in raw.splitlines():
        if _MD_FENCE_RE.match(line):
            in_fence = not in_fence
            continue  # drop the fence markers, keep the code lines
        if in_fence:
            out_lines.append(line)
            continue
        if _MD_REF_DEF_RE.match(line):
            continue
        if _MD_HRULE_RE.match(line):
            continue
        heading = _MD_HEADING_RE.match(line)
        if heading:
            out_lines.append(heading.group(2).strip())
            continue
        line = _MD_IMAGE_RE.sub(r"\1", line)
        line = _MD_LINK_RE.sub(lambda m: m.group(1) or m.group(2), line)
        line = _MD_INLINE_HTML_RE.sub(" ", line)
        line = _MD_EMPHASIS_RE.sub("", line)
        line = _MD_BLOCKQUOTE_RE.sub("", line)
        out_lines.append(line)

    text = normalize_text("\n".join(out_lines))
    if not text:
        return ExtractedBody(
            extraction_format=_FORMAT_MARKDOWN,
            extraction_status=EXTRACTION_STATUS_EMPTY,
            error="empty_markdown_text",
        )
    return ExtractedBody(
        text=text,
        extraction_format=_FORMAT_MARKDOWN,
        extraction_status=EXTRACTION_STATUS_OK,
        content_hash=sha256_text(text),
        truncated=len(text) >= MAX_EXTRACTED_CHARS,
    )
