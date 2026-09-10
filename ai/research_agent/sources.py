"""Bounded public research source layer for the R23 research agent.

Responsibilities:

- load already-stored CVE references (no network)
- validate every outbound research URL before it can be fetched
  (scheme, no localhost/LAN/metadata, never a program/target host)
- optionally fetch validated URLs through the existing
  :class:`ai.collectors.reference.ReferenceCollector` (no second HTTP client)
- deterministically compute each source's content hash from trusted,
  normalized content (the LLM never supplies a hash)

All fetching is fail-soft, bounded by count, bytes, time and document size.
No target/program URLs are ever fetched and no credentials are used.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from ai.collectors.body_extraction import normalize_text, sha256_text
from ai.researcher.reference_cache import canonicalize_reference_url
from ai.schemas.research_agent import (
    MAX_DOC_CHARS,
    MAX_SOURCES,
    SOURCE_AVAILABLE,
    SOURCE_FAILED,
    SOURCE_REJECTED,
    SOURCE_STORED_ONLY,
    ResearchAgentSource,
)

__all__ = [
    "SourceValidationError",
    "ResearchSourceCollector",
    "validate_source_url",
    "classify_source",
    "load_reference_archive",
]

DEFAULT_RESEARCH_DIR = Path("ai_data/research")
DEFAULT_MAX_BYTES = 2_000_000
DEFAULT_FETCH_TIMEOUT = 20.0

# Hostnames that are never valid research sources.
_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
)

# Cloud metadata service addresses (belt-and-braces alongside IP checks).
_METADATA_IPS = frozenset(
    {
        "169.254.169.254",
        "169.254.169.253",
        "169.254.170.2",
        "100.100.100.200",
    }
)

_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost")

# Research source taxonomy.
SOURCE_NVD = "nvd"
SOURCE_GITHUB = "github"
SOURCE_VENDOR = "vendor"
SOURCE_WORDFENCE = "wordfence"
SOURCE_WPSCAN = "wpscan"
SOURCE_WRITEUP = "writeup"
SOURCE_OTHER = "other"
SOURCE_STORED = "stored_reference"

_KNOWN_DOMAINS: tuple[tuple[str, str], ...] = (
    ("nvd.nist.gov", SOURCE_NVD),
    ("cve.mitre.org", SOURCE_NVD),
    ("cve.org", SOURCE_NVD),
    ("github.com", SOURCE_GITHUB),
    ("raw.githubusercontent.com", SOURCE_GITHUB),
    ("gist.github.com", SOURCE_GITHUB),
    ("wordfence.com", SOURCE_WORDFENCE),
    ("wpscan.com", SOURCE_WPSCAN),
)

_WRITEUP_DOMAINS = (
    "hackerone.com",
    "bugcrowd.com",
    "portswigger.net",
    "seclists.org",
    "exploit-db.com",
    "packetstormsecurity.com",
    "thehackernews.com",
    "bleepingcomputer.com",
    "medium.com",
    "projectdiscovery.io",
)

_VENDOR_DOMAINS = (
    "microsoft.com",
    "oracle.com",
    "redhat.com",
    "adobe.com",
    "apache.org",
    "wordpress.org",
    "plugins.trac.wordpress.org",
)


class SourceValidationError(ValueError):
    """Raised when a research URL is not safe to fetch."""


def _host_matches_program(host: str, program: str) -> bool:
    """True when ``program`` names a DNS label of ``host`` (target guard).

    Conservative: the program token is compared against each DNS label of the
    host. This rejects ``dell.com`` / ``www.dell.com`` for program ``dell`` and
    also rejects unrelated hosts that contain the token as a full label.
    """
    token = str(program or "").strip().lower()
    if not token:
        return False
    labels = [label for label in host.split(".") if label]
    return token in labels


def validate_source_url(
    url: str,
    *,
    program: str | None = None,
    forbidden_hosts: set[str] | None = None,
) -> str:
    """Validate one outbound research URL; return it unchanged when safe.

    Rejects (raises :class:`SourceValidationError`):

    - non-http(s) schemes
    - missing/blank hosts
    - localhost / ``*.local`` / ``*.internal`` hostnames
    - cloud metadata hostnames and IPs
    - any private / loopback / link-local / reserved IP literal
    - the program/target host itself (and caller-supplied forbidden hosts)
    """
    text = str(url or "").strip()
    if not text:
        raise SourceValidationError("empty source URL")
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https"):
        raise SourceValidationError(
            f"unsupported scheme for research URL: {parsed.scheme!r}"
        )
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise SourceValidationError("research URL has no host")

    if host in _BLOCKED_HOSTNAMES:
        raise SourceValidationError(f"blocked research host: {host}")
    if host.endswith(_BLOCKED_SUFFIXES):
        raise SourceValidationError(f"blocked research host suffix: {host}")
    if host in _METADATA_IPS:
        raise SourceValidationError(f"blocked metadata address: {host}")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise SourceValidationError(f"blocked non-public address: {host}")

    if program and _host_matches_program(host, program):
        raise SourceValidationError(
            f"refusing target/program host: {host} (program={program})"
        )

    if forbidden_hosts:
        normalized = {h.strip().lower().rstrip(".") for h in forbidden_hosts if h}
        if host in normalized:
            raise SourceValidationError(f"forbidden research host: {host}")

    return text


def classify_source(url: str, fallback: str | None = None) -> str:
    """Deterministic research-source taxonomy for a URL."""
    host = (urlparse(str(url or "")).hostname or "").lower().rstrip(".")
    for domain, kind in _KNOWN_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return kind
    for domain in _WRITEUP_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return SOURCE_WRITEUP
    for domain in _VENDOR_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return SOURCE_VENDOR
    if fallback:
        return str(fallback)
    return SOURCE_OTHER


def load_reference_archive(
    cve: str, *, research_dir: str | Path = DEFAULT_RESEARCH_DIR
) -> list[dict]:
    """Read the local ``<CVE>.references.json`` archive (read-only, fail-soft)."""
    path = Path(research_dir) / f"{cve}.references.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        return []
    return [r for r in records if isinstance(r, dict)]


@dataclass
class _RawSource:
    url: str
    source_type: str = SOURCE_OTHER
    title: str | None = None
    content: str = ""
    content_hash: str | None = None
    status: str = SOURCE_STORED_ONLY
    note: str = ""


class ResearchSourceCollector:
    """Collect bounded, validated research sources for one CVE/plan.

    ``fetcher`` is injectable (any object with ``fetch(url) -> document|None``
    where the document exposes ``content`` / ``content_hash`` / ``url`` /
    ``source_type`` / ``title``). The default builds the existing
    :class:`~ai.collectors.reference.ReferenceCollector`.
    """

    def __init__(
        self,
        *,
        research_dir: str | Path = DEFAULT_RESEARCH_DIR,
        fetcher: Any = None,
        max_sources: int = MAX_SOURCES,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_doc_chars: int = MAX_DOC_CHARS,
        timeout: float = DEFAULT_FETCH_TIMEOUT,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.research_dir = Path(research_dir)
        self._fetcher = fetcher
        self.max_sources = max(int(max_sources), 1)
        self.max_bytes = max(int(max_bytes), 1)
        self.max_doc_chars = max(int(max_doc_chars), 1)
        self.timeout = timeout
        self._clock = clock
        self._seen_urls: set[str] = set()
        self._seen_hashes: set[str] = set()
        # content_hash -> bounded normalized content (for prompt grounding;
        # never persisted inside the result).
        self._content: dict[str, str] = {}

    def _reset(self) -> None:
        """Scope dedupe state to a single plan collection.

        The same collector instance is reused across plans; without this a
        second plan sharing a reference URL would incorrectly see every URL as
        already-seen and collect nothing.
        """
        self._seen_urls = set()
        self._seen_hashes = set()
        self._content = {}

    def content_for(self, source: ResearchAgentSource) -> str:
        """Bounded normalized content for a source ("" when none)."""
        if not source.content_hash:
            return ""
        return self._content.get(source.content_hash, "")

    # -- fetcher ----------------------------------------------------------
    def _get_fetcher(self):
        if self._fetcher is not None:
            return self._fetcher
        from ai.collectors.reference import ReferenceCollector

        self._fetcher = ReferenceCollector(timeout=self.timeout)
        return self._fetcher

    def close(self) -> None:
        fetcher = self._fetcher
        if fetcher is not None and hasattr(fetcher, "close"):
            try:
                fetcher.close()
            except Exception:
                pass

    # -- helpers ----------------------------------------------------------
    def _hash(self, content: str) -> str | None:
        normalized = normalize_text(content or "")[: self.max_doc_chars]
        if not normalized:
            return None
        return sha256_text(normalized)

    def _make(
        self,
        url: str,
        *,
        source_type: str | None = None,
        title: str | None = None,
        content: str = "",
        status: str = SOURCE_STORED_ONLY,
        note: str = "",
    ) -> ResearchAgentSource:
        content_hash = self._hash(content)
        normalized = normalize_text(content or "")[: self.max_doc_chars]
        if content_hash and normalized:
            self._content[content_hash] = normalized
        kind = classify_source(url, fallback=source_type)
        source_id = "src-" + sha256_text(canonicalize_reference_url(url))[:16]
        return ResearchAgentSource(
            source_id=source_id,
            url=url,
            source_type=kind,
            title=(title or None),
            status=status,
            content_hash=content_hash,
            char_count=len(normalize_text(content or "")[: self.max_doc_chars]),
            note=note,
        )

    # -- stored references (offline) -------------------------------------
    def collect_stored(
        self, cve: str, references: list[str] | None = None
    ) -> list[ResearchAgentSource]:
        """URL(s) already associated with the CVE (no network).

        Archive bodies (when present) yield a trusted content hash; URL-only
        references are kept as STORED_ONLY and can never back an evidence
        claim (no content => no hash).
        """
        records = load_reference_archive(cve, research_dir=self.research_dir)
        self._reset()
        by_url: dict[str, dict] = {}
        for record in records:
            url = str(record.get("source_url") or record.get("url") or "").strip()
            if url:
                by_url[canonicalize_reference_url(url)] = record

        urls: list[str] = []
        for url in references or []:
            text = str(url or "").strip()
            if text:
                urls.append(text)
        for record in records:
            url = str(record.get("source_url") or record.get("url") or "").strip()
            if url:
                urls.append(url)

        out: list[ResearchAgentSource] = []
        for url in urls:
            if len(out) >= self.max_sources:
                break
            key = canonicalize_reference_url(url)
            if key in self._seen_urls:
                continue
            self._seen_urls.add(key)
            record = by_url.get(key)
            body = ""
            title = None
            source_type = None
            if record:
                body = str(
                    record.get("body")
                    or record.get("content")
                    or record.get("exact_record")
                    or ""
                )
                title = record.get("title")
                source_type = record.get("source_type")
            source = self._make(
                url,
                source_type=source_type,
                title=title,
                content=body,
                status=SOURCE_STORED_ONLY if not body else SOURCE_AVAILABLE,
                note="" if body else "URL-only stored reference (no local body)",
            )
            if source.content_hash:
                if source.content_hash in self._seen_hashes:
                    continue
                self._seen_hashes.add(source.content_hash)
            out.append(source)
        return out

    # -- fetching (bounded, fail-soft) -----------------------------------
    def fetch_sources(
        self,
        sources: list[ResearchAgentSource],
        *,
        program: str | None = None,
        forbidden_hosts: set[str] | None = None,
        deadline: float | None = None,
    ) -> list[ResearchAgentSource]:
        """Fetch validated URL-only sources, fail-soft per source.

        Returns a NEW list; already-populated (archived) sources are passed
        through unchanged. Never raises for a single source failure.
        """
        out: list[ResearchAgentSource] = []
        for source in sources:
            if source.content_hash:
                out.append(source)
                continue
            if self._clock and deadline is not None and self._clock() >= deadline:
                out.append(
                    source.model_copy(
                        update={"status": SOURCE_FAILED, "note": "time budget expired"}
                    )
                )
                continue
            try:
                url = validate_source_url(
                    source.url,
                    program=program,
                    forbidden_hosts=forbidden_hosts,
                )
            except SourceValidationError as exc:
                out.append(
                    source.model_copy(
                        update={
                            "status": SOURCE_REJECTED,
                            "note": f"rejected: {exc}",
                        }
                    )
                )
                continue
            document = None
            try:
                document = self._get_fetcher().fetch(url)
            except Exception as exc:  # fail-soft: one bad source never aborts
                out.append(
                    source.model_copy(
                        update={
                            "status": SOURCE_FAILED,
                            "note": f"fetch error: {type(exc).__name__}",
                        }
                    )
                )
                continue
            if document is None:
                out.append(
                    source.model_copy(
                        update={"status": SOURCE_FAILED, "note": "fetch failed"}
                    )
                )
                continue
            content = getattr(document, "content", "") or ""
            if isinstance(document, dict):
                content = document.get("content") or ""
            content = content[: self.max_doc_chars]
            content_hash = self._hash(content)
            if not content_hash:
                out.append(
                    source.model_copy(
                        update={"status": SOURCE_FAILED, "note": "empty body"}
                    )
                )
                continue
            if content_hash in self._seen_hashes:
                out.append(
                    source.model_copy(
                        update={
                            "status": SOURCE_AVAILABLE,
                            "content_hash": content_hash,
                            "char_count": len(normalize_text(content)[: self.max_doc_chars]),
                            "note": "duplicate content",
                        }
                    )
                )
                continue
            self._seen_hashes.add(content_hash)
            self._content[content_hash] = normalize_text(content)[: self.max_doc_chars]
            out.append(
                source.model_copy(
                    update={
                        "status": SOURCE_AVAILABLE,
                        "content_hash": content_hash,
                        "char_count": len(normalize_text(content)[: self.max_doc_chars]),
                        "title": getattr(document, "title", None) or source.title,
                        "note": "",
                    }
                )
            )
        return out
