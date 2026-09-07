from __future__ import annotations

from ai.collectors.reference import ReferenceCollector
from ai.schemas.discovery import DiscoveryResult


def fetch_discovered_sources(
    discovery: DiscoveryResult,
    limit: int = 5,
) -> list[dict]:

    results = []

    selected = discovery.sources[:limit]

    with ReferenceCollector() as collector:
        for source in selected:
            document = collector.fetch(
                source.url
            )

            if document is None:
                continue

            results.append(
                {
                    "url": document.url,
                    "source_type": source.source_type,
                    "title": (
                        document.title
                        or source.title
                    ),
                    "priority": source.priority,
                    "tags": source.tags,
                    # Ephemeral discovery provenance (in-memory only;
                    # never persisted, never added to schemas or
                    # telemetry). Distinct from
                    # ``ReferenceDocument.tags``: these describe how
                    # THIS CVE's discovery layer produced the URL, so
                    # downstream ranking can tell a directly-discovered
                    # reference from an incidental one.
                    "discovery_tags": list(source.tags),
                    "discovery_query": source.query,
                    "content": document.content,
                }
            )

    return results