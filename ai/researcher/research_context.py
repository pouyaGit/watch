from __future__ import annotations

from ai.collectors.reference_ranker import ReferenceRanker


def build_research_contexts(
    documents: list[dict],
    cve_id: str,
    keywords: list[str],
) -> list[dict]:
    """Build one raw reference-context dict per fetched document.

    Ephemeral discovery provenance (``discovery_tags`` /
    ``discovery_query``) is forwarded to the ranker when present so it
    can tell a directly-discovered reference from an incidental one.
    These keys are in-memory only: they are stripped from the emitted
    dicts and never reach ``ReferenceContext``, persisted artifacts, or
    telemetry. Documents without them behave exactly as before.
    """

    ranker = ReferenceRanker()
    contexts = []

    for document in documents:
        class SimpleDocument:
            pass

        reference = SimpleDocument()

        reference.url = document["url"]
        reference.source_type = document["source_type"]
        reference.title = document["title"]
        reference.content = document["content"]
        # Ephemeral only; absent => legacy behavior in the ranker.
        reference.discovery_tags = document.get("discovery_tags")
        reference.discovery_query = document.get("discovery_query")

        context = ranker.build(
            document=reference,
            cve_id=cve_id,
            keywords=keywords,
        )

        contexts.append(
            {
                "url": context.source_url,
                "source_type": context.source_type,
                "title": context.title,
                "priority": document.get(
                    "priority",
                    0,
                ),
                "exact_record": context.exact_record,
                "context_chunks": context.context_chunks,
            }
        )

    return contexts