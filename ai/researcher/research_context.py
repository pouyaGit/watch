from __future__ import annotations

from ai.collectors.reference_ranker import ReferenceRanker


def build_research_contexts(
    documents: list[dict],
    cve_id: str,
    keywords: list[str],
) -> list[dict]:

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