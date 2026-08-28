from __future__ import annotations

from ai.knowledge.store import KnowledgeStore
from ai.schemas.knowledge import (
    KnowledgeAttributedValue,
    KnowledgeDocument,
)
from ai.schemas.xss import (
    XSSAttributedValue,
    XSSCase,
    XSSResearchContext,
)


def _attributed(
    item: KnowledgeAttributedValue,
) -> XSSAttributedValue:
    return XSSAttributedValue(
        value=item.value,
        source_ids=list(item.source_ids),
    )


def _project_attributed(
    values: list[KnowledgeAttributedValue],
) -> list[XSSAttributedValue]:
    return [_attributed(item) for item in values]


class XSSResearcher:
    """
    Deterministic XSS research layer.

    Connects an :class:`XSSCase` to a local :class:`KnowledgeStore` and
    produces an :class:`XSSResearchContext`. The researcher never
    invents payloads: at this stage every payload and verification
    pattern is sourced exclusively from ``KnowledgeAggregate`` on
    matched documents.

    The researcher is intentionally side-effect-free on the caller's
    data: it does not mutate the input case, does not perform network
    requests, does not invoke an LLM, and does not synthesize a global
    confidence value. ``research`` returns a tuple of
    ``(updated_case, context)``; ``updated_case`` is a copy of the
    input with ``retrieved_knowledge_ids`` populated from the context,
    so the original case is left unchanged. Ordering is stable;
    timestamps are not used for ordering.
    """

    def __init__(self, store: KnowledgeStore) -> None:
        self.store = store

    def research(
        self,
        case: XSSCase,
    ) -> tuple[XSSCase, XSSResearchContext]:
        context = self._build_context(case)

        updated_case = case.model_copy(
            update={
                "retrieved_knowledge_ids": list(
                    context.retrieved_knowledge_ids
                ),
            }
        )

        return updated_case, context

    def _build_context(
        self,
        case: XSSCase,
    ) -> XSSResearchContext:
        documents = self._retrieve(case)
        documents_sorted = sorted(
            documents,
            key=lambda document: document.knowledge_id,
        )

        retrieved_knowledge_ids = [
            document.knowledge_id
            for document in documents_sorted
        ]

        payload_patterns: list[XSSAttributedValue] = []
        verification_patterns: list[XSSAttributedValue] = []
        contexts: list[XSSAttributedValue] = []
        technologies: list[XSSAttributedValue] = []
        waf_observations: list[XSSAttributedValue] = []

        for document in documents_sorted:
            payload_patterns.extend(
                _project_attributed(
                    document.aggregate.payload_patterns
                )
            )
            verification_patterns.extend(
                _project_attributed(
                    document.aggregate.verification_patterns
                )
            )
            contexts.extend(
                _project_attributed(
                    document.aggregate.contexts
                )
            )
            technologies.extend(
                _project_attributed(
                    document.aggregate.technologies
                )
            )
            waf_observations.extend(
                _project_attributed(
                    document.aggregate.wafs
                )
            )

        return XSSResearchContext(
            case_id=case.case_id,
            retrieved_knowledge_ids=retrieved_knowledge_ids,
            documents=documents_sorted,
            payload_patterns=self._dedupe_attributed(
                payload_patterns
            ),
            verification_patterns=self._dedupe_attributed(
                verification_patterns
            ),
            contexts=self._dedupe_attributed(contexts),
            technologies=self._dedupe_attributed(technologies),
            waf_observations=self._dedupe_attributed(
                waf_observations
            ),
        )

    def _retrieve(
        self,
        case: XSSCase,
    ) -> list[KnowledgeDocument]:
        return self.store.retrieve(
            technologies=case.technology or None,
            xss_types=[case.xss_type] if case.xss_type else None,
            contexts=[case.context.type] if case.context.type else None,
            wafs=[case.waf] if case.waf else None,
        )

    @staticmethod
    def _dedupe_attributed(
        values: list[XSSAttributedValue],
    ) -> list[XSSAttributedValue]:
        merged: dict[str, set[str]] = {}

        for item in values:
            merged.setdefault(item.value, set()).update(
                item.source_ids
            )

        return [
            XSSAttributedValue(
                value=value,
                source_ids=sorted(merged[value]),
            )
            for value in sorted(merged)
        ]
