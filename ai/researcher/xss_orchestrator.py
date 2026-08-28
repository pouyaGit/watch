from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ai.llm.base import LLMProvider
from ai.researcher.xss_llm_researcher import XSSLLMResearcher
from ai.researcher.xss_researcher import XSSResearcher
from ai.schemas.xss import XSSCase, XSSResearchContext, XSSResearchLLMResult


_AllowedStage = Literal["ANALYZED", "INCONCLUSIVE"]


class XSSAnalysisAudit(BaseModel):
    """
    Deterministic, audit-friendly summary of the orchestration
    pipeline. The orchestrator never reports "CONFIRMED" or
    "NOT_VULNERABLE"; that responsibility belongs to the
    verification stage, which is not part of this layer.
    """

    retrieval_call_count: int = 0
    llm_call_count: int = 0

    retrieved_knowledge_ids: list[str] = Field(
        default_factory=list
    )
    retrieval_had_results: bool = False

    had_payload_suggestions: bool = False
    had_verification_ideas: bool = False

    had_any_knowledge_derived_suggestion: bool = False
    had_any_model_generated_suggestion: bool = False

    llm_case_status_suggestion: str | None = None

    notes: list[str] = Field(default_factory=list)


class XSSAnalysisResult(BaseModel):
    """
    Output of :meth:`XSSOrchestrator.analyze`.

    Carries:

    - the updated case (with ``retrieved_knowledge_ids`` set),
    - the deterministic retrieval context,
    - the validated LLM research result,
    - the orchestrator's pre-confirmation stage label, and
    - a deterministic audit object.

    No ``XSSFinding`` is produced at this stage. Findings are
    produced only by a downstream verification stage, which
    is not yet implemented.
    """

    case: XSSCase
    context: XSSResearchContext
    llm_result: XSSResearchLLMResult

    stage: _AllowedStage

    audit: XSSAnalysisAudit


_FORBIDDEN_STATUS_ADVANCE: frozenset[str] = frozenset(
    {"VERIFYING", "CONFIRMED", "NOT_VULNERABLE"}
)


class XSSOrchestrator:
    """
    Provider-agnostic XSS orchestration layer.

    The orchestrator coordinates three existing components:

    - :class:`ai.researcher.xss_researcher.XSSResearcher`
      performs deterministic retrieval against the local
      :class:`ai.knowledge.store.KnowledgeStore`. This is the
      single authoritative retrieval path. The orchestrator
      never calls :meth:`KnowledgeStore.retrieve` directly.

    - :class:`ai.researcher.xss_llm_researcher.XSSLLMResearcher`
      runs the LLM over the retrieved context. The
      orchestrator never duplicates the prompt, the JSON
      parser, or the attribution validator.

    - The LLM provider is injected and never instantiated by
      the orchestrator.

    The orchestrator is not a verifier. It never reports
    ``CONFIRMED`` or ``NOT_VULNERABLE``, never constructs an
    :class:`XSSFinding`, and never advances a case to
    ``VERIFYING`` (which would imply a verification stage).
    """

    def __init__(
        self,
        knowledge_researcher: XSSResearcher,
        llm_researcher: XSSLLMResearcher,
    ) -> None:
        if not isinstance(
            knowledge_researcher, XSSResearcher
        ):
            raise TypeError(
                "knowledge_researcher must be an XSSResearcher"
            )
        if not isinstance(llm_researcher, XSSLLMResearcher):
            raise TypeError(
                "llm_researcher must be an XSSLLMResearcher"
            )
        if not isinstance(llm_researcher.llm, LLMProvider):
            raise TypeError(
                "llm_researcher.llm must be an LLMProvider"
            )

        self.knowledge_researcher = knowledge_researcher
        self.llm_researcher = llm_researcher

    def analyze(self, case: XSSCase) -> XSSAnalysisResult:
        """
        Run one analysis pass.

        Returns an :class:`XSSAnalysisResult`. Failures from
        any component are propagated unchanged so the caller
        can see exactly which stage failed.

        The returned result owns independent deep copies of
        the context and the LLM result. Caller mutations of
        ``result.context`` or ``result.llm_result`` therefore
        cannot leak back into the
        :class:`XSSResearcher` / :class:`XSSLLMResearcher`
        state, nor into subsequent ``analyze`` calls.
        """

        updated_case, context = self.knowledge_researcher.research(
            case
        )

        llm_result = self.llm_researcher.analyze(
            updated_case, context
        )

        stage = self._derive_stage(llm_result, context)

        audit = self._build_audit(updated_case, context, llm_result)

        owned_context = context.model_copy(deep=True)
        owned_llm_result = llm_result.model_copy(deep=True)

        return XSSAnalysisResult(
            case=updated_case,
            context=owned_context,
            llm_result=owned_llm_result,
            stage=stage,
            audit=audit,
        )

    @staticmethod
    def _derive_stage(
        llm_result: XSSResearchLLMResult,
        context: XSSResearchContext,
    ) -> _AllowedStage:
        if llm_result.case_status_suggestion == "INCONCLUSIVE":
            return "INCONCLUSIVE"
        if not context.retrieved_knowledge_ids:
            return "INCONCLUSIVE"
        return "ANALYZED"

    @staticmethod
    def _build_audit(
        case: XSSCase,
        context: XSSResearchContext,
        llm_result: XSSResearchLLMResult,
    ) -> XSSAnalysisAudit:
        notes: list[str] = []

        if not context.retrieved_knowledge_ids:
            notes.append(
                "no_relevant_knowledge: retrieval returned no "
                "documents; case remains pre-confirmation."
            )

        if not llm_result.suggested_payloads:
            notes.append(
                "no_payload_suggestions: LLM returned no "
                "candidate payloads."
            )
        if not llm_result.verification_ideas:
            notes.append(
                "no_verification_ideas: LLM returned no "
                "candidate verification approaches."
            )

        has_kb = False
        has_mg = False
        for item in llm_result.suggested_payloads:
            if item.origin == "knowledge":
                has_kb = True
            elif item.origin == "model_generated":
                has_mg = True
        for item in llm_result.verification_ideas:
            if item.origin == "knowledge":
                has_kb = True
            elif item.origin == "model_generated":
                has_mg = True
        for item in llm_result.context_observations:
            if item.origin == "knowledge":
                has_kb = True
            elif item.origin == "model_generated":
                has_mg = True

        return XSSAnalysisAudit(
            retrieval_call_count=1,
            llm_call_count=1,
            retrieved_knowledge_ids=list(
                case.retrieved_knowledge_ids
            ),
            retrieval_had_results=bool(
                context.retrieved_knowledge_ids
            ),
            had_payload_suggestions=bool(
                llm_result.suggested_payloads
            ),
            had_verification_ideas=bool(
                llm_result.verification_ideas
            ),
            had_any_knowledge_derived_suggestion=has_kb,
            had_any_model_generated_suggestion=has_mg,
            llm_case_status_suggestion=(
                llm_result.case_status_suggestion
            ),
            notes=notes,
        )


__all__ = [
    "XSSAnalysisAudit",
    "XSSAnalysisResult",
    "XSSOrchestrator",
]
