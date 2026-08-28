from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class LLMResult:
    """Provider-agnostic result of a single LLM call."""

    content: str
    request_id: str | None = None
    model: str | None = None


class LLMProvider(ABC):
    """
    Minimal provider interface for the XSS LLM layer.

    A provider must implement :meth:`generate`. The default
    :meth:`complete` wraps :meth:`generate` and yields an
    :class:`LLMResult` with empty provider metadata, so existing
    stub providers that only implement ``generate`` keep working.

    Providers that have real provider-side metadata (response id,
    model identifier) override :meth:`complete` to surface it.
    """

    @abstractmethod
    def generate(self, prompt: str) -> str:
        raise NotImplementedError

    def complete(self, prompt: str) -> LLMResult:
        return LLMResult(content=self.generate(prompt))
