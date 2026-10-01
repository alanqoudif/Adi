"""A fully deterministic LLM used by tests and by `adi doctor`-style
diagnostics. Lets the planner/orchestrator test suite run without any real
provider or network access."""

from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel

from adi.llm.base import LLMMessage, LLMProvider, MalformedResponseError

T = TypeVar("T", bound=BaseModel)


class MockLLM(LLMProvider):
    """Scripted responses, returned in order. `structured()` bypasses the
    JSON-parsing round trip entirely and just returns the next scripted
    model instance (or raises the next scripted exception), so tests are
    not coupled to prompt text."""

    def __init__(self, model: str = "mock-model"):
        self.model = model
        self._scripted_structured: list[BaseModel | Exception] = []
        self._scripted_text: list[str] = []
        self.calls: list[list[LLMMessage]] = []

    def script_structured(self, *responses: BaseModel | Exception) -> None:
        self._scripted_structured.extend(responses)

    def script_text(self, *responses: str) -> None:
        self._scripted_text.extend(responses)

    async def complete(self, messages: list[LLMMessage], *, max_tokens: int = 1024) -> str:
        self.calls.append(messages)
        if self._scripted_text:
            return self._scripted_text.pop(0)
        return "{}"

    async def structured(self, messages: list[LLMMessage], schema: type[T], *, max_tokens: int = 1024) -> T:
        self.calls.append(messages)
        if not self._scripted_structured:
            raise MalformedResponseError("MockLLM has no more scripted responses")
        next_item = self._scripted_structured.pop(0)
        if isinstance(next_item, Exception):
            raise next_item
        if not isinstance(next_item, schema):
            raise MalformedResponseError(
                f"scripted response type {type(next_item).__name__} does not match "
                f"requested schema {schema.__name__}"
            )
        return next_item
