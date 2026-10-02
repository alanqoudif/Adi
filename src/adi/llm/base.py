"""Provider-neutral LLM abstraction.

The orchestrator and planner depend only on `LLMProvider` — never on a
specific SDK. This is what lets `ADI_LLM_PROVIDER` switch between Anthropic,
an OpenAI-compatible API (including OpenRouter and local inference servers),
with no change to agent code.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class LLMMessage(BaseModel):
    role: str  # "system" | "user" | "assistant"
    content: str


class LLMError(RuntimeError):
    """Raised when a provider call fails (network, auth, rate limit, ...)."""


class MalformedResponseError(RuntimeError):
    """Raised when a provider's response cannot be validated against the
    requested schema, even after a retry. The caller (planner) must handle
    this rather than crash the assessment."""


class LLMProvider(ABC):
    """A chat-completion provider. Implementations must not leak
    SDK-specific types across this boundary."""

    model: str

    @abstractmethod
    async def complete(self, messages: list[LLMMessage], *, max_tokens: int = 1024) -> str:
        """Free-text completion."""
        ...

    async def structured(
        self, messages: list[LLMMessage], schema: type[T], *, max_tokens: int = 1024
    ) -> T:
        """Request a completion and validate it against `schema`.

        The default implementation appends a schema instruction to the
        prompt and extracts/validates JSON from the free-text response, with
        one retry on a validation failure. Providers with native structured
        output may override this for better reliability.
        """
        schema_messages = messages + [
            LLMMessage(
                role="user",
                content=(
                    "Respond with ONLY a single JSON object matching this JSON Schema. "
                    "No prose, no markdown code fences.\n\n"
                    f"{json.dumps(schema.model_json_schema())}"
                ),
            )
        ]
        raw = await self.complete(schema_messages, max_tokens=max_tokens)
        try:
            return _parse_and_validate(raw, schema)
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            retry_messages = schema_messages + [
                LLMMessage(role="assistant", content=raw),
                LLMMessage(
                    role="user",
                    content=(
                        f"That response was invalid: {exc}. "
                        "Reply again with ONLY the corrected JSON object, nothing else."
                    ),
                ),
            ]
            raw_retry = await self.complete(retry_messages, max_tokens=max_tokens)
            try:
                return _parse_and_validate(raw_retry, schema)
            except (ValidationError, ValueError, json.JSONDecodeError) as exc2:
                raise MalformedResponseError(
                    f"model response did not match {schema.__name__} after retry: {exc2}\n"
                    f"raw response: {raw_retry[:500]}"
                ) from exc2


_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


def _parse_and_validate[T: BaseModel](raw: str, schema: type[T]) -> T:
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text.removeprefix("json")
    match = _JSON_BLOCK_RE.search(text)
    candidate = match.group(0) if match else text
    data = json.loads(candidate)
    return schema.model_validate(data)
