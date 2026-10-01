"""Anthropic provider. The `anthropic` package is imported lazily so the
rest of Adi works without it installed when another provider is configured."""

from __future__ import annotations

from adi.llm.base import LLMError, LLMMessage, LLMProvider

try:
    import anthropic as _anthropic_sdk

    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False


class AnthropicProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "claude-sonnet-5-5"):
        if not _SDK_AVAILABLE:
            raise LLMError(
                "the 'anthropic' package is not installed (pip install anthropic)"
            )
        if not api_key:
            raise LLMError("no API key provided for the Anthropic provider")
        self.model = model
        self._client = _anthropic_sdk.AsyncAnthropic(api_key=api_key)

    async def complete(self, messages: list[LLMMessage], *, max_tokens: int = 1024) -> str:
        system = "\n".join(m.content for m in messages if m.role == "system") or None
        turns = [
            {"role": m.role, "content": m.content} for m in messages if m.role != "system"
        ]
        try:
            response = await self._client.messages.create(
                model=self.model,
                system=system,
                messages=turns,
                max_tokens=max_tokens,
            )
        except Exception as exc:  # SDK-specific errors collapsed to LLMError
            raise LLMError(f"Anthropic API call failed: {exc}") from exc
        return "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )
