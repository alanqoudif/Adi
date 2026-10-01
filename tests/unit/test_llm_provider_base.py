import pytest
from pydantic import BaseModel

from adi.llm.base import LLMMessage, LLMProvider, MalformedResponseError


class _Point(BaseModel):
    x: int
    y: int


class _ScriptedTextProvider(LLMProvider):
    """Exercises the base class's default JSON-extraction `structured()`
    implementation directly (real providers only implement `complete`)."""

    def __init__(self, responses: list[str]):
        self.model = "scripted"
        self._responses = list(responses)
        self.call_count = 0

    async def complete(self, messages: list[LLMMessage], *, max_tokens: int = 1024) -> str:
        self.call_count += 1
        return self._responses.pop(0)


@pytest.mark.asyncio
async def test_structured_extracts_plain_json():
    provider = _ScriptedTextProvider(['{"x": 1, "y": 2}'])
    point = await provider.structured([LLMMessage(role="user", content="go")], _Point)
    assert point == _Point(x=1, y=2)
    assert provider.call_count == 1


@pytest.mark.asyncio
async def test_structured_extracts_json_from_markdown_fence():
    provider = _ScriptedTextProvider(['Sure thing!\n```json\n{"x": 5, "y": 9}\n```\nDone.'])
    point = await provider.structured([LLMMessage(role="user", content="go")], _Point)
    assert point == _Point(x=5, y=9)


@pytest.mark.asyncio
async def test_structured_retries_once_on_malformed_json_then_succeeds():
    provider = _ScriptedTextProvider(["not json at all", '{"x": 3, "y": 4}'])
    point = await provider.structured([LLMMessage(role="user", content="go")], _Point)
    assert point == _Point(x=3, y=4)
    assert provider.call_count == 2


@pytest.mark.asyncio
async def test_structured_raises_after_exhausting_retry():
    provider = _ScriptedTextProvider(["garbage", "still garbage"])
    with pytest.raises(MalformedResponseError):
        await provider.structured([LLMMessage(role="user", content="go")], _Point)
    assert provider.call_count == 2
