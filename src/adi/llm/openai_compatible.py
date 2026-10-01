"""OpenAI-compatible chat-completions provider.

This single implementation covers OpenAI itself, OpenRouter, and any local
inference server (vLLM, Ollama's OpenAI shim, LM Studio, ...) that exposes
the `/chat/completions` endpoint shape — only `base_url` changes.
"""

from __future__ import annotations

import httpx

from adi.llm.base import LLMError, LLMMessage, LLMProvider


class OpenAICompatibleProvider(LLMProvider):
    def __init__(self, base_url: str, api_key: str, model: str):
        if not base_url:
            raise LLMError("no base_url provided for the OpenAI-compatible provider")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model

    def _endpoint(self) -> str:
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return f"{self.base_url}/chat/completions"

    async def complete(self, messages: list[LLMMessage], *, max_tokens: int = 1024) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": max_tokens,
        }
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(self._endpoint(), json=payload, headers=headers)
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            raise LLMError(f"OpenAI-compatible API call failed: {exc}") from exc
        try:
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise LLMError(f"unexpected response shape from provider: {body}") from exc
