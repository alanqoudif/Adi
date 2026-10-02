"""Native Anthropic messages adapter, using the shared HTTP dependency."""
from __future__ import annotations

import httpx

from adi.llm.base import LLMError, LLMMessage, LLMProvider
from adi.llm.errors import provider_error
from adi.reporting.redaction import redact_text


class AnthropicProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = '', base_url: str = 'https://api.anthropic.com/v1'):
        if not api_key:
            raise LLMError('API key is required for Anthropic')
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')

    async def complete(self, messages: list[LLMMessage], *, max_tokens: int = 1024) -> str:
        payload = {
            'model': self.model, 'max_tokens': max_tokens,
            'messages': [{'role': m.role, 'content': m.content} for m in messages if m.role != 'system'],
        }
        system = '\n'.join(m.content for m in messages if m.role == 'system')
        if system:
            payload['system'] = system
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    self.base_url + '/messages', json=payload,
                    headers={'x-api-key': self.api_key, 'anthropic-version': '2023-06-01'},
                )
                response.raise_for_status()
                body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise LLMError(provider_error(exc)) from None
        try:
            content = ''.join(b['text'] for b in body['content'] if b.get('type') == 'text')
            if not content.strip():
                raise ValueError('empty response')
            return redact_text(content, (self.api_key,))
        except (KeyError, TypeError, ValueError):
            raise LLMError('Provider returned malformed response') from None
