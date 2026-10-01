"""Resolves an `LLMProvider` from environment variables (primary) or
`.adi.yaml` (fallback), without the orchestrator ever importing a specific
SDK directly.

Environment variables:
    ADI_LLM_PROVIDER   "anthropic" | "openai-compatible"  (default: anthropic)
    ADI_LLM_BASE_URL   required for openai-compatible (OpenRouter, local, ...)
    ADI_LLM_API_KEY    provider API key
    ADI_LLM_MODEL      model name
"""

from __future__ import annotations

import os

from adi.config.models import AdiConfig, LLMProviderConfig
from adi.llm.base import LLMError, LLMProvider


class ProviderNotConfiguredError(LLMError):
    """Raised when no usable LLM provider configuration exists. Callers
    (e.g. `adi doctor`, `adi lab --autonomous`) must surface this plainly
    rather than silently falling back to fake planning."""


def is_configured() -> bool:
    return bool(os.environ.get("ADI_LLM_API_KEY")) or bool(
        os.environ.get("ADI_LLM_BASE_URL")
    )


def build_provider(config: AdiConfig | None = None, role: str = "planner") -> LLMProvider:
    """Build the provider for a given model-routing role. Phase 2 routes all
    roles to the same provider unless `.adi.yaml` overrides that role."""
    role_config = _role_override(config, role)

    provider_type = os.environ.get("ADI_LLM_PROVIDER") or (
        role_config.type if role_config else None
    ) or "anthropic"
    base_url = os.environ.get("ADI_LLM_BASE_URL") or (
        role_config.base_url if role_config else None
    )
    api_key = os.environ.get("ADI_LLM_API_KEY") or (
        os.environ.get(role_config.api_key_env) if role_config else None
    )
    model = os.environ.get("ADI_LLM_MODEL") or (
        role_config.model if role_config else None
    ) or "claude-sonnet-5-5"

    if not api_key and not base_url:
        raise ProviderNotConfiguredError(
            "no LLM provider is configured — set ADI_LLM_API_KEY (and ADI_LLM_PROVIDER / "
            "ADI_LLM_BASE_URL / ADI_LLM_MODEL as needed). Deterministic tool execution "
            "('adi run-tool') works without this; autonomous planning does not."
        )

    if provider_type == "anthropic":
        from adi.llm.anthropic import AnthropicProvider

        return AnthropicProvider(api_key=api_key or "", model=model)

    from adi.llm.openai_compatible import OpenAICompatibleProvider

    if not base_url:
        raise ProviderNotConfiguredError(
            "ADI_LLM_PROVIDER=openai-compatible requires ADI_LLM_BASE_URL "
            "(e.g. an OpenRouter or local inference endpoint)"
        )
    return OpenAICompatibleProvider(base_url=base_url, api_key=api_key or "", model=model)


def _role_override(config: AdiConfig | None, role: str) -> LLMProviderConfig | None:
    if config is None:
        return None
    return getattr(config.models, role, None) or config.provider
