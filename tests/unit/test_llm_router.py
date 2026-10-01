import pytest

from adi.config.models import AdiConfig
from adi.llm.router import ProviderNotConfiguredError, build_provider


def test_build_provider_raises_clearly_when_unconfigured(monkeypatch):
    monkeypatch.delenv("ADI_LLM_API_KEY", raising=False)
    monkeypatch.delenv("ADI_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("ADI_LLM_PROVIDER", raising=False)
    with pytest.raises(ProviderNotConfiguredError):
        build_provider(AdiConfig())


def test_build_provider_openai_compatible_requires_base_url(monkeypatch):
    monkeypatch.setenv("ADI_LLM_PROVIDER", "openai-compatible")
    monkeypatch.setenv("ADI_LLM_API_KEY", "sk-test")
    monkeypatch.delenv("ADI_LLM_BASE_URL", raising=False)
    with pytest.raises(ProviderNotConfiguredError):
        build_provider(AdiConfig())


def test_build_provider_openai_compatible_succeeds_with_base_url(monkeypatch):
    monkeypatch.setenv("ADI_LLM_PROVIDER", "openai-compatible")
    monkeypatch.setenv("ADI_LLM_API_KEY", "sk-test")
    monkeypatch.setenv("ADI_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("ADI_LLM_MODEL", "llama3")
    provider = build_provider(AdiConfig())
    assert provider.model == "llama3"
    assert provider.base_url == "http://localhost:11434/v1"
