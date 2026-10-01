"""Configuration schema for `.adi.yaml`."""

from __future__ import annotations

from pydantic import BaseModel, Field


class LLMProviderConfig(BaseModel):
    type: str = "anthropic"  # anthropic | openai-compatible
    base_url: str | None = None
    api_key_env: str = "ADI_LLM_API_KEY"
    model: str = "claude-sonnet-5-5"


class ModelRoutingConfig(BaseModel):
    planner: LLMProviderConfig | None = None
    analysis: LLMProviderConfig | None = None
    critic: LLMProviderConfig | None = None
    report: LLMProviderConfig | None = None


class RuntimeConfig(BaseModel):
    type: str = "docker"  # docker | local | mock
    image: str = "adi-kali:latest"
    allow_local: bool = False


class ExecutionConfig(BaseModel):
    concurrent_tools: int = 2


class UIConfig(BaseModel):
    show_reason_summaries: bool = True
    verbose_tool_output: bool = False


class AgentConfig(BaseModel):
    max_actions: int = 150
    max_consecutive_failures: int = 5


class AdiConfig(BaseModel):
    provider: LLMProviderConfig = Field(default_factory=LLMProviderConfig)
    models: ModelRoutingConfig = Field(default_factory=ModelRoutingConfig)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
