"""ModelManager: provider-independent AI model gateway.

    Adi Agent -> Role Router -> ModelManager -> {anthropic, openai,
    openrouter, ollama, vllm, lmstudio, openai-compatible, mock}
    -> normalized LLMProvider (adi.llm.base.LLMProvider)

Each configured endpoint is a `ProviderProfile`. Profiles are stored in
`.adi/product/providers.json` (project-local) — never with plaintext
secrets; see `adi.product.credentials`. Multiple profiles can coexist
("openrouter-main", "local-qwen", ...) and the active profile can be
switched live without restarting Adi.

Roles (planner/critic/code_analyst/reporter) may each pin a different
profile; unset roles fall back to the active profile. This is what lets
the *existing* `adi.llm.router.build_provider` style role-override concept
extend across arbitrary user-defined profiles instead of only `.adi.yaml`.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from adi.llm.base import LLMError, LLMProvider
from adi.product.credentials import get_secret, set_secret

ProviderKind = Literal[
    "anthropic", "openai", "openrouter", "ollama", "vllm", "lmstudio",
    "openai-compatible", "mock",
]

Locality = Literal["local", "remote"]

_DEFAULT_BASE_URLS: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "ollama": "http://localhost:11434/v1",
    "vllm": "http://localhost:8000/v1",
    "lmstudio": "http://localhost:1234/v1",
}

# Kinds that run on the operator's own machine/network, never a third-party
# vendor — used by privacy routing to decide what may carry source code or
# raw evidence.
_LOCAL_KINDS = {"ollama", "vllm", "lmstudio", "mock"}


class ProviderProfile(BaseModel):
    name: str
    kind: ProviderKind
    base_url: str | None = None
    model: str = ""
    credential_ref: str | None = None  # "keyring" | "env:VAR" | None
    locality: Locality = "remote"

    def resolved_base_url(self) -> str | None:
        return self.base_url or _DEFAULT_BASE_URLS.get(self.kind)


class RoleAssignment(BaseModel):
    planner: str | None = None
    critic: str | None = None
    code_analyst: str | None = None
    reporter: str | None = None


class PrivacyPolicy(BaseModel):
    """Which categories of data may leave the local machine. Checked by
    `ModelManager.provider_for` before any role resolves to a remote
    profile — this is the "never silently fall back from local to remote"
    guarantee required by the product spec."""

    source_code_remote_allowed: bool = False
    raw_evidence_remote_allowed: bool = False
    sanitized_summary_remote_allowed: bool = True
    general_planning_remote_allowed: bool = True


class ProductStore(BaseModel):
    profiles: dict[str, ProviderProfile] = Field(default_factory=dict)
    active_profile: str | None = None
    roles: RoleAssignment = Field(default_factory=RoleAssignment)
    privacy: PrivacyPolicy = Field(default_factory=PrivacyPolicy)


class PrivacyRoutingError(LLMError):
    """Raised when resolving a provider for a given data category would
    violate the configured privacy policy (e.g. sending source code to a
    remote profile while `source_code_remote_allowed` is false)."""


DataCategory = Literal[
    "source_code", "raw_evidence", "sanitized_summary", "general_planning"
]

_CATEGORY_FIELD = {
    "source_code": "source_code_remote_allowed",
    "raw_evidence": "raw_evidence_remote_allowed",
    "sanitized_summary": "sanitized_summary_remote_allowed",
    "general_planning": "general_planning_remote_allowed",
}


def _store_path(project_root: Path | None = None) -> Path:
    root = project_root or Path.cwd()
    directory = root / ".adi" / "product"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "providers.json"


class ModelManager:
    """Loads/saves provider profiles for a project and builds normalized
    `LLMProvider` instances on demand. Switching the active profile or a
    role assignment takes effect on the next `provider_for` call — no
    restart required."""

    def __init__(self, project_root: Path | None = None):
        self.project_root = project_root or Path.cwd()
        self.path = _store_path(self.project_root)
        self.store = self._load()
        self._provider_cache: dict[str, LLMProvider] = {}

    def _load(self) -> ProductStore:
        if self.path.exists():
            try:
                return ProductStore.model_validate_json(self.path.read_text())
            except Exception:
                pass
        return ProductStore()

    def save(self) -> None:
        self.path.write_text(self.store.model_dump_json(indent=2))

    # -- profile management -------------------------------------------------

    def add_profile(self, profile: ProviderProfile, secret: str | None = None) -> None:
        if secret:
            profile.credential_ref = set_secret(profile.name, secret)
        self.store.profiles[profile.name] = profile
        self._provider_cache.pop(profile.name, None)
        if self.store.active_profile is None:
            self.store.active_profile = profile.name
        self.save()

    def remove_profile(self, name: str) -> None:
        self.store.profiles.pop(name, None)
        self._provider_cache.pop(name, None)
        if self.store.active_profile == name:
            self.store.active_profile = next(iter(self.store.profiles), None)
        self.save()

    def list_profiles(self) -> list[ProviderProfile]:
        return list(self.store.profiles.values())

    def set_active(self, name: str) -> None:
        if name not in self.store.profiles:
            raise LLMError(f"no provider profile named '{name}'")
        self.store.active_profile = name
        self.save()

    def active_profile(self) -> ProviderProfile | None:
        if not self.store.active_profile:
            return None
        return self.store.profiles.get(self.store.active_profile)

    def set_role(self, role: str, profile_name: str | None) -> None:
        if profile_name is not None and profile_name not in self.store.profiles:
            raise LLMError(f"no provider profile named '{profile_name}'")
        if not hasattr(self.store.roles, role):
            raise LLMError(f"unknown model role '{role}'")
        setattr(self.store.roles, role, profile_name)
        self.save()

    # -- resolution -----------------------------------------------------

    def profile_for_role(self, role: str) -> ProviderProfile | None:
        name = getattr(self.store.roles, role, None) if hasattr(self.store.roles, role) else None
        if name and name in self.store.profiles:
            return self.store.profiles[name]
        return self.active_profile()

    def provider_for(
        self, role: str = "planner", *, data_category: DataCategory = "general_planning"
    ) -> LLMProvider:
        profile = self.profile_for_role(role)
        if profile is None:
            raise LLMError(
                "no AI provider configured — run first-run setup or 'adi provider add'"
            )
        self._check_privacy(profile, data_category)
        if profile.name not in self._provider_cache:
            self._provider_cache[profile.name] = build_llm_provider(profile)
        return self._provider_cache[profile.name]

    def _check_privacy(self, profile: ProviderProfile, data_category: DataCategory) -> None:
        if profile.locality == "local":
            return
        allowed = getattr(self.store.privacy, _CATEGORY_FIELD[data_category])
        if not allowed:
            raise PrivacyRoutingError(
                f"privacy policy blocks sending '{data_category}' to remote profile "
                f"'{profile.name}'. Configure a local profile for this role, or set "
                f"privacy.{_CATEGORY_FIELD[data_category]}=true explicitly."
            )

    # -- connection testing / discovery ----------------------------------

    async def test_connection(self, profile: ProviderProfile) -> "ConnectionTestResult":
        start = time.monotonic()
        try:
            provider = build_llm_provider(profile)
            from adi.llm.base import LLMMessage

            await provider.complete(
                [LLMMessage(role="user", content="ping")], max_tokens=8
            )
            return ConnectionTestResult(
                ok=True, latency_ms=(time.monotonic() - start) * 1000
            )
        except Exception as exc:
            return ConnectionTestResult(ok=False, error=str(exc))

    async def list_models(self, profile: ProviderProfile) -> list[str]:
        """Best-effort model discovery via the provider's `/models`
        endpoint (OpenAI-compatible shape, used by Ollama/vLLM/LM Studio/
        OpenRouter/OpenAI). Returns [] rather than raising if unsupported
        or unreachable — callers show that as 'unknown', not an error."""
        if profile.kind == "anthropic" or profile.kind == "mock":
            return []
        base_url = profile.resolved_base_url()
        if not base_url:
            return []
        import httpx

        headers = {}
        secret = get_secret(profile.name, profile.credential_ref)
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
        url = base_url.rstrip("/") + "/models"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                body = response.json()
        except Exception:
            return []
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, list):
            return []
        return [item.get("id", "") for item in data if isinstance(item, dict) and item.get("id")]


@dataclass
class ConnectionTestResult:
    ok: bool
    latency_ms: float = 0.0
    error: str | None = None


def build_llm_provider(profile: ProviderProfile) -> LLMProvider:
    """Normalize a `ProviderProfile` into an `LLMProvider`. Provider-
    specific behavior stays inside the adapter classes in `adi.llm.*` —
    this function only chooses which adapter and supplies credentials."""
    secret = get_secret(profile.name, profile.credential_ref)

    if profile.kind == "mock":
        from adi.llm.mock import MockLLM

        return MockLLM(model=profile.model or "mock-model")

    if profile.kind == "anthropic":
        from adi.llm.anthropic import AnthropicProvider

        return AnthropicProvider(api_key=secret or "", model=profile.model or "claude-sonnet-5-5")

    from adi.llm.openai_compatible import OpenAICompatibleProvider

    base_url = profile.resolved_base_url()
    if not base_url:
        raise LLMError(f"provider profile '{profile.name}' has no base_url")
    return OpenAICompatibleProvider(base_url=base_url, api_key=secret or "", model=profile.model)


def default_locality(kind: ProviderKind) -> Locality:
    return "local" if kind in _LOCAL_KINDS else "remote"
