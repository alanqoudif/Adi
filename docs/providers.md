# AI providers

Adi is provider-independent by design — see `adi.product.models.ModelManager`.
Supported provider kinds:

| Kind | Notes |
|---|---|
| `anthropic` | Native Anthropic SDK (`adi.llm.anthropic.AnthropicProvider`) |
| `openai` | OpenAI-compatible HTTP, default base URL `api.openai.com/v1` |
| `openrouter` | OpenAI-compatible HTTP, default base URL `openrouter.ai/api/v1` |
| `ollama` | OpenAI-compatible shim, default `localhost:11434/v1`, no credential required |
| `vllm` | OpenAI-compatible, default `localhost:8000/v1` |
| `lmstudio` | OpenAI-compatible, default `localhost:1234/v1` |
| `openai-compatible` | Any other endpoint exposing `/chat/completions` — custom `base_url` required |
| `mock` | Deterministic, for tests/fixtures only (`adi.llm.mock.MockLLM`) |

Provider-specific behavior stays inside the two adapter classes
(`AnthropicProvider`, `OpenAICompatibleProvider`); `ModelManager.
build_llm_provider()` only chooses which adapter and supplies credentials
— adding a new *kind* that's OpenAI-shaped needs zero new code, just a
default base URL entry.

## Configuring a profile

Interactively, via the first-run wizard (`adi shell`, triggered
automatically when no profile exists) or `/provider`/`/providers` inside
the shell. Programmatically:

```python
from adi.product.models import ModelManager, ProviderProfile

manager = ModelManager(project_root)
manager.add_profile(
    ProviderProfile(name="openrouter-main", kind="openrouter", model="..."),
    secret="sk-...",
)
manager.set_active("openrouter-main")
```

Profiles are stored at `.adi/product/providers.json` (project-local, no
secrets — see [privacy-routing.md](privacy-routing.md) and
credential storage below). Multiple profiles can coexist; switching the
active one or a role assignment takes effect on the next request — no
restart.

## Role routing

```python
manager.set_role("code_analyst", "local-qwen")
```

Unset roles fall back to the active profile. `ProductController._drive`
resolves its LLM via `ModelManager.provider_for(role, data_category=...)`
on every drive cycle, so a role/profile change applies to the *next*
planning step, not just the next assessment.

## Credential storage

Never a plaintext secret in any `.adi` database or session file — only a
`credential_ref`:

- `"keyring"` — resolved from the OS keyring at use time (preferred)
- `"env:VAR_NAME"` — resolved from an environment variable at use time
- `None` — no secret needed (e.g. local Ollama)

When no OS keyring backend is available (headless CI, some sandboxes),
`adi.product.credentials` falls back to a 0600 file under
`~/.config/adi/credential_store.json`. `adi doctor` reports which path is
active.

## Model discovery & connection testing

`ModelManager.list_models(profile)` probes the OpenAI-compatible `/models`
endpoint (works for Ollama/vLLM/LM Studio/OpenRouter/OpenAI); returns `[]`
rather than raising if unsupported/unreachable. `ModelManager.
test_connection(profile)` sends one minimal completion and reports latency
or an error — used by the first-run wizard and `/provider`.

## Provider failure recovery

Two distinct failure points, both non-fatal to the assessment:

1. **Provider cannot be resolved at all** (e.g. a profile is misconfigured
   — missing `base_url`, bad credential): `ModelManager.provider_for()`
   raises `LLMError` *before* the drive loop starts. `ProductController.
   _drive` catches this, emits `MODEL_ERROR`, and leaves state `IDLE`.
2. **The provider resolves but a specific completion/plan call fails**
   (bad response shape, transient network error during planning): this
   is caught *inside* `Orchestrator.run` itself (existing Core behavior,
   unchanged) and surfaced as a `StepOutcome(status="stopped", detail=...)`
   — the controller renders it as a `NOTICE` and returns to `IDLE`. The
   assessment's persisted state (hosts/services/hypotheses/findings) is
   untouched either way.

In both cases the operator can `/provider <other-name>` then `/continue`
— `continue_()` clears the pause gate and `start()` is a no-op if a drive
task is already running, so re-issuing `/continue` after a provider
switch safely restarts the loop against the new profile without
recreating the assessment. See `tests/unit/test_plain_shell.py::
test_provider_failure_then_switch_and_continue` for the exercised path
(case 1); a real-network provider outage was not live-tested in this
sandbox (no outbound network) — see `product-implementation-status.md`.
