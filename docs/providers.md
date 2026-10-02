# AI providers

Adi is provider-independent by design — see `adi.product.models.ModelManager`.
Supported provider kinds:

| Kind | Notes |
|---|---|
| `anthropic` | Native Anthropic Messages HTTP (`AnthropicProvider`); no optional SDK install needed |
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

Launch `adi` or `adi shell`. In the TUI, run `/provider add` or select
**Add AI Provider** with Ctrl+P. Plain mode runs the same wizard on first
launch. You may skip setup and continue without AI.

1. Choose a provider and a profile name.
2. Local/custom endpoints offer an editable base URL. OpenRouter supplies
   `https://openrouter.ai/api/v1` automatically; no endpoint knowledge needed.
   Ollama tries `http://localhost:11434/v1`, requires no key, and discovers
   installed models. LM Studio defaults to port 1234 and vLLM to port 8000.
3. Enter a masked API key for remote providers. Local/custom keys are optional.
   Editing with a blank key keeps the existing credential.
4. Select a discovered model by number or enter its ID. There is no small
   hardcoded catalog; Anthropic pagination is followed as well.
5. Test the connection (default Yes): a real minimal completion must produce
   a nonempty, correctly shaped response. Authentication, connectivity,
   timeouts, rate/quota limits and malformed responses get sanitized errors.
   A failed test leaves the previous configuration and credentials untouched.
   Explicitly skipping testing is allowed and labelled unverified.
6. Save and activate; the status panel updates immediately.

Use `/provider edit <name>`, `/provider remove <name>`, `/provider test <name>`,
`/provider <name>`, `/providers`, `/models`, and `/model <id>` to manage profiles
and models without restarting. `/cancel` exits a TUI setup prompt.

### CLI and scripts

```bash
adi provider add                    # interactive setup, masked key entry
adi providers                       # alias for provider list
adi provider list
adi provider show openrouter
adi provider test openrouter
adi provider use openrouter
adi provider edit openrouter         # interactive edit
adi provider edit local --model installed-model
adi provider remove openrouter
adi models                          # alias for model list
adi model list
adi model show
adi model use model-id

# Local scriptable setup: tests before saving, no key needed
adi provider add local --kind ollama --model installed-model
adi provider add private --kind openai-compatible \
  --base-url http://127.0.0.1:8000/v1 --model private-model

# Credential comes from the script's secret environment, never argv.
# No need to create/edit an .env file.
adi provider add router --kind openrouter --model model-id --key-env ROUTER_KEY
```

`--no-test` explicitly saves unverified configuration; connection tests are
on by default. `provider edit` accepts `--base-url`, `--model`, and `--key-env`
for scripts. Show/list commands never retrieve or print a stored key.

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

`ModelManager.list_models(profile)` probes `/models`
(works for Ollama/vLLM/LM Studio/OpenRouter/OpenAI and native Anthropic); returns `[]`
rather than raising if unsupported/unreachable. `ModelManager.
test_connection(profile)` sends one minimal completion and reports latency
or a sanitized error — used by setup, `/provider test`, and the CLI.
Errors never propagate response bodies, credential-bearing URLs, or headers;
known provider keys are also redacted from response text before structured
planning, persistence, reports, crash recovery or TUI events. The fallback
credential file is replaced atomically with mode 0600.

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
