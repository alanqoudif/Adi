# Configuration

## Layers

| Layer | Location | Contains |
|---|---|---|
| Core/`.adi.yaml` | project root | runtime type, LLM provider env-var routing, agent budgets, UI flags (`adi.config.models.AdiConfig`) — unchanged by the Product layer |
| Product providers | `.adi/product/providers.json` | provider profiles, active profile, role assignments, privacy policy (`adi.product.models.ProductStore`) — never a plaintext secret |
| Product sessions | `.adi/product/sessions.json` | human-readable session name → assessment id (`adi.product.sessions.SessionStore`) |
| Credentials | OS keyring (preferred) or `~/.config/adi/credential_store.json` (0600 fallback) | the one place an actual secret value lives |

All three Product-layer files are project-local and `.gitignore`-able;
none of them ever contains an API key, password, or token — only a
`credential_ref`.

## `.adi.yaml` (Core, unchanged)

```yaml
runtime:
  type: mock | local | docker
  allow_local: true   # required to opt into unsandboxed local execution
provider:
  type: anthropic | openai-compatible
  model: claude-sonnet-5-5
```

See `adi.config.models.AdiConfig` for the full schema; this file predates
the Product layer and is read the same way by both the scripted CLI and
`ProductController` (via `Assessment.create`/`.resume`).

## Effective-value inspection

Not yet implemented as a single `/settings` view showing origin
(assessment vs. project vs. global vs. default) per the full spec — today
`/scope`, `/providers`, and `adi doctor`'s "Product Shell" section each
show their own slice of effective configuration. See
`product-implementation-status.md` for this as a remaining item.

## Environment variables

`ADI_LLM_PROVIDER`, `ADI_LLM_BASE_URL`, `ADI_LLM_API_KEY`, `ADI_LLM_MODEL`
(Core's own env-var routing, see `adi.llm.router`) remain fully
functional and independent of Product-layer provider profiles — a
scripted `adi lab ...`/`adi assess` invocation that never touches
`adi shell` is unaffected by anything in this directory.
`ADI_CONFIG_HOME` overrides the credential-fallback-store directory
(default `~/.config/adi`). `NO_COLOR` disables ANSI color in the plain
shell.
