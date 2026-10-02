# Privacy routing

Every provider profile is marked `locality: "local"` or `"remote"`
(`adi.product.models.ProviderProfile.locality`; `default_locality()`
marks `ollama`/`vllm`/`lmstudio`/`mock` local, everything else remote by
default — overridable per profile).

Four data categories gate what may reach a remote profile
(`PrivacyPolicy` in `adi.product.models`):

| Category | Default |
|---|---|
| `source_code` | remote **blocked** |
| `raw_evidence` | remote **blocked** |
| `sanitized_summary` | remote allowed |
| `general_planning` | remote allowed |

`ModelManager.provider_for(role, data_category=...)` checks the resolved
profile's locality against the policy *before* returning a provider — a
local profile always passes; a remote profile raises
`PrivacyRoutingError` unless the matching policy flag is explicitly
`True`. There is no fallback path from a blocked remote call to a
different (looser) policy or profile — the caller gets the error and
must either configure a local profile for that role or explicitly change
the policy. **Adi never silently falls back from local to remote and
transmits data** — that path does not exist in the code.

```python
manager.provider_for("code_analyst", data_category="source_code")
# raises PrivacyRoutingError unless code_analyst resolves to a local
# profile, or privacy.source_code_remote_allowed is explicitly set True
```

See `tests/unit/test_security_regression.py::
test_privacy_routing_cannot_be_bypassed_by_role_name` for the regression
proof that this can't be routed around by role name, and
`tests/unit/test_product_controller.py::
test_model_manager_privacy_routing_blocks_remote_source` for the basic
behavior test.

## Where this is enforced today

`ProductController._drive` calls `provider_for("planner",
data_category="general_planning")` — the autonomous planning loop never
sends raw source or raw evidence to the model; source/evidence context
that reaches the planner already goes through `ContextBuilder`'s existing
bounded/sanitized context assembly (Core, unchanged). A dedicated
`code_analyst` role with `data_category="source_code"` is wired in
`ModelManager` but not yet called from a source-specific agent step — see
`product-implementation-status.md` for that remaining item.
