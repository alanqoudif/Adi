# Expert / command console

`adi.product.console.ExpertConsole` is the reviewed manual-execution
path. It is *not* a second execution engine — `preview()` only describes
what `ToolExecutor.run_capability`/`run` would do, and `execute()` calls
those same Core methods. There is exactly one execution path in Adi,
autonomous or manual.

```
operator: /run enumerate_services 127.0.0.1 ports=1-1024
  -> ExpertConsole.preview("enumerate_services", "127.0.0.1", {"ports": "1-1024"})
       -> ToolRegistry.ranked(capability)       # candidate tools, ranked
       -> ScopeEngine.authorize(PlannedAction)   # same check autonomy uses
       -> CommandPreview (sanitized: no secrets, no raw shell string)
  -> shell prints preview, asks "Execute? [Approve once/Reject] (y/N)"
  -> on yes: ExpertConsole.execute(...)
       -> ToolExecutor.run_capability(...)       # identical to the
                                                   # autonomous dispatch path
       -> ScopeViolationError / ToolExecutionError surfaced as-is
```

## What the preview shows

Capability, target, candidate tools (ranked by the existing
`ToolRegistry`/`CapabilityResolver` fallback order), runtime, risk level,
rate limit, sanitized parameters, and the `ScopeEngine` decision —
exactly the same information `adi capability <name>`/`adi tools` expose
via the CLI, reused rather than reimplemented
(`ExpertConsole.list_tools/describe_tool/list_capabilities/
describe_capability` call straight into `ToolRegistry`).

## Approval

Core's `ScopeEngine` has exactly one elevated-approval mechanism today:
`Scope.approval_mode` + `Scope.approved_elevated_actions` (keyed
`"capability:target"`), used for `audit_credentials`. `ExpertConsole.
execute(..., grant_elevated_approval=True)` sets that flag and appends
the key — but only *after* the operator has already seen the preview and
typed "y" — then calls `execute()`, then **revokes the grant again
immediately after use** ("approve once"), regardless of success or
failure (`finally` block). A `RiskLevel.HIGH`/`PROHIBITED` action is
hard-blocked by `ScopeEngine` with no override — the console reports that
rejection, it does not attempt to work around it.

## `/tool-run` vs `/run`

`/run <capability> <target>` lets Core pick the best available tool for
that capability (same resolution autonomy uses). `/tool-run <tool>
<target>` pins a specific tool; the console still previews/executes via
the tool's own declared capability so the same scope/risk check applies
— there is no "raw tool, no capability" bypass.

## Tool/capability browser

`/tools`, `/tool <name>`, `/capabilities`, `/capability <name>` read
live from `ToolRegistry` — availability, runtime, version, risk, trust,
fallback order — never from static documentation that could drift from
reality.
