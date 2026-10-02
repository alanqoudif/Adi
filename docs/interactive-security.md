# Interactive security workflow

## Natural language → structured intent, never raw shell

Chat in the Product Shell never becomes a shell command. The only two
things free-form text can do:

1. **Narrow the assessment's goal** (`ProductController.set_goal`) — a
   hint fed into the existing `ContextBuilder`/`Planner`, which still
   proposes a typed `PlannedAction` (capability, not a tool name, let
   alone a shell string) that still goes through `ScopeEngine.authorize`
   before anything runs.
2. **Propose an explicit, confirmed scope change** via
   `adi.product.nlu.interpret_scope_command` — a small *deterministic*
   regex matcher (not an LLM call), so scope changes stay reproducible,
   auditable, and immune to prompt injection from tool/HTTP output. It
   only ever returns a `ScopeProposal`; the shell always asks "Apply this
   scope change? [y/N]" before `ProductController.update_scope_fields`
   is ever called. See `test_plain_shell_chat_scope_proposal_requires_
   explicit_yes` in `tests/unit/test_security_regression.py`.

There is no third path: chat cannot invoke a tool, run a capability, or
touch scope on its own initiative. Direct tool/capability invocation is a
*separate*, explicitly-typed interface — see [expert-mode.md](expert-mode.md).

## The autonomous loop, narrated

```
user message → ProductController.set_goal (or scope proposal + confirm)
             → ProductController.start()
             → Assessment.build_orchestrator(llm)
             → loop: Orchestrator.run(max_iterations=1)
                 → Planner.plan(context) -> PlannedAction
                 → ScopeEngine.authorize(...)
                 → ToolExecutor.run/run_capability (if allowed)
                 → deterministic parser -> Observations -> Evidence
                 → HypothesisEngine / ValidationEngine / FindingPipeline
             → StepOutcome -> typed Event on the EventBus
             → UI renders the event
```

`ProductController` adds no new execution path on top of this — it only
calls `Orchestrator.run(max_iterations=1)` repeatedly (so it can check
pause/stop between actions) and turns each `StepOutcome` into an `Event`.
See `adi.product.controller.ProductController._drive`.

## Pause / continue / stop

- `/pause` clears an `asyncio.Event` the drive loop awaits between
  actions — no new action is dispatched, but Core state is never torn
  down.
- `/continue` sets it again and, if the drive task already finished
  (e.g. after a provider failure), restarts it with `start()` (a no-op
  if a task is already running).
- `/stop` sets a stop flag, lets the current in-flight action finish,
  marks the assessment status `stopped`, and awaits the drive task to
  completion — it does not kill a running tool process mid-syscall;
  Core's own runtime layer (`ToolExecutor`/`ExecutionRuntime`) owns
  process lifecycle and timeout handling, unchanged.

## Why this and not "the model executes a shell command"

See the `security-review` section of
`product-implementation-status.md` and
`tests/unit/test_security_regression.py::
test_planned_action_schema_has_no_raw_shell_field` — the model's output
schema (`PlannedAction`) structurally has no field a shell string could
occupy.
