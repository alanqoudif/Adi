# The Agent Loop (Phase 2)

```
context = ContextBuilder.build(workspace)     # bounded, typed summary
  -> Planner.plan(context)                    # LLM, returns one PlannedAction
  -> ScopeEngine.authorize(action)            # inside ToolExecutor.run for run_tool
       blocked -> record + loop (replan with updated context)
       allowed -> execute (ExecutionRuntime)
                  -> parse (tool skill's deterministic parser.py)
                  -> Workspace.record_observations(...)
  -> HypothesisEngine (for update_hypothesis / investigate_hypothesis actions)
  -> ActionBudget records the attempt/outcome, checks loop-prevention limits
  -> repeat, until COMPLETE / ASK_USER / budget exhausted / too many
     consecutive failures / planner or provider failure
```

`adi.agent.orchestrator.Orchestrator.run()` is the only place this sequence
is implemented — see `tests/integration/test_agent_loop_integration.py` for
a test that exercises every arrow in the diagram above with the real tool
registry, the real nmap parser, and the real `Workspace`, mocking only the
LLM and the process-execution runtime.

## Observation vs. hypothesis vs. finding

- **Observation** (`adi.knowledge.observations.Observation`): a raw,
  falsifiable fact from a deterministic parser. "Port 80 is open." Never a
  vulnerability by itself.
- **Hypothesis** (`adi.knowledge.hypotheses.Hypothesis`): an explicit,
  falsifiable claim the agent is investigating — "possible broken
  object-level authorization on `/api/orders/:id`." Created and transitioned
  only through `adi.agent.reasoner.HypothesisEngine`, which enforces the
  state machine (`new -> investigating -> {supported, confirmed, rejected,
  blocked, duplicate}`, with `confirmed`/`rejected`/`duplicate` terminal). A
  rejected hypothesis is not a failure — it is evidence the agent is
  actually validating things rather than reporting every scanner alert.
- **Finding**: introduced in Phase 4 (`FindingVerifier`), the only path to a
  `confirmed` status. Not implemented yet — the `FindingRecord` schema
  already exists (Phase 1) so no migration is needed when it lands.

## Why the planner never sees the whole database

`ContextBuilder.build()` (`adi.agent.context_builder`) caps what reaches the
LLM: the goal, scope summary, discovered assets (host + open ports only),
active hypotheses, rejected-hypothesis titles (so the agent doesn't
re-investigate them), the last 10 actions, the last 20 observation
summaries, the remaining action budget, and the capabilities currently
available from the tool registry. `PlanningContext.render()` is a pure,
deterministic function of that typed object — there is no hidden
prompt-engineering state outside it.

## Explainability

Every `PlannedAction` carries `reason_summary` and
`expected_information_gain`, required fields the LLM must fill in — these
are what `adi lab ... --autonomous` prints for each step, and what a future
`/why` command would read back from the action audit trail
(`adi.knowledge.db.ActionRecord.reason_summary`). Nothing here exposes
hidden chain-of-thought; it is a concise, after-the-fact justification tied
to an actual action that was actually taken.

## Loop prevention

`adi.agent.scheduler.ActionBudget`:
- `fingerprint(action)` hashes `(action_type, tool, target, capability,
  parameters)` — reasoning text never affects the fingerprint, so two
  requests for the same action with different justifications are still
  recognized as the same action.
- A fingerprint that already **succeeded** is a duplicate — skipped without
  re-execution.
- A fingerprint is retried up to `max_retries_per_action` (default 2) if it
  keeps failing, then skipped.
- `max_actions` (from `Scope.max_actions`) hard-stops the assessment.
- `max_consecutive_failures` (from `Scope.max_consecutive_failures`)
  hard-stops it if nothing is succeeding, independent of the total budget.

## What Phase 2 does not implement yet

- `ActionType.HTTP_REQUEST`, `BROWSER_ACTION`, `READ_FILE`, `SEARCH_CODE`,
  `LOAD_SKILL`, `VERIFY_FINDING`, `GENERATE_REPORT` are valid schema values
  the planner may emit, but the orchestrator records them as `unsupported`
  and reports a `failed` outcome rather than executing them — these land in
  Phases 3–5 as the corresponding capabilities are built.
- Only one tool skill (`nmap`) exists, so `enumerate_services` is the only
  capability an autonomous assessment can actually act on today.
- Model routing (`.adi.yaml`'s `models.planner/analysis/critic/report`)
  exists in config but the orchestrator only ever asks for the `planner`
  role — `analysis`/`critic`/`report` roles are wired for Phase 4's critic
  pass and Phase 4/5 reporting.
