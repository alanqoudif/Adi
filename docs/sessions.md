# Sessions

`adi.product.sessions.SessionRegistry` maps a short, human-readable name
(e.g. `orders-api`) to the underlying `Assessment` id, stored at
`.adi/product/sessions.json` (project-local). You should never need to
type or remember an `assess-<hex>` id directly — `/sessions`,
`/resume <name>`, and `/new <target>` (which auto-derives a name from the
target, de-duplicating with a numeric suffix) are the normal interface.

## Auto-resume

On `adi shell` startup, `ProductController.auto_resume_candidate()`
returns the most-recently-active session (if any); the shell prints a
one-line nudge ("Recent session 'orders-api' ... type '/resume
orders-api'") rather than resuming automatically — resuming is always an
explicit action, never implicit, so the operator always knows which
assessment (and which authorized scope) they're continuing.

## What's persisted vs. not

Persisted (authoritative, survives restart): the session name→assessment
id mapping, target, model name, timestamps — plus everything the existing
Core workspace already persists (scope, hosts/services/endpoints,
hypotheses, findings, evidence, actions). **Not** persisted: hidden model
reasoning/chain-of-thought, raw conversational turns beyond what Core's
`ActionRecord`/`reason_summary` already stores. The structured assessment
state in the Core workspace remains the single source of truth for
anything the Product layer displays — `/status`, `/findings`,
`/evidence`, etc. all read it live, not a cached session snapshot.

## Crash recovery

`Workspace.mark_interrupted_actions()` is called on every
`ProductController.resume_assessment()`: any `ActionRecord` still in
status `planned` (dispatched but never reached `update_action_result`
because the process died first) is marked `interrupted`, and if the
assessment's own status was left as `running`, it flips to `interrupted`
too. The operator is notified via a `NOTICE` event listing how many
actions were affected. Resume never assumes an in-flight action
succeeded — see `tests/unit/test_crash_recovery.py`.
