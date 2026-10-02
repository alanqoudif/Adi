from adi.actions import ActionType, PlannedAction
from adi.agent.scheduler import ActionBudget, fingerprint


def make_action(**overrides) -> PlannedAction:
    defaults = {"action_type": ActionType.RUN_TOOL, "tool": "nmap", "target": "lab.local",
                     "capability": "enumerate_services", "parameters": {}}
    defaults.update(overrides)
    return PlannedAction(**defaults)


def test_fingerprint_is_stable_and_ignores_reasoning_text():
    a1 = make_action(reason_summary="because X")
    a2 = make_action(reason_summary="because Y, totally different reasoning")
    assert fingerprint(a1) == fingerprint(a2)


def test_fingerprint_differs_on_parameters():
    a1 = make_action(parameters={"ports": "80"})
    a2 = make_action(parameters={"ports": "443"})
    assert fingerprint(a1) != fingerprint(a2)


def test_budget_exhaustion():
    budget = ActionBudget(max_actions=2)
    assert not budget.exhausted()
    budget.record_attempt(make_action())
    assert not budget.exhausted()
    budget.record_attempt(make_action(target="other.local"))
    assert budget.exhausted()


def test_consecutive_failure_tracking_and_reset():
    budget = ActionBudget(max_consecutive_failures=3)
    action = make_action()
    budget.record_outcome(action, succeeded=False)
    budget.record_outcome(action, succeeded=False)
    assert not budget.too_many_consecutive_failures()
    budget.record_outcome(action, succeeded=False)
    assert budget.too_many_consecutive_failures()

    budget.record_outcome(action, succeeded=True)
    assert budget.consecutive_failures == 0
    assert not budget.too_many_consecutive_failures()


def test_duplicate_detection_only_after_success():
    budget = ActionBudget()
    action = make_action()
    assert not budget.is_duplicate(action)
    budget.record_outcome(action, succeeded=False)
    assert not budget.is_duplicate(action)  # a failed attempt isn't "done", retry is allowed
    budget.record_outcome(action, succeeded=True)
    assert budget.is_duplicate(action)


def test_retry_limit_reached():
    budget = ActionBudget(max_retries_per_action=2)
    action = make_action()
    assert not budget.retry_limit_reached(action)
    budget.record_attempt(action)
    assert not budget.retry_limit_reached(action)
    budget.record_attempt(action)
    assert budget.retry_limit_reached(action)
