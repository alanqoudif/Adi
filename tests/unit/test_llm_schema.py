import pytest
from pydantic import ValidationError

from adi.actions import ActionType, PlannedAction, RiskLevel


def test_planned_action_valid():
    action = PlannedAction(
        action_type=ActionType.RUN_TOOL,
        capability="enumerate_services",
        reason_summary="No service knowledge yet for this host.",
        expected_information_gain="High — establishes the attack surface.",
        target="10.10.10.15",
        tool="nmap",
        parameters={"ports": "1-1024"},
        risk=RiskLevel.LOW,
    )
    assert action.action_type == ActionType.RUN_TOOL
    assert action.tool == "nmap"


def test_planned_action_rejects_invalid_action_type():
    with pytest.raises(ValidationError):
        PlannedAction.model_validate({"action_type": "delete_everything", "target": "x"})


def test_planned_action_defaults_are_safe():
    action = PlannedAction(action_type=ActionType.COMPLETE)
    assert action.risk == RiskLevel.LOW
    assert action.parameters == {}
    assert action.target is None


def test_planned_action_from_json_round_trip():
    raw = '{"action_type": "run_tool", "capability": "enumerate_services", ' \
          '"target": "lab.local", "tool": "nmap", "parameters": {}, ' \
          '"reason_summary": "x", "expected_information_gain": "y"}'
    action = PlannedAction.model_validate_json(raw)
    assert action.tool == "nmap"
    assert action.target == "lab.local"
