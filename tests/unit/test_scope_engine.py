from adi.actions import ActionType, PlannedAction, RiskLevel
from adi.scope.engine import ScopeEngine
from adi.scope.models import Permissions, Scope


def make_scope(**overrides) -> Scope:
    defaults = {"name": "test", "targets": ["lab.local"], "allowed_ips": ["10.10.10.0/24"]}
    defaults.update(overrides)
    return Scope(**defaults)


def test_in_scope_hostname_allowed():
    engine = ScopeEngine(make_scope())
    action = PlannedAction(action_type=ActionType.RUN_TOOL, target="lab.local", capability="discover_hosts")
    decision = engine.authorize(action)
    assert decision.allowed


def test_subdomain_of_target_allowed():
    engine = ScopeEngine(make_scope())
    action = PlannedAction(action_type=ActionType.RUN_TOOL, target="api.lab.local", capability="discover_hosts")
    assert engine.authorize(action).allowed


def test_out_of_scope_host_blocked():
    engine = ScopeEngine(make_scope())
    action = PlannedAction(action_type=ActionType.RUN_TOOL, target="evil.example.com", capability="discover_hosts")
    decision = engine.authorize(action)
    assert not decision.allowed
    assert "not within the authorized scope" in decision.reason


def test_ip_in_cidr_allowed():
    engine = ScopeEngine(make_scope())
    action = PlannedAction(action_type=ActionType.RUN_TOOL, target="10.10.10.15", capability="discover_hosts")
    assert engine.authorize(action).allowed


def test_ip_outside_cidr_blocked():
    engine = ScopeEngine(make_scope())
    action = PlannedAction(action_type=ActionType.RUN_TOOL, target="10.20.20.20", capability="discover_hosts")
    assert not engine.authorize(action).allowed


def test_excluded_host_blocked_even_if_subdomain():
    engine = ScopeEngine(make_scope(excluded_hosts=["db.lab.local"]))
    action = PlannedAction(action_type=ActionType.RUN_TOOL, target="db.lab.local", capability="discover_hosts")
    assert not engine.authorize(action).allowed


def test_authentication_testing_blocked_by_default():
    engine = ScopeEngine(make_scope())
    action = PlannedAction(
        action_type=ActionType.RUN_TOOL, target="lab.local",
        capability="credential_audit", tool="hydra",
    )
    decision = engine.authorize(action)
    assert not decision.allowed
    assert "authentication_testing" in decision.reason


def test_authentication_testing_allowed_when_enabled():
    scope = make_scope(permissions=Permissions(authentication_testing=True))
    engine = ScopeEngine(scope)
    action = PlannedAction(
        action_type=ActionType.RUN_TOOL, target="lab.local",
        capability="credential_audit", tool="hydra",
    )
    assert engine.authorize(action).allowed


def test_high_risk_action_always_blocked():
    engine = ScopeEngine(make_scope())
    action = PlannedAction(
        action_type=ActionType.RUN_TOOL, target="lab.local",
        capability="discover_hosts", risk=RiskLevel.HIGH,
    )
    assert not engine.authorize(action).allowed


def test_internal_actions_never_blocked_by_host():
    engine = ScopeEngine(make_scope())
    action = PlannedAction(action_type=ActionType.GENERATE_REPORT, target=None)
    assert engine.authorize(action).allowed


def test_url_target_host_extracted():
    engine = ScopeEngine(make_scope())
    action = PlannedAction(
        action_type=ActionType.HTTP_REQUEST, target="https://lab.local/admin",
        capability="web_probe",
    )
    assert engine.authorize(action).allowed

    action2 = PlannedAction(
        action_type=ActionType.HTTP_REQUEST, target="https://evil.com/admin",
        capability="web_probe",
    )
    assert not engine.authorize(action2).allowed
