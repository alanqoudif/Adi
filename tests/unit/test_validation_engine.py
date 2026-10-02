"""Unit-level exercise of the ValidationEngine + validators against the
real local demo app (not mocked HTTP) — proves the validators answer the
right security question for scenarios A–G in the Phase 4 test lab."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures" / "webapp"))
from app import DemoApp

from adi.evidence.store import EvidenceStore
from adi.http.client import HTTPClient
from adi.http.sessions import SessionJarRegistry
from adi.http.workspace import HTTPWorkspace
from adi.knowledge.hypotheses import HypothesisStatus
from adi.knowledge.workspace import Workspace
from adi.scope.engine import ScopeEngine
from adi.scope.models import Scope
from adi.validation.context import ValidationContext
from adi.validation.engine import (
    HypothesisAlreadyResolvedError,
    ValidationBudgetExhaustedError,
    ValidationEngine,
)
from adi.validation.models import ValidationAction, ValidationActionType, ValidationOutcome
from adi.validation.policies import ValidationBudget


@pytest.fixture()
def demo_app():
    app = DemoApp().start()
    yield app
    app.stop()


def build_engine(tmp_path, scope_targets=("127.0.0.1",), max_actions_per_hypothesis=8):
    scope = Scope(name="validation-test", targets=list(scope_targets))
    workspace = Workspace.create(tmp_path / "state.db", scope)
    scope_engine = ScopeEngine(scope)
    http_client = HTTPClient(scope_engine, SessionJarRegistry())
    http_ws = HTTPWorkspace(http_client, workspace, tmp_path / "evidence")
    ctx = ValidationContext(http_ws, EvidenceStore(workspace), workspace)
    engine = ValidationEngine(ctx, ValidationBudget(max_actions_per_hypothesis=max_actions_per_hypothesis))
    return engine, workspace, http_ws


async def _login(http_ws, base, username):
    await http_ws.fetch("POST", base + "/api/login", session_id=username, body=f"username={username}")


@pytest.mark.asyncio
async def test_broken_object_authorization_is_confirmed_by_validator(tmp_path, demo_app):
    engine, workspace, http_ws = build_engine(tmp_path)
    await _login(http_ws, demo_app.base_url, "user_a")
    await _login(http_ws, demo_app.base_url, "user_b")

    hyp = engine.hypothesis_engine.create(title="possible broken object authorization on /api/orders-broken/1")
    result = await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/api/orders-broken/1",
                    "owner_session": "user_a", "other_session": "user_b"},
    ))

    assert result.outcome == ValidationOutcome.SUPPORTS
    updated = engine.hypothesis_engine.get(hyp.id)
    assert updated.status == HypothesisStatus.SUPPORTED
    assert len(updated.supporting_observation_ids) == 1


@pytest.mark.asyncio
async def test_safe_object_authorization_is_rejected_by_validator(tmp_path, demo_app):
    engine, workspace, http_ws = build_engine(tmp_path)
    await _login(http_ws, demo_app.base_url, "user_a")
    await _login(http_ws, demo_app.base_url, "user_b")

    hyp = engine.hypothesis_engine.create(title="possible broken object authorization on /api/orders-safe/1")
    result = await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/api/orders-safe/1",
                    "owner_session": "user_a", "other_session": "user_b"},
    ))

    assert result.outcome == ValidationOutcome.REFUTES
    updated = engine.hypothesis_engine.get(hyp.id)
    assert updated.status == HypothesisStatus.INVESTIGATING  # not promoted
    assert len(updated.contradicting_observation_ids) == 1


@pytest.mark.asyncio
async def test_broken_authentication_boundary_detected(tmp_path, demo_app):
    engine, workspace, http_ws = build_engine(tmp_path)
    hyp = engine.hypothesis_engine.create(title="possible missing authentication on /api/leaky-profile")
    result = await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_AUTH_BOUNDARY, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/api/leaky-profile"},
    ))
    assert result.outcome == ValidationOutcome.SUPPORTS


@pytest.mark.asyncio
async def test_correct_authentication_boundary_rejected(tmp_path, demo_app):
    engine, workspace, http_ws = build_engine(tmp_path)
    hyp = engine.hypothesis_engine.create(title="possible missing authentication on /api/private")
    result = await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_AUTH_BOUNDARY, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/api/private"},
    ))
    assert result.outcome == ValidationOutcome.REFUTES


@pytest.mark.asyncio
async def test_cookie_hardening_issue_detected(tmp_path, demo_app):
    engine, workspace, http_ws = build_engine(tmp_path)
    hyp = engine.hypothesis_engine.create(title="session cookie missing defensive attributes")
    result = await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_COOKIE_ATTRIBUTE, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/api/login", "method": "POST",
                    "body": "username=user_a"},
    ))
    assert result.outcome == ValidationOutcome.SUPPORTS
    assert "HttpOnly" in result.detail or "Secure" in result.detail


@pytest.mark.asyncio
async def test_permissive_cors_detected(tmp_path, demo_app):
    engine, workspace, http_ws = build_engine(tmp_path)
    hyp = engine.hypothesis_engine.create(title="permissive CORS policy")
    result = await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_CORS_POLICY, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/api/cors-test"},
    ))
    assert result.outcome == ValidationOutcome.SUPPORTS


@pytest.mark.asyncio
async def test_debug_disclosure_detected(tmp_path, demo_app):
    engine, workspace, http_ws = build_engine(tmp_path)
    hyp = engine.hypothesis_engine.create(title="possible information disclosure on /api/debug-error")
    result = await engine.execute(ValidationAction(
        action_type=ValidationActionType.VERIFY_SCANNER_INDICATION, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/api/debug-error"},
    ))
    assert result.outcome == ValidationOutcome.SUPPORTS
    assert "Traceback" in result.detail
    evidence = workspace.get_evidence(result.evidence_ids[0])
    assert "/app/src/handlers/orders.py" in evidence.sanitized_preview


@pytest.mark.asyncio
async def test_missing_security_headers_detected(tmp_path, demo_app):
    engine, workspace, http_ws = build_engine(tmp_path)
    hyp = engine.hypothesis_engine.create(title="missing recommended security headers")
    result = await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_SECURITY_HEADER, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/"},
    ))
    assert result.outcome == ValidationOutcome.SUPPORTS  # the demo app sets none of them


@pytest.mark.asyncio
async def test_session_invalidation_after_logout(tmp_path, demo_app):
    engine, workspace, http_ws = build_engine(tmp_path)
    await _login(http_ws, demo_app.base_url, "user_a")
    hyp = engine.hypothesis_engine.create(title="session usable after logout")
    result = await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_SESSION_INVALIDATION, hypothesis_id=hyp.id,
        parameters={"logout_url": demo_app.base_url + "/api/logout",
                    "protected_url": demo_app.base_url + "/api/private", "session_id": "user_a"},
    ))
    assert result.outcome == ValidationOutcome.REFUTES  # correctly invalidated


@pytest.mark.asyncio
async def test_validation_budget_exhausts_per_hypothesis(tmp_path, demo_app):
    engine, workspace, http_ws = build_engine(tmp_path, max_actions_per_hypothesis=1)
    hyp = engine.hypothesis_engine.create(title="repeatedly checked")
    await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_AUTH_BOUNDARY, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/api/private"},
    ))
    with pytest.raises(ValidationBudgetExhaustedError):
        await engine.execute(ValidationAction(
            action_type=ValidationActionType.CHECK_AUTH_BOUNDARY, hypothesis_id=hyp.id,
            parameters={"url": demo_app.base_url + "/api/private"},
        ))


@pytest.mark.asyncio
async def test_stop_after_proof_refuses_further_validation(tmp_path, demo_app):
    engine, workspace, http_ws = build_engine(tmp_path)
    await _login(http_ws, demo_app.base_url, "user_a")
    await _login(http_ws, demo_app.base_url, "user_b")
    hyp = engine.hypothesis_engine.create(title="broken object authorization")
    await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/api/orders-broken/1",
                    "owner_session": "user_a", "other_session": "user_b"},
    ))
    engine.hypothesis_engine.transition(hyp.id, HypothesisStatus.CONFIRMED)

    with pytest.raises(HypothesisAlreadyResolvedError):
        await engine.execute(ValidationAction(
            action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION, hypothesis_id=hyp.id,
            parameters={"url": demo_app.base_url + "/api/orders-broken/2",
                        "owner_session": "user_b", "other_session": "user_a"},
        ))
