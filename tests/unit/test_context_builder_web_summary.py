"""Phase 3Q: ContextBuilder surfaces a bounded web-state summary (endpoint
groups, forms, technologies, recent HTTP, scanner indications) without
dumping every raw URL/response into the LLM prompt."""

from pathlib import Path

from adi.agent.context_builder import ContextBuilder
from adi.knowledge.observations import Observation, ObservationType
from adi.knowledge.workspace import Workspace
from adi.scope.models import Scope
from adi.tools.registry import ToolRegistry

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"


def _registry():
    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()
    return registry


def test_endpoint_groups_and_forms_and_technologies(tmp_path):
    scope = Scope(name="web-ctx", targets=["app.local"], goal="map it")
    workspace = Workspace.create(tmp_path / "state.db", scope)

    for path in ("/api/profile", "/api/orders", "/api/settings"):
        workspace.record_observation(Observation(
            type=ObservationType.WEB_ENDPOINT, subject=f"app.local{path}",
            value={"host": "app.local", "path": path, "methods": ["GET"]}, source="test",
        ))
    workspace.record_observation(Observation(
        type=ObservationType.WEB_ENDPOINT, subject="app.local/login",
        value={"host": "app.local", "path": "/login", "methods": ["POST"]}, source="test",
    ))
    login_ep = next(e for e in workspace.list_endpoints() if e.path == "/login")
    for name in ("email", "password"):
        workspace.record_observation(Observation(
            type=ObservationType.ENDPOINT_PARAMETER, subject=name,
            value={"endpoint_id": login_ep.id, "name": name, "location": "body"}, source="test",
        ))
    workspace.record_observation(Observation(
        type=ObservationType.TECHNOLOGY_FINGERPRINT, subject="app.local",
        value={"name": "nginx", "confidence": "high", "source": "server_header"}, source="test",
        confidence=1.0,
    ))
    workspace.record_observation(Observation(
        type=ObservationType.TECHNOLOGY_FINGERPRINT, subject="app.local",
        value={"name": "React", "confidence": "low", "source": "dom_marker"}, source="test",
        confidence=0.3,
    ))
    workspace.record_observation(Observation(
        type=ObservationType.SCANNER_ALERT, subject="app.local/admin",
        value={"template_id": "x", "name": "Exposed admin", "severity": "medium"}, source="nuclei",
        confidence=0.4,
    ))

    builder = ContextBuilder(workspace, scope, _registry(), goal=scope.goal)
    context = builder.build()

    assert context.endpoint_count == 4
    assert any(g.prefix == "/api/*" and g.count == 3 for g in context.endpoint_groups)

    assert len(context.forms) == 1
    assert context.forms[0].path == "/login"
    assert set(context.forms[0].parameters) == {"email", "password"}

    tech_by_name = {t.name: t.confidence for t in context.technologies}
    assert tech_by_name["nginx"] == "high"
    assert tech_by_name["React"] == "low"

    assert context.scanner_indication_count == 1

    rendered = context.render()
    assert "/api/*" in rendered
    assert "POST /login" in rendered
    assert "nginx" in rendered
    assert "scanner indications: 1" in rendered


def test_recent_http_summary_reflects_exchanges(tmp_path):
    scope = Scope(name="web-ctx-2", targets=["app.local"])
    workspace = Workspace.create(tmp_path / "state.db", scope)
    workspace.record_http_exchange(
        method="GET", url="http://app.local/", session_id="anonymous", status=200,
        content_type="text/html", content_length=10, body_hash="x", title="Home",
        error=None, source="http_client", evidence_path=None, redirects_json="[]",
        started_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        completed_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
    )

    builder = ContextBuilder(workspace, scope, _registry(), goal=scope.goal)
    context = builder.build()

    assert len(context.recent_http) == 1
    assert context.recent_http[0].status == 200
    rendered = context.render()
    assert "GET http://app.local/ -> 200" in rendered
