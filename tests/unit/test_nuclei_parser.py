"""Mandatory Phase 3O test: a nuclei alert must become a scanner indication,
never a confirmed finding."""

from pathlib import Path

from adi.knowledge.observations import ObservationType
from adi.knowledge.workspace import Workspace
from adi.scope.models import Scope
from adi.tools.loader import load_parser

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills" / "nuclei"
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "nuclei" / "scan.jsonl"


def test_nuclei_alert_produces_scanner_indication_not_confirmed_finding(tmp_path):
    parser = load_parser(SKILLS_DIR)
    raw = FIXTURE.read_text()
    observations = parser.parse(stdout=raw, stderr="", context={"target": "x", "exit_code": 0})

    assert len(observations) == 2
    assert all(o.type == ObservationType.SCANNER_ALERT for o in observations)
    assert all(o.confidence < 1.0 for o in observations)  # never reported as a plain fact

    scope = Scope(name="nuclei-test", targets=["127.0.0.1"])
    workspace = Workspace.create(tmp_path / "state.db", scope)
    workspace.record_observations(observations)

    scanner_indications = [o for o in workspace.list_observations() if o.type == "scanner_alert"]
    confirmed_findings = [f for f in workspace.list_findings() if f.status == "confirmed"]

    assert len(scanner_indications) > 0
    assert len(confirmed_findings) == 0


def test_nuclei_alert_content_is_preserved_for_later_hypothesis_formation():
    parser = load_parser(SKILLS_DIR)
    raw = FIXTURE.read_text()
    observations = parser.parse(stdout=raw, stderr="", context={"target": "x", "exit_code": 0})

    names = {o.value["name"] for o in observations}
    assert "Exposed Admin Panel" in names
    severities = {o.value["severity"] for o in observations}
    assert "medium" in severities


def test_nuclei_parser_handles_tool_error_on_failure():
    parser = load_parser(SKILLS_DIR)
    observations = parser.parse(stdout="", stderr="could not load templates", context={"target": "x", "exit_code": 1})
    assert len(observations) == 1
    assert observations[0].type == ObservationType.TOOL_ERROR
