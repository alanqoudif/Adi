from pathlib import Path

from adi.knowledge.observations import ObservationType
from adi.tools.loader import load_parser

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


def test_feroxbuster_parser_excludes_404_and_keeps_others():
    parser = load_parser(SKILLS_DIR / "feroxbuster")
    raw = (FIXTURES_DIR / "feroxbuster" / "scan.jsonl").read_text()
    observations = parser.parse(stdout=raw, stderr="", context={"target": "x", "exit_code": 0})

    paths = {o.value["path"] for o in observations}
    assert "/admin" not in paths  # was 404 in the fixture
    assert {"/", "/login", "/dashboard", "/api/profile", "/api/orders"}.issubset(paths)
    assert all(o.type == ObservationType.WEB_ENDPOINT for o in observations)


def test_ffuf_parser_excludes_404_and_flags_403_as_endpoint():
    parser = load_parser(SKILLS_DIR / "ffuf")
    raw = (FIXTURES_DIR / "ffuf" / "scan.json").read_text()
    observations = parser.parse(stdout=raw, stderr="", context={"target": "x", "exit_code": 0})

    paths = {o.value["path"]: o for o in observations}
    assert "/notfoundxyz" not in paths
    assert "/login" in paths
    assert "/admin" in paths  # 403 is still attack surface
    assert paths["/admin"].value["status"] == 403


def test_whatweb_parser_produces_technology_observations_with_honest_confidence():
    parser = load_parser(SKILLS_DIR / "whatweb")
    raw = (FIXTURES_DIR / "whatweb" / "scan.json").read_text()
    observations = parser.parse(stdout=raw, stderr="", context={"target": "x", "exit_code": 0})

    by_plugin = {o.value["plugin"]: o for o in observations}
    assert by_plugin["HTTPServer"].confidence == 1.0
    assert by_plugin["X-Powered-By"].confidence == 1.0
    assert by_plugin["Cookies"].confidence < 1.0
    assert all(o.type == ObservationType.TECHNOLOGY_FINGERPRINT for o in observations)


def test_ffuf_parser_handles_malformed_json():
    parser = load_parser(SKILLS_DIR / "ffuf")
    observations = parser.parse(stdout="not json", stderr="", context={"target": "x", "exit_code": 0})
    assert len(observations) == 1
    assert observations[0].type == ObservationType.TOOL_ERROR


def test_feroxbuster_parser_handles_empty_output_with_error_exit():
    parser = load_parser(SKILLS_DIR / "feroxbuster")
    observations = parser.parse(stdout="", stderr="connection refused", context={"target": "x", "exit_code": 1})
    assert len(observations) == 1
    assert observations[0].type == ObservationType.TOOL_ERROR
