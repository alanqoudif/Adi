from pathlib import Path

from adi.knowledge.observations import ObservationType
from adi.tools.loader import load_parser

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "nmap" / "scan.xml"
SKILL_DIR = Path(__file__).resolve().parents[2] / "skills" / "nmap"


def test_nmap_parser_produces_host_and_open_port_observations():
    parser = load_parser(SKILL_DIR)
    xml = FIXTURE.read_text()
    observations = parser.parse(stdout=xml, stderr="", context={"target": "10.10.10.15", "exit_code": 0})

    host_obs = [o for o in observations if o.type == ObservationType.HOST_UP]
    assert len(host_obs) == 1
    assert host_obs[0].subject == "10.10.10.15"

    port_obs = {o.subject: o for o in observations if o.type == ObservationType.OPEN_PORT}
    assert "10.10.10.15:22" in port_obs
    assert "10.10.10.15:80" in port_obs
    # port 3306 was closed in the fixture and must not appear
    assert "10.10.10.15:3306" not in port_obs

    http = port_obs["10.10.10.15:80"]
    assert http.value["service"] == "http"
    assert http.value["product"] == "nginx"
    assert http.value["version"] == "1.18.0"


def test_nmap_parser_handles_empty_output_with_nonzero_exit():
    parser = load_parser(SKILL_DIR)
    observations = parser.parse(stdout="", stderr="connection refused", context={"target": "x", "exit_code": 1})
    assert len(observations) == 1
    assert observations[0].type == ObservationType.TOOL_ERROR


def test_nmap_parser_handles_malformed_xml():
    parser = load_parser(SKILL_DIR)
    observations = parser.parse(stdout="<not valid", stderr="", context={"target": "x", "exit_code": 0})
    assert len(observations) == 1
    assert observations[0].type == ObservationType.TOOL_ERROR
