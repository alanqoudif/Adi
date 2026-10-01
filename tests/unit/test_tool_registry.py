from pathlib import Path

from adi.tools.registry import ToolRegistry

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"


def test_discovers_nmap_skill():
    registry = ToolRegistry(SKILLS_DIR)
    tools = registry.discover()
    names = {t.metadata.name for t in tools}
    assert "nmap" in names


def test_by_capability():
    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()
    matches = registry.by_capability("discover_hosts")
    assert any(t.metadata.name == "nmap" for t in matches)


def test_missing_skills_dir_returns_empty():
    registry = ToolRegistry(Path("/nonexistent/path/xyz"))
    assert registry.discover() == []
