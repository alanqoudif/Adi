"""Phase 3I: capability-first tool selection with deterministic fallback."""

from pathlib import Path

from adi.tools.registry import ToolRegistry

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"


def test_resolve_picks_lowest_priority_among_available():
    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()
    registry.get("feroxbuster").available = True
    registry.get("ffuf").available = True

    resolved = registry.resolve("discover_web_content")
    assert resolved.metadata.name == "feroxbuster"  # priority 10 < 20


def test_resolve_falls_back_when_preferred_tool_unavailable():
    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()
    registry.get("feroxbuster").available = False
    registry.get("ffuf").available = True

    resolved = registry.resolve("discover_web_content")
    assert resolved.metadata.name == "ffuf"


def test_resolve_returns_none_when_nothing_available():
    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()
    registry.get("feroxbuster").available = False
    registry.get("ffuf").available = False

    assert registry.resolve("discover_web_content") is None


def test_resolve_ignores_unrelated_capability():
    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()
    assert registry.resolve("totally_made_up_capability") is None


def test_whatweb_and_nuclei_discovered_with_distinct_capabilities():
    registry = ToolRegistry(SKILLS_DIR)
    tools = {t.metadata.name for t in registry.discover()}
    assert {"nmap", "feroxbuster", "ffuf", "whatweb", "nuclei"}.issubset(tools)

    assert any(t.metadata.name == "whatweb" for t in registry.by_capability("fingerprint_web_application"))
    assert any(t.metadata.name == "nuclei" for t in registry.by_capability("web_template_scan"))
