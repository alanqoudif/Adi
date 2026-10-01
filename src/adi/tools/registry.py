"""The tool registry: discovers installed security tools from skill
directories (`skills/<tool>/tool.yaml`) and tracks their local availability.

The orchestrator should reason in capabilities ("discover_web_paths") and
let the registry resolve candidate tools — see spec section 51.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class ToolRequirements(BaseModel):
    target: bool = True


class ToolSupports(BaseModel):
    host: bool = False
    cidr: bool = False
    hostname: bool = False
    url: bool = False


class ToolOutput(BaseModel):
    machine_readable: bool = False
    preferred_format: str = "text"


class ToolExecutionSpec(BaseModel):
    timeout_seconds: int = 300
    default_concurrency: int = 1
    binary: str | None = None  # defaults to tool name
    priority: int = 100  # lower runs first when multiple tools share a capability


class ToolScopeRequirements(BaseModel):
    target_must_be_authorized: bool = True
    explicit_auth_testing_permission: bool = False


class ToolMetadata(BaseModel):
    """Parsed `tool.yaml`."""

    name: str
    category: list[str] = Field(default_factory=list)
    description: str = ""
    capabilities: list[str] = Field(default_factory=list)
    risk_level: str = "low"
    requires: ToolRequirements = Field(default_factory=ToolRequirements)
    supports: ToolSupports = Field(default_factory=ToolSupports)
    output: ToolOutput = Field(default_factory=ToolOutput)
    execution: ToolExecutionSpec = Field(default_factory=ToolExecutionSpec)
    scope_requirements: ToolScopeRequirements = Field(default_factory=ToolScopeRequirements)

    skill_dir: Path | None = None
    trusted: bool = True  # False for dynamically-discovered TemporaryToolSkill


class RegisteredTool(BaseModel):
    metadata: ToolMetadata
    available: bool
    binary_path: str | None = None

    model_config = {"arbitrary_types_allowed": True}


class ToolRegistry:
    def __init__(self, skills_dir: Path):
        self.skills_dir = skills_dir
        self._tools: dict[str, RegisteredTool] = {}

    def discover(self) -> list[RegisteredTool]:
        """Scan `skills_dir` for `tool.yaml` files and probe availability."""
        self._tools.clear()
        if not self.skills_dir.exists():
            return []
        for tool_yaml in sorted(self.skills_dir.glob("*/tool.yaml")):
            try:
                raw = yaml.safe_load(tool_yaml.read_text()) or {}
                metadata = ToolMetadata.model_validate(raw)
                metadata.skill_dir = tool_yaml.parent
            except Exception:  # malformed skill shouldn't crash discovery
                continue
            binary = metadata.execution.binary or metadata.name
            binary_path = shutil.which(binary)
            self._tools[metadata.name] = RegisteredTool(
                metadata=metadata,
                available=binary_path is not None,
                binary_path=binary_path,
            )
        return list(self._tools.values())

    def get(self, name: str) -> RegisteredTool | None:
        return self._tools.get(name)

    def by_capability(self, capability: str) -> list[RegisteredTool]:
        return [t for t in self._tools.values() if capability in t.metadata.capabilities]

    def available_by_capability(self, capability: str) -> list[RegisteredTool]:
        return [t for t in self.by_capability(capability) if t.available]

    def resolve(self, capability: str) -> RegisteredTool | None:
        """Phase 3I: capability-first tool selection. The planner asks for
        a capability (e.g. 'discover_web_content'), never a specific binary
        — this picks the best *available* tool for it, deterministically
        (lowest `execution.priority`, then name, so the choice never
        silently changes run to run)."""
        candidates = sorted(
            self.available_by_capability(capability),
            key=lambda t: (t.metadata.execution.priority, t.metadata.name),
        )
        return candidates[0] if candidates else None

    def all(self) -> list[RegisteredTool]:
        return list(self._tools.values())
