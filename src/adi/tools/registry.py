"""The tool registry: discovers installed security tools from skill
directories (`skills/<tool>/tool.yaml`) and tracks their local availability.

The orchestrator should reason in capabilities ("discover_web_paths") and
let the registry resolve candidate tools — see spec section 51.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from adi.tools.intelligence import Capability, TrustLevel

_VERSION_CACHE: dict[tuple, str] = {}


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

    display_name: str = ""
    binary_names: list[str] = Field(default_factory=list)
    version_args: list[str] = Field(default_factory=list)
    requires_root: bool = False
    requires_network: bool = True
    requires_wordlist: bool = False
    supports_rate_control: bool = False
    approval_requirement: bool = False
    parser_quality: int = 100
    noise: int = 10
    trust_level: TrustLevel = TrustLevel.BUILT_IN_REVIEWED
    documentation_source: str = "reviewed skill"
    parser: str = "parser.py"
    adapter: str = "adapter.py"
    input_schema: dict = Field(default_factory=dict)
    normalized_entities: list[str] = Field(default_factory=lambda: ["Observation"])
    skill_dir: Path | None = None
    trusted: bool = True  # False for dynamically-discovered TemporaryToolSkill


class RegisteredTool(BaseModel):
    metadata: ToolMetadata
    available: bool
    binary_path: str | None = None

    version: str = "unknown"
    runtime: str = "local"
    availability_by_runtime: dict[str, dict] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True}


class ToolRegistry:
    def __init__(self, skills_dir: Path):
        self.skills_dir = skills_dir
        self._tools: dict[str, RegisteredTool] = {}
        self.memory = None
        self.validation_errors: list[str] = []

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
                if metadata.risk_level not in {"passive", "low", "moderate", "elevated", "high", "prohibited"}:
                    raise ValueError("invalid risk")
                if not metadata.capabilities:
                    raise ValueError("missing capabilities")
                for file in (metadata.adapter, metadata.parser, "SKILL.md"):
                    if Path(file).name != file or not (tool_yaml.parent / file).is_file():
                        raise ValueError("missing or unsafe plugin component")
            except (OSError, ValueError, yaml.YAMLError) as exc:
                self.validation_errors.append(f"{tool_yaml.parent.name}: invalid plugin contract")
                logging.getLogger(__name__).debug("Invalid tool skill %s: %s", tool_yaml, exc)
                continue
            binary = metadata.execution.binary or metadata.name
            binary_path = next((shutil.which(b) for b in [binary, *metadata.binary_names] if shutil.which(b)), None)
            venv_binary = Path(sys.executable).parent / binary
            if binary_path is None and venv_binary.is_file():
                binary_path = str(venv_binary)
            self._tools[metadata.name] = RegisteredTool(
                metadata=metadata,
                available=binary_path is not None,
                binary_path=binary_path,
            )
            tool = self._tools[metadata.name]
            tool.version = self.probe_version(tool)
            tool.availability_by_runtime["local"] = {
                "available": tool.available, "path": tool.binary_path, "version": tool.version}
        return list(self._tools.values())

    @staticmethod
    def probe_version(tool: RegisteredTool) -> str:
        if not tool.available or not tool.metadata.version_args:
            return "unknown"
        try:
            stat = Path(tool.binary_path).stat()
            key = (tool.binary_path, stat.st_mtime_ns, stat.st_size, tuple(tool.metadata.version_args))
            if key in _VERSION_CACHE:
                return _VERSION_CACHE[key]
            with tempfile.TemporaryDirectory(prefix="adi-probe-") as directory:
                import certifi
                env = dict(os.environ)
                env["SSL_CERT_FILE"] = certifi.where()
                env.update(SEMGREP_ENABLE_VERSION_CHECK="0", SEMGREP_SEND_METRICS="off",
                           SEMGREP_LOG_FILE=directory + "/semgrep.log",
                           SEMGREP_SETTINGS_FILE=directory + "/settings.yml")
                result = subprocess.run([tool.binary_path, *tool.metadata.version_args],
                                        capture_output=True, text=True, timeout=3, env=env, check=False)
            lines = (result.stdout + result.stderr).strip().splitlines()
            versions = [line for line in lines if re.search(r"\b\d+\.\d+(?:\.\d+)?\b", line)
                        and not line.lower().startswith(("warning", "error", "fatal"))]
            version = versions[0][:100] if versions else "unknown"
            _VERSION_CACHE[key] = version
            return version
        except (OSError, subprocess.SubprocessError):
            return "unknown"

    async def detect_runtime(self, runtime):
        """Probe the selected container; never inherit host availability."""
        from adi.runtime.docker_runtime import DockerKaliRuntime
        if not isinstance(runtime, DockerKaliRuntime):
            return
        ready = await runtime.is_available()
        for tool in self.all():
            if "source" in tool.metadata.category:
                continue
            binary = tool.metadata.execution.binary or tool.metadata.name
            result = await runtime.execute(["which", binary], timeout=5) if ready else None
            path = result.stdout.strip() if result and result.succeeded else None
            version = "unknown"
            if path and tool.metadata.version_args:
                probe = await runtime.execute([path, *tool.metadata.version_args], timeout=5)
                lines = (probe.stdout + probe.stderr).strip().splitlines()
                version = lines[0][:100] if lines else "unknown"
            tool.runtime = "docker-kali"
            tool.available, tool.binary_path, tool.version = bool(path), path, version
            tool.availability_by_runtime["docker-kali"] = {
                "available": bool(path), "path": path, "version": version}

    def knowledge_for(self, capability: str) -> list[dict]:
        from adi.tools.discovery import SkillCache
        if not hasattr(self, '_skill_cache'):
            self._skill_cache = SkillCache()
        return [{"name": t.metadata.name, "trust": t.metadata.trust_level.value,
                 "skill": self._skill_cache.relevant(t)[:1500]}
                for t in self.ranked(capability)[:2]]

    def capabilities(self) -> list[Capability]:
        result = []
        for name in sorted({c for t in self.all() for c in t.metadata.capabilities}):
            tools = self.by_capability(name)
            elevated = name == "audit_credentials"
            permissions = ["authentication_testing"] if elevated else ["discovery"]
            if name in {"discover_web_content", "fingerprint_web_application", "web_template_scan"}:
                permissions = ["web_enumeration"]
            if name.startswith("scan_"):
                permissions = ["source_analysis"]
            result.append(Capability(id=name, name=name,
                description=f"Resolve {name.replace('_', ' ')} through reviewed providers",
                candidate_tools=[t.metadata.name for t in tools],
                category=tools[0].metadata.category[0] if tools[0].metadata.category else "security",
                input_schema=tools[0].metadata.input_schema or {"target": "one explicit authorized target"},
                default_timeout=tools[0].metadata.execution.timeout_seconds,
                risk_level="elevated" if elevated else tools[0].metadata.risk_level,
                required_scope_permissions=permissions, approval_requirement=elevated,
                output_entity_types=sorted({e for t in tools for e in t.metadata.normalized_entities})))
        return result

    def ranked(self, capability: str) -> list[RegisteredTool]:
        candidates = [t for t in self.available_by_capability(capability)
                      if t.metadata.trust_level == TrustLevel.BUILT_IN_REVIEWED
                      and t.metadata.risk_level != "prohibited"
                      and not (self.memory and self.memory.get(t).disabled)]
        return sorted(candidates, key=lambda t: (
            t.metadata.execution.priority + (self.memory.get(t).failed_runs * 20 if self.memory else 0),
            -t.metadata.parser_quality, not t.metadata.output.machine_readable,
            t.metadata.requires_root, t.metadata.noise, t.metadata.name))

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
        candidates = self.ranked(capability)
        return candidates[0] if candidates else None

    def all(self) -> list[RegisteredTool]:
        return list(self._tools.values())
