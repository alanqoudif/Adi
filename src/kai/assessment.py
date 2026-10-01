"""Assessment lifecycle: the `.kai/assessments/<id>/` workspace directory,
tying together scope, the knowledge workspace, the tool registry, and a
runtime. This is the object the CLI and (from Phase 2) the orchestrator
build everything else around."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from kai.config.models import KaiConfig
from kai.knowledge.workspace import Workspace
from kai.runtime.docker_runtime import DockerKaliRuntime
from kai.runtime.mock import MockRuntime
from kai.runtime.process import ExecutionRuntime
from kai.runtime.shell import LocalRuntime
from kai.scope.engine import ScopeEngine
from kai.scope.models import Scope
from kai.tools.executor import ToolExecutor
from kai.tools.registry import ToolRegistry


def assessments_root(project_root: Path | None = None) -> Path:
    return (project_root or Path.cwd()) / ".kai" / "assessments"


def assessment_dir(assessment_id: str, project_root: Path | None = None) -> Path:
    return assessments_root(project_root) / assessment_id


def build_runtime(config: KaiConfig, workspace_dir: Path | None = None) -> ExecutionRuntime:
    if config.runtime.type == "mock":
        return MockRuntime()
    if config.runtime.type == "local":
        if not config.runtime.allow_local:
            raise RuntimeError(
                "runtime.type is 'local' but runtime.allow_local is not set to true "
                "in .kai.yaml — local execution is unsandboxed and opt-in only"
            )
        return LocalRuntime()
    return DockerKaliRuntime(
        image=config.runtime.image,
        workspace_dir=str(workspace_dir) if workspace_dir else None,
    )


def discover_skills_dir() -> Path:
    """Locate the repository's top-level `skills/` directory."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "skills"
        if candidate.exists() and (candidate / "nmap").exists():
            return candidate
    # fall back to cwd-relative, for installed-package scenarios
    return Path.cwd() / "skills"


@dataclass
class Assessment:
    workspace: Workspace
    scope_engine: ScopeEngine
    registry: ToolRegistry
    runtime: ExecutionRuntime
    executor: ToolExecutor
    directory: Path

    @property
    def id(self) -> str:
        return self.workspace.assessment_id

    @classmethod
    def create(cls, scope: Scope, config: KaiConfig, project_root: Path | None = None) -> Assessment:
        workspace_tmp_dir = assessments_root(project_root)
        workspace_tmp_dir.mkdir(parents=True, exist_ok=True)
        # the id is only known after Workspace.create, so build in two steps
        db_path = workspace_tmp_dir / "_pending.db"
        workspace = Workspace.create(db_path, scope)
        final_dir = assessment_dir(workspace.assessment_id, project_root)
        final_dir.mkdir(parents=True, exist_ok=True)
        final_db = final_dir / "state.db"
        db_path.rename(final_db)
        # re-open against the final path (sqlite engine bound to old path otherwise)
        workspace = Workspace.open(final_db, workspace.assessment_id)
        return cls._build(workspace, scope, config, final_dir)

    @classmethod
    def resume(cls, assessment_id: str, config: KaiConfig, project_root: Path | None = None) -> Assessment:
        directory = assessment_dir(assessment_id, project_root)
        db_path = directory / "state.db"
        if not db_path.exists():
            raise ValueError(f"no assessment '{assessment_id}' found at {directory}")
        workspace = Workspace.open(db_path, assessment_id)
        scope = workspace.load_scope()
        return cls._build(workspace, scope, config, directory)

    @classmethod
    def _build(cls, workspace: Workspace, scope: Scope, config: KaiConfig, directory: Path) -> Assessment:
        scope_engine = ScopeEngine(scope)
        registry = ToolRegistry(discover_skills_dir())
        registry.discover()
        runtime = build_runtime(config, workspace_dir=directory / "raw")
        raw_dir = directory / "raw"
        executor = ToolExecutor(registry, runtime, scope_engine, workspace, raw_dir)
        return cls(
            workspace=workspace, scope_engine=scope_engine, registry=registry,
            runtime=runtime, executor=executor, directory=directory,
        )

    @staticmethod
    def list_ids(project_root: Path | None = None) -> list[str]:
        root = assessments_root(project_root)
        if not root.exists():
            return []
        return sorted(p.name for p in root.iterdir() if p.is_dir() and (p / "state.db").exists())
