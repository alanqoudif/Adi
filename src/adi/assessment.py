"""Assessment lifecycle: the `.adi/assessments/<id>/` workspace directory,
tying together scope, the knowledge workspace, the tool registry, and a
runtime. This is the object the CLI and (from Phase 2) the orchestrator
build everything else around."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from adi.agent.context_builder import ContextBuilder
from adi.agent.critic import Critic
from adi.agent.orchestrator import Orchestrator
from adi.agent.planner import Planner
from adi.agent.scheduler import ActionBudget
from adi.config.models import AdiConfig
from adi.evidence.store import EvidenceStore
from adi.findings.pipeline import FindingPipeline
from adi.http.client import HTTPClient
from adi.http.sessions import SessionJarRegistry
from adi.http.workspace import HTTPWorkspace
from adi.knowledge.workspace import Workspace
from adi.llm.base import LLMProvider
from adi.runtime.docker_runtime import DockerKaliRuntime
from adi.runtime.mock import MockRuntime
from adi.runtime.process import ExecutionRuntime
from adi.runtime.shell import LocalRuntime
from adi.scope.engine import ScopeEngine
from adi.scope.models import Scope
from adi.scope.rate_limiter import RateLimiter
from adi.tools.executor import ToolExecutor
from adi.tools.registry import ToolRegistry
from adi.validation.context import ValidationContext
from adi.validation.engine import ValidationEngine


def assessments_root(project_root: Path | None = None) -> Path:
    return (project_root or Path.cwd()) / ".adi" / "assessments"


def assessment_dir(assessment_id: str, project_root: Path | None = None) -> Path:
    return assessments_root(project_root) / assessment_id


def build_runtime(config: AdiConfig, workspace_dir: Path | None = None) -> ExecutionRuntime:
    if config.runtime.type == "mock":
        return MockRuntime()
    if config.runtime.type == "local":
        if not config.runtime.allow_local:
            raise RuntimeError(
                "runtime.type is 'local' but runtime.allow_local is not set to true "
                "in .adi.yaml — local execution is unsandboxed and opt-in only"
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
    http_workspace: HTTPWorkspace
    rate_limiter: RateLimiter
    directory: Path

    @property
    def id(self) -> str:
        return self.workspace.assessment_id

    @classmethod
    def create(cls, scope: Scope, config: AdiConfig, project_root: Path | None = None) -> Assessment:
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
    def resume(cls, assessment_id: str, config: AdiConfig, project_root: Path | None = None) -> Assessment:
        directory = assessment_dir(assessment_id, project_root)
        db_path = directory / "state.db"
        if not db_path.exists():
            raise ValueError(f"no assessment '{assessment_id}' found at {directory}")
        workspace = Workspace.open(db_path, assessment_id)
        scope = workspace.load_scope()
        return cls._build(workspace, scope, config, directory)

    @classmethod
    def _build(cls, workspace: Workspace, scope: Scope, config: AdiConfig, directory: Path) -> Assessment:
        scope_engine = ScopeEngine(scope)
        registry = ToolRegistry(discover_skills_dir())
        registry.discover()
        runtime = build_runtime(config, workspace_dir=directory / "raw")
        raw_dir = directory / "raw"
        rate_limiter = RateLimiter(scope.rate_limits)
        executor = ToolExecutor(registry, runtime, scope_engine, workspace, raw_dir, rate_limiter=rate_limiter)
        http_client = HTTPClient(scope_engine, SessionJarRegistry(), rate_limiter=rate_limiter)
        http_workspace = HTTPWorkspace(http_client, workspace, directory / "evidence")
        return cls(
            workspace=workspace, scope_engine=scope_engine, registry=registry,
            runtime=runtime, executor=executor, http_workspace=http_workspace,
            rate_limiter=rate_limiter, directory=directory,
        )

    def build_orchestrator(self, llm: LLMProvider) -> Orchestrator:
        """Wire the autonomous agent loop against this assessment's existing
        workspace/scope/executor/HTTP workspace — see `adi.agent.orchestrator`."""
        scope = self.workspace.load_scope()
        context_builder = ContextBuilder(self.workspace, scope, self.registry, goal=scope.goal)
        planner = Planner(llm)
        budget = ActionBudget(
            max_actions=scope.max_actions,
            max_consecutive_failures=scope.max_consecutive_failures,
        )
        budget.actions_taken = len(self.workspace.list_actions())

        evidence_store = EvidenceStore(self.workspace)
        validation_engine = ValidationEngine(
            ValidationContext(self.http_workspace, evidence_store, self.workspace)
        )
        finding_pipeline = FindingPipeline(self.workspace, evidence_store, critic=Critic(llm))

        return Orchestrator(self.workspace, self.executor, planner, context_builder, budget,
                             http_workspace=self.http_workspace,
                             validation_engine=validation_engine, finding_pipeline=finding_pipeline)

    @staticmethod
    def list_ids(project_root: Path | None = None) -> list[str]:
        root = assessments_root(project_root)
        if not root.exists():
            return []
        return sorted(p.name for p in root.iterdir() if p.is_dir() and (p / "state.db").exists())
