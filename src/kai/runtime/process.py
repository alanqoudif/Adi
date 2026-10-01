"""The execution-runtime abstraction and its common result type.

No component should build a shell string and hand it to `os.system` or
`shell=True` — see docs/safety-model.md. Arguments are always passed as an
argv list, executed without a shell, so there is no command-injection
surface from interpolated target strings.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime

from pydantic import BaseModel


class ExecutionResult(BaseModel):
    command_id: str
    tool_name: str
    argv: list[str]
    started_at: datetime
    completed_at: datetime
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    stdout_path: str | None = None
    stderr_path: str | None = None
    timed_out: bool = False

    @property
    def duration_seconds(self) -> float:
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class ExecutionRuntime(ABC):
    """Executes a tool's argv in an isolated environment and returns its
    output. Implementations: `MockRuntime` (tests), `LocalRuntime` (opt-in,
    unsandboxed), `DockerKaliRuntime` (default, isolated)."""

    @abstractmethod
    async def execute(
        self,
        argv: list[str],
        *,
        timeout: int = 300,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ExecutionResult: ...

    @abstractmethod
    async def is_available(self) -> bool:
        """Whether this runtime can actually execute right now (e.g. Docker
        daemon reachable, image present)."""
        ...


def utcnow() -> datetime:
    return datetime.now(UTC)
