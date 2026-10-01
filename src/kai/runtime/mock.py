"""A fully deterministic in-memory runtime, used by unit tests and by the
planner/orchestrator test-suite so neither Docker nor real security tools
are required to exercise the agent loop."""

from __future__ import annotations

import uuid

from kai.runtime.process import ExecutionResult, ExecutionRuntime, utcnow


class MockRuntime(ExecutionRuntime):
    def __init__(self):
        # argv tuple -> ExecutionResult fields, so tests can script responses
        self.responses: dict[tuple[str, ...], dict] = {}
        self.calls: list[list[str]] = []

    def script(self, argv_prefix: list[str], *, stdout: str = "", stderr: str = "",
               exit_code: int = 0, timed_out: bool = False) -> None:
        self.responses[tuple(argv_prefix)] = {
            "stdout": stdout, "stderr": stderr, "exit_code": exit_code, "timed_out": timed_out,
        }

    async def execute(self, argv, *, timeout=300, cwd=None, env=None) -> ExecutionResult:
        self.calls.append(argv)
        started = utcnow()
        matched = {}
        for prefix, response in self.responses.items():
            if tuple(argv[: len(prefix)]) == prefix:
                matched = response
                break
        return ExecutionResult(
            command_id=uuid.uuid4().hex[:12],
            tool_name=argv[0] if argv else "",
            argv=argv,
            started_at=started,
            completed_at=utcnow(),
            exit_code=matched.get("exit_code", 1 if not matched else 0),
            stdout=matched.get("stdout", ""),
            stderr=matched.get("stderr", ""),
            timed_out=matched.get("timed_out", False),
        )

    async def is_available(self) -> bool:
        return True
