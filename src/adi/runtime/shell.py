"""LocalRuntime: executes tools directly on the host, with no container
isolation. This is opt-in only (`runtime.type: local` and
`runtime.allow_local: true` in `.adi.yaml`) — the default is
`DockerKaliRuntime`. Useful for development on a machine that already has
security tools installed, at the cost of losing the isolation guarantees
Docker gives us (see docs/safety-model.md)."""

from __future__ import annotations

import asyncio
import shutil
import uuid

from adi.runtime.process import ExecutionResult, ExecutionRuntime, utcnow


class LocalRuntime(ExecutionRuntime):
    async def execute(self, argv, *, timeout=300, cwd=None, env=None) -> ExecutionResult:
        if not argv:
            raise ValueError("argv must not be empty")
        started = utcnow()
        command_id = uuid.uuid4().hex[:12]
        timed_out = False
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=cwd,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                exit_code = proc.returncode or 0
            except TimeoutError:
                proc.kill()
                await proc.wait()
                stdout_b, stderr_b = b"", b""
                exit_code = -1
                timed_out = True
        except FileNotFoundError as exc:
            return ExecutionResult(
                command_id=command_id,
                tool_name=argv[0],
                argv=argv,
                started_at=started,
                completed_at=utcnow(),
                exit_code=127,
                stderr=str(exc),
                timed_out=False,
            )
        return ExecutionResult(
            command_id=command_id,
            tool_name=argv[0],
            argv=argv,
            started_at=started,
            completed_at=utcnow(),
            exit_code=exit_code,
            stdout=stdout_b.decode(errors="replace"),
            stderr=stderr_b.decode(errors="replace"),
            timed_out=timed_out,
        )

    async def is_available(self) -> bool:
        return True

    @staticmethod
    def which(binary: str) -> str | None:
        return shutil.which(binary)
