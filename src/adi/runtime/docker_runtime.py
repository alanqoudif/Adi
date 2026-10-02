"""DockerKaliRuntime: the default, isolated execution environment.

Tools run inside a container built from `runtime.image` (see
`docker/Dockerfile.kali`), with only a per-assessment workspace directory
mounted — never the user's home directory, SSH keys, browser profile, or the
Docker socket. If Docker is not available, `is_available()` returns False
honestly; callers must not fabricate successful output when that happens
(see spec section 87 — never fake tool success).
"""

from __future__ import annotations

import uuid

from adi.runtime.process import ExecutionResult, ExecutionRuntime, utcnow

try:
    from docker.errors import DockerException

    import docker

    _DOCKER_SDK_AVAILABLE = True
except ImportError:  # the `docker` extra is optional
    _DOCKER_SDK_AVAILABLE = False


class DockerUnavailableError(RuntimeError):
    pass


class DockerKaliRuntime(ExecutionRuntime):
    def __init__(self, image: str = "adi-kali:latest", workspace_dir: str | None = None,
                 network_mode: str = "bridge", mem_limit: str = "1g", pids_limit: int = 256):
        self.image = image
        self.workspace_dir = workspace_dir
        self.network_mode = network_mode
        self.mem_limit = mem_limit
        self.pids_limit = pids_limit
        self._client = None

    def _get_client(self):
        if not _DOCKER_SDK_AVAILABLE:
            raise DockerUnavailableError(
                "the 'docker' Python package is not installed (pip install adi[docker])"
            )
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    async def is_available(self) -> bool:
        if not _DOCKER_SDK_AVAILABLE:
            return False
        try:
            client = self._get_client()
            client.ping()
            client.images.get(self.image)
            return True
        except Exception:  # noqa: BLE001 - optional Docker SDK and transport exception boundary
            return False

    async def execute(self, argv, *, timeout=300, cwd=None, env=None) -> ExecutionResult:
        if not argv:
            raise ValueError("argv must not be empty")
        started = utcnow()
        command_id = uuid.uuid4().hex[:12]
        client = self._get_client()

        volumes = {}
        if self.workspace_dir:
            volumes[self.workspace_dir] = {"bind": "/workspace", "mode": "rw"}

        try:
            container = client.containers.run(
                self.image,
                argv,
                detach=True,
                network_mode=self.network_mode,
                mem_limit=self.mem_limit,
                pids_limit=self.pids_limit,
                read_only=False,
                security_opt=["no-new-privileges"],
                cap_drop=["ALL"],
                volumes=volumes or None,
                working_dir="/workspace" if volumes else None,
                environment=env,
            )
        except DockerException as exc:
            return ExecutionResult(
                command_id=command_id, tool_name=argv[0], argv=argv,
                started_at=started, completed_at=utcnow(), exit_code=1,
                stderr=f"docker error: {exc}", timed_out=False,
            )

        timed_out = False
        try:
            result = container.wait(timeout=timeout)
            exit_code = result.get("StatusCode", 1)
        except Exception:  # noqa: BLE001 - optional Docker SDK and transport exception boundary
            timed_out = True
            exit_code = -1
            container.kill()
        finally:
            logs = container.logs(stdout=True, stderr=False) if not timed_out else b""
            errs = container.logs(stdout=False, stderr=True) if not timed_out else b""
            container.remove(force=True)

        return ExecutionResult(
            command_id=command_id,
            tool_name=argv[0],
            argv=argv,
            started_at=started,
            completed_at=utcnow(),
            exit_code=exit_code,
            stdout=logs.decode(errors="replace") if logs else "",
            stderr=errs.decode(errors="replace") if errs else "",
            timed_out=timed_out,
        )
