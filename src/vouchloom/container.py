"""Container-backed SandboxBackend: docker exec with host-visible work dirs.

M0 of the pentest module plan: the agent executes inside a long-lived
pentest container (Kali) that offers mature tooling, while every command
still lands in the same ``CommandReceipt`` evidence chain. Two pieces:

- ``DockerExecutor``: minimal ``docker exec`` transport (swap for kubectl /
  podman later). Timeouts are enforced *inside* the container via
  ``coreutils timeout`` — killing only the host-side docker CLI would leave
  the container process running as an orphan.
- ``ContainerSandbox``: ``SandboxBackend`` implementation. The host runs
  root (bind-mounted into the container at ``container_root``); task work
  dirs are subdirectories of it, so artifact gates that inspect
  ``work_root`` from the host keep working unchanged.

Network containment is the real scope backstop: run the pentest container
on an ``internal: true`` compose network that only reaches the target. The
``ScopePolicy`` here stays as the auditable first gate (same exit-126
semantics as ``ScopeGuardedSandbox``), not the only line of defense.
"""

from __future__ import annotations

import asyncio
import math
import shlex
import time
from pathlib import Path
from typing import Protocol

from vouchloom.receipts import CommandReceipt
from vouchloom.tools import ScopePolicy

DOCKER_GRACE_SECONDS = 15.0


class ContainerExecutor(Protocol):
    """Transport running one shell command inside the pentest container."""

    async def exec(
        self,
        command: str,
        *,
        timeout_seconds: float = 120.0,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[str, int]:
        """Return ``(merged_stdout_stderr, exit_code)``; 124 means timeout."""
        ...


class DockerExecutor:
    """``docker exec <container> sh -c <command>`` transport."""

    def __init__(self, container: str, *, docker_bin: str = "docker") -> None:
        self.container = container
        self.docker_bin = docker_bin

    async def exec(
        self,
        command: str,
        *,
        timeout_seconds: float = 120.0,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[str, int]:
        argv = [self.docker_bin, "exec", "-i"]
        for key, value in (env or {}).items():
            argv += ["-e", f"{key}={value}"]
        if cwd:
            argv += ["-w", str(cwd)]
        inner = (
            "timeout --signal=KILL "
            f"{max(1, int(math.ceil(timeout_seconds)))}s sh -c {shlex.quote(command)}"
        )
        argv += [self.container, "sh", "-c", inner]
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_seconds + DOCKER_GRACE_SECONDS
            )
            code = proc.returncode if proc.returncode is not None else -1
            output = stdout.decode("utf-8", errors="replace")
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            return f"[container exec timed out after {timeout_seconds}s]", 124
        # coreutils timeout exits 137 under --signal=KILL; unify to 124.
        if code in (124, 137):
            return output, 124
        return output, code


class ContainerSandbox:
    """SandboxBackend executing commands inside the pentest container.

    The host-side ``work_root`` must live under ``mount_root`` (the directory
    bind-mounted into the container at ``container_root``); the container-side
    working directory is derived from that relationship, so relative artifact
    paths written in the container appear at identical relative paths on the
    host and the runtime's artifact gates keep working unchanged.
    """

    def __init__(
        self,
        work_root: Path,
        *,
        executor: ContainerExecutor,
        mount_root: Path,
        container_root: str = "/work",
        policy: ScopePolicy | None = None,
    ) -> None:
        self._work_root = work_root.expanduser().resolve()
        self._work_root.mkdir(parents=True, exist_ok=True)
        mount = Path(mount_root).expanduser().resolve()
        if not self._work_root.is_relative_to(mount):
            raise ValueError(
                f"work_root {self._work_root} is not under mount_root {mount}; "
                "it cannot be visible inside the container"
            )
        rel = self._work_root.relative_to(mount)
        self._container_cwd = str(Path(container_root) / rel)
        self._executor = executor
        self.policy = policy

    @property
    def work_root(self) -> Path:
        return self._work_root

    async def execute_command(
        self, command: str, *, sequence: int, timeout_seconds: float = 120.0
    ) -> CommandReceipt:
        started = time.monotonic_ns()
        if self.policy is not None:
            violations = self.policy.command_violations(command)
            if violations:
                return CommandReceipt.from_execution(
                    tool_name="sandbox_shell",
                    sequence=sequence,
                    command=command,
                    output="scope violation: " + "; ".join(violations),
                    exit_code=126,
                )
        output, exit_code = await self._executor.exec(
            command, timeout_seconds=timeout_seconds, cwd=self._container_cwd
        )
        duration_ms = (time.monotonic_ns() - started) // 1_000_000
        return CommandReceipt.from_execution(
            tool_name="sandbox_shell",
            sequence=sequence,
            command=command,
            output=output,
            exit_code=exit_code,
            duration_ms=duration_ms,
        )

    async def aclose(self) -> None:
        return None


__all__ = ["ContainerExecutor", "ContainerSandbox", "DockerExecutor"]
