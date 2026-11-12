"""Container backend: path mapping, scope gate, receipt parity with sandbox."""

from __future__ import annotations

from pathlib import Path

import pytest

from vouchloom import ContainerSandbox, ScopePolicy


class FakeExecutor:
    """Records what would be docker-exec'd; returns canned output."""

    def __init__(self, *, output: str = "ok", exit_code: int = 0) -> None:
        self.output = output
        self.exit_code = exit_code
        self.calls: list[dict] = []

    async def exec(
        self,
        command: str,
        *,
        timeout_seconds: float = 120.0,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[str, int]:
        self.calls.append(
            {
                "command": command,
                "timeout_seconds": timeout_seconds,
                "cwd": cwd,
                "env": env,
            }
        )
        return self.output, self.exit_code


def test_container_cwd_maps_work_root_under_mount(tmp_path: Path) -> None:
    mount = tmp_path / "runs"
    sandbox = ContainerSandbox(
        mount / "task1",
        executor=FakeExecutor(),
        mount_root=mount,
        container_root="/runs",
    )
    assert sandbox.work_root == (mount / "task1").resolve()
    assert sandbox._container_cwd == "/runs/task1"


def test_container_cwd_is_mount_root_when_equal(tmp_path: Path) -> None:
    sandbox = ContainerSandbox(
        tmp_path,
        executor=FakeExecutor(),
        mount_root=tmp_path,
        container_root="/runs",
    )
    assert sandbox._container_cwd == "/runs"


def test_container_rejects_work_root_outside_mount(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not under mount_root"):
        ContainerSandbox(
            tmp_path / "elsewhere",
            executor=FakeExecutor(),
            mount_root=tmp_path / "runs",
            container_root="/runs",
        )


@pytest.mark.asyncio
async def test_execute_command_uses_mapped_cwd(tmp_path: Path) -> None:
    executor = FakeExecutor(output="hello from container")
    sandbox = ContainerSandbox(
        tmp_path / "runs" / "task",
        executor=executor,
        mount_root=tmp_path / "runs",
        container_root="/runs",
    )
    receipt = await sandbox.execute_command("echo hi", sequence=3)
    assert len(executor.calls) == 1
    call = executor.calls[0]
    assert call["command"] == "echo hi"
    assert call["cwd"] == "/runs/task"
    assert receipt.tool_name == "sandbox_shell"
    assert receipt.exit_code == 0
    assert receipt.output == "hello from container"
    assert receipt.sequence == 3


@pytest.mark.asyncio
async def test_scope_violation_never_reaches_container(tmp_path: Path) -> None:
    executor = FakeExecutor()
    policy = ScopePolicy(allowed_hosts={"target"})
    sandbox = ContainerSandbox(
        tmp_path,
        executor=executor,
        mount_root=tmp_path,
        container_root="/runs",
        policy=policy,
    )
    receipt = await sandbox.execute_command(
        "curl -s http://evil.example.com/", sequence=1
    )
    assert receipt.exit_code == 126
    assert "scope violation" in receipt.output
    assert executor.calls == []  # blocked before docker exec


@pytest.mark.asyncio
async def test_executor_timeout_surfaces_as_exit_124(tmp_path: Path) -> None:
    sandbox = ContainerSandbox(
        tmp_path,
        executor=FakeExecutor(output="partial", exit_code=124),
        mount_root=tmp_path,
        container_root="/runs",
    )
    receipt = await sandbox.execute_command(
        "nmap -p 1-1000 target", sequence=1, timeout_seconds=30.0
    )
    assert receipt.exit_code == 124
    assert receipt.output == "partial"


@pytest.mark.asyncio
async def test_receipt_digest_chain_stays_canonical(tmp_path: Path) -> None:
    """Container receipts verify against the same digest rules as local ones."""
    sandbox = ContainerSandbox(
        tmp_path,
        executor=FakeExecutor(output="ok"),
        mount_root=tmp_path,
        container_root="/runs",
    )
    receipt = await sandbox.execute_command("uname -a", sequence=1)
    # CommandReceipt.from_execution already enforces canonical digest via
    # its model validator; round-trip parse proves the same envelope.
    from vouchloom.receipts import CommandReceipt

    again = CommandReceipt.model_validate_json(receipt.model_dump_json())
    assert again.sha256 == receipt.sha256
