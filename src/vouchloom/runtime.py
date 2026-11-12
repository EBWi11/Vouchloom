"""Protocol-first Agent Runtime, Sandbox Command Interceptor, and JSON Repair FSM.

Preserves bug_hunter/codex_runtime.py's battle-tested turn mechanics while
decoupling ModelBackend (OpenAI-compatible HTTP / Mock / Codex stdio) and
SandboxBackend (local workdir / container command execution):
- RequestBudget preflight gate before every model invocation
- Zero-telemetry fresh-thread auto-retry (<=2 retries)
- Live [token_budget] & artifact-deadline steering after completed tool calls
- Immediate SHA-256 snapshot & finalization when required_artifact_path is written
- Hard artifact_deadline_missed abort & tool_boundary_finalization
- Branch conflict resolution (source + handoff -> handoff)
- Two-stage typed output repair: in-thread repair -> isolated tool-free Pure JSON Agent
- DebugAgentRuntime hash-linked audit wrapper.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

import httpx

from vouchloom.agent import (
    MAX_ARTIFACT_BYTES,
    AgentDefinition,
    AgentRuntimeError,
    AgentTrace,
    WorkerModelOutput,
    compact_json_schema,
)
from vouchloom.audit import write_debug_event
from vouchloom.models import ModelUsage, add_usage
from vouchloom.receipts import CommandReceipt

MAX_ZERO_TELEMETRY_RETRIES = 2
MAX_SAME_THREAD_REPAIR_ATTEMPTS = 2
MAX_CONSECUTIVE_IDENTICAL_FAILURES = 2
PURE_JSON_AGENT_MAX_TOTAL_TOKENS = 64_000


@dataclass(frozen=True)
class ModelTurnResponse:
    """Normalized single response from any ModelBackend."""

    model_id: str
    usage: ModelUsage
    final_text: str | None = None
    tool_commands: tuple[str, ...] = ()
    # Named (non-shell) tool invocations, e.g. {"name": "http_request",
    # "arguments": {...}}. Dispatched by ManagedAgentRuntime to its
    # tool_gateway instead of the shell sandbox.
    tool_calls: tuple[dict[str, Any], ...] = ()
    finish_reason: str | None = None


class ModelBackend(Protocol):
    """Pluggable LLM transport (HTTP API, Codex stdio, or deterministic fake)."""

    async def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        output_schema: dict[str, Any],
        allow_tools: bool,
        max_output_tokens: int | None,
    ) -> ModelTurnResponse: ...

    async def aclose(self) -> None: ...


class SandboxBackend(Protocol):
    """Pluggable tool/shell sandbox returning cryptographic CommandReceipts."""

    @property
    def work_root(self) -> Path | None: ...

    async def execute_command(
        self, command: str, *, sequence: int, timeout_seconds: float = 120.0
    ) -> CommandReceipt: ...

    async def aclose(self) -> None: ...


class ToolGateway(Protocol):
    """Named (non-shell) tool dispatcher, e.g. structured HTTP requests."""

    def tool_schemas(self) -> list[dict[str, Any]]: ...

    async def execute(
        self, name: str, arguments: dict[str, Any], *, sequence: int
    ) -> CommandReceipt: ...

    async def aclose(self) -> None: ...


class LocalDirectorySandbox:
    """Isolated scratch sandbox capturing CommandReceipts & checking artifacts."""

    def __init__(
        self,
        work_root: Path,
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self._work_root = work_root.expanduser().resolve()
        self._work_root.mkdir(parents=True, exist_ok=True)
        self._cwd = (cwd or self._work_root).expanduser().resolve()
        self._env = env

    @property
    def work_root(self) -> Path:
        return self._work_root

    async def execute_command(
        self, command: str, *, sequence: int, timeout_seconds: float = 120.0
    ) -> CommandReceipt:
        started = time.monotonic_ns()
        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=str(self._cwd),
            env=self._env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_seconds
            )
            exit_code = proc.returncode if proc.returncode is not None else -1
            output = stdout_bytes.decode("utf-8", errors="replace")
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            exit_code = 124
            output = f"[command timed out after {timeout_seconds}s]"
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


class OpenAICompatibleModelBackend:
    """Standard OpenAI-compatible Chat Completions backend with optional shell tool."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float = 180.0,
        extra_tools: list[dict[str, Any]] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._extra_tools = list(extra_tools or [])
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout_seconds,
        )

    async def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        output_schema: dict[str, Any],
        allow_tools: bool,
        max_output_tokens: int | None,
    ) -> ModelTurnResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "vouchloom_typed_output",
                    "strict": False,
                    "schema": output_schema,
                },
            },
        }
        if max_output_tokens is not None:
            payload["max_tokens"] = max_output_tokens
        if allow_tools:
            shell_tool = {
                "type": "function",
                "function": {
                    "name": "sandbox_shell",
                    "description": (
                        "Execute one bounded shell command in the sandbox."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {"command": {"type": "string"}},
                        "required": ["command"],
                        "additionalProperties": False,
                    },
                },
            }
            payload["tools"] = [shell_tool, *self._extra_tools]
        resp = await self._client.post("/chat/completions", json=payload)
        resp.raise_for_status()
        body = resp.json()
        choice = (body.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        raw_usage = body.get("usage") or {}
        usage = ModelUsage(
            prompt_tokens=int(raw_usage.get("prompt_tokens") or 0),
            completion_tokens=int(raw_usage.get("completion_tokens") or 0),
            total_tokens=int(raw_usage.get("total_tokens") or 0),
        )
        commands: list[str] = []
        named_calls: list[dict[str, Any]] = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            if fn.get("name") == "sandbox_shell":
                args = json.loads(fn.get("arguments") or "{}")
                if isinstance(args.get("command"), str) and args["command"].strip():
                    commands.append(args["command"])
            elif fn.get("name"):
                named_calls.append(
                    {
                        "name": str(fn["name"]),
                        "arguments": json.loads(fn.get("arguments") or "{}"),
                    }
                )
        return ModelTurnResponse(
            model_id=str(body.get("model") or self.model),
            usage=usage,
            final_text=msg.get("content"),
            tool_commands=tuple(commands),
            tool_calls=tuple(named_calls),
            finish_reason=choice.get("finish_reason"),
        )

    async def aclose(self) -> None:
        await self._client.aclose()


class CodexAppServerBackend:
    """JSON-RPC stdio adapter for `codex app-server --stdio` (from bug_hunter)."""

    def __init__(
        self,
        command: list[str],
        *,
        model: str,
        cwd: Path,
        model_provider: str = "openai",
    ) -> None:
        self.command = list(command)
        self.model = model
        self.cwd = cwd.expanduser().resolve()
        self.model_provider = model_provider
        self._proc: asyncio.subprocess.Process | None = None
        self._next_id = 0

    async def _ensure_started(self) -> asyncio.subprocess.Process:
        if self._proc is not None and self._proc.returncode is None:
            return self._proc
        self._proc = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(self.cwd),
        )
        await self._rpc(
            "initialize", {"clientInfo": {"name": "vouchloom", "version": "0.1.0"}}
        )
        return self._proc

    async def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        assert self._proc is not None
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._next_id += 1
        req_id = self._next_id
        line = (
            json.dumps(
                {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
            )
            + "\n"
        )
        self._proc.stdin.write(line.encode("utf-8"))
        await self._proc.stdin.drain()
        while raw := await self._proc.stdout.readline():
            msg = json.loads(raw.decode("utf-8", errors="replace"))
            if msg.get("id") == req_id:
                if "error" in msg:
                    raise RuntimeError(f"codex rpc error: {msg['error']}")
                return dict(msg.get("result") or {})
        raise RuntimeError("codex app-server closed stdout before RPC response")

    async def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        output_schema: dict[str, Any],
        allow_tools: bool,
        max_output_tokens: int | None,
    ) -> ModelTurnResponse:
        proc = await self._ensure_started()
        assert proc.stdout is not None
        system_parts = [m["content"] for m in messages if m.get("role") == "system"]
        user_parts = [
            f"[{m.get('role')}]: {m.get('content')}"
            for m in messages
            if m.get("role") != "system"
        ]
        started = await self._rpc(
            "thread/start",
            {
                "model": self.model,
                "modelProvider": self.model_provider,
                "cwd": str(self.cwd),
                "approvalPolicy": "never",
                "baseInstructions": "\n\n".join(str(x) for x in system_parts),
                "ephemeral": True,
                "sandbox": "danger-full-access" if allow_tools else "read-only",
            },
        )
        thread_id = str((started.get("thread") or {}).get("id") or "")
        await self._rpc(
            "turn/start",
            {
                "threadId": thread_id,
                "input": [{"type": "text", "text": "\n\n".join(user_parts)}],
                "outputSchema": output_schema,
            },
        )
        usage = ModelUsage()
        final_text: str | None = None
        while raw := await proc.stdout.readline():
            msg = json.loads(raw.decode("utf-8", errors="replace"))
            method = msg.get("method")
            params = msg.get("params") or {}
            if method == "rawResponse/completed":
                u = params.get("usage") or {}
                usage = add_usage(
                    usage,
                    ModelUsage(
                        prompt_tokens=int(
                            u.get("inputTokens") or u.get("prompt_tokens") or 0
                        ),
                        completion_tokens=int(
                            u.get("outputTokens") or u.get("completion_tokens") or 0
                        ),
                        total_tokens=int(
                            u.get("totalTokens") or u.get("total_tokens") or 0
                        ),
                    ),
                )
            elif method == "item/completed":
                item = params.get("item") or {}
                if item.get("type") == "agentMessage":
                    final_text = item.get("text")
            elif method == "turn/completed":
                for item in (params.get("turn") or {}).get("items") or []:
                    if item.get("type") == "agentMessage" and item.get("text"):
                        final_text = item["text"]
                break
        return ModelTurnResponse(
            model_id=self.model,
            usage=usage,
            final_text=final_text,
            tool_commands=(),
            finish_reason="stop",
        )

    async def aclose(self) -> None:
        if self._proc is not None and self._proc.returncode is None:
            self._proc.terminate()
            await self._proc.wait()
        self._proc = None


def extract_json_object(raw_text: str) -> str:
    rendered = raw_text.strip()
    if rendered.startswith("```") and rendered.endswith("```"):
        rendered = "\n".join(rendered.splitlines()[1:-1]).strip()
    if rendered.startswith("{") and rendered.endswith("}"):
        return rendered
    start = rendered.find("{")
    end = rendered.rfind("}")
    if 0 <= start < end:
        return rendered[start : end + 1]
    return rendered


def _artifact_identity_on_disk(
    work_root: Path | None, rel_path: str | None
) -> dict[str, Any] | None:
    if work_root is None or rel_path is None:
        return None
    root = work_root.expanduser().resolve()
    unresolved = root / rel_path
    try:
        resolved = unresolved.resolve()
        if (
            not resolved.is_relative_to(root)
            or unresolved.is_symlink()
            or not resolved.is_file()
        ):
            return None
        size = resolved.stat().st_size
        if size < 1 or size > MAX_ARTIFACT_BYTES:
            return None
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    except OSError:
        return None
    return {
        "required_artifact_path": rel_path,
        "artifact_size": size,
        "artifact_sha256": digest,
    }


def _resolve_branch_conflict_to_handoff(
    output_model: type[Any],
    decoded: dict[str, Any] | None,
) -> Any | None:
    """Resolve branch conflict to handoff when both source and handoff exist."""

    if (
        output_model is not WorkerModelOutput
        or not isinstance(decoded, dict)
        or decoded.get("source") is None
        or not isinstance(decoded.get("handoff"), dict)
    ):
        return None
    try:
        return WorkerModelOutput.model_validate({"handoff": decoded["handoff"]})
    except ValueError:
        return None


class ManagedAgentRuntime:
    """Core runtime enforcing budgets, artifact gates, and 2-stage JSON repair."""

    def __init__(
        self,
        model_backend: ModelBackend,
        *,
        sandbox: SandboxBackend | None = None,
        tool_gateway: ToolGateway | None = None,
        enable_pure_json_repair: bool = True,
    ) -> None:
        self.model_backend = model_backend
        self.sandbox = sandbox
        self.tool_gateway = tool_gateway
        self.enable_pure_json_repair = enable_pure_json_repair

    async def run(self, definition: AgentDefinition, task: str) -> AgentTrace:
        if definition.max_total_tokens is None or definition.max_total_tokens < 1:
            raise AgentRuntimeError(
                "stages require a positive max_total_tokens budget",
                code="invalid_agent_definition",
            )
        retry_receipts: list[dict[str, Any]] = []
        for retry_idx in range(MAX_ZERO_TELEMETRY_RETRIES + 1):
            try:
                trace = await self._run_single_thread(definition, task)
                trace.request_receipts[:0] = retry_receipts
                return trace
            except AgentRuntimeError as error:
                zero_telemetry = (
                    error.code in {"transport_closed", "turn_wall_timeout"}
                    and error.model_calls == 0
                    and error.tool_calls == 0
                    and error.usage.total_tokens == 0
                )
                if not zero_telemetry or retry_idx >= MAX_ZERO_TELEMETRY_RETRIES:
                    error.request_receipts[:0] = retry_receipts
                    raise
                retry_receipts.append(
                    {
                        "status": "zero_telemetry_fresh_thread_retry",
                        "retry_number": retry_idx + 1,
                        "first_error_code": error.code,
                    }
                )
        raise AssertionError("unreachable zero-telemetry loop")

    async def _run_single_thread(
        self, definition: AgentDefinition, task: str
    ) -> AgentTrace:
        output_schema = compact_json_schema(definition.output_model.model_json_schema())
        skill_messages = [
            {
                "role": "user",
                "content": json.dumps(
                    {"selected_skill": s.name, "skill_md": s.read_text("SKILL.md")},
                    ensure_ascii=False,
                ),
            }
            for s in definition.skills
        ]
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": definition.system_prompt},
            *skill_messages,
            {"role": "user", "content": task},
        ]
        request_receipts: list[dict[str, Any]] = [
            {
                "status": "skill_installed",
                "skills": [s.name for s in definition.skills],
            }
        ]
        if definition.request_budget is not None:
            budget_eval = definition.request_budget.evaluate(
                messages=messages,
                tools=[{"type": "output_schema", "schema": output_schema}],
                json_mode=True,
            )
            request_receipts.append({"status": "context_budget", **budget_eval})
            if not budget_eval["fits"]:
                raise AgentRuntimeError(
                    "stage input exceeds configured context budget",
                    request_receipts=request_receipts,
                    code="context_budget_exceeded",
                )

        async def _loop() -> AgentTrace:
            usage = ModelUsage()
            model_calls = 0
            tool_calls = 0
            tool_rounds = 0
            model_id = "unknown"
            last_final_text: str | None = None
            command_receipts: list[CommandReceipt] = []
            finalization_mode = False
            artifact_materialized = False
            repair_attempts = 0
            prev_diag: str | None = None
            consecutive_same_diag = 0
            work_root = self.sandbox.work_root if self.sandbox is not None else None
            limit = definition.max_total_tokens or 1

            while True:
                allow_tools = (
                    definition.allow_tools
                    and (self.sandbox is not None or self.tool_gateway is not None)
                    and not finalization_mode
                )
                try:
                    resp = await self.model_backend.complete(
                        messages=messages,
                        output_schema=output_schema,
                        allow_tools=allow_tools,
                        max_output_tokens=definition.max_output_tokens,
                    )
                except Exception as transport_err:
                    raise AgentRuntimeError(
                        f"model transport failed: {transport_err}",
                        messages=messages,
                        tool_calls=tool_calls,
                        model_calls=model_calls,
                        tool_rounds=tool_rounds,
                        usage=usage,
                        model_id=model_id,
                        command_receipts=command_receipts,
                        request_receipts=request_receipts,
                        code="transport_closed",
                        last_final_text=last_final_text,
                    ) from transport_err

                model_calls += 1
                model_id = resp.model_id
                usage = add_usage(usage, resp.usage)
                if resp.final_text:
                    last_final_text = resp.final_text
                request_receipts.append(
                    {
                        "status": "model_response_completed",
                        "model_call": model_calls,
                        "usage": resp.usage.model_dump(mode="json"),
                    }
                )

                if not definition.allow_tools and (
                    resp.tool_commands or resp.tool_calls
                ):
                    raise AgentRuntimeError(
                        "tool-free stage attempted to invoke sandbox tools",
                        messages=messages,
                        tool_calls=tool_calls,
                        model_calls=model_calls,
                        tool_rounds=tool_rounds,
                        usage=usage,
                        model_id=model_id,
                        command_receipts=command_receipts,
                        request_receipts=request_receipts,
                        code="pure_json_tool_violation",
                        last_final_text=last_final_text,
                    )

                if resp.tool_calls and allow_tools and self.tool_gateway is not None:
                    tool_rounds += 1
                    messages.append(
                        {
                            "role": "assistant",
                            "content": resp.final_text
                            or json.dumps(
                                {"tool_calls": [dict(c) for c in resp.tool_calls]}
                            ),
                        }
                    )
                    for call in resp.tool_calls:
                        tool_calls += 1
                        tool_receipt = await self.tool_gateway.execute(
                            str(call.get("name") or ""),
                            dict(call.get("arguments") or {}),
                            sequence=tool_calls,
                        )
                        command_receipts.append(tool_receipt)
                        request_receipts.append(
                            {
                                "status": "tool_executed",
                                "tool": tool_receipt.tool_name,
                                "sequence": tool_receipt.sequence,
                                "command_sha256": tool_receipt.command_sha256,
                                "output_sha256": tool_receipt.output_sha256,
                                "exit_code": tool_receipt.exit_code,
                            }
                        )
                        messages.append(
                            {
                                "role": "tool",
                                "name": tool_receipt.tool_name,
                                "content": tool_receipt.model_dump_json(),
                            }
                        )
                        if (
                            definition.finalization_tool_calls is not None
                            and tool_calls >= definition.finalization_tool_calls
                            and not finalization_mode
                        ):
                            finalization_mode = True
                            request_receipts.append(
                                {
                                    "status": "tool_boundary_finalization",
                                    "tool_calls": tool_calls,
                                    "boundary": definition.finalization_tool_calls,
                                }
                            )
                            break

                if (
                    resp.tool_commands
                    and allow_tools
                    and self.sandbox is None
                    and self.tool_gateway is not None
                ):
                    raise AgentRuntimeError(
                        "shell tool invoked but no sandbox is configured",
                        messages=messages,
                        tool_calls=tool_calls,
                        model_calls=model_calls,
                        tool_rounds=tool_rounds,
                        usage=usage,
                        model_id=model_id,
                        command_receipts=command_receipts,
                        request_receipts=request_receipts,
                        code="sandbox_missing",
                        last_final_text=last_final_text,
                    )

                if resp.tool_commands and allow_tools and self.sandbox is not None:
                    tool_rounds += 1
                    messages.append(
                        {
                            "role": "assistant",
                            "content": resp.final_text
                            or json.dumps({"tool_commands": list(resp.tool_commands)}),
                        }
                    )
                    for cmd in resp.tool_commands:
                        tool_calls += 1
                        cmd_receipt = await self.sandbox.execute_command(
                            cmd, sequence=tool_calls
                        )
                        command_receipts.append(cmd_receipt)
                        request_receipts.append(
                            {
                                "status": "command_executed",
                                "sequence": cmd_receipt.sequence,
                                "command_sha256": cmd_receipt.command_sha256,
                                "output_sha256": cmd_receipt.output_sha256,
                                "exit_code": cmd_receipt.exit_code,
                            }
                        )
                        messages.append(
                            {
                                "role": "tool",
                                "name": "sandbox_shell",
                                "content": cmd_receipt.model_dump_json(),
                            }
                        )

                        # 1. Check artifact materialization immediately
                        if (
                            not artifact_materialized
                            and definition.required_artifact_path is not None
                        ):
                            ident = _artifact_identity_on_disk(
                                work_root, definition.required_artifact_path
                            )
                            if ident is not None:
                                artifact_materialized = True
                                finalization_mode = True
                                request_receipts.append(
                                    {
                                        "status": "artifact_materialized",
                                        "tool_calls": tool_calls,
                                        **ident,
                                    }
                                )
                                break

                        # 2. Check hard artifact deadline
                        if (
                            definition.required_artifact_path is not None
                            and definition.artifact_deadline_tool_calls is not None
                            and tool_calls >= definition.artifact_deadline_tool_calls
                            and _artifact_identity_on_disk(
                                work_root, definition.required_artifact_path
                            )
                            is None
                        ):
                            request_receipts.append(
                                {
                                    "status": "artifact_deadline_missed",
                                    "tool_calls": tool_calls,
                                    "deadline": definition.artifact_deadline_tool_calls,
                                }
                            )
                            raise AgentRuntimeError(
                                "executor missed its artifact creation deadline",
                                messages=messages,
                                tool_calls=tool_calls,
                                model_calls=model_calls,
                                tool_rounds=tool_rounds,
                                usage=usage,
                                model_id=model_id,
                                command_receipts=command_receipts,
                                request_receipts=request_receipts,
                                code="artifact_deadline_missed",
                                last_final_text=last_final_text,
                            )

                        # 3. Check opt-in tool boundary finalization
                        if (
                            definition.finalization_tool_calls is not None
                            and tool_calls >= definition.finalization_tool_calls
                            and not finalization_mode
                        ):
                            finalization_mode = True
                            request_receipts.append(
                                {
                                    "status": "tool_boundary_finalization",
                                    "tool_calls": tool_calls,
                                    "boundary": definition.finalization_tool_calls,
                                }
                            )
                            break

                    # 4. Sync cumulative token budget after shell round
                    if usage.total_tokens >= limit:
                        raise AgentRuntimeError(
                            "turn exhausted its total-token budget",
                            messages=messages,
                            tool_calls=tool_calls,
                            model_calls=model_calls,
                            tool_rounds=tool_rounds,
                            usage=usage,
                            model_id=model_id,
                            command_receipts=command_receipts,
                            request_receipts=request_receipts,
                            code="token_budget_exhausted",
                            last_final_text=last_final_text,
                        )
                    remaining = max(0, limit - usage.total_tokens)
                    avg = max(1, math.ceil(usage.total_tokens / model_calls))
                    reserve = min(
                        max(64_000, avg * 2, (definition.max_output_tokens or 0) * 3),
                        max(1, limit // 3),
                    )
                    if remaining <= reserve:
                        finalization_mode = True
                        request_receipts.append(
                            {
                                "status": "token_budget_finalization",
                                "remaining_tokens": remaining,
                                "reserve_tokens": reserve,
                            }
                        )
                    steer_note = (
                        f"[token_budget] used={usage.total_tokens}; "
                        f"remaining={remaining}; tool_calls={tool_calls}. "
                        + (
                            "FINALIZATION REQUIRED: stop tool use and emit the "
                            "final typed JSON object immediately."
                            if finalization_mode
                            else "Continue bounded work within remaining budget."
                        )
                    )
                    messages.append({"role": "user", "content": steer_note})
                    continue

                # No tool commands executed -> validate typed JSON output
                decoded: dict[str, Any] | None = None
                validation_err: Exception | None = None
                if not resp.final_text:
                    validation_err = ValueError("turn returned no final JSON message")
                else:
                    try:
                        parsed = json.loads(extract_json_object(resp.final_text))
                        if not isinstance(parsed, dict):
                            raise TypeError("typed result must be a JSON object")
                        decoded = parsed
                        validated = definition.output_model.model_validate(decoded)
                        if (
                            definition.required_artifact_path is not None
                            and _artifact_identity_on_disk(
                                work_root, definition.required_artifact_path
                            )
                            is None
                        ):
                            raise ValueError(
                                "required artifact was not persisted before typed "
                                f"result: /work/{definition.required_artifact_path}"
                            )
                        messages.append(
                            {"role": "assistant", "content": resp.final_text}
                        )
                        return AgentTrace(
                            agent_id=definition.id,
                            model_id=model_id,
                            messages=messages,
                            tool_calls=tool_calls,
                            usage=usage,
                            result=validated,
                            model_calls=model_calls,
                            tool_rounds=tool_rounds,
                            command_receipts=command_receipts,
                            request_receipts=request_receipts,
                        )
                    except Exception as caught:
                        validation_err = caught
                        request_receipts.append(
                            {
                                "status": "typed_result_validation_failed",
                                "error_type": type(caught).__name__,
                                "error": str(caught)[:400],
                            }
                        )

                # Branch conflict resolution (source + handoff -> handoff)
                resolved_conflict = _resolve_branch_conflict_to_handoff(
                    definition.output_model, decoded
                )
                if resolved_conflict is not None:
                    request_receipts.append(
                        {
                            "status": "typed_result_branch_conflict_resolved",
                            "selected_branch": "handoff",
                        }
                    )
                    return AgentTrace(
                        agent_id=definition.id,
                        model_id=model_id,
                        messages=messages,
                        tool_calls=tool_calls,
                        usage=usage,
                        result=resolved_conflict,
                        model_calls=model_calls,
                        tool_rounds=tool_rounds,
                        command_receipts=command_receipts,
                        request_receipts=request_receipts,
                    )

                diag = f"{type(validation_err).__name__}:{validation_err}"
                if diag == prev_diag:
                    consecutive_same_diag += 1
                else:
                    prev_diag = diag
                    consecutive_same_diag = 1

                use_pure_json = (
                    self.enable_pure_json_repair
                    and definition.allow_tools
                    and bool(last_final_text)
                    and (
                        consecutive_same_diag >= MAX_CONSECUTIVE_IDENTICAL_FAILURES
                        or repair_attempts >= MAX_SAME_THREAD_REPAIR_ATTEMPTS
                        or usage.total_tokens >= limit
                    )
                )
                if use_pure_json:
                    request_receipts.append({"status": "pure_json_agent_started"})
                    repaired = await self._run_pure_json_repair(
                        definition,
                        draft=last_final_text or "",
                        error=validation_err or ValueError("invalid JSON"),
                    )
                    return AgentTrace(
                        agent_id=definition.id,
                        model_id=repaired.model_id,
                        messages=[*messages, *repaired.messages],
                        tool_calls=tool_calls,
                        usage=add_usage(usage, repaired.usage),
                        result=repaired.result,
                        model_calls=model_calls + repaired.model_calls,
                        tool_rounds=tool_rounds,
                        command_receipts=command_receipts,
                        request_receipts=[
                            *request_receipts,
                            {"status": "pure_json_agent_completed"},
                            *repaired.request_receipts,
                        ],
                    )

                if usage.total_tokens >= limit:
                    raise AgentRuntimeError(
                        "typed result repair exhausted total-token budget",
                        messages=messages,
                        tool_calls=tool_calls,
                        model_calls=model_calls,
                        tool_rounds=tool_rounds,
                        usage=usage,
                        model_id=model_id,
                        command_receipts=command_receipts,
                        request_receipts=request_receipts,
                        code="token_budget_exhausted",
                        last_final_text=last_final_text,
                    )
                if repair_attempts >= MAX_SAME_THREAD_REPAIR_ATTEMPTS:
                    raise AgentRuntimeError(
                        "typed result repair exhausted attempt limit: "
                        f"{validation_err}",
                        messages=messages,
                        tool_calls=tool_calls,
                        model_calls=model_calls,
                        tool_rounds=tool_rounds,
                        usage=usage,
                        model_id=model_id,
                        command_receipts=command_receipts,
                        request_receipts=request_receipts,
                        code="typed_result_repair_exhausted",
                        last_final_text=last_final_text,
                    )
                repair_attempts += 1
                finalization_mode = True
                if resp.final_text:
                    messages.append({"role": "assistant", "content": resp.final_text})
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Your previous JSON output failed schema validation: "
                            f"{validation_err}. Return ONLY a valid JSON object "
                            "matching the schema without invoking tools."
                        ),
                    }
                )

        if definition.max_turn_seconds is None:
            return await _loop()
        try:
            return await asyncio.wait_for(_loop(), timeout=definition.max_turn_seconds)
        except TimeoutError as timeout_err:
            raise AgentRuntimeError(
                "turn exceeded its wall-clock limit",
                request_receipts=request_receipts,
                code="turn_wall_timeout",
            ) from timeout_err

    async def _run_pure_json_repair(
        self,
        parent_def: AgentDefinition,
        *,
        draft: str,
        error: Exception,
    ) -> AgentTrace:
        repair_def = AgentDefinition(
            id=f"{parent_def.id}.pure-json-repair",
            version=parent_def.version,
            system_prompt=(
                "You are a tool-free JSON schema repair agent. Convert the supplied "
                "draft into a valid JSON object satisfying outputSchema without "
                "inventing new facts or calling tools."
            ),
            output_model=parent_def.output_model,
            max_total_tokens=PURE_JSON_AGENT_MAX_TOTAL_TOKENS,
            max_output_tokens=parent_def.max_output_tokens,
            allow_tools=False,
        )
        repair_runtime = ManagedAgentRuntime(
            self.model_backend,
            sandbox=None,
            enable_pure_json_repair=False,
        )
        return await repair_runtime.run(
            repair_def,
            json.dumps({"validation_error": str(error), "draft": draft}),
        )

    async def release(self) -> None:
        """Close per-run resources only; the (possibly shared) backend stays open."""
        if self.sandbox is not None:
            await self.sandbox.aclose()

    async def aclose(self) -> None:
        await self.model_backend.aclose()
        await self.release()


class DebugAgentRuntime:
    """Hash-linked redacting audit wrapper around any ManagedAgentRuntime."""

    def __init__(self, runtime: ManagedAgentRuntime, debug_dir: Path) -> None:
        self.runtime = runtime
        self.debug_dir = debug_dir

    async def run(self, definition: AgentDefinition, task: str) -> AgentTrace:
        debug_def = replace(definition, debug_capture=True)
        started = time.monotonic_ns()
        write_debug_event(
            self.debug_dir,
            stage=definition.id,
            event="agent_started",
            payload={
                "agent_id": definition.id,
                "output_model": definition.output_model.__name__,
                "task_sha256": hashlib.sha256(task.encode("utf-8")).hexdigest(),
            },
        )
        try:
            trace = await self.runtime.run(debug_def, task)
        except AgentRuntimeError as error:
            write_debug_event(
                self.debug_dir,
                stage=definition.id,
                event="agent_failed",
                payload={
                    "error": str(error),
                    "code": error.code,
                    "model_calls": error.model_calls,
                    "tool_calls": error.tool_calls,
                    "usage": error.usage,
                    "command_receipts": error.command_receipts,
                    "request_receipts": error.request_receipts,
                    "duration_ms": (time.monotonic_ns() - started) // 1_000_000,
                },
            )
            raise
        write_debug_event(
            self.debug_dir,
            stage=definition.id,
            event="agent_completed",
            payload={
                "model_id": trace.model_id,
                "model_calls": trace.model_calls,
                "tool_calls": trace.tool_calls,
                "usage": trace.usage,
                "command_receipts": trace.command_receipts,
                "request_receipts": trace.request_receipts,
                "result": trace.result,
                "duration_ms": (time.monotonic_ns() - started) // 1_000_000,
            },
        )
        return trace

    async def aclose(self) -> None:
        await self.runtime.aclose()
