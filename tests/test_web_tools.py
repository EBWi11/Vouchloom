"""Web tool layer: scope policy, HTTP gateway receipts, runtime dispatch."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from vouchloom import (
    AgentDefinition,
    HttpRequestGateway,
    ManagedAgentRuntime,
    ModelTurnResponse,
    ModelUsage,
    ScopeGuardedSandbox,
    ScopePolicy,
)
from vouchloom.runtime import LocalDirectorySandbox
from vouchloom.tools import HTTP_REQUEST_TOOL_SCHEMA


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/echo?"):
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({"path": self.path, "server": "planted/1.0"}).encode()
            )
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")

    def log_message(self, *args: Any) -> None:
        return None


@pytest.fixture()
def target_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.mark.asyncio
async def test_scope_policy_allows_and_blocks(target_server: str) -> None:
    from urllib.parse import urlsplit

    host = urlsplit(target_server).hostname
    policy = ScopePolicy(allowed_hosts={host})
    assert policy.check_url(f"{target_server}/echo?x=1") is None
    assert "not in scope" in (policy.check_url("http://evil.example.com/") or "")
    assert "scheme" in (policy.check_url("ftp://host/") or "")


def test_scope_policy_check_target_bare_host_forms() -> None:
    policy = ScopePolicy(allowed_hosts={"target", "10.0.0.5"})
    assert policy.check_target("target") is None
    assert policy.check_target("target:18080") is None
    assert policy.check_target("10.0.0.5/24") is None  # CIDR base name
    assert policy.check_target("user@target") is None
    assert policy.check_target("http://target:18080/") is None  # delegates
    assert "not in scope" in (policy.check_target("evil.example.com") or "")
    assert "not in scope" in (policy.check_target("10.0.0.9:8080") or "")
    assert policy.check_target("") == "empty target"


@pytest.mark.asyncio
async def test_http_gateway_receipt_structure(target_server: str) -> None:
    from urllib.parse import urlsplit

    policy = ScopePolicy(allowed_hosts={urlsplit(target_server).hostname})
    gateway = HttpRequestGateway(policy=policy)
    receipt = await gateway.execute(
        "http_request",
        {"method": "GET", "url": f"{target_server}/echo?x=1"},
        sequence=1,
    )
    assert receipt.tool_name == "http_request"
    assert receipt.exit_code == 0
    payload = json.loads(receipt.output)
    assert payload["status_code"] == 200
    assert json.loads(payload["body"])["server"] == "planted/1.0"
    # command field is canonical replayable JSON
    req = json.loads(receipt.command)
    assert req["method"] == "GET" and req["url"].endswith("/echo?x=1")
    await gateway.aclose()


@pytest.mark.asyncio
async def test_http_gateway_scope_violation_is_rejected_with_receipt(
    target_server: str,
) -> None:
    policy = ScopePolicy(allowed_hosts={"127.0.0.1"})  # ports unconstrained
    gateway = HttpRequestGateway(policy=policy)
    receipt = await gateway.execute(
        "http_request",
        {"method": "GET", "url": "http://evil.example.com/steal"},
        sequence=1,
    )
    assert receipt.exit_code == 126
    assert "scope violation" in receipt.output
    await gateway.aclose()


@pytest.mark.asyncio
async def test_scope_guarded_sandbox_blocks_out_of_scope_curl(tmp_path: Path) -> None:
    policy = ScopePolicy(allowed_hosts={"127.0.0.1"})
    sandbox = ScopeGuardedSandbox(tmp_path, policy=policy)
    receipt = await sandbox.execute_command(
        "curl -s http://evil.example.com/", sequence=1
    )
    assert receipt.exit_code == 126
    assert "scope violation" in receipt.output
    ok = await sandbox.execute_command("echo harmless", sequence=2)
    assert ok.exit_code == 0


class _ScriptedHttpBackend:
    """One http_request tool call, then a final typed answer."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.saw_tool_receipt = False
        self.declared_tools: list[dict[str, Any]] | None = None

    async def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        output_schema: dict[str, Any],
        allow_tools: bool,
        max_output_tokens: int | None,
    ) -> ModelTurnResponse:
        if allow_tools and not any(m.get("role") == "tool" for m in messages):
            return ModelTurnResponse(
                model_id="fake",
                usage=ModelUsage(total_tokens=10),
                tool_calls=(
                    {
                        "name": "http_request",
                        "arguments": {"method": "GET", "url": self.url},
                    },
                ),
            )
        if any(m.get("role") == "tool" for m in messages):
            self.saw_tool_receipt = True
        return ModelTurnResponse(
            model_id="fake",
            usage=ModelUsage(total_tokens=10),
            final_text=json.dumps({"answer": "done"}),
        )

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_runtime_dispatches_named_tool_and_feeds_receipt_back(
    tmp_path: Path, target_server: str
) -> None:
    from urllib.parse import urlsplit

    from pydantic import BaseModel

    class Out(BaseModel):
        answer: str

    policy = ScopePolicy(allowed_hosts={urlsplit(target_server).hostname})
    gateway = HttpRequestGateway(policy=policy)
    backend = _ScriptedHttpBackend(f"{target_server}/echo?probe=1")
    runtime = ManagedAgentRuntime(
        backend,
        sandbox=LocalDirectorySandbox(tmp_path),
        tool_gateway=gateway,
    )
    trace = await runtime.run(
        AgentDefinition(
            id="probe",
            version="1",
            system_prompt="Use the tools.",
            output_model=Out,
            max_total_tokens=1_000,
            finalization_tool_calls=4,
        ),
        "probe the target",
    )
    assert backend.saw_tool_receipt
    assert trace.tool_calls == 1
    receipt = trace.command_receipts[0]
    assert receipt.tool_name == "http_request"
    assert json.loads(receipt.output)["status_code"] == 200
    await gateway.aclose()


def test_http_request_tool_schema_shape() -> None:
    fn = HTTP_REQUEST_TOOL_SCHEMA["function"]
    assert fn["name"] == "http_request"
    assert set(fn["parameters"]["required"]) == {"method", "url"}
