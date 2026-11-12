"""Live-LLM benchmark for Vouchloom against a fully simulated range.

Nothing is executed on the host: the sandbox returns canned outputs keyed by
command keywords, and the evaluator is a deterministic in-process oracle. Only
the model backend talks to a real OpenAI-compatible endpoint.

Configuration (never hard-code credentials):
  VOUCHLOOM_LLM_BASE_URL      e.g. https://<gateway>/v1
  VOUCHLOOM_LLM_API_KEY_FILE  path to a file holding the key (or VOUCHLOOM_LLM_API_KEY)
  VOUCHLOOM_LLM_MODEL         model id

Usage:
  uv run python benchmarks/live_llm_benchmark.py [--suite quick|all|json|tools|team]
                                                 [--repeat N]

  The default "quick" suite runs only the single-agent json/tools cases (about a
  minute). The multi-agent team suite takes minutes per run; use --suite team
  or --suite all to include it.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from vouchloom import (
    AgentDefinition,
    ExecutionReceipt,
    GuardClause,
    ManagedAgentRuntime,
    OpenAICompatibleModelBackend,
    RouteSummary,
    StateMachineRegistry,
    StateMachineSpec,
    StateNodeSpec,
    TaskMemoryStore,
    TeamOrchestrator,
    TransitionSpec,
    TriggerPredicate,
    TwoTierObserver,
)
from vouchloom.receipts import CommandReceipt

SECRET_TOKEN = "VLM-7Q3K-ALPHA"

# ---------------------------------------------------------------- simulated range


class SimulatedRangeSandbox:
    """Keyword-routed canned shell. Never spawns a process."""

    def __init__(
        self,
        routes: list[tuple[tuple[str, ...], RouteOutput, int]],
        work_root=None,
    ):
        self._routes = routes
        self._work_root = work_root
        self.commands: list[str] = []

    @property
    def work_root(self) -> Path | None:
        return self._work_root

    async def execute_command(
        self, command: str, *, sequence: int, timeout_seconds: float = 120.0
    ) -> CommandReceipt:
        self.commands.append(command)
        low = command.lower()
        # Compound commands (`a; b && c`) get the output of every matching
        # route, so a scan and a fetch on one line both report back.
        hits = [
            route(command) if callable(route) else (route, rc)
            for keywords, route, rc in self._routes
            if any(k in low for k in keywords)
        ]
        if not hits:
            output, code = "simulated range: command not available\n", 127
        else:
            output = "".join(out for out, _ in hits)
            code = max(rc for _, rc in hits)
        return CommandReceipt.from_execution(
            tool_name="sandbox_shell",
            sequence=sequence,
            command=command,
            output=output,
            exit_code=code,
        )

    async def aclose(self) -> None:
        return None


OPEN_PORT = 8080


def _http_route(command: str) -> tuple[str, int]:
    """Only the open port answers; any other explicit port refuses."""
    ports = {int(p) for p in re.findall(r":(\d{2,5})\b", command)}
    if ports and OPEN_PORT not in ports:
        return "curl: (7) Failed to connect: Connection refused\n", 7
    return (
        "HTTP/1.1 200 OK\nserver: uvicorn\nx-powered-by: fastapi\n"
        f"x-debug-token: {SECRET_TOKEN}\ncontent-type: application/json\n\n"
        '{"status":"ok","docs":"/docs"}\n',
        0,
    )


def _tcp_probe_route(command: str) -> tuple[str, int]:
    return (f"OPEN {OPEN_PORT}\n" if str(OPEN_PORT) in command else ""), 0


RouteOutput = str | Callable[[str], tuple[str, int]]

RANGE_ROUTES: list[tuple[tuple[str, ...], RouteOutput, int]] = [
    (("curl", "http", "wget", "header"), _http_route, 0),
    (("/dev/tcp",), _tcp_probe_route, 0),
    (
        ("nmap", "scan", "port", "netstat", "ss ", "nc "),
        f"PORT     STATE SERVICE\n{OPEN_PORT}/tcp open  http (uvicorn / fastapi)\n"
        "22/tcp   closed ssh\n",
        0,
    ),
    (("ls ", "find ", "cat ", "pwd"), "README.range\n", 0),
]


class RangeOracle:
    """Deterministic evaluator: milestone iff artifact carries the debug token."""

    def __init__(self) -> None:
        self.calls = 0

    async def evaluate_candidate(
        self, content: bytes, *, route: RouteSummary, is_replay: bool = False
    ) -> ExecutionReceipt:
        self.calls += 1
        hit = SECRET_TOKEN.encode() in content
        return ExecutionReceipt.build(
            subject_sha256=hashlib.sha256(content).hexdigest(),
            output="token accepted: milestone" if hit else "token rejected",
            exit_code=77 if hit else 0,
            observed_target="svc.8080",
            phase="target_runtime",
            input_consumption="observed",
            fingerprint_sha256=hashlib.sha256(b"milestone").hexdigest()
            if hit
            else None,
        )


# ---------------------------------------------------------------- result model


@dataclass
class CaseResult:
    suite: str
    case: str
    ok: bool
    seconds: float
    total_tokens: int = 0
    model_calls: int = 0
    tool_calls: int = 0
    detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------- suite: json


class Extraction(BaseModel):
    service: str
    port: int
    severity: str


JSON_CASES = [
    (
        "log-extract",
        "Log line: '2026-11-01 WARN gateway payments-api listening on :9431 "
        "with TLS disabled'. Extract service, port, and a severity in "
        "{low,medium,high}.",
        lambda o: o.service.startswith("payments") and o.port == 9431,
    ),
    (
        "nested-text",
        "Ticket: The inventory service (port 7002) leaks stack traces to "
        "anonymous users. Extract service, port and severity in {low,medium,high}.",
        lambda o: "inventory" in o.service and o.port == 7002,
    ),
    (
        "distractor",
        "Ports 80 and 443 belong to nginx; the admin-console runs on 8800 and "
        "has no auth. Extract the admin-console's service, port, severity "
        "in {low,medium,high}.",
        lambda o: "admin" in o.service and o.port == 8800 and o.severity == "high",
    ),
]


async def run_json_suite(backend) -> list[CaseResult]:
    rt = ManagedAgentRuntime(backend)
    out: list[CaseResult] = []
    for name, task, check in JSON_CASES:
        d = AgentDefinition(
            id=f"json-{name}",
            version="1",
            system_prompt="Return only the JSON object required by the schema.",
            output_model=Extraction,
            allow_tools=False,
            max_total_tokens=16_000,
            max_output_tokens=2_000,
        )
        t0 = time.monotonic()
        try:
            tr = await rt.run(d, task)
            ok = bool(check(tr.result))
            out.append(
                CaseResult(
                    "json",
                    name,
                    ok,
                    time.monotonic() - t0,
                    tr.usage.total_tokens,
                    tr.model_calls,
                    tr.tool_calls,
                    tr.result.model_dump_json(),
                )
            )
        except Exception as e:  # noqa: BLE001
            out.append(CaseResult("json", name, False, time.monotonic() - t0,
                                  detail=f"{type(e).__name__}: {e}"[:300]))
    return out


# ---------------------------------------------------------------- suite: tools


class ReconAnswer(BaseModel):
    port: int
    framework: str
    debug_token: str


async def run_tools_suite(backend) -> list[CaseResult]:
    out: list[CaseResult] = []
    prompts = [
        ("scan-then-curl", "Use sandbox_shell to scan ports, then fetch the HTTP "
         "headers of the open web service. Report port, framework, debug_token."),
        ("minimal-steps", "Using at most 3 sandbox_shell calls, find the web "
         "service's port, framework and the value of its x-debug-token header."),
    ]
    for name, task in prompts:
        sandbox = SimulatedRangeSandbox(RANGE_ROUTES)
        rt = ManagedAgentRuntime(backend, sandbox=sandbox)
        d = AgentDefinition(
            id=f"tools-{name}",
            version="1",
            system_prompt=(
                "You are a recon agent inside a simulated range. Only use "
                "evidence from sandbox_shell outputs. Finish with the JSON object."
            ),
            output_model=ReconAnswer,
            max_total_tokens=40_000,
            max_output_tokens=2_000,
        )
        t0 = time.monotonic()
        try:
            tr = await rt.run(d, task)
            r = tr.result
            ok = (
                r.port == 8080
                and "fastapi" in r.framework.lower()
                and r.debug_token == SECRET_TOKEN
                and tr.tool_calls >= 1
                and len(tr.command_receipts) == tr.tool_calls
            )
            out.append(CaseResult("tools", name, ok, time.monotonic() - t0,
                                  tr.usage.total_tokens, tr.model_calls,
                                  tr.tool_calls, r.model_dump_json(),
                                  {"commands": sandbox.commands}))
        except Exception as e:  # noqa: BLE001
            out.append(CaseResult("tools", name, False, time.monotonic() - t0,
                                  detail=f"{type(e).__name__}: {e}"[:300],
                                  extra={"commands": sandbox.commands}))
    return out


# ---------------------------------------------------------------- suite: team


def build_registry() -> StateMachineRegistry:
    reg = StateMachineRegistry()
    reg.register(
        StateMachineSpec(
            fsm_id="range-root",
            description="Root discovery of the simulated range",
            initial_state="scan",
            states=[
                StateNodeSpec(
                    id="scan",
                    title="Root Recon",
                    mode="research",
                    system_prompt=(
                        "Root Recon Stage. Use sandbox_shell to scan the simulated "
                        "range. Emit a research handoff: put receipt-backed "
                        "observations in items (status runtime_observed, cite "
                        "evidence like 'cmd:<sequence>'), and register every "
                        "discovered network service under discovered_entities with "
                        "kind 'http_service' and attributes.framework set to the "
                        "observed framework name in lowercase."
                    ),
                ),
                StateNodeSpec(id="done", title="Done", system_prompt="Terminal.",
                              is_terminal=True),
            ],
            transitions=[
                TransitionSpec(
                    id="finish_scan",
                    source="scan",
                    target="done",
                    guard=GuardClause(required_sections=["checkpoint"],
                                      min_status="runtime_observed"),
                )
            ],
        )
    )
    reg.register(
        StateMachineSpec(
            fsm_id="fastapi-token",
            description="Auto-mounted for discovered FastAPI services",
            trigger=TriggerPredicate(entity_kind="http_service",
                                     required_attributes={"framework": "fastapi"}),
            initial_state="extract",
            states=[
                StateNodeSpec(
                    id="extract",
                    title="Extract Debug Token",
                    system_prompt=(
                        "Use sandbox_shell to fetch the service's HTTP headers. "
                        "Deliver an artifact whose bytes are exactly the value of "
                        "the x-debug-token header (inline source, base64-encoded)."
                    ),
                ),
                StateNodeSpec(id="done", title="Done", system_prompt="Terminal.",
                              is_terminal=True),
            ],
            transitions=[TransitionSpec(id="complete", source="extract",
                                        target="done")],
        )
    )
    return reg


async def run_team_suite(backend, run_root: Path, tag: str) -> list[CaseResult]:
    oracle = RangeOracle()
    sandboxes: list[SimulatedRangeSandbox] = []

    def factory(work_dir: Path) -> ManagedAgentRuntime:
        sb = SimulatedRangeSandbox(RANGE_ROUTES, work_root=work_dir)
        sandboxes.append(sb)
        return ManagedAgentRuntime(backend, sandbox=sb)

    orch = TeamOrchestrator(
        registry=build_registry(),
        worker_runtime_factory=factory,
        observer=TwoTierObserver(None, probe_max_tool_calls=3),
        evaluator=oracle,
        concurrency=2,
    )
    task_dir = run_root / f"team-{tag}"
    t0 = time.monotonic()
    try:
        res = await orch.run_task(
            task_id=f"range-{tag}",
            root_fsm_id="range-root",
            task_dir=task_dir,
            objective="Discover the range's web service and deliver its debug token.",
            total_token_limit=600_000,
            max_generations=8,
        )
        board = TaskMemoryStore(task_dir / "memory.json", f"range-{tag}").load()
        mounted = sorted({r.fsm_id for r in board.routes})
        ok = res.status == "passed" and res.final_artifact is not None and (
            SECRET_TOKEN.encode() in res.final_artifact
        )
        return [
            CaseResult(
                "team",
                f"e2e-{tag}",
                ok,
                time.monotonic() - t0,
                res.budget.total_tokens_used,
                res.budget.model_calls_used,
                sum(len(s.commands) for s in sandboxes),
                detail=(
                    f"status={res.status} attempts={len(res.attempts)} "
                    "first_milestone_tokens="
                    f"{res.budget.first_milestone_total_tokens_used}"
                ),
                extra={
                    "mounted_fsms": mounted,
                    "entities": sorted(e.entity_id for e in board.entities),
                    "oracle_calls": oracle.calls,
                    "final_artifact": (res.final_artifact or b"")[:64].decode(
                        "utf-8", "replace"),
                    "attempt_statuses": [a.status for a in res.attempts],
                    "audit_zip": str(res.audit_zip_path),
                },
            )
        ]
    except Exception as e:  # noqa: BLE001
        return [CaseResult("team", f"e2e-{tag}", False, time.monotonic() - t0,
                           detail=f"{type(e).__name__}: {e}"[:400])]


# ---------------------------------------------------------------- main


def load_backend() -> OpenAICompatibleModelBackend:
    base_url = os.environ.get("VOUCHLOOM_LLM_BASE_URL")
    model = os.environ.get("VOUCHLOOM_LLM_MODEL")
    key = os.environ.get("VOUCHLOOM_LLM_API_KEY")
    key_file = os.environ.get("VOUCHLOOM_LLM_API_KEY_FILE")
    if not key and key_file:
        key = Path(key_file).expanduser().read_text().strip()
    if not (base_url and model and key):
        sys.exit("set VOUCHLOOM_LLM_BASE_URL, VOUCHLOOM_LLM_MODEL and an API key")
    return OpenAICompatibleModelBackend(base_url=base_url, api_key=key, model=model,
                                        timeout_seconds=240.0)


async def main() -> None:
    ap = argparse.ArgumentParser()
    # "quick" covers the single-agent cases only; the multi-agent team suite is
    # slow (minutes per run) and must be requested explicitly.
    ap.add_argument(
        "--suite", default="quick", choices=["quick", "all", "json", "tools", "team"]
    )
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--out", default=".vouchloom-runs/benchmark")
    args = ap.parse_args()

    backend = load_backend()
    run_root = Path(args.out) / time.strftime("%Y%m%d-%H%M%S")
    run_root.mkdir(parents=True, exist_ok=True)
    results: list[CaseResult] = []

    def progress(batch: list[CaseResult]) -> list[CaseResult]:
        for r in batch:
            print(f"  {r.suite}/{r.case}: {'PASS' if r.ok else 'FAIL'} "
                  f"({r.seconds:.1f}s)", flush=True)
        return batch

    try:
        for i in range(args.repeat):
            if args.suite in ("quick", "all", "json"):
                results += progress(await run_json_suite(backend))
            if args.suite in ("quick", "all", "tools"):
                results += progress(await run_tools_suite(backend))
            if args.suite in ("all", "team"):
                results += progress(
                    await run_team_suite(backend, run_root, f"r{i + 1}")
                )
    finally:
        await backend.aclose()

    print(f"\nmodel={backend.model}")
    print(f"{'suite':6} {'case':16} {'ok':4} {'sec':>6} {'tokens':>8} "
          f"{'calls':>5} {'tools':>5}  detail")
    for r in results:
        print(f"{r.suite:6} {r.case:16} {'PASS' if r.ok else 'FAIL':4} "
              f"{r.seconds:6.1f} {r.total_tokens:8d} {r.model_calls:5d} "
              f"{r.tool_calls:5d}  {r.detail[:90]}")
    passed = sum(r.ok for r in results)
    print(f"\n{passed}/{len(results)} passed")
    report = {
        "model": backend.model,
        "passed": passed,
        "total": len(results),
        "results": [asdict(r) for r in results],
    }
    (run_root / "report.json").write_text(json.dumps(report, indent=2,
                                                      ensure_ascii=False))
    print(f"report: {run_root / 'report.json'}")


if __name__ == "__main__":
    asyncio.run(main())
