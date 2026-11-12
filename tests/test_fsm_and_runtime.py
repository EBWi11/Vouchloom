"""Tests for Layer 1 Hybrid FSM IR & Layer 2 ManagedAgentRuntime repair/gates."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from vouchloom import (
    AgentDefinition,
    AgentRuntimeError,
    GuardClause,
    GuardRegistry,
    LocalDirectorySandbox,
    ManagedAgentRuntime,
    ModelTurnResponse,
    ModelUsage,
    StateMachineRegistry,
    StateMachineSpec,
    StateNodeSpec,
    TransitionSpec,
    WorkerArtifactOnlyOutput,
    WorkerModelOutput,
)


class ScriptedModelBackend:
    def __init__(self, turns: list[ModelTurnResponse | Exception]) -> None:
        self._turns = list(turns)
        self.calls = 0

    async def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        output_schema: dict[str, Any],
        allow_tools: bool,
        max_output_tokens: int | None,
    ) -> ModelTurnResponse:
        idx = min(self.calls, len(self._turns) - 1)
        self.calls += 1
        item = self._turns[idx]
        if isinstance(item, Exception):
            raise item
        return item

    async def aclose(self) -> None:
        return None


def test_fsm_yaml_roundtrip_and_cyclic_hierarchy_rejection() -> None:
    guards = GuardRegistry()
    guards.register("always_true", lambda board, route_id, ctx: True)

    spec = StateMachineSpec(
        fsm_id="web-recon",
        version="1.0.0",
        description="Web reconnaissance micro-FSM",
        initial_state="fingerprint",
        states=[
            StateNodeSpec(
                id="fingerprint",
                title="Fingerprint Stack",
                system_prompt="Identify framework.",
            ),
            StateNodeSpec(
                id="done",
                title="Recon Complete",
                system_prompt="Done.",
                is_terminal=True,
            ),
        ],
        transitions=[
            TransitionSpec(
                id="to_done",
                source="fingerprint",
                target="done",
                guard=GuardClause(python_guard="always_true"),
            )
        ],
    )
    yaml_text = spec.to_yaml()
    reloaded = StateMachineSpec.from_yaml(yaml_text)
    assert reloaded.fsm_id == "web-recon"

    reg = StateMachineRegistry(guard_registry=guards)
    reg.register(reloaded)
    with pytest.raises(ValueError, match="already registered"):
        reg.register(reloaded)

    # semantic_arbiter is not evaluated yet, so it must be rejected (not fail-open)
    arbitered = spec.model_copy(
        update={
            "fsm_id": "web-recon-arbitered",
            "transitions": [
                TransitionSpec(
                    id="to_done",
                    source="fingerprint",
                    target="done",
                    guard=GuardClause(semantic_arbiter="pivot_judge"),
                )
            ],
        }
    )
    with pytest.raises(ValueError, match="semantic_arbiter"):
        reg.register(arbitered)

    # Cyclic sub_fsm_id hierarchy across two FSMs must be rejected
    fsm_a = StateMachineSpec(
        fsm_id="fsm-a",
        description="A",
        initial_state="s1",
        states=[
            StateNodeSpec(id="s1", title="S1", system_prompt="p", sub_fsm_id="fsm-b"),
            StateNodeSpec(id="end", title="End", system_prompt="p", is_terminal=True),
        ],
        transitions=[TransitionSpec(id="t1", source="s1", target="end")],
    )
    fsm_b = StateMachineSpec(
        fsm_id="fsm-b",
        description="B",
        initial_state="s1",
        states=[
            StateNodeSpec(id="s1", title="S1", system_prompt="p", sub_fsm_id="fsm-a"),
            StateNodeSpec(id="end", title="End", system_prompt="p", is_terminal=True),
        ],
        transitions=[TransitionSpec(id="t1", source="s1", target="end")],
    )
    with pytest.raises(ValueError, match="unknown sub_fsm_id"):
        reg.register(fsm_a)
    # Even if pre-populated, cycle detection catches A <-> B
    with pytest.raises(ValueError, match="cyclic sub_fsm_id"):
        StateMachineRegistry._verify_acyclic_hierarchy({"fsm-a": fsm_a, "fsm-b": fsm_b})


@pytest.mark.asyncio
async def test_runtime_artifact_materialization_and_deadline_gates(
    tmp_path: Path,
) -> None:
    sandbox = LocalDirectorySandbox(tmp_path / "work")
    # 1) Deadline missed after 2 shell calls without creating poc.bin
    backend_miss = ScriptedModelBackend(
        [
            ModelTurnResponse(
                model_id="test",
                usage=ModelUsage(total_tokens=100),
                tool_commands=("echo step1", "echo step2"),
            )
        ]
    )
    rt_miss = ManagedAgentRuntime(backend_miss, sandbox=sandbox)
    delivery_def = AgentDefinition(
        id="delivery",
        version="0.1",
        system_prompt="Write poc.bin",
        output_model=WorkerArtifactOnlyOutput,
        max_total_tokens=50_000,
        required_artifact_path="poc.bin",
        artifact_deadline_tool_calls=2,
    )
    with pytest.raises(AgentRuntimeError) as exc_info:
        await rt_miss.run(delivery_def, "go")
    assert exc_info.value.code == "artifact_deadline_missed"

    # 2) Writing poc.bin on call 1 triggers artifact_materialized & finalizes
    backend_ok = ScriptedModelBackend(
        [
            ModelTurnResponse(
                model_id="test",
                usage=ModelUsage(total_tokens=100),
                tool_commands=("printf 'PAYLOAD' > poc.bin", "echo should_not_run"),
            ),
            ModelTurnResponse(
                model_id="test",
                usage=ModelUsage(total_tokens=80),
                final_text=json.dumps(
                    {
                        "source": {"kind": "path", "artifact_path": "poc.bin"},
                        "rationale": "Built payload",
                    }
                ),
            ),
        ]
    )
    rt_ok = ManagedAgentRuntime(backend_ok, sandbox=sandbox)
    trace = await rt_ok.run(delivery_def, "go")
    assert trace.tool_calls == 1
    assert any(
        r.get("status") == "artifact_materialized" for r in trace.request_receipts
    )


@pytest.mark.asyncio
async def test_runtime_pure_json_repair_and_zero_telemetry_retry(
    tmp_path: Path,
) -> None:
    valid_handoff_json = json.dumps(
        {
            "handoff": {
                "summary": "Inspected entrypoint",
                "next_step": "Check parser",
                "next_action": {
                    "id": "act.1",
                    "kind": "inspect",
                    "target": "parser.c",
                    "expected_observation": "bounds check",
                },
                "items": [
                    {
                        "id": "item.1",
                        "kind": "contract",
                        "status": "source_backed",
                        "claim": "Entry reads stdin",
                        "evidence": ["main.c:5"],
                    }
                ],
            }
        }
    )
    # 1st call: transport error with 0 telemetry -> auto fresh-thread retry!
    # 2nd & 3rd calls: identical malformed JSON -> triggers Pure JSON Repair Agent!
    # 4th call (Pure JSON Agent): returns valid JSON!
    backend = ScriptedModelBackend(
        [
            RuntimeError("connection reset before first byte"),
            ModelTurnResponse(
                model_id="test",
                usage=ModelUsage(total_tokens=50),
                final_text="{broken json",
            ),
            ModelTurnResponse(
                model_id="test",
                usage=ModelUsage(total_tokens=50),
                final_text="{broken json",
            ),
            ModelTurnResponse(
                model_id="test-repair",
                usage=ModelUsage(total_tokens=40),
                final_text=valid_handoff_json,
            ),
        ]
    )
    sandbox = LocalDirectorySandbox(tmp_path / "work2")
    rt = ManagedAgentRuntime(backend, sandbox=sandbox)
    defn = AgentDefinition(
        id="research",
        version="0.1",
        system_prompt="Research",
        output_model=WorkerModelOutput,
        max_total_tokens=100_000,
    )
    trace = await rt.run(defn, "start")
    statuses = [r.get("status") for r in trace.request_receipts]
    assert "zero_telemetry_fresh_thread_retry" in statuses
    assert "pure_json_agent_started" in statuses
    assert "pure_json_agent_completed" in statuses
