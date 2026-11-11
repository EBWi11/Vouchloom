"""Tests for Layer 3 Agent Team, Entity Fission, Observer, & Review Audit."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from vouchloom import (
    ExecutionReceipt,
    GuardClause,
    LocalDirectorySandbox,
    ManagedAgentRuntime,
    ModelTurnResponse,
    ModelUsage,
    ProofLedgerEntry,
    RouteSummary,
    SemanticArbiterSuite,
    StateMachineRegistry,
    StateMachineSpec,
    StateNodeSpec,
    TaskMemoryStore,
    TeamOrchestrator,
    TransitionSpec,
    TriggerPredicate,
    TwoTierObserver,
    audit_memory_review_transition,
)


class DynamicTeamBackend:
    """Simulates recon -> 1->N entity spawn -> Observer probe -> delivery."""

    def __init__(self) -> None:
        self.step = 0

    async def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        output_schema: dict[str, Any],
        allow_tools: bool,
        max_output_tokens: int | None,
    ) -> ModelTurnResponse:
        sys_prompt = str(messages[0].get("content", ""))
        has_tool_output = any(m.get("role") == "tool" for m in messages)

        # Observer leashed probe turn
        if "LEASHED EXPLORATORY PROBE" in sys_prompt:
            if allow_tools and not has_tool_output:
                return ModelTurnResponse(
                    model_id="mock",
                    usage=ModelUsage(total_tokens=120),
                    tool_commands=("echo 'graphql introspection confirmed'",),
                )
            return ModelTurnResponse(
                model_id="mock",
                usage=ModelUsage(total_tokens=120),
                final_text=json.dumps(
                    {
                        "handoff": {
                            "summary": "Verified GraphQL schema endpoint",
                            "next_step": "Use discovered GraphQL mutation clue",
                            "next_action": {
                                "id": "probe.done",
                                "kind": "inspect",
                                "target": "graphql",
                                "expected_observation": "schema",
                            },
                            "items": [
                                {
                                    "id": "probe.graphql",
                                    "kind": "observation",
                                    "status": "runtime_observed",
                                    "claim": "GraphQL debug mutation enabled",
                                    "evidence": ["cmd:1"],
                                }
                            ],
                        }
                    }
                ),
            )

        # Root recon FSM: runs 1 cmd, discovers child entity + sideband signal!
        if "Root Recon Stage" in sys_prompt:
            if allow_tools and not has_tool_output:
                return ModelTurnResponse(
                    model_id="mock",
                    usage=ModelUsage(total_tokens=200),
                    tool_commands=("echo '8080/tcp open http-api'",),
                )
            return ModelTurnResponse(
                model_id="mock",
                usage=ModelUsage(total_tokens=200),
                final_text=json.dumps(
                    {
                        "handoff": {
                            "summary": "Discovered API service on 8080",
                            "next_step": "Complete root recon",
                            "next_action": {
                                "id": "recon.finish",
                                "kind": "inspect",
                                "target": "svc.8080",
                                "expected_observation": "banner",
                            },
                            "items": [
                                {
                                    "id": "recon.port8080",
                                    "kind": "observation",
                                    "status": "runtime_observed",
                                    "claim": "Port 8080 exposes API token hint",
                                    "evidence": ["scan:8080"],
                                    "cross_entity_refs": ["svc.8080"],
                                }
                            ],
                            "discovered_entities": [
                                {
                                    "entity_id": "svc.8080",
                                    "kind": "http_service",
                                    "label": "HTTP API on 8080",
                                    "attributes": {"framework": "fastapi"},
                                    "command_sequence": 1,
                                }
                            ],
                            "unexpected_signals": [
                                {
                                    "signal_id": "sig.graphql",
                                    "category": "unexpected_surface",
                                    "summary": "Unexpected X-GraphQL-Debug header",
                                    "proposed_hypothesis": "Query /graphql schema",
                                    "command_sequence": 1,
                                }
                            ],
                        }
                    }
                ),
            )

        # Triggered child HTTP service FSM: receives clue & emits payload!
        b64 = base64.b64encode(b"EXPLOIT_POC_BYTES").decode("ascii")
        return ModelTurnResponse(
            model_id="mock",
            usage=ModelUsage(total_tokens=250),
            final_text=json.dumps(
                {
                    "source": {"kind": "inline", "artifact_base64": b64},
                    "rationale": "Triggered verified payload on svc.8080",
                    "causal_dimension": "input_boundary",
                    "changed_constraint": "Encoded API header",
                    "semantic_checkpoint": "svc.8080 sink",
                }
            ),
        )

    async def aclose(self) -> None:
        return None


class MockDifferentialEvaluator:
    async def evaluate_candidate(
        self,
        content: bytes,
        *,
        route: RouteSummary,
        is_replay: bool = False,
    ) -> ExecutionReceipt:
        return ExecutionReceipt.build(
            subject_sha256="f" * 64,
            output="ASAN crash at api_handler.c:88",
            exit_code=77,
            observed_target="svc.8080",
            phase="target_runtime",
            input_consumption="observed",
            fingerprint_sha256="e" * 64,
        )


@pytest.mark.asyncio
async def test_team_orchestrator_entity_fission_and_observer_breakout(
    tmp_path: Path,
) -> None:
    registry = StateMachineRegistry()
    registry.register(
        StateMachineSpec(
            fsm_id="root-recon",
            description="Root asset discovery",
            initial_state="scan",
            states=[
                StateNodeSpec(
                    id="scan",
                    title="Scan",
                    system_prompt="Root Recon Stage",
                ),
                StateNodeSpec(
                    id="done",
                    title="Done",
                    system_prompt="Done",
                    is_terminal=True,
                ),
            ],
            transitions=[
                TransitionSpec(
                    id="finish_scan",
                    source="scan",
                    target="done",
                    guard=GuardClause(
                        required_sections=["checkpoint"],
                        min_status="runtime_observed",
                    ),
                )
            ],
        )
    )
    registry.register(
        StateMachineSpec(
            fsm_id="http-service-audit",
            description="Auto-triggered HTTP service workflow",
            trigger=TriggerPredicate(
                entity_kind="http_service",
                required_attributes={"framework": "fastapi"},
            ),
            initial_state="probe_service",
            states=[
                StateNodeSpec(
                    id="probe_service",
                    title="Probe HTTP Service",
                    system_prompt="Audit FastAPI service",
                ),
                StateNodeSpec(
                    id="done",
                    title="Done",
                    system_prompt="Done",
                    is_terminal=True,
                ),
            ],
            transitions=[
                TransitionSpec(
                    id="complete_audit", source="probe_service", target="done"
                )
            ],
        )
    )

    backend = DynamicTeamBackend()
    orchestrator = TeamOrchestrator(
        registry=registry,
        worker_runtime_factory=lambda work_dir: ManagedAgentRuntime(
            backend, sandbox=LocalDirectorySandbox(work_dir)
        ),
        observer=TwoTierObserver(None, probe_max_tool_calls=5),
        evaluator=MockDifferentialEvaluator(),
        concurrency=2,
    )

    run_res = await orchestrator.run_task(
        task_id="range-target-01",
        root_fsm_id="root-recon",
        task_dir=tmp_path / "run",
        objective="Discover services and produce verified PoC",
        max_generations=4,
    )

    assert run_res.status == "passed"
    assert run_res.final_artifact == b"EXPLOIT_POC_BYTES"
    assert len(run_res.breakout_episodes) == 1
    assert run_res.breakout_episodes[0].tier == "tier1_probe"
    assert run_res.breakout_episodes[0].succeeded is True
    assert run_res.audit_zip_path is not None and run_res.audit_zip_path.is_file()

    board = TaskMemoryStore(tmp_path / "run" / "memory.json", "range-target-01").load()
    entity_ids = {e.entity_id for e in board.entities}
    assert "svc.8080" in entity_ids
    assert any(r.fsm_id == "http-service-audit" for r in board.routes)


def test_memory_review_transition_audit_blocks_self_created_stop(
    tmp_path: Path,
) -> None:
    store = TaskMemoryStore(tmp_path / "bb.json", "task-rev")
    r = store.apply_route_decision(
        action="new", route_id=None, attempt=1, rationale="Init", model="core"
    )
    before = store.load()
    # Reviewer tries to invent a brand-new contradicted cell and claim "stop"
    invented = ProofLedgerEntry(
        key="cond.invented",
        section="condition",
        condition_role="required",
        claim="Invented stop condition",
        status="contradicted",
        evidence=["src.c:1"],
        route_id=r.route_id,
    )
    after = store.merge_ledger([invented], retire_route_ids={r.route_id})
    audit = audit_memory_review_transition(
        before,
        status="stop",
        confidence="source_backed",
        next_step=None,
        updates=[invented],
        after=after,
    )
    assert audit.severity == "invalid"
    assert "stop_without_preexisting_required_contradiction" in audit.codes


@pytest.mark.asyncio
async def test_bug_hunter_fidelity_safe_path_startup_retry_and_final_selector(
    tmp_path: Path,
) -> None:
    """Verify wired gates: safe_path + 2-vote diag, startup retry, & 2-PoC selector."""

    reg = StateMachineRegistry()
    reg.register(
        StateMachineSpec(
            fsm_id="fidelity-fsm",
            description="Fidelity check",
            initial_state="solve",
            states=[
                StateNodeSpec(id="solve", title="Solve", system_prompt="Emit bytes"),
                StateNodeSpec(
                    id="done", title="Done", system_prompt="Done", is_terminal=True
                ),
            ],
            transitions=[TransitionSpec(id="t_done", source="solve", target="done")],
        )
    )

    worker_step = 0

    class FidelityWorkerBackend:
        async def complete(
            self,
            *,
            messages: list[dict[str, Any]],
            output_schema: dict[str, Any],
            allow_tools: bool,
            max_output_tokens: int | None,
        ) -> ModelTurnResponse:
            nonlocal worker_step
            worker_step += 1
            payload = f"CANDIDATE_{worker_step}".encode("ascii")
            b64 = base64.b64encode(payload).decode("ascii")
            return ModelTurnResponse(
                model_id="worker",
                usage=ModelUsage(total_tokens=200),
                final_text=json.dumps(
                    {
                        "source": {"kind": "inline", "artifact_base64": b64},
                        "rationale": f"Candidate {worker_step}",
                        "causal_dimension": "input_boundary",
                        "changed_constraint": f"constraint-{worker_step}",
                        "semantic_checkpoint": f"ckpt-{worker_step}",
                    }
                ),
            )

        async def aclose(self) -> None:
            return None

    arbiter_responses: list[dict[str, Any]] = [
        # Candidate 1: rejected pre-execution as safe_path + 2/2 semantic_no_fault!
        {
            "required_qualifier": "async_state",
            "qualifier_binding": "absent",
            "classification": "explicit_no_fault_or_unproven",
            "reason": "Missing async_state qualifier",
        },
        {"decision": "semantic_no_fault", "reason": "Acceptance only"},
        {"decision": "semantic_no_fault", "reason": "Acceptance only"},
        # Candidate 2: admitted!
        {
            "required_qualifier": "async_state",
            "qualifier_binding": "bound",
            "classification": "admit_candidate",
            "reason": "Bound",
        },
        # Candidate 3: admitted + distinct_experiment!
        {
            "required_qualifier": "async_state",
            "qualifier_binding": "bound",
            "classification": "admit_candidate",
            "reason": "Bound",
        },
        {"decision": "distinct_experiment", "reason": "Different producer"},
        # Final 2-candidate selector picks attempt 3!
        {"attempt_number": 3, "rationale": "Cleaner minimal precondition"},
    ]
    arb_idx = 0

    class FidelityArbiterBackend:
        async def complete(
            self,
            *,
            messages: list[dict[str, Any]],
            output_schema: dict[str, Any],
            allow_tools: bool,
            max_output_tokens: int | None,
        ) -> ModelTurnResponse:
            nonlocal arb_idx
            item = arbiter_responses[min(arb_idx, len(arbiter_responses) - 1)]
            arb_idx += 1
            return ModelTurnResponse(
                model_id="arbiter",
                usage=ModelUsage(total_tokens=50),
                final_text=json.dumps(item),
            )

        async def aclose(self) -> None:
            return None

    eval_calls = 0

    class StartupNoiseThenMilestoneEvaluator:
        async def evaluate_candidate(
            self,
            content: bytes,
            *,
            route: RouteSummary,
            is_replay: bool = False,
        ) -> ExecutionReceipt:
            nonlocal eval_calls
            eval_calls += 1
            # First ever evaluation hits environment_startup noise -> auto-retried!
            if eval_calls == 1:
                return ExecutionReceipt.build(
                    subject_sha256="1" * 64,
                    output="ASLR personality startup error",
                    exit_code=77,
                    phase="environment_startup",
                    startup_failure="msan_personality_aslr",
                    input_consumption="not_observed",
                )
            fp = "a" * 64 if content == b"CANDIDATE_2" else "b" * 64
            return ExecutionReceipt.build(
                subject_sha256="2" * 64,
                output="Milestone hit",
                exit_code=77,
                observed_target="official_bin",
                phase="target_runtime",
                input_consumption="observed",
                fingerprint_sha256=fp,
            )

    worker_backend = FidelityWorkerBackend()
    orch = TeamOrchestrator(
        registry=reg,
        worker_runtime_factory=lambda wd: ManagedAgentRuntime(
            worker_backend, sandbox=LocalDirectorySandbox(wd)
        ),
        arbiters=SemanticArbiterSuite(ManagedAgentRuntime(FidelityArbiterBackend())),
        evaluator=StartupNoiseThenMilestoneEvaluator(),
        concurrency=1,
    )

    res = await orch.run_task(
        task_id="fidelity-01",
        root_fsm_id="fidelity-fsm",
        task_dir=tmp_path / "fidelity-run",
        objective="Trigger async_state milestone",
        max_generations=6,
    )

    # Attempt 1 was safe_path blocked with semantic_no_fault
    assert res.attempts[0].status == "blocked"
    assert res.attempts[0].block_category == "safe_path"
    assert res.attempts[0].safe_path_diagnostic == "semantic_no_fault"
    # Attempts 2 & 3 both hit milestones (attempt 2 survived startup retry!)
    assert res.attempts[1].status == "milestone_candidate"
    assert res.attempts[2].status == "milestone_candidate"
    # Two-stage final selector chose attempt 3 and wrote WAL final-intent.json!
    assert res.final_artifact == b"CANDIDATE_3"
    intent = json.loads(
        (tmp_path / "fidelity-run" / "final-intent.json").read_text(encoding="utf-8")
    )
    assert intent["attempt_number"] == 3
    assert intent["selection_method"] == "agent_selected"

    # Authoritative core.latest-runtime & core.latest-gap were merged into memory.json
    mem = TaskMemoryStore(
        tmp_path / "fidelity-run" / "memory.json", "fidelity-01"
    ).load()
    assert any(x.key == "core.latest-runtime" for x in mem.proof_ledger)
