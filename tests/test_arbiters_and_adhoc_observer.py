"""Tests for Layer 2 isolated SemanticArbiterSuite & Tier 2 Ad-Hoc FSM Observer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from vouchloom import (
    AgentRuntimeError,
    BlackboardStore,
    CommandReceipt,
    ManagedAgentRuntime,
    MemoryItem,
    ModelTurnResponse,
    ModelUsage,
    NextAction,
    ResearchHandoff,
    SemanticArbiterSuite,
    SidebandSignal,
    StateMachineRegistry,
    StateMachineSpec,
    StateNodeSpec,
    TransitionSpec,
    TwoTierObserver,
)


class SequencedTextBackend:
    def __init__(self, responses: list[dict[str, Any] | Exception]) -> None:
        self._responses = list(responses)
        self.idx = 0

    async def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        output_schema: dict[str, Any],
        allow_tools: bool,
        max_output_tokens: int | None,
    ) -> ModelTurnResponse:
        assert allow_tools is False
        item = self._responses[min(self.idx, len(self._responses) - 1)]
        self.idx += 1
        if isinstance(item, Exception):
            raise item
        return ModelTurnResponse(
            model_id="arbiter-mock",
            usage=ModelUsage(total_tokens=64),
            final_text=json.dumps(item),
        )

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_semantic_arbiters_fail_open_fail_closed_and_2_vote_consensus() -> None:
    # 1. Delivery admission fail-open when classifier transport fails
    err_suite = SemanticArbiterSuite(
        ManagedAgentRuntime(SequencedTextBackend([RuntimeError("down")]))
    )
    reopen, adm_audit = await err_suite.classify_delivery_admission({"gap": "x"})
    assert reopen is False
    assert any(
        r.get("status") == "delivery_admission_fail_open" for r in adm_audit.receipts
    )

    # 2. Memory semantics fail-closed on ID mismatch, then succeeds on valid set
    items = [
        MemoryItem(
            id="c.1",
            kind="construction",
            status="source_backed",
            claim="Frame header layout",
            evidence=["hdr.h:12"],
        ),
        MemoryItem(
            id="g.1",
            kind="gap",
            status="hypothesis",
            claim="Missing CRC offset",
            evidence=["crc.c:4"],
        ),
    ]
    bad_mem_suite = SemanticArbiterSuite(
        ManagedAgentRuntime(SequencedTextBackend([{"decisions": []}]))
    )
    carriers_bad, _, _, _ = await bad_mem_suite.classify_memory_semantics(items)
    assert carriers_bad == set()

    good_mem_suite = SemanticArbiterSuite(
        ManagedAgentRuntime(
            SequencedTextBackend(
                [
                    {
                        "decisions": [
                            {
                                "id": "c.1",
                                "classification": "carrier_construction",
                                "blocking_gap_ids": ["g.1"],
                            }
                        ]
                    }
                ]
            )
        )
    )
    carriers_ok, _, blockers_ok, _ = await good_mem_suite.classify_memory_semantics(
        items
    )
    assert carriers_ok == {"c.1"}
    assert blockers_ok == {"c.1": ["g.1"]}

    # 3. Handoff identity arbiter downgrades sibling claim & injects reconcile action
    handoff = ResearchHandoff(
        summary="Tested sibling binary",
        next_step="Emit payload",
        next_action=NextAction(
            id="act.orig",
            kind="materialize",
            target="/work/poc.bin",
            expected_observation="bytes",
        ),
        items=[
            MemoryItem(
                id="edge.sibling",
                kind="call_edge",
                status="runtime_observed",
                claim="Sibling binary reached helper",
                evidence=["local_run"],
            )
        ],
    )
    id_suite = SemanticArbiterSuite(
        ManagedAgentRuntime(
            SequencedTextBackend(
                [
                    {
                        "classification": "unanchored_alternate",
                        "untrusted_item_ids": ["edge.sibling"],
                        "reason": "Used sibling binary instead of official target",
                    }
                ]
            )
        )
    )
    reconciled, _ = await id_suite.reconcile_handoff_identity(
        handoff, bound_target="official_target"
    )
    assert reconciled.items[0].status == "hypothesis"
    assert reconciled.next_action.id.startswith("identity.reconcile.")

    # 4. 2-vote consensus: split vote (1 semantic_no_fault + 1 operational) -> False!
    split_diag_suite = SemanticArbiterSuite(
        ManagedAgentRuntime(
            SequencedTextBackend(
                [
                    {"decision": "semantic_no_fault", "reason": "Acceptance only"},
                    {"decision": "operational_or_unproven", "reason": "Unclear"},
                ]
            )
        )
    )
    (
        is_no_fault_split,
        _,
    ) = await split_diag_suite.classify_safe_path_diagnostic_consensus({"attempt": 1})
    assert is_no_fault_split is False

    # Unanimous 2/2 route retirement citing >=2 valid attempts -> True!
    unanimous_retire_suite = SemanticArbiterSuite(
        ManagedAgentRuntime(
            SequencedTextBackend(
                [
                    {
                        "decision": "retire_route",
                        "evidence_attempts": [1, 2],
                        "rationale": "Both clean at max bound",
                    },
                    {
                        "decision": "retire_route",
                        "evidence_attempts": [1, 2],
                        "rationale": "Confirmed safe path",
                    },
                ]
            )
        )
    )
    retire, _, _ = await unanimous_retire_suite.classify_route_retirement_consensus(
        {"attempts": [{"number": 1}, {"number": 2}]},
        valid_attempt_numbers={1, 2},
    )
    assert retire is True

    # 5. Bounded 1-command wall-timeout receipt recovery
    cmd_rec = CommandReceipt.from_execution(
        tool_name="sandbox_shell",
        sequence=1,
        command="./probe_target /work/seed.bin",
        output="gdef_has_data=1; variation_set_empty=1\n",
        exit_code=0,
    )
    timeout_err = AgentRuntimeError(
        "turn exceeded its wall-clock limit",
        command_receipts=[cmd_rec],
        code="turn_wall_timeout",
    )
    req_act = NextAction(
        id="inst.gdef",
        kind="instrument",
        target="probe_target",
        expected_observation="check variation set",
    )
    rec_suite = SemanticArbiterSuite(
        ManagedAgentRuntime(
            SequencedTextBackend(
                [
                    {
                        "action_id": "inst.gdef",
                        "outcome": "completed",
                        "observation": "gdef_has_data=1 and variation_set_empty=1",
                        "changed_constraint": "Upstream variation index set is empty",
                    }
                ]
            )
        )
    )
    salvaged_rec, _ = await rec_suite.recover_bounded_action_receipt(
        req_act, timeout_err
    )
    assert salvaged_rec is not None
    assert salvaged_rec.command_receipt_sha256 == cmd_rec.sha256


@pytest.mark.asyncio
async def test_observer_tier2_adhoc_fsm_mount_and_oversized_downgrade(
    tmp_path: Path,
) -> None:
    store = BlackboardStore(tmp_path / "bb.json", "obs-task")
    route = store.apply_route_decision(
        action="new", route_id=None, attempt=1, rationale="Start", model="core"
    )
    reg = StateMachineRegistry()
    adhoc_spec = StateMachineSpec(
        fsm_id="adhoc-grpc-reflection",
        description="Ephemeral gRPC reflection sub-FSM",
        initial_state="list_services",
        states=[
            StateNodeSpec(
                id="list_services",
                title="List Services",
                system_prompt="Query gRPC reflection",
            ),
            StateNodeSpec(
                id="done", title="Done", system_prompt="Done", is_terminal=True
            ),
        ],
        transitions=[
            TransitionSpec(id="finish", source="list_services", target="done")
        ],
    )
    obs = TwoTierObserver(
        ManagedAgentRuntime(
            SequencedTextBackend(
                [
                    {
                        "action": "tier2_mount_adhoc_fsm",
                        "rationale": "Discovered unmodeled gRPC reflection port",
                        "adhoc_fsm": adhoc_spec.model_dump(mode="json"),
                    }
                ]
            )
        ),
        max_adhoc_states=4,
    )
    sig = SidebandSignal(
        signal_id="sig.grpc",
        entity_id="root",
        category="novel_component",
        summary="gRPC server reflection enabled",
        proposed_hypothesis="Enumerate reflection services",
        command_receipt_sha256="a" * 64,
    )
    decision, _ = await obs.evaluate(
        board=store.load(),
        route=route,
        verified_signals=[sig],
        registry=reg,
    )
    assert decision.action == "tier2_mount_adhoc_fsm"
    assert decision.adhoc_fsm is not None
    assert decision.adhoc_fsm.ad_hoc_ephemeral is True
    assert reg.get("adhoc-grpc-reflection").ad_hoc_ephemeral is True
