"""Tests for Layer 4 RL Credit Assignment, Bandit Router, & Shadow Replay."""

from __future__ import annotations

from pathlib import Path

import pytest

from vouchloom import (
    AddGuardOp,
    BlackboardStore,
    BreakoutEpisodeRecord,
    ContextualBanditRouter,
    EdgeCreditLedger,
    GraphPatch,
    GuardClause,
    HistoricalShadowControl,
    ManagedAgentRuntime,
    MetaEvolutionAgent,
    ModelTurnResponse,
    ModelUsage,
    ProofLedgerEntry,
    PruneTransitionOp,
    ShadowReplayGate,
    SplitStateOp,
    StateMachineSpec,
    StateNodeSpec,
    TaskBudgetEnvelope,
    TaskRunResult,
    TransitionSpec,
    TriggerPredicate,
    apply_graph_patch,
    synthesize_fsm_from_breakout,
)


def _sample_spec() -> StateMachineSpec:
    return StateMachineSpec(
        fsm_id="auth-test",
        version="0.1.0",
        description="Auth testing micro-FSM",
        initial_state="recon",
        states=[
            StateNodeSpec(id="recon", title="Recon", system_prompt="Recon prompt"),
            StateNodeSpec(
                id="exploit", title="Exploit", system_prompt="Exploit prompt"
            ),
            StateNodeSpec(
                id="done", title="Done", system_prompt="Done", is_terminal=True
            ),
        ],
        transitions=[
            TransitionSpec(
                id="fast_path",
                source="recon",
                target="exploit",
                priority=1,
                guard=GuardClause(
                    required_sections=["target_contract"], min_status="source_backed"
                ),
            ),
            TransitionSpec(
                id="noisy_path",
                source="recon",
                target="exploit",
                priority=1,
                guard=GuardClause(
                    required_sections=["target_contract"], min_status="source_backed"
                ),
            ),
            TransitionSpec(
                id="finish",
                source="exploit",
                target="done",
                guard=GuardClause(
                    required_sections=["sink"], min_status="source_backed"
                ),
            ),
        ],
    )


def test_backward_causal_credit_and_bandit_routing(tmp_path: Path) -> None:
    spec = _sample_spec()
    store = BlackboardStore(tmp_path / "bb.json", "rl-task")
    r_win = store.apply_route_decision(
        action="new", route_id=None, attempt=1, rationale="Win", model="core"
    )
    r_dead = store.apply_route_decision(
        action="new", route_id=None, attempt=2, rationale="Dead", model="core"
    )
    store.merge_ledger(
        [
            ProofLedgerEntry(
                key="t1",
                section="target_contract",
                claim="Target",
                status="source_backed",
                evidence=["e1"],
                route_id=r_win.route_id,
            ),
            ProofLedgerEntry(
                key="s1",
                section="sink",
                claim="Sink",
                status="runtime_observed",
                depends_on=["t1"],
                evidence=["e2"],
                route_id=r_win.route_id,
            ),
            ProofLedgerEntry(
                key="dead_obs",
                section="checkpoint",
                claim="Irrelevant banner",
                status="source_backed",
                evidence=["e3"],
                route_id=r_dead.route_id,
            ),
        ]
    )

    credit = EdgeCreditLedger()
    rewards = credit.attribute_episode(
        board=store.load(),
        transition_log=[
            {
                "route_id": r_win.route_id,
                "fsm_id": "auth-test",
                "transition_id": "fast_path",
                "context_key": "web",
                "tokens_used": 100_000,
                "produced_keys": ["t1"],
            },
            {
                "route_id": r_dead.route_id,
                "fsm_id": "auth-test",
                "transition_id": "noisy_path",
                "context_key": "web",
                "tokens_used": 500_000,
                "produced_keys": ["dead_obs"],
            },
        ],
        winning_route_id=r_win.route_id,
        winning_terminal_keys=["s1"],
    )
    assert rewards[("web", "auth-test", "fast_path")] > 0.8
    assert rewards[("web", "auth-test", "noisy_path")] == 0.0

    # Record a few more pulls so greedy/UCB clearly prefers fast_path
    router = ContextualBanditRouter(credit, strategy="greedy")
    for _ in range(4):
        router.record_outcome(
            fsm_id="auth-test",
            transition_id="fast_path",
            context_key="web",
            reward=1.0,
            tokens_used=50_000,
        )
        router.record_outcome(
            fsm_id="auth-test",
            transition_id="noisy_path",
            context_key="web",
            reward=0.0,
            tokens_used=200_000,
        )

    chosen = router.select_transition(
        spec.outgoing_transitions("recon"), fsm_id="auth-test", context_key="web"
    )
    assert chosen.id == "fast_path"

    baked = router.bake_weights_into_spec(spec, context_key="web")
    weights = {t.id: t.bandit_prior_weight for t in baked.transitions}
    assert weights["fast_path"] > weights["noisy_path"]


def test_graph_patch_mutations_and_shadow_replay_gate(tmp_path: Path) -> None:
    spec = _sample_spec()

    # Severing path to terminal must fail closed immediately
    bad_prune = GraphPatch(
        patch_id="patch.bad-prune",
        target_fsm_id="auth-test",
        new_version="0.2.0",
        rationale="Prune finish",
        operations=[PruneTransitionOp(transition_id="finish")],
    )
    with pytest.raises(ValueError, match="severed all paths"):
        apply_graph_patch(spec, bad_prune)

    # SplitState + Prune noisy_path + Promote Observer breakout
    promoted_fsm = synthesize_fsm_from_breakout(
        BreakoutEpisodeRecord(
            entity_id="svc.1",
            trigger_signal=None,
            tier="tier1_probe",
            hypothesis="GraphQL batching bypass",
            succeeded=True,
        ),
        fsm_id="graphql-batch-check",
        trigger=TriggerPredicate(entity_kind="graphql_endpoint"),
    )
    split_patch = GraphPatch(
        patch_id="patch.split-recon",
        target_fsm_id="auth-test",
        new_version="0.2.0",
        rationale="Split recon into passive & active stages",
        operations=[
            PruneTransitionOp(transition_id="noisy_path"),
            SplitStateOp(
                target_state_id="recon",
                first_state=StateNodeSpec(
                    id="recon_passive", title="Passive", system_prompt="Passive"
                ),
                second_state=StateNodeSpec(
                    id="recon_active", title="Active", system_prompt="Active"
                ),
                connecting_transition_id="passive_to_active",
            ),
        ],
    )
    mutated, companions = apply_graph_patch(spec, split_patch)
    assert mutated.initial_state == "recon_passive"
    assert promoted_fsm.fsm_id == "graphql-batch-check"
    assert companions == []

    # Build historical winner & fail-closed control slices for ShadowReplayGate
    winner_store = BlackboardStore(tmp_path / "winner.json", "ctrl-win")
    rw = winner_store.apply_route_decision(
        action="new", route_id=None, attempt=1, rationale="w", model="core"
    )
    winner_store.merge_ledger(
        [
            ProofLedgerEntry(
                key="t",
                section="target_contract",
                claim="Bound",
                status="source_backed",
                evidence=["a"],
                route_id=rw.route_id,
            )
        ]
    )

    blocker_store = BlackboardStore(tmp_path / "blocker.json", "ctrl-block")
    rb = blocker_store.apply_route_decision(
        action="new", route_id=None, attempt=1, rationale="b", model="core"
    )
    # Empty ledger -> must NOT transition from recon to exploit!

    controls = [
        HistoricalShadowControl(
            control_id="winner-01",
            kind="historical_winner",
            board=winner_store.load(),
            route_id=rw.route_id,
            source_state_id="recon",
            expected_target_state_id="exploit",
            context={"last_action_outcome": "completed"},
        ),
        HistoricalShadowControl(
            control_id="fail-closed-01",
            kind="fail_closed_control",
            board=blocker_store.load(),
            route_id=rb.route_id,
            source_state_id="recon",
            expected_target_state_id=None,
            context={"last_action_outcome": "completed"},
        ),
    ]

    gate = ShadowReplayGate()
    # Baseline spec passes both controls
    report_ok = gate.evaluate_candidate(spec, [], controls)
    assert report_ok.accepted is True

    # Over-tightened guard demanding 'sink' before leaving 'recon' blocks winner!
    over_tight_patch = GraphPatch(
        patch_id="patch.overtight",
        target_fsm_id="auth-test",
        new_version="0.3.0",
        rationale="Over-tight guard",
        operations=[
            AddGuardOp(
                transition_id="fast_path",
                guard=GuardClause(
                    required_sections=["sink"], min_status="runtime_observed"
                ),
            ),
            PruneTransitionOp(transition_id="noisy_path"),
        ],
    )
    over_tight_spec, _ = apply_graph_patch(spec, over_tight_patch)
    report_regressed = gate.evaluate_candidate(over_tight_spec, [], controls)
    assert report_regressed.accepted is False
    assert report_regressed.newly_blocked_winners == ("winner-01",)


@pytest.mark.asyncio
async def test_meta_evolution_agent_end_to_end_yaml_persistence(tmp_path: Path) -> None:
    import json
    from typing import Any

    spec = _sample_spec()

    class MockMetaBackend:
        async def complete(
            self,
            *,
            messages: list[dict[str, Any]],
            output_schema: dict[str, Any],
            allow_tools: bool,
            max_output_tokens: int | None,
        ) -> ModelTurnResponse:
            patch = GraphPatch(
                patch_id="patch.prune-noisy",
                target_fsm_id="auth-test",
                new_version="0.2.0",
                rationale="Prune zero-reward noisy_path while keeping fast_path",
                operations=[PruneTransitionOp(transition_id="noisy_path")],
            )
            return ModelTurnResponse(
                model_id="meta-mock",
                usage=ModelUsage(total_tokens=300),
                final_text=json.dumps(patch.model_dump(mode="json")),
            )

        async def aclose(self) -> None:
            return None

    winner_store = BlackboardStore(tmp_path / "win2.json", "ctrl-win2")
    rw = winner_store.apply_route_decision(
        action="new", route_id=None, attempt=1, rationale="w", model="core"
    )
    winner_store.merge_ledger(
        [
            ProofLedgerEntry(
                key="t",
                section="target_contract",
                claim="Bound",
                status="source_backed",
                evidence=["a"],
                route_id=rw.route_id,
            )
        ]
    )
    controls = [
        HistoricalShadowControl(
            control_id="winner-01",
            kind="historical_winner",
            board=winner_store.load(),
            route_id=rw.route_id,
            source_state_id="recon",
            expected_target_state_id="exploit",
            context={"last_action_outcome": "completed"},
        )
    ]

    meta = MetaEvolutionAgent(ManagedAgentRuntime(MockMetaBackend()))
    episode = TaskRunResult(
        task_id="ep-1",
        status="passed",
        budget=TaskBudgetEnvelope(total_token_limit=100_000),
    )
    yaml_dir = tmp_path / "evolved_specs"
    outcome = await meta.evolve_once(
        spec,
        [episode],
        controls=controls,
        yaml_output_dir=yaml_dir,
    )
    assert outcome.accepted is True
    assert len(outcome.persisted_yaml_paths) == 1
    persisted_spec = StateMachineSpec.from_yaml(
        outcome.persisted_yaml_paths[0].read_text(encoding="utf-8")
    )
    assert persisted_spec.version == "0.2.0"
    assert [t.id for t in persisted_spec.transitions] == ["fast_path", "finish"]
