"""Layer 4: Outer RL Credit Assignment, Bandit Routing, & Shadow Replay.

Allows an outer Meta-Agent in simulation/range environments to continuously
evolve declarative StateMachineSpecs safely:
1. EdgeCreditLedger: backward causal credit assignment along TaskMemory depends_on DAGs
2. ContextualBanditRouter: UCB1 / Thompson Sampling over competing FSM transitions
3. Atomic Graph Mutation Operators: SplitState, AddGuard, PruneTransition,
   ExpandNodeToSubFSM, and PromoteBreakoutToSubFSM
4. ShadowReplayGate: historical winner/blocker control suite preventing regressions.
"""

from __future__ import annotations

import math
import random
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field

from vouchloom.agent import AgentDefinition, AgentRuntimeError
from vouchloom.fsm import (
    GuardClause,
    GuardRegistry,
    StateMachineRegistry,
    StateMachineSpec,
    StateNodeSpec,
    TransitionSpec,
    TriggerPredicate,
)
from vouchloom.memory import (
    ProofLedgerEntry,
    TaskMemory,
    ledger_dependency_closure,
)
from vouchloom.models import ModelUsage, StrictModel
from vouchloom.runtime import ManagedAgentRuntime
from vouchloom.team import BreakoutEpisodeRecord, TaskRunResult

# ---------------------------------------------------------------------------
# 1. Backward Causal Credit Assignment over Proof Ledger DAGs
# ---------------------------------------------------------------------------


@dataclass
class EdgeStats:
    pulls: int = 0
    causal_wins: float = 0.0
    total_reward: float = 0.0
    total_tokens: int = 0

    @property
    def alpha(self) -> float:
        return 1.0 + self.causal_wins

    @property
    def beta(self) -> float:
        return 1.0 + max(0.0, self.pulls - self.causal_wins)

    @property
    def mean_reward(self) -> float:
        return self.alpha / (self.alpha + self.beta)


class EdgeCreditLedger:
    """Assigns causal RL credit to FSM transitions via TaskMemory closures."""

    def __init__(self) -> None:
        self._stats: dict[tuple[str, str, str], EdgeStats] = {}

    def stats_for(
        self, *, fsm_id: str, transition_id: str, context_key: str = "root"
    ) -> EdgeStats:
        return self._stats.setdefault((context_key, fsm_id, transition_id), EdgeStats())

    def attribute_episode(
        self,
        *,
        memory: TaskMemory,
        transition_log: Sequence[dict[str, Any]],
        winning_route_id: str | None,
        winning_terminal_keys: Sequence[str] = (),
        token_penalty_scale: float = 1_000_000.0,
    ) -> dict[tuple[str, str, str], float]:
        """Compute per-transition rewards backward from winning proof cells."""

        causal_keys: set[tuple[str, str]] = set()
        if winning_route_id is not None:
            route_entries = [
                x for x in memory.proof_ledger if x.route_id == winning_route_id
            ]
            by_key = {x.key: x for x in route_entries}
            seeds: list[ProofLedgerEntry] = (
                [by_key[k] for k in winning_terminal_keys if k in by_key]
                if winning_terminal_keys
                else [
                    x
                    for x in route_entries
                    if x.section in {"sink", "construction"}
                    and x.status
                    in {"source_backed", "artifact_encoded", "runtime_observed"}
                ]
            )
            for seed in seeds:
                for dep_k in ledger_dependency_closure(seed, by_key):
                    causal_keys.add((winning_route_id, dep_k))

                # Also credit cross-entity upstream producers!
                for cell in route_entries:
                    for ref_entity in cell.cross_entity_refs:
                        for other in memory.proof_ledger:
                            if other.entity_id == ref_entity and other.status in {
                                "source_backed",
                                "artifact_encoded",
                                "runtime_observed",
                            }:
                                causal_keys.add((other.route_id, other.key))

        assigned: dict[tuple[str, str, str], float] = {}
        for entry in transition_log:
            fsm_id = str(entry["fsm_id"])
            trans_id = str(entry["transition_id"])
            ctx_key = str(entry.get("context_key") or "root")
            r_id = str(entry["route_id"])
            tokens = int(entry.get("tokens_used") or 0)
            produced = entry.get("produced_keys") or []

            on_winning_spine = (
                winning_route_id is not None
                and (
                    r_id == winning_route_id
                    and (
                        not causal_keys
                        or any((r_id, k) in causal_keys for k in produced)
                    )
                )
                or any((r_id, k) in causal_keys for k in produced)
            )

            token_cost = min(0.3, tokens / max(1.0, token_penalty_scale) * 0.1)
            reward = (1.0 - token_cost) if on_winning_spine else 0.0

            bucket = self.stats_for(
                fsm_id=fsm_id, transition_id=trans_id, context_key=ctx_key
            )
            bucket.pulls += 1
            bucket.total_tokens += tokens
            bucket.total_reward += reward
            if on_winning_spine:
                bucket.causal_wins += 1.0
            assigned[(ctx_key, fsm_id, trans_id)] = reward
        return assigned


# ---------------------------------------------------------------------------
# 2. Contextual UCB1 / Thompson Sampling Bandit Router
# ---------------------------------------------------------------------------


class ContextualBanditRouter:
    """Balances exploration & exploitation across competing guarded FSM transitions."""

    def __init__(
        self,
        credit_ledger: EdgeCreditLedger,
        *,
        strategy: Literal["ucb1", "thompson", "greedy"] = "ucb1",
        exploration_c: float = 1.2,
        rng: random.Random | None = None,
    ) -> None:
        self.credit_ledger = credit_ledger
        self.strategy = strategy
        self.exploration_c = exploration_c
        self._rng = rng or random.Random(0)

    def select_transition(
        self,
        candidates: Sequence[TransitionSpec],
        *,
        fsm_id: str,
        context_key: str = "root",
    ) -> TransitionSpec:
        if not candidates:
            raise ValueError("select_transition requires at least one candidate")
        if len(candidates) == 1:
            return candidates[0]

        total_pulls = sum(
            self.credit_ledger.stats_for(
                fsm_id=fsm_id, transition_id=t.id, context_key=context_key
            ).pulls
            for t in candidates
        )

        def score(trans: TransitionSpec) -> tuple[float, int, str]:
            st = self.credit_ledger.stats_for(
                fsm_id=fsm_id, transition_id=trans.id, context_key=context_key
            )
            prior_bonus = 0.05 * math.log1p(trans.bandit_prior_weight)
            if self.strategy == "thompson":
                val = self._rng.betavariate(st.alpha, st.beta) + prior_bonus
            elif self.strategy == "ucb1":
                if st.pulls == 0:
                    val = 10.0 + prior_bonus + trans.priority * 0.01
                else:
                    bonus = self.exploration_c * math.sqrt(
                        math.log(max(2, total_pulls + 1)) / st.pulls
                    )
                    val = st.mean_reward + bonus + prior_bonus
            else:
                val = st.mean_reward + prior_bonus
            return (val, trans.priority, trans.id)

        return max(candidates, key=score)

    def record_outcome(
        self,
        *,
        fsm_id: str,
        transition_id: str,
        context_key: str,
        reward: float,
        tokens_used: int,
    ) -> None:
        st = self.credit_ledger.stats_for(
            fsm_id=fsm_id, transition_id=transition_id, context_key=context_key
        )
        st.pulls += 1
        st.total_tokens += tokens_used
        st.total_reward += max(0.0, min(1.0, reward))
        if reward >= 0.5:
            st.causal_wins += 1.0

    def bake_weights_into_spec(
        self, spec: StateMachineSpec, *, context_key: str = "root"
    ) -> StateMachineSpec:
        """Export learned posterior means back into declarative YAML weights."""

        updated_transitions: list[TransitionSpec] = []
        for trans in spec.transitions:
            st = self.credit_ledger.stats_for(
                fsm_id=spec.fsm_id, transition_id=trans.id, context_key=context_key
            )
            if st.pulls > 0:
                weight = round(max(0.05, min(100.0, st.mean_reward * 10.0)), 4)
                trans = trans.model_copy(update={"bandit_prior_weight": weight})
            updated_transitions.append(trans)
        return spec.model_copy(update={"transitions": updated_transitions})


# ---------------------------------------------------------------------------
# 3. Atomic Declarative Graph Mutation Operators (Meta-RL Action Space)
# ---------------------------------------------------------------------------


class SplitStateOp(StrictModel):
    """Split one overloaded/timeout-prone state into two sequential states."""

    op: Literal["split_state"] = "split_state"
    target_state_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    first_state: StateNodeSpec
    second_state: StateNodeSpec
    connecting_transition_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    connecting_guard: GuardClause = Field(default_factory=GuardClause)


class AddGuardOp(StrictModel):
    """Tighten or update the GuardClause on an existing transition."""

    op: Literal["add_guard"] = "add_guard"
    transition_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    guard: GuardClause


class PruneTransitionOp(StrictModel):
    """Remove a zero-credit dead transition while preserving terminal reachability."""

    op: Literal["prune_transition"] = "prune_transition"
    transition_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")


class ExpandNodeToSubFSMOp(StrictModel):
    """Fractal Statechart growth: expand one state node into a nested Sub-FSM."""

    op: Literal["expand_node_to_sub_fsm"] = "expand_node_to_sub_fsm"
    state_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    sub_fsm_spec: StateMachineSpec


class PromoteBreakoutToSubFSMOp(StrictModel):
    """Promote an Observer breakout trajectory into a reusable triggered Micro-FSM."""

    op: Literal["promote_breakout"] = "promote_breakout"
    new_fsm_spec: StateMachineSpec


GraphMutationOp = Annotated[
    SplitStateOp
    | AddGuardOp
    | PruneTransitionOp
    | ExpandNodeToSubFSMOp
    | PromoteBreakoutToSubFSMOp,
    Field(discriminator="op"),
]


class GraphPatch(StrictModel):
    """Atomic, auditable topological diff proposed by the Outer Meta-Agent."""

    patch_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    target_fsm_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    new_version: str = Field(min_length=1, max_length=40)
    rationale: str = Field(min_length=1, max_length=1_000)
    operations: list[GraphMutationOp] = Field(min_length=1, max_length=16)


def _has_path_to_terminal(spec: StateMachineSpec) -> bool:
    terminals = {s.id for s in spec.states if s.is_terminal}
    adj: dict[str, list[str]] = {s.id: [] for s in spec.states}
    for t in spec.transitions:
        adj[t.source].append(t.target)
    visited: set[str] = set()
    stack = [spec.initial_state]
    while stack:
        cur = stack.pop()
        if cur in terminals:
            return True
        if cur in visited:
            continue
        visited.add(cur)
        stack.extend(adj.get(cur, []))
    return False


def apply_graph_patch(
    spec: StateMachineSpec,
    patch: GraphPatch,
) -> tuple[StateMachineSpec, list[StateMachineSpec]]:
    """Apply atomic topological mutations and verify reachability & static invariants.

    Returns (updated_target_spec, newly_created_companion_sub_fsms).
    """

    if patch.target_fsm_id != spec.fsm_id:
        raise ValueError(
            f"patch target '{patch.target_fsm_id}' does not match '{spec.fsm_id}'"
        )
    states = list(spec.states)
    transitions = list(spec.transitions)
    initial_state = spec.initial_state
    companion_specs: list[StateMachineSpec] = []

    for op in patch.operations:
        if isinstance(op, SplitStateOp):
            if not any(s.id == op.target_state_id for s in states):
                raise KeyError(f"split_state target not found: {op.target_state_id}")
            if op.first_state.is_terminal:
                raise ValueError("split_state first_state cannot be terminal")
            states = [
                x
                for s in states
                for x in (
                    (op.first_state, op.second_state)
                    if s.id == op.target_state_id
                    else (s,)
                )
            ]
            if initial_state == op.target_state_id:
                initial_state = op.first_state.id
            rewired: list[TransitionSpec] = []
            for t in transitions:
                new_src = (
                    op.second_state.id if t.source == op.target_state_id else t.source
                )
                new_dst = (
                    op.first_state.id if t.target == op.target_state_id else t.target
                )
                rewired.append(
                    t.model_copy(update={"source": new_src, "target": new_dst})
                )
            rewired.append(
                TransitionSpec(
                    id=op.connecting_transition_id,
                    source=op.first_state.id,
                    target=op.second_state.id,
                    guard=op.connecting_guard,
                    description=f"Split transition from {op.target_state_id}",
                )
            )
            transitions = rewired

        elif isinstance(op, AddGuardOp):
            if not any(t.id == op.transition_id for t in transitions):
                raise KeyError(f"add_guard transition not found: {op.transition_id}")
            transitions = [
                t.model_copy(update={"guard": op.guard})
                if t.id == op.transition_id
                else t
                for t in transitions
            ]

        elif isinstance(op, PruneTransitionOp):
            if not any(t.id == op.transition_id for t in transitions):
                raise KeyError(f"prune_transition target not found: {op.transition_id}")
            transitions = [t for t in transitions if t.id != op.transition_id]

        elif isinstance(op, ExpandNodeToSubFSMOp):
            if not any(s.id == op.state_id for s in states):
                raise KeyError(f"expand_node_to_sub_fsm state not found: {op.state_id}")
            sub = op.sub_fsm_spec.model_copy(update={"ad_hoc_ephemeral": False})
            companion_specs.append(sub)
            states = [
                s.model_copy(update={"sub_fsm_id": sub.fsm_id})
                if s.id == op.state_id
                else s
                for s in states
            ]

        elif isinstance(op, PromoteBreakoutToSubFSMOp):
            promoted = op.new_fsm_spec.model_copy(update={"ad_hoc_ephemeral": False})
            if promoted.trigger is None:
                raise ValueError(
                    "promoted breakout Micro-FSM requires an entity TriggerPredicate"
                )
            companion_specs.append(promoted)

    updated = StateMachineSpec(
        fsm_id=spec.fsm_id,
        version=patch.new_version,
        description=spec.description,
        trigger=spec.trigger,
        initial_state=initial_state,
        states=states,
        transitions=transitions,
        ad_hoc_ephemeral=False,
    )
    if not _has_path_to_terminal(updated):
        raise ValueError(
            f"patch '{patch.patch_id}' severed all paths from initial_state to terminal"
        )
    return updated, companion_specs


def synthesize_fsm_from_breakout(
    breakout: BreakoutEpisodeRecord,
    *,
    fsm_id: str,
    trigger: TriggerPredicate,
) -> StateMachineSpec:
    """Convert a successful Observer breakout episode into a permanent Micro-FSM."""

    if not breakout.succeeded:
        raise ValueError("cannot promote an unsuccessful breakout episode")
    if breakout.adhoc_spec is not None:
        return breakout.adhoc_spec.model_copy(
            update={
                "fsm_id": fsm_id,
                "trigger": trigger,
                "ad_hoc_ephemeral": False,
            }
        )
    return StateMachineSpec(
        fsm_id=fsm_id,
        version="0.1.0",
        description=f"Promoted from Observer breakout: {breakout.hypothesis[:200]}",
        trigger=trigger,
        initial_state="verify_hypothesis",
        states=[
            StateNodeSpec(
                id="verify_hypothesis",
                title="Verify Promoted Hypothesis",
                mode="research",
                agent_stage="analysis",
                system_prompt=(
                    f"Verify hypothesis derived from breakout: {breakout.hypothesis}"
                ),
                max_total_tokens=480_000,
                max_output_tokens=8_192,
            ),
            StateNodeSpec(
                id="done",
                title="Hypothesis Closed",
                mode="research",
                system_prompt="Terminal state.",
                is_terminal=True,
            ),
        ],
        transitions=[
            TransitionSpec(
                id="close_hypothesis",
                source="verify_hypothesis",
                target="done",
                guard=GuardClause(
                    required_sections=["checkpoint"],
                    min_status="runtime_observed",
                ),
            )
        ],
    )


# ---------------------------------------------------------------------------
# 4. Shadow Replay Regression Gate (Preserving bug_hunter's Validation Policy)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HistoricalShadowControl:
    """One captured real-run state slice used to gate candidate FSM mutations."""

    control_id: str
    kind: Literal["historical_winner", "fail_closed_control"]
    memory: TaskMemory
    route_id: str
    source_state_id: str
    expected_target_state_id: str | None
    context: dict[str, Any]


@dataclass(frozen=True)
class ShadowReplayReport:
    accepted: bool
    controls_evaluated: int
    newly_blocked_winners: tuple[str, ...]
    broken_fail_closed_controls: tuple[str, ...]


class ShadowReplayGate:
    """Validates candidate GraphPatches against historical winning & fail-closed slices.

    Enforces bug_hunter's golden rule: zero newly blocked historical winners and
    zero weakened fail-closed controls before any evolved FSM enters production.
    """

    def __init__(self, guard_registry: GuardRegistry | None = None) -> None:
        self.guard_registry = guard_registry or GuardRegistry()

    def evaluate_candidate(
        self,
        candidate_spec: StateMachineSpec,
        companion_specs: Sequence[StateMachineSpec],
        controls: Sequence[HistoricalShadowControl],
        *,
        existing_specs: Sequence[StateMachineSpec] = (),
    ) -> ShadowReplayReport:
        # 1. Verify full registry hierarchy (catches cyclic sub_fsm_id & missing guards)
        temp_registry = StateMachineRegistry(guard_registry=self.guard_registry)
        for item in existing_specs:
            if item.fsm_id != candidate_spec.fsm_id:
                temp_registry.register(item)
        for comp in companion_specs:
            temp_registry.register(comp)
        temp_registry.register(candidate_spec)

        blocked_winners: list[str] = []
        broken_controls: list[str] = []

        for ctrl in controls:
            try:
                outgoing = candidate_spec.outgoing_transitions(ctrl.source_state_id)
            except KeyError:
                outgoing = []

            enabled = [
                t
                for t in outgoing
                if t.guard.evaluate_deterministic(
                    ctrl.memory,
                    ctrl.route_id,
                    context=ctrl.context,
                    guard_registry=self.guard_registry,
                )
            ]
            chosen_target = enabled[0].target if enabled else None

            if ctrl.kind == "historical_winner":
                if chosen_target != ctrl.expected_target_state_id:
                    blocked_winners.append(ctrl.control_id)
            else:
                # Fail-closed control expects None (blocked) or safe target state
                if chosen_target != ctrl.expected_target_state_id:
                    broken_controls.append(ctrl.control_id)

        accepted = not blocked_winners and not broken_controls
        return ShadowReplayReport(
            accepted=accepted,
            controls_evaluated=len(controls),
            newly_blocked_winners=tuple(blocked_winners),
            broken_fail_closed_controls=tuple(broken_controls),
        )


# ---------------------------------------------------------------------------
# 5. Outer Meta-Evolution Agent (Diagnose -> Propose GraphPatch -> Gate -> YAML)
# ---------------------------------------------------------------------------


@dataclass
class EvolutionCycleOutcome:
    """Result of one outer-loop MetaEvolutionAgent optimization step."""

    accepted: bool
    patch: GraphPatch | None
    updated_spec: StateMachineSpec | None
    companion_specs: tuple[StateMachineSpec, ...] = ()
    replay_report: ShadowReplayReport | None = None
    persisted_yaml_paths: tuple[Path, ...] = ()
    rejection_reason: str | None = None
    usage: ModelUsage = field(default_factory=ModelUsage)


def _persist_yaml_specs_sync(
    output_dir: Path, specs: Sequence[StateMachineSpec]
) -> tuple[Path, ...]:
    resolved = output_dir.expanduser().resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for item in specs:
        path = resolved / f"{item.fsm_id}.fsm.yaml"
        path.write_text(item.to_yaml(), encoding="utf-8")
        written.append(path)
    return tuple(written)


class MetaEvolutionAgent:
    """Outer-loop Agent inspecting trajectories, emitting GraphPatch, & writing YAML."""

    def __init__(
        self,
        runtime: ManagedAgentRuntime,
        *,
        replay_gate: ShadowReplayGate | None = None,
        credit_ledger: EdgeCreditLedger | None = None,
    ) -> None:
        self._runtime = ManagedAgentRuntime(
            runtime.model_backend,
            sandbox=None,
            enable_pure_json_repair=True,
        )
        self.replay_gate = replay_gate or ShadowReplayGate()
        self.credit_ledger = credit_ledger or EdgeCreditLedger()

    def summarize_episodes(
        self,
        spec: StateMachineSpec,
        episodes: Sequence[TaskRunResult],
        *,
        context_key: str = "root",
    ) -> dict[str, Any]:
        """Build a compact diagnostic digest of failures, edge credits, & breakouts."""

        block_counts: dict[str, int] = {}
        state_blocks: dict[str, dict[str, int]] = {}
        breakouts: list[dict[str, Any]] = []

        for ep in episodes:
            for att in ep.attempts:
                if att.status == "blocked" and att.block_category:
                    block_counts[att.block_category] = (
                        block_counts.get(att.block_category, 0) + 1
                    )
                    bucket = state_blocks.setdefault(att.state_id, {})
                    bucket[att.block_category] = bucket.get(att.block_category, 0) + 1
            for brk in ep.breakout_episodes:
                if brk.succeeded:
                    breakouts.append(
                        {
                            "entity_id": brk.entity_id,
                            "tier": brk.tier,
                            "hypothesis": brk.hypothesis,
                            "discovered_claims": list(brk.discovered_claims),
                            "has_adhoc_spec": brk.adhoc_spec is not None,
                        }
                    )

        edge_telemetry = {
            t.id: {
                "pulls": (
                    st := self.credit_ledger.stats_for(
                        fsm_id=spec.fsm_id,
                        transition_id=t.id,
                        context_key=context_key,
                    )
                ).pulls,
                "causal_wins": st.causal_wins,
                "mean_reward": round(st.mean_reward, 4),
                "total_tokens": st.total_tokens,
            }
            for t in spec.transitions
        }
        return {
            "target_fsm": spec.model_dump(mode="json"),
            "episode_count": len(episodes),
            "pass_count": sum(ep.status == "passed" for ep in episodes),
            "block_counts": block_counts,
            "state_blocks": state_blocks,
            "edge_telemetry": edge_telemetry,
            "successful_breakouts": breakouts,
        }

    async def evolve_once(
        self,
        spec: StateMachineSpec,
        episodes: Sequence[TaskRunResult],
        *,
        controls: Sequence[HistoricalShadowControl] = (),
        existing_specs: Sequence[StateMachineSpec] = (),
        yaml_output_dir: Path | None = None,
        context_key: str = "root",
        max_total_tokens: int = 128_000,
    ) -> EvolutionCycleOutcome:
        """Run one end-to-end outer evolution step and persist validated YAML specs."""

        import asyncio
        import json

        summary = self.summarize_episodes(spec, episodes, context_key=context_key)
        definition = AgentDefinition(
            id="vouchloom.meta-evolution-agent",
            version="0.1.0",
            system_prompt=(
                "You are the Outer Meta-Evolution Agent for Vouchloom. Analyze the "
                "target StateMachineSpec, state timeout/block counts, backward causal "
                "edge telemetry, and successful Observer breakouts. Emit one atomic "
                "GraphPatch (split_state, add_guard, prune_transition, "
                "expand_node_to_sub_fsm, or promote_breakout) that improves the state "
                "machine while preserving terminal reachability and historical winners."
            ),
            output_model=GraphPatch,
            max_total_tokens=max_total_tokens,
            max_output_tokens=8_192,
            allow_tools=False,
            max_turn_seconds=180,
        )
        try:
            trace = await self._runtime.run(
                definition,
                json.dumps(summary, ensure_ascii=False, separators=(",", ":")),
            )
            patch = GraphPatch.model_validate(trace.result)
        except (AgentRuntimeError, ValueError) as err:
            return EvolutionCycleOutcome(
                accepted=False,
                patch=None,
                updated_spec=None,
                rejection_reason=f"patch generation failed: {err}",
            )

        try:
            candidate_spec, companions = apply_graph_patch(spec, patch)
            report = self.replay_gate.evaluate_candidate(
                candidate_spec,
                companions,
                controls,
                existing_specs=existing_specs,
            )
        except (KeyError, ValueError) as err:
            return EvolutionCycleOutcome(
                accepted=False,
                patch=patch,
                updated_spec=None,
                rejection_reason=f"static topology or guard validation failed: {err}",
                usage=trace.usage,
            )

        if not report.accepted:
            return EvolutionCycleOutcome(
                accepted=False,
                patch=patch,
                updated_spec=candidate_spec,
                companion_specs=tuple(companions),
                replay_report=report,
                rejection_reason=(
                    f"ShadowReplayGate rejected patch: "
                    f"blocked_winners={report.newly_blocked_winners}, "
                    f"broken_controls={report.broken_fail_closed_controls}"
                ),
                usage=trace.usage,
            )

        persisted: tuple[Path, ...] = ()
        if yaml_output_dir is not None:
            persisted = await asyncio.to_thread(
                _persist_yaml_specs_sync,
                yaml_output_dir,
                [candidate_spec, *companions],
            )
        return EvolutionCycleOutcome(
            accepted=True,
            patch=patch,
            updated_spec=candidate_spec,
            companion_specs=tuple(companions),
            replay_report=report,
            persisted_yaml_paths=persisted,
            usage=trace.usage,
        )
