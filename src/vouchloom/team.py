"""Agent Team Orchestrator, Route Controller, Reviewer, & Two-Tier Observer.

Combines bug_hunter's battle-tested deterministic routing, receipt gates,
Memory Reviewer (+TransitionAudit), and write-ahead finalization with:
- Claude Code style Supervisor + Ephemeral Context-Isolated Workers
- Automatic 1 -> N Entity-Triggered Sub-FSM spawning
- Two-Tier Observer leashed breakouts (5-call Exploratory Probe & Ad-hoc Sub-FSM).
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import Field

from vouchloom.agent import (
    AgentDefinition,
    AgentRuntimeError,
    AgentSkill,
    ArtifactOutput,
    HandoffOutput,
    InlineArtifactSource,
    MemoryItem,
    MemoryReviewOutput,
    PathArtifactSource,
    ResearchHandoff,
    WorkerArtifactOnlyOutput,
    WorkerHandoffOnlyOutput,
    WorkerModelOutput,
    decode_strict_base64,
    recover_research_handoff,
)
from vouchloom.arbiters import SemanticArbiterSuite
from vouchloom.audit import write_debug_event, write_task_audit_bundle
from vouchloom.fsm import (
    StateMachineRegistry,
    StateMachineSpec,
    StateNodeSpec,
    TransitionSpec,
)
from vouchloom.memory import (
    CORE_OWNED_KEY_PREFIX,
    ProofLedgerEntry,
    ProofSection,
    RouteSummary,
    TaskMemory,
    TaskMemoryConclusion,
    TaskMemoryEntity,
    TaskMemorySnapshot,
    TaskMemoryStore,
    conclusion_rejection_reason,
    dependency_closed_runtime_frontier,
    ledger_entry_contradicts_route,
)
from vouchloom.models import (
    ROTATABLE_CAUSAL_DIMENSIONS,
    BlockCategory,
    CausalDimension,
    ModelUsage,
    StrictModel,
    TaskBudgetEnvelope,
)
from vouchloom.proof import delivery_stage_ready
from vouchloom.receipts import (
    ExecutionReceipt,
    NextAction,
    SidebandSignal,
)
from vouchloom.request_budget import RequestBudget
from vouchloom.runtime import ManagedAgentRuntime

SEMANTIC_ROUTE_FAILURES = frozenset(
    {"target_no_effect", "semantic_route_duplicate", "duplicate_candidate"}
)

_ITEM_KIND_TO_PROOF_SECTION: dict[str, ProofSection] = {
    "contract": "target_contract",
    "protocol": "state_transition",
    "call_edge": "call_edge",
    "sink": "sink",
    "condition": "condition",
    "construction": "construction",
    "observation": "checkpoint",
    "gap": "open_gap",
}


class DynamicConcurrencyLimiter:
    """Resize future Worker admission dynamically without cancelling active slots."""

    def __init__(self, target: int) -> None:
        if target < 1:
            raise ValueError("concurrency target must be at least 1")
        self._target = target
        self._active = 0
        self._condition = asyncio.Condition()

    @property
    def target(self) -> int:
        return self._target

    @property
    def active(self) -> int:
        return self._active

    async def resize(self, target: int) -> None:
        if target < 1:
            raise ValueError("concurrency target must be at least 1")
        async with self._condition:
            self._target = target
            self._condition.notify_all()

    async def acquire(self) -> None:
        async with self._condition:
            await self._condition.wait_for(lambda: self._active < self._target)
            self._active += 1

    async def release(self) -> None:
        async with self._condition:
            if self._active < 1:
                raise RuntimeError("concurrency slot released without owner")
            self._active -= 1
            self._condition.notify_all()

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        await self.acquire()
        try:
            yield
        finally:
            await asyncio.shield(self.release())


class AttemptRecord(StrictModel):
    """Canonical single attempt record generalizing CyberGymAttempt."""

    number: int = Field(ge=1)
    route_id: str = Field(pattern=r"^route-[0-9]{3,}$")
    entity_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{0,119}$")
    fsm_id: str
    state_id: str
    status: Literal[
        "generated", "duplicate", "submitted", "milestone_candidate", "blocked", "error"
    ]
    block_category: BlockCategory | None = None
    artifact_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    artifact_size: int | None = Field(default=None, ge=1)
    causal_dimension: CausalDimension = "unclassified"
    changed_constraint: str | None = None
    semantic_checkpoint: str | None = None
    duplicate: bool = False
    semantic_duplicate: bool = False
    safe_path_diagnostic: Literal["semantic_no_fault"] | None = None
    initial_receipt: ExecutionReceipt | None = None
    replay_receipt: ExecutionReceipt | None = None
    fingerprint_match: bool | None = None
    error: str | None = None

    def stopped_at_startup(self) -> bool:
        receipt = self.replay_receipt or self.initial_receipt
        return receipt is not None and receipt.phase == "environment_startup"


# ---------------------------------------------------------------------------
# Memory Review Transition Audit (exact generalization of cybergym_transition_audit.py)
# ---------------------------------------------------------------------------

ReviewStatus = Literal["resume", "stop", "blocked"]
ReviewConfidence = Literal["source_backed", "insufficient"]
ReviewTransitionAction = Literal[
    "continue_route", "replace_route", "terminate", "fresh_solver"
]


@dataclass(frozen=True)
class MemoryReviewTransitionAudit:
    severity: Literal["consistent", "invalid"]
    action: ReviewTransitionAction
    codes: tuple[str, ...]


def audit_memory_review_transition(
    before: TaskMemory,
    *,
    status: ReviewStatus,
    confidence: ReviewConfidence,
    next_step: str | None,
    updates: Sequence[ProofLedgerEntry],
    after: TaskMemory,
) -> MemoryReviewTransitionAudit:
    """Verify Reviewer state transition invariants independently of ledger pruning."""

    codes: list[str] = []
    active_route_id = before.active_route_id
    if active_route_id is None or before.route_decision is None:
        codes.append("review_without_active_route")
    elif any(
        r.route_id == active_route_id and r.support == "contradicted"
        for r in before.routes
    ):
        codes.append("review_started_on_contradicted_route")
    if after.active_route_id != active_route_id:
        codes.append("review_changed_active_route")
    if any(u.route_id != active_route_id for u in updates):
        codes.append("review_delta_outside_active_route")

    before_by_key = {(x.route_id, x.key): x for x in before.proof_ledger}
    after_by_key = {(x.route_id, x.key): x for x in after.proof_ledger}
    retained_updates = [
        u for u in updates if after_by_key.get((u.route_id, u.key)) == u
    ]
    structural_updates = [u for u in updates if ledger_entry_contradicts_route(u)]
    retained_structural = [
        u for u in retained_updates if ledger_entry_contradicts_route(u)
    ]
    if updates and len(retained_updates) != len(updates):
        codes.append("review_delta_partially_pruned")

    if status == "blocked":
        if confidence != "insufficient":
            codes.append("blocked_review_claimed_source_authority")
        if updates:
            codes.append("blocked_review_mutated_ledger")
        return MemoryReviewTransitionAudit(
            severity="invalid" if codes else "consistent",
            action="fresh_solver",
            codes=tuple(codes),
        )

    if confidence != "source_backed":
        codes.append("decisive_review_without_source_authority")

    if status == "stop":
        preexisting_req = [
            u
            for u in structural_updates
            if (prev := before_by_key.get((u.route_id, u.key))) is not None
            and prev.section == "condition"
            and prev.condition_role == "required"
        ]
        if not preexisting_req:
            codes.append("stop_without_preexisting_required_contradiction")
        elif not any(u in retained_structural for u in preexisting_req):
            codes.append("stop_predicate_pruned")
        return MemoryReviewTransitionAudit(
            severity="invalid" if codes else "consistent",
            action="terminate",
            codes=tuple(codes),
        )

    if next_step is None or not next_step.strip():
        codes.append("resume_without_next_step")
    if not updates:
        codes.append("resume_without_material_delta")
    if structural_updates:
        retired = any(
            r.route_id == active_route_id and r.support == "contradicted"
            for r in after.routes
        )
        if not retired:
            codes.append("replace_route_not_retired")
        codes = [c for c in codes if c != "review_delta_partially_pruned"]
        return MemoryReviewTransitionAudit(
            severity="invalid" if codes else "consistent",
            action="replace_route",
            codes=tuple(codes),
        )
    if updates and not retained_updates:
        codes.append("resume_delta_pruned")
    return MemoryReviewTransitionAudit(
        severity="invalid" if codes else "consistent",
        action="continue_route",
        codes=tuple(codes),
    )


# ---------------------------------------------------------------------------
# Deterministic Route Controller (Zero LLM Tokens)
# ---------------------------------------------------------------------------


class DeterministicRouteController:
    """Pure-Python route selector preserving bug_hunter/_select_poc_route."""

    def select_route(
        self,
        store: TaskMemoryStore,
        attempts: Sequence[AttemptRecord],
        *,
        attempt_number: int,
        default_fsm_id: str = "default",
        default_initial_state: str = "initial",
    ) -> RouteSummary:
        board = store.load()
        previous = attempts[-1] if attempts else None
        active = next(
            (r for r in board.routes if r.route_id == board.active_route_id), None
        )

        if board.active_route_id is None:
            # Prefer any already-spawned paused/active non-contradicted route first
            ready_existing = next(
                (
                    r
                    for r in board.routes
                    if r.support != "contradicted"
                    and r.lifecycle in {"active", "paused"}
                ),
                None,
            )
            if ready_existing is not None:
                return store.apply_route_decision(
                    action="reopen",
                    route_id=ready_existing.route_id,
                    attempt=attempt_number,
                    rationale="Activate spawned entity Micro-FSM route.",
                    model="core-deterministic",
                    causal_dimension="input_boundary",
                )
            return store.apply_route_decision(
                action="new",
                route_id=None,
                attempt=attempt_number,
                rationale="Start the first evidence-backed route.",
                model="core-deterministic",
                entity_id="root",
                fsm_id=default_fsm_id,
                initial_state_id=default_initial_state,
                causal_dimension="input_boundary",
                required_constraint="Resolve entry boundary and one complete path.",
                forbidden_repeat="Do not emit while target contract is ambiguous.",
            )

        contradicted = active is not None and active.support == "contradicted"
        if previous is None:
            return store.apply_route_decision(
                action="new" if contradicted else "continue",
                route_id=None if contradicted else board.active_route_id,
                attempt=attempt_number,
                rationale=(
                    "Start replacement root after structural contradiction."
                    if contradicted
                    else "Continue initialized route before execution feedback."
                ),
                model="core-deterministic",
                fsm_id=active.fsm_id if active else default_fsm_id,
                initial_state_id=default_initial_state,
                causal_dimension="precondition_gate",
            )

        if previous.status == "milestone_candidate":
            if previous.stopped_at_startup():
                return store.apply_route_decision(
                    action="new" if contradicted else "continue",
                    route_id=None if contradicted else board.active_route_id,
                    attempt=attempt_number,
                    rationale=(
                        "Obtain target_runtime receipt; startup exit is not proof."
                    ),
                    model="core-deterministic",
                    fsm_id=active.fsm_id if active else default_fsm_id,
                    initial_state_id=default_initial_state,
                    causal_dimension="evidence_arbitration",
                )
            return store.apply_route_decision(
                action="new" if contradicted else "fork",
                route_id=None if contradicted else board.active_route_id,
                attempt=attempt_number,
                rationale=(
                    "Retain first milestone as fallback while probing causal identity."
                ),
                model="core-deterministic",
                fsm_id=active.fsm_id if active else default_fsm_id,
                initial_state_id=default_initial_state,
                causal_dimension="precondition_gate",
                required_constraint=(
                    "Verify exact task claim identity or probe distinct causal path."
                ),
                forbidden_repeat=(
                    "Do not rematerialize byte/size variants at same site."
                ),
            )

        dim, required, forbidden = self._requirement_from_failure(previous, board)
        exact_dup = (
            previous.block_category == "duplicate_candidate" or previous.duplicate
        )
        sem_dup = previous.semantic_duplicate
        action: Literal["new", "fork", "continue"] = (
            "new" if contradicted else ("fork" if sem_dup or exact_dup else "continue")
        )
        return store.apply_route_decision(
            action=action,
            route_id=None if contradicted else board.active_route_id,
            attempt=attempt_number,
            rationale=(
                "Start replacement root because prior proof chain was contradicted."
                if contradicted
                else (
                    "Fork retained evidence into fresh writable route after duplicate."
                    if action == "fork"
                    else "Retain active route because failure did not contradict proof."
                )
            ),
            model="core-deterministic",
            entity_id=active.entity_id if active else "root",
            fsm_id=active.fsm_id if active else default_fsm_id,
            initial_state_id=default_initial_state,
            causal_dimension=dim,
            required_constraint=required,
            forbidden_repeat=forbidden,
        )

    @staticmethod
    def _requirement_from_failure(
        previous: AttemptRecord, board: TaskMemory
    ) -> tuple[CausalDimension, str, str]:
        if previous.status == "submitted":
            cat = (
                "semantic_route_duplicate"
                if previous.semantic_duplicate
                else "target_no_effect"
            )
            dim: CausalDimension = "evidence_arbitration"
            req = (
                "Determine whether predicate was rejected or reached without effect; "
                "trace to the next consumer."
            )
        elif previous.status == "duplicate":
            cat = "duplicate_candidate"
            dim = "construction_encoding"
            req = "Produce a materially different semantic constraint, not same bytes."
        elif previous.block_category in {
            "token_budget_exhausted",
            "schema_invalid",
            "artifact_deadline_missed",
            "turn_wall_timeout",
            "context_budget_exceeded",
        }:
            cat = previous.block_category or "tool_completion"
            dim = "tool_completion"
            req = "Close top gap, persist artifact, and return typed JSON promptly."
        else:
            cat = previous.block_category or "generation_failed"
            dim = "evidence_arbitration"
            req = "Resolve concrete conflict in retained evidence before emitting."

        active_route = next(
            (r for r in board.routes if r.route_id == board.active_route_id), None
        )
        decision = board.route_decision
        if (
            decision is not None
            and active_route is not None
            and max(
                (
                    cnt
                    for k, cnt in active_route.failure_counts.items()
                    if k in SEMANTIC_ROUTE_FAILURES
                ),
                default=0,
            )
            >= 2
            and dim == decision.causal_dimension
        ):
            dim = next(
                d for d in ROTATABLE_CAUSAL_DIMENSIONS if d != decision.causal_dimension
            )
            req = "Rotate causal dimension after two matching semantic failures."
        forbidden = f"Do not repeat prior {cat.replace('_', ' ')} unchanged."
        return dim, req, forbidden


# ---------------------------------------------------------------------------
# Two-Tier Observer (Leashed Probe + Validated Ad-Hoc Sub-FSM Breakout)
# ---------------------------------------------------------------------------


class ObserverDecisionOutput(StrictModel):
    action: Literal["keep_course", "tier1_exploratory_probe", "tier2_mount_adhoc_fsm"]
    rationale: str = Field(min_length=1, max_length=500)
    probe_target: str | None = Field(default=None, max_length=300)
    probe_hypothesis: str | None = Field(default=None, max_length=400)
    adhoc_fsm: StateMachineSpec | None = None


@dataclass(frozen=True)
class BreakoutEpisodeRecord:
    """Captured breakout record fed to Layer 4 RL for PromoteBreakoutToSubFSM."""

    entity_id: str
    trigger_signal: SidebandSignal | None
    tier: Literal["tier1_probe", "tier2_adhoc_fsm"]
    hypothesis: str
    succeeded: bool
    adhoc_spec: StateMachineSpec | None = None
    discovered_claims: tuple[str, ...] = ()


class TwoTierObserver:
    """Out-of-band Observer enforcing leashed exploration & static Sub-FSM checks."""

    def __init__(
        self,
        runtime: ManagedAgentRuntime | None = None,
        *,
        stall_threshold: int = 3,
        probe_max_tokens: int = 240_000,
        probe_max_tool_calls: int = 5,
        max_adhoc_states: int = 6,
    ) -> None:
        self._runtime = (
            ManagedAgentRuntime(runtime.model_backend, sandbox=None)
            if runtime is not None
            else None
        )
        self.stall_threshold = stall_threshold
        self.probe_max_tokens = probe_max_tokens
        self.probe_max_tool_calls = probe_max_tool_calls
        self.max_adhoc_states = max_adhoc_states

    def should_wake(
        self,
        *,
        route: RouteSummary,
        verified_signals: Sequence[SidebandSignal],
    ) -> bool:
        return bool(verified_signals) or route.stall_count >= self.stall_threshold

    async def evaluate(
        self,
        *,
        board: TaskMemory,
        route: RouteSummary,
        verified_signals: Sequence[SidebandSignal],
        registry: StateMachineRegistry,
    ) -> tuple[ObserverDecisionOutput, ModelUsage]:
        if self._runtime is None:
            # Deterministic fallback: Tier 1 leashed probe on verified signal
            if verified_signals:
                sig = verified_signals[0]
                return (
                    ObserverDecisionOutput(
                        action="tier1_exploratory_probe",
                        rationale=f"Leashed probe for verified signal {sig.signal_id}",
                        probe_target=sig.entity_id,
                        probe_hypothesis=sig.proposed_hypothesis,
                    ),
                    ModelUsage(),
                )
            return (
                ObserverDecisionOutput(
                    action="keep_course",
                    rationale="No verified anomaly requiring breakout.",
                ),
                ModelUsage(),
            )

        definition = AgentDefinition(
            id="vouchloom-observer",
            version="0.1.0",
            system_prompt=(
                "You are the Out-of-Band Observer. Inspect verified sideband signals "
                "and route stall state. Choose keep_course, tier1_exploratory_probe "
                "(<=5 tool calls), or tier2_mount_adhoc_fsm (ephemeral <=6-state FSM "
                "for an unmodeled multi-step sub-domain)."
            ),
            output_model=ObserverDecisionOutput,
            max_total_tokens=64_000,
            max_output_tokens=4_096,
            allow_tools=False,
            max_turn_seconds=120,
        )
        payload = {
            "route": route.model_dump(mode="json"),
            "signals": [s.model_dump(mode="json") for s in verified_signals],
            "registered_fsms": [spec.fsm_id for spec in registry.all_specs()],
        }
        trace = await self._runtime.run(
            definition,
            TaskMemorySnapshot.model_validate(board.prompt_snapshot()).model_dump_json()
            + "\n"
            + str(payload),
        )
        decision = ObserverDecisionOutput.model_validate(trace.result)
        if decision.action == "tier2_mount_adhoc_fsm":
            if (
                decision.adhoc_fsm is None
                or len(decision.adhoc_fsm.states) > self.max_adhoc_states
            ):
                return (
                    ObserverDecisionOutput(
                        action="tier1_exploratory_probe",
                        rationale=(
                            "Downgraded oversized/missing ad-hoc FSM to Tier 1 probe."
                        ),
                        probe_target=route.entity_id,
                        probe_hypothesis=decision.rationale[:300],
                    ),
                    trace.usage,
                )
            adhoc = decision.adhoc_fsm.model_copy(update={"ad_hoc_ephemeral": True})
            registry.register(adhoc)
            decision = decision.model_copy(update={"adhoc_fsm": adhoc})
        return decision, trace.usage

    def build_leashed_probe_node(
        self, *, target: str, hypothesis: str
    ) -> StateNodeSpec:
        return StateNodeSpec(
            id="observer.leashed-probe",
            title=f"Leashed Breakout Probe ({target})",
            mode="exploratory_probe",
            agent_stage="analysis",
            system_prompt=(
                "LEASHED EXPLORATORY PROBE: Test ONLY the supplied hypothesis on "
                f"target '{target}': {hypothesis}. Do not broaden scope. Return a "
                "typed handoff with receipt-backed observations."
            ),
            max_total_tokens=self.probe_max_tokens,
            max_output_tokens=4_096,
            finalization_tool_calls=self.probe_max_tool_calls,
            max_turn_seconds=300,
        )


# ---------------------------------------------------------------------------
# Supervisor Frontier Scheduler & Team Orchestrator
# ---------------------------------------------------------------------------


class TargetEvaluator(Protocol):
    """Domain-specific target verifier (e.g., vulnerable run + fresh replay)."""

    async def evaluate_candidate(
        self,
        content: bytes,
        *,
        route: RouteSummary,
        is_replay: bool = False,
    ) -> ExecutionReceipt: ...


class TransitionRouter(Protocol):
    """Optional Bandit router hook for selecting among enabled transitions."""

    def select_transition(
        self,
        candidates: Sequence[TransitionSpec],
        *,
        fsm_id: str,
        context_key: str,
    ) -> TransitionSpec: ...

    def record_outcome(
        self,
        *,
        fsm_id: str,
        transition_id: str,
        context_key: str,
        reward: float,
        tokens_used: int,
    ) -> None: ...


@dataclass
class TaskRunResult:
    task_id: str
    status: Literal["passed", "candidate", "not_reproduced", "blocked", "completed"]
    budget: TaskBudgetEnvelope
    attempts: list[AttemptRecord] = field(default_factory=list)
    final_artifact: bytes | None = None
    final_artifact_sha256: str | None = None
    breakout_episodes: list[BreakoutEpisodeRecord] = field(default_factory=list)
    transition_log: list[dict[str, Any]] = field(default_factory=list)
    audit_zip_path: Path | None = None


class SupervisorScheduler:
    """Prioritizes active entity Micro-FSM routes & wires cross-branch clues."""

    def rank_runnable_routes(
        self,
        board: TaskMemory,
        registry: StateMachineRegistry,
    ) -> list[RouteSummary]:
        runnable: list[tuple[tuple[int, int, int, str], RouteSummary]] = []
        for route in board.routes:
            if route.support == "contradicted" or route.lifecycle in {
                "abandoned",
                "completed",
            }:
                continue
            spec = registry.get(route.fsm_id)
            state_node = spec.state_by_id(route.current_state_id)
            if state_node.is_terminal:
                continue
            cross_clues = sum(
                1 for x in board.proof_ledger if route.entity_id in x.cross_entity_refs
            )
            priority_key = (
                1 if route.lifecycle == "active" else 0,
                cross_clues,
                -route.stall_count,
                route.route_id,
            )
            runnable.append((priority_key, route))
        runnable.sort(key=lambda pair: pair[0], reverse=True)
        return [r for _, r in runnable]

    def cross_entity_briefing(
        self, board: TaskMemory, entity_id: str
    ) -> list[dict[str, Any]]:
        """Collect verified clues discovered on sibling branches targeting entity_id."""

        clues: list[dict[str, Any]] = []
        for cell in board.proof_ledger:
            if (
                cell.entity_id != entity_id
                and entity_id in cell.cross_entity_refs
                and cell.status
                in {"source_backed", "artifact_encoded", "runtime_observed"}
            ):
                clues.append(
                    {
                        "from_entity": cell.entity_id,
                        "from_route": cell.route_id,
                        "key": cell.key,
                        "claim": cell.claim,
                        "evidence": cell.evidence[:2],
                    }
                )
        return clues[:8]


def _resolve_dir_sync(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def _read_work_artifact_sync(work_dir: Path, rel_path: str) -> bytes | None:
    root = work_dir.resolve()
    cand = (root / rel_path).resolve()
    if not cand.is_relative_to(root) or not cand.is_file():
        return None
    return cand.read_bytes()


def convert_handoff_items_to_updates(
    items: Sequence[MemoryItem],
    *,
    route_id: str,
    entity_id: str,
    attempt_number: int,
    carrier_ids: set[str],
    durable_note_ids: set[str],
    construction_blockers: dict[str, list[str]],
    classify_unfiltered: bool = False,
) -> tuple[list[TaskMemoryConclusion], list[ProofLedgerEntry]]:
    """Convert Worker MemoryItems into TaskMemory conclusions & ProofLedgerEntries."""

    conclusions: list[TaskMemoryConclusion] = []
    ledger: list[ProofLedgerEntry] = []

    for item in items:
        if item.id.startswith(CORE_OWNED_KEY_PREFIX):
            continue
        if item.kind == "note":
            if not classify_unfiltered and item.id not in durable_note_ids:
                continue
            cand = TaskMemoryConclusion(
                key=item.id,
                kind="fact" if item.status != "hypothesis" else "hypothesis",
                statement=item.claim,
                confidence=(
                    "high_confidence"
                    if item.status in {"source_backed", "runtime_observed"}
                    else "general_confidence"
                ),
                status=(
                    "contradicted"
                    if item.status == "contradicted"
                    else ("supported" if item.status != "hypothesis" else "uncertain")
                ),
                scope="route",
                route_id=route_id,
                entity_id=entity_id,
                evidence=item.evidence,
                updated_attempt=attempt_number,
            )
            if conclusion_rejection_reason(cand) is None:
                conclusions.append(cand)
            continue

        section = _ITEM_KIND_TO_PROOF_SECTION[item.kind]
        is_carrier = section == "construction" and (
            classify_unfiltered or item.id in carrier_ids
        )
        if section == "construction" and not is_carrier:
            section = "checkpoint"
        deps = list(
            dict.fromkeys([*item.depends_on, *construction_blockers.get(item.id, [])])
        )
        ledger.append(
            ProofLedgerEntry(
                key=item.id,
                section=section,
                carrier_construction=is_carrier,
                claim=item.claim,
                status=item.status,
                condition_role=item.role,
                depends_on=deps,
                cross_entity_refs=list(item.cross_entity_refs),
                evidence=item.evidence,
                route_id=route_id,
                entity_id=entity_id,
                updated_attempt=attempt_number,
            )
        )
    return conclusions, ledger


class TeamOrchestrator:
    """Hierarchical FSM + Agent Team + Two-Tier Observer execution engine."""

    def __init__(
        self,
        *,
        registry: StateMachineRegistry,
        worker_runtime_factory: Callable[[Path], ManagedAgentRuntime],
        arbiters: SemanticArbiterSuite | None = None,
        observer: TwoTierObserver | None = None,
        evaluator: TargetEvaluator | None = None,
        transition_router: TransitionRouter | None = None,
        skills: dict[str, AgentSkill] | None = None,
        concurrency: int = 2,
    ) -> None:
        self.registry = registry
        self.worker_runtime_factory = worker_runtime_factory
        self.arbiters = arbiters or SemanticArbiterSuite(None)
        self.observer = observer or TwoTierObserver(None)
        self.evaluator = evaluator
        self.transition_router = transition_router
        self.skills = skills or {}
        self.limiter = DynamicConcurrencyLimiter(concurrency)
        self.route_controller = DeterministicRouteController()
        self.supervisor = SupervisorScheduler()

    async def run_task(
        self,
        *,
        task_id: str,
        root_fsm_id: str,
        task_dir: Path,
        objective: str,
        anchor_evidence: dict[str, Any] | None = None,
        total_token_limit: int = 3_600_000,
        max_generations: int = 32,
    ) -> TaskRunResult:
        resolved_dir = await asyncio.to_thread(_resolve_dir_sync, task_dir)
        debug_dir = resolved_dir / "debug"
        store = TaskMemoryStore(resolved_dir / "memory.json", task_id)
        store.merge_conclusions([])  # Initialize root entity & memory on disk

        root_spec = self.registry.get(root_fsm_id)
        budget = TaskBudgetEnvelope(
            total_token_limit=total_token_limit,
            initial_total_token_limit=total_token_limit,
        )
        result = TaskRunResult(task_id=task_id, status="blocked", budget=budget)
        anchor = anchor_evidence or {
            "target": task_id,
            "complete": True,
            "ambiguous": False,
        }
        seen_artifacts: set[str] = set()
        spawned_entity_fsms: set[tuple[str, str]] = {("root", root_fsm_id)}
        required_actions_by_route: dict[str, NextAction] = {}
        retried_receipt_ids: set[str] = set()
        reviews_completed = 0

        # Ensure initial root route exists
        self.route_controller.select_route(
            store,
            result.attempts,
            attempt_number=1,
            default_fsm_id=root_fsm_id,
            default_initial_state=root_spec.initial_state,
        )

        for generation in range(1, max_generations + 1):
            if budget.remaining_tokens < 16_000:
                if (
                    reviews_completed < 2
                    and not any(
                        a.status == "milestone_candidate" for a in result.attempts
                    )
                    and await self._run_memory_review(
                        store=store,
                        budget=budget,
                        review_index=reviews_completed,
                        task_dir=resolved_dir,
                        objective=objective,
                    )
                ):
                    reviews_completed += 1
                    continue
                break

            milestones = [
                a
                for a in result.attempts
                if a.status == "milestone_candidate"
                and not a.duplicate
                and not a.semantic_duplicate
            ]
            if len(milestones) >= 2 or (
                milestones and budget.verification_window_exhausted
            ):
                break

            board = store.load()
            runnable = self.supervisor.rank_runnable_routes(board, self.registry)
            if not runnable:
                # Invoke deterministic controller if active route was contradicted
                active = next(
                    (r for r in board.routes if r.route_id == board.active_route_id),
                    None,
                )
                if active is not None and active.support == "contradicted":
                    new_r = self.route_controller.select_route(
                        store,
                        result.attempts,
                        attempt_number=len(result.attempts) + 1,
                        default_fsm_id=root_fsm_id,
                        default_initial_state=root_spec.initial_state,
                    )
                    runnable = [new_r]
                else:
                    break

            batch_routes = runnable[: self.limiter.target]
            await asyncio.gather(
                *(
                    self._execute_route_step(
                        route=route,
                        generation=generation,
                        objective=objective,
                        anchor=anchor,
                        store=store,
                        result=result,
                        task_dir=resolved_dir,
                        debug_dir=debug_dir,
                        seen_artifacts=seen_artifacts,
                        spawned_entity_fsms=spawned_entity_fsms,
                        required_actions_by_route=required_actions_by_route,
                        retried_receipt_ids=retried_receipt_ids,
                    )
                    for route in batch_routes
                )
            )

        # Finalize task outcome & deterministic audit ZIP
        winning = next(
            (a for a in result.attempts if a.status == "milestone_candidate"),
            None,
        )
        artifacts_map: dict[str, bytes] = {}
        if winning is not None and winning.artifact_sha256 is not None:
            cand_file = resolved_dir / "attempts" / f"attempt-{winning.number:02d}.bin"
            if cand_file.is_file():
                raw_final = cand_file.read_bytes()
                (resolved_dir / "final.bin").write_bytes(raw_final)
                result.final_artifact = raw_final
                result.final_artifact_sha256 = winning.artifact_sha256
                artifacts_map["final.bin"] = raw_final
            result.status = "passed" if winning.fingerprint_match else "candidate"
        else:
            final_board = store.load()
            all_completed = bool(final_board.routes) and all(
                r.lifecycle == "completed" for r in final_board.routes
            )
            if all_completed:
                result.status = "completed"
            elif any(a.status == "submitted" for a in result.attempts):
                result.status = "not_reproduced"
            else:
                result.status = "blocked"

        result.audit_zip_path = write_task_audit_bundle(
            resolved_dir,
            task_id=task_id,
            outcome_label=result.status,
            state_payload={
                "task_id": task_id,
                "status": result.status,
                "budget": budget.model_dump(mode="json"),
                "attempts": [a.model_dump(mode="json") for a in result.attempts],
                "transitions": result.transition_log,
            },
            memory_path=store.path,
            artifacts=artifacts_map,
        )
        return result

    async def _execute_route_step(
        self,
        *,
        route: RouteSummary,
        generation: int,
        objective: str,
        anchor: dict[str, Any],
        store: TaskMemoryStore,
        result: TaskRunResult,
        task_dir: Path,
        debug_dir: Path,
        seen_artifacts: set[str],
        spawned_entity_fsms: set[tuple[str, str]],
        required_actions_by_route: dict[str, NextAction],
        retried_receipt_ids: set[str],
    ) -> None:
        async with self.limiter.slot():
            board = store.load()
            spec = self.registry.get(route.fsm_id)
            state_node = spec.state_by_id(route.current_state_id)

            # Hierarchical Sub-FSM expansion: if current state delegates to sub_fsm_id
            if state_node.sub_fsm_id is not None:
                sub_spec = self.registry.get(state_node.sub_fsm_id)
                key = (route.entity_id, sub_spec.fsm_id)
                if key not in spawned_entity_fsms:
                    spawned_entity_fsms.add(key)
                    store.apply_route_decision(
                        action="new",
                        route_id=None,
                        attempt=len(result.attempts) + 1,
                        rationale=f"Enter nested Sub-FSM {sub_spec.fsm_id}",
                        model="core-sub-fsm",
                        entity_id=route.entity_id,
                        fsm_id=sub_spec.fsm_id,
                        initial_state_id=sub_spec.initial_state,
                    )
                self._advance_fsm_state(
                    store=store,
                    route_id=route.route_id,
                    spec=spec,
                    action_outcome="completed",
                    tokens_used=0,
                    produced_keys=[],
                    result=result,
                )
                return

            work_dir = task_dir / "workers" / route.route_id
            work_dir.mkdir(parents=True, exist_ok=True)
            if state_node.required_artifact_path:
                art_file = work_dir / state_node.required_artifact_path
                if art_file.exists():
                    art_file.unlink()
            memory_view_path = store.publish_agent_view(work_dir)
            snapshot = store.load().prompt_snapshot()

            # Check deterministic RuntimeFrontier override
            req_action = required_actions_by_route.get(route.route_id)
            if req_action is None and state_node.mode == "research":
                rt_frontier = dependency_closed_runtime_frontier(
                    snapshot, route.route_id
                )
                if rt_frontier is not None:
                    fid = hashlib.sha256(
                        f"{rt_frontier.route_id}:{rt_frontier.gap_key}".encode()
                    ).hexdigest()[:12]
                    req_action = NextAction(
                        id=f"runtime-frontier.{fid}",
                        kind="execute",
                        target=(
                            f"{rt_frontier.sink_key} via {rt_frontier.construction_key}"
                        ),
                        expected_observation=rt_frontier.gap_claim,
                    )
                    required_actions_by_route[route.route_id] = req_action

            delivery_mode = state_node.mode in {"delivery", "thin_mutation"}
            if delivery_mode and delivery_stage_ready(
                snapshot, route.route_id, anchor, has_concrete_carrier=True
            ):
                reopen, adm_audit = await self.arbiters.classify_delivery_admission(
                    {
                        "route_id": route.route_id,
                        "proof_ledger": [
                            x.model_dump(mode="json")
                            for x in snapshot.proof_ledger
                            if x.route_id == route.route_id
                        ],
                    }
                )
                result.budget.charge(adm_audit.usage, model_calls=adm_audit.model_calls)
                if reopen:
                    delivery_mode = False

            output_model = (
                WorkerHandoffOnlyOutput
                if state_node.mode in {"core_action", "exploratory_probe"}
                else (WorkerArtifactOnlyOutput if delivery_mode else WorkerModelOutput)
            )
            admitted_skills = tuple(
                self.skills[name]
                for name in state_node.allowed_skills
                if name in self.skills
            )
            stage_budget = min(
                state_node.max_total_tokens, max(1_024, result.budget.remaining_tokens)
            )
            req_path = state_node.required_artifact_path if delivery_mode else None
            deadline_calls = (
                state_node.artifact_deadline_tool_calls if delivery_mode else None
            )
            definition = AgentDefinition(
                id=f"worker.{route.fsm_id}.{state_node.id}",
                version=spec.version,
                system_prompt=state_node.system_prompt,
                output_model=output_model,
                max_total_tokens=stage_budget,
                max_output_tokens=state_node.max_output_tokens,
                request_budget=RequestBudget(
                    context_window_tokens=917_000,
                    max_output_tokens=state_node.max_output_tokens,
                ),
                skills=admitted_skills,
                required_artifact_path=req_path,
                artifact_deadline_tool_calls=deadline_calls,
                finalization_tool_calls=state_node.finalization_tool_calls,
                max_turn_seconds=state_node.max_turn_seconds,
            )

            worker_payload = {
                "task_id": result.task_id,
                "objective": objective,
                "route_id": route.route_id,
                "entity_id": route.entity_id,
                "fsm_id": route.fsm_id,
                "state_id": state_node.id,
                "memory_capsule": snapshot.resume_capsule(),
                "full_memory_path": memory_view_path,
                "cross_entity_clues": self.supervisor.cross_entity_briefing(
                    board, route.entity_id
                ),
                "required_next_action": (
                    req_action.model_dump(mode="json") if req_action else None
                ),
            }

            worker_rt = self.worker_runtime_factory(work_dir)
            try:
                trace = await worker_rt.run(
                    definition,
                    TaskMemorySnapshot.model_validate(snapshot).model_dump_json()
                    + "\n"
                    + str(worker_payload),
                )
                result.budget.charge(trace.usage, model_calls=trace.model_calls)
            except AgentRuntimeError as err:
                result.budget.charge(err.usage, model_calls=err.model_calls)
                # Try bounded-action 1-command timeout receipt recovery
                if req_action is not None:
                    (
                        rec_receipt,
                        rec_audit,
                    ) = await self.arbiters.recover_bounded_action_receipt(
                        req_action, err
                    )
                    if rec_audit is not None:
                        result.budget.charge(
                            rec_audit.usage, model_calls=rec_audit.model_calls
                        )
                    if rec_receipt is not None:
                        salvaged_handoff = ResearchHandoff(
                            summary=rec_receipt.observation,
                            next_step=rec_receipt.changed_constraint,
                            next_action=req_action,
                            action_receipt=rec_receipt,
                            items=[
                                MemoryItem(
                                    id=f"recovered.{req_action.id[:40]}",
                                    kind="observation",
                                    status="runtime_observed",
                                    claim=rec_receipt.changed_constraint,
                                    evidence=[rec_receipt.observation],
                                )
                            ],
                        )
                        await self._process_handoff(
                            handoff=salvaged_handoff,
                            command_receipts=err.command_receipts,
                            tool_calls=err.tool_calls,
                            tokens_used=err.usage.total_tokens,
                            route=route,
                            spec=spec,
                            anchor=anchor,
                            store=store,
                            result=result,
                            debug_dir=debug_dir,
                            spawned_entity_fsms=spawned_entity_fsms,
                            required_actions_by_route=required_actions_by_route,
                            retried_receipt_ids=retried_receipt_ids,
                        )
                        return

                salvaged = recover_research_handoff(err.last_final_text)
                if salvaged is not None and not delivery_mode:
                    await self._process_handoff(
                        handoff=salvaged,
                        command_receipts=err.command_receipts,
                        tool_calls=err.tool_calls,
                        tokens_used=err.usage.total_tokens,
                        route=route,
                        spec=spec,
                        anchor=anchor,
                        store=store,
                        result=result,
                        debug_dir=debug_dir,
                        spawned_entity_fsms=spawned_entity_fsms,
                        required_actions_by_route=required_actions_by_route,
                        retried_receipt_ids=retried_receipt_ids,
                    )
                    return

                self._record_blocked_attempt(
                    store=store,
                    result=result,
                    route=route,
                    category=(
                        "artifact_deadline_missed"
                        if err.code == "artifact_deadline_missed"
                        else "turn_wall_timeout"
                        if err.code == "turn_wall_timeout"
                        else "token_budget_exhausted"
                        if err.code == "token_budget_exhausted"
                        else "generation_failed"
                    ),
                    error=str(err),
                )
                return
            finally:
                await worker_rt.aclose()

            branch = trace.result.branch
            if isinstance(branch, HandoffOutput):
                await self._process_handoff(
                    handoff=branch.handoff,
                    command_receipts=trace.command_receipts,
                    tool_calls=trace.tool_calls,
                    tokens_used=trace.usage.total_tokens,
                    route=route,
                    spec=spec,
                    anchor=anchor,
                    store=store,
                    result=result,
                    debug_dir=debug_dir,
                    spawned_entity_fsms=spawned_entity_fsms,
                    required_actions_by_route=required_actions_by_route,
                    retried_receipt_ids=retried_receipt_ids,
                )
                return

            assert isinstance(branch, ArtifactOutput)
            await self._process_artifact(
                artifact_out=branch,
                work_dir=work_dir,
                tokens_used=trace.usage.total_tokens,
                route=route,
                spec=spec,
                store=store,
                result=result,
                task_dir=task_dir,
                seen_artifacts=seen_artifacts,
            )

    async def _process_handoff(
        self,
        *,
        handoff: ResearchHandoff,
        command_receipts: Sequence[Any],
        tool_calls: int,
        tokens_used: int,
        route: RouteSummary,
        spec: StateMachineSpec,
        anchor: dict[str, Any],
        store: TaskMemoryStore,
        result: TaskRunResult,
        debug_dir: Path,
        spawned_entity_fsms: set[tuple[str, str]],
        required_actions_by_route: dict[str, NextAction],
        retried_receipt_ids: set[str],
    ) -> None:
        req_action = required_actions_by_route.get(route.route_id)
        if req_action is not None:
            receipt = handoff.action_receipt
            invalid = (
                receipt is None or receipt.action_id != req_action.id or tool_calls < 1
            )
            if invalid:
                if tool_calls > 0 and req_action.id not in retried_receipt_ids:
                    retried_receipt_ids.add(req_action.id)
                    return
                self._record_blocked_attempt(
                    store=store,
                    result=result,
                    route=route,
                    category="required_action_unreceipted",
                    error=(
                        "handoff did not execute and receipt required action "
                        f"{req_action.id}"
                    ),
                )
                return

        # Reconcile handoff identity against bound target
        reconciled, id_audit = await self.arbiters.reconcile_handoff_identity(
            handoff, bound_target=anchor.get("target")
        )
        if id_audit is not None:
            result.budget.charge(id_audit.usage, model_calls=id_audit.model_calls)

        (
            carrier_ids,
            durable_notes,
            blockers,
            mem_audit,
        ) = await self.arbiters.classify_memory_semantics(reconciled.items)
        if mem_audit is not None:
            result.budget.charge(mem_audit.usage, model_calls=mem_audit.model_calls)

        use_unfiltered = self.arbiters._runtime is None
        conclusions, ledger_updates = convert_handoff_items_to_updates(
            reconciled.items,
            route_id=route.route_id,
            entity_id=route.entity_id,
            attempt_number=len(result.attempts) + 1,
            carrier_ids=carrier_ids,
            durable_note_ids=durable_notes,
            construction_blockers=blockers,
            classify_unfiltered=use_unfiltered,
        )

        # Verify CommandReceipt bindings for discovered entities & sideband signals
        cmd_by_seq = {c.sequence: c for c in command_receipts}
        new_entities: list[TaskMemoryEntity] = []
        for draft in reconciled.discovered_entities:
            cmd_rec = cmd_by_seq.get(draft.command_sequence)
            if cmd_rec is None:
                continue
            new_entities.append(
                TaskMemoryEntity(
                    entity_id=draft.entity_id,
                    kind=draft.kind,
                    parent_entity_id=route.entity_id,
                    label=draft.label,
                    attributes=draft.attributes,
                    receipt_sha256=cmd_rec.sha256,
                    discovered_attempt=len(result.attempts) + 1,
                )
            )
        if new_entities:
            store.register_entities(new_entities)
            # 1 -> N Dynamic Entity-Triggered Micro-FSM Instantiation!
            for entity in new_entities:
                for triggered_spec in self.registry.matching_specs_for_entity(entity):
                    pair = (entity.entity_id, triggered_spec.fsm_id)
                    if pair in spawned_entity_fsms:
                        continue
                    spawned_entity_fsms.add(pair)
                    store.apply_route_decision(
                        action="new",
                        route_id=None,
                        attempt=len(result.attempts) + 1,
                        rationale=(
                            f"Auto-mounted Micro-FSM '{triggered_spec.fsm_id}' on "
                            f"discovered entity '{entity.entity_id}'."
                        ),
                        model="core-entity-trigger",
                        entity_id=entity.entity_id,
                        fsm_id=triggered_spec.fsm_id,
                        initial_state_id=triggered_spec.initial_state,
                    )

        prev_ledger_count = len(store.load().proof_ledger)
        if ledger_updates:
            store.merge_ledger(ledger_updates)
        if conclusions:
            store.merge_conclusions(conclusions)
        after_board = store.load()
        made_fact_gain = len(after_board.proof_ledger) > prev_ledger_count or bool(
            new_entities
        )
        store.update_route(
            route.route_id,
            attempt=len(result.attempts) + 1,
            summary=f"{reconciled.summary} Next: {reconciled.next_step}"[:600],
            increment_stall=not made_fact_gain,
            reset_stall=made_fact_gain,
        )
        required_actions_by_route[route.route_id] = reconciled.next_action

        updated_route = next(
            r for r in store.load().routes if r.route_id == route.route_id
        )
        if updated_route.support == "contradicted":
            self._record_blocked_attempt(
                store=store,
                result=result,
                route=updated_route,
                category="route_contradicted",
                error="research handoff contradicted the active route",
            )
            return

        # Advance FSM state if an enabled transition's guard is now satisfied
        action_outcome = (
            reconciled.action_receipt.outcome
            if reconciled.action_receipt is not None
            else "completed"
        )
        self._advance_fsm_state(
            store=store,
            route_id=route.route_id,
            spec=spec,
            action_outcome=action_outcome,
            tokens_used=tokens_used,
            produced_keys=[u.key for u in ledger_updates],
            result=result,
        )

        # Wake Two-Tier Observer if verified sideband signals or route stall occurred
        verified_signals: list[SidebandSignal] = []
        for sig_draft in reconciled.unexpected_signals:
            cmd_rec = cmd_by_seq.get(sig_draft.command_sequence)
            if cmd_rec is None:
                continue
            verified_signals.append(
                SidebandSignal(
                    signal_id=sig_draft.signal_id,
                    entity_id=route.entity_id,
                    category=sig_draft.category,
                    summary=sig_draft.summary,
                    proposed_hypothesis=sig_draft.proposed_hypothesis,
                    command_receipt_sha256=cmd_rec.sha256,
                )
            )
        refreshed_route = next(
            r for r in store.load().routes if r.route_id == route.route_id
        )
        if self.observer.should_wake(
            route=refreshed_route, verified_signals=verified_signals
        ):
            await self._run_observer_breakout(
                route=refreshed_route,
                verified_signals=verified_signals,
                store=store,
                result=result,
                debug_dir=debug_dir,
                spawned_entity_fsms=spawned_entity_fsms,
            )

    async def _run_observer_breakout(
        self,
        *,
        route: RouteSummary,
        verified_signals: list[SidebandSignal],
        store: TaskMemoryStore,
        result: TaskRunResult,
        debug_dir: Path,
        spawned_entity_fsms: set[tuple[str, str]],
    ) -> None:
        board = store.load()
        obs_decision, obs_usage = await self.observer.evaluate(
            board=board,
            route=route,
            verified_signals=verified_signals,
            registry=self.registry,
        )
        result.budget.charge(obs_usage, model_calls=1, role="observer")
        write_debug_event(
            debug_dir,
            stage="observer",
            event=obs_decision.action,
            payload=obs_decision.model_dump(mode="json"),
        )

        if obs_decision.action == "keep_course":
            return

        if (
            obs_decision.action == "tier2_mount_adhoc_fsm"
            and obs_decision.adhoc_fsm is not None
        ):
            adhoc = obs_decision.adhoc_fsm
            pair = (route.entity_id, adhoc.fsm_id)
            if pair not in spawned_entity_fsms:
                spawned_entity_fsms.add(pair)
                store.apply_route_decision(
                    action="new",
                    route_id=None,
                    attempt=len(result.attempts) + 1,
                    rationale=f"Observer mounted ad-hoc Sub-FSM {adhoc.fsm_id}",
                    model="observer-tier2",
                    entity_id=route.entity_id,
                    fsm_id=adhoc.fsm_id,
                    initial_state_id=adhoc.initial_state,
                )
                result.breakout_episodes.append(
                    BreakoutEpisodeRecord(
                        entity_id=route.entity_id,
                        trigger_signal=verified_signals[0]
                        if verified_signals
                        else None,
                        tier="tier2_adhoc_fsm",
                        hypothesis=obs_decision.rationale,
                        succeeded=True,
                        adhoc_spec=adhoc,
                    )
                )
            return

        # Tier 1: Leashed Exploratory Probe (<=5 tool calls)
        target = obs_decision.probe_target or route.entity_id
        hypothesis = obs_decision.probe_hypothesis or obs_decision.rationale
        probe_node = self.observer.build_leashed_probe_node(
            target=target, hypothesis=hypothesis
        )
        probe_dir = debug_dir.parent / "workers" / f"{route.route_id}-probe"
        probe_dir.mkdir(parents=True, exist_ok=True)
        probe_rt = self.worker_runtime_factory(probe_dir)
        probe_def = AgentDefinition(
            id=f"observer.probe.{route.route_id}",
            version="0.1.0",
            system_prompt=probe_node.system_prompt,
            output_model=WorkerHandoffOnlyOutput,
            max_total_tokens=min(
                probe_node.max_total_tokens, max(1_024, result.budget.remaining_tokens)
            ),
            max_output_tokens=probe_node.max_output_tokens,
            finalization_tool_calls=probe_node.finalization_tool_calls,
            max_turn_seconds=probe_node.max_turn_seconds,
        )
        try:
            trace = await probe_rt.run(
                probe_def,
                f"Target: {target}\nHypothesis: {hypothesis}",
            )
            result.budget.charge(
                trace.usage, model_calls=trace.model_calls, role="observer"
            )
            probe_handoff = trace.result.branch.handoff
            use_unfiltered = self.arbiters._runtime is None
            concs, ledgers = convert_handoff_items_to_updates(
                probe_handoff.items,
                route_id=route.route_id,
                entity_id=route.entity_id,
                attempt_number=len(result.attempts) + 1,
                carrier_ids=set(),
                durable_note_ids=set(),
                construction_blockers={},
                classify_unfiltered=use_unfiltered,
            )
            if ledgers:
                store.merge_ledger(ledgers)
            if concs:
                store.merge_conclusions(concs)
            store.update_route(
                route.route_id,
                attempt=len(result.attempts) + 1,
                reset_stall=bool(ledgers),
            )
            result.breakout_episodes.append(
                BreakoutEpisodeRecord(
                    entity_id=route.entity_id,
                    trigger_signal=verified_signals[0] if verified_signals else None,
                    tier="tier1_probe",
                    hypothesis=hypothesis,
                    succeeded=bool(ledgers),
                    discovered_claims=tuple(x.claim for x in ledgers),
                )
            )
        except AgentRuntimeError as err:
            result.budget.charge(
                err.usage, model_calls=err.model_calls, role="observer"
            )
            result.breakout_episodes.append(
                BreakoutEpisodeRecord(
                    entity_id=route.entity_id,
                    trigger_signal=verified_signals[0] if verified_signals else None,
                    tier="tier1_probe",
                    hypothesis=hypothesis,
                    succeeded=False,
                )
            )
        finally:
            await probe_rt.aclose()

    async def _process_artifact(
        self,
        *,
        artifact_out: ArtifactOutput,
        work_dir: Path,
        tokens_used: int,
        route: RouteSummary,
        spec: StateMachineSpec,
        store: TaskMemoryStore,
        result: TaskRunResult,
        task_dir: Path,
        seen_artifacts: set[str],
    ) -> None:
        src = artifact_out.source
        if isinstance(src, InlineArtifactSource):
            content = decode_strict_base64(src.artifact_base64)
        elif isinstance(src, PathArtifactSource):
            loaded = await asyncio.to_thread(
                _read_work_artifact_sync, work_dir, src.artifact_path
            )
            if loaded is None:
                self._record_blocked_attempt(
                    store=store,
                    result=result,
                    route=route,
                    category="artifact_path_invalid",
                    error=f"invalid artifact path: {src.artifact_path}",
                )
                return
            content = loaded
        else:
            self._record_blocked_attempt(
                store=store,
                result=result,
                route=route,
                category="generation_failed",
                error="unknown disclosed candidate id",
            )
            return

        digest = hashlib.sha256(content).hexdigest()
        attempt_num = len(result.attempts) + 1
        attempts_dir = task_dir / "attempts"
        attempts_dir.mkdir(parents=True, exist_ok=True)
        (attempts_dir / f"attempt-{attempt_num:02d}.bin").write_bytes(content)

        if digest in seen_artifacts:
            dup = AttemptRecord(
                number=attempt_num,
                route_id=route.route_id,
                entity_id=route.entity_id,
                fsm_id=route.fsm_id,
                state_id=route.current_state_id,
                status="duplicate",
                artifact_sha256=digest,
                artifact_size=len(content),
                duplicate=True,
                causal_dimension=artifact_out.causal_dimension,
                changed_constraint=artifact_out.changed_constraint,
                semantic_checkpoint=artifact_out.semantic_checkpoint,
            )
            result.attempts.append(dup)
            store.update_route(
                route.route_id,
                attempt=attempt_num,
                outcome="duplicate",
                failure_category="duplicate_candidate",
                failure_summary="Repeated exact artifact SHA-256.",
                increment_stall=True,
            )
            self.route_controller.select_route(
                store,
                result.attempts,
                attempt_number=attempt_num + 1,
                default_fsm_id=spec.fsm_id,
                default_initial_state=spec.initial_state,
            )
            return

        seen_artifacts.add(digest)
        initial_rec: ExecutionReceipt | None = None
        replay_rec: ExecutionReceipt | None = None
        fp_match: bool | None = None
        status: Literal["generated", "submitted", "milestone_candidate"] = "generated"

        if self.evaluator is not None:
            initial_rec = await self.evaluator.evaluate_candidate(
                content, route=route, is_replay=False
            )
            if initial_rec.exit_code not in (0, 300):
                replay_rec = await self.evaluator.evaluate_candidate(
                    content, route=route, is_replay=True
                )
                if replay_rec.exit_code not in (0, 300):
                    status = "milestone_candidate"
                    if (
                        initial_rec.fingerprint_sha256 is not None
                        and replay_rec.fingerprint_sha256 is not None
                    ):
                        fp_match = (
                            initial_rec.fingerprint_sha256
                            == replay_rec.fingerprint_sha256
                        )
                    else:
                        fp_match = initial_rec.exit_code == replay_rec.exit_code
                else:
                    status = "submitted"
            else:
                status = "submitted"

        rec = AttemptRecord(
            number=attempt_num,
            route_id=route.route_id,
            entity_id=route.entity_id,
            fsm_id=route.fsm_id,
            state_id=route.current_state_id,
            status=status,
            artifact_sha256=digest,
            artifact_size=len(content),
            causal_dimension=artifact_out.causal_dimension,
            changed_constraint=artifact_out.changed_constraint,
            semantic_checkpoint=artifact_out.semantic_checkpoint,
            initial_receipt=initial_rec,
            replay_receipt=replay_rec,
            fingerprint_match=fp_match,
        )
        result.attempts.append(rec)

        if status == "milestone_candidate" and not rec.stopped_at_startup():
            result.budget.start_verification_window()
            store.update_route(
                route.route_id,
                attempt=attempt_num,
                outcome="milestone_candidate",
                support="supported",
                reset_stall=True,
            )
            self._advance_fsm_state(
                store=store,
                route_id=route.route_id,
                spec=spec,
                action_outcome="completed",
                tokens_used=tokens_used,
                produced_keys=[],
                result=result,
            )
        else:
            store.update_route(
                route.route_id,
                attempt=attempt_num,
                outcome=status,
                lifecycle="paused" if status == "submitted" else "active",
                failure_category="target_no_effect" if status == "submitted" else None,
                increment_stall=(status == "submitted"),
            )

        self.route_controller.select_route(
            store,
            result.attempts,
            attempt_number=attempt_num + 1,
            default_fsm_id=spec.fsm_id,
            default_initial_state=spec.initial_state,
        )

    def _advance_fsm_state(
        self,
        *,
        store: TaskMemoryStore,
        route_id: str,
        spec: StateMachineSpec,
        action_outcome: Literal["completed", "refuted", "blocked"],
        tokens_used: int,
        produced_keys: list[str],
        result: TaskRunResult,
    ) -> None:
        board = store.load()
        route = next((r for r in board.routes if r.route_id == route_id), None)
        if route is None:
            return
        outgoing = spec.outgoing_transitions(route.current_state_id)
        enabled = [
            t
            for t in outgoing
            if t.guard.evaluate_deterministic(
                board,
                route_id,
                context={"last_action_outcome": action_outcome},
                guard_registry=self.registry.guard_registry,
            )
        ]
        if not enabled:
            return
        entity = next(
            (e for e in board.entities if e.entity_id == route.entity_id), None
        )
        ctx_key = entity.kind if entity is not None else "root"
        chosen = (
            self.transition_router.select_transition(
                enabled, fsm_id=spec.fsm_id, context_key=ctx_key
            )
            if self.transition_router is not None and len(enabled) > 1
            else enabled[0]
        )
        next_node = spec.state_by_id(chosen.target)
        store.update_route(
            route_id,
            attempt=len(result.attempts) + 1,
            current_state_id=next_node.id,
            lifecycle="completed" if next_node.is_terminal else route.lifecycle,
        )
        result.transition_log.append(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "route_id": route_id,
                "entity_id": route.entity_id,
                "fsm_id": spec.fsm_id,
                "source_state": route.current_state_id,
                "transition_id": chosen.id,
                "target_state": next_node.id,
                "context_key": ctx_key,
                "tokens_used": tokens_used,
                "produced_keys": produced_keys,
            }
        )

    def _record_blocked_attempt(
        self,
        *,
        store: TaskMemoryStore,
        result: TaskRunResult,
        route: RouteSummary,
        category: BlockCategory,
        error: str,
    ) -> None:
        num = len(result.attempts) + 1
        rec = AttemptRecord(
            number=num,
            route_id=route.route_id,
            entity_id=route.entity_id,
            fsm_id=route.fsm_id,
            state_id=route.current_state_id,
            status="blocked",
            block_category=category,
            error=error,
        )
        result.attempts.append(rec)
        store.update_route(
            route.route_id,
            attempt=num,
            outcome="blocked",
            failure_category=category,
            failure_summary=error[:240],
            increment_stall=True,
        )

    async def _run_memory_review(
        self,
        *,
        store: TaskMemoryStore,
        budget: TaskBudgetEnvelope,
        review_index: int,
        task_dir: Path,
        objective: str,
    ) -> bool:
        board = store.load()
        if board.active_route_id is None or board.route_decision is None:
            return False
        rev_limit = budget.allocate_review_extension(
            review_index=review_index,
            stage_reserve=240_000,
            overrun_reserve=16_000,
            min_stage_tokens=32_000,
        )
        if rev_limit is None:
            return False
        rev_dir = task_dir / "workers" / f"reviewer-{review_index + 1}"
        rev_dir.mkdir(parents=True, exist_ok=True)
        store.publish_agent_view(rev_dir)
        rev_rt = self.worker_runtime_factory(rev_dir)
        rev_def = AgentDefinition(
            id="vouchloom.memory-reviewer",
            version="0.1.0",
            system_prompt=(
                "You are the one-time Memory Reviewer at the task-token boundary. "
                "Inspect /work/task-memory.json and return resume, stop (ONLY if a "
                "preexisting required condition is source-contradicted), or blocked."
            ),
            output_model=MemoryReviewOutput,
            max_total_tokens=rev_limit,
            max_output_tokens=4_096,
            max_turn_seconds=180,
        )
        try:
            trace = await rev_rt.run(rev_def, f"Objective: {objective}")
            budget.charge(trace.usage, model_calls=trace.model_calls, role="reviewer")
            out = MemoryReviewOutput.model_validate(trace.result)
        except AgentRuntimeError as err:
            budget.charge(err.usage, model_calls=err.model_calls, role="reviewer")
            return review_index == 0 and budget.remaining_tokens >= 32_000
        finally:
            await rev_rt.aclose()

        active_route = next(
            r for r in board.routes if r.route_id == board.active_route_id
        )
        _, ledger_deltas = convert_handoff_items_to_updates(
            out.items,
            route_id=active_route.route_id,
            entity_id=active_route.entity_id,
            attempt_number=999,
            carrier_ids={x.id for x in out.items if x.kind == "construction"},
            durable_note_ids=set(),
            construction_blockers={},
            classify_unfiltered=True,
        )
        retire = any(ledger_entry_contradicts_route(x) for x in ledger_deltas)
        after_board = (
            store.merge_ledger(
                ledger_deltas,
                retire_route_ids={active_route.route_id} if retire else None,
            )
            if ledger_deltas and out.decision in {"resume", "stop"}
            else board
        )
        audit = audit_memory_review_transition(
            board,
            status=out.decision,
            confidence="source_backed" if out.decision != "blocked" else "insufficient",
            next_step=out.next_step,
            updates=ledger_deltas if out.decision != "blocked" else [],
            after=after_board,
        )
        if out.decision == "stop":
            # Invalid stop becomes fresh_solver continuation (from bug_hunter)
            return audit.severity == "invalid"
        if audit.severity == "invalid":
            return review_index == 0 and budget.remaining_tokens >= 32_000
        return out.decision == "resume"
