"""Persistent, proof-oriented TaskMemory & 10+1 Proof Ledger (from bug_hunter).

Preserves every battle-tested invariant from bug_hunter's TaskMemory v5:
- Per-route 10-cell proof cap + 1 reserved Core runtime-target identity slot
- Acyclic dependency checks & cascading descendant deletion on contradiction
- Indivisible carrier-construction + blocking-gap closure under pruning
- Structural route contradiction retirement + read-only negative premise projection
- Deterministic RuntimeFrontier and CarrierPrefixFrontier detection
- Bounded 32k prompt_snapshot, 4k dependency-closed resume_capsule, and 0o444 agent view
- Extends cleanly to 1 -> N receipt-bound dynamic Entity spawning & cross-branch refs.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from vouchloom.models import CausalDimension, StrictModel

MEMORY_SCHEMA_VERSION = "vouchloom-task-memory/1.0"
MAX_PROMPT_MEMORY_CHARS = 32_000
MAX_ROUTE_LEDGER_ENTRIES = 10
AGENT_MEMORY_VIEW_VERSION = 2
MAX_AGENT_MEMORY_CAPSULE_CHARS = 4_000

CORE_OWNED_KEY_PREFIX = "core."
CORE_RUNTIME_TARGET_KEY_PREFIX = "core.runtime-target."

MemoryConfidence = Literal["high_confidence", "general_confidence", "guess"]

_CONFIDENCE_LEVELS: tuple[MemoryConfidence, ...] = (
    "guess",
    "general_confidence",
    "high_confidence",
)
_CONFIDENCE_RANK = {level: rank for rank, level in enumerate(_CONFIDENCE_LEVELS)}
_KIND_PRIORITY = {
    "constraint": 5,
    "fact": 4,
    "hypothesis": 3,
    "next_step": 2,
    "result": 1,
}
_STATUS_PRIORITY = {"contradicted": 3, "supported": 2, "uncertain": 1}
LEDGER_STATUS_PRIORITY = {
    "contradicted": 6,
    "runtime_observed": 5,
    "artifact_encoded": 4,
    "source_backed": 3,
    "hypothesis": 1,
}

_RAW_HEX_RUN = re.compile(r"\b[0-9A-Fa-f]{32,}\b")
_RAW_HEX_BYTES = re.compile(r"(?:\b[0-9A-Fa-f]{2}[\s,:-]+){15,}")

ProofSection = Literal[
    "target_contract",
    "sink",
    "call_edge",
    "condition",
    "state_transition",
    "checkpoint",
    "construction",
    "open_gap",
]
ProofStatus = Literal[
    "hypothesis",
    "source_backed",
    "artifact_encoded",
    "runtime_observed",
    "contradicted",
]
ConditionRole = Literal[
    "required",
    "derived",
    "optional",
    "not_applicable",
    "unknown",
]


class TaskMemoryEntity(StrictModel):
    """One discovered domain object supporting 1 -> N dynamic task fission.

    Root entities may be seeded by Core; any Worker-discovered child entity MUST
    bind a verified CommandReceipt SHA-256 so hallucinated assets cannot enter.
    """

    entity_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{0,119}$")
    kind: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    parent_entity_id: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._:-]{0,119}$"
    )
    label: str = Field(min_length=1, max_length=300)
    attributes: dict[str, str] = Field(default_factory=dict)
    receipt_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    discovered_attempt: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def require_receipt_for_derived_entity(self) -> Self:
        if self.parent_entity_id is not None and self.receipt_sha256 is None:
            raise ValueError(
                "derived child entities require a verified command/execution receipt"
            )
        if self.parent_entity_id == self.entity_id:
            raise ValueError("an entity cannot be its own parent")
        return self


class ProofLedgerEntry(StrictModel):
    """One evidence-backed cell in a route's proof state."""

    key: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    section: ProofSection
    carrier_construction: bool = False
    claim: str = Field(min_length=1)
    status: ProofStatus
    condition_role: ConditionRole = "unknown"
    depends_on: list[str] = Field(default_factory=list)
    cross_entity_refs: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(min_length=1)
    route_id: str = Field(pattern=r"^route-[0-9]{3,}$")
    entity_id: str = Field(default="root", pattern=r"^[a-z0-9][a-z0-9._:-]{0,119}$")
    receipt_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    updated_attempt: int = Field(default=0, ge=0)

    @field_validator("claim")
    @classmethod
    def normalize_claim(cls, value: str) -> str:
        rendered = " ".join(value.split())
        if not rendered:
            raise ValueError("proof ledger claims must be non-empty")
        return rendered

    @field_validator("evidence")
    @classmethod
    def normalize_evidence(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            rendered = " ".join(value.split())
            if not rendered:
                raise ValueError("proof ledger evidence must be non-empty")
            normalized.append(rendered)
        return normalized

    @field_validator("depends_on")
    @classmethod
    def require_normalized_dependencies(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)) or any(
            re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,79}", value) is None
            for value in values
        ):
            raise ValueError("ledger dependencies must be unique normalized keys")
        return values

    @model_validator(mode="before")
    @classmethod
    def ignore_irrelevant_condition_role(cls, value: Any) -> Any:
        if (
            isinstance(value, dict)
            and value.get("section") != "condition"
            and value.get("condition_role", "unknown") != "unknown"
        ):
            return {**value, "condition_role": "unknown"}
        return value

    @model_validator(mode="after")
    def validate_self_and_construction_marker(self) -> Self:
        if self.key in self.depends_on:
            raise ValueError("a proof ledger cell cannot depend on itself")
        if (self.section == "construction") != self.carrier_construction:
            raise ValueError(
                "construction ledger cells require the Core carrier_construction marker"
            )
        return self


@dataclass(frozen=True)
class RuntimeFrontier:
    """One dependency-closed producer-to-consumer gap safe to probe once."""

    route_id: str
    gap_key: str
    gap_claim: str
    target_key: str
    sink_key: str
    construction_key: str
    producer_keys: tuple[str, ...]
    spine_keys: tuple[str, ...]


@dataclass(frozen=True)
class CarrierPrefixFrontier:
    """The sole next source-backed transition after a reached carrier prefix."""

    route_id: str
    transition_key: str
    transition_claim: str
    gap_key: str
    gap_claim: str
    target_key: str
    sink_key: str
    construction_key: str
    observed_prefix_keys: tuple[str, ...]
    spine_keys: tuple[str, ...]


class TaskMemoryConclusion(StrictModel):
    """One bounded conclusion derived from task-visible evidence."""

    key: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    kind: Literal["fact", "constraint", "hypothesis", "result", "next_step"]
    statement: str = Field(min_length=1)
    confidence: MemoryConfidence
    status: Literal["supported", "contradicted", "uncertain"]
    scope: Literal["common", "route"] = "common"
    route_id: str | None = Field(default=None, pattern=r"^route-[0-9]{3,}$")
    entity_id: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._:-]{0,119}$"
    )
    evidence: list[str] = Field(default_factory=list)
    updated_attempt: int = Field(default=0, ge=0)

    @field_validator("statement")
    @classmethod
    def normalize_statement(cls, value: str) -> str:
        rendered = " ".join(value.split())
        if not rendered:
            raise ValueError("conclusions must be non-empty")
        return rendered

    @field_validator("evidence")
    @classmethod
    def normalize_conclusion_evidence(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            rendered = " ".join(value.split())
            if not rendered:
                raise ValueError("conclusion evidence must be non-empty")
            normalized.append(rendered)
        return normalized

    @model_validator(mode="after")
    def route_scope_is_bound(self) -> Self:
        if self.scope == "route" and self.route_id is None:
            raise ValueError("route conclusion requires route_id")
        if self.scope == "common" and self.route_id is not None:
            raise ValueError("common conclusion cannot declare route_id")
        return self


def conclusion_rejection_reason(conclusion: TaskMemoryConclusion) -> str | None:
    """Reject activity logs, reserved summary keys, and raw hex byte blobs."""

    if conclusion.key.startswith("memory-summary-"):
        return "memory-summary keys are reserved for Core prompt projections"
    if not conclusion.evidence:
        return "a durable conclusion requires a concise evidence reference"
    statement = " ".join(conclusion.statement.split())
    if _RAW_HEX_RUN.search(statement) or _RAW_HEX_BYTES.search(statement):
        return "raw byte strings and artifact material do not belong in memory"
    return None


def is_structural_ledger_cell(item: ProofLedgerEntry) -> bool:
    return item.section in {
        "target_contract",
        "sink",
        "call_edge",
        "state_transition",
    } or (item.section == "condition" and item.condition_role == "required")


def ledger_entry_contradicts_route(item: ProofLedgerEntry) -> bool:
    """Whether one cell disproves the current route's causal structure."""

    return item.status == "contradicted" and is_structural_ledger_cell(item)


def ledger_dependency_closure(
    item: ProofLedgerEntry,
    by_key: dict[str, ProofLedgerEntry],
) -> set[str]:
    closure = {item.key}
    pending = list(item.depends_on)
    while pending:
        key = pending.pop()
        if key in closure or key not in by_key:
            continue
        closure.add(key)
        pending.extend(by_key[key].depends_on)
    return closure


def ledger_gap_blocks_construction(
    gap: ProofLedgerEntry,
    by_key: dict[str, ProofLedgerEntry],
) -> bool:
    """Return whether resolving a gap is required to finish carrier construction."""

    if gap.section != "open_gap" or gap.status != "hypothesis":
        return False
    if any(
        by_key[key].section == "construction"
        for key in ledger_dependency_closure(gap, by_key)
        if key in by_key
    ):
        return True
    return any(
        item.section == "construction"
        and item.carrier_construction
        and gap.key in ledger_dependency_closure(item, by_key)
        for item in by_key.values()
    )


def _construction_gap_closure(
    gap: ProofLedgerEntry,
    by_key: dict[str, ProofLedgerEntry],
) -> set[str]:
    """Keep one carrier and its classified blocker indivisible under pruning."""

    gap_closure = ledger_dependency_closure(gap, by_key)
    blocked_constructions = [
        item
        for item in by_key.values()
        if item.section == "construction"
        and item.carrier_construction
        and gap.key in ledger_dependency_closure(item, by_key)
    ]
    if not blocked_constructions:
        return gap_closure
    construction_closure, _ = min(
        (
            (ledger_dependency_closure(item, by_key), item)
            for item in blocked_constructions
        ),
        key=lambda pair: (
            len(pair[0]),
            -LEDGER_STATUS_PRIORITY[pair[1].status],
            -pair[1].updated_attempt,
            pair[1].key,
        ),
    )
    return gap_closure | construction_closure


def select_active_ledger_gap(
    entries: list[ProofLedgerEntry],
    *,
    route_id: str,
) -> ProofLedgerEntry | None:
    """Select one live route gap for Agent-facing projections."""

    retained = [
        item
        for item in entries
        if item.route_id == route_id and item.status != "contradicted"
    ]
    by_key = {item.key: item for item in retained}
    candidates = [
        item
        for item in retained
        if item.section == "open_gap"
        or (
            item.section == "construction"
            and item.status == "hypothesis"
            and item.carrier_construction
        )
    ]
    return max(
        candidates,
        key=lambda item: (
            item.section == "construction"
            or ledger_gap_blocks_construction(item, by_key),
            not (item.key == "core.latest-gap" and not item.depends_on),
            item.updated_attempt,
            item.key,
        ),
        default=None,
    )


def _route_ledger_cycle_keys(
    route_id: str,
    by_key: dict[str, ProofLedgerEntry],
) -> set[tuple[str, str]]:
    cycles: set[tuple[str, str]] = set()
    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(key: str) -> None:
        if state.get(key) == 2:
            return
        if state.get(key) == 1:
            cycles.update((route_id, item) for item in stack[stack.index(key) :])
            return
        state[key] = 1
        stack.append(key)
        for dep in by_key[key].depends_on:
            if dep in by_key:
                visit(dep)
        stack.pop()
        state[key] = 2

    for key in by_key:
        visit(key)
    return cycles


def _ledger_cycle_keys(entries: list[ProofLedgerEntry]) -> set[tuple[str, str]]:
    cycles: set[tuple[str, str]] = set()
    for route_id in dict.fromkeys(item.route_id for item in entries):
        by_key = {item.key: item for item in entries if item.route_id == route_id}
        cycles.update(_route_ledger_cycle_keys(route_id, by_key))
    return cycles


def _coherent_proof_ledger(entries: list[ProofLedgerEntry]) -> list[ProofLedgerEntry]:
    """Drop cyclic, dangling, or contradicted downstream derivations."""

    retained = list(entries)
    while True:
        cycle_keys = _ledger_cycle_keys(retained)
        by_key = {(item.route_id, item.key): item for item in retained}
        filtered = [
            item
            for item in retained
            if (item.route_id, item.key) not in cycle_keys
            and all(
                (dep := by_key.get((item.route_id, key))) is not None
                and dep.status != "contradicted"
                for key in item.depends_on
            )
        ]
        if len(filtered) == len(retained):
            return filtered
        retained = filtered


def _remove_ledger_descendants(
    entries: dict[tuple[str, str], ProofLedgerEntry],
    *,
    route_id: str,
    root_key: str,
) -> None:
    removed = {root_key}
    while True:
        descendants = {
            item.key
            for item in entries.values()
            if item.route_id == route_id and removed.intersection(item.depends_on)
        } - removed
        if not descendants:
            break
        removed.update(descendants)
    for key in removed - {root_key}:
        entries.pop((route_id, key), None)


def _bounded_proof_ledger(entries: list[ProofLedgerEntry]) -> list[ProofLedgerEntry]:
    """Keep <=10 regular proof cells per route + 1 reserved Core runtime-target slot."""

    selected: set[tuple[str, str]] = set()
    for route_id in dict.fromkeys(item.route_id for item in entries):
        route_entries = [item for item in entries if item.route_id == route_id]
        by_key = {item.key: item for item in route_entries}
        runtime_targets = sorted(
            (
                item
                for item in route_entries
                if item.key.startswith(CORE_RUNTIME_TARGET_KEY_PREFIX)
                and item.section == "target_contract"
                and item.status == "runtime_observed"
            ),
            key=lambda item: (item.updated_attempt, item.key),
            reverse=True,
        )
        runtime_target = runtime_targets[0] if runtime_targets else None
        core_identity_keys = (
            {runtime_target.key} if runtime_target is not None else set()
        )
        stale_target_keys = {item.key for item in runtime_targets[1:]}
        if stale_target_keys:
            route_entries = [
                item
                for item in route_entries
                if not (ledger_dependency_closure(item, by_key) & stale_target_keys)
            ]
            by_key = {item.key: item for item in route_entries}

        gaps = [item for item in route_entries if item.section == "open_gap"]
        ranked_gaps = sorted(
            gaps,
            key=lambda item: (
                ledger_gap_blocks_construction(item, by_key),
                item.updated_attempt,
                item.key,
            ),
            reverse=True,
        )
        contradictions = sorted(
            (item for item in route_entries if ledger_entry_contradicts_route(item)),
            key=lambda item: (item.updated_attempt, item.key),
            reverse=True,
        )
        ranked = sorted(
            (
                item
                for item in route_entries
                if item.section != "open_gap" and item.key not in core_identity_keys
            ),
            key=lambda item: (
                LEDGER_STATUS_PRIORITY[item.status],
                item.updated_attempt,
                item.key,
            ),
            reverse=True,
        )

        route_selected: set[str] = set()
        for item in contradictions:
            closure = ledger_dependency_closure(item, by_key) - core_identity_keys
            if len(route_selected | closure) <= MAX_ROUTE_LEDGER_ENTRIES:
                route_selected.update(closure)

        primary_gap = ranked_gaps[0] if ranked_gaps else None
        if primary_gap is not None:
            gap_closure = (
                _construction_gap_closure(primary_gap, by_key) - core_identity_keys
            )
            if len(route_selected | gap_closure) <= MAX_ROUTE_LEDGER_ENTRIES:
                route_selected.update(gap_closure)
            else:
                fallback = (
                    ledger_dependency_closure(primary_gap, by_key) - core_identity_keys
                )
                if len(route_selected | fallback) <= MAX_ROUTE_LEDGER_ENTRIES:
                    route_selected.update(fallback)

        if runtime_target is not None:
            established = {"source_backed", "artifact_encoded", "runtime_observed"}
            target_edges: list[tuple[set[str], ProofLedgerEntry]] = []
            for item in route_entries:
                if item.section != "call_edge" or item.status not in established:
                    continue
                closure = ledger_dependency_closure(item, by_key)
                if runtime_target.key in closure:
                    target_edges.append((closure - core_identity_keys, item))
            if target_edges:
                edge_closure, _ = min(
                    target_edges,
                    key=lambda pair: (
                        len(pair[0]),
                        -LEDGER_STATUS_PRIORITY[pair[1].status],
                        -pair[1].updated_attempt,
                        pair[1].key,
                    ),
                )
                if len(route_selected | edge_closure) <= MAX_ROUTE_LEDGER_ENTRIES:
                    route_selected.update(edge_closure)

        for gap in ranked_gaps[1:]:
            gap_closure = ledger_dependency_closure(gap, by_key) - core_identity_keys
            if len(route_selected | gap_closure) <= MAX_ROUTE_LEDGER_ENTRIES:
                route_selected.update(gap_closure)
        for item in ranked:
            closure = ledger_dependency_closure(item, by_key) - core_identity_keys
            if len(route_selected | closure) <= MAX_ROUTE_LEDGER_ENTRIES:
                route_selected.update(closure)
        selected.update((route_id, key) for key in route_selected | core_identity_keys)
    return [item for item in entries if (item.route_id, item.key) in selected]


class RouteDecisionMemory(StrictModel):
    """The sole active route choice and generation constraint."""

    decision_id: str = Field(pattern=r"^decision-[0-9]{3,}$")
    attempt: int = Field(ge=1)
    action: Literal["continue", "fork", "reopen", "new"]
    source_route_id: str | None = Field(default=None, pattern=r"^route-[0-9]{3,}$")
    target_route_id: str = Field(pattern=r"^route-[0-9]{3,}$")
    rationale: str = Field(min_length=1, max_length=300)
    causal_dimension: CausalDimension = "unclassified"
    required_constraint: str = Field(min_length=1, max_length=300)
    forbidden_repeat: str = Field(min_length=1, max_length=300)
    visible_route_ids: list[str] = Field(min_length=1, max_length=3)
    writable_route_id: str = Field(pattern=r"^route-[0-9]{3,}$")
    model: str = Field(min_length=1, max_length=200)

    @field_validator("rationale", "required_constraint", "forbidden_repeat")
    @classmethod
    def normalize_decision_text(cls, value: str) -> str:
        return " ".join(value.split())

    @model_validator(mode="after")
    def coherent_scope(self) -> Self:
        if len(self.visible_route_ids) != len(set(self.visible_route_ids)):
            raise ValueError("visible route ids must be unique")
        if self.writable_route_id != self.target_route_id:
            raise ValueError("only the decision target route can be writable")
        if self.target_route_id not in self.visible_route_ids:
            raise ValueError("the decision target route must be visible")
        if self.action == "new" and self.source_route_id is not None:
            raise ValueError("a new route decision cannot have a source route")
        if self.action != "new" and self.source_route_id is None:
            raise ValueError("a non-new route decision requires a source route")
        if self.action in {"continue", "reopen"} and (
            self.source_route_id != self.target_route_id
        ):
            raise ValueError("continue and reopen must start from the target route")
        if self.action == "fork" and self.source_route_id == self.target_route_id:
            raise ValueError("a fork target must differ from its source route")
        return self


class RouteSummary(StrictModel):
    """One compact route / Micro-FSM instance bound to an Entity."""

    route_id: str = Field(pattern=r"^route-[0-9]{3,}$")
    parent_route_id: str | None = Field(default=None, pattern=r"^route-[0-9]{3,}$")
    entity_id: str = Field(default="root", pattern=r"^[a-z0-9][a-z0-9._:-]{0,119}$")
    fsm_id: str = Field(default="default", pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    current_state_id: str = Field(
        default="initial", pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$"
    )
    lifecycle: Literal["active", "paused", "abandoned", "completed"] = "active"
    support: Literal["supported", "contradicted", "uncertain"] = "uncertain"
    summary: str = Field(min_length=1, max_length=600)
    last_outcome: str | None = Field(default=None, max_length=120)
    failure_counts: dict[str, int] = Field(default_factory=dict)
    stall_count: int = Field(default=0, ge=0)
    last_failure: str | None = Field(default=None, max_length=240)
    updated_attempt: int = Field(default=0, ge=0)


class TaskMemorySnapshot(StrictModel):
    """Bounded prompt projection (<=32,000 chars) permitted in a Worker request."""

    schema_version: Literal["vouchloom-task-memory/1.0"] = MEMORY_SCHEMA_VERSION
    task_id: str = Field(min_length=1, max_length=500)
    entities: list[TaskMemoryEntity] = Field(default_factory=list)
    common: list[TaskMemoryConclusion] = Field(default_factory=list)
    route_summaries: list[RouteSummary] = Field(default_factory=list)
    route_decision: RouteDecisionMemory | None = None
    visible_route_conclusions: list[TaskMemoryConclusion] = Field(default_factory=list)
    proof_ledger: list[ProofLedgerEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_bounded_snapshot(self) -> Self:
        if len(self.model_dump_json()) > MAX_PROMPT_MEMORY_CHARS:
            raise ValueError("task memory prompt snapshot exceeds 32,000 characters")
        ledger_keys = [(item.route_id, item.key) for item in self.proof_ledger]
        if len(ledger_keys) != len(set(ledger_keys)):
            raise ValueError("prompt proof ledger keys must be unique")
        by_key = {(item.route_id, item.key): item for item in self.proof_ledger}
        if any(
            (dep := by_key.get((item.route_id, key))) is None
            or dep.status == "contradicted"
            for item in self.proof_ledger
            for key in item.depends_on
        ):
            raise ValueError(
                "prompt proof ledger has a dangling or contradicted dependency"
            )
        if _ledger_cycle_keys(self.proof_ledger):
            raise ValueError("prompt proof ledger dependencies must be acyclic")
        return self

    def resume_capsule(
        self, *, max_chars: int = MAX_AGENT_MEMORY_CAPSULE_CHARS
    ) -> dict[str, Any]:
        """Return small dependency-closed handoff capsule (<=4,000 chars)."""

        if not 500 <= max_chars <= MAX_AGENT_MEMORY_CAPSULE_CHARS:
            raise ValueError("capsule limit must be between 500 and 4,000 characters")
        visible_ids = (
            list(self.route_decision.visible_route_ids)
            if self.route_decision is not None
            else [item.route_id for item in self.route_summaries[:1]]
        )
        visible_set = set(visible_ids)
        ledger = sorted(
            self.proof_ledger,
            key=lambda item: (
                item.route_id
                == (
                    self.route_decision.target_route_id
                    if self.route_decision is not None
                    else None
                ),
                item.section == "open_gap",
                item.status == "contradicted",
                item.updated_attempt,
                item.key,
            ),
            reverse=True,
        )
        by_key = {(item.route_id, item.key): item for item in self.proof_ledger}

        def bundle(root: ProofLedgerEntry) -> list[dict[str, Any]]:
            ordered: list[ProofLedgerEntry] = []
            visited: set[tuple[str, str]] = set()

            def visit(node: ProofLedgerEntry) -> None:
                ident = (node.route_id, node.key)
                if ident in visited:
                    return
                visited.add(ident)
                for dep in node.depends_on:
                    visit(by_key[(node.route_id, dep)])
                ordered.append(node)

            visit(root)
            return [
                {
                    "id": item.key,
                    "route_id": item.route_id,
                    "section": item.section,
                    "status": item.status,
                    "claim": item.claim,
                    "depends_on": list(item.depends_on),
                }
                for item in ordered
            ]

        capsule: dict[str, Any] = {
            "version": AGENT_MEMORY_VIEW_VERSION,
            "task_id": self.task_id,
            "active_route_id": (
                self.route_decision.target_route_id
                if self.route_decision is not None
                else (visible_ids[0] if visible_ids else None)
            ),
            "routes": [
                {
                    "id": r.route_id,
                    "entity_id": r.entity_id,
                    "fsm_id": r.fsm_id,
                    "state": r.current_state_id,
                    "status": r.lifecycle,
                    "summary": r.summary[:160],
                }
                for r in self.route_summaries
                if r.route_id in visible_set
            ],
            "items": [],
            "complete": False,
        }
        selected: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for entry in ledger:
            additions = [
                x for x in bundle(entry) if (x["route_id"], x["id"]) not in seen
            ]
            if not additions:
                continue
            proposed = [*selected, *additions]
            capsule["items"] = proposed
            size = len(
                json.dumps(capsule, ensure_ascii=False, separators=(",", ":")).encode(
                    "utf-8"
                )
            )
            if size > max_chars:
                capsule["items"] = selected
                continue
            selected = proposed
            seen.update((x["route_id"], x["id"]) for x in additions)
        capsule["complete"] = len(seen) == len(self.proof_ledger)
        return capsule


def dependency_closed_runtime_frontier(
    snapshot: TaskMemorySnapshot | dict[str, Any],
    route_id: str,
) -> RuntimeFrontier | None:
    """Return the sole reached-producer gap with one dependency-closed sink."""

    if isinstance(snapshot, dict):
        snapshot = TaskMemorySnapshot.model_validate(snapshot)
    entries = [item for item in snapshot.proof_ledger if item.route_id == route_id]
    if not entries or any(ledger_entry_contradicts_route(item) for item in entries):
        return None
    by_key = {item.key: item for item in entries}
    gaps = [
        item
        for item in entries
        if item.section == "open_gap" and item.status == "hypothesis"
    ]
    if len(gaps) != 1:
        return None
    gap = gaps[0]
    closure_keys = ledger_dependency_closure(gap, by_key)
    if any(key not in by_key for key in closure_keys):
        return None
    closure = [by_key[key] for key in closure_keys]
    established = {"source_backed", "artifact_encoded", "runtime_observed"}
    if any(item is not gap and item.status not in established for item in closure):
        return None
    targets = [
        item
        for item in closure
        if item.section == "target_contract" and item.status in established
    ]
    sinks = [
        item
        for item in closure
        if item.section == "sink" and item.status in established
    ]
    constructions = [
        item
        for item in closure
        if item.section == "construction"
        and item.carrier_construction
        and item.status in {"artifact_encoded", "runtime_observed"}
    ]
    producers = [
        item
        for item in closure
        if item.section in {"condition", "state_transition"}
        and item.status == "runtime_observed"
        and (item.section == "state_transition" or item.condition_role == "required")
    ]
    unobserved_prefix = [
        item
        for item in closure
        if item.status == "source_backed"
        and (
            item.section == "state_transition"
            or (item.section == "condition" and item.condition_role == "required")
        )
    ]
    if (
        len(targets) != 1
        or len(sinks) != 1
        or len(constructions) != 1
        or not producers
        or unobserved_prefix
    ):
        return None
    sink_closure = ledger_dependency_closure(sinks[0], by_key)
    if targets[0].key not in sink_closure or not any(
        p.key in sink_closure for p in producers
    ):
        return None
    construction_closure = ledger_dependency_closure(constructions[0], by_key)
    if sinks[0].key not in construction_closure:
        return None
    return RuntimeFrontier(
        route_id=route_id,
        gap_key=gap.key,
        gap_claim=gap.claim,
        target_key=targets[0].key,
        sink_key=sinks[0].key,
        construction_key=constructions[0].key,
        producer_keys=tuple(sorted(item.key for item in producers)),
        spine_keys=tuple(sorted(key for key in closure_keys if key != gap.key)),
    )


def dependency_closed_carrier_prefix_frontier(
    snapshot: TaskMemorySnapshot | dict[str, Any],
    route_id: str,
) -> CarrierPrefixFrontier | None:
    """Return one earliest unobserved transition after a reached carrier prefix."""

    if isinstance(snapshot, dict):
        snapshot = TaskMemorySnapshot.model_validate(snapshot)
    entries = [item for item in snapshot.proof_ledger if item.route_id == route_id]
    if not entries or any(ledger_entry_contradicts_route(item) for item in entries):
        return None
    by_key = {item.key: item for item in entries}
    constructions = [
        item
        for item in entries
        if item.section == "construction"
        and item.carrier_construction
        and item.status in {"artifact_encoded", "runtime_observed"}
    ]
    if len(constructions) != 1:
        return None
    construction = constructions[0]
    closure_keys = ledger_dependency_closure(construction, by_key)
    if any(key not in by_key for key in closure_keys):
        return None
    closure = [by_key[key] for key in closure_keys]
    established = {"source_backed", "artifact_encoded", "runtime_observed"}
    if any(item.status not in established for item in closure):
        return None
    targets = [
        item
        for item in closure
        if item.section == "target_contract" and item.status in established
    ]
    sinks = [
        item
        for item in closure
        if item.section == "sink" and item.status in established
    ]
    if len(targets) != 1 or len(sinks) != 1:
        return None

    def is_typed_prefix_cell(item: ProofLedgerEntry) -> bool:
        return item.section == "state_transition" or (
            item.section == "condition" and item.condition_role == "required"
        )

    gaps = [
        item
        for item in entries
        if item.section == "open_gap" and item.status == "hypothesis"
    ]
    if not gaps or any(
        not ledger_gap_blocks_construction(item, by_key) for item in gaps
    ):
        return None
    minimal_gaps = [
        item
        for item in gaps
        if not any(
            other.key != item.key
            and other.key in ledger_dependency_closure(item, by_key)
            for other in gaps
        )
    ]
    if len(minimal_gaps) != 1:
        return None
    gap = minimal_gaps[0]
    candidates = [
        item
        for item in closure
        if item.section == "state_transition" and item.status == "source_backed"
    ]
    earliest: list[tuple[ProofLedgerEntry, set[str]]] = []
    for candidate in candidates:
        cand_closure = ledger_dependency_closure(candidate, by_key)
        if targets[0].key not in cand_closure:
            continue
        if any(
            other.key != candidate.key
            and other.key in cand_closure
            and is_typed_prefix_cell(other)
            and other.status == "source_backed"
            for other in closure
        ):
            continue
        observed_prefix = [
            item
            for item in closure
            if item.key in cand_closure
            and is_typed_prefix_cell(item)
            and item.status == "runtime_observed"
        ]
        if not observed_prefix:
            continue
        earliest.append((candidate, cand_closure))
    if len(earliest) != 1:
        return None
    transition, trans_closure = earliest[0]
    observed_keys = tuple(
        sorted(
            item.key
            for item in closure
            if item.key in trans_closure
            and is_typed_prefix_cell(item)
            and item.status == "runtime_observed"
        )
    )
    sink_closure = ledger_dependency_closure(sinks[0], by_key)
    if targets[0].key not in sink_closure or transition.key not in sink_closure:
        return None
    return CarrierPrefixFrontier(
        route_id=route_id,
        transition_key=transition.key,
        transition_claim=transition.claim,
        gap_key=gap.key,
        gap_claim=gap.claim,
        target_key=targets[0].key,
        sink_key=sinks[0].key,
        construction_key=construction.key,
        observed_prefix_keys=observed_keys,
        spine_keys=tuple(
            sorted(
                (closure_keys | {item.key for item in gaps}) - {transition.key, gap.key}
            )
        ),
    )


class TaskMemory(StrictModel):
    """Canonical durable Entity-Fact & Route-Proof state owned exclusively by Core."""

    schema_version: Literal["vouchloom-task-memory/1.0"] = MEMORY_SCHEMA_VERSION
    task_id: str = Field(min_length=1, max_length=500)
    updated_at: datetime
    entities: list[TaskMemoryEntity] = Field(default_factory=list)
    conclusions: list[TaskMemoryConclusion] = Field(default_factory=list)
    routes: list[RouteSummary] = Field(default_factory=list)
    proof_ledger: list[ProofLedgerEntry] = Field(default_factory=list)
    active_route_id: str | None = Field(default=None, pattern=r"^route-[0-9]{3,}$")
    route_decision: RouteDecisionMemory | None = None

    @model_validator(mode="after")
    def validate_coherent_state(self) -> Self:
        entity_ids = [e.entity_id for e in self.entities]
        if len(entity_ids) != len(set(entity_ids)):
            raise ValueError("task memory entity_ids must be unique")
        known_entities = set(entity_ids) | {"root"}
        if any(
            e.parent_entity_id is not None and e.parent_entity_id not in known_entities
            for e in self.entities
        ):
            raise ValueError("entity parent_entity_id references an unknown entity")

        conclusion_keys = [c.key for c in self.conclusions]
        if len(conclusion_keys) != len(set(conclusion_keys)):
            raise ValueError("task memory conclusion keys must be unique")

        route_ids = [r.route_id for r in self.routes]
        if len(route_ids) != len(set(route_ids)):
            raise ValueError("route ids must be unique")
        known_routes = set(route_ids)
        if (
            self.active_route_id is not None
            and self.active_route_id not in known_routes
        ):
            raise ValueError("active_route_id is unknown")

        ledger_keys = [(item.route_id, item.key) for item in self.proof_ledger]
        if len(ledger_keys) != len(set(ledger_keys)):
            raise ValueError("proof ledger keys must be unique per route")
        if any(item.route_id not in known_routes for item in self.proof_ledger):
            raise ValueError("proof ledger references an unknown route")

        by_key = {(item.route_id, item.key): item for item in self.proof_ledger}
        if any(
            (dep := by_key.get((item.route_id, key))) is None
            or dep.status == "contradicted"
            for item in self.proof_ledger
            for key in item.depends_on
        ):
            raise ValueError("proof ledger has a dangling or contradicted dependency")
        if _ledger_cycle_keys(self.proof_ledger):
            raise ValueError("proof ledger dependencies must be acyclic")

        for route_id in known_routes:
            route_items = [x for x in self.proof_ledger if x.route_id == route_id]
            core_targets = [
                x
                for x in route_items
                if x.key.startswith(CORE_RUNTIME_TARGET_KEY_PREFIX)
                and x.section == "target_contract"
                and x.status == "runtime_observed"
            ]
            if len(core_targets) > 1:
                raise ValueError("route has multiple Core runtime target identities")
            if len(route_items) - len(core_targets) > MAX_ROUTE_LEDGER_ENTRIES:
                raise ValueError("proof ledger exceeds per-route 10-cell limit")

        if (self.active_route_id is None) != (self.route_decision is None):
            raise ValueError("an active route requires exactly one active decision")
        if self.route_decision is not None:
            if self.route_decision.target_route_id != self.active_route_id:
                raise ValueError("active decision target must match active_route_id")
        return self

    def visible_route_ids(self) -> list[str]:
        if self.route_decision is not None:
            return list(self.route_decision.visible_route_ids)
        return [self.active_route_id] if self.active_route_id is not None else []

    def agent_view(self) -> dict[str, Any]:
        """Simple read-only view published to /work/task-memory.json (chmod 0444)."""

        gaps = {
            r.route_id: gap.key
            for r in self.routes
            if (gap := select_active_ledger_gap(self.proof_ledger, route_id=r.route_id))
            is not None
        }
        return {
            "version": AGENT_MEMORY_VIEW_VERSION,
            "task_id": self.task_id,
            "updated_at": self.updated_at.isoformat(),
            "active_route_id": self.active_route_id,
            "entities": [e.model_dump(mode="json") for e in self.entities],
            "routes": [
                {
                    "id": r.route_id,
                    "parent_id": r.parent_route_id,
                    "entity_id": r.entity_id,
                    "fsm_id": r.fsm_id,
                    "state": r.current_state_id,
                    "status": r.lifecycle,
                    "support": r.support,
                    "summary": r.summary,
                    "current_gap": gaps.get(r.route_id),
                }
                for r in self.routes
            ],
            "items": [item.model_dump(mode="json") for item in self.proof_ledger],
            "conclusions": [c.model_dump(mode="json") for c in self.conclusions],
        }

    def _retired_route_contradiction(self) -> TaskMemoryConclusion | None:
        decision = self.route_decision
        if decision is None or decision.action != "new":
            return None
        visible = set(decision.visible_route_ids)
        retired = [
            r
            for r in self.routes
            if r.route_id not in visible and r.support == "contradicted"
        ]
        if not retired:
            return None
        route = max(retired, key=lambda r: (r.updated_attempt, r.route_id))
        contradictions = [
            item
            for item in self.proof_ledger
            if item.route_id == route.route_id and ledger_entry_contradicts_route(item)
        ]
        if not contradictions:
            return None
        top = max(contradictions, key=lambda x: (x.updated_attempt, x.key))
        return TaskMemoryConclusion(
            key=f"retired-{route.route_id}-contradiction",
            kind="result",
            statement=(
                f"Historical {route.route_id} contains this typed structural "
                f"contradiction: {top.claim} Treat it as read-only negative "
                "evidence scoped to that retired route. Do not repeat its "
                "disproved premise unchanged."
            ),
            confidence="high_confidence",
            status="contradicted",
            scope="common",
            evidence=[
                "Core retained this typed contradiction from the retired route.",
                *(ev[:300] for ev in top.evidence[:2]),
            ],
            updated_attempt=top.updated_attempt,
        )

    def prompt_snapshot(
        self, *, max_chars: int = MAX_PROMPT_MEMORY_CHARS
    ) -> TaskMemorySnapshot:
        """Derive a <=32,000-char prompt snapshot without mutating durable state."""

        visible_ids = self.visible_route_ids()
        visible_set = set(visible_ids)
        ledger = [x for x in self.proof_ledger if x.route_id in visible_set]
        common = [
            c
            for c in self.conclusions
            if c.scope == "common" and conclusion_rejection_reason(c) is None
        ]
        retired_neg = self._retired_route_contradiction()
        if retired_neg is not None:
            common.append(retired_neg)
        common = sorted(
            common,
            key=lambda c: (
                _STATUS_PRIORITY[c.status],
                _CONFIDENCE_RANK[c.confidence],
                _KIND_PRIORITY[c.kind],
                c.updated_attempt,
            ),
            reverse=True,
        )[:12]
        visible_conclusions = [
            c
            for c in self.conclusions
            if c.scope == "route"
            and c.route_id in visible_set
            and conclusion_rejection_reason(c) is None
        ][:16]
        cards = [r for r in self.routes if r.route_id in visible_set] + [
            r for r in self.routes if r.route_id not in visible_set
        ][:8]

        payload: dict[str, Any] = {
            "schema_version": MEMORY_SCHEMA_VERSION,
            "task_id": self.task_id,
            "entities": [e.model_dump(mode="json") for e in self.entities[:32]],
            "common": [c.model_dump(mode="json") for c in common],
            "route_summaries": [r.model_dump(mode="json") for r in cards],
            "route_decision": (
                self.route_decision.model_dump(mode="json")
                if self.route_decision is not None
                else None
            ),
            "visible_route_conclusions": [
                c.model_dump(mode="json") for c in visible_conclusions
            ],
            "proof_ledger": [x.model_dump(mode="json") for x in ledger],
        }
        while (
            len(json.dumps(payload, separators=(",", ":"))) > max_chars
            and payload["visible_route_conclusions"]
        ):
            payload["visible_route_conclusions"].pop()
        while (
            len(json.dumps(payload, separators=(",", ":"))) > max_chars
            and payload["common"]
        ):
            payload["common"].pop()
        if len(json.dumps(payload, separators=(",", ":"))) > max_chars:
            for claim_chars, ev_chars in ((300, 160), (160, 100), (64, 48)):
                payload["proof_ledger"] = [
                    {
                        **x.model_dump(mode="json"),
                        "claim": x.claim[:claim_chars],
                        "evidence": [ev[:ev_chars] for ev in x.evidence[:1]],
                    }
                    for x in ledger
                ]
                if len(json.dumps(payload, separators=(",", ":"))) <= max_chars:
                    break
        return TaskMemorySnapshot.model_validate(payload)


class TaskMemoryStore:
    """Atomic persistence and mutation controller for one task TaskMemory."""

    def __init__(self, path: Path, task_id: str) -> None:
        self.path = path.expanduser().resolve()
        self.task_id = task_id

    def load(self) -> TaskMemory:
        if not self.path.exists():
            return TaskMemory(
                task_id=self.task_id,
                updated_at=datetime.now(UTC),
                entities=[
                    TaskMemoryEntity(
                        entity_id="root",
                        kind="root",
                        label=f"Root target for {self.task_id}",
                    )
                ],
            )
        board = TaskMemory.model_validate_json(self.path.read_text(encoding="utf-8"))
        if board.task_id != self.task_id:
            raise ValueError("task memory task_id mismatch")
        routes = [
            (
                route.model_copy(update={"support": "contradicted"})
                if route.support != "contradicted"
                and any(
                    item.route_id == route.route_id
                    and ledger_entry_contradicts_route(item)
                    for item in board.proof_ledger
                )
                else route
            )
            for route in board.routes
        ]
        if routes != board.routes:
            board = TaskMemory.model_validate(
                board.model_copy(update={"routes": routes}).model_dump()
            )
        return board

    def publish_agent_view(self, work_root: Path) -> str:
        """Atomically publish read-only 0o444 /work/task-memory.json."""

        board = self.load()
        work_dir = work_root.expanduser().resolve()
        work_dir.mkdir(parents=True, exist_ok=True)
        target = work_dir / "task-memory.json"
        if target.exists():
            target.chmod(0o600)
        raw = (
            json.dumps(board.agent_view(), ensure_ascii=False, indent=2, sort_keys=True)
            + "\n"
        ).encode("utf-8")
        fd, tmp = tempfile.mkstemp(prefix=".task-memory.", dir=work_dir)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(tmp, 0o444)
            os.replace(tmp, target)
        finally:
            with suppress(OSError):
                os.unlink(tmp)
        return "/work/task-memory.json"

    def register_entities(self, updates: list[TaskMemoryEntity]) -> TaskMemory:
        board = self.load()
        by_id = {e.entity_id: e for e in board.entities}
        for entity in updates:
            by_id[entity.entity_id] = entity
        validated = TaskMemory.model_validate(
            board.model_copy(
                update={
                    "updated_at": datetime.now(UTC),
                    "entities": list(by_id.values()),
                }
            ).model_dump()
        )
        self._write(validated)
        return validated

    def merge_conclusions(self, updates: list[TaskMemoryConclusion]) -> TaskMemory:
        board = self.load()
        known_routes = {r.route_id for r in board.routes}
        by_key = {c.key: c for c in board.conclusions}
        for update in updates:
            if update.scope == "route" and update.route_id not in known_routes:
                raise ValueError("route conclusion references an unknown route")
            if (
                update.scope == "route"
                and any(
                    r.route_id == update.route_id and r.support == "contradicted"
                    for r in board.routes
                )
                and update.status != "contradicted"
            ):
                continue
            if (
                update.scope == "route"
                and update.route_id is not None
                and not update.key.startswith(f"{update.route_id}.")
            ):
                update = update.model_copy(
                    update={"key": f"{update.route_id}.{update.key}"}
                )
            by_key[update.key] = update
        validated = TaskMemory.model_validate(
            board.model_copy(
                update={
                    "updated_at": datetime.now(UTC),
                    "conclusions": list(by_key.values()),
                }
            ).model_dump()
        )
        self._write(validated)
        return validated

    def merge_ledger(
        self,
        updates: list[ProofLedgerEntry],
        *,
        retire_route_ids: set[str] | None = None,
    ) -> TaskMemory:
        """Atomically upsert proof cells with cascading prune & 10-cell cap."""

        board = self.load()
        known_routes = {r.route_id for r in board.routes}
        retired = set(retire_route_ids or ())
        if not retired <= known_routes:
            raise ValueError("cannot retire an unknown route")
        by_key = {(item.route_id, item.key): item for item in board.proof_ledger}
        for update in updates:
            if update.route_id not in known_routes:
                raise ValueError("ledger update references an unknown route")

        prospective = dict(by_key)
        prospective.update(((item.route_id, item.key), item) for item in updates)
        established = {"source_backed", "artifact_encoded", "runtime_observed"}
        rewritten_structural_routes: set[str] = set()

        for update in updates:
            previous = by_key.get((update.route_id, update.key))
            claim_rewrites = previous is not None and (
                previous.claim != update.claim
                and not (
                    previous.status == "source_backed"
                    and update.status == "source_backed"
                )
            )
            dep_rewrites = False
            if previous is not None and previous.depends_on != update.depends_on:
                prev_deps = set(previous.depends_on)
                new_deps = set(update.depends_on)
                added = new_deps - prev_deps
                dep_rewrites = not (
                    prev_deps.issubset(new_deps)
                    and previous.status in established
                    and update.status in established
                    and all(
                        (d := prospective.get((update.route_id, dep_k))) is not None
                        and d.status in established
                        for dep_k in added
                    )
                )
            materially_changed = previous is not None and (
                claim_rewrites
                or previous.section != update.section
                or previous.condition_role != update.condition_role
                or dep_rewrites
                or LEDGER_STATUS_PRIORITY[update.status]
                < LEDGER_STATUS_PRIORITY[previous.status]
                or update.status == "contradicted"
            )
            if materially_changed:
                if is_structural_ledger_cell(previous) or is_structural_ledger_cell(
                    update
                ):
                    rewritten_structural_routes.add(update.route_id)
                _remove_ledger_descendants(
                    by_key, route_id=update.route_id, root_key=update.key
                )

        for update in updates:
            by_key[(update.route_id, update.key)] = update
        coherent = _coherent_proof_ledger(list(by_key.values()))
        merged = _bounded_proof_ledger(coherent)

        routes: list[RouteSummary] = []
        for route in board.routes:
            contradicted = any(
                x.route_id == route.route_id and ledger_entry_contradicts_route(x)
                for x in merged
            )
            support = route.support
            if contradicted or route.route_id in retired:
                support = "contradicted"
            elif (
                support == "contradicted"
                and route.route_id in rewritten_structural_routes
            ):
                support = "uncertain"
            routes.append(route.model_copy(update={"support": support}))

        invalidated = (
            rewritten_structural_routes
            | retired
            | {r.route_id for r in routes if r.support == "contradicted"}
        )
        conclusions = [
            c
            for c in board.conclusions
            if not (
                c.scope == "route"
                and c.route_id in invalidated
                and c.status != "contradicted"
            )
        ]
        validated = TaskMemory.model_validate(
            board.model_copy(
                update={
                    "updated_at": datetime.now(UTC),
                    "proof_ledger": merged,
                    "routes": routes,
                    "conclusions": conclusions,
                }
            ).model_dump()
        )
        self._write(validated)
        return validated

    def update_route(
        self,
        route_id: str,
        *,
        attempt: int,
        summary: str | None = None,
        current_state_id: str | None = None,
        outcome: str | None = None,
        support: Literal["supported", "contradicted", "uncertain"] | None = None,
        lifecycle: Literal["active", "paused", "abandoned", "completed"] | None = None,
        failure_category: str | None = None,
        failure_summary: str | None = None,
        increment_stall: bool = False,
        reset_stall: bool = False,
    ) -> TaskMemory:
        board = self.load()
        routes: list[RouteSummary] = []
        found = False
        for route in board.routes:
            if route.route_id != route_id:
                routes.append(route)
                continue
            found = True
            counts = dict(route.failure_counts)
            if failure_category is not None:
                counts[failure_category] = counts.get(failure_category, 0) + 1
            eff_support = support or route.support
            if any(
                x.route_id == route_id and ledger_entry_contradicts_route(x)
                for x in board.proof_ledger
            ):
                eff_support = "contradicted"
            stall = (
                0
                if reset_stall
                else (route.stall_count + 1 if increment_stall else route.stall_count)
            )
            routes.append(
                route.model_copy(
                    update={
                        "summary": summary or route.summary,
                        "current_state_id": current_state_id or route.current_state_id,
                        "last_outcome": outcome or route.last_outcome,
                        "support": eff_support,
                        "lifecycle": lifecycle or route.lifecycle,
                        "failure_counts": counts,
                        "stall_count": stall,
                        "last_failure": failure_summary or route.last_failure,
                        "updated_attempt": attempt,
                    }
                )
            )
        if not found:
            raise ValueError(f"cannot update unknown route: {route_id}")
        validated = TaskMemory.model_validate(
            board.model_copy(
                update={"updated_at": datetime.now(UTC), "routes": routes}
            ).model_dump()
        )
        self._write(validated)
        return validated

    def apply_route_decision(
        self,
        *,
        action: Literal["continue", "fork", "reopen", "new"],
        route_id: str | None,
        attempt: int,
        rationale: str,
        model: str,
        entity_id: str = "root",
        fsm_id: str = "default",
        initial_state_id: str = "initial",
        causal_dimension: CausalDimension = "unclassified",
        required_constraint: str = (
            "Apply the route rationale as a concrete constraint."
        ),
        forbidden_repeat: str = "Do not repeat the prior construction unchanged.",
    ) -> RouteSummary:
        board = self.load()
        by_id = {r.route_id: r for r in board.routes}
        if action == "continue":
            if route_id is None or route_id != board.active_route_id:
                raise ValueError("continue must select the active route")
            if by_id[route_id].support == "contradicted":
                raise ValueError("a contradicted route cannot continue")
        elif action == "reopen":
            if route_id is None or route_id not in by_id:
                raise ValueError("reopen must select a known route")
            if route_id == board.active_route_id:
                raise ValueError("reopen must select an inactive route")
            if by_id[route_id].support == "contradicted":
                raise ValueError("a contradicted route cannot reopen")
        elif action == "fork":
            if route_id is None or route_id not in by_id:
                raise ValueError("fork must select a known parent route")
            if by_id[route_id].support == "contradicted":
                raise ValueError(
                    "a contradicted route cannot fork; start a new root route"
                )
        elif route_id is not None:
            raise ValueError("a new root route cannot select a parent")

        if action in {"continue", "reopen"}:
            routes = [
                r.model_copy(
                    update={
                        "lifecycle": (
                            "active"
                            if r.route_id == route_id
                            else "paused"
                            if r.lifecycle == "active"
                            else r.lifecycle
                        ),
                        "updated_attempt": (
                            attempt if r.route_id == route_id else r.updated_attempt
                        ),
                    }
                )
                for r in board.routes
            ]
            selected = next(r for r in routes if r.route_id == route_id)
        else:
            routes = [
                r.model_copy(
                    update={"lifecycle": "paused"}
                    if r.route_id == board.active_route_id and r.lifecycle == "active"
                    else {}
                )
                for r in board.routes
            ]
            parent = by_id[route_id] if action == "fork" and route_id else None
            new_route_id = f"route-{len(routes) + 1:03d}"
            selected = RouteSummary(
                route_id=new_route_id,
                parent_route_id=route_id if action == "fork" else None,
                entity_id=parent.entity_id if parent is not None else entity_id,
                fsm_id=parent.fsm_id if parent is not None else fsm_id,
                current_state_id=(
                    parent.current_state_id if parent is not None else initial_state_id
                ),
                summary="An evidence-backed route is being explored.",
                updated_attempt=attempt,
            )
            routes.append(selected)

        target_id = selected.route_id
        prev_decision = board.route_decision
        if action == "continue" and prev_decision is not None:
            visible_ids = list(prev_decision.visible_route_ids)
        elif action == "fork":
            assert route_id is not None
            visible_ids = [route_id, target_id]
        else:
            visible_ids = [target_id]

        decision = RouteDecisionMemory(
            decision_id=f"decision-{attempt:03d}",
            attempt=attempt,
            action=action,
            source_route_id=None if action == "new" else route_id,
            target_route_id=target_id,
            rationale=rationale,
            causal_dimension=causal_dimension,
            required_constraint=required_constraint,
            forbidden_repeat=forbidden_repeat,
            visible_route_ids=visible_ids,
            writable_route_id=target_id,
            model=model,
        )
        validated = TaskMemory.model_validate(
            board.model_copy(
                update={
                    "updated_at": datetime.now(UTC),
                    "routes": routes,
                    "active_route_id": target_id,
                    "route_decision": decision,
                }
            ).model_dump()
        )
        self._write(validated)
        return next(r for r in validated.routes if r.route_id == target_id)

    def _write(self, board: TaskMemory) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        raw = board.model_dump_json(indent=2).encode("utf-8") + b"\n"
        fd, tmp = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, self.path)
        finally:
            with suppress(OSError):
                os.unlink(tmp)
