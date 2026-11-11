"""Hybrid Declarative FSM Spec IR (YAML/JSON) + Deterministic Python Guard Registry.

Enables composable Micro-FSMs, hierarchical Statechart nesting (sub_fsm_id),
1 -> N entity-triggered instantiation, and safe outer-RL graph mutation without
allowing the outer Agent to inject arbitrary Python code.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, Literal, Self

import yaml
from pydantic import Field, model_validator

from vouchloom.memory import (
    LEDGER_STATUS_PRIORITY,
    ProofSection,
    ProofStatus,
    TaskMemory,
    TaskMemoryEntity,
    ledger_gap_blocks_construction,
)
from vouchloom.models import StrictModel
from vouchloom.proof import CapabilityStage

FSM_SPEC_SCHEMA_VERSION = "vouchloom-fsm-spec/1.0"

StateExecutionMode = Literal[
    "research",
    "core_action",
    "bounded_action",
    "delivery",
    "thin_mutation",
    "exploratory_probe",
]

GuardCallable = Callable[[TaskMemory, str, dict[str, Any]], bool]


class GuardRegistry:
    """Registry of deterministic Python guard plugins addressable in YAML/JSON."""

    def __init__(self) -> None:
        self._guards: dict[str, GuardCallable] = {}

    def register(self, name: str, fn: GuardCallable) -> None:
        if re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", name) is None:
            raise ValueError(f"invalid guard plugin name: {name}")
        self._guards[name] = fn

    def get(self, name: str) -> GuardCallable | None:
        return self._guards.get(name)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._guards))


class TriggerPredicate(StrictModel):
    """Declarative trigger mounting a Micro-FSM onto matching TaskMemoryEntities."""

    entity_kind: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    required_attributes: dict[str, str] = Field(default_factory=dict)
    attribute_regex: dict[str, str] = Field(default_factory=dict)

    def matches(self, entity: TaskMemoryEntity) -> bool:
        if entity.kind != self.entity_kind:
            return False
        for key, expected in self.required_attributes.items():
            if entity.attributes.get(key) != expected:
                return False
        for key, pattern in self.attribute_regex.items():
            actual = entity.attributes.get(key, "")
            if re.search(pattern, actual) is None:
                return False
        return True


class GuardClause(StrictModel):
    """Hybrid declarative + plugin guard evaluated deterministically by Core."""

    required_sections: list[ProofSection] = Field(default_factory=list)
    min_status: ProofStatus = "source_backed"
    require_no_construction_gap: bool = False
    require_no_contradiction: bool = True
    require_action_outcome: Literal["completed", "refuted", "blocked"] | None = None
    entity_attribute_equals: dict[str, str] = Field(default_factory=dict)
    python_guard: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_.-]{0,79}$")
    semantic_arbiter: str | None = Field(
        default=None, pattern=r"^[a-z][a-z0-9_.-]{0,79}$"
    )

    def evaluate_deterministic(
        self,
        board: TaskMemory,
        route_id: str,
        *,
        context: dict[str, Any] | None = None,
        guard_registry: GuardRegistry | None = None,
    ) -> bool:
        ctx = context or {}
        route = next((r for r in board.routes if r.route_id == route_id), None)
        if route is None:
            return False
        if self.require_no_contradiction and route.support == "contradicted":
            return False
        if (
            self.require_action_outcome is not None
            and ctx.get("last_action_outcome") != self.require_action_outcome
        ):
            return False

        entity = next(
            (e for e in board.entities if e.entity_id == route.entity_id), None
        )
        for key, expected in self.entity_attribute_equals.items():
            if entity is None or entity.attributes.get(key) != expected:
                return False

        entries = [
            x
            for x in board.proof_ledger
            if x.route_id == route_id and x.status != "contradicted"
        ]
        min_rank = LEDGER_STATUS_PRIORITY[self.min_status]
        for section in self.required_sections:
            if not any(
                x.section == section and LEDGER_STATUS_PRIORITY[x.status] >= min_rank
                for x in entries
            ):
                return False

        if self.require_no_construction_gap:
            by_key = {x.key: x for x in entries}
            if any(
                ledger_gap_blocks_construction(x, by_key)
                for x in entries
                if x.section == "open_gap" and x.status == "hypothesis"
            ):
                return False

        if self.python_guard is not None:
            if guard_registry is None:
                raise ValueError(
                    f"python_guard '{self.python_guard}' requires a GuardRegistry"
                )
            fn = guard_registry.get(self.python_guard)
            if fn is None:
                raise KeyError(f"unregistered python_guard: {self.python_guard}")
            if not fn(board, route_id, ctx):
                return False
        return True


class StateNodeSpec(StrictModel):
    """One state contract inside a composable Micro-FSM."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    title: str = Field(min_length=1, max_length=200)
    mode: StateExecutionMode = "research"
    agent_stage: CapabilityStage | None = None
    system_prompt: str = Field(min_length=1)
    allowed_skills: list[str] = Field(default_factory=list, max_length=8)
    max_total_tokens: int = Field(default=1_200_000, ge=1_024)
    max_output_tokens: int = Field(default=32_768, ge=256)
    max_turn_seconds: int | None = Field(default=600, ge=1)
    finalization_tool_calls: int | None = Field(default=None, ge=1)
    required_artifact_path: str | None = None
    artifact_deadline_tool_calls: int | None = Field(default=None, ge=1)
    sub_fsm_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    is_terminal: bool = False

    @model_validator(mode="after")
    def validate_artifact_and_skills(self) -> Self:
        if (self.required_artifact_path is None) != (
            self.artifact_deadline_tool_calls is None
        ):
            raise ValueError(
                "required_artifact_path and artifact_deadline_tool_calls must be "
                "configured together"
            )
        if len(self.allowed_skills) != len(set(self.allowed_skills)):
            raise ValueError("allowed_skills must be unique")
        return self


class TransitionSpec(StrictModel):
    """One directed, guarded, Bandit-weighted state transition."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    source: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    target: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    priority: int = Field(default=0, ge=-1_000, le=1_000)
    bandit_prior_weight: float = Field(default=1.0, gt=0.0, le=100.0)
    description: str = Field(default="", max_length=400)
    guard: GuardClause = Field(default_factory=GuardClause)


class StateMachineSpec(StrictModel):
    """Declarative Micro-FSM IR serializable to/from YAML and JSON."""

    schema_version: Literal["vouchloom-fsm-spec/1.0"] = FSM_SPEC_SCHEMA_VERSION
    fsm_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    version: str = Field(default="0.1.0", min_length=1, max_length=40)
    description: str = Field(min_length=1, max_length=1_000)
    trigger: TriggerPredicate | None = None
    initial_state: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    states: list[StateNodeSpec] = Field(min_length=1)
    transitions: list[TransitionSpec] = Field(default_factory=list)
    ad_hoc_ephemeral: bool = False

    @model_validator(mode="after")
    def verify_static_topology(self) -> Self:
        state_ids = [s.id for s in self.states]
        if len(state_ids) != len(set(state_ids)):
            raise ValueError(f"duplicate state ids in FSM {self.fsm_id}")
        known = set(state_ids)
        if self.initial_state not in known:
            raise ValueError(
                f"initial_state '{self.initial_state}' not in FSM {self.fsm_id}"
            )
        if not any(s.is_terminal for s in self.states):
            raise ValueError(
                f"FSM {self.fsm_id} must declare at least one terminal state"
            )
        trans_ids = [t.id for t in self.transitions]
        if len(trans_ids) != len(set(trans_ids)):
            raise ValueError(f"duplicate transition ids in FSM {self.fsm_id}")
        for trans in self.transitions:
            if trans.source not in known:
                raise ValueError(
                    f"transition {trans.id} has unknown source '{trans.source}'"
                )
            if trans.target not in known:
                raise ValueError(
                    f"transition {trans.id} has unknown target '{trans.target}'"
                )
            source_node = next(s for s in self.states if s.id == trans.source)
            if source_node.is_terminal:
                raise ValueError(
                    f"terminal state '{source_node.id}' cannot have outgoing edges"
                )
        for state in self.states:
            if state.sub_fsm_id == self.fsm_id:
                raise ValueError(f"state '{state.id}' cannot nest its own FSM")
        return self

    def state_by_id(self, state_id: str) -> StateNodeSpec:
        for state in self.states:
            if state.id == state_id:
                return state
        raise KeyError(f"state '{state_id}' not found in FSM '{self.fsm_id}'")

    def outgoing_transitions(self, state_id: str) -> list[TransitionSpec]:
        return sorted(
            (t for t in self.transitions if t.source == state_id),
            key=lambda t: (-t.priority, -t.bandit_prior_weight, t.id),
        )

    def to_yaml(self) -> str:
        return yaml.safe_dump(
            self.model_dump(mode="json"),
            sort_keys=False,
            allow_unicode=True,
        )

    @classmethod
    def from_yaml(cls, raw: str) -> StateMachineSpec:
        loaded = yaml.safe_load(raw)
        if not isinstance(loaded, dict):
            raise ValueError("FSM YAML must deserialize to a mapping")
        return cls.model_validate(loaded)


class StateMachineRegistry:
    """Validated catalog of Micro-FSMs enforcing acyclic hierarchical nesting."""

    def __init__(self, guard_registry: GuardRegistry | None = None) -> None:
        self.guard_registry = guard_registry or GuardRegistry()
        self._specs: dict[str, StateMachineSpec] = {}

    def register(self, spec: StateMachineSpec) -> None:
        prospective = {**self._specs, spec.fsm_id: spec}
        self._verify_acyclic_hierarchy(prospective)
        for trans in spec.transitions:
            if (
                trans.guard.python_guard is not None
                and self.guard_registry.get(trans.guard.python_guard) is None
            ):
                raise KeyError(
                    f"transition '{trans.id}' references unregistered python_guard "
                    f"'{trans.guard.python_guard}'"
                )
        self._specs[spec.fsm_id] = spec

    def get(self, fsm_id: str) -> StateMachineSpec:
        if fsm_id not in self._specs:
            raise KeyError(f"unknown FSM '{fsm_id}'")
        return self._specs[fsm_id]

    def all_specs(self) -> list[StateMachineSpec]:
        return [self._specs[k] for k in sorted(self._specs)]

    def matching_specs_for_entity(
        self, entity: TaskMemoryEntity
    ) -> list[StateMachineSpec]:
        return [
            spec
            for spec in self.all_specs()
            if spec.trigger is not None and spec.trigger.matches(entity)
        ]

    @staticmethod
    def _verify_acyclic_hierarchy(specs: dict[str, StateMachineSpec]) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(fsm_id: str) -> None:
            if fsm_id in visited or fsm_id not in specs:
                return
            if fsm_id in visiting:
                raise ValueError(f"cyclic sub_fsm_id hierarchy involving '{fsm_id}'")
            visiting.add(fsm_id)
            for state in specs[fsm_id].states:
                if state.sub_fsm_id is not None:
                    if state.sub_fsm_id not in specs:
                        raise ValueError(
                            f"state '{state.id}' references unknown sub_fsm_id "
                            f"'{state.sub_fsm_id}'"
                        )
                    visit(state.sub_fsm_id)
            visiting.remove(fsm_id)
            visited.add(fsm_id)

        for key in specs:
            visit(key)
