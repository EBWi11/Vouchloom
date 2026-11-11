"""Standalone bug_hunter CyberGym Level 1 preset migrated onto Vouchloom.

Loads the complete migrated configuration bundle under `presets/bug_hunter/`:
- `fsm_specs/*.fsm.yaml`: Core PoC pipeline + project/protocol Micro-FSMs
- `handbook_data/{common,generic,projects}.yaml`: validated ASCII handbook catalog
- `skills/*`: all 16 packaged fail-closed Codex skills & deterministic scripts
- `sandbox_helpers/*`: bitstream, byte-patch, archive-member, & witness-sweep CLIs
- Deterministic `GuardRegistry` plugins (`bug_hunter.*`) faithfully reproducing
  `cybergym_runner.py` and `cybergym_agent.py` admission gates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from vouchloom.agent import AgentSkill
from vouchloom.fsm import GuardRegistry, StateMachineRegistry, StateMachineSpec
from vouchloom.memory import (
    CORE_RUNTIME_TARGET_KEY_PREFIX,
    TaskMemory,
    dependency_closed_runtime_frontier,
    ledger_dependency_closure,
    ledger_entry_contradicts_route,
    ledger_gap_blocks_construction,
)
from vouchloom.models import CausalDimension
from vouchloom.proof import CapabilityStage, delivery_stage_ready

BUG_HUNTER_PRESET_ROOT = Path(__file__).with_name("bug_hunter")
BUG_HUNTER_CORE_FSM_ID = "bug-hunter-core"

HANDBOOK_SCHEMA_VERSION = 1
MAX_HANDBOOK_TOPIC_CHARS = 4_000
MAX_HANDBOOK_SUMMARY_CHARS = 120
MAX_REQUIRED_HANDBOOK_TOPICS = 9
_TOPIC_ID_PATTERN = re.compile(r"^[A-Za-z0-9_]+$")
_PROJECT_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.+-]*$")

BUG_HUNTER_SKILL_STAGE: dict[str, CapabilityStage] = {
    "c-cpp-targeted-static-triage": "analysis",
    "source-backed-byte-construction": "construction",
    "fixture-backed-carrier-projection": "construction",
    "archive-member-carrier-triage": "construction",
    "framed-transcript-reconciliation": "construction",
    "runtime-witness-sweep": "runtime",
    "ffmpeg-target-dec-native-search": "runtime",
    "ffmpeg-demux-native-search": "runtime",
    "graphicsmagick-nested-coder-search": "runtime",
    "graphicsmagick-coder-native-search": "runtime",
    "libxaac-native-msan-search": "runtime",
    "source-derived-bit-offset-probe": "construction",
    "libxml2-api-bytecode-carrier": "construction",
    "libxaac-spatial-fill-carrier": "construction",
    "curl-fuzzer-tlv-carrier": "construction",
    "cryptofuzz-operation-carrier": "construction",
}

_TOPICS_BY_DIMENSION: dict[CausalDimension, tuple[str, ...]] = {
    "input_boundary": ("input_boundary",),
    "parser_phase": (
        "structured_state",
        "state_transition_witness",
        "runtime_probe_debugging",
    ),
    "precondition_gate": ("input_boundary", "sink_contract"),
    "framing_integrity": (
        "structured_state",
        "artifact_fidelity",
        "state_transition_witness",
    ),
    "observability": (
        "fault_observability",
        "sink_contract",
        "runtime_probe_debugging",
    ),
    "state_geometry": ("fault_observability", "sink_contract"),
    "lifecycle_order": (
        "lifecycle_ownership",
        "state_transition_witness",
        "sink_contract",
    ),
    "construction_encoding": (
        "deterministic_construction",
        "artifact_fidelity",
    ),
    "evidence_arbitration": ("evidence_arbitration",),
    "tool_completion": ("memory_and_retry",),
}


@dataclass(frozen=True)
class HandbookTopic:
    """Validated ASCII handbook topic migrated from bug_hunter/handbook.py."""

    topic_id: str
    summary: str
    content: str
    project_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.topic_id.isascii() or not _TOPIC_ID_PATTERN.fullmatch(
            self.topic_id
        ):
            raise ValueError(f"invalid handbook topic id: {self.topic_id}")
        if not self.summary.isascii() or not self.content.isascii():
            raise ValueError(f"handbook topic {self.topic_id} must be strict ASCII")
        if not 1 <= len(self.summary) <= MAX_HANDBOOK_SUMMARY_CHARS:
            raise ValueError(f"handbook topic {self.topic_id} summary length invalid")
        if not self.content.strip() or len(self.content) > MAX_HANDBOOK_TOPIC_CHARS:
            raise ValueError(f"handbook topic {self.topic_id} content length invalid")
        if len(set(self.project_names)) != len(self.project_names):
            raise ValueError(f"duplicate project_names in {self.topic_id}")
        for pname in self.project_names:
            if not pname.isascii() or not _PROJECT_NAME_PATTERN.fullmatch(pname):
                raise ValueError(f"invalid project name {pname!r} in {self.topic_id}")


@dataclass(frozen=True)
class BugHunterHandbookCatalog:
    common: HandbookTopic
    topics: dict[str, HandbookTopic]
    project_topic_by_name: dict[str, str]

    def render_base_prompt(self) -> str:
        return (
            "You are an authorized, source-visible vulnerability and raw-PoC "
            "research agent.\n\n"
            f"{self.common.content.strip()}\n\n"
            "Mandatory causal-construction rules:\n\n"
            f"{self.topics['causal_construction_loop'].content.strip()}\n"
        )


@dataclass(frozen=True)
class BugHunterPresetBundle:
    """Complete ready-to-run bug_hunter configuration mounted into Vouchloom."""

    root: Path
    registry: StateMachineRegistry
    specs: dict[str, StateMachineSpec]
    skills: dict[str, AgentSkill]
    handbook: BugHunterHandbookCatalog
    sandbox_helpers: dict[str, Path]


# ---------------------------------------------------------------------------
# 1. Handbook Loader & Topic Selector
# ---------------------------------------------------------------------------


def _parse_topic_entry(raw: Any, *, project_topic: bool) -> HandbookTopic:
    if not isinstance(raw, dict):
        raise ValueError("handbook topic entry must be a mapping")
    project_names: tuple[str, ...] = ()
    if project_topic:
        names = raw.get("project_names")
        if not isinstance(names, list) or not names:
            raise ValueError("project topic requires non-empty project_names")
        project_names = tuple(str(x) for x in names)
    parsed = HandbookTopic(
        topic_id=str(raw["id"]),
        summary=str(raw["summary"]),
        content=str(raw["content"]),
        project_names=project_names,
    )
    if project_topic != parsed.topic_id.startswith("project_"):
        raise ValueError(f"project topic prefix mismatch on {parsed.topic_id}")
    return parsed


def load_bug_hunter_handbook(
    data_dir: Path | None = None,
) -> BugHunterHandbookCatalog:
    """Load and validate common.yaml, generic.yaml, and projects.yaml."""

    root = data_dir or (BUG_HUNTER_PRESET_ROOT / "handbook_data")
    common_doc = yaml.safe_load((root / "common.yaml").read_text(encoding="ascii"))
    if common_doc.get("version") != HANDBOOK_SCHEMA_VERSION:
        raise ValueError("unsupported common.yaml version")
    common = _parse_topic_entry(common_doc["common"], project_topic=False)

    generic_doc = yaml.safe_load((root / "generic.yaml").read_text(encoding="ascii"))
    projects_doc = yaml.safe_load((root / "projects.yaml").read_text(encoding="ascii"))
    if (
        generic_doc.get("version") != HANDBOOK_SCHEMA_VERSION
        or projects_doc.get("version") != HANDBOOK_SCHEMA_VERSION
    ):
        raise ValueError("unsupported handbook topics version")

    ordered = [
        *(_parse_topic_entry(x, project_topic=False) for x in generic_doc["topics"]),
        *(_parse_topic_entry(x, project_topic=True) for x in projects_doc["topics"]),
    ]
    topics: dict[str, HandbookTopic] = {}
    by_project: dict[str, str] = {}
    for item in ordered:
        if item.topic_id == "common" or item.topic_id in topics:
            raise ValueError(f"duplicate handbook topic: {item.topic_id}")
        topics[item.topic_id] = item
        for pname in item.project_names:
            if pname in by_project:
                raise ValueError(f"duplicate project mapping: {pname}")
            by_project[pname] = item.topic_id
    return BugHunterHandbookCatalog(
        common=common,
        topics=topics,
        project_topic_by_name=by_project,
    )


def select_bug_hunter_handbook_topics(
    catalog: BugHunterHandbookCatalog,
    *,
    harness_evidence: dict[str, Any],
    project_name: str | None = None,
    causal_dimension: CausalDimension = "unclassified",
    causal_focus: Literal["complete_route", "task_identity_probe"] = "complete_route",
    has_attempts: bool = False,
    semantic_topics: list[str] | None = None,
) -> list[str]:
    """Exact port of bug_hunter's deterministic `required_handbook_topics`."""

    selected: list[str] = []

    def add(tid: str) -> None:
        if tid in catalog.topics and tid not in selected:
            selected.append(tid)

    dim_topics = _TOPICS_BY_DIMENSION.get(causal_dimension, ())
    if dim_topics:
        add(dim_topics[0])
    cand_paths = harness_evidence.get("candidate_paths")
    if (
        harness_evidence.get("ambiguous") is True
        or harness_evidence.get("complete") is False
        or (
            isinstance(cand_paths, list)
            and len(cand_paths) > 1
            and not harness_evidence.get("target")
        )
    ):
        add("harness_binding")

    norm_proj = str(project_name or "").strip().casefold()
    proj_topic = catalog.project_topic_by_name.get(norm_proj)

    if causal_focus == "task_identity_probe":
        add("evidence_arbitration")
        if proj_topic is not None:
            add(proj_topic)
        if has_attempts:
            add("memory_and_retry")
        add("sink_contract")
        for mapped in dim_topics[1:]:
            add(mapped)
        if not has_attempts and proj_topic is None:
            add("source_navigation")
        for tid in semantic_topics or []:
            add(tid)
    else:
        for tid in semantic_topics or []:
            add(tid)
        if proj_topic is not None:
            add(proj_topic)
        if has_attempts:
            add("memory_and_retry")
        for mapped in dim_topics[1:]:
            add(mapped)
        if not has_attempts and proj_topic is None:
            add("source_navigation")
    return selected[:MAX_REQUIRED_HANDBOOK_TOPICS]


# ---------------------------------------------------------------------------
# 2. Deterministic Python Guard Plugins (`bug_hunter.*`)
# ---------------------------------------------------------------------------


def _guard_target_reconciled(
    memory: TaskMemory, route_id: str, ctx: dict[str, Any]
) -> bool:
    """True when no Core runtime-target exists OR a call_edge closes to it."""

    del ctx
    entries = [x for x in memory.proof_ledger if x.route_id == route_id]
    by_key = {x.key: x for x in entries}
    core_targets = [
        x
        for x in entries
        if x.key.startswith(CORE_RUNTIME_TARGET_KEY_PREFIX)
        and x.section == "target_contract"
        and x.status == "runtime_observed"
    ]
    if not core_targets:
        return any(
            x.section == "target_contract"
            and x.status in {"source_backed", "artifact_encoded", "runtime_observed"}
            for x in entries
        )
    target_key = core_targets[0].key
    established = {"source_backed", "artifact_encoded", "runtime_observed"}
    return any(
        x.section == "call_edge"
        and x.status in established
        and target_key in ledger_dependency_closure(x, by_key)
        for x in entries
    )


def _guard_construction_gap_action_ready(
    memory: TaskMemory, route_id: str, ctx: dict[str, Any]
) -> bool:
    del ctx
    entries = [x for x in memory.proof_ledger if x.route_id == route_id]
    by_key = {x.key: x for x in entries}
    return any(
        ledger_gap_blocks_construction(x, by_key)
        for x in entries
        if x.section == "open_gap" and x.status == "hypothesis"
    )


def _guard_runtime_frontier_ready(
    memory: TaskMemory, route_id: str, ctx: dict[str, Any]
) -> bool:
    del ctx
    return (
        dependency_closed_runtime_frontier(memory.prompt_snapshot(), route_id)
        is not None
    )


def _guard_artifact_stage_ready(
    memory: TaskMemory, route_id: str, ctx: dict[str, Any]
) -> bool:
    anchor = ctx.get("anchor_evidence") or {"complete": True, "ambiguous": False}
    has_carrier = bool(ctx.get("has_concrete_carrier", True))
    return delivery_stage_ready(
        memory.prompt_snapshot(),
        route_id,
        anchor,
        has_concrete_carrier=has_carrier,
    )


def _guard_thin_mutation_ready(
    memory: TaskMemory, route_id: str, ctx: dict[str, Any]
) -> bool:
    if not _guard_artifact_stage_ready(memory, route_id, ctx):
        return False
    return bool(ctx.get("prior_artifact_available", False))


def _guard_recovery_probe_ready(
    memory: TaskMemory, route_id: str, ctx: dict[str, Any]
) -> bool:
    """Port of cybergym_agent.recovery_probe_stage_ready."""

    if not ctx.get("post_memory_review", False):
        return False
    entries = [x for x in memory.proof_ledger if x.route_id == route_id]
    if any(ledger_entry_contradicts_route(x) for x in entries):
        return False
    established = {"source_backed", "artifact_encoded", "runtime_observed"}
    return (
        any(x.section == "target_contract" and x.status in established for x in entries)
        and any(
            x.section in {"call_edge", "sink", "condition"} and x.status in established
            for x in entries
        )
        and any(
            x.section == "construction"
            and x.carrier_construction
            and x.status == "hypothesis"
            for x in entries
        )
        and not any(
            x.section == "construction"
            and x.carrier_construction
            and x.status in established
            for x in entries
        )
    )


def _guard_first_crash_needs_comparison(
    memory: TaskMemory, route_id: str, ctx: dict[str, Any]
) -> bool:
    if ctx.get("distinct_crashes", 0) == 1 and not ctx.get(
        "high_confidence_first_crash", False
    ):
        return True
    route = next((r for r in memory.routes if r.route_id == route_id), None)
    return route is not None and route.last_outcome == "milestone_candidate"


def _guard_ready_to_finalize(
    memory: TaskMemory, route_id: str, ctx: dict[str, Any]
) -> bool:
    if ctx.get("distinct_crashes", 0) >= 2 or ctx.get(
        "high_confidence_first_crash", False
    ):
        return True
    if ctx.get("verification_window_exhausted", False):
        return True
    route = next((r for r in memory.routes if r.route_id == route_id), None)
    return (
        route is not None
        and route.support == "supported"
        and route.last_outcome == "milestone_candidate"
        and bool(ctx.get("single_crash_mode", False))
    )


def _guard_ffmpeg_demux_search_ready(
    memory: TaskMemory, route_id: str, ctx: dict[str, Any]
) -> bool:
    del ctx
    route = next((r for r in memory.routes if r.route_id == route_id), None)
    if route is None:
        return False
    entity = next((e for e in memory.entities if e.entity_id == route.entity_id), None)
    target = entity.attributes.get("target", "") if entity else ""
    return bool(re.fullmatch(r"ffmpeg_dem_[A-Za-z0-9_]+_fuzzer", target))


def _guard_gm_nested_coder_ready(
    memory: TaskMemory, route_id: str, ctx: dict[str, Any]
) -> bool:
    del ctx
    entries = [x for x in memory.proof_ledger if x.route_id == route_id]
    established = {"source_backed", "runtime_observed"}
    return any(
        x.status in established
        and (
            (
                x.section == "state_transition"
                and "nested" in x.claim.casefold()
                and "dispatch" in x.claim.casefold()
            )
            or (
                x.section == "call_edge"
                and "extracttilejpg" in x.claim.casefold()
                and "blobtoimage" in x.claim.casefold()
            )
        )
        for x in entries
    )


def register_bug_hunter_guards(guard_registry: GuardRegistry) -> GuardRegistry:
    """Register all `bug_hunter.*` deterministic guards onto a GuardRegistry."""

    guard_registry.register("bug_hunter.target_reconciled", _guard_target_reconciled)
    guard_registry.register(
        "bug_hunter.construction_gap_action_ready",
        _guard_construction_gap_action_ready,
    )
    guard_registry.register(
        "bug_hunter.runtime_frontier_ready", _guard_runtime_frontier_ready
    )
    guard_registry.register(
        "bug_hunter.artifact_stage_ready", _guard_artifact_stage_ready
    )
    guard_registry.register(
        "bug_hunter.thin_mutation_ready", _guard_thin_mutation_ready
    )
    guard_registry.register(
        "bug_hunter.recovery_probe_ready", _guard_recovery_probe_ready
    )
    guard_registry.register(
        "bug_hunter.first_crash_needs_comparison",
        _guard_first_crash_needs_comparison,
    )
    guard_registry.register("bug_hunter.ready_to_finalize", _guard_ready_to_finalize)
    guard_registry.register(
        "bug_hunter.ffmpeg_demux_search_ready", _guard_ffmpeg_demux_search_ready
    )
    guard_registry.register(
        "bug_hunter.gm_nested_coder_ready", _guard_gm_nested_coder_ready
    )
    return guard_registry


# ---------------------------------------------------------------------------
# 3. Packaged Skills & Complete Preset Bundle Loader
# ---------------------------------------------------------------------------


def load_bug_hunter_skills(skills_dir: Path | None = None) -> dict[str, AgentSkill]:
    """Snapshot all 16 packaged bug_hunter skills with mode bits preserved."""

    root = skills_dir or (BUG_HUNTER_PRESET_ROOT / "skills")
    loaded: dict[str, AgentSkill] = {}
    for child in sorted(root.iterdir()):
        if child.is_dir() and (child / "SKILL.md").is_file():
            skill = AgentSkill(name=child.name, path=child)
            loaded[skill.name] = skill
    return loaded


def load_bug_hunter_preset(
    preset_root: Path | None = None,
    *,
    registry: StateMachineRegistry | None = None,
) -> BugHunterPresetBundle:
    """Load and cross-validate all bug_hunter YAML FSMs, guards, skills, & handbook."""

    root = (preset_root or BUG_HUNTER_PRESET_ROOT).expanduser().resolve()
    fsm_registry = registry or StateMachineRegistry()
    register_bug_hunter_guards(fsm_registry.guard_registry)

    skills = load_bug_hunter_skills(root / "skills")
    handbook = load_bug_hunter_handbook(root / "handbook_data")

    specs: dict[str, StateMachineSpec] = {}
    specs_dir = root / "fsm_specs"
    for yaml_path in sorted(specs_dir.glob("*.fsm.yaml")):
        spec = StateMachineSpec.from_yaml(yaml_path.read_text(encoding="utf-8"))
        # Verify every skill referenced in YAML exists & shares one CapabilityStage!
        for state in spec.states:
            stages_in_state: set[CapabilityStage] = set()
            for sname in state.allowed_skills:
                if sname not in skills:
                    raise KeyError(
                        f"FSM '{spec.fsm_id}' state '{state.id}' references "
                        f"missing skill '{sname}'"
                    )
                if sname in BUG_HUNTER_SKILL_STAGE:
                    stages_in_state.add(BUG_HUNTER_SKILL_STAGE[sname])
            if len(stages_in_state) > 1:
                raise ValueError(
                    f"FSM '{spec.fsm_id}' state '{state.id}' mixes multiple "
                    f"Agent capability stages: {sorted(stages_in_state)}"
                )
        fsm_registry.register(spec)
        specs[spec.fsm_id] = spec

    helpers_dir = root / "sandbox_helpers"
    helpers = {p.name: p for p in sorted(helpers_dir.iterdir()) if p.is_file()}
    return BugHunterPresetBundle(
        root=root,
        registry=fsm_registry,
        specs=specs,
        skills=skills,
        handbook=handbook,
        sandbox_helpers=helpers,
    )
