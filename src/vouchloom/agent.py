"""Runtime-neutral Agent definitions, immutable Skills, and typed Worker outputs.

Faithfully generalizes bug_hunter/agent.py and bug_hunter/poc.py, preserving
branch-locked Pydantic schemas (WorkerModelOutput, WorkerHandoffOnlyOutput,
WorkerArtifactOnlyOutput), canonical RFC 4648 base64 checks, acyclic handoff
validation, JSON byte headroom caps, and interrupted handoff salvage.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from vouchloom.models import CausalDimension, ModelUsage, StrictModel
from vouchloom.receipts import ActionReceipt, CommandReceipt, NextAction
from vouchloom.request_budget import RequestBudget

MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_ARTIFACT_BASE64_CHARS = 4 * ((MAX_ARTIFACT_BYTES + 2) // 3)
ARTIFACT_TARGET_JSON_BYTES = 10 * 1024
HANDOFF_TARGET_JSON_BYTES = 24 * 1024
JSON_SIZE_HEADROOM_PERCENT = 15
ARTIFACT_MAX_JSON_BYTES = (
    ARTIFACT_TARGET_JSON_BYTES * (100 + JSON_SIZE_HEADROOM_PERCENT) + 99
) // 100
HANDOFF_MAX_JSON_BYTES = (
    HANDOFF_TARGET_JSON_BYTES * (100 + JSON_SIZE_HEADROOM_PERCENT) + 99
) // 100
MAX_PROJECTED_HANDOFF_ITEMS = 10

_SCHEMA_ANNOTATION_KEYS = frozenset({"default", "title"})


def compact_json_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Strip non-semantic schema annotations to save context tokens."""

    def visit(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                k: visit(v)
                for k, v in value.items()
                if k not in _SCHEMA_ANNOTATION_KEYS
            }
        if isinstance(value, list):
            return [visit(v) for v in value]
        return value

    return visit(schema)


@dataclass(frozen=True)
class AgentSkillFile:
    path: str
    content: bytes = field(repr=False)
    mode: int


@dataclass(frozen=True)
class AgentSkill:
    """Explicitly admitted immutable skill snapshot (automatic discovery disabled)."""

    name: str
    path: Path
    files: tuple[AgentSkillFile, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", self.name) is None:
            raise ValueError("agent skill names must use normalized hyphen-case")
        resolved = Path(self.path).expanduser().resolve()
        if not (resolved / "SKILL.md").is_file():
            raise ValueError(f"agent skill has no SKILL.md: {resolved}")
        files = tuple(
            AgentSkillFile(
                path=item.relative_to(resolved).as_posix(),
                content=item.read_bytes(),
                mode=stat.S_IMODE(item.stat().st_mode),
            )
            for item in sorted(
                (cand for cand in resolved.rglob("*") if cand.is_file()),
                key=lambda cand: cand.relative_to(resolved).as_posix(),
            )
        )
        object.__setattr__(self, "path", resolved)
        object.__setattr__(self, "files", files)

    def read_text(self, relative_path: str = "SKILL.md") -> str:
        for item in self.files:
            if item.path == relative_path:
                return item.content.decode("utf-8")
        raise FileNotFoundError(f"skill snapshot has no file: {relative_path}")


@dataclass(frozen=True)
class AgentDefinition:
    """Complete stage execution contract enforced by ManagedAgentRuntime."""

    id: str
    version: str
    system_prompt: str
    output_model: type[BaseModel]
    max_total_tokens: int | None = None
    max_output_tokens: int | None = None
    request_budget: RequestBudget | None = None
    skills: tuple[AgentSkill, ...] = ()
    allow_tools: bool = True
    required_artifact_path: str | None = None
    artifact_deadline_tool_calls: int | None = None
    finalization_tool_calls: int | None = None
    max_turn_seconds: int | None = None
    debug_capture: bool = False

    def __post_init__(self) -> None:
        if (self.required_artifact_path is None) != (
            self.artifact_deadline_tool_calls is None
        ):
            raise ValueError(
                "required_artifact_path and artifact_deadline_tool_calls must "
                "be configured together"
            )
        if self.required_artifact_path is not None:
            rel = PurePosixPath(self.required_artifact_path)
            if (
                rel.is_absolute()
                or not rel.parts
                or ".." in rel.parts
                or str(rel) in {"", "."}
            ):
                raise ValueError("required_artifact_path must be work-root relative")
        if (
            self.artifact_deadline_tool_calls is not None
            and self.artifact_deadline_tool_calls < 1
        ):
            raise ValueError("artifact_deadline_tool_calls must be positive")
        if self.max_turn_seconds is not None and self.max_turn_seconds < 1:
            raise ValueError("max_turn_seconds must be positive")
        if (
            self.finalization_tool_calls is not None
            and self.finalization_tool_calls < 1
        ):
            raise ValueError("finalization_tool_calls must be positive")


@dataclass
class AgentTrace:
    agent_id: str
    model_id: str
    messages: list[dict[str, Any]]
    tool_calls: int
    usage: ModelUsage
    result: BaseModel
    model_calls: int = 1
    tool_rounds: int | None = None
    command_receipts: list[CommandReceipt] = field(default_factory=list)
    request_receipts: list[dict[str, Any]] = field(default_factory=list)


class AgentRuntimeError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        messages: list[dict[str, Any]] | None = None,
        tool_calls: int = 0,
        model_calls: int = 0,
        tool_rounds: int | None = None,
        usage: ModelUsage | None = None,
        model_id: str | None = None,
        command_receipts: list[CommandReceipt] | None = None,
        request_receipts: list[dict[str, Any]] | None = None,
        code: str | None = None,
        last_final_text: str | None = None,
    ) -> None:
        super().__init__(message)
        self.messages = messages or []
        self.tool_calls = tool_calls
        self.model_calls = model_calls
        self.tool_rounds = tool_rounds
        self.usage = usage or ModelUsage()
        self.model_id = model_id
        self.command_receipts = command_receipts or []
        self.request_receipts = request_receipts or []
        self.code = code
        self.last_final_text = last_final_text


MemoryItemKind = Literal[
    "contract",
    "protocol",
    "call_edge",
    "sink",
    "condition",
    "construction",
    "observation",
    "gap",
    "note",
]
MemoryItemStatus = Literal[
    "hypothesis",
    "source_backed",
    "artifact_encoded",
    "runtime_observed",
    "contradicted",
]
MemoryItemRole = Literal["required", "derived", "optional", "unknown"]


class MemoryItem(StrictModel):
    """One evidence-addressable proof/note item emitted in a Worker Handoff."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    kind: MemoryItemKind
    status: MemoryItemStatus
    claim: str = Field(min_length=1)
    evidence: list[str] = Field(min_length=1)
    depends_on: list[str] = Field(default_factory=list)
    cross_entity_refs: list[str] = Field(default_factory=list)
    role: MemoryItemRole = "unknown"

    @field_validator("claim")
    @classmethod
    def normalize_claim(cls, value: str) -> str:
        rendered = " ".join(value.split())
        if not rendered:
            raise ValueError("handoff claims must be non-empty")
        return rendered

    @field_validator("evidence")
    @classmethod
    def normalize_evidence(cls, values: list[str]) -> list[str]:
        normalized = [" ".join(v.split()) for v in values]
        if any(not v for v in normalized):
            raise ValueError("handoff evidence must be non-empty")
        return normalized

    @field_validator("depends_on")
    @classmethod
    def validate_dependencies(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)) or any(
            re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,79}", v) is None for v in values
        ):
            raise ValueError("handoff dependencies must be unique normalized ids")
        return values

    @model_validator(mode="after")
    def no_self_dependency(self) -> MemoryItem:
        if self.id in self.depends_on:
            raise ValueError("a handoff item cannot depend on itself")
        return self


class DiscoveredEntityDraft(StrictModel):
    """Candidate child entity proposed by a Worker, citing a real tool sequence."""

    entity_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{0,119}$")
    kind: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    label: str = Field(min_length=1, max_length=300)
    attributes: dict[str, str] = Field(default_factory=dict)
    command_sequence: int = Field(ge=1)


class UnexpectedSignalDraft(StrictModel):
    """Out-of-band signal proposed to the Observer, citing a real tool sequence."""

    signal_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    category: Literal[
        "unexpected_surface",
        "novel_component",
        "cross_branch_clue",
        "protocol_anomaly",
        "state_deadlock",
    ]
    summary: str = Field(min_length=1, max_length=600)
    proposed_hypothesis: str = Field(min_length=1, max_length=600)
    command_sequence: int = Field(ge=1)


class ResearchHandoff(StrictModel):
    """Typed checkpoint emitted from a Worker's live context before a fresh thread."""

    summary: str = Field(min_length=1)
    next_step: str = Field(min_length=1)
    next_action: NextAction
    action_receipt: ActionReceipt | None = None
    items: list[MemoryItem] = Field(min_length=1)
    discovered_entities: list[DiscoveredEntityDraft] = Field(default_factory=list)
    unexpected_signals: list[UnexpectedSignalDraft] = Field(default_factory=list)

    @field_validator("summary", "next_step")
    @classmethod
    def normalize_text(cls, value: str) -> str:
        rendered = " ".join(value.split())
        if not rendered:
            raise ValueError("handoff text must be non-empty")
        return rendered

    @model_validator(mode="after")
    def validate_acyclic_items(self) -> ResearchHandoff:
        ids = [item.id for item in self.items]
        if len(ids) != len(set(ids)):
            raise ValueError("handoff item ids must be unique")
        by_id = {item.id: item for item in self.items}
        if any(dep not in by_id for item in self.items for dep in item.depends_on):
            raise ValueError("handoff dependencies must be present in the handoff")
        if any(
            item.kind != "note" and by_id[dep].kind == "note"
            for item in self.items
            for dep in item.depends_on
        ):
            raise ValueError("proof-state items cannot depend on note items")
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(key: str) -> None:
            if key in visited:
                return
            if key in visiting:
                raise ValueError("handoff dependencies must be acyclic")
            visiting.add(key)
            for dep in by_id[key].depends_on:
                visit(dep)
            visiting.remove(key)
            visited.add(key)

        for key in by_id:
            visit(key)
        return self


def decode_strict_base64(value: str) -> bytes:
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise ValueError("artifact_base64 must be strict RFC 4648 base64") from error
    if base64.b64encode(decoded) != encoded:
        raise ValueError("artifact_base64 must use canonical padding")
    if not decoded or len(decoded) > MAX_ARTIFACT_BYTES:
        raise ValueError("artifact has an invalid byte size")
    return decoded


class InlineArtifactSource(StrictModel):
    kind: Literal["inline"]
    artifact_base64: str = Field(max_length=MAX_ARTIFACT_BASE64_CHARS)

    @model_validator(mode="after")
    def check_base64(self) -> InlineArtifactSource:
        decode_strict_base64(self.artifact_base64)
        return self


class DisclosedArtifactSource(StrictModel):
    kind: Literal["disclosed"]
    disclosed_candidate_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class PathArtifactSource(StrictModel):
    kind: Literal["path"]
    artifact_path: str = Field(min_length=1, max_length=500)

    @field_validator("artifact_path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        rendered = value.strip()
        if not rendered:
            raise ValueError("artifact_path must be non-empty")
        return rendered


ArtifactSource = InlineArtifactSource | DisclosedArtifactSource | PathArtifactSource


class ArtifactPayload(StrictModel):
    source: ArtifactSource
    rationale: str = Field(default="model-generated candidate", min_length=1)
    claim_binding: str | None = None
    construction_receipt: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    deterministically_constructed: bool = False
    construction_context: str | None = None
    causal_dimension: CausalDimension = "unclassified"
    changed_constraint: str | None = None
    semantic_checkpoint: str | None = None


class ArtifactOutput(ArtifactPayload):
    kind: Literal["artifact"] = "artifact"


class HandoffOutput(StrictModel):
    kind: Literal["handoff"] = "handoff"
    handoff: ResearchHandoff


def _projected_json_bytes(value: Any, *, exclude_inline_bytes: bool) -> int:
    measured = value
    if exclude_inline_bytes and isinstance(value, dict):
        source = value.get("source")
        if isinstance(source, dict) and source.get("kind") == "inline":
            measured = {**value, "source": {**source, "artifact_base64": ""}}
    return len(
        json.dumps(measured, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8", errors="surrogatepass"
        )
    )


def project_worker_output(value: object, *, allow_handoff: bool) -> object:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python")
    if not isinstance(value, dict):
        return value
    source = value.get("source")
    handoff = value.get("handoff")
    if source is not None and handoff is None:
        projected = {
            k: v
            for k, v in value.items()
            if k != "handoff"
            and not (
                k in {"rationale", "deterministically_constructed", "causal_dimension"}
                and v is None
            )
        }
        actual = _projected_json_bytes(projected, exclude_inline_bytes=True)
        if actual > ARTIFACT_MAX_JSON_BYTES:
            raise ValueError(
                f"projected artifact JSON is {actual} bytes; "
                f"maximum is {ARTIFACT_MAX_JSON_BYTES} bytes"
            )
        return projected
    if handoff is not None and source is None and allow_handoff:
        if isinstance(handoff, dict) and isinstance(handoff.get("items"), list):
            handoff = {
                **handoff,
                "items": handoff["items"][:MAX_PROJECTED_HANDOFF_ITEMS],
            }
        projected = {"handoff": handoff}
        actual = _projected_json_bytes(projected, exclude_inline_bytes=False)
        if actual > HANDOFF_MAX_JSON_BYTES:
            raise ValueError(
                f"projected handoff JSON is {actual} bytes; "
                f"maximum is {HANDOFF_MAX_JSON_BYTES} bytes"
            )
        return projected
    return value


class WorkerModelOutput(StrictModel):
    """Flat Worker output permitting either one artifact source OR one handoff."""

    source: ArtifactSource | None = None
    rationale: str | None = Field(default=None, min_length=1)
    claim_binding: str | None = None
    construction_receipt: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    deterministically_constructed: bool | None = None
    construction_context: str | None = None
    causal_dimension: CausalDimension | None = None
    changed_constraint: str | None = None
    semantic_checkpoint: str | None = None
    handoff: ResearchHandoff | None = None

    @model_validator(mode="before")
    @classmethod
    def project_raw(cls, value: object) -> object:
        return project_worker_output(value, allow_handoff=True)

    @model_validator(mode="after")
    def require_single_branch(self) -> WorkerModelOutput:
        if (self.source is None) == (self.handoff is None):
            raise ValueError("return exactly one artifact source or handoff")
        project_worker_output(self.model_dump(mode="python"), allow_handoff=True)
        return self

    @property
    def branch(self) -> ArtifactOutput | HandoffOutput:
        if self.source is not None:
            return ArtifactOutput(
                source=self.source,
                rationale=self.rationale or "model-generated candidate",
                claim_binding=self.claim_binding,
                construction_receipt=self.construction_receipt,
                deterministically_constructed=self.deterministically_constructed
                or False,
                construction_context=self.construction_context,
                causal_dimension=self.causal_dimension or "unclassified",
                changed_constraint=self.changed_constraint,
                semantic_checkpoint=self.semantic_checkpoint,
            )
        assert self.handoff is not None
        return HandoffOutput(handoff=self.handoff)


class WorkerHandoffOnlyOutput(StrictModel):
    """Core-action schema physically removing the artifact branch."""

    handoff: ResearchHandoff

    @model_validator(mode="before")
    @classmethod
    def project_raw(cls, value: object) -> object:
        return project_worker_output(value, allow_handoff=True)

    @property
    def branch(self) -> HandoffOutput:
        return HandoffOutput(handoff=self.handoff)


class WorkerArtifactOnlyOutput(ArtifactPayload):
    """Delivery-stage schema physically removing the handoff branch."""

    @model_validator(mode="before")
    @classmethod
    def project_raw(cls, value: object) -> object:
        return project_worker_output(value, allow_handoff=False)

    @property
    def branch(self) -> ArtifactOutput:
        return ArtifactOutput(**self.model_dump(mode="python"))


def recover_research_handoff(raw_text: str | None) -> ResearchHandoff | None:
    """Salvage a complete, independently valid ResearchHandoff from interrupted text."""

    if not raw_text:
        return None
    rendered = raw_text.strip()
    if rendered.startswith("```") and rendered.endswith("```"):
        rendered = "\n".join(rendered.splitlines()[1:-1]).strip()
    payload: Any = None
    try:
        payload = json.loads(rendered)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        idx = rendered.find("{")
        while idx >= 0:
            try:
                payload, _ = decoder.raw_decode(rendered, idx)
                break
            except json.JSONDecodeError:
                idx = rendered.find("{", idx + 1)
    if payload is None:
        return None
    try:
        projected = project_worker_output(payload, allow_handoff=True)
        if not isinstance(projected, dict) or projected.get("source") is not None:
            return None
        raw_handoff = projected.get("handoff")
        if not isinstance(raw_handoff, dict):
            return None
        return ResearchHandoff.model_validate(raw_handoff)
    except ValueError:
        return None


class MemoryReviewItem(MemoryItem):
    """Structural delta proposed by the Exhausted Memory Reviewer."""

    kind: Literal[
        "contract",
        "protocol",
        "call_edge",
        "sink",
        "condition",
        "construction",
        "gap",
    ]
    status: Literal["source_backed", "contradicted"]


class MemoryReviewOutput(StrictModel):
    """Source-backed decision at the original task-budget boundary."""

    decision: Literal["resume", "stop", "blocked"]
    rationale: str = Field(min_length=1)
    next_step: str | None = None
    items: list[MemoryReviewItem] = Field(default_factory=list, max_length=8)
