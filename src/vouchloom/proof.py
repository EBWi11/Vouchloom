"""Core-owned Proof Graph, Single-State Capability Admission, and Delivery Gates.

Faithfully generalizes bug_hunter/cybergym_proof.py and artifact_stage_ready().
"""

from __future__ import annotations

from typing import Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from vouchloom.blackboard import (
    BlackboardSnapshot,
    ConditionRole,
    ProofStatus,
    ledger_gap_blocks_construction,
    select_active_ledger_gap,
)
from vouchloom.models import StrictModel
from vouchloom.receipts import ExecutionReceipt, canonical_sha256

PROOF_GRAPH_SCHEMA_VERSION = "vouchloom-proof-graph/1.0"
CAPABILITY_PLAN_SCHEMA_VERSION = "vouchloom-capabilities/1.0"

ProofNodeKind = Literal[
    "target",
    "entrypoint",
    "protocol",
    "carrier",
    "call_edge",
    "guard",
    "state",
    "sink",
    "checkpoint",
    "gap",
    "runtime",
    "startup",
]
ProofNodeOrigin = Literal["anchor", "memory", "execution"]
CapabilityStage = Literal[
    "contract",
    "proof",
    "carrier_source",
    "protocol",
    "construction",
    "runtime",
    "analysis",
]

_LEDGER_SECTION_TO_NODE_KIND: dict[str, ProofNodeKind] = {
    "target_contract": "target",
    "sink": "sink",
    "call_edge": "call_edge",
    "condition": "guard",
    "state_transition": "state",
    "checkpoint": "checkpoint",
    "construction": "carrier",
    "open_gap": "gap",
}


class ProofNode(StrictModel):
    """One typed fact projected from admissible current-task evidence."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,119}$")
    kind: ProofNodeKind
    status: ProofStatus
    origin: ProofNodeOrigin
    claim: str = Field(min_length=1, max_length=1_000)
    condition_role: ConditionRole = "unknown"
    observed_target: str | None = Field(
        default=None,
        max_length=500,
        pattern=r"^[A-Za-z0-9_.:/+-]+$",
    )
    depends_on: list[str] = Field(default_factory=list, max_length=16)
    receipt_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("claim")
    @classmethod
    def normalize_claim(cls, value: str) -> str:
        rendered = " ".join(value.split())
        if not rendered:
            raise ValueError("proof node claims must be non-empty")
        return rendered

    @field_validator("depends_on")
    @classmethod
    def unique_dependencies(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("proof node dependencies must be unique")
        return values


def proof_graph_digest(nodes: list[ProofNode]) -> str:
    return canonical_sha256(
        {
            "schema_version": PROOF_GRAPH_SCHEMA_VERSION,
            "nodes": [item.model_dump(mode="json") for item in nodes],
        }
    )


class ProofGraph(StrictModel):
    """Acyclic, integrity-hashed projection of current route & execution proof."""

    schema_version: Literal["vouchloom-proof-graph/1.0"] = PROOF_GRAPH_SCHEMA_VERSION
    nodes: list[ProofNode] = Field(default_factory=list, max_length=64)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_acyclic_and_digest(self) -> Self:
        by_id = {n.id: n for n in self.nodes}
        if len(by_id) != len(self.nodes):
            raise ValueError("proof node ids must be unique")
        if any(dep not in by_id for n in self.nodes for dep in n.depends_on):
            raise ValueError("proof graph dependencies must be present")
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node_id: str) -> None:
            if node_id in visited:
                return
            if node_id in visiting:
                raise ValueError("proof graph dependencies must be acyclic")
            visiting.add(node_id)
            for dep in by_id[node_id].depends_on:
                visit(dep)
            visiting.remove(node_id)
            visited.add(node_id)

        for node_id in by_id:
            visit(node_id)
        if self.sha256 != proof_graph_digest(self.nodes):
            raise ValueError("proof graph digest is not canonical")
        return self

    def dependency_closure(self, node_id: str) -> set[str]:
        by_id = {n.id: n for n in self.nodes}
        closure: set[str] = set()
        pending = [node_id]
        while pending:
            cur = pending.pop()
            if cur in closure or cur not in by_id:
                continue
            closure.add(cur)
            pending.extend(by_id[cur].depends_on)
        return closure


class Capability(StrictModel):
    """One Core or Worker skill capability admitted by the typed ProofGraph."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{0,119}$")
    stage: CapabilityStage
    skill_name: str | None = Field(default=None, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    proof_node_ids: list[str] = Field(default_factory=list, max_length=16)


def capability_plan_digest(
    *, proof_graph_sha256: str, capabilities: list[Capability]
) -> str:
    return canonical_sha256(
        {
            "schema_version": CAPABILITY_PLAN_SCHEMA_VERSION,
            "proof_graph_sha256": proof_graph_sha256,
            "capabilities": [c.model_dump(mode="json") for c in capabilities],
        }
    )


class CapabilityPlan(StrictModel):
    """Deterministic Worker capabilities enforcing single-state execution."""

    schema_version: Literal["vouchloom-capabilities/1.0"] = (
        CAPABILITY_PLAN_SCHEMA_VERSION
    )
    proof_graph_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    capabilities: list[Capability] = Field(default_factory=list, max_length=8)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def enforce_single_agent_state(self) -> Self:
        ids = [c.id for c in self.capabilities]
        if len(ids) != len(set(ids)):
            raise ValueError("capability ids must be unique")
        agent_caps = [c for c in self.capabilities if c.skill_name is not None]
        agent_stages = {c.stage for c in agent_caps}
        if len(agent_stages) > 1:
            raise ValueError("one Worker turn may execute only one Agent state")
        skill_names = [c.skill_name for c in agent_caps]
        if len(skill_names) != len(set(skill_names)):
            raise ValueError("Agent skill capabilities must be unique")
        expected = capability_plan_digest(
            proof_graph_sha256=self.proof_graph_sha256,
            capabilities=self.capabilities,
        )
        if self.sha256 != expected:
            raise ValueError("capability plan digest is not canonical")
        return self


def build_capability_plan(
    graph: ProofGraph, capabilities: list[Capability]
) -> CapabilityPlan:
    return CapabilityPlan(
        proof_graph_sha256=graph.sha256,
        capabilities=capabilities,
        sha256=capability_plan_digest(
            proof_graph_sha256=graph.sha256, capabilities=capabilities
        ),
    )


def project_proof_graph(
    *,
    anchor_evidence: dict[str, Any],
    snapshot: BlackboardSnapshot | None,
    active_route_id: str | None,
    execution_receipts: list[ExecutionReceipt],
) -> ProofGraph:
    """Project anchor contract, active-route proof cells, & receipts into a DAG."""

    nodes: list[ProofNode] = []
    target = anchor_evidence.get("target")
    anchor_bound = (
        anchor_evidence.get("complete") is True
        and anchor_evidence.get("ambiguous") is not True
        and isinstance(target, str)
        and bool(target.strip())
    )
    if anchor_bound:
        nodes.append(
            ProofNode(
                id="anchor.target",
                kind="target",
                status="source_backed",
                origin="anchor",
                claim=f"Current bound target is {target.strip()}.",
                observed_target=target.strip(),
            )
        )
    if anchor_evidence.get("entrypoint_bound") is True:
        deps = ["anchor.target"] if anchor_bound else []
        nodes.append(
            ProofNode(
                id="anchor.entrypoint",
                kind="entrypoint",
                status="source_backed",
                origin="anchor",
                claim="Current target resolves one deterministic entrypoint.",
                depends_on=deps,
            )
        )
        if anchor_evidence.get("protocol_bound") is True:
            nodes.append(
                ProofNode(
                    id="anchor.protocol",
                    kind="protocol",
                    status="source_backed",
                    origin="anchor",
                    claim="Current entrypoint provides a typed input protocol.",
                    depends_on=["anchor.entrypoint"],
                )
            )

    if snapshot is not None and active_route_id is not None:
        retained = [
            item for item in snapshot.proof_ledger if item.route_id == active_route_id
        ]
        retained_keys = {item.key for item in retained}
        for item in retained:
            deps = [f"memory.{dep}" for dep in item.depends_on if dep in retained_keys]
            claim = " ".join(item.claim.split())
            if len(claim) > 1_000:
                claim = f"{claim[:997].rstrip()}..."
            nodes.append(
                ProofNode(
                    id=f"memory.{item.key}",
                    kind=_LEDGER_SECTION_TO_NODE_KIND[item.section],
                    status=item.status,
                    origin="memory",
                    claim=claim,
                    condition_role=item.condition_role,
                    depends_on=deps,
                    receipt_sha256=item.receipt_sha256,
                )
            )

    for idx, receipt in enumerate(execution_receipts[-16:], start=1):
        if receipt.phase == "environment_startup":
            kind: ProofNodeKind = "startup"
            claim = "The execution stopped during environment startup."
        elif receipt.phase == "target_runtime":
            kind = "runtime"
            claim = "The subject was executed by the observed target at runtime."
        else:
            continue
        deps = (
            ["anchor.target"]
            if anchor_bound and receipt.observed_target == target
            else []
        )
        nodes.append(
            ProofNode(
                id=f"execution.{idx}",
                kind=kind,
                status="runtime_observed",
                origin="execution",
                claim=claim,
                observed_target=receipt.observed_target,
                depends_on=deps,
                receipt_sha256=receipt.sha256,
            )
        )

    return ProofGraph(nodes=nodes, sha256=proof_graph_digest(nodes))


def delivery_stage_ready(
    snapshot: BlackboardSnapshot | None,
    active_route_id: str | None,
    anchor_evidence: dict[str, Any],
    *,
    has_concrete_carrier: bool = False,
) -> bool:
    """Generalizes bug_hunter's artifact_stage_ready() gate.

    Blocks final delivery when:
    - Target/carrier contract is unbound;
    - No established carrier_construction exists on the route;
    - Sinks are only hypotheses;
    - Active non-construction fault gap has no established sink in its closure;
    - Source-backed construction depends on an open gap without concrete carrier.
    """

    if snapshot is None or active_route_id is None:
        return False
    contract_bound = (
        anchor_evidence.get("complete") is True
        and anchor_evidence.get("ambiguous") is not True
    )
    if not contract_bound:
        return False

    retained = [
        item
        for item in snapshot.proof_ledger
        if item.route_id == active_route_id and item.status != "contradicted"
    ]
    if not retained:
        return False
    established = {"source_backed", "artifact_encoded", "runtime_observed"}
    has_construction = any(
        item.section == "construction"
        and item.carrier_construction
        and item.status in established
        for item in retained
    )
    if not has_construction:
        return False

    sinks = [item for item in retained if item.section == "sink"]
    if sinks and all(item.status == "hypothesis" for item in sinks):
        return False

    by_key = {item.key: item for item in retained}
    active_gap = select_active_ledger_gap(retained, route_id=active_route_id)
    graph = project_proof_graph(
        anchor_evidence={},
        snapshot=snapshot,
        active_route_id=active_route_id,
        execution_receipts=[],
    )
    if (
        active_gap is not None
        and active_gap.section == "open_gap"
        and active_gap.status == "hypothesis"
        and not ledger_gap_blocks_construction(active_gap, by_key)
        and not (active_gap.key == "core.latest-gap" and not active_gap.depends_on)
    ):
        closure = graph.dependency_closure(f"memory.{active_gap.key}")
        has_bound_sink = any(
            node.id in closure
            and node.origin == "memory"
            and node.kind == "sink"
            and node.status in established
            for node in graph.nodes
        )
        if not has_bound_sink:
            return False

    if not has_concrete_carrier:
        open_gap_ids = {
            n.id for n in graph.nodes if n.kind == "gap" and n.status == "hypothesis"
        }
        if any(
            n.kind == "carrier"
            and n.status == "source_backed"
            and bool((graph.dependency_closure(n.id) - {n.id}) & open_gap_ids)
            for n in graph.nodes
        ):
            return False
    return True
