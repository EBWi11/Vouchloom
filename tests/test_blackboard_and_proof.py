"""Tests for Layer 1 Blackboard 10+1 ledger invariants, frontiers, and ProofGraph."""

from __future__ import annotations

from pathlib import Path

import pytest

from vouchloom import (
    BlackboardEntity,
    BlackboardStore,
    Capability,
    ExecutionReceipt,
    ProofLedgerEntry,
    build_capability_plan,
    delivery_stage_ready,
    dependency_closed_carrier_prefix_frontier,
    dependency_closed_runtime_frontier,
    project_proof_graph,
)


def test_blackboard_entity_requires_receipt_and_10_plus_1_pruning(
    tmp_path: Path,
) -> None:
    store = BlackboardStore(tmp_path / "blackboard.json", "task-01")
    route = store.apply_route_decision(
        action="new",
        route_id=None,
        attempt=1,
        rationale="Initial route",
        model="core-deterministic",
    )

    with pytest.raises(ValueError, match="derived child entities require"):
        BlackboardEntity(
            entity_id="svc-8080",
            kind="service",
            parent_entity_id="root",
            label="Port 8080",
            receipt_sha256=None,
        )

    store.register_entities(
        [
            BlackboardEntity(
                entity_id="svc-8080",
                kind="service",
                parent_entity_id="root",
                label="Port 8080",
                receipt_sha256="1" * 64,
            )
        ]
    )

    # Insert 1 reserved core.runtime-target.* slot + 12 regular cells -> 10 + 1 = 11!
    entries = [
        ProofLedgerEntry(
            key="core.runtime-target.official",
            section="target_contract",
            claim="Official runtime target bound",
            status="runtime_observed",
            evidence=["probe receipt"],
            route_id=route.route_id,
            updated_attempt=1,
        )
    ]
    for idx in range(12):
        entries.append(
            ProofLedgerEntry(
                key=f"obs.{idx:02d}",
                section="checkpoint",
                claim=f"Observation {idx}",
                status="source_backed",
                evidence=[f"src:{idx}"],
                depends_on=["core.runtime-target.official"],
                route_id=route.route_id,
                updated_attempt=idx + 1,
            )
        )
    board = store.merge_ledger(entries)
    retained_keys = {x.key for x in board.proof_ledger}
    assert "core.runtime-target.official" in retained_keys
    assert len(board.proof_ledger) == 11


def test_cascading_contradiction_and_retired_negative_projection(
    tmp_path: Path,
) -> None:
    store = BlackboardStore(tmp_path / "blackboard.json", "task-02")
    r1 = store.apply_route_decision(
        action="new",
        route_id=None,
        attempt=1,
        rationale="Explore route 1",
        model="core-deterministic",
    )
    store.merge_ledger(
        [
            ProofLedgerEntry(
                key="target.main",
                section="target_contract",
                claim="Target main entry",
                status="source_backed",
                evidence=["main.c:10"],
                route_id=r1.route_id,
                updated_attempt=1,
            ),
            ProofLedgerEntry(
                key="guard.auth",
                section="condition",
                condition_role="required",
                claim="Auth header bypassable",
                status="source_backed",
                depends_on=["target.main"],
                evidence=["auth.c:42"],
                route_id=r1.route_id,
                updated_attempt=1,
            ),
            ProofLedgerEntry(
                key="sink.exec",
                section="sink",
                claim="Command sink reached",
                status="hypothesis",
                depends_on=["guard.auth"],
                evidence=["exec.c:99"],
                route_id=r1.route_id,
                updated_attempt=1,
            ),
        ]
    )

    # Contradict upstream required condition -> downstream sink.exec cascades out
    board = store.merge_ledger(
        [
            ProofLedgerEntry(
                key="guard.auth",
                section="condition",
                condition_role="required",
                claim="Auth header strictly enforced by middleware",
                status="contradicted",
                depends_on=["target.main"],
                evidence=["middleware.c:15"],
                route_id=r1.route_id,
                updated_attempt=2,
            )
        ]
    )
    keys = {x.key for x in board.proof_ledger if x.route_id == r1.route_id}
    assert "sink.exec" not in keys
    route_after = next(r for r in board.routes if r.route_id == r1.route_id)
    assert route_after.support == "contradicted"

    # Contradicted route cannot continue or fork
    with pytest.raises(ValueError, match="contradicted"):
        store.apply_route_decision(
            action="continue",
            route_id=r1.route_id,
            attempt=3,
            rationale="Try continue",
            model="core",
        )

    # Replacement 'new' route projects retired contradiction as negative premise
    store.apply_route_decision(
        action="new",
        route_id=None,
        attempt=3,
        rationale="Start replacement root",
        model="core",
    )
    snap = store.load().prompt_snapshot()
    assert any(c.key == f"retired-{r1.route_id}-contradiction" for c in snap.common)


def test_frontiers_proof_graph_single_state_and_delivery_gate(tmp_path: Path) -> None:
    store = BlackboardStore(tmp_path / "blackboard.json", "task-03")
    r = store.apply_route_decision(
        action="new",
        route_id=None,
        attempt=1,
        rationale="Build proof spine",
        model="core",
    )
    store.merge_ledger(
        [
            ProofLedgerEntry(
                key="target",
                section="target_contract",
                claim="Bound target",
                status="source_backed",
                evidence=["t.c:1"],
                route_id=r.route_id,
            ),
            ProofLedgerEntry(
                key="prod",
                section="state_transition",
                claim="Header parsed",
                status="runtime_observed",
                depends_on=["target"],
                evidence=["run:1"],
                route_id=r.route_id,
            ),
            ProofLedgerEntry(
                key="sink",
                section="sink",
                claim="Sink reached",
                status="source_backed",
                depends_on=["prod"],
                evidence=["s.c:20"],
                route_id=r.route_id,
            ),
            ProofLedgerEntry(
                key="carrier",
                section="construction",
                carrier_construction=True,
                claim="Frame layout encoded",
                status="artifact_encoded",
                depends_on=["sink"],
                evidence=["/work/seed.bin"],
                route_id=r.route_id,
            ),
            ProofLedgerEntry(
                key="gap.probe",
                section="open_gap",
                claim="Observe sink hit on encoded frame",
                status="hypothesis",
                depends_on=["carrier"],
                evidence=["pending"],
                route_id=r.route_id,
            ),
        ]
    )
    snap = store.load().prompt_snapshot()
    rt_frontier = dependency_closed_runtime_frontier(snap, r.route_id)
    assert rt_frontier is not None
    assert rt_frontier.sink_key == "sink"

    anchor = {"target": "fuzzer_x", "complete": True, "ambiguous": False}
    assert delivery_stage_ready(snap, r.route_id, anchor, has_concrete_carrier=True)

    receipt = ExecutionReceipt.build(
        subject_sha256="c" * 64,
        output="ran",
        exit_code=0,
        observed_target="fuzzer_x",
        phase="target_runtime",
    )
    graph = project_proof_graph(
        anchor_evidence=anchor,
        snapshot=snap,
        active_route_id=r.route_id,
        execution_receipts=[receipt],
    )
    # Single-state Agent capability invariant: mixing analysis + construction fails
    with pytest.raises(ValueError, match="only one Agent state"):
        build_capability_plan(
            graph,
            [
                Capability(id="agent.s1", stage="analysis", skill_name="skill-one"),
                Capability(id="agent.s2", stage="construction", skill_name="skill-two"),
            ],
        )

    # CarrierPrefixFrontier check when next state_transition is source_backed
    store2 = BlackboardStore(tmp_path / "bb2.json", "task-04")
    r2 = store2.apply_route_decision(
        action="new", route_id=None, attempt=1, rationale="Prefix", model="core"
    )
    store2.merge_ledger(
        [
            ProofLedgerEntry(
                key="t",
                section="target_contract",
                claim="Target",
                status="source_backed",
                evidence=["a"],
                route_id=r2.route_id,
            ),
            ProofLedgerEntry(
                key="step1",
                section="state_transition",
                claim="Handshake step 1",
                status="runtime_observed",
                depends_on=["t"],
                evidence=["obs"],
                route_id=r2.route_id,
            ),
            ProofLedgerEntry(
                key="step2",
                section="state_transition",
                claim="Auth packet step 2",
                status="source_backed",
                depends_on=["step1"],
                evidence=["src"],
                route_id=r2.route_id,
            ),
            ProofLedgerEntry(
                key="s",
                section="sink",
                claim="Sink",
                status="source_backed",
                depends_on=["step2"],
                evidence=["src"],
                route_id=r2.route_id,
            ),
            ProofLedgerEntry(
                key="c",
                section="construction",
                carrier_construction=True,
                claim="Carrier with step1",
                status="artifact_encoded",
                depends_on=["s"],
                evidence=["bin"],
                route_id=r2.route_id,
            ),
            ProofLedgerEntry(
                key="gap.step2",
                section="open_gap",
                claim="Encode step 2",
                status="hypothesis",
                depends_on=["c"],
                evidence=["gap"],
                route_id=r2.route_id,
            ),
        ]
    )
    prefix_f = dependency_closed_carrier_prefix_frontier(
        store2.load().prompt_snapshot(), r2.route_id
    )
    assert prefix_f is not None
    assert prefix_f.transition_key == "step2"
