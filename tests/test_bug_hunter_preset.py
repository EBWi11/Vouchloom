"""Comprehensive verification for the migrated bug_hunter standalone preset."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from vouchloom import (
    ArtifactOutput,
    ExecutionReceipt,
    InlineArtifactSource,
    LocalDirectorySandbox,
    ManagedAgentRuntime,
    ModelTurnResponse,
    ModelUsage,
    ProofLedgerEntry,
    PublicNeutralizationReceipt,
    RouteSummary,
    TaskMemoryEntity,
    TaskMemoryStore,
    TeamOrchestrator,
    candidate_has_high_confidence_source_proof,
)
from vouchloom.presets import (
    BUG_HUNTER_CORE_FSM_ID,
    BugHunterRequestComposer,
    load_bug_hunter_preset,
    select_bug_hunter_handbook_topics,
)


def test_bug_hunter_preset_bundle_loads_all_fsms_skills_handbook_and_helpers() -> None:
    bundle = load_bug_hunter_preset()

    # All 5 declarative FSM YAMLs loaded & registered cleanly
    assert set(bundle.specs) == {
        "bug-hunter-core",
        "bug-hunter-ffmpeg-native-search",
        "bug-hunter-graphicsmagick-search",
        "bug-hunter-curl-tlv-delivery",
        "bug-hunter-structured-carriers",
    }
    core_spec = bundle.registry.get(BUG_HUNTER_CORE_FSM_ID)
    assert core_spec.initial_state == "core_target_reconcile"
    assert len(core_spec.states) == 10
    assert len(core_spec.transitions) == 15

    # All 16 packaged fail-closed skills loaded with SKILL.md snapshots
    assert len(bundle.skills) == 16
    assert "c-cpp-targeted-static-triage" in bundle.skills
    assert "ffmpeg-target-dec-native-search" in bundle.skills
    assert "graphicsmagick-nested-coder-search" in bundle.skills
    assert "curl-fuzzer-tlv-carrier" in bundle.skills
    assert "framed-transcript-reconciliation" in bundle.skills

    # Handbook catalog loaded & deterministic topic selection matches bug_hunter
    assert bundle.handbook.common.topic_id == "common"
    assert "causal_construction_loop" in bundle.handbook.topics
    assert "project_ffmpeg" in bundle.handbook.topics
    topics = select_bug_hunter_handbook_topics(
        bundle.handbook,
        harness_evidence={"complete": False, "ambiguous": True},
        project_name="ffmpeg",
        causal_dimension="parser_phase",
        causal_focus="task_identity_probe",
        has_attempts=True,
    )
    assert "evidence_arbitration" in topics
    assert "harness_binding" in topics
    assert "project_ffmpeg" in topics
    assert "memory_and_retry" in topics

    # Sandbox deterministic helpers present
    assert "bug_hunter_bitstream_build.py" in bundle.sandbox_helpers
    assert "bug_hunter_byte_patch.py" in bundle.sandbox_helpers
    assert "bug_hunter_archive_member.py" in bundle.sandbox_helpers
    assert "bug_hunter_witness_sweep.py" in bundle.sandbox_helpers


def test_bug_hunter_entity_triggers_and_deterministic_guards(tmp_path: Path) -> None:
    bundle = load_bug_hunter_preset()

    # Entity TriggerPredicate matching for FFmpeg, GraphicsMagick, Curl, & libxml2
    ffmpeg_entity = TaskMemoryEntity(
        entity_id="target.vp9",
        kind="fuzz_target",
        parent_entity_id="root",
        label="FFmpeg VP9 decoder fuzzer",
        attributes={"project": "ffmpeg", "target": "ffmpeg_AV_CODEC_ID_VP9_fuzzer"},
        receipt_sha256="a" * 64,
    )
    matched_ffmpeg = [
        s.fsm_id for s in bundle.registry.matching_specs_for_entity(ffmpeg_entity)
    ]
    assert matched_ffmpeg == ["bug-hunter-ffmpeg-native-search"]

    gm_entity = TaskMemoryEntity(
        entity_id="target.jnx",
        kind="fuzz_target",
        parent_entity_id="root",
        label="GraphicsMagick JNX fuzzer",
        attributes={"project": "graphicsmagick", "target": "coder_JNX_fuzzer"},
        receipt_sha256="b" * 64,
    )
    matched_gm = [
        s.fsm_id for s in bundle.registry.matching_specs_for_entity(gm_entity)
    ]
    assert matched_gm == ["bug-hunter-graphicsmagick-search"]

    # Guard check: core_target_reconcile needs call_edge to core.runtime-target.*
    store = TaskMemoryStore(tmp_path / "memory.json", "arvo:10147")
    route = store.apply_route_decision(
        action="new",
        route_id=None,
        attempt=1,
        rationale="Bind official target",
        model="core",
        fsm_id=BUG_HUNTER_CORE_FSM_ID,
        initial_state_id="core_target_reconcile",
    )
    store.merge_ledger(
        [
            ProofLedgerEntry(
                key="core.runtime-target.jnx",
                section="target_contract",
                claim="Official target coder_JNX_fuzzer",
                status="runtime_observed",
                evidence=["probe"],
                route_id=route.route_id,
            )
        ]
    )
    core_spec = bundle.specs[BUG_HUNTER_CORE_FSM_ID]
    reconcile_edge = core_spec.outgoing_transitions("core_target_reconcile")[0]
    # Without call_edge -> False!
    assert (
        reconcile_edge.guard.evaluate_deterministic(
            store.load(),
            route.route_id,
            guard_registry=bundle.registry.guard_registry,
        )
        is False
    )
    # Add dependent call_edge -> True!
    store.merge_ledger(
        [
            ProofLedgerEntry(
                key="edge.entry",
                section="call_edge",
                claim="LLVMFuzzerTestOneInput -> ReadJNXImage",
                status="source_backed",
                depends_on=["core.runtime-target.jnx"],
                evidence=["jnx.c:412"],
                route_id=route.route_id,
            )
        ]
    )
    assert (
        reconcile_edge.guard.evaluate_deterministic(
            store.load(),
            route.route_id,
            guard_registry=bundle.registry.guard_registry,
        )
        is True
    )


@pytest.mark.asyncio
async def test_bug_hunter_core_fsm_end_to_end_pipeline_execution(
    tmp_path: Path,
) -> None:
    """Run bug-hunter-core FSM through Reconcile -> Research -> 2-Call Delivery."""

    bundle = load_bug_hunter_preset()

    class ScriptedBugHunterWorker:
        async def complete(
            self,
            *,
            messages: list[dict[str, Any]],
            output_schema: dict[str, Any],
            allow_tools: bool,
            max_output_tokens: int | None,
        ) -> ModelTurnResponse:
            sys_prompt = str(messages[0].get("content", ""))
            has_tool = any(m.get("role") == "tool" for m in messages)

            # Stage 1: core_target_reconcile (handoff-only)
            if "Core-owned action-reconciliation stage" in sys_prompt:
                if allow_tools and not has_tool:
                    return ModelTurnResponse(
                        model_id="bh-worker",
                        usage=ModelUsage(total_tokens=150),
                        tool_commands=("echo 'checked entrypoint'",),
                    )
                return ModelTurnResponse(
                    model_id="bh-worker",
                    usage=ModelUsage(total_tokens=150),
                    final_text=json.dumps(
                        {
                            "handoff": {
                                "summary": "Bound target entrypoint",
                                "next_step": "Trace sink and carrier construction",
                                "next_action": {
                                    "id": "act.trace",
                                    "kind": "inspect",
                                    "target": "ReadJNXImage",
                                    "expected_observation": "sink check",
                                },
                                "items": [
                                    {
                                        "id": "target.jnx",
                                        "kind": "contract",
                                        "status": "source_backed",
                                        "claim": "Bound coder_JNX_fuzzer contract",
                                        "evidence": ["fuzz.cc:18"],
                                    }
                                ],
                            }
                        }
                    ),
                )

            # Stage 2: static_source_research -> closes sink + carrier -> delivery!
            if "Research the authorized vulnerable source" in sys_prompt:
                if allow_tools and not has_tool:
                    return ModelTurnResponse(
                        model_id="bh-worker",
                        usage=ModelUsage(total_tokens=220),
                        tool_commands=("echo 'closed sink and carrier layout'",),
                    )
                return ModelTurnResponse(
                    model_id="bh-worker",
                    usage=ModelUsage(total_tokens=220),
                    final_text=json.dumps(
                        {
                            "handoff": {
                                "summary": "Closed JNX route & carrier layout",
                                "next_step": "Materialize /work/poc.bin",
                                "next_action": {
                                    "id": "act.mat",
                                    "kind": "materialize",
                                    "target": "/work/poc.bin",
                                    "expected_observation": "281-byte JNX carrier",
                                },
                                "action_receipt": {
                                    "action_id": "act.trace",
                                    "outcome": "completed",
                                    "observation": "Verified sink reachability",
                                    "changed_constraint": "Bound tile offset",
                                },
                                "items": [
                                    {
                                        "id": "target.jnx",
                                        "kind": "contract",
                                        "status": "source_backed",
                                        "claim": "Bound coder_JNX_fuzzer contract",
                                        "evidence": ["fuzz.cc:18"],
                                    },
                                    {
                                        "id": "sink.jnx",
                                        "kind": "sink",
                                        "status": "source_backed",
                                        "claim": "Tile read OOB sink",
                                        "depends_on": ["target.jnx"],
                                        "evidence": ["jnx.c:310"],
                                    },
                                    {
                                        "id": "carrier.jnx",
                                        "kind": "construction",
                                        "status": "artifact_encoded",
                                        "claim": "281-byte JNX header + tile record",
                                        "depends_on": ["sink.jnx"],
                                        "evidence": ["/work/seed.bin"],
                                    },
                                ],
                            }
                        }
                    ),
                )

            # Stage 3: final_artifact_delivery (2-call deadline, writes /work/poc.bin!)
            if allow_tools and not has_tool:
                return ModelTurnResponse(
                    model_id="bh-worker",
                    usage=ModelUsage(total_tokens=180),
                    tool_commands=("printf 'JNX_VERIFIED_POC' > poc.bin",),
                )
            return ModelTurnResponse(
                model_id="bh-worker",
                usage=ModelUsage(total_tokens=120),
                final_text=json.dumps(
                    {
                        "source": {"kind": "path", "artifact_path": "poc.bin"},
                        "rationale": "Materialized JNX carrier hitting OOB sink",
                        "causal_dimension": "construction_encoding",
                        "changed_constraint": "tile_offset -> OOB read",
                        "semantic_checkpoint": "ReadJNXImage:310",
                    }
                ),
            )

        async def aclose(self) -> None:
            return None

    class OfficialVulnerableEvaluator:
        async def evaluate_candidate(
            self,
            content: bytes,
            *,
            route: RouteSummary,
            is_replay: bool = False,
        ) -> ExecutionReceipt:
            assert content == b"JNX_VERIFIED_POC"
            return ExecutionReceipt.build(
                subject_sha256="9" * 64,
                output="ASAN heap-buffer-overflow at jnx.c:310",
                exit_code=77,
                observed_target="coder_JNX_fuzzer",
                phase="target_runtime",
                input_consumption="observed",
                fingerprint_sha256="8" * 64,
            )

    worker = ScriptedBugHunterWorker()
    orch = TeamOrchestrator(
        registry=bundle.registry,
        worker_runtime_factory=lambda wd: ManagedAgentRuntime(
            worker, sandbox=LocalDirectorySandbox(wd)
        ),
        evaluator=OfficialVulnerableEvaluator(),
        request_composer=BugHunterRequestComposer(
            bundle.handbook, project_name="graphicsmagick"
        ),
        skills=bundle.skills,
        concurrency=1,
    )

    res = await orch.run_task(
        task_id="arvo:10147",
        root_fsm_id=BUG_HUNTER_CORE_FSM_ID,
        task_dir=tmp_path / "bh-run",
        objective="Reproduce JNX tile bounds fault",
        mode="fast",
        max_generations=3,
    )

    assert res.status == "passed"
    assert res.final_artifact == b"JNX_VERIFIED_POC"
    visited_targets = [t["target_state"] for t in res.transition_log]
    assert "static_source_research" in visited_targets
    assert "final_artifact_delivery" in visited_targets


def test_bug_hunter_high_confidence_first_crash_and_seed_carrier_persistence(
    tmp_path: Path,
) -> None:
    """Verify high-confidence source proof & /work/seeds/current.bin persistence."""

    import base64

    from vouchloom import MemoryItem, NextAction, ResearchHandoff
    from vouchloom.team import _persist_handoff_work_carrier_sync

    store = TaskMemoryStore(tmp_path / "hc.json", "arvo:64945")
    route = store.apply_route_decision(
        action="new",
        route_id=None,
        attempt=1,
        rationale="Closed route",
        model="core",
    )
    store.merge_ledger(
        [
            ProofLedgerEntry(
                key="t",
                section="target_contract",
                claim="mruby_fuzzer",
                status="source_backed",
                evidence=["fuzz.c:1"],
                route_id=route.route_id,
            ),
            ProofLedgerEntry(
                key="e",
                section="call_edge",
                claim="mrb_str_format -> fmt_float",
                status="source_backed",
                depends_on=["t"],
                evidence=["fmt_fp.c:80"],
                route_id=route.route_id,
            ),
            ProofLedgerEntry(
                key="cond",
                section="condition",
                condition_role="required",
                claim="Subnormal float32 operand",
                status="source_backed",
                depends_on=["e"],
                evidence=["fmt_fp.c:140"],
                route_id=route.route_id,
            ),
            ProofLedgerEntry(
                key="s",
                section="sink",
                claim="Buffer overflow at mrb_format_float:200",
                status="source_backed",
                depends_on=["cond"],
                evidence=["fmt_fp.c:200"],
                route_id=route.route_id,
            ),
            ProofLedgerEntry(
                key="c",
                section="construction",
                carrier_construction=True,
                claim="160-byte Ruby format string",
                status="artifact_encoded",
                depends_on=["s"],
                evidence=["/work/poc.bin"],
                route_id=route.route_id,
            ),
        ]
    )
    art = ArtifactOutput(
        source=InlineArtifactSource(
            kind="inline",
            artifact_base64=base64.b64encode(b"A" * 16).decode("ascii"),
        ),
        rationale="Exact closed construction",
        claim_binding="mrb_format_float overflow",
        construction_receipt="f" * 64,
        deterministically_constructed=True,
        public_neutralization_receipt=PublicNeutralizationReceipt(
            operation="guard buf end before write",
            baseline_observation="exit 1 ASan overflow",
            neutralized_observation="exit 0 clean",
        ),
        causal_dimension="fault_precondition",
        changed_constraint="subnormal exponent -> overflow",
        semantic_checkpoint="mrb_format_float:200",
    )
    assert candidate_has_high_confidence_source_proof(store.load(), route.route_id, art)

    # Verify /work/poc.bin -> read-only 0o444 /work/seeds/current.bin persistence
    work = tmp_path / "work"
    work.mkdir()
    (work / "poc.bin").write_bytes(b"SEED_CARRIER_BYTES")
    handoff = ResearchHandoff(
        summary="Saved discovered fixture carrier",
        next_step="Execute against target",
        next_action=NextAction(
            id="act.exec",
            kind="execute",
            target="Run target on /work/poc.bin",
            expected_observation="checkpoint trace",
        ),
        items=[
            MemoryItem(
                id="obs.1",
                kind="observation",
                status="source_backed",
                claim="Fixture copied",
                evidence=["/work/poc.bin"],
            )
        ],
    )
    rewritten = _persist_handoff_work_carrier_sync(handoff, work)
    assert "/work/seeds/current.bin" in rewritten.next_action.target
    assert (work / "seeds" / "current.bin").read_bytes() == b"SEED_CARRIER_BYTES"
