"""Tests for Layer 0 receipts, RequestBudget, and hash-linked audit chains."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from vouchloom import (
    CommandReceipt,
    ExecutionReceipt,
    ModelUsage,
    RequestBudget,
    SidebandSignal,
    TaskBudgetEnvelope,
    redact_sensitive,
    verify_debug_chain,
    write_debug_event,
    write_task_audit_bundle,
)


def test_command_and_execution_receipt_invariants() -> None:
    cmd = CommandReceipt.from_execution(
        tool_name="sandbox_shell",
        sequence=1,
        command="echo hello",
        output="hello\n",
        exit_code=0,
        duration_ms=12,
    )
    assert len(cmd.sha256) == 64
    with pytest.raises(ValueError, match="canonical"):
        cmd.model_copy(update={"sha256": "0" * 64}).verify_canonical_digest()

    # environment_startup requires startup_failure and not_observed input_consumption
    with pytest.raises(ValueError, match="environment_startup"):
        ExecutionReceipt.build(
            subject_sha256="a" * 64,
            output="startup error",
            exit_code=77,
            phase="environment_startup",
            startup_failure=None,
            input_consumption="not_observed",
        )

    startup_rec = ExecutionReceipt.build(
        subject_sha256="a" * 64,
        output="MSan ASLR personality error",
        exit_code=77,
        phase="environment_startup",
        startup_failure="msan_personality_aslr",
        input_consumption="not_observed",
    )
    assert startup_rec.phase == "environment_startup"

    # target_runtime requires observed_target
    with pytest.raises(ValueError, match="observed_target"):
        ExecutionReceipt.build(
            subject_sha256="b" * 64,
            output="ok",
            exit_code=0,
            phase="target_runtime",
            observed_target=None,
        )

    sig = SidebandSignal(
        signal_id="sig.graphql",
        entity_id="host.01",
        category="unexpected_surface",
        summary="Found exposed /graphql introspection header",
        proposed_hypothesis="Query __schema on /graphql",
        command_receipt_sha256=cmd.sha256,
    )
    assert sig.command_receipt_sha256 == cmd.sha256


def test_request_budget_and_task_envelope() -> None:
    rb = RequestBudget(
        context_window_tokens=10_000,
        max_output_tokens=2_000,
        safety_margin_tokens=1_000,
    )
    assert rb.window_input_tokens == 7_000
    ok_eval = rb.evaluate(
        messages=[{"role": "user", "content": "hello"}],
        tools=[],
        json_mode=True,
    )
    assert ok_eval["fits"] is True

    huge_eval = rb.evaluate(
        messages=[{"role": "user", "content": "x" * 30_000}],
        tools=[],
        json_mode=True,
    )
    assert huge_eval["fits"] is False

    env = TaskBudgetEnvelope(
        total_token_limit=1_000_000,
        initial_total_token_limit=1_000_000,
    )
    env.charge(ModelUsage(total_tokens=200_000), model_calls=2)
    env.start_verification_window(
        multiplier=1.2, selector_reserve=100_000, stage_limit=300_000
    )
    assert env.verification_window_token_limit == 240_000
    assert env.remaining_tokens == 240_000


def test_redacted_hash_linked_debug_chain_and_audit_zip(tmp_path: Path) -> None:
    debug_dir = tmp_path / "debug"
    write_debug_event(
        debug_dir,
        stage="worker-1",
        event="started",
        payload={"api_key": "sk-secret", "reasoning_content": "hidden", "ok": 1},
    )
    second_path = write_debug_event(
        debug_dir,
        stage="worker-1",
        event="completed",
        payload={"raw_blob": b"\x01\x02\x03"},
    )
    assert second_path is not None

    first_json = json.loads((debug_dir / "0001-worker-1-started.json").read_text())
    assert first_json["payload"]["api_key"] == "[redacted]"
    assert first_json["payload"]["reasoning_content"] == "[redacted]"
    assert redact_sensitive({"password": "p"})["password"] == "[redacted]"

    chain = verify_debug_chain(debug_dir)
    assert chain["record_count"] == 2
    assert chain["head_record_sha256"] != chain["tail_record_sha256"]

    zip_path = write_task_audit_bundle(
        tmp_path,
        task_id="task:001",
        outcome_label="passed",
        state_payload={"status": "passed"},
        artifacts={"final.bin": b"ABC"},
    )
    sidecar = Path(f"{zip_path}.sha256").read_text(encoding="ascii")
    expected_sha = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    assert sidecar.startswith(expected_sha)
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = set(zf.namelist())
        assert "manifest.json" in names
        assert "integrity.json" in names
        assert "artifacts/final.bin" in names

    # Tamper with record 2 and verify chain fails closed
    tampered = json.loads(second_path.read_text())
    tampered["payload"]["tampered"] = True
    second_path.write_text(json.dumps(tampered))
    with pytest.raises(ValueError, match="digest mismatch"):
        verify_debug_chain(debug_dir)
