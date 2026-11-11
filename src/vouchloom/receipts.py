"""Cryptographic execution, command, action, and sideband-signal receipts.

Core rule inherited from bug_hunter: no state transition, blackboard fact, or
observer breakout signal is trusted without an integrity-bound receipt.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from vouchloom.models import StrictModel


def canonical_sha256(payload: dict[str, Any]) -> str:
    """Compute canonical deterministic SHA-256 over a JSON-serializable dict."""

    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def truncate_utf8_audited(value: str, max_bytes: int) -> dict[str, Any]:
    encoded = value.encode("utf-8", errors="replace")
    sha256 = hashlib.sha256(encoded).hexdigest()
    if len(encoded) <= max_bytes:
        return {
            "text": value,
            "utf8_bytes": len(encoded),
            "sha256": sha256,
            "truncated": False,
        }
    clipped = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return {
        "text": clipped,
        "utf8_bytes": len(encoded),
        "sha256": sha256,
        "truncated": True,
    }


def command_receipt_digest(
    *,
    tool_name: str,
    sequence: int,
    command_sha256: str,
    output_sha256: str,
    exit_code: int,
) -> str:
    return canonical_sha256(
        {
            "tool_name": tool_name,
            "sequence": sequence,
            "command_sha256": command_sha256,
            "output_sha256": output_sha256,
            "exit_code": exit_code,
        }
    )


class CommandReceipt(StrictModel):
    """Core-captured tool/shell execution receipt; Workers cannot forge this."""

    tool_name: str = Field(min_length=1, max_length=120)
    sequence: int = Field(ge=1)
    command: str
    command_utf8_bytes: int = Field(ge=0)
    command_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    command_truncated: bool = False
    output: str
    output_utf8_bytes: int = Field(ge=0)
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_truncated: bool = False
    exit_code: int
    duration_ms: int = Field(default=0, ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def verify_canonical_digest(self) -> Self:
        expected = command_receipt_digest(
            tool_name=self.tool_name,
            sequence=self.sequence,
            command_sha256=self.command_sha256,
            output_sha256=self.output_sha256,
            exit_code=self.exit_code,
        )
        if self.sha256 != expected:
            raise ValueError("command receipt digest is not canonical")
        return self

    @classmethod
    def from_execution(
        cls,
        *,
        tool_name: str,
        sequence: int,
        command: str,
        output: str,
        exit_code: int,
        duration_ms: int = 0,
        max_command_bytes: int = 8_000,
        max_output_bytes: int = 24_000,
    ) -> CommandReceipt:
        cmd_audit = truncate_utf8_audited(command, max_command_bytes)
        out_audit = truncate_utf8_audited(output, max_output_bytes)
        digest = command_receipt_digest(
            tool_name=tool_name,
            sequence=sequence,
            command_sha256=cmd_audit["sha256"],
            output_sha256=out_audit["sha256"],
            exit_code=exit_code,
        )
        return cls(
            tool_name=tool_name,
            sequence=sequence,
            command=cmd_audit["text"],
            command_utf8_bytes=cmd_audit["utf8_bytes"],
            command_sha256=cmd_audit["sha256"],
            command_truncated=cmd_audit["truncated"],
            output=out_audit["text"],
            output_utf8_bytes=out_audit["utf8_bytes"],
            output_sha256=out_audit["sha256"],
            output_truncated=out_audit["truncated"],
            exit_code=exit_code,
            duration_ms=duration_ms,
            sha256=digest,
        )


ExecutionPhase = Literal["unknown", "environment_startup", "target_runtime"]
InputConsumption = Literal["unknown", "not_observed", "observed"]


def execution_receipt_digest(
    *,
    subject_sha256: str,
    output_sha256: str,
    exit_code: int,
    observed_target: str | None,
    phase: ExecutionPhase,
    startup_failure: str | None,
    input_consumption: InputConsumption,
    fingerprint_sha256: str | None,
) -> str:
    return canonical_sha256(
        {
            "subject_sha256": subject_sha256,
            "output_sha256": output_sha256,
            "exit_code": exit_code,
            "observed_target": observed_target,
            "phase": phase,
            "startup_failure": startup_failure,
            "input_consumption": input_consumption,
            "fingerprint_sha256": fingerprint_sha256,
        }
    )


class ExecutionReceipt(StrictModel):
    """Integrity-bound target verification facts owned exclusively by Core."""

    subject_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exit_code: int
    observed_target: str | None = Field(
        default=None,
        max_length=500,
        pattern=r"^[A-Za-z0-9_.:/+-]+$",
    )
    phase: ExecutionPhase = "unknown"
    startup_failure: str | None = Field(default=None, max_length=120)
    input_consumption: InputConsumption = "unknown"
    fingerprint_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def verify_phase_and_digest(self) -> Self:
        if self.phase == "environment_startup":
            if self.startup_failure is None or self.input_consumption != "not_observed":
                raise ValueError(
                    "environment_startup receipts require startup_failure and "
                    "not_observed input_consumption"
                )
        elif self.startup_failure is not None:
            raise ValueError(
                "startup_failure is only valid for environment_startup receipts"
            )
        if self.phase == "target_runtime" and self.observed_target is None:
            raise ValueError("target_runtime receipts require an observed_target")
        expected = execution_receipt_digest(
            subject_sha256=self.subject_sha256,
            output_sha256=self.output_sha256,
            exit_code=self.exit_code,
            observed_target=self.observed_target,
            phase=self.phase,
            startup_failure=self.startup_failure,
            input_consumption=self.input_consumption,
            fingerprint_sha256=self.fingerprint_sha256,
        )
        if self.sha256 != expected:
            raise ValueError("execution receipt digest is not canonical")
        return self

    @classmethod
    def build(
        cls,
        *,
        subject_sha256: str,
        output: str,
        exit_code: int,
        observed_target: str | None = None,
        phase: ExecutionPhase = "unknown",
        startup_failure: str | None = None,
        input_consumption: InputConsumption = "unknown",
        fingerprint_sha256: str | None = None,
    ) -> ExecutionReceipt:
        output_sha256 = hashlib.sha256(output.encode("utf-8")).hexdigest()
        digest = execution_receipt_digest(
            subject_sha256=subject_sha256,
            output_sha256=output_sha256,
            exit_code=exit_code,
            observed_target=observed_target,
            phase=phase,
            startup_failure=startup_failure,
            input_consumption=input_consumption,
            fingerprint_sha256=fingerprint_sha256,
        )
        return cls(
            subject_sha256=subject_sha256,
            output_sha256=output_sha256,
            exit_code=exit_code,
            observed_target=observed_target,
            phase=phase,
            startup_failure=startup_failure,
            input_consumption=input_consumption,
            fingerprint_sha256=fingerprint_sha256,
            sha256=digest,
        )


ActionKind = Literal[
    "inspect",
    "instrument",
    "build",
    "mutate",
    "execute",
    "materialize",
    "probe",
]


class NextAction(StrictModel):
    """One bounded operation that the next fresh Worker must execute first."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    kind: ActionKind
    target: str = Field(min_length=1)
    expected_observation: str = Field(min_length=1)

    @field_validator("target", "expected_observation")
    @classmethod
    def normalize_action_text(cls, value: str) -> str:
        rendered = " ".join(value.split())
        if not rendered:
            raise ValueError("action text must be non-empty")
        return rendered

    @property
    def signature(self) -> tuple[str, str, str]:
        return (self.kind, self.target, self.expected_observation)


class ActionReceipt(StrictModel):
    """Typed evidence that a required NextAction was actually attempted."""

    action_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    outcome: Literal["completed", "refuted", "blocked"]
    observation: str = Field(min_length=1)
    changed_constraint: str = Field(min_length=1)
    command_receipt_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("observation", "changed_constraint")
    @classmethod
    def normalize_receipt_text(cls, value: str) -> str:
        rendered = " ".join(value.split())
        if not rendered:
            raise ValueError("action receipt text must be non-empty")
        return rendered


class SidebandSignal(StrictModel):
    """Unexpected out-of-state-machine observation reported to the Observer.

    Requires an explicit command_receipt_sha256 from the current Worker turn so
    speculative hallucinations can never trigger an Observer breakout.
    """

    signal_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    entity_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{0,119}$")
    category: Literal[
        "unexpected_surface",
        "novel_component",
        "cross_branch_clue",
        "protocol_anomaly",
        "state_deadlock",
    ]
    summary: str = Field(min_length=1, max_length=600)
    proposed_hypothesis: str = Field(min_length=1, max_length=600)
    command_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("summary", "proposed_hypothesis")
    @classmethod
    def normalize_signal_text(cls, value: str) -> str:
        rendered = " ".join(value.split())
        if not rendered:
            raise ValueError("sideband signal text must be non-empty")
        return rendered
