"""Core strict data models, causal dimensions, and budget envelopes."""

from __future__ import annotations

import math
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Base model forbidding any undeclared fields across all Vouchloom contracts."""

    model_config = ConfigDict(extra="forbid")


class ModelUsage(StrictModel):
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    cache_hit_tokens: int = Field(default=0, ge=0)
    cache_miss_tokens: int = Field(default=0, ge=0)


def add_usage(left: ModelUsage, right: ModelUsage) -> ModelUsage:
    return ModelUsage(
        prompt_tokens=left.prompt_tokens + right.prompt_tokens,
        completion_tokens=left.completion_tokens + right.completion_tokens,
        total_tokens=left.total_tokens + right.total_tokens,
        cache_hit_tokens=left.cache_hit_tokens + right.cache_hit_tokens,
        cache_miss_tokens=left.cache_miss_tokens + right.cache_miss_tokens,
    )


CausalDimension = Literal[
    "input_boundary",
    "parser_phase",
    "fault_precondition",
    "fault_observability",
    "allocation_geometry",
    "precondition_gate",
    "observability",
    "state_geometry",
    "framing_integrity",
    "lifecycle_order",
    "construction_encoding",
    "evidence_arbitration",
    "tool_completion",
    "unclassified",
]

CAUSAL_DIMENSIONS: tuple[CausalDimension, ...] = (
    "input_boundary",
    "parser_phase",
    "fault_precondition",
    "fault_observability",
    "allocation_geometry",
    "framing_integrity",
    "lifecycle_order",
    "construction_encoding",
    "evidence_arbitration",
    "tool_completion",
    "unclassified",
)

ROTATABLE_CAUSAL_DIMENSIONS: tuple[CausalDimension, ...] = (
    "parser_phase",
    "allocation_geometry",
    "framing_integrity",
    "lifecycle_order",
)

BlockCategory = Literal[
    "artifact_deadline_missed",
    "artifact_path_invalid",
    "artifact_size_invalid",
    "carrier_prefix_mismatch",
    "runtime_unavailable",
    "context_budget_exceeded",
    "duplicate_candidate",
    "final_artifact_handoff",
    "fresh_thread_reserve_exhausted",
    "generation_failed",
    "model_transport_failed",
    "model_unconfigured",
    "no_metered_progress",
    "required_action_unreceipted",
    "required_action_unreceipted_terminal",
    "route_contradicted",
    "safe_path",
    "schema_invalid",
    "token_budget_exhausted",
    "turn_wall_timeout",
]

RunMode = Literal["fast", "fast-competition", "competition", "standard", "thorough"]

MODE_BUDGET_RATIOS: dict[RunMode, tuple[int, int]] = {
    "fast": (2, 5),
    "fast-competition": (1, 1),
    "competition": (7, 5),
    "standard": (1, 1),
    "thorough": (7, 5),
}


class TaskBudgetEnvelope(StrictModel):
    """Token accounting envelope preserving bug_hunter's stage & recovery reserves."""

    total_token_limit: int = Field(ge=1)
    initial_total_token_limit: int | None = Field(default=None, ge=1)
    recovery_extension_token_limit: int = Field(default=0, ge=0)
    recovery_review_model_calls_used: int = Field(default=0, ge=0)
    recovery_review_total_tokens_used: int = Field(default=0, ge=0)
    observer_model_calls_used: int = Field(default=0, ge=0)
    observer_total_tokens_used: int = Field(default=0, ge=0)
    model_calls_used: int = Field(default=0, ge=0)
    total_tokens_used: int = Field(default=0, ge=0)
    first_milestone_model_calls_used: int | None = Field(default=None, ge=0)
    first_milestone_total_tokens_used: int | None = Field(default=None, ge=0)
    verification_window_token_limit: int | None = Field(default=None, ge=0)
    verification_window_model_calls_used: int = Field(default=0, ge=0)
    verification_window_total_tokens_used: int = Field(default=0, ge=0)
    final_selection_model_calls_used: int = Field(default=0, ge=0)
    final_selection_total_tokens_used: int = Field(default=0, ge=0)

    def charge(
        self,
        usage: ModelUsage,
        *,
        model_calls: int = 1,
        role: Literal["worker", "reviewer", "observer", "selector"] = "worker",
    ) -> None:
        self.model_calls_used += model_calls
        self.total_tokens_used += usage.total_tokens
        if role == "reviewer":
            self.recovery_review_model_calls_used += model_calls
            self.recovery_review_total_tokens_used += usage.total_tokens
        elif role == "observer":
            self.observer_model_calls_used += model_calls
            self.observer_total_tokens_used += usage.total_tokens
        elif role == "selector":
            self.final_selection_model_calls_used += model_calls
            self.final_selection_total_tokens_used += usage.total_tokens
        self.refresh_verification_usage()

    def refresh_verification_usage(self) -> None:
        if self.first_milestone_model_calls_used is None:
            return
        self.verification_window_model_calls_used = max(
            0,
            self.model_calls_used
            - self.first_milestone_model_calls_used
            - self.final_selection_model_calls_used,
        )
        self.verification_window_total_tokens_used = max(
            0,
            self.total_tokens_used
            - (self.first_milestone_total_tokens_used or 0)
            - self.final_selection_total_tokens_used,
        )

    def start_verification_window(
        self,
        *,
        multiplier: float = 1.2,
        selector_reserve: int = 1_000_000,
        stage_limit: int = 1_200_000,
        min_probe_reserve: int = 64_000,
    ) -> None:
        """Freeze the 1.2x post-milestone identity verification budget exactly once."""

        if self.first_milestone_model_calls_used is not None:
            return
        self.first_milestone_model_calls_used = self.model_calls_used
        self.first_milestone_total_tokens_used = self.total_tokens_used
        available = max(0, self.total_token_limit - self.total_tokens_used)
        remaining = max(
            max(0, available - selector_reserve),
            min(stage_limit, max(0, available - min(selector_reserve, 256_000))),
        )
        scaled = math.ceil(max(1, self.total_tokens_used) * multiplier)
        self.verification_window_token_limit = min(
            remaining,
            max(scaled, min(min_probe_reserve, remaining)),
        )
        self.refresh_verification_usage()

    @property
    def remaining_tokens(self) -> int:
        task_remaining = max(0, self.total_token_limit - self.total_tokens_used)
        if self.first_milestone_model_calls_used is None:
            return task_remaining
        self.refresh_verification_usage()
        window_remaining = max(
            0,
            (self.verification_window_token_limit or 0)
            - self.verification_window_total_tokens_used,
        )
        return min(task_remaining, window_remaining)

    @property
    def verification_window_exhausted(self) -> bool:
        if self.first_milestone_model_calls_used is None:
            return False
        self.refresh_verification_usage()
        return self.verification_window_total_tokens_used >= (
            self.verification_window_token_limit or 0
        )

    def allocate_review_extension(
        self,
        *,
        review_index: int,
        stage_reserve: int = 1_200_000,
        overrun_reserve: int = 64_000,
        min_stage_tokens: int = 128_000,
    ) -> int | None:
        """Compute reviewer token budget under a +60% extension (<=1/3 to reviewer)."""

        original = self.initial_total_token_limit or self.total_token_limit
        extension = original * 3 // 5
        extended_limit = original + extension * (review_index + 1)
        remaining_after_extend = max(0, extended_limit - self.total_tokens_used)
        reviewer_capacity = max(
            0, remaining_after_extend - stage_reserve - overrun_reserve
        )
        reviewer_limit = min(extension // 3, reviewer_capacity)
        if reviewer_limit < min_stage_tokens:
            return None
        self.total_token_limit = extended_limit
        self.recovery_extension_token_limit = extension * (review_index + 1)
        return reviewer_limit
