"""Provider-independent conservative request-context budget gate.

Faithfully preserves bug_hunter's UTF-8 byte/3 preflight estimation so context
limits never depend on a local model-specific tokenizer.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RequestBudget:
    """Bound one complete model request, including its output reservation."""

    context_window_tokens: int
    max_output_tokens: int
    safety_margin_tokens: int = 4_096
    preferred_input_tokens: int | None = None

    def __post_init__(self) -> None:
        if self.context_window_tokens < 1:
            raise ValueError("context_window_tokens must be positive")
        if self.max_output_tokens < 1:
            raise ValueError("max_output_tokens must be positive")
        if self.safety_margin_tokens < 0:
            raise ValueError("safety_margin_tokens must not be negative")
        if self.window_input_tokens < 1:
            raise ValueError(
                "context window must exceed output reservation and safety margin"
            )
        if self.preferred_input_tokens is not None and self.preferred_input_tokens < 1:
            raise ValueError("preferred_input_tokens must be positive")

    @property
    def window_input_tokens(self) -> int:
        return (
            self.context_window_tokens
            - self.max_output_tokens
            - self.safety_margin_tokens
        )

    @property
    def max_input_tokens(self) -> int:
        if self.preferred_input_tokens is None:
            return self.window_input_tokens
        return min(self.window_input_tokens, self.preferred_input_tokens)

    def evaluate(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        json_mode: bool,
    ) -> dict[str, Any]:
        """Measure the exact model-visible request shape before transmission."""

        rendered = json.dumps(
            {
                "messages": messages,
                "tools": tools,
                "json_mode": json_mode,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        estimated = max(1, math.ceil(len(rendered) / 3))
        limit = self.max_input_tokens
        return {
            "estimator": "rendered_utf8_bytes_div_3",
            "rendered_input_bytes": len(rendered),
            "estimated_input_tokens": estimated,
            "context_window_tokens": self.context_window_tokens,
            "max_output_tokens": self.max_output_tokens,
            "safety_margin_tokens": self.safety_margin_tokens,
            "window_input_tokens": self.window_input_tokens,
            "preferred_input_tokens": self.preferred_input_tokens,
            "max_input_tokens": limit,
            "remaining_input_tokens": limit - estimated,
            "fits": estimated <= limit,
        }
