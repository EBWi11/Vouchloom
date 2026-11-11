"""Isolated Text-Only Semantic Arbiters & K-of-N Consensus Gates.

Faithfully generalizes bug_hunter's small, zero-tool LLM arbiters:
- ArtifactAdmissionArbiter (fail-open: reopens research if prerequisite unbound)
- HandoffIdentityArbiter (fail-open: downgrades unanchored/counterfactual claims)
- MemorySemanticsArbiter (fail-closed: carrier_construction vs tooling_checkpoint)
- ArtifactCausalGateArbiter & 2-vote SafePathDiagnosticArbiter
- 2-vote SafePathRouteAuthorityArbiter (retires hopelessly safe routes)
- SemanticDuplicateArbiter
- BoundedActionReceiptRecoveryArbiter (salvages 1-command wall-timeout receipts).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import Field, model_validator

from vouchloom.agent import (
    AgentDefinition,
    AgentRuntimeError,
    MemoryItem,
    ResearchHandoff,
)
from vouchloom.models import ModelUsage, StrictModel, add_usage
from vouchloom.receipts import ActionReceipt, CommandReceipt, NextAction
from vouchloom.runtime import ManagedAgentRuntime

BOUNDED_RECOVERY_MAX_CMD_BYTES = 8_000
BOUNDED_RECOVERY_MAX_OUT_BYTES = 24_000


@dataclass
class ArbiterAudit:
    arbiter_id: str
    model_calls: int = 0
    usage: ModelUsage = field(default_factory=ModelUsage)
    receipts: list[dict[str, Any]] = field(default_factory=list)


class AdmissionDecisionOutput(StrictModel):
    decision: Literal["artifact_ready", "evidence_action_required"]
    reason: str = Field(min_length=1, max_length=400)


class HandoffIdentityOutput(StrictModel):
    classification: Literal[
        "preserve", "unanchored_alternate", "counterfactual_substitution"
    ]
    untrusted_item_ids: list[str] = Field(default_factory=list)
    reason: str = Field(min_length=1, max_length=400)

    @model_validator(mode="after")
    def validate_preserve_empty(self) -> HandoffIdentityOutput:
        if len(self.untrusted_item_ids) != len(set(self.untrusted_item_ids)):
            raise ValueError("untrusted_item_ids must be unique")
        if self.classification == "preserve" and self.untrusted_item_ids:
            raise ValueError("preserve must return an empty untrusted_item_ids list")
        return self


class MemorySemanticItemDecision(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    classification: Literal[
        "carrier_construction",
        "tooling_checkpoint",
        "durable_memory",
        "activity_log",
        "insufficient",
    ]
    blocking_gap_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_blockers(self) -> MemorySemanticItemDecision:
        if len(self.blocking_gap_ids) != len(set(self.blocking_gap_ids)):
            raise ValueError("blocking_gap_ids must be unique")
        return self


class MemorySemanticOutput(StrictModel):
    decisions: list[MemorySemanticItemDecision] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_ids(self) -> MemorySemanticOutput:
        ids = [d.id for d in self.decisions]
        if len(ids) != len(set(ids)):
            raise ValueError("memory semantic decision ids must be unique")
        return self


class CausalAlignmentOutput(StrictModel):
    required_qualifier: str = Field(min_length=1, max_length=300)
    qualifier_binding: Literal["bound", "absent", "not_applicable"]
    classification: Literal["admit_candidate", "explicit_no_fault_or_unproven"]
    reason: str = Field(min_length=1, max_length=400)

    @model_validator(mode="after")
    def absent_qualifier_cannot_admit(self) -> CausalAlignmentOutput:
        if (
            self.qualifier_binding == "absent"
            and self.classification == "admit_candidate"
        ):
            raise ValueError(
                "an absent required causal qualifier cannot admit a candidate"
            )
        return self


class SafePathDiagnosticOutput(StrictModel):
    decision: Literal["semantic_no_fault", "operational_or_unproven"]
    reason: str = Field(min_length=1, max_length=400)


class SafePathRouteAuthorityOutput(StrictModel):
    decision: Literal["keep_route", "retire_route"]
    evidence_attempts: list[int] = Field(default_factory=list)
    rationale: str = Field(min_length=1, max_length=400)


class SemanticRelationOutput(StrictModel):
    decision: Literal["distinct_experiment", "semantic_duplicate"]
    reason: str = Field(min_length=1, max_length=400)


class FinalCandidateSelectionOutput(StrictModel):
    attempt_number: int = Field(ge=1)
    rationale: str = Field(min_length=1, max_length=600)


class SemanticArbiterSuite:
    """Isolated text-only semantic arbiters with deterministic fallbacks."""

    def __init__(self, runtime: ManagedAgentRuntime | None) -> None:
        self._runtime = (
            ManagedAgentRuntime(
                runtime.model_backend,
                sandbox=None,
                enable_pure_json_repair=True,
            )
            if runtime is not None
            else None
        )

    async def _run_text_stage(
        self,
        *,
        arbiter_id: str,
        prompt: str,
        output_model: type[StrictModel],
        payload: dict[str, Any],
        max_total_tokens: int = 32_000,
    ) -> tuple[Any | None, ArbiterAudit]:
        if self._runtime is None:
            return None, ArbiterAudit(
                arbiter_id=arbiter_id,
                receipts=[{"status": f"{arbiter_id}_unconfigured"}],
            )
        definition = AgentDefinition(
            id=arbiter_id,
            version="0.1.0",
            system_prompt=prompt,
            output_model=output_model,
            max_total_tokens=max_total_tokens,
            max_output_tokens=2_048,
            allow_tools=False,
            max_turn_seconds=120,
        )
        try:
            trace = await self._runtime.run(
                definition,
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            )
            return trace.result, ArbiterAudit(
                arbiter_id=arbiter_id,
                model_calls=trace.model_calls,
                usage=trace.usage,
                receipts=list(trace.request_receipts),
            )
        except (AgentRuntimeError, ValueError) as error:
            return None, ArbiterAudit(
                arbiter_id=arbiter_id,
                receipts=[
                    {"status": f"{arbiter_id}_failed", "error": str(error)[:300]}
                ],
            )

    async def classify_delivery_admission(
        self, payload: dict[str, Any]
    ) -> tuple[bool, ArbiterAudit]:
        """Fail-open: returns True only when evidence_action_required is decided."""

        res, audit = await self._run_text_stage(
            arbiter_id="vouchloom-delivery-admission",
            prompt=(
                "Decide whether the active gap still leaves an upstream producer, "
                "consumer, or prerequisite trace unbound (evidence_action_required) "
                "or is ready for concrete delivery (artifact_ready)."
            ),
            output_model=AdmissionDecisionOutput,
            payload=payload,
        )
        if not isinstance(res, AdmissionDecisionOutput):
            audit.receipts.append({"status": "delivery_admission_fail_open"})
            return False, audit
        return res.decision == "evidence_action_required", audit

    async def reconcile_handoff_identity(
        self,
        handoff: ResearchHandoff,
        *,
        bound_target: str | None,
    ) -> tuple[ResearchHandoff, ArbiterAudit | None]:
        """Fail-open: downgrade unanchored claims & inject reconcile action."""

        if not bound_target:
            return handoff, None
        res, audit = await self._run_text_stage(
            arbiter_id="vouchloom-handoff-identity",
            prompt=(
                "Audit handoff items against bound_target. If items promote a "
                "sibling target or counterfactual local build as target proof, "
                "classify as unanchored_alternate or counterfactual_substitution "
                "and list their ids."
            ),
            output_model=HandoffIdentityOutput,
            payload={
                "bound_target": bound_target,
                "items": [item.model_dump(mode="json") for item in handoff.items],
            },
        )
        if (
            not isinstance(res, HandoffIdentityOutput)
            or res.classification == "preserve"
        ):
            return handoff, audit

        untrusted = {i for i in res.untrusted_item_ids if not i.startswith("core.")}
        updated_items = [
            (
                item.model_copy(update={"status": "hypothesis"})
                if item.id in untrusted
                and item.status
                in {"source_backed", "artifact_encoded", "runtime_observed"}
                else item
            )
            for item in handoff.items
        ]
        reconcile_hash = hashlib.sha256(
            f"{bound_target}:{res.classification}".encode()
        ).hexdigest()[:12]
        reconcile_action = NextAction(
            id=f"identity.reconcile.{reconcile_hash}",
            kind="inspect",
            target=bound_target,
            expected_observation=(
                f"Bind {bound_target} directly from authoritative evidence without "
                "sibling or counterfactual substitution."
            ),
        )
        return (
            handoff.model_copy(
                update={"items": updated_items, "next_action": reconcile_action}
            ),
            audit,
        )

    async def classify_memory_semantics(
        self, items: list[MemoryItem]
    ) -> tuple[set[str], set[str], dict[str, list[str]], ArbiterAudit | None]:
        """Fail-closed (from bug_hunter): classify construction & note items."""

        candidates = [x for x in items if x.kind in {"construction", "note"}]
        if not candidates:
            return set(), set(), {}, None
        candidate_ids = {x.id for x in candidates}
        open_gaps = [x for x in items if x.kind == "gap" and x.status == "hypothesis"]
        res, audit = await self._run_text_stage(
            arbiter_id="vouchloom-memory-semantics",
            prompt=(
                "Classify each construction item as carrier_construction, "
                "tooling_checkpoint, or insufficient; each note item as "
                "durable_memory, activity_log, or insufficient. Attach "
                "blocking_gap_ids only to carrier_construction items."
            ),
            output_model=MemorySemanticOutput,
            payload={
                "items": [
                    {
                        "id": x.id,
                        "declared_kind": x.kind,
                        "claim": x.claim,
                        "evidence": x.evidence,
                    }
                    for x in candidates
                ],
                "open_gaps": [
                    {"id": g.id, "claim": g.claim, "depends_on": g.depends_on}
                    for g in open_gaps
                ],
            },
        )
        if not isinstance(res, MemorySemanticOutput):
            audit.receipts.append({"status": "memory_semantics_failed_closed"})
            return set(), set(), {}, audit

        if {d.id for d in res.decisions} != candidate_ids:
            audit.receipts.append(
                {"status": "memory_semantics_id_mismatch_failed_closed"}
            )
            return set(), set(), {}, audit

        by_id = {x.id: x for x in candidates}
        gap_ids = {g.id for g in open_gaps}
        for d in res.decisions:
            kind = by_id[d.id].kind
            if kind == "construction" and d.classification not in {
                "carrier_construction",
                "tooling_checkpoint",
                "insufficient",
            }:
                return set(), set(), {}, audit
            if kind == "note" and d.classification not in {
                "durable_memory",
                "activity_log",
                "insufficient",
            }:
                return set(), set(), {}, audit
            if any(
                d.classification != "carrier_construction" or gid not in gap_ids
                for gid in d.blocking_gap_ids
            ):
                return set(), set(), {}, audit

        all_by_id = {x.id: x for x in items}

        def closure_of(node_id: str) -> set[str]:
            seen: set[str] = set()
            stack = [node_id]
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                if cur in all_by_id:
                    stack.extend(all_by_id[cur].depends_on)
            return seen

        carrier_ids = {
            d.id for d in res.decisions if d.classification == "carrier_construction"
        }
        durable_notes = {
            d.id for d in res.decisions if d.classification == "durable_memory"
        }
        blockers: dict[str, list[str]] = {}
        for d in res.decisions:
            accepted = [
                gid for gid in d.blocking_gap_ids if d.id not in closure_of(gid)
            ]
            if accepted:
                blockers[d.id] = accepted
        return carrier_ids, durable_notes, blockers, audit

    async def classify_safe_path_diagnostic_consensus(
        self, payload: dict[str, Any]
    ) -> tuple[bool, ArbiterAudit]:
        """2-vote unanimous consensus required to declare semantic_no_fault."""

        votes: list[str] = []
        total_usage = ModelUsage()
        calls = 0
        receipts: list[dict[str, Any]] = []
        for replica in (1, 2):
            res, audit = await self._run_text_stage(
                arbiter_id=f"vouchloom-safe-path-diag-{replica}",
                prompt=(
                    "Classify whether the rejected candidate represents a true "
                    "semantic_no_fault path (merely logical acceptance without a "
                    "real fault sink) or operational_or_unproven."
                ),
                output_model=SafePathDiagnosticOutput,
                payload=payload,
            )
            calls += audit.model_calls
            total_usage = add_usage(total_usage, audit.usage)
            receipts.extend(audit.receipts)
            if isinstance(res, SafePathDiagnosticOutput):
                votes.append(res.decision)
        return (
            votes == ["semantic_no_fault", "semantic_no_fault"],
            ArbiterAudit(
                arbiter_id="vouchloom-safe-path-diag",
                model_calls=calls,
                usage=total_usage,
                receipts=receipts,
            ),
        )

    async def classify_route_retirement_consensus(
        self, payload: dict[str, Any], *, valid_attempt_numbers: set[int]
    ) -> tuple[bool, str, ArbiterAudit]:
        """2-vote unanimous consensus citing >=2 valid attempts to retire route."""

        outputs: list[SafePathRouteAuthorityOutput] = []
        total_usage = ModelUsage()
        calls = 0
        receipts: list[dict[str, Any]] = []
        for replica in (1, 2):
            res, audit = await self._run_text_stage(
                arbiter_id=f"vouchloom-route-authority-{replica}",
                prompt=(
                    "Decide whether repeated safe/clean attempts prove this route "
                    "cannot satisfy the objective (retire_route, citing >=2 attempt "
                    "numbers) or keep_route."
                ),
                output_model=SafePathRouteAuthorityOutput,
                payload=payload,
            )
            calls += audit.model_calls
            total_usage = add_usage(total_usage, audit.usage)
            receipts.extend(audit.receipts)
            if isinstance(res, SafePathRouteAuthorityOutput):
                outputs.append(res)
        retire = len(outputs) == 2 and all(
            o.decision == "retire_route"
            and len(set(o.evidence_attempts)) >= 2
            and set(o.evidence_attempts).issubset(valid_attempt_numbers)
            for o in outputs
        )
        rationale = (
            " | ".join(o.rationale for o in outputs)
            if outputs
            else "route authority arbiter unavailable"
        )
        return (
            retire,
            rationale,
            ArbiterAudit(
                arbiter_id="vouchloom-route-authority",
                model_calls=calls,
                usage=total_usage,
                receipts=receipts,
            ),
        )

    async def recover_bounded_action_receipt(
        self,
        action: NextAction,
        error: AgentRuntimeError,
    ) -> tuple[ActionReceipt | None, ArbiterAudit | None]:
        """Salvage ActionReceipt on wall timeout after 1 untruncated command."""

        if error.code != "turn_wall_timeout" or len(error.command_receipts) != 1:
            return None, None
        cmd: CommandReceipt = error.command_receipts[0]
        if (
            cmd.command_truncated
            or cmd.output_truncated
            or cmd.command_utf8_bytes > BOUNDED_RECOVERY_MAX_CMD_BYTES
            or cmd.output_utf8_bytes > BOUNDED_RECOVERY_MAX_OUT_BYTES
        ):
            return None, None
        res, audit = await self._run_text_stage(
            arbiter_id="vouchloom-bounded-receipt-recovery",
            prompt=(
                "Summarize ONLY the supplied command execution receipt into one "
                "ActionReceipt with matching action_id. Do not invent unobserved facts."
            ),
            output_model=ActionReceipt,
            payload={
                "required_next_action": action.model_dump(mode="json"),
                "command_receipt": cmd.model_dump(mode="json"),
            },
        )
        if not isinstance(res, ActionReceipt) or res.action_id != action.id:
            return None, audit
        return (
            res.model_copy(update={"command_receipt_sha256": cmd.sha256}),
            audit,
        )

    async def classify_candidate_causal_alignment(
        self, payload: dict[str, Any]
    ) -> tuple[bool, ArbiterAudit | None]:
        """Audit pre-execution candidate alignment (True if explicit safe/no-fault).

        When no arbiter runtime is configured, returns (False, None) so offline
        or deterministic test runs proceed cleanly; when configured, fails closed
        to True on invalid/unavailable arbiter output, matching bug_hunter's
        _classify_artifact_fault_claim.
        """

        if self._runtime is None:
            return False, None
        res, audit = await self._run_text_stage(
            arbiter_id="vouchloom-artifact-causal-alignment",
            prompt=(
                "Name any required causal qualifier from the objective, classify "
                "its binding (bound | absent | not_applicable), and return "
                "explicit_no_fault_or_unproven when the candidate omits the "
                "required qualifier or explicitly states a safe/no-fault path."
            ),
            output_model=CausalAlignmentOutput,
            payload=payload,
        )
        if not isinstance(res, CausalAlignmentOutput):
            return True, audit
        return res.classification == "explicit_no_fault_or_unproven", audit

    async def classify_semantic_duplicate(
        self,
        previous: dict[str, Any],
        current: dict[str, Any],
    ) -> tuple[bool, ArbiterAudit | None]:
        """Detect repeated causal producer/constraint across two attempts."""

        if self._runtime is None:
            return False, None
        res, audit = await self._run_text_stage(
            arbiter_id="vouchloom-semantic-relation",
            prompt=(
                "Compare previous and current attempt metadata. Return "
                "semantic_duplicate only when both test the same causal "
                "producer, guard, and constraint with mere byte/layout variation."
            ),
            output_model=SemanticRelationOutput,
            payload={"previous": previous, "current": current},
        )
        return (
            isinstance(res, SemanticRelationOutput)
            and res.decision == "semantic_duplicate"
        ), audit

    async def select_final_candidate(
        self,
        candidates: list[dict[str, Any]],
        *,
        objective: str,
        budget_tokens: int = 128_000,
    ) -> tuple[int | None, str | None, ArbiterAudit | None]:
        """Isolated two-stage (primary + compact fallback) final candidate selector."""

        if self._runtime is None or len(candidates) < 2 or budget_tokens < 2_048:
            return None, None, None
        valid_numbers = {
            int(num)
            for c in candidates
            if isinstance((num := c.get("attempt_number") or c.get("attempt")), int)
        }
        fallback_reserve = min(32_000, max(1_024, budget_tokens // 4))
        primary_budget = max(1_024, budget_tokens - fallback_reserve)
        payload = {"objective": objective, "candidates": candidates[:2]}

        res, primary_audit = await self._run_text_stage(
            arbiter_id="vouchloom-final-selector-primary",
            prompt=(
                "Select the single final candidate from the two verified "
                "milestone candidates. Require causal binding to the stated "
                "objective and minimize extraneous preconditions before raw size."
            ),
            output_model=FinalCandidateSelectionOutput,
            payload=payload,
            max_total_tokens=primary_budget,
        )
        if (
            isinstance(res, FinalCandidateSelectionOutput)
            and res.attempt_number in valid_numbers
        ):
            return res.attempt_number, res.rationale, primary_audit

        fb_res, fb_audit = await self._run_text_stage(
            arbiter_id="vouchloom-final-selector-fallback",
            prompt="Return one valid attempt_number and concise rationale immediately.",
            output_model=FinalCandidateSelectionOutput,
            payload=payload,
            max_total_tokens=fallback_reserve,
        )
        merged_audit = ArbiterAudit(
            arbiter_id="vouchloom-final-selector",
            model_calls=primary_audit.model_calls + fb_audit.model_calls,
            usage=add_usage(primary_audit.usage, fb_audit.usage),
            receipts=[*primary_audit.receipts, *fb_audit.receipts],
        )
        if (
            isinstance(fb_res, FinalCandidateSelectionOutput)
            and fb_res.attempt_number in valid_numbers
        ):
            return fb_res.attempt_number, fb_res.rationale, merged_audit
        return None, None, merged_audit
