"""Deterministic supervisor: investigation state machine, triggers, budgets.

Owns investigation state transitions, trigger deduplication, task assignment,
permissions, deadlines, budgets, timeouts, retries, escalation, and terminal
state. Can halt any investigation. Human reviewers can pause, resume, or
reassign with an audit record.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .domain import (
    AccountEvent,
    EvidenceFinding,
    FindingStatus,
    Investigation,
    InvestigationStatus,
)
from .baseline import BaselineEvaluator, BaselineResult


@dataclass
class InvestigationContext:
    """Runtime context for an active investigation."""

    investigation: Investigation
    baseline_result: Optional[BaselineResult] = None
    findings: list[EvidenceFinding] = field(default_factory=list)
    tool_calls_used: int = 0
    meko_retrievals_used: int = 0
    tokens_used: int = 0
    started_at: Optional[datetime] = None
    halted: bool = False


class Orchestrator:
    """Deterministic supervisor for investigation lifecycle."""

    def __init__(
        self,
        baseline_evaluator: Optional[BaselineEvaluator] = None,
        default_tool_budget: int = 10,
        default_meko_budget: int = 5,
        default_token_budget: int = 4000,
        default_deadline_seconds: int = 60,
    ):
        self.baseline = baseline_evaluator or BaselineEvaluator()
        self.default_tool_budget = default_tool_budget
        self.default_meko_budget = default_meko_budget
        self.default_token_budget = default_token_budget
        self.default_deadline_seconds = default_deadline_seconds
        self._investigations: dict[str, InvestigationContext] = {}

    def create_investigation(
        self,
        event: AccountEvent,
        trigger_type: str,
        hypothesis: str,
    ) -> Investigation:
        """Create a bounded investigation task."""
        investigation = Investigation(
            account_id=event.account_id,
            trigger_event_id=event.event_id,
            trigger_type=trigger_type,
            hypothesis=hypothesis,
            allowed_tools=["meko_context_search", "meko_memory_add"],
            evidence_scopes=["account_signals", "knowledge_base"],
            tool_call_budget=self.default_tool_budget,
            meko_retrieval_budget=self.default_meko_budget,
            token_budget=self.default_token_budget,
            wall_clock_deadline_seconds=self.default_deadline_seconds,
        )
        ctx = InvestigationContext(
            investigation=investigation,
            started_at=datetime.now(timezone.utc),
        )
        self._investigations[investigation.investigation_id] = ctx
        return investigation

    def get_investigation(self, investigation_id: str) -> Optional[InvestigationContext]:
        return self._investigations.get(investigation_id)

    def add_finding(
        self,
        investigation_id: str,
        finding: EvidenceFinding,
    ) -> bool:
        """Add a typed finding to the investigation record."""
        ctx = self._investigations.get(investigation_id)
        if ctx is None or ctx.halted:
            return False
        ctx.findings.append(finding)
        ctx.investigation.findings.append(finding.finding_id)
        ctx.investigation.status = InvestigationStatus.ASSESSING
        ctx.investigation.updated_at = datetime.now(timezone.utc)
        return True

    def check_budget(self, investigation_id: str) -> tuple[bool, Optional[str]]:
        """Check if the investigation has exhausted any budget.

        Returns (ok, reason). If not ok, the investigation should halt.
        """
        ctx = self._investigations.get(investigation_id)
        if ctx is None:
            return False, "investigation not found"

        inv = ctx.investigation
        if ctx.tool_calls_used >= inv.tool_call_budget:
            return False, "tool_call_budget_exhausted"
        if ctx.meko_retrievals_used >= inv.meko_retrieval_budget:
            return False, "meko_retrieval_budget_exhausted"
        if ctx.tokens_used >= inv.token_budget:
            return False, "token_budget_exhausted"

        now = datetime.now(timezone.utc)
        if ctx.started_at:
            elapsed = (now - ctx.started_at).total_seconds()
            if elapsed >= inv.wall_clock_deadline_seconds:
                return False, "wall_clock_deadline_exceeded"

        return True, None

    def record_tool_call(self, investigation_id: str) -> bool:
        """Record a tool call against the investigation budget."""
        ctx = self._investigations.get(investigation_id)
        if ctx is None or ctx.halted:
            return False
        ctx.tool_calls_used += 1
        ok, reason = self.check_budget(investigation_id)
        if not ok:
            ctx.halted = True
            ctx.investigation.status = InvestigationStatus.CLOSED
            ctx.investigation.error = reason
        return ok

    def record_meko_retrieval(self, investigation_id: str) -> bool:
        """Record a Meko retrieval against the investigation budget."""
        ctx = self._investigations.get(investigation_id)
        if ctx is None or ctx.halted:
            return False
        ctx.meko_retrievals_used += 1
        ok, reason = self.check_budget(investigation_id)
        if not ok:
            ctx.halted = True
            ctx.investigation.status = InvestigationStatus.CLOSED
            ctx.investigation.error = reason
        return ok

    def record_tokens(self, investigation_id: str, count: int) -> bool:
        """Record token usage against the investigation budget."""
        ctx = self._investigations.get(investigation_id)
        if ctx is None or ctx.halted:
            return False
        ctx.tokens_used += count
        ok, reason = self.check_budget(investigation_id)
        if not ok:
            ctx.halted = True
            ctx.investigation.status = InvestigationStatus.CLOSED
            ctx.investigation.error = reason
        return ok

    def halt(self, investigation_id: str, reason: str) -> bool:
        """Halt an investigation with a reason."""
        ctx = self._investigations.get(investigation_id)
        if ctx is None:
            return False
        ctx.halted = True
        ctx.investigation.status = InvestigationStatus.CLOSED
        ctx.investigation.error = reason
        ctx.investigation.updated_at = datetime.now(timezone.utc)
        return True

    def close(self, investigation_id: str) -> bool:
        """Close an investigation normally."""
        ctx = self._investigations.get(investigation_id)
        if ctx is None:
            return False
        ctx.investigation.status = InvestigationStatus.CLOSED
        ctx.investigation.updated_at = datetime.now(timezone.utc)
        return True

    def escalate(self, investigation_id: str) -> bool:
        """Escalate an investigation to human review."""
        ctx = self._investigations.get(investigation_id)
        if ctx is None:
            return False
        ctx.investigation.status = InvestigationStatus.ESCALATED
        ctx.investigation.updated_at = datetime.now(timezone.utc)
        return True

    def evaluate_baseline(self, event: AccountEvent) -> BaselineResult:
        """Run the deterministic baseline against an event."""
        return self.baseline.evaluate(event)
