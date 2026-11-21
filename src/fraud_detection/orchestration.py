"""Deterministic supervisor: investigation state machine, triggers, budgets.

Owns investigation state transitions, trigger deduplication, task assignment,
permissions, deadlines, budgets, timeouts, retries, escalation, and terminal
state. Can halt any investigation. Human reviewers can pause, resume, or
reassign with an audit record.

Phase 3 extension: investigations are persisted to durable storage via
``Storage`` so state survives process restarts. On construction, the
orchestrator can recover open investigations from storage.
"""
from __future__ import annotations

import json
import uuid
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
from .storage import Storage


@dataclass
class InvestigationContext:
    """Runtime context for an active investigation."""

    investigation: Investigation
    baseline_result: Optional[BaselineResult] = None
    findings: list[EvidenceFinding] = field(default_factory=list)
    tool_calls_used: int = 0
    meko_retrievals_used: int = 0
    meko_retrieval_content_tokens_used: int = 0
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
        default_meko_content_token_budget: int = 500,
        default_deadline_seconds: int = 60,
        storage: Optional[Storage] = None,
    ):
        self.baseline = baseline_evaluator or BaselineEvaluator()
        self.default_tool_budget = default_tool_budget
        self.default_meko_budget = default_meko_budget
        self.default_token_budget = default_token_budget
        self.default_meko_content_token_budget = default_meko_content_token_budget
        self.default_deadline_seconds = default_deadline_seconds
        self.storage = storage
        self._investigations: dict[str, InvestigationContext] = {}

    def recover(self) -> int:
        """Recover open investigations from durable storage.

        Returns the number of investigations recovered. Investigations
        in terminal states (closed, escalated) are not recovered into
        active memory but remain in storage.
        """
        if self.storage is None:
            return 0
        rows = self.storage.get_open_investigations()
        count = 0
        for row in rows:
            inv = Investigation(
                investigation_id=row["investigation_id"],
                account_id=row["account_id"],
                trigger_event_id=row["trigger_event_id"],
                trigger_type=row["trigger_type"],
                hypothesis=row["hypothesis"],
                status=InvestigationStatus(row["status"]),
                policy_version=row["policy_version"],
                allowed_tools=json_loads(row["allowed_tools"]),
                evidence_scopes=json_loads(row["evidence_scopes"]),
                tool_call_budget=row["tool_call_budget"],
                meko_retrieval_budget=row["meko_retrieval_budget"],
                meko_retrieval_content_token_budget=row["meko_retrieval_content_token_budget"],
                token_budget=row["token_budget"],
                wall_clock_deadline_seconds=row["wall_clock_deadline_seconds"],
                created_at=parse_iso(row["created_at"]),
                updated_at=parse_iso(row["updated_at"]),
                error=row["error"],
                findings=[],  # findings reloaded separately below
            )
            # Reload findings for this investigation
            finding_rows = self.storage.get_findings_for_investigation(inv.investigation_id)
            # Findings are stored but we don't reconstruct EvidenceFinding objects
            # here; they are available via storage for audit/replay purposes.
            ctx = InvestigationContext(
                investigation=inv,
                started_at=inv.created_at,
            )
            self._investigations[inv.investigation_id] = ctx
            count += 1
        return count

    def create_investigation(
        self,
        event: AccountEvent,
        trigger_type: str,
        hypothesis: str,
    ) -> Investigation:
        """Create a bounded investigation task and persist it."""
        investigation = Investigation(
            account_id=event.account_id,
            trigger_event_id=event.event_id,
            trigger_type=trigger_type,
            hypothesis=hypothesis,
            allowed_tools=["meko_context_search", "meko_memory_add"],
            evidence_scopes=["account_signals", "knowledge_base"],
            tool_call_budget=self.default_tool_budget,
            meko_retrieval_budget=self.default_meko_budget,
            meko_retrieval_content_token_budget=self.default_meko_content_token_budget,
            token_budget=self.default_token_budget,
            wall_clock_deadline_seconds=self.default_deadline_seconds,
            trace_id=str(uuid.uuid4()),
        )
        ctx = InvestigationContext(
            investigation=investigation,
            started_at=datetime.now(timezone.utc),
        )
        self._investigations[investigation.investigation_id] = ctx
        if self.storage is not None:
            self.storage.insert_investigation(investigation)
        return investigation

    def get_investigation(self, investigation_id: str) -> Optional[InvestigationContext]:
        # Fall back to storage if not in memory
        ctx = self._investigations.get(investigation_id)
        if ctx is not None:
            return ctx
        if self.storage is not None:
            row = self.storage.get_investigation(investigation_id)
            if row is not None:
                inv = Investigation(
                    investigation_id=row["investigation_id"],
                    account_id=row["account_id"],
                    trigger_event_id=row["trigger_event_id"],
                    trigger_type=row["trigger_type"],
                    hypothesis=row["hypothesis"],
                    status=InvestigationStatus(row["status"]),
                    policy_version=row["policy_version"],
                    allowed_tools=json_loads(row["allowed_tools"]),
                    evidence_scopes=json_loads(row["evidence_scopes"]),
                    tool_call_budget=row["tool_call_budget"],
                    meko_retrieval_budget=row["meko_retrieval_budget"],
                    meko_retrieval_content_token_budget=row["meko_retrieval_content_token_budget"],
                    token_budget=row["token_budget"],
                    wall_clock_deadline_seconds=row["wall_clock_deadline_seconds"],
                    created_at=parse_iso(row["created_at"]),
                    updated_at=parse_iso(row["updated_at"]),
                    error=row["error"],
                    trace_id=row["trace_id"],
                    findings=[],
                )
                ctx = InvestigationContext(investigation=inv, started_at=inv.created_at)
                self._investigations[investigation_id] = ctx
                return ctx
        return None

    def add_finding(
        self,
        investigation_id: str,
        finding: EvidenceFinding,
    ) -> bool:
        """Add a typed finding to the investigation record and persist it."""
        ctx = self._investigations.get(investigation_id)
        if ctx is None or ctx.halted:
            return False
        ctx.findings.append(finding)
        ctx.investigation.findings.append(finding.finding_id)
        ctx.investigation.status = InvestigationStatus.ASSESSING
        ctx.investigation.updated_at = datetime.now(timezone.utc)
        if self.storage is not None:
            self.storage.insert_finding(finding)
            self.storage.insert_investigation(ctx.investigation)
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
        if ctx.meko_retrieval_content_tokens_used >= inv.meko_retrieval_content_token_budget:
            return False, "meko_retrieval_content_token_budget_exhausted"
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
            if self.storage is not None:
                self.storage.insert_investigation(ctx.investigation)
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
            if self.storage is not None:
                self.storage.insert_investigation(ctx.investigation)
        return ok

    def record_meko_retrieval_content_tokens(
        self, investigation_id: str, count: int
    ) -> bool:
        """Record Meko retrieval content token usage against the budget.

        Tracks the token size of retrieved memory content separately from
        the call-count budget to prevent LLM context bloat from broad
        memory searches. Per Meko docs, retrieving all memories or running
        broad searches can add substantial content to LLM context.
        """
        ctx = self._investigations.get(investigation_id)
        if ctx is None or ctx.halted:
            return False
        ctx.meko_retrieval_content_tokens_used += count
        ok, reason = self.check_budget(investigation_id)
        if not ok:
            ctx.halted = True
            ctx.investigation.status = InvestigationStatus.CLOSED
            ctx.investigation.error = reason
            if self.storage is not None:
                self.storage.insert_investigation(ctx.investigation)
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
            if self.storage is not None:
                self.storage.insert_investigation(ctx.investigation)
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
        if self.storage is not None:
            self.storage.insert_investigation(ctx.investigation)
        return True

    def close(self, investigation_id: str) -> bool:
        """Close an investigation normally."""
        ctx = self._investigations.get(investigation_id)
        if ctx is None:
            return False
        ctx.investigation.status = InvestigationStatus.CLOSED
        ctx.investigation.updated_at = datetime.now(timezone.utc)
        if self.storage is not None:
            self.storage.insert_investigation(ctx.investigation)
        return True

    def escalate(self, investigation_id: str) -> bool:
        """Escalate an investigation to human review."""
        ctx = self._investigations.get(investigation_id)
        if ctx is None:
            return False
        ctx.investigation.status = InvestigationStatus.ESCALATED
        ctx.investigation.updated_at = datetime.now(timezone.utc)
        if self.storage is not None:
            self.storage.insert_investigation(ctx.investigation)
        return True

    def evaluate_baseline(self, event: AccountEvent) -> BaselineResult:
        """Run the deterministic baseline against an event."""
        return self.baseline.evaluate(event)


def json_loads(value: str | None) -> list:
    """Safely parse a JSON list from storage."""
    if not value:
        return []
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []


def parse_iso(value: str | None) -> Optional[datetime]:
    """Parse an ISO-8601 datetime string."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
