"""Case queue with evidence timeline (plan.md Phase 4).

Builds and manages the analyst case queue from investigation records,
agent findings, recommendations, and audit log entries. Each queue item
contains the evidence timeline (chronological events with citations),
reason codes, model/rule versions, label state, assignment, and
escalation info.

function.md alignment:
- Capability 5 (triage ordering): queue summarization with "why ranked high"
- Guardrails: cited claims, untrusted text marked as data, logging with
  analyst ID
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from .audit import AuditLog
from .domain import (
    AccessControlEntry,
    AccessDecision,
    AssignmentAction,
    CaseAssignment,
    CaseQueueItem,
    CaseQueueStatus,
    LabelState,
    Role,
)
from .storage import Storage


class CaseQueue:
    """Analyst case queue with evidence timeline and assignment/escalation.

    Consumes investigation records, agent findings, shadow recommendations,
    and audit log entries to build queue items that analysts can view,
    assign, reassign, escalate, and close.
    """

    def __init__(self, storage: Storage, audit: AuditLog):
        self.storage = storage
        self.audit = audit
        self._queue: dict[str, CaseQueueItem] = {}
        self._assignments: list[CaseAssignment] = []

    # ------------------------------------------------------------------
    # Build queue items from storage
    # ------------------------------------------------------------------

    def build_queue_item(
        self,
        investigation: dict,
        findings: list[dict],
        recommendation: Optional[dict] = None,
        events: Optional[list[dict]] = None,
        rank: int = 0,
        score: float = 0.0,
    ) -> CaseQueueItem:
        """Build a CaseQueueItem from investigation + findings + evidence.

        Args:
            investigation: Investigation record dict from storage.
            findings: Agent findings for the investigation.
            recommendation: Shadow recommendation dict (optional).
            events: Account events for the evidence timeline (optional).
            rank: Queue rank (deterministic, set by triage service).
            score: Deterministic risk score.

        Returns:
            A CaseQueueItem with evidence timeline, reason codes, and
            model/rule versions.
        """
        inv_id = investigation["investigation_id"]
        account_id = investigation["account_id"]

        # Build evidence timeline from events + findings
        timeline = self._build_evidence_timeline(events or [], findings)

        # Collect reason codes from findings + recommendation
        reason_codes: list[str] = []
        for f in findings:
            reason_codes.extend(f.get("reason_codes", []))
        if recommendation:
            reason_codes.extend(recommendation.get("reason_codes", []))
        reason_codes = list(dict.fromkeys(reason_codes))  # dedupe, preserve order

        # Agent findings summary
        agent_findings = [
            {
                "agent_id": f.get("agent_id", "unknown"),
                "conclusion": f.get("conclusion", ""),
                "confidence": f.get("confidence", 0.0),
                "evidence_refs": f.get("evidence_refs", []),
            }
            for f in findings
        ]

        # Label state from investigation or default
        label_state = LabelState.UNKNOWN
        label_confidence = 0.5

        queue_item = CaseQueueItem(
            investigation_id=inv_id,
            account_id=account_id,
            status=CaseQueueStatus.QUEUED,
            rank=rank,
            score=round(score, 3),
            reason_codes=reason_codes,
            agent_findings=agent_findings,
            recommendation=recommendation.get("recommendation", "review")
            if recommendation
            else "review",
            uncertainty=recommendation.get("uncertainty", "medium")
            if recommendation
            else "medium",
            trigger_type=investigation.get("trigger_type", "unknown"),
            evidence_timeline=timeline,
            policy_version=investigation.get("policy_version", "2026-11-v1"),
            model_version=recommendation.get("model_version", "deterministic-baseline-v1")
            if recommendation
            else "deterministic-baseline-v1",
            label_state=label_state,
            label_confidence=label_confidence,
        )
        self._queue[inv_id] = queue_item
        return queue_item

    def _build_evidence_timeline(
        self, events: list[dict], findings: list[dict]
    ) -> list[dict]:
        """Build a chronological evidence timeline with citations.

        Merges events and findings into a single timeline ordered by
        timestamp. Each entry includes the event/finding ID as a
        citation so analysts can click through to verify.
        """
        timeline_entries: list[dict] = []

        for event in events:
            timeline_entries.append(
                {
                    "timestamp": event.get("timestamp", ""),
                    "type": "event",
                    "event_type": event.get("event_type", ""),
                    "source": event.get("source", ""),
                    "description": (
                        f"{event.get('event_type', '')} event from "
                        f"{event.get('source', '')}"
                    ),
                    "event_id": event.get("event_id", ""),
                    "citation": event.get("event_id", ""),
                    "provenance": event.get("provenance", "synthetic"),
                }
            )

        for finding in findings:
            timeline_entries.append(
                {
                    "timestamp": finding.get("created_at", ""),
                    "type": "finding",
                    "agent_id": finding.get("agent_id", ""),
                    "conclusion": finding.get("conclusion", ""),
                    "confidence": finding.get("confidence", 0.0),
                    "reason_codes": finding.get("reason_codes", []),
                    "evidence_refs": finding.get("evidence_refs", []),
                    "finding_id": finding.get("finding_id", ""),
                    "citation": finding.get("finding_id", ""),
                }
            )

        # Sort by timestamp
        timeline_entries.sort(key=lambda e: e.get("timestamp", ""))
        return timeline_entries

    # ------------------------------------------------------------------
    # Queue operations
    # ------------------------------------------------------------------

    def get_queue_item(self, investigation_id: str) -> Optional[CaseQueueItem]:
        return self._queue.get(investigation_id)

    def list_queue(
        self,
        status: Optional[CaseQueueStatus] = None,
        assigned_to: Optional[str] = None,
    ) -> list[CaseQueueItem]:
        """List queue items, optionally filtered by status or assignee."""
        items = list(self._queue.values())
        if status is not None:
            items = [i for i in items if i.status == status]
        if assigned_to is not None:
            items = [i for i in items if i.assigned_to == assigned_to]
        items.sort(key=lambda i: i.rank)
        return items

    def get_unassigned(self) -> list[CaseQueueItem]:
        """Return queue items with no assignee (available for pickup)."""
        return [
            i
            for i in self._queue.values()
            if i.assigned_to is None
            and i.status in (CaseQueueStatus.QUEUED, CaseQueueStatus.ASSIGNED)
        ]

    # ------------------------------------------------------------------
    # Assignment / reassignment / escalation
    # ------------------------------------------------------------------

    def assign(
        self,
        investigation_id: str,
        to_analyst: str,
        assigned_by: str,
        reason: str = "",
    ) -> CaseAssignment:
        """Assign a queue item to an analyst."""
        item = self._queue.get(investigation_id)
        if item is None:
            raise ValueError(f"Queue item not found: {investigation_id}")

        assignment = CaseAssignment(
            investigation_id=investigation_id,
            queue_item_id=item.queue_item_id,
            action=AssignmentAction.ASSIGN,
            from_analyst=item.assigned_to,
            to_analyst=to_analyst,
            assigned_by=assigned_by,
            reason=reason,
        )
        item.assigned_to = to_analyst
        item.assigned_at = datetime.now(timezone.utc)
        item.assigned_by = assigned_by
        item.status = CaseQueueStatus.ASSIGNED
        item.updated_at = datetime.now(timezone.utc)
        self._assignments.append(assignment)

        # Audit the assignment
        self.audit._write_entry(
            {
                "type": "case_assignment",
                "assignment_id": assignment.assignment_id,
                "investigation_id": investigation_id,
                "queue_item_id": item.queue_item_id,
                "action": assignment.action,
                "from_analyst": assignment.from_analyst,
                "to_analyst": assignment.to_analyst,
                "assigned_by": assignment.assigned_by,
                "reason": assignment.reason,
            }
        )
        return assignment

    def reassign(
        self,
        investigation_id: str,
        to_analyst: str,
        assigned_by: str,
        reason: str = "",
    ) -> CaseAssignment:
        """Reassign a queue item to a different analyst."""
        item = self._queue.get(investigation_id)
        if item is None:
            raise ValueError(f"Queue item not found: {investigation_id}")

        assignment = CaseAssignment(
            investigation_id=investigation_id,
            queue_item_id=item.queue_item_id,
            action=AssignmentAction.REASSIGN,
            from_analyst=item.assigned_to,
            to_analyst=to_analyst,
            assigned_by=assigned_by,
            reason=reason,
        )
        item.assigned_to = to_analyst
        item.assigned_at = datetime.now(timezone.utc)
        item.assigned_by = assigned_by
        item.status = CaseQueueStatus.ASSIGNED
        item.updated_at = datetime.now(timezone.utc)
        self._assignments.append(assignment)

        self.audit._write_entry(
            {
                "type": "case_reassignment",
                "assignment_id": assignment.assignment_id,
                "investigation_id": investigation_id,
                "queue_item_id": item.queue_item_id,
                "action": assignment.action,
                "from_analyst": assignment.from_analyst,
                "to_analyst": assignment.to_analyst,
                "assigned_by": assignment.assigned_by,
                "reason": assignment.reason,
            }
        )
        return assignment

    def escalate(
        self,
        investigation_id: str,
        to_analyst: str,
        assigned_by: str,
        reason: str = "",
    ) -> CaseAssignment:
        """Escalate a queue item to a senior analyst/supervisor."""
        item = self._queue.get(investigation_id)
        if item is None:
            raise ValueError(f"Queue item not found: {investigation_id}")

        assignment = CaseAssignment(
            investigation_id=investigation_id,
            queue_item_id=item.queue_item_id,
            action=AssignmentAction.ESCALATE,
            from_analyst=item.assigned_to,
            to_analyst=to_analyst,
            assigned_by=assigned_by,
            reason=reason,
        )
        item.assigned_to = to_analyst
        item.assigned_at = datetime.now(timezone.utc)
        item.assigned_by = assigned_by
        item.status = CaseQueueStatus.ESCALATED
        item.escalated = True
        item.escalated_to = to_analyst
        item.escalated_at = datetime.now(timezone.utc)
        item.escalation_reason = reason
        item.updated_at = datetime.now(timezone.utc)
        self._assignments.append(assignment)

        self.audit._write_entry(
            {
                "type": "case_escalation",
                "assignment_id": assignment.assignment_id,
                "investigation_id": investigation_id,
                "queue_item_id": item.queue_item_id,
                "action": assignment.action,
                "from_analyst": assignment.from_analyst,
                "to_analyst": assignment.to_analyst,
                "assigned_by": assignment.assigned_by,
                "reason": assignment.reason,
            }
        )
        return assignment

    def close(
        self, investigation_id: str, closed_by: str, reason: str = ""
    ) -> None:
        """Close a queue item."""
        item = self._queue.get(investigation_id)
        if item is None:
            raise ValueError(f"Queue item not found: {investigation_id}")
        item.status = CaseQueueStatus.CLOSED
        item.updated_at = datetime.now(timezone.utc)

        self.audit._write_entry(
            {
                "type": "case_closed",
                "investigation_id": investigation_id,
                "queue_item_id": item.queue_item_id,
                "closed_by": closed_by,
                "reason": reason,
            }
        )

    def start_review(self, investigation_id: str, analyst_id: str) -> None:
        """Mark a queue item as in_review by an analyst."""
        item = self._queue.get(investigation_id)
        if item is None:
            raise ValueError(f"Queue item not found: {investigation_id}")
        item.status = CaseQueueStatus.IN_REVIEW
        item.updated_at = datetime.now(timezone.utc)

        self.audit._write_entry(
            {
                "type": "case_review_started",
                "investigation_id": investigation_id,
                "queue_item_id": item.queue_item_id,
                "analyst_id": analyst_id,
            }
        )

    def resolve(
        self,
        investigation_id: str,
        resolved_by: str,
        resolution: str = "",
        label_state: Optional[LabelState] = None,
    ) -> None:
        """Resolve a queue item."""
        item = self._queue.get(investigation_id)
        if item is None:
            raise ValueError(f"Queue item not found: {investigation_id}")
        item.status = CaseQueueStatus.RESOLVED
        item.updated_at = datetime.now(timezone.utc)
        if label_state is not None:
            item.label_state = label_state

        self.audit._write_entry(
            {
                "type": "case_resolved",
                "investigation_id": investigation_id,
                "queue_item_id": item.queue_item_id,
                "resolved_by": resolved_by,
                "resolution": resolution,
                "label_state": label_state.value if label_state else None,
            }
        )

    # ------------------------------------------------------------------
    # Label state updates (from analyst feedback)
    # ------------------------------------------------------------------

    def update_label_state(
        self,
        investigation_id: str,
        label_state: LabelState,
        confidence: float = 0.5,
        updated_by: str = "system",
    ) -> None:
        """Update the label state on a queue item (from analyst feedback)."""
        item = self._queue.get(investigation_id)
        if item is None:
            raise ValueError(f"Queue item not found: {investigation_id}")
        item.label_state = label_state
        item.label_confidence = confidence
        item.updated_at = datetime.now(timezone.utc)

        self.audit._write_entry(
            {
                "type": "case_label_updated",
                "investigation_id": investigation_id,
                "queue_item_id": item.queue_item_id,
                "label_state": label_state,
                "confidence": confidence,
                "updated_by": updated_by,
            }
        )

    def get_assignments_for_investigation(
        self, investigation_id: str
    ) -> list[CaseAssignment]:
        return [a for a in self._assignments if a.investigation_id == investigation_id]
