"""Append-only decision record interface.

Records events, task transitions, handoffs, input references, and results
in a local append-only development log. Meko traces are supplementary;
this is the authoritative audit record.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .domain import (
    AccountEvent,
    CaseBrief,
    CaseDraft,
    Investigation,
    EvidenceFinding,
    ShadowRecommendation,
    TriageQueueItem,
    AnalystFeedback,
)


class AuditLog:
    """Append-only audit log for fraud detection decisions."""

    def __init__(self, log_path: str | Path = "audit.log"):
        self.log_path = Path(log_path)
        self._entries: list[dict[str, Any]] = []

    def _write_entry(self, entry: dict[str, Any]) -> None:
        entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        self._entries.append(entry)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def record_event(self, event: AccountEvent) -> None:
        """Record an incoming event."""
        self._write_entry({
            "type": "event",
            "event_id": event.event_id,
            "account_id": event.account_id,
            "event_type": event.event_type,
            "source": event.source,
            "schema_version": event.schema_version,
            "idempotency_key": event.idempotency_key,
            "provenance": event.provenance,
        })

    def record_ingestion_result(
        self,
        event_id: str,
        result: str,
        error: str | None = None,
    ) -> None:
        """Record an ingestion result (accepted/duplicate/rejected)."""
        entry: dict[str, Any] = {
            "type": "ingestion_result",
            "event_id": event_id,
            "result": result,
        }
        if error:
            entry["error"] = error
        self._write_entry(entry)

    def record_investigation_created(self, investigation: Investigation) -> None:
        """Record investigation creation."""
        self._write_entry({
            "type": "investigation_created",
            "investigation_id": investigation.investigation_id,
            "account_id": investigation.account_id,
            "trigger_event_id": investigation.trigger_event_id,
            "trigger_type": investigation.trigger_type,
            "hypothesis": investigation.hypothesis,
            "policy_version": investigation.policy_version,
            "status": investigation.status,
        })

    def record_finding(self, finding: EvidenceFinding) -> None:
        """Record an agent finding."""
        self._write_entry({
            "type": "finding",
            "finding_id": finding.finding_id,
            "investigation_id": finding.investigation_id,
            "agent_id": finding.agent_id,
            "conclusion": finding.conclusion,
            "confidence": finding.confidence,
            "reason_codes": finding.reason_codes,
            "evidence_refs": finding.evidence_refs,
            "source": finding.source,
            "status": finding.status,
        })

    def record_recommendation(
        self,
        account_id: str,
        recommendation: ShadowRecommendation,
    ) -> None:
        """Record a shadow recommendation."""
        self._write_entry({
            "type": "recommendation",
            "account_id": account_id,
            "recommendation": recommendation.recommendation,
            "reason_codes": recommendation.reason_codes,
            "baseline_result": recommendation.baseline_result,
            "uncertainty": recommendation.uncertainty,
            "abstention": recommendation.abstention,
            "policy_version": recommendation.policy_version,
            "model_version": recommendation.model_version,
            "prompt_version": recommendation.prompt_version,
            "evidence_provenance": recommendation.evidence_provenance,
        })

    def record_investigation_transition(
        self,
        investigation: Investigation,
        new_status: str,
        actor: str | None = None,
    ) -> None:
        """Record an investigation state transition."""
        self._write_entry({
            "type": "investigation_transition",
            "investigation_id": investigation.investigation_id,
            "account_id": investigation.account_id,
            "from_status": investigation.status,
            "to_status": new_status,
            "actor": actor,
        })

    def record_containment_proposal(
        self,
        account_id: str,
        action_type: str,
        target: str,
        reason_codes: list[str],
        evidence_refs: list[str],
        reversibility: str,
    ) -> None:
        """Record a containment proposal (shadow mode: proposal only, no execution)."""
        self._write_entry({
            "type": "containment_proposal",
            "account_id": account_id,
            "action_type": action_type,
            "target": target,
            "reason_codes": reason_codes,
            "evidence_refs": evidence_refs,
            "reversibility": reversibility,
            "executed": False,
            "shadow_mode": True,
        })

    def record_containment_review(
        self,
        account_id: str,
        action_type: str,
        target: str,
        review_decision: str,
        analyst_id: str,
        analyst_reason: str,
        evidence_refs: list[str],
        evidence_snapshot: dict[str, Any],
        review_id: str,
    ) -> None:
        """Record a human analyst's review decision on a containment proposal."""
        self._write_entry({
            "type": "containment_review",
            "review_id": review_id,
            "account_id": account_id,
            "action_type": action_type,
            "target": target,
            "review_decision": review_decision,
            "analyst_id": analyst_id,
            "analyst_reason": analyst_reason,
            "evidence_refs": evidence_refs,
            "evidence_snapshot": evidence_snapshot,
            "executed": False,
        })

    def record_containment_execution(
        self,
        account_id: str,
        action_type: str,
        target: str,
        executed: bool,
        analyst_id: str,
        reason_codes: list[str],
        evidence_refs: list[str],
        review_id: str,
        execution_reason: str,
        executed_at: str | None = None,
    ) -> None:
        """Record the execution result of an analyst-approved containment proposal."""
        self._write_entry({
            "type": "containment_execution",
            "review_id": review_id,
            "account_id": account_id,
            "action_type": action_type,
            "target": target,
            "executed": executed,
            "analyst_id": analyst_id,
            "reason_codes": reason_codes,
            "evidence_refs": evidence_refs,
            "execution_reason": execution_reason,
            "executed_at": executed_at,
        })

    def record_phase2_gate_result(
        self,
        account_id: str,
        investigation_id: str,
        detection_metrics: dict[str, Any],
        baseline_metrics: dict[str, Any],
        latency_metrics: dict[str, Any],
        gate_result: dict[str, Any],
    ) -> None:
        """Record Phase 2 gate evaluation results (baseline comparison + go/no-go)."""
        self._write_entry({
            "type": "phase2_gate_result",
            "account_id": account_id,
            "investigation_id": investigation_id,
            "detection_metrics": detection_metrics,
            "baseline_metrics": baseline_metrics,
            "latency_metrics": latency_metrics,
            "gate_result": gate_result,
        })

    def record_case_brief(
        self,
        brief: CaseBrief,
    ) -> None:
        """Record a case brief generation (function.md: logging with analyst ID)."""
        self._write_entry({
            "type": "case_brief",
            "brief_id": brief.brief_id,
            "account_id": brief.account_id,
            "investigation_id": brief.investigation_id,
            "analyst_id": brief.analyst_id,
            "generated_at": brief.generated_at.isoformat(),
            "timeline_entries": len(brief.timeline),
            "signals": len(brief.signals),
            "prior_incidents": len(brief.prior_incidents),
            "citations": brief.citations,
        })

    def record_case_draft(
        self,
        draft: CaseDraft,
        action: str,
    ) -> None:
        """Record a case draft creation/edit/sign (function.md: logging with analyst ID)."""
        self._write_entry({
            "type": "case_draft",
            "draft_id": draft.draft_id,
            "account_id": draft.account_id,
            "investigation_id": draft.investigation_id,
            "analyst_id": draft.analyst_id,
            "draft_type": draft.draft_type,
            "status": draft.status,
            "action": action,
            "edit_count": draft.edit_count,
            "citations": draft.citations,
        })

    def record_triage_view(
        self,
        queue_item: TriageQueueItem,
        analyst_id: str,
    ) -> None:
        """Record an analyst viewing a triage queue item."""
        self._write_entry({
            "type": "triage_view",
            "investigation_id": queue_item.investigation_id,
            "account_id": queue_item.account_id,
            "analyst_id": analyst_id,
            "rank": queue_item.rank,
            "score": queue_item.score,
            "recommendation": queue_item.recommendation,
        })

    def record_analyst_feedback(
        self,
        feedback: AnalystFeedback,
    ) -> None:
        """Record analyst feedback capture (function.md: Capability 6)."""
        self._write_entry({
            "type": "analyst_feedback",
            "feedback_id": feedback.feedback_id,
            "account_id": feedback.account_id,
            "investigation_id": feedback.investigation_id,
            "analyst_id": feedback.analyst_id,
            "original_recommendation": feedback.original_recommendation,
            "analyst_response": feedback.analyst_response,
            "label": feedback.label,
            "label_reason": feedback.label_reason,
        })
