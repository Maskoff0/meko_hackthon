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

from .domain import AccountEvent, Investigation, EvidenceFinding, ShadowRecommendation


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
