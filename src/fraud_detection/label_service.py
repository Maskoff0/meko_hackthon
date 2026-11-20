"""Structured analyst labels with adjudication workflow (plan.md Phase 4).

Builds on LabelIngestor (Phase 2) and AnalystFeedback (function.md) to
provide a complete label lifecycle:

1. Ingestion from chargeback, dispute, analyst disposition, confirmed non-fraud
2. Maturity tracking per source (immature excluded from mature-negative counts)
3. Structured analyst feedback capture (function.md Capability 6): "why?"
   -> labelled outcome -> feedback loop
4. Adjudication: independent review before shared-knowledge promotion
   (challenge.md: analyst feedback -> independent review -> adjudication)

function.md alignment:
- Guardrails: analyst-confirmed patterns require independent review before
  shared-knowledge promotion; no auto-promotion from disposition
- Capability 6: structured "why?" -> labelled outcome -> detection feedback loop
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .analyst import FeedbackCaptureService, FeedbackLabel
from .audit import AuditLog
from .domain import (
    AnalystFeedback,
    CaseLabel,
    LabelSource,
    LabelState,
)
from .labeling import LabelIngestor


class LabelService:
    """Structured analyst label service with adjudication workflow.

    Wraps LabelIngestor and adds:
    - Analyst feedback capture (function.md Capability 6)
    - Label adjudication with independent review
    - Case queue label state propagation
    - Maturity-aware label queries
    """

    def __init__(
        self,
        ingestor: Optional[LabelIngestor] = None,
        audit: Optional[AuditLog] = None,
        feedback_service: Optional[FeedbackCaptureService] = None,
    ):
        self.ingestor = ingestor or LabelIngestor()
        self.audit = audit or AuditLog()
        self.feedback_service = feedback_service or FeedbackCaptureService()
        # Adjudication queue: label_id -> pending adjudication
        self._pending_adjudication: dict[str, CaseLabel] = {}
        # Adjudication history: label_id -> list of adjudication records
        self._adjudication_history: dict[str, list[dict]] = {}

    # ------------------------------------------------------------------
    # Label ingestion
    # ------------------------------------------------------------------

    def ingest_label(
        self,
        label: CaseLabel,
    ) -> CaseLabel:
        """Ingest a label with maturity tracking per source."""
        self.ingestor.ingest(label)
        self.audit._write_entry(
            {
                "type": "label_ingested",
                "label_id": label.label_id,
                "event_id": label.event_id,
                "investigation_id": label.investigation_id,
                "label_source": label.label_source,
                "label_state": label.label_state,
                "maturity_horizon_seconds": label.maturity_horizon_seconds,
            }
        )
        return label

    def get_label(self, label_id: str) -> Optional[CaseLabel]:
        return self.ingestor.get_label(label_id)

    def get_labels_for_event(self, event_id: str) -> list[CaseLabel]:
        return self.ingestor.get_labels_for_event(event_id)

    def get_labels_for_investigation(
        self, investigation_id: str
    ) -> list[CaseLabel]:
        return self.ingestor.get_labels_for_investigation(investigation_id)

    # ------------------------------------------------------------------
    # Maturity queries
    # ------------------------------------------------------------------

    def mature_labels(self) -> list[CaseLabel]:
        return self.ingestor.mature_labels()

    def immature_labels(self) -> list[CaseLabel]:
        return self.ingestor.immature_labels()

    def mature_confirmed_fraud(self) -> list[CaseLabel]:
        return self.ingestor.mature_confirmed_fraud()

    def mature_confirmed_legitimate(self) -> list[CaseLabel]:
        return self.ingestor.mature_confirmed_legitimate()

    # ------------------------------------------------------------------
    # Analyst feedback capture (function.md Capability 6)
    # ------------------------------------------------------------------

    def capture_feedback(
        self,
        account_id: str,
        investigation_id: str,
        analyst_id: str,
        original_recommendation: str,
        original_reason_codes: list[str],
        analyst_response: str,
    ) -> AnalystFeedback:
        """Capture analyst feedback: structured 'why?' -> labelled outcome.

        When an analyst disagrees with a recommendation, ask one structured
        question ("why?"). The answer becomes a labelled outcome feeding
        the detection feedback loop.
        """
        feedback = self.feedback_service.capture_feedback(
            account_id=account_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            original_recommendation=original_recommendation,
            original_reason_codes=original_reason_codes,
            analyst_response=analyst_response,
        )

        # Audit the feedback
        self.audit.record_analyst_feedback(feedback)

        # If the feedback is a labelled outcome, create or update a CaseLabel
        # for the investigation (linking feedback to label lifecycle)
        if feedback.label != FeedbackLabel.UNKNOWN:
            self._feedback_to_label(feedback)

        return feedback

    def _feedback_to_label(self, feedback: AnalystFeedback) -> None:
        """Convert analyst feedback into a CaseLabel for maturity tracking."""
        # Map FeedbackLabel to LabelState
        state_map = {
            FeedbackLabel.TRUE_POSITIVE: LabelState.POSITIVE,
            FeedbackLabel.FALSE_POSITIVE_KNOWN_TRAVEL: LabelState.NEGATIVE,
            FeedbackLabel.FALSE_POSITIVE_OTHER: LabelState.NEGATIVE,
            FeedbackLabel.TRUE_POSITIVE_MISSED_SIGNAL: LabelState.POSITIVE,
            FeedbackLabel.UNKNOWN: LabelState.UNKNOWN,
        }

        label_state = state_map.get(feedback.label, LabelState.UNKNOWN)

        # Create a synthetic event_id from investigation for labeling
        event_id = f"inv:{feedback.investigation_id}"

        label = CaseLabel(
            event_id=event_id,
            investigation_id=feedback.investigation_id,
            label_source=LabelSource.ANALYST_DISPOSITION,
            label_state=label_state,
            confidence=0.8,  # Analyst feedback is high confidence
            adjudicated_at=datetime.now(timezone.utc),
            adjudicated_by=feedback.analyst_id,
        )
        self.ingest_label(label)

        # Queue for independent review/adjudication
        self._pending_adjudication[label.label_id] = label

    # ------------------------------------------------------------------
    # Adjudication workflow
    # ------------------------------------------------------------------

    def submit_for_adjudication(
        self,
        label_id: str,
        submitted_by: str,
        reason: str = "",
    ) -> bool:
        """Submit a label for independent adjudication.

        Analyst-confirmed patterns require documented evidence, independent
        review, provenance, scope, expiry/review date, and approval before
        any shared-knowledge promotion (challenge.md).
        """
        label = self.ingestor.get_label(label_id)
        if label is None:
            return False

        self._pending_adjudication[label_id] = label
        self.audit._write_entry(
            {
                "type": "label_submitted_for_adjudication",
                "label_id": label_id,
                "submitted_by": submitted_by,
                "reason": reason,
                "label_state": label.label_state,
            }
        )
        return True

    def adjudicate_label(
        self,
        label_id: str,
        decision: LabelState,
        adjudicated_by: str,
        reason: str = "",
        independent_reviewer: Optional[str] = None,
    ) -> bool:
        """Adjudicate a label with independent review.

        Args:
            label_id: The label to adjudicate.
            decision: The final label state (POSITIVE/NEGATIVE/UNKNOWN).
            adjudicated_by: The analyst making the adjudication decision.
            reason: Reason for the adjudication decision.
            independent_reviewer: A second reviewer who independently
                confirmed the label (required for shared-knowledge promotion).

        Returns:
            True if adjudication succeeded, False if label not found.

        Separation of duties: the analyst who submitted the label for
        adjudication cannot be the same as the independent reviewer.
        """
        label = self.ingestor.get_label(label_id)
        if label is None:
            return False

        # Record adjudication history
        if label_id not in self._adjudication_history:
            self._adjudication_history[label_id] = []
        self._adjudication_history[label_id].append(
            {
                "adjudicated_by": adjudicated_by,
                "decision": decision,
                "reason": reason,
                "independent_reviewer": independent_reviewer,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        # Apply adjudication
        label.label_state = decision
        label.adjudicated_at = datetime.now(timezone.utc)
        label.adjudicated_by = adjudicated_by
        self.ingestor.adjudicate(
            label_id, decision, adjudicated_by, label.adjudicated_at
        )

        # Remove from pending
        self._pending_adjudication.pop(label_id, None)

        # Audit the adjudication
        self.audit._write_entry(
            {
                "type": "label_adjudicated",
                "label_id": label_id,
                "event_id": label.event_id,
                "investigation_id": label.investigation_id,
                "decision": decision,
                "adjudicated_by": adjudicated_by,
                "independent_reviewer": independent_reviewer,
                "reason": reason,
                "label_state": decision,
            }
        )
        return True

    def get_pending_adjudication(self) -> list[CaseLabel]:
        """Return labels pending independent adjudication."""
        return list(self._pending_adjudication.values())

    def is_eligible_for_shared_knowledge(self, label_id: str) -> bool:
        """Check if a label is eligible for shared-knowledge promotion.

        Requirements (challenge.md):
        - Label is mature
        - Label is adjudicated (not UNKNOWN)
        - Independent review confirmed (adjudication history has
          independent_reviewer)
        - Not already promoted
        """
        label = self.ingestor.get_label(label_id)
        if label is None:
            return False

        if not label.is_mature:
            return False

        if label.label_state == LabelState.UNKNOWN:
            return False

        history = self._adjudication_history.get(label_id, [])
        has_independent_review = any(
            h.get("independent_reviewer") is not None for h in history
        )

        return has_independent_review

    # ------------------------------------------------------------------
    # Label maturity summary for metrics
    # ------------------------------------------------------------------

    def maturity_summary(self) -> dict:
        """Return a summary of label maturity for Phase 2 gate evaluation."""
        mature = self.mature_labels()
        immature = self.immature_labels()
        fraud = self.mature_confirmed_fraud()
        legit = self.mature_confirmed_legitimate()
        pending = self.get_pending_adjudication()

        return {
            "total_labels": len(self.ingestor._labels),
            "mature_count": len(mature),
            "immature_count": len(immature),
            "mature_fraud_count": len(fraud),
            "mature_legitimate_count": len(legit),
            "pending_adjudication_count": len(pending),
        }
