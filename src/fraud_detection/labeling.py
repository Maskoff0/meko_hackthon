"""Label ingestion with maturity tracking per source.

Implements challenge.md label sources: chargeback, dispute, analyst disposition,
confirmed non-fraud. Each source has a maturity horizon; immature and unknown
cases are kept out of mature-negative counts.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, validator

from .domain import CaseLabel, LabelSource, LabelState


class MaturityHorizon(str, Enum):
    CHARGEBACK = "chargeback"
    DISPUTE = "dispute"
    ANALYST_DISPOSITION = "analyst_disposition"
    CONFIRMED_NON_FRAUD = "confirmed_non_fraud"


# Default maturity horizons per label source (in seconds).
# Chargebacks/payment-network outcomes: delayed and incomplete.
# Customer disputes: may arrive late.
# Analyst dispositions: timely but subjective.
# Confirmed non-fraud: require defined maturity horizon.
DEFAULT_MATURITY_HORIZONS: dict[MaturityHorizon, int] = {
    MaturityHorizon.CHARGEBACK: 604800,      # 7 days
    MaturityHorizon.DISPUTE: 259200,         # 3 days
    MaturityHorizon.ANALYST_DISPOSITION: 3600,  # 1 hour
    MaturityHorizon.CONFIRMED_NON_FRAUD: 604800,  # 7 days
}


class LabelIngestor:
    """Ingests and tracks labels with maturity per source."""

    def __init__(
        self,
        maturity_horizons: Optional[dict[MaturityHorizon, int]] = None,
    ):
        self.maturity_horizons = maturity_horizons or dict(DEFAULT_MATURITY_HORIZONS)
        self._labels: dict[str, CaseLabel] = {}

    def ingest(self, label: CaseLabel) -> None:
        """Ingest a label, validating maturity horizon per source."""
        source_key = MaturityHorizon(label.label_source)
        horizon = self.maturity_horizons[source_key]
        label.maturity_horizon_seconds = horizon
        self._labels[label.label_id] = label

    def get_label(self, label_id: str) -> Optional[CaseLabel]:
        return self._labels.get(label_id)

    def get_labels_for_event(self, event_id: str) -> list[CaseLabel]:
        return [l for l in self._labels.values() if l.event_id == event_id]

    def get_labels_for_investigation(
        self, investigation_id: str
    ) -> list[CaseLabel]:
        return [
            l for l in self._labels.values()
            if l.investigation_id == investigation_id
        ]

    def is_mature(self, label: CaseLabel) -> bool:
        """Check if a label is mature per its source's maturity horizon."""
        return label.is_mature

    def mature_labels(self) -> list[CaseLabel]:
        """Return all mature labels."""
        return [l for l in self._labels.values() if l.is_mature]

    def immature_labels(self) -> list[CaseLabel]:
        """Return all immature labels (excluded from mature-negative counts)."""
        return [l for l in self._labels.values() if not l.is_mature]

    def mature_confirmed_fraud(self) -> list[CaseLabel]:
        """Mature confirmed fraud labels (chargeback/dispute positive)."""
        return [
            l for l in self._labels.values()
            if l.is_mature
            and l.label_state == LabelState.POSITIVE
            and l.label_source in (LabelSource.CHARGEBACK, LabelSource.DISPUTE)
        ]

    def mature_confirmed_legitimate(self) -> list[CaseLabel]:
        """Mature confirmed legitimate labels."""
        return [
            l for l in self._labels.values()
            if l.is_mature
            and l.label_state == LabelState.NEGATIVE
        ]

    def adjudicate(
        self,
        label_id: str,
        state: LabelState,
        adjudicated_by: str,
        adjudicated_at: Optional[datetime] = None,
    ) -> bool:
        """Adjudicate a label with a reviewer."""
        label = self._labels.get(label_id)
        if label is None:
            return False
        label.label_state = state
        label.adjudicated_at = adjudicated_at or datetime.now(timezone.utc)
        label.adjudicated_by = adjudicated_by
        return True
