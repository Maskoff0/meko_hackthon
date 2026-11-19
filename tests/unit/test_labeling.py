"""Unit tests for Phase 2: label ingestion and maturity tracking."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from fraud_detection.domain import CaseLabel, LabelSource, LabelState
from fraud_detection.labeling import LabelIngestor, MaturityHorizon, DEFAULT_MATURITY_HORIZONS


def make_label(
    label_source: LabelSource = LabelSource.CHARGEBACK,
    label_state: LabelState = LabelState.POSITIVE,
    minutes_ago: int = 0,
    event_id: str = "evt_001",
) -> CaseLabel:
    return CaseLabel(
        event_id=event_id,
        label_source=label_source,
        label_state=label_state,
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
    )


def test_maturity_horizons_defaults():
    assert DEFAULT_MATURITY_HORIZONS[MaturityHorizon.CHARGEBACK] == 604800
    assert DEFAULT_MATURITY_HORIZONS[MaturityHorizon.DISPUTE] == 259200
    assert DEFAULT_MATURITY_HORIZONS[MaturityHorizon.ANALYST_DISPOSITION] == 3600
    assert DEFAULT_MATURITY_HORIZONS[MaturityHorizon.CONFIRMED_NON_FRAUD] == 604800


def test_ingest_and_get_label():
    ingestor = LabelIngestor()
    label = make_label()
    ingestor.ingest(label)
    retrieved = ingestor.get_label(label.label_id)
    assert retrieved is not None
    assert retrieved.label_id == label.label_id
    assert retrieved.maturity_horizon_seconds == 604800


def test_mature_vs_immature():
    ingestor = LabelIngestor()
    mature_label = make_label(minutes_ago=11000)  # > 7 days for chargeback (604800s)
    immature_label = make_label(minutes_ago=10)  # < 7 days
    ingestor.ingest(mature_label)
    ingestor.ingest(immature_label)

    mature = ingestor.mature_labels()
    immature = ingestor.immature_labels()

    assert len(mature) == 1
    assert len(immature) == 1
    assert mature[0].label_id == mature_label.label_id
    assert immature[0].label_id == immature_label.label_id


def test_immature_excluded_from_mature_negative():
    """Immature labels must not count as mature negatives."""
    ingestor = LabelIngestor()
    # Create a mature negative label and an immature negative label
    mature_neg = make_label(
        label_source=LabelSource.CONFIRMED_NON_FRAUD,
        label_state=LabelState.NEGATIVE,
        minutes_ago=11000,
    )
    immature_neg = make_label(
        label_source=LabelSource.CONFIRMED_NON_FRAUD,
        label_state=LabelState.NEGATIVE,
        minutes_ago=10,
    )
    ingestor.ingest(mature_neg)
    ingestor.ingest(immature_neg)

    legit = ingestor.mature_confirmed_legitimate()
    assert len(legit) == 1
    assert legit[0].label_id == mature_neg.label_id


def test_adjudicate():
    ingestor = LabelIngestor()
    label = make_label(label_state=LabelState.UNKNOWN)
    ingestor.ingest(label)

    ok = ingestor.adjudicate(
        label.label_id,
        LabelState.POSITIVE,
        adjudicated_by="analyst_01",
    )
    assert ok is True

    updated = ingestor.get_label(label.label_id)
    assert updated.label_state == LabelState.POSITIVE
    assert updated.adjudicated_by == "analyst_01"
    assert updated.adjudicated_at is not None


def test_adjudicate_nonexistent():
    ingestor = LabelIngestor()
    ok = ingestor.adjudicate("nonexistent", LabelState.POSITIVE, "analyst_01")
    assert ok is False


def test_get_labels_for_event():
    ingestor = LabelIngestor()
    l1 = make_label(event_id="evt_a")
    l2 = make_label(event_id="evt_b")
    l3 = make_label(event_id="evt_a")
    ingestor.ingest(l1)
    ingestor.ingest(l2)
    ingestor.ingest(l3)

    evt_a_labels = ingestor.get_labels_for_event("evt_a")
    assert len(evt_a_labels) == 2

    evt_b_labels = ingestor.get_labels_for_event("evt_b")
    assert len(evt_b_labels) == 1
