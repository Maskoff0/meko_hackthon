"""Contract tests for Phase 2: label schema validation."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from fraud_detection.domain import CaseLabel, LabelSource, LabelState
from fraud_detection.labeling import LabelIngestor


def test_case_label_required_fields():
    """CaseLabel requires event_id and label_source."""
    with pytest.raises(ValueError):
        CaseLabel()  # missing required fields


def test_case_label_event_id_required():
    """event_id is required."""
    with pytest.raises(ValueError):
        CaseLabel(label_source=LabelSource.CHARGEBACK)


def test_case_label_source_required():
    """label_source is required."""
    with pytest.raises(ValueError):
        CaseLabel(event_id="evt_1")


def test_case_label_confidence_bounds():
    """confidence must be between 0.0 and 1.0."""
    with pytest.raises(ValueError):
        CaseLabel(
            event_id="evt_1",
            label_source=LabelSource.CHARGEBACK,
            confidence=1.5,
        )
    with pytest.raises(ValueError):
        CaseLabel(
            event_id="evt_1",
            label_source=LabelSource.CHARGEBACK,
            confidence=-0.1,
        )


def test_case_label_valid_sources():
    """All LabelSource enum values are valid."""
    for source in LabelSource:
        label = CaseLabel(
            event_id="evt_1",
            label_source=source,
        )
        assert label.label_source == source


def test_case_label_valid_states():
    """All LabelState enum values are valid."""
    for state in LabelState:
        label = CaseLabel(
            event_id="evt_1",
            label_source=LabelSource.CHARGEBACK,
            label_state=state,
        )
        assert label.label_state == state


def test_case_label_is_mature_property():
    """is_mature property checks age against maturity horizon."""
    old_label = CaseLabel(
        event_id="evt_1",
        label_source=LabelSource.ANALYST_DISPOSITION,
        label_state=LabelState.POSITIVE,
        timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc),
        maturity_horizon_seconds=3600,  # 1 hour
    )
    assert old_label.is_mature is True

    new_label = CaseLabel(
        event_id="evt_2",
        label_source=LabelSource.ANALYST_DISPOSITION,
        label_state=LabelState.POSITIVE,
        timestamp=datetime.now(timezone.utc),
        maturity_horizon_seconds=3600,
    )
    assert new_label.is_mature is False


def test_ingestor_enforces_maturity_horizon_per_source():
    """Ingestor sets maturity horizon based on label source."""
    ingestor = LabelIngestor()

    chargeback_label = CaseLabel(
        event_id="evt_cb",
        label_source=LabelSource.CHARGEBACK,
        label_state=LabelState.POSITIVE,
    )
    ingestor.ingest(chargeback_label)
    assert chargeback_label.maturity_horizon_seconds == 604800  # 7 days

    dispute_label = CaseLabel(
        event_id="evt_disp",
        label_source=LabelSource.DISPUTE,
        label_state=LabelState.POSITIVE,
    )
    ingestor.ingest(dispute_label)
    assert dispute_label.maturity_horizon_seconds == 259200  # 3 days

    analyst_label = CaseLabel(
        event_id="evt_analyst",
        label_source=LabelSource.ANALYST_DISPOSITION,
        label_state=LabelState.POSITIVE,
    )
    ingestor.ingest(analyst_label)
    assert analyst_label.maturity_horizon_seconds == 3600  # 1 hour
