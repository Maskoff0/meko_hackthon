"""Unit tests for Phase 2: replay harness."""
from __future__ import annotations

from datetime import datetime, timezone

from fraud_detection.domain import AccountEvent, EventType
from fraud_detection.baseline import BaselineEvaluator
from fraud_detection.policy import PolicyEngine
from fraud_detection.replay import ReplayHarness, RecordedDecisionReplay


def test_replay_decision_provenance():
    harness = ReplayHarness()
    event = AccountEvent(
        account_id="acct_1",
        event_type=EventType.LOGIN,
        source="test",
        payload={"failed_count": 10},
    )
    record = harness.replay_decision(event=event, shadow_mode=True)

    assert record.event_id == event.event_id
    assert record.account_id == event.account_id
    assert record.policy_version == "2026-11-v1"
    assert record.model_version == "deterministic-baseline-v1"
    assert record.decision in ("review", "abstain")
    assert record.feature_code_version == "2026-11-v1"
    assert record.input_snapshot["account_id"] == "acct_1"
    assert record.input_snapshot["payload"] == {"failed_count": 10}


def test_replay_batch_agreement():
    harness = ReplayHarness()
    events = [
        AccountEvent(
            account_id="acct_1",
            event_type=EventType.TRANSACTION,
            source="test",
            payload={"new_payee": True, "test_payment": True},
        ),
        AccountEvent(
            account_id="acct_2",
            event_type=EventType.LOGIN,
            source="test",
            payload={"failed_count": 1},
        ),
    ]
    result = harness.replay_batch(events=events, shadow_mode=True)

    assert result.total_events == 2
    assert result.agreement_count + result.disagreement_count == 2
    assert 0.0 <= result.agreement_rate() <= 1.0


def test_replay_prevents_temporal_leakage():
    """Only features available at decision time are used."""
    harness = ReplayHarness()
    event = AccountEvent(
        account_id="acct_1",
        event_type=EventType.TRANSACTION,
        source="test",
        payload={"new_payee": True, "test_payment": True},
        timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
    )
    record = harness.replay_decision(event=event, shadow_mode=True)

    # Input snapshot should only contain decision-time features
    assert record.input_snapshot["payload"] == {"new_payee": True, "test_payment": True}
    # No future information should be in the snapshot
    assert "future" not in str(record.input_snapshot)


def test_recorded_decision_replay_fresh_run():
    harness = ReplayHarness()
    rdr = RecordedDecisionReplay(harness)

    event = AccountEvent(
        account_id="acct_1",
        event_type=EventType.LOGIN,
        source="test",
        payload={"failed_count": 3},
    )

    # Record original
    original = harness.replay_decision(event=event, shadow_mode=True)
    rdr.record_original(original)

    # Replay fresh
    fresh = rdr.replay_fresh(event=event, shadow_mode=True)

    comparison = rdr.compare_runs()
    assert comparison["original_count"] == 1
    assert comparison["fresh_count"] == 1
    assert "note" in comparison
    assert "new experiments" in comparison["note"]


def test_fresh_runs_are_new_experiments():
    """Fresh runs should be tracked separately and flagged as fresh."""
    harness = ReplayHarness()
    event = AccountEvent(
        account_id="acct_1",
        event_type=EventType.LOGIN,
        source="test",
        payload={"failed_count": 3},
    )

    original = harness.replay_decision(event=event, shadow_mode=True, is_fresh_run=False)
    fresh = harness.replay_decision(event=event, shadow_mode=True, is_fresh_run=True)

    assert original.is_fresh_run is False
    assert fresh.is_fresh_run is True

    fresh_runs = harness.get_fresh_runs()
    assert len(fresh_runs) == 1
    assert fresh_runs[0].is_fresh_run is True
