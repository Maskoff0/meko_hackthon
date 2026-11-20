"""Unit tests for Phase 1 baseline.py (deterministic rules and velocity features).

Tests the BaselineEvaluator, VelocityWindow, and BaselineResult classes
against challenge.md requirements for transparent, reproducible baseline
comparison independent of Meko or an LLM.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

from fraud_detection.baseline import BaselineEvaluator, BaselineResult, VelocityWindow
from fraud_detection.domain import AccountEvent, EventType


def _make_event(
    account_id: str = "acct_1",
    event_type: EventType = EventType.LOGIN,
    source: str = "source_a",
    payload: dict | None = None,
    minutes_ago: int = 0,
) -> AccountEvent:
    return AccountEvent(
        account_id=account_id,
        event_type=event_type,
        source=source,
        payload=payload or {},
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
    )


# ---------------------------------------------------------------------------
# VelocityWindow tests
# ---------------------------------------------------------------------------


def test_velocity_window_add_and_count():
    """VelocityWindow adds events and counts within the window."""
    window = VelocityWindow(window_seconds=600)
    now = datetime.now(timezone.utc)

    window.add(now)
    window.add(now - timedelta(minutes=1))
    window.add(now - timedelta(minutes=11))  # outside 600s window

    assert window.count(now) == 2


def test_velocity_window_eviction():
    """VelocityWindow evicts events older than the window."""
    window = VelocityWindow(window_seconds=60)
    now = datetime.now(timezone.utc)

    window.add(now - timedelta(seconds=30))
    window.add(now - timedelta(seconds=90))  # outside window

    assert window.count(now) == 1


def test_velocity_window_empty():
    """Empty VelocityWindow returns count 0."""
    window = VelocityWindow(window_seconds=600)
    assert window.count() == 0


# ---------------------------------------------------------------------------
# BaselineResult tests
# ---------------------------------------------------------------------------


def test_baseline_result_to_dict():
    """BaselineResult.to_dict returns a serializable dict."""
    result = BaselineResult(
        triggered=True,
        reason_codes=["velocity_breach", "new_device"],
        score=0.65,
        details={"failed_login_count_window": 6},
    )
    d = result.to_dict()
    assert d["triggered"] is True
    assert d["reason_codes"] == ["velocity_breach", "new_device"]
    assert d["score"] == 0.65
    assert d["details"] == {"failed_login_count_window": 6}


# ---------------------------------------------------------------------------
# BaselineEvaluator tests
# ---------------------------------------------------------------------------


def test_baseline_failed_login_velocity_triggers():
    """Multiple failed logins in a window trigger velocity_breach."""
    evaluator = BaselineEvaluator(failed_login_threshold=5)

    for i in range(5):
        event = _make_event(
            event_type=EventType.LOGIN,
            payload={"failed": True},
            minutes_ago=i,
        )
        result = evaluator.evaluate(event)

    assert result.triggered is True
    assert "velocity_breach" in result.reason_codes
    assert result.score >= 0.4


def test_baseline_failed_login_below_threshold():
    """Failed logins below threshold do not trigger velocity_breach."""
    evaluator = BaselineEvaluator(failed_login_threshold=5)

    event = _make_event(
        event_type=EventType.LOGIN,
        payload={"failed": True},
    )
    result = evaluator.evaluate(event)

    assert result.triggered is False
    assert "velocity_breach" not in result.reason_codes


def test_baseline_new_device_triggers():
    """New device event triggers new_device reason code."""
    evaluator = BaselineEvaluator()

    event = _make_event(event_type=EventType.DEVICE)
    result = evaluator.evaluate(event)

    assert "new_device" in result.reason_codes
    assert result.details["new_device"] is True


def test_baseline_password_reset_triggers():
    """Password reset event triggers password_reset reason code."""
    evaluator = BaselineEvaluator()

    event = _make_event(event_type=EventType.RESET)
    result = evaluator.evaluate(event)

    assert "password_reset" in result.reason_codes
    assert result.details["password_reset"] is True


def test_baseline_new_payee_triggers():
    """Transaction with new_payee triggers new_payee reason code."""
    evaluator = BaselineEvaluator()

    event = _make_event(
        event_type=EventType.TRANSACTION,
        payload={"new_payee": True},
    )
    result = evaluator.evaluate(event)

    assert "new_payee" in result.reason_codes
    assert result.score >= 0.3


def test_baseline_test_payment_triggers():
    """Transaction with test_payment triggers test_payment reason code."""
    evaluator = BaselineEvaluator()

    event = _make_event(
        event_type=EventType.TRANSACTION,
        payload={"test_payment": True},
    )
    result = evaluator.evaluate(event)

    assert "test_payment" in result.reason_codes
    assert result.score >= 0.2


def test_baseline_limit_change_triggers():
    """Transaction with limit_change triggers limit_change reason code."""
    evaluator = BaselineEvaluator()

    event = _make_event(
        event_type=EventType.TRANSACTION,
        payload={"limit_change": True},
    )
    result = evaluator.evaluate(event)

    assert "limit_change" in result.reason_codes
    assert result.score >= 0.25


def test_baseline_device_reset_sequence():
    """New device + reset sequence triggers device_reset_sequence."""
    evaluator = BaselineEvaluator()

    # Add a device event first
    device_event = _make_event(event_type=EventType.DEVICE)
    evaluator.evaluate(device_event)

    # Then a reset event
    reset_event = _make_event(event_type=EventType.RESET)
    result = evaluator.evaluate(reset_event)

    assert "device_reset_sequence" in result.reason_codes


def test_baseline_score_capped_at_1_0():
    """Baseline score is capped at 1.0."""
    evaluator = BaselineEvaluator()

    # Combine many high-score signals
    event = _make_event(
        event_type=EventType.LOGIN,
        payload={"failed": True},
        minutes_ago=0,
    )
    # Push many login events to max out velocity score
    for i in range(20):
        ev = _make_event(
            event_type=EventType.LOGIN,
            payload={"failed": True},
            minutes_ago=i,
        )
        result = evaluator.evaluate(ev)

    assert result.score <= 1.0


def test_baseline_triggered_threshold_0_5():
    """Baseline triggers when score >= 0.5."""
    evaluator = BaselineEvaluator()

    # Score below 0.5 should not trigger
    event = _make_event(event_type=EventType.DEVICE, payload={"is_new_device": True})
    result = evaluator.evaluate(event)
    # new_device adds 0.25, which is below 0.5
    assert result.triggered is False

    # Multiple signals should push above 0.5
    # new_payee (0.3) + test_payment (0.2) + limit_change (0.25) = 0.75
    event2 = _make_event(
        event_type=EventType.TRANSACTION,
        payload={"new_payee": True, "test_payment": True, "limit_change": True},
    )
    result2 = evaluator.evaluate(event2)
    assert result2.triggered is True
    assert result2.score >= 0.5


def test_baseline_deterministic():
    """Running the same event twice produces identical results."""
    evaluator = BaselineEvaluator()

    event = _make_event(
        event_type=EventType.TRANSACTION,
        payload={"new_payee": True, "test_payment": True},
    )

    result1 = evaluator.evaluate(event)
    result2 = evaluator.evaluate(event)

    assert result1.triggered == result2.triggered
    assert result1.score == result2.score
    assert result1.reason_codes == result2.reason_codes


def test_baseline_per_account_isolation():
    """Baseline state is isolated per account."""
    evaluator = BaselineEvaluator()

    # Add events for account 1
    for i in range(5):
        ev = _make_event(account_id="acct_1", event_type=EventType.LOGIN, payload={"failed": True}, minutes_ago=i)
        evaluator.evaluate(ev)

    # Account 1 should be triggered
    assert evaluator._login_windows["acct_1"].count() == 5

    # Account 2 should have no events
    assert "acct_2" not in evaluator._login_windows


def test_baseline_custom_threshold():
    """Custom failed_login_threshold is respected."""
    evaluator = BaselineEvaluator(failed_login_threshold=3)

    for i in range(3):
        ev = _make_event(event_type=EventType.LOGIN, payload={"failed": True}, minutes_ago=i)
        result = evaluator.evaluate(ev)

    assert result.triggered is True
    assert "velocity_breach" in result.reason_codes


def test_baseline_custom_window():
    """Custom velocity_window_seconds is respected."""
    evaluator = BaselineEvaluator(velocity_window_seconds=60)

    now = datetime.now(timezone.utc)
    # Add event 30 seconds ago (within 60s window)
    ev1 = _make_event(event_type=EventType.LOGIN, payload={"failed": True}, minutes_ago=0)
    # Manually set timestamp to 30 seconds ago
    ev1.timestamp = now - timedelta(seconds=30)
    result1 = evaluator.evaluate(ev1)

    # Add event 90 seconds ago (outside 60s window)
    ev2 = _make_event(event_type=EventType.LOGIN, payload={"failed": True}, minutes_ago=0)
    ev2.timestamp = now - timedelta(seconds=90)
    result2 = evaluator.evaluate(ev2)

    # ev1 should count in window, ev2 should not
    assert result1.details["failed_login_count_window"] == 1
