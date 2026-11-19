"""Unit tests for Phase 1 trigger engine."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

from fraud_detection.domain import AccountEvent, EventType
from fraud_detection.triggers import (
    TriggerEngine,
    TriggerRule,
    TriggerType,
    TriggerEvaluation,
)


def make_event(
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


def test_new_signal_source_triggers_on_first_seen():
    """First event from a new source should trigger new_signal_source."""
    engine = TriggerEngine()
    event = make_event(source="source_a")

    evaluations = engine.evaluate(event)
    assert len(evaluations) == 1
    assert evaluations[0].triggered is True
    assert evaluations[0].trigger_type == TriggerType.NEW_SIGNAL_SOURCE
    assert evaluations[0].rule_id == "new_signal_source"
    assert "new signal source" in evaluations[0].reason


def test_new_signal_source_does_not_retrigger_same_source():
    """Second event from same source should NOT trigger new_signal_source."""
    engine = TriggerEngine()
    event1 = make_event(source="source_a")
    event2 = make_event(source="source_a")

    evals1 = engine.evaluate(event1)
    assert len(evals1) == 1
    assert evals1[0].triggered is True

    evals2 = engine.evaluate(event2)
    # new_signal_source should not fire again for same source
    source_evals = [e for e in evals2 if e.trigger_type == TriggerType.NEW_SIGNAL_SOURCE]
    assert len(source_evals) == 0
    assert not source_evals[0].triggered if source_evals else True


def test_different_sources_each_trigger():
    """Each new source should trigger new_signal_source."""
    engine = TriggerEngine()
    events = [
        make_event(source="source_a"),
        make_event(source="source_b"),
        make_event(source="source_c"),
    ]

    for event in events:
        evaluations = engine.evaluate(event)
        assert len(evaluations) == 1
        assert evaluations[0].triggered is True
        assert evaluations[0].trigger_type == TriggerType.NEW_SIGNAL_SOURCE


def test_velocity_window_crossing():
    """Velocity window crossing triggers when count >= threshold."""
    engine = TriggerEngine()
    # Disable other rules to isolate velocity testing
    engine.disable_rule("new_signal_source")
    engine.disable_rule("high_risk_event")

    # Add 5 events rapidly - 5th should cross threshold of 5
    for i in range(5):
        event = make_event(source="source_a", minutes_ago=i)
        evaluations = engine.evaluate(event)
        velocity_evals = [e for e in evaluations if e.trigger_type == TriggerType.VELOCITY_WINDOW_CROSSING]
        if i < 4:
            assert len(velocity_evals) == 0, f"Event {i} should not cross threshold yet"
        else:
            assert len(velocity_evals) == 1
            assert velocity_evals[0].triggered is True
            assert velocity_evals[0].metadata["count"] == 5


def test_velocity_window_count_reaches_threshold():
    """Adding events to velocity window increases count toward threshold."""
    engine = TriggerEngine()
    engine.disable_rule("new_signal_source")
    engine.disable_rule("high_risk_event")

    # Add 4 events - each evaluation should not cross threshold yet
    for i in range(4):
        event = make_event(source="source_a", minutes_ago=i)
        evaluations = engine.evaluate(event)
        velocity_evals = [e for e in evaluations if e.trigger_type == TriggerType.VELOCITY_WINDOW_CROSSING]
        assert len(velocity_evals) == 0, f"Event {i} should not cross threshold yet"

    # 5th event should cross threshold of 5
    event5 = make_event(source="source_a", minutes_ago=0)
    evaluations = engine.evaluate(event5)
    velocity_evals = [e for e in evaluations if e.trigger_type == TriggerType.VELOCITY_WINDOW_CROSSING]
    assert len(velocity_evals) == 1
    assert velocity_evals[0].triggered is True
    assert velocity_evals[0].metadata["count"] == 5


def test_high_risk_event_reset_with_new_payee():
    """RESET event with new_payee payload should trigger high_risk_event."""
    engine = TriggerEngine()
    engine.disable_rule("new_signal_source")
    engine.disable_rule("velocity_window_login")

    event = make_event(
        event_type=EventType.RESET,
        source="source_a",
        payload={"new_payee": True},
    )
    evaluations = engine.evaluate(event)
    high_risk_evals = [e for e in evaluations if e.trigger_type == TriggerType.HIGH_RISK_EVENT]
    assert len(high_risk_evals) == 1
    assert high_risk_evals[0].triggered is True
    assert "new_payee" in high_risk_evals[0].metadata["payload_keys_found"]


def test_high_risk_event_transaction_with_limit_change():
    """TRANSACTION event with limit_change should trigger high_risk_event."""
    engine = TriggerEngine()
    engine.disable_rule("new_signal_source")
    engine.disable_rule("velocity_window_login")

    event = make_event(
        event_type=EventType.TRANSACTION,
        source="source_a",
        payload={"limit_change": True},
    )
    evaluations = engine.evaluate(event)
    high_risk_evals = [e for e in evaluations if e.trigger_type == TriggerType.HIGH_RISK_EVENT]
    assert len(high_risk_evals) == 1
    assert high_risk_evals[0].triggered is True


def test_high_risk_event_login_does_not_trigger():
    """LOGIN event should NOT trigger high_risk_event (not in high_risk_event_types)."""
    engine = TriggerEngine()
    engine.disable_rule("new_signal_source")
    engine.disable_rule("velocity_window_login")

    event = make_event(
        event_type=EventType.LOGIN,
        source="source_a",
        payload={"new_payee": True},
    )
    evaluations = engine.evaluate(event)
    high_risk_evals = [e for e in evaluations if e.trigger_type == TriggerType.HIGH_RISK_EVENT]
    assert len(high_risk_evals) == 0


def test_high_risk_event_reset_without_payload_key():
    """RESET event without high-risk payload keys should NOT trigger."""
    engine = TriggerEngine()
    engine.disable_rule("new_signal_source")
    engine.disable_rule("velocity_window_login")

    event = make_event(
        event_type=EventType.RESET,
        source="source_a",
        payload={"routine": True},  # no new_payee, limit_change, cash_out
    )
    evaluations = engine.evaluate(event)
    high_risk_evals = [e for e in evaluations if e.trigger_type == TriggerType.HIGH_RISK_EVENT]
    assert len(high_risk_evals) == 0


def test_should_create_investigation_returns_trigger_type():
    """should_create_investigation returns the trigger type string."""
    engine = TriggerEngine()
    engine.disable_rule("velocity_window_login")
    engine.disable_rule("high_risk_event")

    event = make_event(source="source_a")
    result = engine.should_create_investigation(event)
    assert result == TriggerType.NEW_SIGNAL_SOURCE.value


def test_should_create_investigation_returns_none_when_no_trigger():
    """should_create_investigation returns None when no rule triggers."""
    engine = TriggerEngine()
    # Disable all rules
    for rule_id in engine.get_rules():
        engine.disable_rule(rule_id)

    event = make_event(source="source_a")
    result = engine.should_create_investigation(event)
    assert result is None


def test_rule_enable_disable():
    """Rules can be enabled and disabled."""
    engine = TriggerEngine()
    assert engine.enable_rule("new_signal_source") is True
    assert engine.disable_rule("new_signal_source") is True
    assert engine.enable_rule("nonexistent_rule") is False
    assert engine.disable_rule("nonexistent_rule") is False


def test_trigger_version():
    """Trigger engine has a version."""
    engine = TriggerEngine()
    assert engine.get_trigger_version() == "2026-11-v1"


def test_custom_rules():
    """Custom rules can be provided."""
    custom_rule = TriggerRule(
        rule_id="custom_velocity",
        version="2026-11-v2",
        trigger_type=TriggerType.VELOCITY_WINDOW_CROSSING,
        enabled=True,
        window_seconds=120,
        threshold=2,
    )
    engine = TriggerEngine(rules=[custom_rule])

    assert "custom_velocity" in engine.get_rules()
    assert engine.get_rules()["custom_velocity"].threshold == 2
    assert engine.get_rules()["custom_velocity"].window_seconds == 120


def test_multiple_triggers_same_event():
    """An event can trigger multiple rules."""
    engine = TriggerEngine()
    event = make_event(
        source="source_a",  # new source
        event_type=EventType.TRANSACTION,
        payload={"new_payee": True},  # high risk
    )
    evaluations = engine.evaluate(event)
    # Both new_signal_source and high_risk_event should fire
    triggered_types = [e.trigger_type for e in evaluations if e.triggered]
    assert TriggerType.NEW_SIGNAL_SOURCE in triggered_types
    assert TriggerType.HIGH_RISK_EVENT in triggered_types


def test_trigger_evaluation_metadata():
    """Trigger evaluations carry useful metadata."""
    engine = TriggerEngine()
    engine.disable_rule("new_signal_source")
    engine.disable_rule("high_risk_event")

    event = make_event(source="source_a", minutes_ago=1)
    evaluations = engine.evaluate(event)
    velocity_evals = [e for e in evaluations if e.trigger_type == TriggerType.VELOCITY_WINDOW_CROSSING]
    if velocity_evals:
        assert "count" in velocity_evals[0].metadata
        assert "threshold" in velocity_evals[0].metadata
        assert "window_seconds" in velocity_evals[0].metadata
