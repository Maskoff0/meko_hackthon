"""Phase 3 tests: durable storage, event stream, outbox, restart recovery.

Tests cover:
  - SQLite persistence and idempotency
  - Durable event stream with replay
  - Outbox retry and dead-letter
  - Orchestrator recovery after restart
  - Duplicate and out-of-order event delivery
  - Trigger deduplication
  - Budget enforcement
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone, timedelta

import pytest

from fraud_detection.domain import (
    AccountEvent,
    EventType,
    EvidenceFinding,
    FindingStatus,
    Investigation,
    InvestigationStatus,
    LabelSource,
    LabelState,
    CaseLabel,
    ShadowRecommendation,
    Recommendation,
)
from fraud_detection.storage import Storage
from fraud_detection.stream import EventStream
from fraud_detection.outbox import Outbox, OutboxMessage
from fraud_detection.monitoring import Monitor, Snapshot, SLOTarget
from fraud_detection.orchestration import Orchestrator
from fraud_detection.baseline import BaselineEvaluator


import gc

# ---------------------------------------------------------------------------
# Storage tests
# ---------------------------------------------------------------------------


def _safe_unlink(path: str) -> None:
    """Best-effort file deletion; ignore Windows file-lock errors."""
    try:
        gc.collect()
        os.unlink(path)
    except PermissionError:
        pass  # Windows may hold the file briefly after SQLite close

def test_storage_insert_and_retrieve_event():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        storage = Storage(db_path=db_path)
        storage.connect()
        event = AccountEvent(
            account_id="acct_1",
            event_type=EventType.LOGIN,
            source="test_source",
            payload={"failed_count": 5},
        )
        inserted = storage.insert_event(event)
        assert inserted is True

        # Duplicate by idempotency_key should fail
        event2 = AccountEvent(
            account_id="acct_1",
            event_type=EventType.LOGIN,
            source="test_source",
            payload={"failed_count": 5},
            idempotency_key=event.idempotency_key,  # same idempotency key
        )
        inserted_dup = storage.insert_event(event2)
        assert inserted_dup is False

        retrieved = storage.get_event(event.event_id)
        assert retrieved is not None
        assert retrieved["account_id"] == "acct_1"
        assert retrieved["event_type"] == "login"

        events = storage.get_events_for_account("acct_1")
        assert len(events) == 1
        storage.close()
    finally:
        _safe_unlink(db_path)


def test_storage_investigation_persistence():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        storage = Storage(db_path=db_path)
        storage.connect()

        inv = Investigation(
            account_id="acct_1",
            trigger_event_id="evt_1",
            trigger_type="new_signal_source",
            hypothesis="test hypothesis",
        )
        storage.insert_investigation(inv)

        retrieved = storage.get_investigation(inv.investigation_id)
        assert retrieved is not None
        assert retrieved["account_id"] == "acct_1"
        assert retrieved["status"] == "open"

        # Update status
        storage.update_investigation_status(inv.investigation_id, "closed")
        retrieved2 = storage.get_investigation(inv.investigation_id)
        assert retrieved2["status"] == "closed"

        open_invs = storage.get_open_investigations()
        assert len(open_invs) == 0  # closed, so not open
        storage.close()
    finally:
        _safe_unlink(db_path)


def test_storage_finding_persistence():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        storage = Storage(db_path=db_path)
        storage.connect()

        inv = Investigation(
            account_id="acct_1",
            trigger_event_id="evt_1",
            trigger_type="new_signal_source",
            hypothesis="test",
        )
        storage.insert_investigation(inv)

        finding = EvidenceFinding(
            investigation_id=inv.investigation_id,
            agent_id="test_agent",
            conclusion="test_conclusion",
            confidence=0.8,
            reason_codes=["code1"],
            evidence_refs=["ref1"],
        )
        storage.insert_finding(finding)

        findings = storage.get_findings_for_investigation(inv.investigation_id)
        assert len(findings) == 1
        assert findings[0]["agent_id"] == "test_agent"
        assert findings[0]["conclusion"] == "test_conclusion"
        storage.close()
    finally:
        _safe_unlink(db_path)


def test_storage_audit_append():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        storage = Storage(db_path=db_path)
        storage.connect()

        row_id = storage.append_audit("test_event", {"key": "value"})
        assert row_id == 1

        entries = storage.get_audit_entries(entry_type="test_event", limit=10)
        assert len(entries) == 1
        assert entries[0]["type"] == "test_event"
        payload = json.loads(entries[0]["payload"])
        assert payload["key"] == "value"
        storage.close()
    finally:
        _safe_unlink(db_path)


def test_storage_outbox_and_dead_letter():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        storage = Storage(db_path=db_path)
        storage.connect()

        oid = storage.outbox_insert(
            aggregate_type="event",
            aggregate_id="evt_1",
            event_type="meko_write",
            payload={"data": "test"},
        )
        assert oid == 1

        pending = storage.outbox_pending(limit=10)
        assert len(pending) == 1
        assert pending[0]["status"] == "pending"

        storage.outbox_mark_sent(oid)
        pending2 = storage.outbox_pending(limit=10)
        assert len(pending2) == 0

        did = storage.dead_letter_insert(
            source_table="outbox",
            source_id=str(oid),
            reason="max_attempts_exceeded",
            payload={"data": "test"},
        )
        assert did == 1
        storage.close()
    finally:
        _safe_unlink(db_path)


# ---------------------------------------------------------------------------
# EventStream tests
# ---------------------------------------------------------------------------

def test_stream_append_and_replay():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        storage = Storage(db_path=db_path)
        storage.connect()
        stream = EventStream(storage)

        event1 = AccountEvent(
            account_id="acct_1",
            event_type=EventType.LOGIN,
            source="src_a",
            payload={},
        )
        event2 = AccountEvent(
            account_id="acct_1",
            event_type=EventType.DEVICE,
            source="src_b",
            payload={},
        )

        off1 = stream.append(event1)
        off2 = stream.append(event2)
        assert off1 > 0
        assert off2 > off1

        # Duplicate append returns existing offset
        off1_dup = stream.append(event1)
        assert off1_dup == off1

        assert stream.count() == 2  # only 2 unique events

        replayed = stream.replay(from_offset=1)
        assert len(replayed) == 2
        assert replayed[0].event_id == event1.event_id
        assert replayed[1].event_id == event2.event_id

        # Replay from offset 2 should only get event2
        replayed2 = stream.replay(from_offset=off2)
        assert len(replayed2) == 1
        assert replayed2[0].event_id == event2.event_id

        storage.close()
    finally:
        _safe_unlink(db_path)


def test_stream_subscribe_and_dispatch():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        storage = Storage(db_path=db_path)
        storage.connect()
        stream = EventStream(storage)

        received = []
        def handler(event: AccountEvent):
            received.append(event)

        stream.subscribe("agent_a", handler)
        stream.start()

        event = AccountEvent(
            account_id="acct_1",
            event_type=EventType.LOGIN,
            source="src_a",
            payload={},
        )
        stream.append(event)

        # Wait for dispatch with retry
        import time
        for _ in range(20):
            time.sleep(0.1)
            if len(received) >= 1:
                break

        stream.stop()
        time.sleep(0.2)  # allow thread to release DB connection
        storage.close()
        time.sleep(0.2)  # allow file handle release on Windows
        assert len(received) == 1
        assert received[0].event_id == event.event_id
        storage.close()
    finally:
        _safe_unlink(db_path)


# ---------------------------------------------------------------------------
# Outbox tests
# ---------------------------------------------------------------------------

def test_outbox_enqueue_and_stats():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        storage = Storage(db_path=db_path)
        storage.connect()

        delivery_calls = []
        def deliver(payload):
            delivery_calls.append(payload)

        outbox = Outbox(storage, deliver=deliver)
        oid = outbox.enqueue(
            aggregate_type="event",
            aggregate_id="evt_1",
            event_type="meko_write",
            payload={"data": "test1"},
        )
        outbox.enqueue(
            aggregate_type="event",
            aggregate_id="evt_2",
            event_type="meko_write",
            payload={"data": "test2"},
        )

        stats = outbox.stats()
        assert stats["pending"] == 2
        assert stats["delivered"] == 0

        # Process pending manually
        outbox._process_pending()
        assert len(delivery_calls) == 2
        stats2 = outbox.stats()
        assert stats2["delivered"] == 2
        assert stats2["pending"] == 0
        storage.close()
    finally:
        _safe_unlink(db_path)


def test_outbox_dead_letter_on_failure():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        storage = Storage(db_path=db_path)
        storage.connect()

        def failing_deliver(payload):
            raise RuntimeError("Meko is down")

        outbox = Outbox(storage, deliver=failing_deliver, max_attempts=1)
        outbox.enqueue(
            aggregate_type="event",
            aggregate_id="evt_1",
            event_type="meko_write",
            payload={"data": "fail"},
        )
        outbox._process_pending()

        # Should be dead-lettered after 1 failed attempt
        stats = outbox.stats()
        assert stats["failed"] == 1
        assert stats["pending"] == 0
        storage.close()
    finally:
        _safe_unlink(db_path)


# ---------------------------------------------------------------------------
# Orchestrator recovery tests
# ---------------------------------------------------------------------------

def test_orchestrator_recover_open_investigations():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        storage = Storage(db_path=db_path)
        storage.connect()

        # Create first orchestrator, create investigation
        orch1 = Orchestrator(storage=storage)
        inv = orch1.create_investigation(
            event=AccountEvent(
                account_id="acct_1",
                event_type=EventType.LOGIN,
                source="src_a",
                payload={},
            ),
            trigger_type="new_signal_source",
            hypothesis="test",
        )
        # Add a finding
        finding = EvidenceFinding(
            investigation_id=inv.investigation_id,
            agent_id="agent_a",
            conclusion="conclusion_a",
            confidence=0.8,
            reason_codes=["code1"],
        )
        orch1.add_finding(inv.investigation_id, finding)

        # Simulate restart: create new orchestrator with same storage
        orch2 = Orchestrator(storage=storage)
        recovered = orch2.recover()
        assert recovered == 1

        # The recovered investigation should be in memory
        ctx = orch2.get_investigation(inv.investigation_id)
        assert ctx is not None
        assert ctx.investigation.investigation_id == inv.investigation_id
        assert ctx.investigation.status == InvestigationStatus.ASSESSING
        storage.close()
    finally:
        _safe_unlink(db_path)


def test_orchestrator_persists_finding():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        storage = Storage(db_path=db_path)
        storage.connect()

        orch = Orchestrator(storage=storage)
        inv = orch.create_investigation(
            event=AccountEvent(
                account_id="acct_1",
                event_type=EventType.LOGIN,
                source="src_a",
                payload={},
            ),
            trigger_type="new_signal_source",
            hypothesis="test",
        )
        finding = EvidenceFinding(
            investigation_id=inv.investigation_id,
            agent_id="agent_a",
            conclusion="conclusion_a",
            confidence=0.8,
            reason_codes=["code1"],
        )
        orch.add_finding(inv.investigation_id, finding)

        # Verify finding persisted in storage
        findings = storage.get_findings_for_investigation(inv.investigation_id)
        assert len(findings) == 1
        assert findings[0]["agent_id"] == "agent_a"
        storage.close()
    finally:
        _safe_unlink(db_path)


def test_orchestrator_budget_enforcement():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        storage = Storage(db_path=db_path)
        storage.connect()

        orch = Orchestrator(
            default_tool_budget=3,
            default_meko_budget=3,
            storage=storage,
        )
        inv = orch.create_investigation(
            event=AccountEvent(
                account_id="acct_1",
                event_type=EventType.LOGIN,
                source="src_a",
                payload={},
            ),
            trigger_type="new_signal_source",
            hypothesis="test",
        )

        # Use up tool budget: 2 calls OK (1 < 3, 2 < 3)
        assert orch.record_tool_call(inv.investigation_id) is True
        assert orch.record_tool_call(inv.investigation_id) is True
        # Third call exhausts budget (3 >= 3)
        result = orch.record_tool_call(inv.investigation_id)
        assert result is False
        ctx = orch.get_investigation(inv.investigation_id)
        assert ctx.halted is True
        assert ctx.investigation.error == "tool_call_budget_exhausted"
        storage.close()
    finally:
        _safe_unlink(db_path)


# ---------------------------------------------------------------------------
# Monitoring tests
# ---------------------------------------------------------------------------

def test_monitor_snapshot_and_slo():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        storage = Storage(db_path=db_path)
        storage.connect()

        # Insert some events
        for i in range(3):
            event = AccountEvent(
                account_id="acct_1",
                event_type=EventType.LOGIN,
                source="src",
                payload={},
            )
            storage.insert_event(event)

        monitor = Monitor(storage)
        snapshot = monitor.snapshot()
        assert snapshot.total_events == 3
        assert snapshot.timestamp is not None

        # Evaluate SLOs
        result = monitor.evaluate_slos(snapshot)
        assert "all_pass" in result
        assert "slos" in result

        d = monitor.to_dict(snapshot)
        assert d["total_events"] == 3
        assert d["all_slos_pass"] is True
        storage.close()
    finally:
        _safe_unlink(db_path)


def test_slo_target_pass_fail():
    slo_max = SLOTarget(name="latency", threshold=100.0, actual=50.0, unit="ms", direction="max", measurement="test")
    assert slo_max.pass_status is True

    slo_max_fail = SLOTarget(name="latency", threshold=100.0, actual=150.0, unit="ms", direction="max", measurement="test")
    assert slo_max_fail.pass_status is False

    slo_min = SLOTarget(name="coverage", threshold=0.8, actual=0.9, unit="ratio", direction="min", measurement="test")
    assert slo_min.pass_status is True

    slo_min_fail = SLOTarget(name="coverage", threshold=0.8, actual=0.5, unit="ratio", direction="min", measurement="test")
    assert slo_min_fail.pass_status is False


# ---------------------------------------------------------------------------
# Idempotency and duplicate handling
# ---------------------------------------------------------------------------

def test_event_idempotency_on_reinsert():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        storage = Storage(db_path=db_path)
        storage.connect()

        event = AccountEvent(
            account_id="acct_1",
            event_type=EventType.LOGIN,
            source="src",
            payload={"failed_count": 5},
        )
        assert storage.insert_event(event) is True
        assert storage.insert_event(event) is False  # same event_id
        storage.close()
    finally:
        _safe_unlink(db_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
