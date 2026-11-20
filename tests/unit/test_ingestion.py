"""Unit tests for Phase 1 ingestion.py (validation, normalization, idempotency).

Tests the Ingestor class against challenge.md requirements:
- Signal contents treated as untrusted data
- Schema validation before ingestion
- Idempotent deduplication by stable event ID
- Invalid inputs rejected
"""
from __future__ import annotations

from datetime import datetime, timezone

from fraud_detection.domain import AccountEvent, EventType
from fraud_detection.ingestion import Ingestor, IngestionResult


def _make_event(
    account_id: str = "acct_1",
    event_type: EventType = EventType.LOGIN,
    source: str = "source_a",
    payload: dict | None = None,
    event_id: str | None = None,
    **kwargs,
) -> AccountEvent:
    return AccountEvent(
        account_id=account_id,
        event_type=event_type,
        source=source,
        payload=payload or {},
        event_id=event_id or f"evt_{datetime.now(timezone.utc).timestamp()}",
        **kwargs,
    )


def _make_invalid_event(**overrides) -> AccountEvent:
    """Create an AccountEvent bypassing pydantic validation for testing
    Ingestor validation of invalid inputs."""
    data = {
        "event_id": "evt_invalid",
        "account_id": overrides.get("account_id", "acct_1"),
        "event_type": overrides.get("event_type", EventType.LOGIN),
        "source": overrides.get("source", "source_a"),
        "payload": overrides.get("payload", {}),
        "timestamp": datetime.now(timezone.utc),
        "schema_version": overrides.get("schema_version", "1.0"),
        "idempotency_key": overrides.get("idempotency_key", "key_1"),
    }
    return AccountEvent.model_construct(**data)


# ---------------------------------------------------------------------------
# IngestionResult tests
# ---------------------------------------------------------------------------


def test_ingestion_result_enum_values():
    """IngestionResult has expected enum values."""
    assert IngestionResult.ACCEPTED == "accepted"
    assert IngestionResult.DUPLICATE == "duplicate"
    assert IngestionResult.REJECTED == "rejected"


# ---------------------------------------------------------------------------
# Ingestor validation tests
# ---------------------------------------------------------------------------


def test_validate_valid_event():
    """A fully valid event returns None (no error)."""
    ingestor = Ingestor()
    event = _make_event()
    error = ingestor.validate(event)
    assert error is None


def test_validate_empty_account_id():
    """Empty account_id is rejected by Ingestor.validate."""
    ingestor = Ingestor()
    event = _make_invalid_event(account_id="")
    error = ingestor.validate(event)
    assert error == "account_id must not be empty"


def test_validate_whitespace_account_id():
    """Whitespace-only account_id is rejected."""
    ingestor = Ingestor()
    event = _make_invalid_event(account_id="   ")
    error = ingestor.validate(event)
    assert error == "account_id must not be empty"


def test_validate_missing_event_type():
    """Missing event_type is rejected."""
    ingestor = Ingestor()
    event = _make_event()
    event.event_type = None  # type: ignore[assignment]
    error = ingestor.validate(event)
    assert error == "event_type is required"


def test_validate_empty_idempotency_key():
    """Empty idempotency_key is rejected."""
    ingestor = Ingestor()
    event = _make_event()
    event.idempotency_key = ""
    error = ingestor.validate(event)
    assert error == "idempotency_key must not be empty"


def test_validate_empty_schema_version():
    """Empty schema_version is rejected."""
    ingestor = Ingestor()
    event = _make_event()
    event.schema_version = ""
    error = ingestor.validate(event)
    assert error == "schema_version is required"


# ---------------------------------------------------------------------------
# Ingestor idempotency tests
# ---------------------------------------------------------------------------


def test_ingest_accepted_first_time():
    """First ingestion of a unique event is ACCEPTED."""
    ingestor = Ingestor()
    event = _make_event()
    result, error = ingestor.ingest(event)
    assert result == IngestionResult.ACCEPTED
    assert error is None


def test_ingest_duplicate_rejected():
    """Second ingestion of the same event ID is DUPLICATE."""
    ingestor = Ingestor()
    event = _make_event()
    result1, _ = ingestor.ingest(event)
    assert result1 == IngestionResult.ACCEPTED

    result2, error = ingestor.ingest(event)
    assert result2 == IngestionResult.DUPLICATE
    assert "Duplicate" in error
    assert event.event_id in error


def test_ingest_rejected_invalid():
    """Invalid event is REJECTED and not recorded as seen."""
    ingestor = Ingestor()
    event = _make_invalid_event(account_id="")
    result, error = ingestor.ingest(event)
    assert result == IngestionResult.REJECTED
    assert error == "account_id must not be empty"

    # The invalid event should not be recorded as seen
    assert ingestor.is_duplicate(event.event_id) is False


def test_is_duplicate_before_ingest():
    """is_duplicate returns False for unseen event IDs."""
    ingestor = Ingestor()
    assert ingestor.is_duplicate("nonexistent_id") is False


def test_record_seen_then_is_duplicate():
    """After record_seen, is_duplicate returns True."""
    ingestor = Ingestor()
    ingestor.record_seen("evt_123")
    assert ingestor.is_duplicate("evt_123") is True


def test_ingestor_per_instance_state():
    """Each Ingestor instance maintains its own seen IDs."""
    ingestor1 = Ingestor()
    ingestor2 = Ingestor()

    event = _make_event()
    ingestor1.ingest(event)

    assert ingestor1.is_duplicate(event.event_id) is True
    assert ingestor2.is_duplicate(event.event_id) is False


def test_ingest_different_events_both_accepted():
    """Different event IDs are both ACCEPTED."""
    ingestor = Ingestor()
    event1 = _make_event(event_id="evt_1")
    event2 = _make_event(event_id="evt_2")

    result1, _ = ingestor.ingest(event1)
    result2, _ = ingestor.ingest(event2)

    assert result1 == IngestionResult.ACCEPTED
    assert result2 == IngestionResult.ACCEPTED


def test_ingest_deduplicates_by_event_id_not_content():
    """Deduplication is by event_id, not by event content."""
    ingestor = Ingestor()

    event1 = _make_event(
        event_id="evt_same",
        payload={"amount": 100},
    )
    event2 = _make_event(
        event_id="evt_same",
        payload={"amount": 200},  # different content, same ID
    )

    result1, _ = ingestor.ingest(event1)
    result2, error = ingestor.ingest(event2)

    assert result1 == IngestionResult.ACCEPTED
    assert result2 == IngestionResult.DUPLICATE


# ---------------------------------------------------------------------------
# Ingestor with untrusted data
# ---------------------------------------------------------------------------


def test_ingest_event_with_untrusted_payload():
    """Events with untrusted payload content (e.g., attacker-controlled text)
    are accepted as long as schema fields are valid."""
    ingestor = Ingestor()
    event = _make_event(
        payload={
            "payee_name": "<script>alert('xss')</script>",
            "support_message": "please reset my password '; DROP TABLE users; --",
        }
    )
    result, error = ingestor.ingest(event)
    assert result == IngestionResult.ACCEPTED
    assert error is None
