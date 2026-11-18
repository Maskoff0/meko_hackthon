"""Event ingestion: validation, normalization, and idempotency.

Accepts authenticated, schema-validated events and deduplicates by stable
event ID. Rejects invalid inputs. Duplicate and out-of-order inputs do not
change the result.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from .domain import AccountEvent
from .settings import Settings


class IngestionResult(str, Enum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"


class Ingestor:
    """Validates, normalizes, and deduplicates incoming events."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or Settings()
        self._seen_ids: set[str] = set()

    def validate(self, event: AccountEvent) -> Optional[str]:
        """Validate an event. Returns None if valid, or an error message."""
        if not event.account_id or not event.account_id.strip():
            return "account_id must not be empty"
        if not event.event_type:
            return "event_type is required"
        if not event.idempotency_key or not event.idempotency_key.strip():
            return "idempotency_key must not be empty"
        if not event.schema_version:
            return "schema_version is required"
        return None

    def is_duplicate(self, event_id: str) -> bool:
        """Check if an event ID has already been seen."""
        return event_id in self._seen_ids

    def record_seen(self, event_id: str) -> None:
        """Record an event ID as seen."""
        self._seen_ids.add(event_id)

    def ingest(self, event: AccountEvent) -> tuple[IngestionResult, Optional[str]]:
        """Ingest an event: validate, deduplicate, normalize.

        Returns (result, error_message). On ACCEPTED, the event ID is recorded.
        On DUPLICATE or REJECTED, no state change occurs.
        """
        error = self.validate(event)
        if error:
            return IngestionResult.REJECTED, error

        if self.is_duplicate(event.event_id):
            return IngestionResult.DUPLICATE, f"Duplicate event id: {event.event_id}"

        self.record_seen(event.event_id)
        return IngestionResult.ACCEPTED, None
