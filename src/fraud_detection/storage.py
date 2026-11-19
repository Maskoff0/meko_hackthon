"""Durable SQLite storage layer for Phase 3.

Persists events, investigations, findings, labels, recommendations,
audit entries, outbox messages, and dead letters. All writes are
transactional and append-only where required by challenge.md:

  - Append-only decision log is the audit record of truth.
  - Meko traces are supplementary; this store is authoritative.

Schema is versioned and designed for local/persistent storage per
plan.md Phase 3: "Persist events, investigation tasks/transitions,
structured handoffs, cases, labels, recommendations, and the append-only
audit log independently of Meko."
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


SCHEMA_VERSION = "2026-11-v1"

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    account_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL,
    provenance TEXT NOT NULL DEFAULT 'synthetic',
    ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS investigations (
    investigation_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    trigger_event_id TEXT NOT NULL,
    trigger_type TEXT NOT NULL,
    hypothesis TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    policy_version TEXT NOT NULL DEFAULT '2026-11-v1',
    allowed_tools TEXT NOT NULL DEFAULT '[]',
    evidence_scopes TEXT NOT NULL DEFAULT '[]',
    tool_call_budget INTEGER NOT NULL DEFAULT 10,
    meko_retrieval_budget INTEGER NOT NULL DEFAULT 5,
    token_budget INTEGER NOT NULL DEFAULT 4000,
    wall_clock_deadline_seconds INTEGER NOT NULL DEFAULT 60,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    error TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    conclusion TEXT NOT NULL,
    confidence REAL NOT NULL,
    reason_codes TEXT NOT NULL DEFAULT '[]',
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL DEFAULT 'agent',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id)
);

CREATE TABLE IF NOT EXISTS labels (
    label_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    investigation_id TEXT,
    label_source TEXT NOT NULL,
    label_state TEXT NOT NULL DEFAULT 'unknown',
    confidence REAL NOT NULL DEFAULT 0.5,
    timestamp TEXT NOT NULL,
    maturity_horizon_seconds INTEGER NOT NULL DEFAULT 86400,
    adjudicated_at TEXT,
    adjudicated_by TEXT,
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);

CREATE TABLE IF NOT EXISTS recommendations (
    recommendation_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    investigation_id TEXT,
    recommendation TEXT NOT NULL,
    reason_codes TEXT NOT NULL DEFAULT '[]',
    baseline_result TEXT NOT NULL DEFAULT '{}',
    uncertainty TEXT NOT NULL DEFAULT 'low',
    abstention INTEGER NOT NULL DEFAULT 0,
    policy_version TEXT NOT NULL,
    model_version TEXT NOT NULL,
    prompt_version TEXT,
    evidence_provenance TEXT NOT NULL DEFAULT '[]',
    timestamp TEXT NOT NULL,
    FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id)
);

CREATE TABLE IF NOT EXISTS audit_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    payload TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    created_at TEXT NOT NULL,
    delivered_at TEXT,
    last_error TEXT
);

CREATE TABLE IF NOT EXISTS dead_letters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_table TEXT NOT NULL,
    source_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_account_id ON events(account_id);
CREATE INDEX IF NOT EXISTS idx_events_idempotency_key ON events(idempotency_key);
CREATE INDEX IF NOT EXISTS idx_investigations_account_id ON investigations(account_id);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);
CREATE INDEX IF NOT EXISTS idx_findings_investigation_id ON findings(investigation_id);
CREATE INDEX IF NOT EXISTS idx_labels_event_id ON labels(event_id);
CREATE INDEX IF NOT EXISTS idx_audit_entries_type ON audit_entries(type);
CREATE INDEX IF NOT EXISTS idx_audit_entries_timestamp ON audit_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_outbox_status ON outbox(status);
CREATE INDEX IF NOT EXISTS idx_outbox_created_at ON outbox(created_at);
"""


class Storage:
    """SQLite-backed durable storage for the fraud detection system."""

    def __init__(self, db_path: str | Path = "fraud_detection.db"):
        self.db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self) -> None:
        """Open the database and create schema if needed."""
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Storage not connected. Call connect() first.")
        return self._conn

    # --- Events -----------------------------------------------------------

    def insert_event(self, event) -> bool:
        """Insert an event idempotently.

        Returns True if inserted, False if duplicate (by idempotency_key
        or event_id).
        """
        try:
            self.conn.execute(
                """
                INSERT INTO events (event_id, account_id, event_type, source,
                                    timestamp, schema_version, idempotency_key,
                                    payload, provenance, ingested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.account_id,
                    event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type),
                    event.source,
                    event.timestamp.isoformat() if hasattr(event.timestamp, "isoformat") else str(event.timestamp),
                    event.schema_version,
                    event.idempotency_key,
                    json.dumps(event.payload, default=str),
                    event.provenance,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            self.conn.rollback()
            return False

    def get_event(self, event_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM events WHERE event_id = ?", (event_id,)
        ).fetchone()
        return dict(row) if row else None

    def count_events(self) -> int:
        """Return the total number of events in storage."""
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM events").fetchone()
        return row["cnt"] if row else 0

    def get_events_for_account(self, account_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM events WHERE account_id = ? ORDER BY timestamp",
            (account_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Investigations ---------------------------------------------------

    def insert_investigation(self, inv) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO investigations
            (investigation_id, account_id, trigger_event_id, trigger_type,
             hypothesis, status, policy_version, allowed_tools,
             evidence_scopes, tool_call_budget, meko_retrieval_budget,
             token_budget, wall_clock_deadline_seconds, created_at,
             updated_at, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                inv.investigation_id,
                inv.account_id,
                inv.trigger_event_id,
                inv.trigger_type,
                inv.hypothesis,
                inv.status.value if hasattr(inv.status, "value") else str(inv.status),
                inv.policy_version,
                json.dumps(getattr(inv, "allowed_tools", [])),
                json.dumps(getattr(inv, "evidence_scopes", [])),
                getattr(inv, "tool_call_budget", 10),
                getattr(inv, "meko_retrieval_budget", 5),
                getattr(inv, "token_budget", 4000),
                getattr(inv, "wall_clock_deadline_seconds", 60),
                inv.created_at.isoformat() if hasattr(inv.created_at, "isoformat") else str(inv.created_at),
                inv.updated_at.isoformat() if hasattr(inv.updated_at, "isoformat") else str(inv.updated_at),
                getattr(inv, "error", None),
            ),
        )
        self.conn.commit()

    def get_investigation(self, investigation_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM investigations WHERE investigation_id = ?",
            (investigation_id,),
        ).fetchone()
        return dict(row) if row else None

    def update_investigation_status(
        self, investigation_id: str, status: str, error: Optional[str] = None
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "UPDATE investigations SET status = ?, updated_at = ?, error = ? WHERE investigation_id = ?",
            (status, now, error, investigation_id),
        )
        self.conn.commit()

    def get_investigations_for_account(self, account_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM investigations WHERE account_id = ? ORDER BY created_at",
            (account_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_open_investigations(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM investigations WHERE status IN ('open', 'assessing', 'correlating', 'decided', 'escalated') ORDER BY created_at"
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Findings ---------------------------------------------------------

    def insert_finding(self, finding) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO findings
            (finding_id, investigation_id, agent_id, conclusion, confidence,
             reason_codes, evidence_refs, source, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.finding_id,
                finding.investigation_id,
                finding.agent_id,
                finding.conclusion,
                finding.confidence,
                json.dumps(finding.reason_codes),
                json.dumps(finding.evidence_refs),
                finding.source,
                finding.status.value if hasattr(finding.status, "value") else str(finding.status),
                finding.created_at.isoformat() if hasattr(finding.created_at, "isoformat") else str(finding.created_at),
            ),
        )
        self.conn.commit()

    def get_findings_for_investigation(self, investigation_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE investigation_id = ? ORDER BY created_at",
            (investigation_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Labels -----------------------------------------------------------

    def insert_label(self, label) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO labels
            (label_id, event_id, investigation_id, label_source, label_state,
             confidence, timestamp, maturity_horizon_seconds, adjudicated_at,
             adjudicated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                label.label_id,
                label.event_id,
                getattr(label, "investigation_id", None),
                label.label_source.value if hasattr(label.label_source, "value") else str(label.label_source),
                label.label_state.value if hasattr(label.label_state, "value") else str(label.label_state),
                label.confidence,
                label.timestamp.isoformat() if hasattr(label.timestamp, "isoformat") else str(label.timestamp),
                label.maturity_horizon_seconds,
                label.adjudicated_at.isoformat()
                if getattr(label, "adjudicated_at", None) and hasattr(label.adjudicated_at, "isoformat")
                else str(getattr(label, "adjudicated_at", None)),
                getattr(label, "adjudicated_by", None),
            ),
        )
        self.conn.commit()

    def get_labels_for_event(self, event_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM labels WHERE event_id = ? ORDER BY timestamp",
            (event_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Recommendations --------------------------------------------------

    def insert_recommendation(self, rec) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO recommendations
            (recommendation_id, account_id, investigation_id, recommendation,
             reason_codes, baseline_result, uncertainty, abstention,
             policy_version, model_version, prompt_version,
             evidence_provenance, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                getattr(rec, "recommendation_id", None) or rec.event_id if hasattr(rec, "event_id") else rec.account_id,
                rec.account_id,
                getattr(rec, "investigation_id", None),
                rec.recommendation.value if hasattr(rec.recommendation, "value") else str(rec.recommendation),
                json.dumps(rec.reason_codes),
                json.dumps(rec.baseline_result if hasattr(rec, "baseline_result") else {}),
                rec.uncertainty,
                1 if rec.abstention else 0,
                rec.policy_version,
                rec.model_version,
                getattr(rec, "prompt_version", None),
                json.dumps(rec.evidence_provenance),
                rec.timestamp.isoformat() if hasattr(rec.timestamp, "isoformat") else str(rec.timestamp),
            ),
        )
        self.conn.commit()

    # --- Audit ------------------------------------------------------------

    def append_audit(self, entry_type: str, payload: dict[str, Any]) -> int:
        """Append an audit entry. Returns the row id."""
        cur = self.conn.execute(
            "INSERT INTO audit_entries (type, payload, timestamp) VALUES (?, ?, ?)",
            (entry_type, json.dumps(payload, default=str), datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_audit_entries(self, entry_type: Optional[str] = None, limit: int = 100) -> list[dict]:
        if entry_type:
            rows = self.conn.execute(
                "SELECT * FROM audit_entries WHERE type = ? ORDER BY id DESC LIMIT ?",
                (entry_type, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM audit_entries ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # --- Outbox -----------------------------------------------------------

    def outbox_pending(self, limit: int = 100) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM outbox WHERE status = 'pending' ORDER BY created_at LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def outbox_mark_sent(self, outbox_id: int) -> None:
        self.conn.execute(
            "UPDATE outbox SET status = 'sent', delivered_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), outbox_id),
        )
        self.conn.commit()

    def outbox_increment_attempts(self, outbox_id: int, error: Optional[str] = None) -> None:
        self.conn.execute(
            "UPDATE outbox SET attempts = attempts + 1, last_error = ? WHERE id = ?",
            (error, outbox_id),
        )
        self.conn.commit()

    def outbox_insert(
        self,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload: dict,
        max_attempts: int = 5,
    ) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO outbox (aggregate_type, aggregate_id, event_type, payload,
                                status, attempts, max_attempts, created_at)
            VALUES (?, ?, ?, ?, 'pending', 0, ?, ?)
            """,
            (
                aggregate_type,
                aggregate_id,
                event_type,
                json.dumps(payload, default=str),
                max_attempts,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self.conn.commit()
        return cur.lastrowid

    # --- Dead letters -----------------------------------------------------

    def dead_letter_insert(
        self, source_table: str, source_id: str, reason: str, payload: dict
    ) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO dead_letters (source_table, source_id, reason, payload, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                source_table,
                source_id,
                reason,
                json.dumps(payload, default=str),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self.conn.commit()
        return cur.lastrowid

    # --- Context manager --------------------------------------------------

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
