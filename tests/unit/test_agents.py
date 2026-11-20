"""Unit tests for Phase 1 agents/ package (scoped agent tasks and typed handoffs).

Tests that each agent produces typed EvidenceFinding results with conclusion,
confidence, reason codes, and evidence references per challenge.md requirements.
Agents use Meko only for enrichment; they never execute containment.
"""
from __future__ import annotations

from datetime import datetime, timezone

import asyncio

from fraud_detection.agents import (
    LoginAgent,
    DeviceAgent,
    TransactionAgent,
    SupportAgent,
    ResetAgent,
    CorrelatorAgent,
)
from fraud_detection.domain import AccountEvent, EventType, EvidenceFinding
from fraud_detection.meko_adapter import MekoAdapter


class _FakeMeko:
    """Fake Meko adapter for agent testing (no real MCP calls)."""

    async def create_conversation(self, agent_id, title, metadata):
        return "conv_123"

    async def call(self, tool, **args):
        return {"status": "ok"}


def _make_event(
    account_id: str = "acct_1",
    event_type: EventType = EventType.LOGIN,
    source: str = "source_a",
    payload: dict | None = None,
) -> AccountEvent:
    return AccountEvent(
        account_id=account_id,
        event_type=event_type,
        source=source,
        payload=payload or {},
    )


# ---------------------------------------------------------------------------
# LoginAgent tests
# ---------------------------------------------------------------------------


def test_login_agent_credential_stuffing():
    """High failed count triggers credential_stuffing_detected."""
    agent = LoginAgent(meko=_FakeMeko())
    event = _make_event(
        event_type=EventType.LOGIN,
        payload={"failed_count": 10, "failure_rate": 0.9},
    )
    finding = asyncio.run(agent.assess(event))

    assert isinstance(finding, EvidenceFinding)
    assert finding.agent_id == "login_agent"
    assert finding.conclusion == "credential_stuffing_detected"
    assert finding.confidence == 0.8
    assert "failed_login_velocity" in finding.reason_codes
    assert "high_failure_rate" in finding.reason_codes
    assert finding.status == "complete"
    assert event.event_id in finding.evidence_refs


def test_login_agent_elevated_failed_logins():
    """Medium failed count triggers elevated_failed_logins."""
    agent = LoginAgent(meko=_FakeMeko())
    event = _make_event(
        event_type=EventType.LOGIN,
        payload={"failed_count": 7},
    )
    finding = asyncio.run(agent.assess(event))

    assert finding.conclusion == "elevated_failed_logins"
    assert finding.confidence == 0.6
    assert "failed_login_velocity" in finding.reason_codes


def test_login_agent_no_anomaly():
    """No failed logins triggers no_login_anomaly."""
    agent = LoginAgent(meko=_FakeMeko())
    event = _make_event(
        event_type=EventType.LOGIN,
        payload={"failed_count": 0},
    )
    finding = asyncio.run(agent.assess(event))

    assert finding.conclusion == "no_login_anomaly"
    assert finding.confidence == 0.1


# ---------------------------------------------------------------------------
# DeviceAgent tests
# ---------------------------------------------------------------------------


def test_device_agent_suspicious_device():
    """Emulator or spoofed fingerprint triggers suspicious_device."""
    agent = DeviceAgent(meko=_FakeMeko())
    event = _make_event(
        event_type=EventType.DEVICE,
        payload={"is_emulator": True},
    )
    finding = asyncio.run(agent.assess(event))

    assert finding.conclusion == "suspicious_device"
    assert finding.confidence == 0.85
    assert "emulator_detected" in finding.reason_codes


def test_device_agent_new_device():
    """New device triggers new_device_observed."""
    agent = DeviceAgent(meko=_FakeMeko())
    event = _make_event(
        event_type=EventType.DEVICE,
        payload={"is_new_device": True},
    )
    finding = asyncio.run(agent.assess(event))

    assert finding.conclusion == "new_device_observed"
    assert finding.confidence == 0.6
    assert "new_device" in finding.reason_codes


def test_device_agent_known_device():
    """Known device triggers known_device with low confidence."""
    agent = DeviceAgent(meko=_FakeMeko())
    event = _make_event(
        event_type=EventType.DEVICE,
        payload={"is_new_device": False},
    )
    finding = asyncio.run(agent.assess(event))

    assert finding.conclusion == "known_device"
    assert finding.confidence == 0.1


# ---------------------------------------------------------------------------
# TransactionAgent tests
# ---------------------------------------------------------------------------


def test_transaction_agent_high_risk_sequence():
    """Cash out or new_payee+test_payment triggers high_risk_transaction_sequence."""
    agent = TransactionAgent(meko=_FakeMeko())
    event = _make_event(
        event_type=EventType.TRANSACTION,
        payload={"cash_out": True},
    )
    finding = asyncio.run(agent.assess(event))

    assert finding.conclusion == "high_risk_transaction_sequence"
    assert finding.confidence == 0.85
    assert "cash_out" in finding.reason_codes


def test_transaction_agent_new_payee_and_test_payment():
    """new_payee + test_payment triggers high_risk_transaction_sequence."""
    agent = TransactionAgent(meko=_FakeMeko())
    event = _make_event(
        event_type=EventType.TRANSACTION,
        payload={"new_payee": True, "test_payment": True},
    )
    finding = asyncio.run(agent.assess(event))

    assert finding.conclusion == "high_risk_transaction_sequence"
    assert "new_payee" in finding.reason_codes
    assert "test_payment" in finding.reason_codes


def test_transaction_agent_routine():
    """Routine transaction triggers routine_transaction."""
    agent = TransactionAgent(meko=_FakeMeko())
    event = _make_event(
        event_type=EventType.TRANSACTION,
        payload={},
    )
    finding = asyncio.run(agent.assess(event))

    assert finding.conclusion == "routine_transaction"
    assert finding.confidence == 0.1


# ---------------------------------------------------------------------------
# SupportAgent tests
# ---------------------------------------------------------------------------


def test_support_agent_takeover_pattern():
    """Multiple reset requests + unusual time triggers support_takeover_pattern."""
    agent = SupportAgent(meko=_FakeMeko())
    event = _make_event(
        event_type=EventType.SUPPORT,
        payload={"reset_requests": 3, "unusual_time": True},
    )
    finding = asyncio.run(agent.assess(event))

    assert finding.conclusion == "support_takeover_pattern"
    assert finding.confidence == 0.75


def test_support_agent_elevated_reset_requests():
    """2+ reset requests triggers elevated_reset_requests."""
    agent = SupportAgent(meko=_FakeMeko())
    event = _make_event(
        event_type=EventType.SUPPORT,
        payload={"reset_requests": 2},
    )
    finding = asyncio.run(agent.assess(event))

    assert finding.conclusion == "elevated_reset_requests"
    assert finding.confidence == 0.6


# ---------------------------------------------------------------------------
# ResetAgent tests
# ---------------------------------------------------------------------------


def test_reset_agent_after_failures_unusual_time():
    """Reset after failures at unusual time triggers highest confidence."""
    agent = ResetAgent(meko=_FakeMeko())
    event = _make_event(
        event_type=EventType.RESET,
        payload={"after_failures": True, "unusual_time": True},
    )
    finding = asyncio.run(agent.assess(event))

    assert finding.conclusion == "reset_after_failures_unusual_time"
    assert finding.confidence == 0.75


def test_reset_agent_routine():
    """Routine reset triggers routine_reset."""
    agent = ResetAgent(meko=_FakeMeko())
    event = _make_event(
        event_type=EventType.RESET,
        payload={},
    )
    finding = asyncio.run(agent.assess(event))

    assert finding.conclusion == "routine_reset"
    assert finding.confidence == 0.2


# ---------------------------------------------------------------------------
# CorrelatorAgent tests
# ---------------------------------------------------------------------------


def test_correlator_aggregates_findings():
    """Correlator aggregates multiple findings into a correlated finding."""
    agent = CorrelatorAgent(meko=_FakeMeko())

    finding1 = EvidenceFinding(
        investigation_id="inv_1",
        agent_id="login_agent",
        conclusion="credential_stuffing_detected",
        confidence=0.8,
        reason_codes=["failed_login_velocity"],
        evidence_refs=["evt_1"],
        source="login_agent",
    )
    finding2 = EvidenceFinding(
        investigation_id="inv_1",
        agent_id="device_agent",
        conclusion="new_device_observed",
        confidence=0.6,
        reason_codes=["new_device"],
        evidence_refs=["evt_1"],
        source="device_agent",
    )

    correlated = asyncio.run(
        agent.correlate("inv_1", [finding1, finding2])
    )

    assert correlated.agent_id == "correlator_agent"
    assert correlated.conclusion == "correlated_multi_agent_high_confidence"
    assert correlated.confidence >= 0.7
    assert "failed_login_velocity" in correlated.reason_codes
    assert "new_device" in correlated.reason_codes
    assert "evt_1" in correlated.evidence_refs


def test_correlator_no_findings():
    """Correlator with no findings returns no_findings_to_correlate."""
    agent = CorrelatorAgent(meko=_FakeMeko())
    correlated = asyncio.run(agent.correlate("inv_1", []))

    assert correlated.conclusion == "no_findings_to_correlate"
    assert correlated.confidence == 0.0
    assert "no_evidence" in correlated.reason_codes


def test_correlator_verifies_evidence_refs():
    """Correlator deduplicates and verifies evidence references."""
    agent = CorrelatorAgent(meko=_FakeMeko())

    finding1 = EvidenceFinding(
        investigation_id="inv_1",
        agent_id="login_agent",
        conclusion="credential_stuffing_detected",
        confidence=0.8,
        reason_codes=["failed_login_velocity"],
        evidence_refs=["evt_1", "evt_2"],
        source="login_agent",
    )
    finding2 = EvidenceFinding(
        investigation_id="inv_1",
        agent_id="device_agent",
        conclusion="new_device_observed",
        confidence=0.6,
        reason_codes=["new_device"],
        evidence_refs=["evt_2", "evt_3"],  # evt_2 is duplicate
        source="device_agent",
    )

    correlated = asyncio.run(
        agent.correlate("inv_1", [finding1, finding2])
    )

    # evt_2 should appear only once
    assert correlated.evidence_refs.count("evt_2") == 1
    assert "evt_1" in correlated.evidence_refs
    assert "evt_3" in correlated.evidence_refs


# ---------------------------------------------------------------------------
# Agents package exports
# ---------------------------------------------------------------------------


def test_agents_package_exports_all_agents():
    """The agents package exports all expected agent classes."""
    from fraud_detection.agents import (
        LoginAgent,
        DeviceAgent,
        TransactionAgent,
        SupportAgent,
        ResetAgent,
        CorrelatorAgent,
    )

    assert LoginAgent is not None
    assert DeviceAgent is not None
    assert TransactionAgent is not None
    assert SupportAgent is not None
    assert ResetAgent is not None
    assert CorrelatorAgent is not None


# ---------------------------------------------------------------------------
# Agents are read-only (no containment execution)
# ---------------------------------------------------------------------------


def test_agents_do_not_execute_containment():
    """Agents produce findings only; they never execute containment actions."""
    agent = LoginAgent(meko=_FakeMeko())
    event = _make_event(
        event_type=EventType.LOGIN,
        payload={"failed_count": 10},
    )
    finding = asyncio.run(agent.assess(event))

    # Finding is evidence, not authority
    assert finding.conclusion is not None
    assert finding.confidence > 0
    assert finding.evidence_refs  # cites evidence

    # No action/execution method on the agent
    assert not hasattr(finding, "execute")
    assert not hasattr(finding, "approve")
    assert not hasattr(finding, "block")
