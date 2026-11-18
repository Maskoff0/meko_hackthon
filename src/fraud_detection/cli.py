"""Phase 1 CLI entry point: local fixture/replay flow.

End-to-end synthetic flow that exercises the full Phase 1 path:

  ingest -> trigger -> bounded investigation -> scoped agents ->
  Meko write/retrieval -> correlator -> deterministic baseline ->
  policy engine -> shadow recommendation -> audit log ->
  containment gate (denied in shadow mode).

All signals are synthetic. No production signals are sent. No
containment/action credentials exist, so no execution path exists.
Constraints are enforced via Settings and can be eliminated by toggling
shadow_mode=False and configuring credentials (see module docstring in
containment.py).
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from typing import Optional

from .domain import (
    AccountEvent,
    EventType,
    EvidenceFinding,
    FindingStatus,
    Recommendation,
)
from .ingestion import Ingestor
from .orchestration import Orchestrator
from .baseline import BaselineEvaluator
from .policy import PolicyEngine
from .audit import AuditLog
from .meko_adapter import MekoAdapter
from .containment import ContainmentGate, ContainmentProposal
from .agents import (
    LoginAgent,
    DeviceAgent,
    ResetAgent,
    TransactionAgent,
    CorrelatorAgent,
)
from .settings import Settings


SYNTHETIC_FIXTURES = [
    {
        "event_type": EventType.LOGIN,
        "source": "synthetic_login_agent",
        "payload": {"failed_count": 12, "failure_rate": 0.9, "new_location": True},
        "provenance": "synthetic",
    },
    {
        "event_type": EventType.DEVICE,
        "source": "synthetic_device_agent",
        "payload": {"is_new_device": True, "is_emulator": True},
        "provenance": "synthetic",
    },
    {
        "event_type": EventType.RESET,
        "source": "synthetic_reset_agent",
        "payload": {"after_failures": True, "unusual_time": True},
        "provenance": "synthetic",
    },
    {
        "event_type": EventType.TRANSACTION,
        "source": "synthetic_transaction_agent",
        "payload": {
            "new_payee": True,
            "test_payment": True,
            "limit_change": False,
        },
        "provenance": "synthetic",
    },
]

ACCOUNT_ID = "acct_1042"
TRIGGER_TYPES = {
    EventType.LOGIN: "new_signal_source",
    EventType.DEVICE: "new_signal_source",
    EventType.RESET: "high_risk_event",
    EventType.TRANSACTION: "high_risk_event",
}


def build_event(fixture: dict) -> AccountEvent:
    return AccountEvent(
        account_id=ACCOUNT_ID,
        event_type=fixture["event_type"],
        source=fixture["source"],
        payload=fixture["payload"],
        provenance=fixture["provenance"],
        timestamp=datetime.now(timezone.utc),
    )


async def run_phase1(shadow_mode: Optional[bool] = None) -> int:
    """Run the Phase 1 end-to-end synthetic flow.

    Returns 0 on success, non-zero on failure.
    """
    settings = Settings()
    if shadow_mode is not None:
        settings.shadow_mode = shadow_mode

    print(f"=== Phase 1 Fraud Detection (shadow_mode={settings.shadow_mode}) ===\n")

    # --- 1. Ingest synthetic fixtures -------------------------------------
    ingestor = Ingestor(settings)
    audit = AuditLog()
    events: list[AccountEvent] = []

    for fixture in SYNTHETIC_FIXTURES:
        event = build_event(fixture)
        result, error = ingestor.ingest(event)
        audit.record_event(event)
        audit.record_ingestion_result(event.event_id, result, error)
        status = "ACCEPTED" if result.value == "accepted" else result.value.upper()
        print(f"[ingest] {event.event_type.value} for {event.account_id}: {status}")
        if error:
            print(f"         error: {error}")
        if result.value == "accepted":
            events.append(event)

    if not events:
        print("No events accepted; aborting.")
        return 1

    # --- 2. Trigger investigation on the highest-severity event -----------
    # Use the transaction event (new payee + test payment) as the trigger.
    trigger_event = events[-1]
    trigger_type = TRIGGER_TYPES[trigger_event.event_type]

    orchestrator = Orchestrator(
        baseline_evaluator=BaselineEvaluator(
            failed_login_threshold=settings.velocity_failed_login_threshold,
            velocity_window_seconds=settings.velocity_window_seconds,
        ),
        default_tool_budget=settings.default_tool_call_budget,
        default_meko_budget=settings.default_meko_retrieval_budget,
        default_token_budget=settings.default_token_budget,
        default_deadline_seconds=settings.default_wall_clock_deadline_seconds,
    )

    investigation = orchestrator.create_investigation(
        event=trigger_event,
        trigger_type=trigger_type,
        hypothesis=(
            "Account takeover sequence: credential stuffing -> new device -> "
            "password reset -> new payee test payment"
        ),
    )
    audit.record_investigation_created(investigation)
    print(f"\n[investigate] created {investigation.investigation_id} "
          f"(trigger={trigger_type}, budget={investigation.tool_call_budget} "
          f"tool calls, {investigation.meko_retrieval_budget} Meko retrievals)")

    # --- 3. Run scoped agents against permitted evidence ------------------
    findings: list[EvidenceFinding] = []
    agent_classes = [
        (LoginAgent, events[0] if len(events) > 0 else trigger_event),
        (DeviceAgent, events[1] if len(events) > 1 else trigger_event),
        (ResetAgent, events[2] if len(events) > 2 else trigger_event),
        (TransactionAgent, trigger_event),
    ]

    meko = MekoAdapter(settings)
    async with meko.connect() as meko_session:
        for agent_cls, event in agent_classes:
            agent = agent_cls(meko)
            finding = await agent.assess(event)
            finding.investigation_id = investigation.investigation_id
            ok = orchestrator.add_finding(investigation.investigation_id, finding)
            if not ok:
                print(f"[agent] {agent.agent_id}: investigation halted, "
                      f"skipping remaining agents")
                break
            findings.append(finding)
            audit.record_finding(finding)
            print(
                f"[agent] {agent.agent_id}: {finding.conclusion} "
                f"(confidence={finding.confidence}, "
                f"reason_codes={finding.reason_codes})"
            )

            # Record Meko retrieval against budget (context_search counts as
            # one retrieval; agents do not call Meko directly in Phase 1 —
            # Meko calls are made through the adapter at trigger points).
            if not orchestrator.record_meko_retrieval(investigation.investigation_id):
                print(f"[budget] Meko retrieval budget exhausted after "
                      f"{agent.agent_id}")
                break

        # --- 4. Correlate findings ---------------------------------------
        correlator = CorrelatorAgent(meko)
        correlated = await correlator.correlate(
            investigation.investigation_id, findings
        )
        correlated.investigation_id = investigation.investigation_id
        ok = orchestrator.add_finding(investigation.investigation_id, correlated)
        audit.record_finding(correlated)
        print(
            f"[correlator] {correlated.conclusion} "
            f"(confidence={correlated.confidence}, "
            f"reason_codes={correlated.reason_codes})"
        )

        # --- 5. Write signals to Meko memory (trigger point only) --------
        for event in events:
            await meko.write_signal(
                agent_id="ingestion_agent",
                account_id=event.account_id,
                signal_type=event.event_type.value,
                value=str(event.payload),
                confidence=0.7,
                evidence_refs=[event.event_id],
            )
        print(f"[meko] wrote {len(events)} signal(s) to memory")

        # --- 6. Search context via Meko ----------------------------------
        ctx = await meko.correlate(ACCOUNT_ID)
        match_quality = (
            ctx.get("match_quality") if isinstance(ctx, dict) else "n/a"
        )
        print(f"[meko] context search match_quality={match_quality}")

    # --- 7. Deterministic baseline ----------------------------------------
    baseline = orchestrator.evaluate_baseline(trigger_event)
    print(f"\n[baseline] triggered={baseline.triggered} score={baseline.score:.2f} "
          f"reason_codes={baseline.reason_codes}")

    # --- 8. Policy engine -> shadow recommendation ------------------------
    policy = PolicyEngine(policy_version=investigation.policy_version)
    recommendation = policy.decide(
        event=trigger_event,
        baseline=baseline,
        findings=findings + [correlated],
        shadow_mode=settings.shadow_mode,
    )
    audit.record_recommendation(ACCOUNT_ID, recommendation)
    print(f"\n[policy] recommendation={recommendation.recommendation.value} "
          f"abstention={recommendation.abstention} "
          f"uncertainty={recommendation.uncertainty}")
    print(f"         reason_codes={recommendation.reason_codes}")
    print(f"         evidence_provenance={recommendation.evidence_provenance}")
    print(f"         policy_version={recommendation.policy_version}")
    print(f"         model_version={recommendation.model_version}")

    # --- 9. Containment gate (proposal ≠ authority) ----------------------
    gate = ContainmentGate(settings)
    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target=ACCOUNT_ID,
        reason_codes=list(recommendation.reason_codes),
        evidence_refs=[f.finding_id for f in findings] + [correlated.finding_id],
        reversibility="reversible_within_24h",
        proposed_by="correlator_agent",
    )
    result = gate.evaluate(proposal)
    audit.record_containment_proposal(
        account_id=ACCOUNT_ID,
        action_type=proposal.action_type,
        target=proposal.target,
        reason_codes=proposal.reason_codes,
        evidence_refs=proposal.evidence_refs,
        reversibility=proposal.reversibility,
    )
    print(f"\n[containment] decision={result.decision.value} executed={result.executed}")
    print(f"         reason: {result.reason}")

    # --- 10. Close investigation -----------------------------------------
    orchestrator.close(investigation.investigation_id)
    audit.record_investigation_transition(
        investigation, "closed", actor="system"
    )

    # --- Summary ----------------------------------------------------------
    print("\n=== Phase 1 complete ===")
    print(f"  Recommendation: {recommendation.recommendation.value} "
          f"(shadow only — no action executed)")
    print(f"  Containment:    {result.decision.value} "
          f"(no executable action path in Phase 1)")
    print(f"  Audit log:      {audit.log_path}")
    print("\nNo production signals were sent. No containment/action credentials exist.")
    return 0


def main() -> int:
    """CLI entry point."""
    shadow_mode = True
    if "--no-shadow" in sys.argv:
        shadow_mode = False
        print("WARNING: --no-shadow disables shadow mode. "
              "This is a configuration change, not a Phase 1 default.")
    return asyncio.run(run_phase1(shadow_mode=shadow_mode))


if __name__ == "__main__":
    sys.exit(main())
