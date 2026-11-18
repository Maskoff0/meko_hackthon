"""Phase 1 CLI entry point: local fixture/replay flow.

End-to-end synthetic flow that exercises the full Phase 1 path:

  ingest -> trigger -> bounded investigation -> scoped agents ->
  Meko write/retrieval -> correlator -> deterministic baseline ->
  policy engine -> shadow recommendation -> audit log ->
  containment gate (denied in shadow mode).

Also produces:

  - Baseline comparison: shared vs no-shared Meko memory (challenge.md
    Expected Outcome 4: baseline comparison encouraged).
  - Trace walkthroughs: >=3 end-to-end decision traces (challenge.md
    Expected Outcome 3: trace walkthroughs).

All signals are synthetic. No production signals are sent. No
containment/action credentials exist, so no execution path exists.
Constraints are enforced via Settings and can be eliminated by toggling
shadow_mode=False and configuring credentials (see module docstring in
containment.py).
"""
from __future__ import annotations

import asyncio
import json
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
    SupportAgent,
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
        "event_type": EventType.SUPPORT,
        "source": "synthetic_support_agent",
        "payload": {"reset_requests": 3, "unusual_time": True, "multiple_contacts": True},
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
    EventType.SUPPORT: "high_risk_event",
    EventType.TRANSACTION: "high_risk_event",
}

AGENT_MAP = {
    EventType.LOGIN: LoginAgent,
    EventType.DEVICE: DeviceAgent,
    EventType.RESET: ResetAgent,
    EventType.SUPPORT: SupportAgent,
    EventType.TRANSACTION: TransactionAgent,
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


async def run_agent_pipeline(
    events: list[AccountEvent],
    investigation_id: str,
    meko: Optional[MekoAdapter],
    orchestrator: Orchestrator,
    audit: AuditLog,
) -> tuple[list[EvidenceFinding], EvidenceFinding]:
    """Run scoped agents against permitted evidence.

    Returns (findings, correlated_finding).
    """
    findings: list[EvidenceFinding] = []
    agent_classes = [(AGENT_MAP[e.event_type], e) for e in events]

    for agent_cls, event in agent_classes:
        agent = agent_cls(meko) if meko is not None else agent_cls(MekoAdapter(Settings()))
        finding = await agent.assess(event)
        finding.investigation_id = investigation_id
        ok = orchestrator.add_finding(investigation_id, finding)
        if not ok:
            break
        findings.append(finding)
        audit.record_finding(finding)

    correlator = CorrelatorAgent(meko) if meko is not None else CorrelatorAgent(
        MekoAdapter(Settings())
    )
    correlated = await correlator.correlate(investigation_id, findings)
    correlated.investigation_id = investigation_id
    ok = orchestrator.add_finding(investigation_id, correlated)
    audit.record_finding(correlated)

    return findings, correlated


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
            "password reset -> support contact -> new payee test payment"
        ),
    )
    audit.record_investigation_created(investigation)
    print(f"\n[investigate] created {investigation.investigation_id} "
          f"(trigger={trigger_type}, budget={investigation.tool_call_budget} "
          f"tool calls, {investigation.meko_retrieval_budget} Meko retrievals)")

    # --- 3. Run agents with shared Meko memory -----------------------------
    print("\n--- Phase 1a: Shared Meko memory path ---\n")
    findings_shared: list[EvidenceFinding] = []
    correlated_shared: Optional[EvidenceFinding] = None

    meko_shared = MekoAdapter(settings)
    async with meko_shared.connect() as meko_session:
        for agent_cls, event in [
            (LoginAgent, events[0]),
            (DeviceAgent, events[1]),
            (ResetAgent, events[2]),
            (SupportAgent, events[3]),
            (TransactionAgent, trigger_event),
        ]:
            agent = agent_cls(meko_session)
            finding = await agent.assess(event)
            finding.investigation_id = investigation.investigation_id
            ok = orchestrator.add_finding(investigation.investigation_id, finding)
            if not ok:
                print(f"[agent] {agent.agent_id}: investigation halted")
                break
            findings_shared.append(finding)
            audit.record_finding(finding)
            print(
                f"[agent] {agent.agent_id}: {finding.conclusion} "
                f"(confidence={finding.confidence}, "
                f"reason_codes={finding.reason_codes})"
            )
            if not orchestrator.record_meko_retrieval(investigation.investigation_id):
                print(f"[budget] Meko retrieval budget exhausted after {agent.agent_id}")
                break

        correlator = CorrelatorAgent(meko_session)
        correlated_shared = await correlator.correlate(
            investigation.investigation_id, findings_shared
        )
        correlated_shared.investigation_id = investigation.investigation_id
        ok = orchestrator.add_finding(investigation.investigation_id, correlated_shared)
        audit.record_finding(correlated_shared)
        print(
            f"[correlator] {correlated_shared.conclusion} "
            f"(confidence={correlated_shared.confidence}, "
            f"reason_codes={correlated_shared.reason_codes})"
        )

        # Write signals to Meko memory
        for event in events:
            await meko_shared.write_signal(
                agent_id="ingestion_agent",
                account_id=event.account_id,
                signal_type=event.event_type.value,
                value=str(event.payload),
                confidence=0.7,
                evidence_refs=[event.event_id],
            )
        print(f"[meko] wrote {len(events)} signal(s) to memory")

        # Search context via Meko
        ctx = await meko_shared.correlate(ACCOUNT_ID)
        match_quality = ctx.get("match_quality") if isinstance(ctx, dict) else "n/a"
        print(f"[meko] context search match_quality={match_quality}")

    # --- 4. Run agents WITHOUT shared Meko memory (baseline comparison) ---
    print("\n--- Phase 1b: No-shared-Meko baseline path ---\n")
    orchestrator_no_meko = Orchestrator(
        baseline_evaluator=BaselineEvaluator(
            failed_login_threshold=settings.velocity_failed_login_threshold,
            velocity_window_seconds=settings.velocity_window_seconds,
        ),
        default_tool_budget=settings.default_tool_call_budget,
        default_meko_budget=0,
        default_token_budget=settings.default_token_budget,
        default_deadline_seconds=settings.default_wall_clock_deadline_seconds,
    )
    investigation_no_meko = orchestrator_no_meko.create_investigation(
        event=trigger_event,
        trigger_type=trigger_type,
        hypothesis=investigation.hypothesis,
    )

    findings_no_meko, correlated_no_meko = await run_agent_pipeline(
        events,
        investigation_no_meko.investigation_id,
        meko=None,
        orchestrator=orchestrator_no_meko,
        audit=audit,
    )
    print(
        f"[no-meko] findings={len(findings_no_meko)}, "
        f"correlated={correlated_no_meko.conclusion} "
        f"(confidence={correlated_no_meko.confidence})"
    )

    # --- 5. Deterministic baseline ----------------------------------------
    baseline_shared = orchestrator.evaluate_baseline(trigger_event)
    baseline_no_meko = orchestrator_no_meko.evaluate_baseline(trigger_event)
    print(f"\n[baseline shared] triggered={baseline_shared.triggered} "
          f"score={baseline_shared.score:.2f} "
          f"reason_codes={baseline_shared.reason_codes}")
    print(f"[baseline no-meko] triggered={baseline_no_meko.triggered} "
          f"score={baseline_no_meko.score:.2f} "
          f"reason_codes={baseline_no_meko.reason_codes}")

    # Baseline comparison: shared vs no-shared
    baseline_diff = baseline_shared.score - baseline_no_meko.score
    finding_diff = len(findings_shared) - len(findings_no_meko)
    print(f"\n[baseline comparison] score delta={baseline_diff:+.2f} "
          f"findings delta={finding_diff:+d}")

    # --- 6. Policy engine -> shadow recommendation -------------------------
    policy = PolicyEngine(policy_version=investigation.policy_version)
    recommendation_shared = policy.decide(
        event=trigger_event,
        baseline=baseline_shared,
        findings=findings_shared + [correlated_shared],
        shadow_mode=settings.shadow_mode,
    )
    audit.record_recommendation(ACCOUNT_ID, recommendation_shared)
    print(f"\n[policy shared] recommendation={recommendation_shared.recommendation.value} "
          f"abstention={recommendation_shared.abstention} "
          f"uncertainty={recommendation_shared.uncertainty}")
    print(f"         reason_codes={recommendation_shared.reason_codes}")

    recommendation_no_meko = policy.decide(
        event=trigger_event,
        baseline=baseline_no_meko,
        findings=findings_no_meko + [correlated_no_meko],
        shadow_mode=settings.shadow_mode,
    )
    print(f"[policy no-meko] recommendation={recommendation_no_meko.recommendation.value} "
          f"uncertainty={recommendation_no_meko.uncertainty}")
    print(f"         reason_codes={recommendation_no_meko.reason_codes}")

    # Policy comparison
    rec_diff = recommendation_shared.reason_codes != recommendation_no_meko.reason_codes
    print(f"[policy comparison] reason codes differ={rec_diff}")

    # --- 7. Containment gate (proposal ≠ authority) -----------------------
    gate = ContainmentGate(settings)
    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target=ACCOUNT_ID,
        reason_codes=list(recommendation_shared.reason_codes),
        evidence_refs=[f.finding_id for f in findings_shared]
        + [correlated_shared.finding_id],
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

    # --- 8. Trace walkthroughs (≥3 end-to-end decision traces) ------------
    print("\n=== Trace Walkthroughs ===")
    traces: list[dict] = []

    for i in range(3):
        trace_event = events[i % len(events)]
        trace_inv = orchestrator.create_investigation(
            event=trace_event,
            trigger_type=TRIGGER_TYPES[trace_event.event_type],
            hypothesis=f"Trace walkthrough {i + 1}: {trace_event.event_type.value} signal",
        )
        trace_finding = await AGENT_MAP[trace_event.event_type](MekoAdapter(settings)).assess(
            trace_event
        )
        trace_finding.investigation_id = trace_inv.investigation_id
        orchestrator.add_finding(trace_inv.investigation_id, trace_finding)

        trace_baseline = orchestrator.evaluate_baseline(trace_event)
        trace_policy = PolicyEngine(policy_version=trace_inv.policy_version)
        trace_rec = trace_policy.decide(
            event=trace_event,
            baseline=trace_baseline,
            findings=[trace_finding],
            shadow_mode=settings.shadow_mode,
        )

        trace_gate = ContainmentGate(settings)
        trace_proposal = ContainmentProposal(
            action_type="temporary_hold",
            target=trace_event.account_id,
            reason_codes=list(trace_rec.reason_codes),
            evidence_refs=[trace_finding.finding_id],
            reversibility="reversible_within_24h",
            proposed_by="correlator_agent",
        )
        trace_gate_result = trace_gate.evaluate(trace_proposal)

        trace = {
            "trace_id": i + 1,
            "account_id": trace_event.account_id,
            "event_type": trace_event.event_type.value,
            "event_id": trace_event.event_id,
            "investigation_id": trace_inv.investigation_id,
            "agent_finding": trace_finding.conclusion,
            "agent_confidence": trace_finding.confidence,
            "baseline_triggered": trace_baseline.triggered,
            "baseline_score": trace_baseline.score,
            "recommendation": trace_rec.recommendation.value,
            "reason_codes": trace_rec.reason_codes,
            "containment_decision": trace_gate_result.decision.value,
            "containment_executed": trace_gate_result.executed,
            "policy_version": trace_rec.policy_version,
            "model_version": trace_rec.model_version,
        }
        traces.append(trace)
        audit.record_investigation_transition(
            trace_inv, "closed", actor="system"
        )
        print(f"\n[trace {i + 1}] {trace_event.event_type.value} -> "
              f"agent={trace_finding.conclusion} -> "
              f"baseline={trace_baseline.triggered} -> "
              f"policy={trace_rec.recommendation.value} -> "
              f"containment={trace_gate_result.decision.value}")

    trace_path = "trace_walkthroughs.json"
    with open(trace_path, "w", encoding="utf-8") as f:
        json.dump(traces, f, indent=2, default=str)
    print(f"\n[trace] wrote {len(traces)} trace walkthroughs to {trace_path}")

    # --- 9. Close investigation -------------------------------------------
    orchestrator.close(investigation.investigation_id)
    audit.record_investigation_transition(
        investigation, "closed", actor="system"
    )

    # --- Summary ----------------------------------------------------------
    print("\n=== Phase 1 complete ===")
    print(f"  Recommendation (shared):  {recommendation_shared.recommendation.value}")
    print(f"  Recommendation (no-meko): {recommendation_no_meko.recommendation.value}")
    print(f"  Baseline score delta:     {baseline_diff:+.2f}")
    print(f"  Containment:              {result.decision.value} "
          f"(no executable action path in Phase 1)")
    print(f"  Trace walkthroughs:       {len(traces)} written to {trace_path}")
    print(f"  Audit log:                {audit.log_path}")
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
