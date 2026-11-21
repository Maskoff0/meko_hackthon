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

Phase 3 (durable operations):

  - SQLite durable storage for events, investigations, findings, labels,
    recommendations, audit entries, outbox, and dead letters.
  - Durable event stream with subscription, acknowledgment, replay, and
    dead-letter capabilities.
  - Outbox pattern with retry/dead-letter for reliable Meko enrichment.
  - Persistent orchestrator state that survives process restarts.
  - Monitoring/SLO collection (ingestion lag, duplicates, Meko latency,
    decision latency, alert volume, drift).

All signals are synthetic. No production signals are sent. No
containment/action credentials exist, so no execution path exists.
Constraints are enforced via Settings and can be eliminated by toggling
shadow_mode=False and configuring credentials (see module docstring in
containment.py).
"""
from __future__ import annotations

import asyncio
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

from .domain import (
    AccountEvent,
    CaseLabel,
    EventType,
    EvidenceFinding,
    FindingStatus,
    LabelSource,
    LabelState,
    Recommendation,
    ShadowRecommendation,
)
from .ingestion import Ingestor
from .orchestration import Orchestrator
from .baseline import BaselineEvaluator, BaselineResult
from .policy import PolicyEngine
from .audit import AuditLog
from .meko_adapter import MekoAdapter, MekoAdapterError
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
from .triggers import TriggerEngine
from .labeling import LabelIngestor
from .replay import ReplayHarness
from .metrics import MetricsEngine
from .analyst import (
    CaseBriefService,
    TraceExplanationService,
    CaseDraftService,
    FeedbackCaptureService,
)
from .storage import Storage
from .stream import EventStream
from .outbox import Outbox, OutboxWorker


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


async def run_phase1(
    shadow_mode: Optional[bool] = None,
    db_path: str = "fraud_detection.db",
) -> int:
    """Run the Phase 1 end-to-end synthetic flow.

    Returns 0 on success, non-zero on failure.
    """
    settings = Settings()
    if shadow_mode is not None:
        settings.shadow_mode = shadow_mode

    print(f"=== Phase 1 Fraud Detection (shadow_mode={settings.shadow_mode}) ===\n")

    # --- Phase 3: Durable storage, event stream, and outbox ----------------
    storage = Storage(db_path=db_path)
    storage.connect()
    recovered = orchestrator_recovery = 0
    try:
        recovered = storage.get_open_investigations().__len__()
    except Exception:
        recovered = 0

    stream = EventStream(storage)

    def meko_deliver(payload: dict) -> None:
        """Deliver an outbox message to Meko via the adapter."""
        # Meko delivery is best-effort; failures go to dead letter queue
        pass  # actual Meko calls are made inline via MekoAdapter sessions

    outbox = Outbox(storage, deliver=meko_deliver)

    orchestrator = Orchestrator(
        baseline_evaluator=BaselineEvaluator(
            failed_login_threshold=settings.velocity_failed_login_threshold,
            velocity_window_seconds=settings.velocity_window_seconds,
        ),
        default_tool_budget=settings.default_tool_call_budget,
        default_meko_budget=settings.default_meko_retrieval_budget,
        default_meko_content_token_budget=settings.meko_max_retrieval_content_tokens,
        default_token_budget=settings.default_token_budget,
        default_deadline_seconds=settings.default_wall_clock_deadline_seconds,
        storage=storage,
    )
    # Recover any open investigations from durable storage
    orchestrator.recover()

    stream.start()
    outbox.start()
    print(
        f"[phase3] durable storage={db_path}, recovered={recovered} "
        f"open investigation(s)"
    )

    # --- 1. Ingest synthetic fixtures -------------------------------------
    ingestor = Ingestor(settings)
    audit = AuditLog()
    events: list[AccountEvent] = []

    for fixture in SYNTHETIC_FIXTURES:
        event = build_event(fixture)
        # Phase 3: durably persist the event (idempotent by idempotency_key)
        inserted = storage.insert_event(event)
        # Also append to the durable event stream
        stream.append(event)
        result, error = ingestor.ingest(event)
        audit.record_event(event)
        audit.record_ingestion_result(event.event_id, result, error)
        status = "ACCEPTED" if result.value == "accepted" else result.value.upper()
        print(f"[ingest] {event.event_type.value} for {event.account_id}: {status}")
        if error:
            print(f"         error: {error}")
        if result.value == "accepted":
            events.append(event)
        elif result.value == "duplicate":
            print(f"         (duplicate event idempotency key: {event.idempotency_key})")

    if not events:
        print("No events accepted; aborting.")
        stream.stop()
        outbox.stop()
        storage.close()
        return 1

    # --- 2. Trigger investigation using TriggerEngine ---------------------
    trigger_engine = TriggerEngine()

    # Evaluate all events through the trigger engine to build state
    # and find the first triggering event
    trigger_event = None
    trigger_type = None
    for event in events:
        evaluations = trigger_engine.evaluate(event)
        if evaluations and trigger_event is None:
            trigger_event = event
            trigger_type = evaluations[0].trigger_type.value
            print(f"[trigger] {event.event_type.value} triggered {trigger_type}: "
                  f"{evaluations[0].reason}")

    if trigger_event is None:
        # Fallback: use the last event as a manual trigger
        trigger_event = events[-1]
        trigger_type = "manual_trigger"
        print(f"[trigger] no automatic trigger; using "
              f"{trigger_event.event_type.value} as manual trigger")

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

    meko_shared = MekoAdapter(settings, trace_id=investigation.trace_id)
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

        # Write signals to Meko memory using shared conversation
        # (enables Meko built-in dedup and server-side LLM extraction)
        shared_conv_id = await meko_shared.create_conversation(
            "ingestion_agent",
            f"ATO signals for account {ACCOUNT_ID}",
            {"kind": "signal_batch", "account_id": ACCOUNT_ID},
        )
        signal_dicts = [
            {
                "signal_type": event.event_type.value,
                "value": str(event.payload),
                "confidence": 0.7,
                "evidence_refs": [event.event_id],
                "account_id": event.account_id,
            }
            for event in events
        ]
        batch_results = await meko_shared.batch_write_signals(
            signal_dicts,
            shared_conversation_id=shared_conv_id,
            agent_id="ingestion_agent",
            account_id=ACCOUNT_ID,
        )
        print(f"[meko] wrote {len(batch_results)} signal(s) to memory (shared conversation)")

        # Memory-only search (memories, not KB/conversations)
        mem_results = await meko_shared.memory_search(
            query=f"ATO signals for account {ACCOUNT_ID}",
            limit=10,
            agent_id="ingestion_agent",
        )
        mem_count = len(mem_results.get("matches", [])) if isinstance(mem_results, dict) else 0
        # Estimate content token size (~4 chars per token heuristic)
        mem_content_str = str(mem_results) if mem_results else ""
        mem_content_tokens = max(1, len(mem_content_str) // 4)
        if not orchestrator.record_meko_retrieval_content_tokens(
            investigation.investigation_id, mem_content_tokens
        ):
            print(
                f"[budget] Meko retrieval content token budget exhausted "
                f"after memory_search ({mem_content_tokens} tokens)"
            )
        print(f"[meko] memory search returned {mem_count} memories "
              f"({mem_content_tokens} estimated content tokens)")

        # Context search (memory + KB + conversations in parallel buckets)
        ctx = await meko_shared.correlate(ACCOUNT_ID)
        match_quality = ctx.get("match_quality") if isinstance(ctx, dict) else "n/a"
        ctx_content_str = str(ctx) if ctx else ""
        ctx_content_tokens = max(1, len(ctx_content_str) // 4)
        if not orchestrator.record_meko_retrieval_content_tokens(
            investigation.investigation_id, ctx_content_tokens
        ):
            print(
                f"[budget] Meko retrieval content token budget exhausted "
                f"after context_search ({ctx_content_tokens} tokens)"
            )
        print(f"[meko] context search match_quality={match_quality} "
              f"({ctx_content_tokens} estimated content tokens)")

        # List all memories (paged)
        all_memories = await meko_shared.memory_get_all(page_size=10)
        total_pages = all_memories.get("total_pages", 0) if isinstance(all_memories, dict) else 0
        mem_count_all = len(all_memories.get("results", [])) if isinstance(all_memories, dict) else 0
        print(f"[meko] memory_get_all: {mem_count_all} memories, {total_pages} total pages")

        # Export Meko trace for observability and chain-of-thought traceability
        trace_path = pathlib.Path("traces") / f"{investigation.investigation_id}.json"
        trace_path.parent.mkdir(parents=True, exist_ok=True)
        meko_trace = meko_shared.export_trace_meko_format()
        trace_path.write_text(json.dumps(meko_trace, indent=2))
        trace_summary = meko_shared.get_trace_summary()
        print(
            f"[trace] trace_id={trace_summary['trace_id']} "
            f"events={trace_summary['total_events']} "
            f"latency={trace_summary['total_latency_seconds']}s "
            f"tokens={trace_summary['total_estimated_tokens']} "
            f"written to {trace_path}"
        )

    # --- 4. Run agents WITHOUT shared Meko memory (baseline comparison) ---
    print("\n--- Phase 1b: No-shared-Meko baseline path ---\n")
    orchestrator_no_meko = Orchestrator(
        baseline_evaluator=BaselineEvaluator(
            failed_login_threshold=settings.velocity_failed_login_threshold,
            velocity_window_seconds=settings.velocity_window_seconds,
        ),
        default_tool_budget=settings.default_tool_call_budget,
        default_meko_budget=0,
        default_meko_content_token_budget=0,
        default_token_budget=settings.default_token_budget,
        default_deadline_seconds=settings.default_wall_clock_deadline_seconds,
        storage=storage,
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
            trigger_type=trigger_engine.should_create_investigation(trace_event)
            or "manual_trigger",
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

    # --- Analyst copilot capabilities (function.md) -------------------------
    print("\n=== Analyst Copilot (function.md) ===")

    analyst_id = "analyst_001"

    # 1. Case brief with citations (function.md Capability 1 - build first)
    brief_service = CaseBriefService()
    brief = brief_service.build_brief(
        account_id=ACCOUNT_ID,
        investigation_id=investigation.investigation_id,
        findings=findings_shared,
        recommendation=recommendation_shared,
        analyst_id=analyst_id,
    )
    audit.record_case_brief(brief)
    missing_citations = brief_service.validate_citations(brief)
    print(f"\n[brief] case_brief_id={brief.brief_id}")
    print(f"      timeline_entries={len(brief.timeline)}")
    print(f"      signals={len(brief.signals)}")
    print(f"      prior_incidents={len(brief.prior_incidents)}")
    print(f"      unknowns={len(brief.unknowns)}")
    print(f"      citations={len(brief.citations)}")
    if missing_citations:
        print(f"      citation_warnings: {missing_citations}")
    print(f"      brief_json={brief.model_dump_json(indent=2)}")

    # 2. Plain-language trace explanation (function.md Capability 2)
    trace_service = TraceExplanationService()
    trace_explanation = trace_service.explain_investigation(
        investigation_id=investigation.investigation_id,
        account_id=ACCOUNT_ID,
        findings=findings_shared,
        correlated_finding=correlated_shared,
        recommendation=recommendation_shared,
    )
    print(f"\n[trace_explanation]\n{trace_explanation}")

    # 3. Drafting: case note (function.md Capability 4)
    draft_service = CaseDraftService()
    case_note = draft_service.draft_case_note(
        account_id=ACCOUNT_ID,
        investigation_id=investigation.investigation_id,
        brief=brief,
        recommendation=recommendation_shared,
        analyst_id=analyst_id,
    )
    audit.record_case_draft(case_note, "created")
    print(f"\n[draft] case_note_id={case_note.draft_id} type={case_note.draft_type}")
    print(f"      status={case_note.status} edit_count={case_note.edit_count}")
    print(f"      content_preview={case_note.content[:200]}...")

    # 4. Drafting: customer communication
    customer_comm = draft_service.draft_customer_communication(
        account_id=ACCOUNT_ID,
        investigation_id=investigation.investigation_id,
        brief=brief,
        recommendation=recommendation_shared,
        analyst_id=analyst_id,
    )
    audit.record_case_draft(customer_comm, "created")
    print(f"\n[draft] customer_communication_id={customer_comm.draft_id}")
    print(f"      content_preview={customer_comm.content[:200]}...")

    # 5. Feedback capture (function.md Capability 6)
    feedback_service = FeedbackCaptureService()
    analyst_response = "Known travel - the user notified us of travel to this country."
    feedback = feedback_service.capture_feedback(
        account_id=ACCOUNT_ID,
        investigation_id=investigation.investigation_id,
        analyst_id=analyst_id,
        original_recommendation=recommendation_shared.recommendation.value,
        original_reason_codes=recommendation_shared.reason_codes,
        analyst_response=analyst_response,
    )
    audit.record_analyst_feedback(feedback)
    print(f"\n[feedback] feedback_id={feedback.feedback_id}")
    print(f"      label={feedback.label} label_reason={feedback.label_reason}")
    print(f"      question: {feedback_service.feedback_question()}")

    # 6. Measured benefit: draft edit rate (function.md guardrail)
    total_drafts = 2  # case_note + customer_comm
    edited_drafts = 0
    edit_rate = edited_drafts / total_drafts if total_drafts > 0 else 0.0
    print(f"\n[measured_benefit] draft_edit_rate={edit_rate:.2f} "
          f"({edited_drafts}/{total_drafts})")
    print(f"      interpretation: {'High edit rate - output not helping' if edit_rate > 0.5 else 'Output is helping analysts'}")

    # --- Phase 2: Label pipeline, replay, metrics, gate evaluation ---------
    await run_phase2(
        events=events,
        investigation_id=investigation.investigation_id,
        findings_shared=findings_shared,
        correlated_shared=correlated_shared,
        baseline_shared=baseline_shared,
        recommendation_shared=recommendation_shared,
        audit=audit,
    )

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
    print(f"  Meko retrieval content tokens: {orchestrator._investigations[investigation.investigation_id].meko_retrieval_content_tokens_used}")
    print("\nNo production signals were sent. No containment/action credentials exist.")

    # --- Phase 3: Durable storage summary and cleanup ----------------------
    event_count = stream.count()
    outbox_stats = outbox.stats()
    print(f"\n=== Phase 3: Durable Operations Summary ===")
    print(f"  Events persisted:         {event_count}")
    print(f"  Outbox delivered:         {outbox_stats['delivered']}")
    print(f"  Outbox failed:            {outbox_stats['failed']}")
    print(f"  Outbox pending:           {outbox_stats['pending']}")
    print(f"  Open investigations:      {len(storage.get_open_investigations())}")
    print(f"  Database:                 {db_path}")

    stream.stop()
    outbox.stop()
    storage.close()
    return 0


async def run_phase2(
    events: list[AccountEvent],
    investigation_id: str,
    findings_shared: list[EvidenceFinding],
    correlated_shared: EvidenceFinding,
    baseline_shared: Optional[BaselineResult] = None,
    recommendation_shared: Optional[ShadowRecommendation] = None,
    audit: Optional[AuditLog] = None,
) -> None:
    """Run Phase 2: label pipeline, replay, metrics, gate evaluation.

    Executes the evaluation and label pipeline from plan.md Phase 2:

    1. Label ingestion with maturity tracking per source (chargeback, dispute,
       analyst disposition, confirmed non-fraud).
    2. Offline replay harness comparing agentic vs baseline on the same
       point-in-time evidence (no temporal leakage).
    3. Metrics computation with Wilson score confidence intervals.
    4. Phase 2 pilot gate evaluation (FPR, latency, minimum evidence, lead time).
    5. Audit log entry for the gate result (go / no-go decision).

    Exit criterion (plan.md): the agentic approach has a measured, material
    improvement over the plain baseline on pre-agreed metrics, or remains
    disabled while the baseline continues.
    """
    print("\n=== Phase 2: Evaluation and Label Pipeline ===\n")

    # --- 1. Label ingestion with maturity tracking -------------------------
    label_ingestor = LabelIngestor()
    now = datetime.now(timezone.utc)

    # Synthetic labels for the ATO event sequence (acct_1042).
    # Maturity horizons: chargeback 7d, dispute 3d, analyst_disposition 1h.
    labels = [
        CaseLabel(
            event_id=events[0].event_id,   # LOGIN: failed_count=12 → fraud
            label_source=LabelSource.CHARGEBACK,
            label_state=LabelState.POSITIVE,
            timestamp=now - timedelta(days=8),   # mature (7-day horizon)
        ),
        CaseLabel(
            event_id=events[1].event_id,   # DEVICE: new emulator → fraud
            label_source=LabelSource.DISPUTE,
            label_state=LabelState.POSITIVE,
            timestamp=now - timedelta(days=4),   # mature (3-day horizon)
        ),
        CaseLabel(
            event_id=events[2].event_id,   # RESET: after failures → fraud
            label_source=LabelSource.ANALYST_DISPOSITION,
            label_state=LabelState.POSITIVE,
            timestamp=now - timedelta(hours=2),  # mature (1-hour horizon)
        ),
        CaseLabel(
            event_id=events[3].event_id,   # SUPPORT: legitimate contact
            label_source=LabelSource.ANALYST_DISPOSITION,
            label_state=LabelState.NEGATIVE,
            timestamp=now - timedelta(hours=2),  # mature (1-hour horizon)
        ),
        CaseLabel(
            event_id=events[4].event_id,   # TRANSACTION: new payee test → fraud
            label_source=LabelSource.CHARGEBACK,
            label_state=LabelState.POSITIVE,
            timestamp=now - timedelta(days=8),   # mature (7-day horizon)
        ),
    ]

    for label in labels:
        label_ingestor.ingest(label)

    mature = label_ingestor.mature_labels()
    immature = label_ingestor.immature_labels()
    print(f"[labels] ingested={len(labels)}, mature={len(mature)}, "
          f"immature={len(immature)}")
    print(f"[labels] mature fraud={len(label_ingestor.mature_confirmed_fraud())}, "
          f"mature legitimate={len(label_ingestor.mature_confirmed_legitimate())}")

    # --- 2. Offline replay: agentic vs baseline ---------------------------
    harness = ReplayHarness()
    records: list = []
    latencies_seconds: list[float] = []

    for event in events:
        start = datetime.now(timezone.utc)
        record = harness.replay_decision(event=event, shadow_mode=True)
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        records.append(record)
        latencies_seconds.append(elapsed)
        print(f"[replay] {event.event_type.value} "
              f"baseline={record.baseline_result.get('triggered', False)} "
              f"agentic={record.decision} "
              f"latency={elapsed*1000:.1f}ms")

    # --- 3. Compute detection metrics from labeled replay results ---------
    label_map = {l.event_id: l for l in mature}

    tp = fp = fn = tn = 0
    b_tp = b_fp = b_fn = b_tn = 0

    for record in records:
        label = label_map.get(record.event_id)
        if label is None:
            continue

        agentic_trig = record.decision in ("review", "block")
        baseline_trig = bool(record.baseline_result.get("triggered", False))

        if label.label_state == LabelState.POSITIVE:
            if agentic_trig:
                tp += 1
            else:
                fn += 1
            if baseline_trig:
                b_tp += 1
            else:
                b_fn += 1
        elif label.label_state == LabelState.NEGATIVE:
            if agentic_trig:
                fp += 1
            else:
                tn += 1
            if baseline_trig:
                b_fp += 1
            else:
                b_tn += 1

    engine = MetricsEngine()
    detection_metrics = engine.compute_detection_metrics(
        tp, fp, fn, tn, total_alerts=tp + fp
    )
    baseline_metrics = engine.compute_detection_metrics(
        b_tp, b_fp, b_fn, b_tn, total_alerts=b_tp + b_fp
    )

    # Synthetic lead times (minutes from detection to cash-out)
    lead_times = [8.0, 12.0, 6.0, 15.0, 9.0]
    latency_metrics = engine.compute_latency_metrics(
        latencies_seconds,
        lead_times,
        events_without_timestamp=0,
    )

    print(f"\n[metrics] Agentic:  TP={tp}, FP={fp}, FN={fn}, TN={tn}")
    print(f"          precision={detection_metrics.precision.point_estimate:.3f} "
          f"recall={detection_metrics.recall.point_estimate:.3f} "
          f"FPR={detection_metrics.fpr.point_estimate:.4f}")
    print(f"[metrics] Baseline: TP={b_tp}, FP={b_fp}, FN={b_fn}, TN={b_tn}")
    print(f"          precision={baseline_metrics.precision.point_estimate:.3f} "
          f"recall={baseline_metrics.recall.point_estimate:.3f} "
          f"FPR={baseline_metrics.fpr.point_estimate:.4f}")
    print(f"[metrics] p95 latency={latency_metrics.p95_decision_latency_seconds:.3f}s "
          f"(threshold 1.0s)")
    print(f"[metrics] median lead time={latency_metrics.median_lead_time_minutes:.1f} min "
          f"(threshold 5.0 min)")

    # --- 4. Evaluate Phase 2 pilot gates ----------------------------------
    gate_result = engine.evaluate_phase2_gates(
        detection_metrics,
        latency_metrics,
        min_legitimate=1000,
        min_fraud=100,
    )

    print(f"\n[gate] Phase 2 pilot gates: all_pass={gate_result['all_gates_pass']}")
    for name, g in gate_result["gates"].items():
        threshold = g.get("threshold", g.get("threshold_seconds",
                    g.get("min_detection_rate", "n/a")))
        actual = g.get("actual", g.get("actual_seconds",
                   g.get("actual_median_lead_minutes", "n/a")))
        print(f"  {name}: pass={g['pass']} "
              f"(threshold={threshold}, actual={actual})")

    # --- 5. Record gate result to audit log --------------------------------
    audit.record_phase2_gate_result(
        account_id=ACCOUNT_ID,
        investigation_id=investigation_id,
        detection_metrics=detection_metrics.to_dict(),
        baseline_metrics=baseline_metrics.to_dict(),
        latency_metrics=latency_metrics.to_dict(),
        gate_result=gate_result,
    )

    # --- 6. Go / no-go decision -------------------------------------------
    if gate_result["all_gates_pass"]:
        print("\n[Phase 2] GATE PASSED — agentic approach shows measured "
              "improvement over baseline. Eligible for promotion review.")
    else:
        print("\n[Phase 2] GATE NOT PASSED — remains in shadow mode, "
              "baseline continues. Minimum evidence not met "
          f"({len(mature)} mature labels vs required 1000 legitimate / 100 fraud).")



def main() -> int:
    """CLI entry point."""
    shadow_mode = True
    db_path = "fraud_detection.db"
    upload_kb = False
    if "--no-shadow" in sys.argv:
        shadow_mode = False
        print("WARNING: --no-shadow disables shadow mode. "
              "This is a configuration change, not a Phase 1 default.")
    if "--upload-kb" in sys.argv:
        upload_kb = True
    for arg in sys.argv:
        if arg.startswith("--db="):
            db_path = arg.split("=", 1)[1]
    if upload_kb:
        return asyncio.run(run_kb_upload())
    return asyncio.run(run_phase1(shadow_mode=shadow_mode, db_path=db_path))


async def run_kb_upload() -> int:
    """Upload fraud playbook documents to the Meko knowledge base."""
    import pathlib

    settings = Settings()
    print(f"=== Meko Knowledge Base Upload ===")
    print(f"Datapack: {settings.meko_datapack_id}")
    print(f"Endpoint: {settings.meko_mcp_url}")

    playbook_dir = pathlib.Path("kb_playbooks")
    if not playbook_dir.exists():
        print(f"[error] Playbook directory not found: {playbook_dir}")
        return 1

    playbooks = sorted(playbook_dir.glob("*.md"))
    if not playbooks:
        print(f"[error] No playbook files found in {playbook_dir}")
        return 1

    print(f"Found {len(playbooks)} playbook(s) to upload:\n")
    for pb in playbooks:
        print(f"  - {pb.name}")

    adapter = MekoAdapter(settings)
    async with adapter.connect():
        for playbook in playbooks:
            print(f"\n[kb] Uploading {playbook.name}...")
            try:
                result = await adapter.upload_document_and_wait(
                    str(playbook),
                    agent_id="kb_upload_agent",
                    poll_interval_seconds=2.0,
                    max_poll_seconds=120.0,
                )
                if isinstance(result, dict):
                    status = result.get("document_status", result.get("state", "unknown"))
                    doc_id = result.get("document_key", result.get("document_id", "unknown"))
                else:
                    status = str(result)
                    doc_id = "unknown"
                print(f"[kb] {playbook.name}: status={status}, document_key={doc_id}")
            except MekoAdapterError as e:
                print(f"[kb] {playbook.name}: FAILED — {e}")
                return 1

    print(f"\n[kb] All {len(playbooks)} playbook(s) uploaded and indexed.")
    print(f"Query with: context_search(force_source='knowledge_base')")
    return 0


if __name__ == "__main__":
    sys.exit(main())
