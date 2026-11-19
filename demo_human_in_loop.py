"""Immediate next-step demo: human-in-the-loop containment.

Demonstrates the flow:

  1. Shadow mode off, containment credentials + allowlist configured.
  2. MCP client / Claude proposes a containment action (temporary_hold).
  3. ContainmentGate.evaluate() validates gates (no shadow, credentials,
     allowlisted action) -> PROPOSED.
  4. Human analyst reviews and decides (approve / reject / escalate).
  5. Execution re-validates at execution time (shadow off, credentials,
     allowlisted, human-approved, idempotency) -> EXECUTED or rejected.

No automated approval queue or executor (those are Phase 4). The human
analyst manually decides and this script simulates that decision.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone

# Allow running from project root without installation
sys.path.insert(0, "src")

from fraud_detection.containment import (
    ContainmentDecision,
    ContainmentGate,
    ContainmentProposal,
    ContainmentReviewDecision,
)
from fraud_detection.settings import Settings
from fraud_detection.audit import AuditLog


def main() -> int:
    # --- Step 0: Configure settings (shadow mode OFF) ----------------------
    settings = Settings()
    settings.shadow_mode = False
    print(f"[config] shadow_mode={settings.shadow_mode}")

    # --- Step 1: Configure containment credentials + allowlist -------------
    # These would come from a fraud-owner-approved source, not hard-coded
    # in production. Here we simulate them for the demo.
    credentials = {
        "action_provider": "sandbox_transaction_hold",
        "api_key": "sk_sandbox_demo_only",
        "expires_at": "2027-01-01T00:00:00Z",
    }
    allowlist = ["temporary_hold"]

    gate = ContainmentGate(settings)
    gate.configure_action_credentials(credentials, allowlist)
    print(f"[config] credentials configured, allowlist={allowlist}")

    # --- Step 2: MCP client / Claude proposes a containment action -------
    # Claude, having read signals from Meko, outputs a structured proposal.
    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=[
            "new_payee",
            "test_payment",
            "failed_login_velocity",
            "new_device",
            "emulator_detected",
            "password_reset_after_failures",
        ],
        evidence_refs=[
            "evt_login_001",
            "evt_device_001",
            "evt_reset_001",
            "evt_transaction_001",
        ],
        reversibility="reversible_within_24h",
        expiry_seconds=86400,
        proposed_by="claude_mcp_client",
    )

    # --- Step 3: Gate evaluates the proposal ------------------------------
    eval_result = gate.evaluate(proposal)
    print(f"\n[gate.evaluate] decision={eval_result.decision.value}")
    print(f"         reason: {eval_result.reason}")

    if eval_result.decision != ContainmentDecision.PROPOSED:
        print("[abort] proposal did not pass initial gates; cannot proceed to review.")
        return 1

    # Record the proposal in the audit log
    audit = AuditLog(log_path="audit.log")
    audit.record_containment_proposal(
        account_id=proposal.target,
        action_type=proposal.action_type,
        target=proposal.target,
        reason_codes=proposal.reason_codes,
        evidence_refs=proposal.evidence_refs,
        reversibility=proposal.reversibility,
    )
    print("[audit] recorded containment proposal")

    # --- Step 4: Human analyst reviews ------------------------------------
    # Simulate an analyst decision. In production this comes from a human
    # via an approval UI, not from code.
    analyst_id = "analyst_jdoe"
    analyst_decision = ContainmentReviewDecision.APPROVE
    analyst_reason = "Correlated multi-agent high-confidence ATO pattern. " \
                     "Approving 24-hour temporary hold to prevent cash-out."

    review_result = gate.review(
        proposal=proposal,
        decision=analyst_decision,
        analyst_id=analyst_id,
        analyst_reason=analyst_reason,
        evidence_snapshot={
            "baseline_triggered": True,
            "agent_findings": [
                {"agent_id": "login_agent", "conclusion": "credential_stuffing_detected", "confidence": 0.8},
                {"agent_id": "device_agent", "conclusion": "suspicious_device", "confidence": 0.85},
                {"agent_id": "transaction_agent", "conclusion": "high_risk_transaction_sequence", "confidence": 0.85},
            ],
            "policy_version": "2026-11-v1",
        },
    )
    print(f"\n[gate.review] decision={review_result.decision.value}")
    print(f"         reason: {review_result.reason}")

    # Record the review in the audit log
    audit.record_containment_review(
        account_id=proposal.target,
        action_type=proposal.action_type,
        target=proposal.target,
        review_decision=analyst_decision.value,
        analyst_id=analyst_id,
        analyst_reason=analyst_reason,
        evidence_refs=proposal.evidence_refs,
        evidence_snapshot=review_result.review.evidence_snapshot if review_result.review else {},
        review_id=review_result.review.review_id if review_result.review else "",
    )
    print("[audit] recorded containment review")

    if analyst_decision != ContainmentReviewDecision.APPROVE:
        print(f"[abort] analyst did not approve (decision={analyst_decision.value}). No action executed.")
        return 0

    # --- Step 5: Execution with re-validation ------------------------------
    # The execution re-validates everything at execution time.
    exec_result = gate.execute(proposal, analyst_id=analyst_id)
    print(f"\n[gate.execute] decision={exec_result.decision.value}")
    print(f"         executed={exec_result.executed}")
    print(f"         reason: {exec_result.reason}")
    if exec_result.executed_at:
        print(f"         executed_at={exec_result.executed_at.isoformat()}")
    if exec_result.actor:
        print(f"         actor={exec_result.actor}")

    # Record the execution in the audit log
    audit.record_containment_execution(
        account_id=proposal.target,
        action_type=proposal.action_type,
        target=proposal.target,
        executed=exec_result.executed,
        analyst_id=analyst_id,
        reason_codes=proposal.reason_codes,
        evidence_refs=proposal.evidence_refs,
        review_id=exec_result.review.review_id if exec_result.review else "",
        execution_reason=exec_result.reason,
        executed_at=exec_result.executed_at.isoformat() if exec_result.executed_at else None,
    )
    print("[audit] recorded containment execution")

    # --- Step 6: Idempotency check (duplicate execution attempt) ----------
    print("\n--- Idempotency check: duplicate execution attempt ---")
    dup_result = gate.execute(proposal, analyst_id=analyst_id)
    print(f"[gate.execute duplicate] decision={dup_result.decision.value}")
    print(f"         reason: {dup_result.reason}")
    print(f"         executed={dup_result.executed}")

    audit.record_containment_execution(
        account_id=proposal.target,
        action_type=proposal.action_type,
        target=proposal.target,
        executed=dup_result.executed,
        analyst_id=analyst_id,
        reason_codes=proposal.reason_codes,
        evidence_refs=proposal.evidence_refs,
        review_id=dup_result.review.review_id if dup_result.review else "",
        execution_reason=dup_result.reason,
    )

    print("\n=== Human-in-the-loop containment demo complete ===")
    print("No automated approval queue or executor (Phase 4).")
    print("Audit log updated at audit.log")
    return 0


if __name__ == "__main__":
    sys.exit(main())
