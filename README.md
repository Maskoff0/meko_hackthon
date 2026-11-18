# meko hackthon — Agentic Fraud Detection System

## What this is

A production-grade, agentic fraud detection system built as a **cross-channel takeover detector** covering **login + support + payment** signals, with an **analyst copilot** that explains every alert.

It detects account-takeover (ATO) patterns across channels:

| Channel | Signals detected |
|---------|------------------|
| Login | Credential stuffing, failed login velocity, new location/IP |
| Support | Password reset after failures, unusual timing, multiple resets |
| Payment | New payee, test payments, limit changes, cash-out sequences |

For each alert, the system produces a **shadow recommendation** (non-actionable in Phase 1) with reason codes, evidence provenance, confidence scores, and a plain-language explanation — so human analysts can review and act, not just react to a black-box score.

## Architecture (Phase 1)

```
ingest → trigger → bounded investigation → scoped agents → correlator →
Meko write/search → deterministic baseline → policy engine → shadow
recommendation → audit log → containment gate (denied in shadow mode)
```

Key boundaries:
- **Deterministic supervisor** owns investigation state, budgets, deadlines — not an LLM
- **Agent output is evidence, never authority** — the policy engine decides
- **Meko is enrichment only** — memory writes and context searches never execute containment
- **Proposal ≠ authority** — the containment gate denies all proposals in shadow mode
- **Append-only audit log** is the authoritative record; Meko traces are supplementary

## Package structure

```
src/fraud_detection/
    domain.py          # event, label, case, evidence, decision models
    ingestion.py       # validation, normalization, idempotency
    orchestration.py   # deterministic supervisor: triggers, state machine, budgets
    agents/            # scoped agents: login, device, reset, transaction, correlator
    baseline.py        # deterministic rules and velocity features
    policy.py          # versioned decisions, thresholds, abstention
    meko_adapter.py    # MCP transport and tool contracts (enrichment only)
    audit.py           # append-only decision record interface
    containment.py     # proposal validation — proposal is not authority
    settings.py        # validated configuration and secret loading
    cli.py             # local fixture/replay entry point (Phase 1 end-to-end)
tests/   unit/, contract/, replay/
```

## Setup

```powershell
# Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# Install the project
python -m pip install -e .

# Copy .env.example to .env and fill in your Meko API key and datapack ID
```

## Run

```powershell
# Phase 1 end-to-end synthetic flow (shadow mode — no action executed)
python main.py
```

Or via the installed script:

```powershell
fraud-detection
```

## Output example

```
[agent] login_agent: credential_stuffing_detected (confidence=0.8)
[agent] device_agent: suspicious_device (confidence=0.85)
[agent] reset_agent: reset_after_failures_unusual_time (confidence=0.75)
[agent] transaction_agent: high_risk_transaction_sequence (confidence=0.85)
[correlator] correlated_multi_agent_high_confidence (confidence=0.95)
[policy] recommendation=review uncertainty=high
[containment] decision=denied_shadow_mode executed=False
```

## Phase 1 constraints

- Synthetic or approved de-identified signals only — no production signals
- Shadow mode: recommendations are non-actionable (review/abstain only)
- No containment/action credentials or executable action path exists
- Meko integration credentials permitted for hosted memory writes/searches only

## Analyst copilot

Each alert includes:
- Reason codes (e.g., `new_payee`, `test_payment`, `failed_login_velocity`)
- Evidence provenance (which agent/source contributed what)
- Confidence scores per finding
- Baseline score and trigger rationale
- Policy and model versions for audit traceability

This gives analysts a clear, explainable narrative for every alert rather than an opaque score.
