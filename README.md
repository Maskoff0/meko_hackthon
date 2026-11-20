# meko hackthon — Agentic Fraud Detection System

A production-grade, agentic fraud detection system built as a **cross-channel takeover detector** covering **login + support + payment** signals, with an **analyst copilot** that explains every alert and a **phased human-approval containment model** that keeps agents in an evidence-only role.

It detects account-takeover (ATO) patterns across channels:

| Channel | Signals detected |
|---------|------------------|
| Login | Credential stuffing, failed login velocity, new location/IP |
| Device | New device, emulator detected |
| Support | Password reset after failures, unusual timing, multiple resets |
| Payment | New payee, test payments, limit changes, cash-out sequences |

For each alert, the system produces a **shadow recommendation** (non-actionable in shadow mode) with reason codes, evidence provenance, confidence scores, and a plain-language explanation — so human analysts can review and act, not just react to a black-box score.

---

## System flowchart

```mermaid
flowchart TB
    %% Phase 1 - Detection pipeline
    subgraph P1["PHASE 1 — Thin vertical slice (deterministic baseline + shadow mode)"]
        A[Synthetic Fixtures<br/>login/device/reset/support/transaction] --> B[Ingestor<br/>validate + deduplicate + normalize]
        B --> C[Durable Event Stream<br/>SQLite-backed append-only]
        C --> D[TriggerEngine<br/>new_signal_source / velocity / high_risk_event]
        D --> E[Orchestrator<br/>bounded investigation + budgets]
        E --> F[Phase 1a: Shared Meko Memory<br/>Login/Device/Reset/Support/Transaction agents]
        F --> G[CorrelatorAgent<br/>correlated_multi_agent_high_confidence]
        G --> H[BaselineEvaluator<br/>deterministic rules + velocity]
        H --> I[PolicyEngine<br/>shadow recommendation: review/abstain]
        I --> J[ContainmentGate<br/>proposal ≠ authority<br/>denied in shadow mode]
        J --> K[Audit Log<br/>append-only decision record]
        E --> L[Phase 1b: No-shared-Meko baseline path<br/>baseline comparison]
        F --> M[Outbox<br/>durable Meko delivery with retry/DLQ]
        M --> N[Meko MCP<br/>enrichment only]
    end

    %% Phase 2 - Evaluation
    subgraph P2["PHASE 2 — Evaluation and label pipeline"]
        P[Phase 2: LabelIngestor<br/>maturity horizons per source] --> Q[ReplayHarness<br/>offline replay, no temporal leakage]
        Q --> R[MetricsEngine<br/>precision/recall/FPR/FNR + Wilson CIs]
        R --> S[Phase 2 Gate<br/>FPR / latency / min evidence / lead time]
        S --> T[Go / No-Go decision<br/>recorded in audit log]
    end

    %% Phase 3 - Durable operations
    subgraph P3["PHASE 3 — Durable ingestion and shadow operations"]
        U[Phase 3: Monitoring<br/>SLOs: decision latency, Meko latency, ingestion lag] --> V[Snapshot + alerting]
        W[Storage & Stream<br/>SQLite + event stream + outbox] --> X[Restart recovery<br/>Orchestrator.recover()]
    end

    %% Phase 4 - Human approval
    subgraph P4["PHASE 4 — Human approval"]
        Y[Case Queue<br/>evidence timeline + assignment + escalation] --> Z[RBAC<br/>least privilege + separation of duties]
        Z --> AA[Sandbox Containment<br/>simulated execution + reversal]
        AA --> AB[Structured Labels<br/>feedback capture + adjudication]
    end

    %% Phase 5 - Limited reversible automation
    subgraph P5["PHASE 5 — Limited reversible automation"]
        AC[Reversible Automation Engine<br/>fresh checks + allowlist + kill switch] --> AD[Canary Rollout<br/>sandbox → cohort → full]
        AD --> AE[Reversal + Customer Notification<br/>+ incident procedures]
    end

    %% Phase 6 - Irreversible containment
    subgraph P6["PHASE 6 — Irreversible containment & production cutover"]
        AF[Irreversible Containment<br/>FRAUD_OWNER approval + independent review] --> AG[Appeals & Remediation<br/>customer recourse path]
        AG --> AH[Production Cutover<br/>SLO validation + stage transitions]
    end

    %% Cross-links
    K --> Y
    AB --> AF
    AH --> AD

    %% Styling
    style A fill:#e1f5fe,stroke:#01579b
    style B fill:#e8f5e9,stroke:#1b5e20
    style C fill:#fff3e0,stroke:#e65100
    style D fill:#f3e5f5,stroke:#4a148c
    style E fill:#e8f5e9,stroke:#1b5e20
    style F fill:#e3f2fd,stroke:#0d47a1
    style G fill:#e3f2fd,stroke:#0d47a1
    style H fill:#f3e5f5,stroke:#4a148c
    style I fill:#f3e5f5,stroke:#4a148c
    style J fill:#ffebee,stroke:#b71c1c
    style K fill:#e8f5e9,stroke:#1b5e20
    style M fill:#fff3e0,stroke:#e65100
    style P fill:#e3f2fd,stroke:#0d47a1
    style Q fill:#e3f2fd,stroke:#0d47a1
    style R fill:#f3e5f5,stroke:#4a148c
    style S fill:#ffebee,stroke:#b71c1c
    style T fill:#ffebee,stroke:#b71c1c
    style U fill:#e3f2fd,stroke:#0d47a1
    style V fill:#e3f2fd,stroke:#0d47a1
    style W fill:#e8f5e9,stroke:#1b5e20
    style X fill:#e8f5e9,stroke:#1b5e20
    style Y fill:#e3f2fd,stroke:#0d47a1
    style Z fill:#e3f2fd,stroke:#0d47a1
    style AA fill:#e3f2fd,stroke:#0d47a1
    style AB fill:#e3f2fd,stroke:#0d47a1
    style AC fill:#e3f2fd,stroke:#0d47a1
    style AD fill:#e3f2fd,stroke:#0d47a1
    style AE fill:#e3f2fd,stroke:#0d47a1
    style AF fill:#fce4ec,stroke:#880e4f
    style AG fill:#fce4ec,stroke:#880e4f
    style AH fill:#fce4ec,stroke:#880e4f

    linkStyle default stroke-width:2px
```

---

## System overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  PHASE 1 — Thin vertical slice (deterministic baseline + shadow mode)          │
│  ingest → trigger → bounded investigation → scoped agents → correlator →       │
│  Meko write/search → deterministic baseline → policy → shadow recommendation → │
│  audit log → containment gate (denied in shadow mode)                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│  PHASE 2 — Evaluation and label pipeline                                       │
│  LabelIngestor (maturity horizons) → ReplayHarness (no temporal leakage) →     │
│  MetricsEngine (Wilson CIs) → Phase 2 pilot gate → go/no-go decision           │
├─────────────────────────────────────────────────────────────────────────────────┤
│  PHASE 3 — Durable ingestion and shadow operations                             │
│  SQLite storage → durable event stream → outbox pattern → restart recovery →   │
│  monitoring/SLOs → outbox retry/dead-letter                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│  PHASE 4 — Human approval                                                      │
│  Case queue (evidence timeline + assignment + escalation) → RBAC (least        │
│  privilege + separation of duties) → Sandbox containment (simulated execution) │
│  → Structured labels (feedback capture + adjudication)                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│  PHASE 5 — Limited reversible automation                                       │
│  Reversible automation engine (fresh checks + allowlist + kill switch) →       │
│  Canary rollout (sandbox → cohort → full) → Reversal + customer notification   │
├─────────────────────────────────────────────────────────────────────────────────┤
│  PHASE 6 — Irreversible containment & production cutover                       │
│  Irreversible containment (FRAUD_OWNER approval + independent review) →        │
│  Appeals & remediation (customer recourse) → Production cutover (SLO validation│
│  + stage transitions)                                                          │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Key design principles

- **Deterministic supervisor** owns investigation state, budgets, deadlines — not an LLM
- **Agent output is evidence, never authority** — the policy engine decides
- **Meko is enrichment only** — memory writes and context searches never execute containment
- **Proposal ≠ authority** — the containment gate denies all proposals in shadow mode
- **Append-only audit log** is the authoritative record; Meko traces are supplementary
- **No temporal leakage** — replay uses only features available at decision time
- **Idempotent ingestion** — duplicate events by `idempotency_key` are rejected
- **Durable persistence** — SQLite storage survives process restarts; investigations recover on restart
- **Human-in-the-loop** — analysts approve containment; reversible actions limited to fraud-owner-approved allowlist; irreversible blocks require FRAUD_OWNER + independent review

---

## Phase-by-phase breakdown

### Phase 1 — Thin vertical slice and deterministic baseline

- Synthetic fixtures for login, device, reset, support, transaction events
- `Ingestor` validates, normalizes, and deduplicates by idempotency key
- `TriggerEngine` fires on `new_signal_source`, `velocity_window_crossing`, or `high_risk_event` (versioned rules)
- `Orchestrator` creates bounded investigations with tool/Meko/token budgets and wall-clock deadlines
- Six scoped agents (login, device, reset, support, transaction, correlator) write typed findings
- `MekoAdapter` writes signals to memory and searches context (enrichment only)
- `BaselineEvaluator` computes deterministic rules-and-velocity scores
- `PolicyEngine` emits shadow recommendations (`review` or `abstain` only — never block/allow)
- `ContainmentGate` enforces `proposal ≠ authority` (denied in shadow mode)
- ≥3 trace walkthroughs written to `trace_walkthroughs.json`
- Baseline comparison: shared Meko memory vs no-shared-Meko path
- Analyst copilot capabilities (function.md): case briefs with citations (MCP server), trace explanation, drafting, feedback capture, measured benefit

### Phase 2 — Evaluation and label pipeline

- `LabelIngestor` ingests labels with per-source maturity horizons (chargeback 7d, dispute 3d, analyst_disposition 1h, confirmed_non_fraud 7d)
- Immature labels excluded from mature-negative counts
- `ReplayHarness` performs offline replay comparing agentic vs baseline on point-in-time evidence
- Temporal leakage prevention: input snapshots pinned, fresh runs tracked separately
- `MetricsEngine` computes precision/recall/FPR/FNR with Wilson score CIs, cost, latency, cohort, and baseline-relative lift
- `evaluate_phase2_gates()` checks pilot gates: FPR ≤ 0.5%, p95 latency ≤ 1s, minimum evidence (1000 legit / 100 fraud), median lead time ≥ 5 min
- Gate result recorded to audit log as `phase2_gate_result`
- Track analyst-efficiency metrics: time from case open to decision, draft edit rate

### Phase 3 — Durable ingestion and shadow operations

- `Storage` — SQLite-backed durable persistence for events, investigations, findings, labels, recommendations, audit entries, outbox, dead letters
- `EventStream` — durable append-only stream with subscribe/dispatch, replay from offset, dead-letter queue
- `Outbox` — reliable Meko enrichment delivery with retry, backoff, and dead-letter on max attempts
- `Orchestrator.recover()` — restores open investigations from storage after restart
- `Monitor` — SLO collection: decision latency p95 ≤ 1s, Meko latency p95 ≤ 5s, ingestion lag, alert volume, label coverage
- All state survives process restarts; Meko is not a single point of failure

### Phase 4 — Human approval

- `CaseQueue` — case queue with evidence timeline, reason codes, model/rule versions, label state, assignment, escalation, close/resolve
- `RBACManager` — role-based access control with least privilege (analyst, senior_analyst, supervisor, fraud_owner, auditor roles; 10 permissions); separation of duties: approver ≠ executor
- `SandboxContainmentService` — simulated containment execution (no real actions), reversal, customer notification
- `LabelService` — structured analyst labels with adjudication workflow (independent review required before shared-knowledge promotion)
- Feedback capture: structured "why?" → labelled outcome → feedback loop (function.md Capability 6)

### Phase 5 — Limited reversible automation

- `ReversibleAutomationEngine` — executes reversible containment actions (temporary_hold, limit_reduction, payee_block, device_challenge, session_reset) only after fresh checks pass
- Fresh checks: kill switch, policy enabled, stage not rolled_back, allowlist, permissions, separation of duties, idempotency, budget, per-account daily limit, global hourly limit, evidence confidence, Meko availability, reversal path, cohort membership, drift bounds, false positive rate
- Deterministic fallback on budget exhaustion, uncertain evidence, policy conflict, Meko outage, drift detection, kill switch, guardrail violation, insufficient permissions, not allowlisted, idle timeout
- Canary rollout: sandbox → cohort_1 → cohort_2 → full → rolled_back (automatic rollback on guardrail violations)
- Reversal of executed actions; customer notification; incident procedures
- Draft edit rate tracking for measured benefit

### Phase 6 — Irreversible containment & production cutover

- `IrreversibleContainmentService` — irreversible actions (permanent_block, fund_freeze, irreversible_payee_block, account_closure) with NO automation path
- FRAUD_OWNER approval required; independent review by a different analyst before approval
- Separation of duties: approver cannot execute; executor must be a different FRAUD_OWNER
- Customer notification before execution (mandatory pre-condition); remediation availability check
- Appeals workflow (file → review → grant/deny with remediation type); remediation records (fund restoration, account reinstatement, payee unblock, goodwill credit, other)
- Exceptional revocation (FRAUD_OWNER only, when original determination was incorrect)
- `ProductionCutoverService` — stage transitions (shadow → human_approval → limited_automation → full_production → rolled_back)
- Final SLO validation required before advancing to automation/production stages
- Guardrail snapshots at each stage; automatic rollback on violations

---

## Package structure

```
src/fraud_detection/
    domain.py          # event, label, case, evidence, decision models (all phases)
    ingestion.py       # validation, normalization, idempotency (Phase 1)
    orchestration.py   # deterministic supervisor: triggers, state machine, budgets, recovery (Phase 1+3)
    agents/            # scoped agents: login, device, reset, transaction, correlator (Phase 1)
    baseline.py        # deterministic rules and velocity features (Phase 1)
    policy.py          # versioned decisions, thresholds, abstention (Phase 1)
    meko_adapter.py    # MCP transport and tool contracts (enrichment only) (Phase 1)
    audit.py           # append-only decision record interface (all phases)
    containment.py     # proposal validation — proposal is not authority (Phase 1+4)
    analyst.py         # analyst copilot: case briefs, trace explanation, pattern lookup, drafting, triage, feedback (function.md)
    mcp_server.py      # MCP server exposing analyst capabilities (function.md: case brief via MCP server)
    case_queue.py      # case queue with evidence timeline + assignment/escalation (Phase 4)
    rbac.py            # role-based access control + separation of duties (Phase 4)
    sandbox_containment.py  # sandbox containment: simulated execution + reversal (Phase 4)
    label_service.py   # structured analyst labels + adjudication workflow (Phase 4)
    reversible_automation.py  # reversible automation engine + canary rollout (Phase 5)
    irreversible_containment.py  # irreversible containment + appeals + remediation (Phase 6)
    production_cutover.py  # production cutover stages + SLO validation (Phase 6)
    settings.py        # validated configuration and secret loading (all phases)
    cli.py             # local fixture/replay entry point (Phases 1+2+3 + analyst copilot)
    storage.py         # SQLite durable storage (Phase 3)
    stream.py          # durable event stream with replay/DLQ (Phase 3)
    outbox.py          # outbox pattern with retry/dead-letter (Phase 3)
    monitoring.py      # SLO collection and snapshot (Phase 3)
    labeling.py        # LabelIngestor with maturity horizons (Phase 2)
    replay.py          # ReplayHarness for offline replay (Phase 2)
    metrics.py         # MetricsEngine with Wilson CIs and gate eval (Phase 2)
    triggers.py        # TriggerEngine with versioned rules (Phase 2)
tests/
    unit/              # test_baseline, test_ingestion, test_agents, test_labeling, test_metrics, test_replay, test_triggers
    contract/          # test_label_contracts, test_mcp_schemas (plan.md line 24)
    phase3/            # test_phase3 (storage, stream, outbox, orchestrator, monitoring)
    phase4/            # test_phase4 (case queue, RBAC, sandbox containment, labels)
    phase5/            # test_phase5 (reversible automation, fresh checks, canary rollout, reversal)
    phase6/            # test_phase6 (irreversible containment, appeals, remediation, cutover)
```

---

## Setup

```powershell
# Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# Install the project
python -m pip install -e .

# Copy .env.example to .env and fill in your Meko API key and datapack ID
```

## Run

### Phase 1 end-to-end synthetic flow (shadow mode — no action executed)

```powershell
python main.py
```

Or via the installed script:

```powershell
fraud-detection
```

### Phase 3 with durable storage

```powershell
# Specify a custom database path
python main.py --db=fraud_detection.db

# Disable shadow mode (configuration change — requires credentials configured)
python main.py --no-shadow --db=fraud_detection.db
```

### Analyst copilot via MCP server

```powershell
# Run the MCP server exposing analyst capabilities (function.md Capability 1 - build first)
python -m fraud_detection.mcp_server
```

The MCP server exposes 12 tools: `generate_case_brief`, `explain_trace`, `explain_investigation`, `lookup_patterns`, `draft_case_note`, `draft_customer_communication`, `draft_regulator_explanation`, `build_triage_queue`, `capture_feedback`, `edit_draft`, `sign_draft`, `get_draft_edit_rate`.

---

## Output example

```
=== Phase 1 Fraud Detection (shadow_mode=True) ===

[phase3] durable storage=fraud_detection.db, recovered=0 open investigation(s)
[ingest] login for acct_1042: ACCEPTED
[ingest] device for acct_1042: ACCEPTED
[ingest] reset for acct_1042: ACCEPTED
[ingest] support for acct_1042: ACCEPTED
[ingest] transaction for acct_1042: ACCEPTED
[trigger] login triggered new_signal_source: new signal source 'synthetic_login_agent' for account acct_1042

[investigate] created b36ccf44-6c74-4ef0-bd38-84d5fd995d80 (trigger=new_signal_source, budget=10 tool calls, 5 Meko retrievals)

--- Phase 1a: Shared Meko memory path ---
[agent] login_agent: credential_stuffing_detected (confidence=0.8)
[agent] device_agent: suspicious_device (confidence=0.85)
[agent] reset_agent: reset_after_failures_unusual_time (confidence=0.75)
[agent] support_agent: support_takeover_pattern (confidence=0.75)
[agent] transaction_agent: routine_transaction (confidence=0.1)
[budget] Meko retrieval budget exhausted after transaction_agent
[correlator] correlated_multi_agent_high_confidence (confidence=0.95)
[meko] wrote 5 signal(s) to memory
[meko] context search match_quality=mid

--- Phase 1b: No-shared-Meko baseline path ---
[no-meko] findings=5, correlated=correlated_multi_agent_high_confidence (confidence=0.95)
[baseline shared] triggered=False score=0.00 reason_codes=[]
[baseline no-meko] triggered=False score=0.00 reason_codes=[]

[policy shared] recommendation=review uncertainty=high
[policy no-meko] recommendation=review uncertainty=high

[containment] decision=denied_shadow_mode executed=False
  reason: shadow_mode is enabled; containment proposals are logged only and never executed

=== Trace Walkthroughs ===
[trace 1] login -> agent=credential_stuffing_detected -> baseline=False -> policy=review -> containment=denied_shadow_mode
[trace 2] device -> agent=suspicious_device -> baseline=False -> policy=review -> containment=denied_shadow_mode
[trace 3] reset -> agent=reset_after_failures_unusual_time -> baseline=False -> policy=review -> containment=denied_shadow_mode

=== Analyst Copilot (function.md) ===
[brief] case_brief_id=... timeline_entries=5 signals=5 prior_incidents=0 unknowns=2 citations=5
[trace_explanation] Investigation ... for account acct_1042:
  • login_agent found 'credential_stuffing_detected' (confidence 80%, reason codes: failed_login_velocity, high_failure_rate).
  • ...
[draft] case_note_id=... type=case_note status=draft edit_count=0
[draft] customer_communication_id=... status=draft edit_count=0
[feedback] feedback_id=... label=false_positive: known travel label_reason=Analyst identified the activity as known travel.
  question: Why do you disagree with this recommendation?
[measured_benefit] draft_edit_rate=0.00 (0/2) interpretation: Output is helping analysts.

=== Phase 2: Evaluation and Label Pipeline ===
[labels] ingested=5, mature=5, immature=0
[replay] login baseline=False agentic=abstain latency=0.4ms
[replay] transaction baseline=True agentic=review latency=0.2ms
[gate] Phase 2 pilot gates: all_pass=False
  minimum_evaluation_evidence: pass=False (5 mature labels vs required 1000/100)
[Phase 2] GATE NOT PASSED — remains in shadow mode, baseline continues

=== Phase 3: Durable Operations Summary ===
  Events persisted:         5
  Outbox delivered:         5
  Outbox failed:            0
  Open investigations:      4
  Database:                 fraud_detection.db
```

---

## Phase 1 constraints

- Synthetic or approved de-identified signals only — no production signals
- Shadow mode: recommendations are non-actionable (review/abstain only)
- No containment/action credentials or executable action path exists in Phase 1
- Meko integration credentials permitted for hosted memory writes/searches only

---

## Analyst copilot (function.md)

Six capabilities delivered through the MCP server:

| Capability | Description | function.md ref |
|------------|-------------|-----------------|
| Case briefs on demand | One-screen brief from decision log + Meko context with ordered timeline, per-agent confidence, prior incidents, unknowns. Every claim cites a source ID. | Capability 1 (build first) |
| Trace explanation | Plain-language translation of agent traces; raw trace stays record of truth | Capability 2 |
| Pattern lookup | Hybrid retrieval against knowledge base and past confirmed cases | Capability 3 |
| Drafting, not deciding | Drafts case notes, customer communications, regulator-facing explanations; analyst edits and signs | Capability 4 |
| Triage ordering | Queue summarization with "why ranked high" explanation; deterministic ranking | Capability 5 |
| Feedback capture | Structured "why?" → labelled outcome → feedback loop | Capability 6 |
| Measured benefit | Time from case open to decision; draft edit rate | Guardrails |

Analyst copilot guardrails:
- **Read-only by default** — can create pending requests and drafts, cannot approve containment or write to the official record
- **Cited claims** — every factual claim cites a source ID; no citation, no claim
- **Untrusted text** — attacker-controlled text marked as data so it cannot steer outputs
- **Logging** — every brief and draft generation logged with analyst ID
- **Measured benefit** — track time from case open to decision and draft edit rate

---

## Audit log

The append-only `audit.log` is the authoritative decision record. Entry types include:

| Type | Description | Phase |
|------|-------------|-------|
| `event` | Incoming synthetic event | 1 |
| `ingestion_result` | Accepted/duplicate/rejected | 1 |
| `investigation_created` | Investigation opened | 1 |
| `finding` | Agent finding | 1 |
| `recommendation` | Shadow recommendation | 1 |
| `containment_proposal` | Containment proposal (shadow mode) | 1 |
| `containment_review` | Human analyst review decision | 4 |
| `containment_execution` | Execution result | 4 |
| `phase2_gate_result` | Phase 2 gate evaluation | 2 |
| `investigation_transition` | State change | 1 |
| `case_brief` | Case brief generation (analyst ID) | Analyst |
| `case_draft` | Case draft creation/edit/sign (analyst ID) | Analyst |
| `analyst_feedback` | Structured analyst feedback (analyst ID) | Analyst/4 |
| `case_assignment` | Case assign/reassign/escalate | 4 |
| `case_closed` | Case closure | 4 |
| `case_resolved` | Case resolution | 4 |
| `case_label_updated` | Label state update | 4 |
| `access_control` | RBAC allow/deny decision | 4 |
| `guardrail_violation` | Automation guardrail violation | 5 |
| `automation_executed` | Reversible automation execution | 5 |
| `automation_denied` | Automation denial with fresh checks | 5 |
| `automation_fallback` | Deterministic fallback applied | 5 |
| `automation_reversed` | Automation reversal | 5 |
| `customer_notification` | Customer notification sent | 5/6 |
| `automation_incident_opened` | Incident opened | 5 |
| `automation_incident_closed` | Incident closed | 5 |
| `irreversible_containment_proposed` | Irreversible action proposed | 6 |
| `irreversible_containment_independent_review` | Independent review recorded | 6 |
| `irreversible_containment_approved` | FRAUD_OWNER approval | 6 |
| `irreversible_containment_rejected` | FRAUD_OWNER rejection | 6 |
| `irreversible_containment_executed` | Irreversible action executed | 6 |
| `irreversible_containment_customer_notified` | Customer notified before execution | 6 |
| `irreversible_containment_remediation_marked` | Remediation availability marked | 6 |
| `irreversible_containment_appeal_filed` | Customer appeal filed | 6 |
| `irreversible_containment_appeal_reviewed` | Appeal review decision | 6 |
| `irreversible_containment_remediation_created` | Remediation record created | 6 |
| `irreversible_containment_remediation_completed` | Remediation completed | 6 |
| `irreversible_containment_revoked` | Exceptional revocation | 6 |
| `production_slo_validation` | Final SLO validation result | 6 |
| `production_guardrail_snapshot` | Guardrail snapshot at cutover stage | 6 |
| `production_cutover_advanced` | Stage transition | 6 |
| `production_cutover_rollback` | Rollback to rolled_back | 6 |

---

## Running tests

```powershell
# Install test dependencies
python -m pip install pytest

# Run all tests (200 tests across all 6 phases)
python -m pytest tests/ -v

# Run specific phase tests
python -m pytest tests/phase1/ -v
python -m pytest tests/phase4/ -v
python -m pytest tests/phase5/ -v
python -m pytest tests/phase6/ -v

# Run contract tests (MCP schemas, label contracts)
python -m pytest tests/contract/ -v

# Run unit tests
python -m pytest tests/unit/ -v
```

## Data persistence

Events, investigations, findings, labels, recommendations, audit entries, outbox messages, and dead letters are persisted to `fraud_detection.db` (SQLite, WAL mode). The database path is configurable via `--db=`.

On restart, `Orchestrator.recover()` reloads open investigations from storage so work resumes safely.

---

## Cross-cutting engineering and risk controls

- **Monitor events, not Meko**: agents subscribe to the application's durable event stream
- **Bound every investigation**: persist an investigation/task object with scope, trigger, hypothesis, allowed tools, budgets, deadline, state, policy version
- **Use structured handoffs**: agents write schema-validated findings; next agent reads and verifies evidence references
- **Enforce least privilege**: per-agent tool/read/write allowlists; separation of duties (approver ≠ executor)
- **Keep supervision deterministic**: ordinary code owns task transitions, deadlines, budget accounting; humans can pause/resume/reassign with audit
- **Separate proposal from authority**: correlator may propose; proposal is untrusted input to policy, not authorization
- **Re-check at the point of execution**: containment service independently checks stage, policy, permissions, allowlist, evidence, expiry, idempotency, rate limits, kill switch, audit availability
- **Memory poisoning and prompt injection**: treat support text, payee names, device strings, retrieved memories as attacker-controlled data; validate signal fields; keep free text out of system instructions
- **Deterministic replay and model governance**: pin provider/model/prompt/tool/policy versions; store exact input snapshots; replay recorded outputs
- **Privacy, retention, and provider exit**: decide explicitly what PII enters Meko; prefer tenant-scoped tokens; keep Meko behind an adapter with contract tests and provider-exit path
- **Audit source of truth**: application-owned append-only log; Meko memories are supplementary context only

---

## Rollout and release checklist

1. **Local development and Meko integration**: local synthetic fixtures and deterministic tests; integration checks with hosted Meko using synthetic or approved de-identified data
2. **Offline replay**: mature labels, point-in-time features, baseline comparison, confidence intervals
3. **Shadow**: real-time recommendations and hosted Meko memory operations only within approved data boundaries; actions disabled
4. **Human approval**: sandbox first, then explicitly scoped operational queue and downstream action
5. **Limited automation**: reversible actions only, cohort and rate-limited, with kill switch and rollback
6. **Automatic hold/block**: only separately approved scopes, after customer recourse, failure behavior, independent review, and all numerical gates pass

Every release must have a named owner, reviewed changes, test/evaluation report, monitoring and rollback plan, and a recorded go/no-go decision.

---

## Decisions intentionally left open

- Target product/rail, event volume, latency budget, and fraud-specific cost model
- Exact false-positive, agreement, lead-time, and latency limits after historical measurement and stakeholder ratification
- Label maturity windows by source and product
- Database, queue, web framework, model provider, cloud/BYOC deployment, and retention durations
- Which actions are reversible and which human roles can authorize them
- Which specific reversible actions and eligibility criteria fraud owners will approve for the automation allowlist
- Whether hosted Meko satisfies privacy, deletion, consistency, and operational requirements for any approved production data
