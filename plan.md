# Production-grade agentic fraud detection system

## Purpose and scope

This plan evolves the current Meko MCP demo into a fraud-detection service in stages. The first implementation target is a **locally run prototype that intentionally connects to the hosted Meko MCP endpoint** using configured Meko credentials to write and retrieve memory. Use synthetic or approved de-identified signals by default. Production signals may be sent only after explicit privacy and security approval and the required data controls are in place.

Meko memory writes and context searches are real hosted service operations, but they do not execute fraud containment. The prototype can produce only non-actionable recommendations or shadow results; containment/action credentials and execution remain disabled until a later phase receives its own approvals and passes its gates. Each authority increase is a separate release decision. A completed phase does not automatically enable the next one.

## What exists today

`main.py` currently combines:

- MCP transport setup and authentication.
- A `Meko` wrapper for creating conversations, writing memories, searching context, and recording decisions.
- `write_signal`, which formats signal data as both text and JSON for `memory_add`.
- `correlate` and `past_attack_patterns`, which retrieve contextual material through `context_search`.
- `record_decision`, which records a conversation and trace artifact.
- `demo()`, which submits hard-coded example signals to the hosted Meko endpoint, searches context, and records a fixed `"block"` value in a trace.

This is useful for exercising live Meko memory and retrieval, but it is not an event-ingestion service, fraud classifier, approval system, or action executor. The `"block"` value is only recorded in the demo trace; no transaction or account action is performed. Replace it with a non-actionable recommendation/shadow result before using the demo as the prototype path. MCP server schemas have already required iteration; schema contract tests should be part of the adapter from the start.

## Target architecture

Keep boundaries small and explicit. Avoid choosing a cloud, database, queue, or model provider until the operating contract and measured workload justify the choice.

1. **Event ingress and durable stream** — accepts authenticated, schema-validated login, device, reset, and transaction events and publishes them to a durable event stream. Every event carries a schema version and stable idempotency key. Agents subscribe to this stream; they do not poll Meko or one another for work.
2. **Explicit trigger rules** — create or update an account investigation when an account-level signal arrives from a new source, a configured velocity-window threshold is crossed, or a high-risk step occurs (for example, payee change, reset, or limit change). Correlation runs at these trigger points rather than on every signal. Trigger and deduplication rules are versioned and tested.
3. **Canonical event, investigation, and case models** — record event and observation times, source, entity tokens, provenance, schema version, and idempotency key. An investigation task contains account/entity scope, trigger, hypothesis, allowed evidence/tools, budget, deadline, and status. State changes are owned by the supervisor and persisted so work can resume safely.
4. **Agent roles and structured handoffs** — narrowly scoped agents may collect or assess evidence available to their task. Each writes a typed result to the investigation record with conclusion, confidence, reason codes, and evidence references. The correlator reads these records and verifies references; it does not trust another agent’s free-text prompt or result as instruction.
5. **Deterministic supervisor** — ordinary code, not an LLM, owns the investigation state machine, trigger deduplication, task assignment, permissions, deadlines, budgets, timeouts, retries, escalation, and terminal state. It can halt work. Human reviewers can pause, resume, or reassign an investigation with an audit record.
6. **Deterministic baseline and decision policy** — rules and velocity features provide a transparent, reproducible comparison independent of Meko or an LLM. A versioned policy combines validated evidence and agent findings to recommend, abstain, or route to review. Agent output is evidence, never authority.
7. **Agentic enrichment** — uses a replaceable Meko adapter to make real requests to the configured hosted Meko endpoint for approved memory writes and context retrieval. Prototype requests use synthetic or approved de-identified signals; production signals require explicit privacy/security approval. Retrieved text and user-controlled fields are untrusted data, never instructions. Meko is not the event bus, task queue, case store, or sole source of truth.
8. **Authoritative audit and case store** — an application-owned append-only decision/event history records exact inputs or privacy-safe references, investigation transitions, evidence handoffs, budgets, policy/model/prompt versions, outputs, approvals, proposals, and action results. Meko traces are supplementary.
9. **Approval and containment boundaries** — an agent may submit a structured containment proposal, but that proposal is not authorization. A separate containment service re-checks current policy stage, permissions, action allowlist, kill switch, idempotency, and audit requirements before execution. Human approval is required in that stage; later automation is limited to fraud-owner-approved, reversible actions.
10. **Operations and evaluation** — dashboards, SLOs, alerting, label maturation, offline replay, drift monitoring, cost/budget tracking, incident response, and controlled rollout.

## Ground truth, metrics, and promotion gates

Define label sources and their limitations before treating shadow results as evidence:

- **Chargebacks/payment-network outcomes:** strongest for some payment fraud types, but delayed and incomplete; record the source, effective date, and the applicable scheme/reporting maturity window.
- **Customer disputes and account-recovery reports:** useful but may be mistaken, duplicated, or arrive late; retain source and adjudication status rather than treating every report as certain.
- **Analyst dispositions:** timely but subjective; capture reviewer, reason code, evidence available at decision time, and whether a second review confirmed the disposition.
- **Confirmed non-fraud:** do not infer this only from the absence of a chargeback. Require a defined maturity horizon and preserve an “unknown/unresolved” label state.

For each label source, measure the empirical time from event to first label and to stable/adjudicated label. Set the evaluation maturity horizon from those distributions and contractual reporting windows; exclude immature examples from false-positive and false-negative denominators. Report metrics by event type, customer cohort, and action severity with confidence intervals.

The following are **proposed initial pilot gates**, not validated business limits. Fraud, risk, legal, and operations owners must ratify or replace them using historical prevalence, customer impact, and confidence intervals before any promotion:

| Gate | Candidate initial threshold | Measurement |
|---|---:|---|
| High-risk false-positive rate | At most 0.5% of mature, confirmed legitimate eligible events | Mature labels only; report by segment and include the upper confidence bound. Do not mask a bad segment with an aggregate. |
| Analyst agreement | At least 80% agreement on high-risk recommendations, and Cohen’s kappa at least 0.70 on double-reviewed cases | Blind reviewers to the agent recommendation for a subset; report disagreements and abstentions. |
| Pre-cash-out detection lead time | Detect at least 70% of confirmed eligible fraud before cash-out; median lead time at least 5 minutes | Compute from event and cash-out timestamps; report the distribution and the fraction with no usable timestamp. Ratify per payment rail/product. |
| Synchronous decision latency | p95 at most 1 second for the local policy decision using already-available evidence | Measure end-to-end from validated event to decision; report p50/p95/p99 and segment by cold/warm path. |
| Context enrichment budget | Meko must not block the synchronous decision beyond a separately configured bounded timeout | Record connect, tool, and end-to-end latency; a timeout becomes an explicit degraded/abstain state. |
| Minimum evaluation evidence | At least 1,000 mature legitimate examples and 100 mature confirmed fraud examples for the overall pilot; each promoted high-impact segment must also meet a pre-agreed sample/confidence requirement | If evidence is insufficient, continue shadow mode; do not lower the threshold or infer safety from a small sample. |

Also report precision, recall, alert volume, missed-fraud cost, customer friction, abstention rate, label coverage/maturity, and baseline-relative lift. No threshold alone authorizes action. Final promotion requires written sign-off, no unresolved critical safety/privacy issues, and successful rollback drills.

## Phased implementation backlog

### Phase 0 — Operating contract and event schema

**Goal:** settle the risks and data contract quickly, without trying to predict every issue before seeing a working slice.

- Identify products, fraud types, event sources, event volumes, decision latency needs, downstream actions, customer recourse, data residency, retention, and accountable owners.
- Define alert, review, hold, and block separately. Specify scope, duration, reversibility, customer impact, and authority required for each.
- Agree label sources, positive/negative/unknown states, label quality, maturity horizons, adjudication, timestamp semantics, and metric definitions.
- Ratify or replace the proposed pilot gates above. Set per-segment limits, sample sizes/confidence rules, and explicit promotion/rollback criteria.
- Draft and version the canonical event schema and idempotency rules **before** durable ingestion or database/queue selection. Define stable event IDs, duplicate behavior, ordering, late arrival, replay, entity references, provenance, and schema evolution.
- Confirm which synthetic and de-identified fields are approved for hosted Meko writes; require explicit privacy/security approval before any production signal is sent. Verify Meko authentication/authorization, datapack ownership, rate/retention/deletion behavior, tool schemas, and export/exit path.
- Distinguish Meko integration credentials needed for hosted memory operations from containment/action credentials, which are not used in the prototype.
- Threat-model poisoned memories, prompt injection, account/tenant isolation, secret leakage, replay, and unauthorized action paths.
- Bound this phase to one focused decision cycle. Record unresolved questions as explicit blockers rather than extending design indefinitely.

**Deliverables:** approved operating contract, versioned schema draft, initial metric definitions/gates, data-flow/privacy map, threat model, and a list of unresolved infrastructure choices.

### Phase 1 — Thin vertical slice and deterministic baseline

Build a working path early so the contract can be tested against real interfaces:

1. Use synthetic fixtures for login, device, and password-reset signals in local unit/replay tests. For the integration slice, send synthetic or approved de-identified signals to the configured hosted Meko endpoint using Meko integration credentials. Do not send production signals until privacy/security approval and required controls are documented.
2. Validate and normalize the events against the draft schema; reject invalid inputs and deduplicate by stable event ID.
3. Publish fixtures to a local durable-stream interface and implement the explicit triggers: new account-level signal source, configured velocity-window crossing, or high-risk event. Verify duplicate and out-of-order inputs do not change the result and ordinary signals do not cause unnecessary correlation.
4. Have a deterministic supervisor create a bounded investigation task with scope, hypothesis, tool/Meko-call/token/time budgets, deadline, and state. Begin with a small deterministic rules-and-velocity baseline (for example, failed-login count in a time window plus a new-device/reset sequence).
5. Run scoped login, device, and reset agents only against permitted evidence. Store typed findings, confidence, and evidence references in the investigation record; make the correlator read and verify those handoffs.
6. Make real hosted Meko calls through the adapter only at configured trigger points and within the task budget. Measure write/search visibility using synthetic tagged records. Treat retrieved content and agent output as untrusted evidence. Budget exhaustion or timeout produces an explicit degraded result, escalation, or deterministic fallback.
7. Produce a **shadow recommendation** with reason codes, baseline result, evidence provenance, uncertainty/abstention, and policy/prompt/model versions. Replace the demo’s fixed `"block"` trace value with a non-actionable recommendation. If a containment proposal is emitted, record it as a proposal only; the prototype has no containment/action credentials or execution path.
8. Record events, task transitions, handoffs, input references, and results in a local append-only development log; compare against fixtures and manually reviewed expected outcomes.

Extract the current script into a modest package, for example:

```text
src/fraud_detection/
    domain.py          # event, label, case, evidence, decision models
    ingestion.py      # validation, normalization, idempotency
    orchestration.py  # event triggers, investigation state machine, budgets
    agents/           # scoped agent tasks and typed handoff results
    baseline.py       # deterministic rules and velocity features
    policy.py         # versioned decisions, thresholds, abstention
    meko_adapter.py   # MCP transport and tool contracts
    audit.py          # append-only decision record interface
    containment.py    # proposal validation and separately gated execution
    settings.py       # validated configuration and secret loading
    cli.py            # local fixture/replay entry point
tests/
    unit/
    contract/
    replay/
```

Keep the package small; use interfaces where they protect a real boundary (Meko, audit storage, action provider), not for speculative abstractions. Replace hard-coded values and the fixed `"block"` in `demo()` with fixtures and an explicitly non-actionable recommendation.

**Tests:** schema validation/versioning; explicit trigger boundaries; duplicate/out-of-order/late events; deterministic supervisor transitions; task-scope denial; structured handoff validation and evidence-reference checks; per-task budget/deadline exhaustion; deterministic baseline boundaries; policy and abstention; ensure a proposal cannot execute in shadow mode; fixture replay; adapter contracts; malformed MCP output; timeout propagation; no PII/secrets in logs.

**Exit:** one synthetic or approved de-identified login/device/reset flow runs through event trigger, bounded scoped tasks, structured handoffs, real hosted Meko write/retrieval, and a reproducible non-actionable shadow recommendation. The deterministic supervisor owns state; Meko integration credentials may be configured, but no containment/action credential or executable action path exists. Production signals remain gated on explicit privacy/security approval.

### Phase 2 — Evaluation and label pipeline

- Implement label ingestion with source, timestamps, confidence, adjudication state, and links to the original event/case.
- Measure label delay distributions and define source-specific maturity horizons; keep immature and unknown cases out of mature-negative counts.
- Build an offline replay/evaluation harness that compares agentic recommendations with the deterministic baseline on the same point-in-time evidence.
- Prevent temporal leakage: only features available at decision time may be used for that decision.
- Pin the model/provider identifier and prompt/template version. Persist exact privacy-approved input snapshots or immutable references, retrieved evidence identifiers, tool versions, output, and decision versions.
- Replay recorded decisions against the recorded outputs/inputs for audit. Do not expect a fresh LLM invocation to produce identical text or results; evaluate fresh runs as new experiments.
- Report metrics, confidence intervals, cohort slices, alert volume, false-positive/missed-fraud costs, lead time, latency, and baseline-relative lift.

**Tests:** label-source disagreement and maturity; leakage checks; repeatable deterministic baseline; recorded-decision replay; model/prompt version changes; metrics against hand-calculated fixtures; confidence/sample-size behavior.

**Exit:** the agentic approach has a measured, material improvement over the plain baseline on pre-agreed metrics, or remains disabled while the baseline continues.

### Phase 3 — Durable ingestion and shadow operations

- After schema, idempotency, trigger, and supervisor-state rules are approved, select local/persistent storage and a durable event stream based on volume, latency, recovery, retention, and deployment needs. Avoid selecting infrastructure first.
- Persist events, investigation tasks/transitions, structured handoffs, cases, labels, recommendations, and the append-only audit log independently of Meko. Add migrations, backup/restore, access control, and retention/deletion workflows.
- Use an outbox or equivalent reliable delivery for Meko enrichment; subscribe agents to the durable stream rather than polling Meko or other agents. Correlate only at configured triggers. Handle retries, budgets, rate limits, backpressure, dead letters, and provider outages explicitly.
- Run shadow mode beside existing controls. Generate alerts for analyst review but do not alter transactions or customer access.
- Monitor ingestion lag, duplicates, missing features, Meko latency/searchability, decision latency, errors, alert volume, label coverage, drift, and baseline-relative performance.

**Tests:** restart/crash recovery; duplicate and out-of-order event delivery; trigger deduplication; investigation resume after restart; replay/backfill; task budget enforcement; storage migration and restore; stream redelivery; provider timeout/outage; rate limiting; access isolation; deletion/retention; latency and load.

**Exit:** durable, replayable shadow decisions; metric sample gates met; Meko is not a single point of failure; operational dashboards and response runbooks are exercised.

### Phase 4 — Human approval

- Build a case queue with evidence timeline, reason codes, model/rule versions, label state, investigation status, assignment, and escalation. Let authorized reviewers pause, resume, and reassign tasks; record each transition.
- Add authenticated role-based access, least privilege, separation of duties, and complete audit records for approve, reject, override, expire, and reassignment.
- Let the correlator submit a typed containment proposal (action type, target, reason codes, evidence references, reversibility, and expiry). Treat it as a request only; never let agent output invoke the action adapter directly.
- Revalidate case version, policy stage, proposal evidence, permissions, and action eligibility at approval and execution time; use idempotency to prevent duplicate approvals/actions.
- Start with a sandbox containment service. Require explicit human authorization and record the actor, scope, expiry, policy version, exact action requested, outcome, and customer recourse path.
- Collect structured analyst labels and disagreement reasons. Review and adjudicate feedback; do not auto-promote a disposition into shared knowledge.

**Tests:** permissions and per-agent scopes; pause/resume/reassignment; stale/racing approvals; duplicate submission; proposal is not authorization; re-check at execution; expiry; analyst override; audit integrity; containment sandbox; notification failures; appeal/escalation.

**Exit:** all actions are explicitly approved, scoped, attributable, auditable, and reversible or have a documented customer-remedy path.

### Phase 5 — Limited reversible automation

- Automate only a narrow class of low-impact, reversible action after Phase 4 gates pass and fraud owners approve the explicit action allowlist. Engineering must not select allowed actions by default.
- Execute only structured proposals that pass the separate containment service’s fresh checks: current stage, policy, permissions, allowlist, evidence, budget, per-tenant/global limits, rate caps, feature flags, idempotency, expiry/reversal path, and kill switch.
- The deterministic supervisor enforces investigation budgets and deadlines. On exhaustion, missing/stale data, uncertain evidence, policy conflict, Meko outage, or drift, stop the task and use the explicitly defined deterministic fallback or human escalation; never continue silently.
- Roll out through internal/sandbox traffic, a small controlled cohort, and gradual expansion. Compare continuously with the human-approved baseline; stop automatically on guardrail violations.
- Exercise reversal, customer notification, and incident procedures before expansion.

**Tests:** action simulator; proposal-versus-authorization boundary; allowlist and permission denial; limit boundaries; budget/deadline enforcement; kill switch; expiry/reversal; race and replay safety; provider outage; drift/guardrail trip; staged rollout and rollback drills.

**Exit:** guardrails and customer impact remain within ratified limits over the agreed observation period; independent risk and operations owners approve scope expansion.

### Phase 6 — Automatic holds/blocks

- Treat automatic holds and blocks as separate authorities. Define maximum hold duration, review service level, release conditions, customer notice/appeal, and who can block permanently.
- Use a dedicated containment service with narrowly scoped credentials. Re-check the current stage, policy, action allowlist, agent/task permissions, kill switch, proposal expiry, and idempotency at execution time. No agent, LLM, memory result, or tool-generated text can directly invoke the service.
- Keep irreversible blocks on confirmed accounts human-approved unless fraud owners and the existing promotion gates explicitly approve a future change after a sustained evaluation period. The reversible-action allowlist remains a fraud-owner policy decision.
- Require deterministic policy eligibility plus validated evidence and healthy monitoring. On uncertainty, missing evidence, audit failure, or dependency outage, follow the action-specific failure policy and abstain/escalate.
- Expand only through approved cohorts with canary monitoring, an always-available kill switch, and tested rollback/compensation.
- Conduct independent security, fraud, legal, privacy, and operations review before any production authority increase.

**Tests:** end-to-end sandbox and canary; stage and authorization denial; proposal tampering; duplicate/replay and concurrency; hold expiry; appeal/release; downstream outage; audit-store outage; kill switch and rollback drills; independent adversarial review.

**Exit:** documented approvals, demonstrated safety gates, functioning customer recourse, reliable observability, and a successful rollback drill for the exact production scope.

## Cross-cutting engineering and risk controls

### Agent orchestration and containment

- **Monitor events, not Meko:** agents subscribe to the application’s durable event stream. Trigger an account investigation on a new account-level signal source, a configured velocity-window threshold crossing, or a configured high-risk event such as payee change, reset, or limit change. Version the trigger rules; do not correlate on every event by default.
- **Bound every investigation:** persist an investigation/task object with account/entity scope, trigger event, hypothesis, allowed tools and evidence scopes, tool-call/Meko-retrieval/model-token budgets, wall-clock deadline, state, and policy version. Do not let an agent expand its own scope or budget.
- **Use structured handoffs:** an agent writes a schema-validated finding to the investigation record, including status, conclusion, reason codes, confidence, evidence references, source, and version. The next agent reads the record and verifies evidence references; it does not inherit free-text instructions or trust another agent’s conclusion as authorization.
- **Enforce least privilege:** define per-agent tool, read, and write allowlists. A device investigation cannot read payment history unless its task explicitly permits it. Route Meko writes through a service identity attributable to the agent; record that identity and task ID in the authoritative audit record.
- **Keep supervision deterministic:** ordinary code owns task transitions, deadlines, budget accounting, retries, escalation, and cancellation. The supervisor can halt any agent. Human reviewers can pause, resume, or reassign a task, with all transitions audited. Agents and LLMs cannot change supervisor policy or state directly.
- **Make budget exhaustion explicit:** exceeding any call, retrieval, token, or time limit stops the task and yields a typed budget-exhausted outcome. The supervisor then uses the approved deterministic fallback or escalates to a human; it must not silently continue or return a success-shaped partial result.
- **Separate proposal from authority:** a correlator may propose a structured action containing action type, target, reason codes, evidence references, reversibility, and expiry. The proposal is untrusted input to policy, not authorization. In shadow mode it is logged only; in human-approval mode it is queued; limited automation can proceed only through the separate containment service.
- **Re-check at the point of execution:** the containment service independently checks stage, policy version, agent and human permissions, fraud-owner-approved allowlist, evidence validity, expiry, idempotency, rate/tenant limits, kill switch, audit availability, and required reversal/review path. Record requester, approver or policy authorization, exact policy version, action result, expiry/reversal, and customer recourse. No agent or Meko tool directly receives containment credentials.
- **Keep action scope a governance decision:** engineering must not choose the reversible action allowlist. Fraud owners must approve specific actions and eligibility criteria. Irreversible blocks on confirmed accounts remain human-approved under the existing promotion gates.

### Meko availability and search consistency

- Decide fail-open/fail-closed **per action**. A recommendation-only flow may continue with the deterministic baseline and mark context as unavailable. Never block a legitimate transaction solely because a non-critical context provider failed. A high-risk action must abstain or route to a person if required evidence is missing; any temporary hold behavior must be explicitly risk-approved.
- Bound network and tool timeouts, retries, and concurrency. Retries must be limited to transient failures and must not duplicate non-idempotent writes.
- Early in the vertical slice, measure `memory_add`-to-`memory_search` visibility with synthetic tagged records. Record p50/p95/p99 and maximum observed delay across repeated trials and under concurrent writes. Define an application policy for expected visibility delay; do not assume immediate consistency from documentation.
- Make the decision independent of just-written memory becoming searchable. Carry current-event evidence directly through the case/decision path, and use Meko retrieval as enrichment.

### Memory poisoning and prompt injection

- Treat support text, payee names, device strings, notes, retrieved memories, and MCP results as attacker-controlled data.
- Validate signal fields, lengths, encodings, allowed enums, and provenance. Store structured fields separately from free text; minimize or omit free text from shared memory.
- Keep free text out of system/developer instructions and tool-routing decisions. Delimit and label any necessary text as untrusted evidence; retrieved content cannot alter policy or authorize actions.
- Namespace and scope memories by tenant, purpose, source, and trust level. Do not let one case or tenant silently contaminate another’s retrieval.
- Red-team prompt injection, poisoned memories, misleading support narratives, malicious identifiers, and cross-case retrieval. Alert on suspicious or policy-changing retrieved content.

### Deterministic replay and model governance

- Pin and record provider/model ID, prompt/template hash, tool/schema versions, policy/rule version, retrieval settings, and feature-code version.
- Store exact privacy-approved input snapshots or immutable references, evidence ordering, retrieved item IDs, output, and final decision in the audit record.
- Replay recorded outputs to reproduce the decision path. Re-running a model is a new experiment, not a deterministic replay; compare it separately and retain both runs.
- Require review and evaluation before model, prompt, retrieval, feature, or threshold changes. Preserve rollback to the previous approved version.

### Privacy, retention, and provider exit

- Decide explicitly what PII may enter Meko. Prefer tenant-scoped tokens or keyed pseudonyms for account identifiers; do not send full transaction details or sensitive support text by default.
- Map legal purpose, residency, retention, deletion, access, and subject-request requirements for both the application audit store and Meko. Reconcile immutable audit needs with privacy obligations using minimized data, references, and controlled redaction/deletion procedures—not by retaining raw PII indefinitely.
- The prototype intentionally uses the configured hosted Meko endpoint. Before production signals are sent, privacy/security owners must approve the data flow and decide whether hosted Meko meets residency, access, retention, and deletion requirements or whether a different deployment (including BYOC) is required. Confirm export/exit capabilities and limitations.
- Keep Meko behind an adapter/interface and contract tests. Maintain a provider-exit path: export required records, stop writes, remove provider credentials, verify deletion where required, and continue decisions/audits from application-owned records.

### Audit source of truth

- Maintain an application-owned append-only log for input references, labels, policy/model versions, decisions, approvals, action requests/results, and corrections.
- Make audit writes durable before consequential state transitions; define and test what happens if audit persistence is unavailable.
- Treat Meko memories and trace artifacts as supplementary observability/context only. They are mutable and may be delayed or deleted; they cannot be the authoritative record.

### Feedback and shared-knowledge governance

- Analyst-confirmed patterns require documented evidence, independent review, provenance, scope, expiry/review date, and approval before any shared-knowledge promotion.
- Do not automatically call `memory_promote` from an analyst disposition or agent output. Its one-way behavior raises the bar for approval.
- Before promotion, define a retract/containment procedure and test it. If the provider cannot retract a promoted item, quarantine or supersede it with an explicit correction and ensure retrieval excludes it; document residual exposure.
- Track promoted knowledge versions and downstream decisions that used them so a bad pattern can trigger reevaluation and incident response.

### Adversarial evaluation and drift

- Maintain a versioned suite of synthetic and approved de-identified replay cases covering known attack sequences, benign lookalikes, evasion, timing/ordering changes, and injected instructions in untrusted fields.
- Evaluate baseline and agentic policy side by side; include false-positive impacts and subgroup slices.
- Monitor changes in input distributions, label rates, feature missingness, calibration, retrieval behavior, baseline lift, and outcome metrics.
- Define drift thresholds, investigation ownership, alerting, and automatic rollback/disable behavior before automation is enabled. Re-run adversarial cases for every policy/model/prompt change.

## Rollout and release checklist

1. **Local development and Meko integration:** local synthetic fixtures and deterministic tests; integration checks make real hosted Meko memory writes/searches with synthetic or approved de-identified data. Meko integration credentials are permitted for this purpose; production signals require explicit privacy/security approval. No containment/action credentials or action execution.
2. **Offline replay:** mature labels, point-in-time features, baseline comparison, confidence intervals.
3. **Shadow:** real-time recommendations and hosted Meko memory operations only within approved data boundaries; actions disabled.
4. **Human approval:** sandbox first, then an explicitly scoped operational queue and downstream action.
5. **Limited automation:** reversible actions only, cohort and rate-limited, with kill switch and rollback.
6. **Automatic hold/block:** only separately approved scopes, after customer recourse, failure behavior, independent review, and all numerical gates pass.

Every release must have a named owner, reviewed changes, test/evaluation report, monitoring and rollback plan, and a recorded go/no-go decision. Failed gates mean hold the current authority level, investigate, and rerun evaluation—not lower the metric or promote by default.

## Decisions intentionally left open

- Target product/rail, event volume, latency budget, and fraud-specific cost model.
- Exact false-positive, agreement, lead-time, and latency limits after historical measurement and stakeholder ratification.
- Label maturity windows by source and product.
- Database, queue, web framework, model provider, cloud/BYOC deployment, and retention durations.
- Which actions are reversible and which human roles can authorize them.
- Which specific reversible actions and eligibility criteria fraud owners will approve for the automation allowlist.
- Whether hosted Meko satisfies privacy, deletion, consistency, and operational requirements for any approved production data, or whether a different deployment is needed.
