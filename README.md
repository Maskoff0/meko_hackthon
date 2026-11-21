# meko hackthon — Agentic Fraud Detection System

A production-grade, agentic fraud detection system built as a **cross-channel account takeover (ATO) detector** covering **login + device + reset + support + transaction** signals, with an **analyst copilot** that explains every alert and a **phased human-approval containment model** that keeps agents in an evidence-only role.

## Channels & signals

| Channel | Signals |
|---|---|
| Login | Credential stuffing, failed login velocity, new location/IP |
| Device | New device, emulator detected |
| Reset | Password reset after failures, unusual timing, multiple resets |
| Support | Support takeover pattern, social engineering contacts |
| Transaction | New payee, test payments, limit changes, cash-out sequences |

For each alert, the system produces a **shadow recommendation** (non-actionable in shadow mode) with reason codes, evidence provenance, confidence scores, and a plain-language explanation — so human analysts review and act, not just react to a black-box score.

---

## System flow

```
ingest → trigger → bounded investigation → scoped agents →
Meko write/search → deterministic baseline → policy → shadow recommendation →
audit log → containment gate (denied in shadow mode)
```

The system runs in **shadow mode** by default: all containment proposals are logged only and never executed.

---

## Key design principles

- **Deterministic supervisor** owns investigation state, budgets, deadlines — not an LLM
- **Agent output is evidence, never authority** — the policy engine decides
- **Meko is enrichment only** — memory writes and context searches never execute containment
- **Proposal ≠ authority** — the containment gate denies all proposals in shadow mode
- **Append-only audit log** is the authoritative record; Meko traces are supplementary
- **Idempotent ingestion** — duplicate events by `idempotency_key` are rejected
- **Durable persistence** — SQLite storage survives process restarts; investigations recover on restart
- **Human-in-the-loop** — analysts approve containment; irreversible blocks require FRAUD_OWNER + independent review

---

## Meko integration

The system integrates with the hosted Meko MCP endpoint as an **enrichment-only layer** (never executable actions). All Meko operations go through `MekoAdapter` (shadow mode: read/write memory and KB only).

### Memory lifecycle
| Operation | MCP tool | Description |
|---|---|---|
| Write signals | `memory_add` | Stores signal text as memory (batched via shared conversation for dedup) |
| Search memories | `memory_search` | Memory-only retrieval (semantic + keyword + entity boosting) |
| Update fact | `memory_update` | Changes an existing memory without creating duplicates |
| List memories | `memory_get_all` | Paged listing of all memories in the datapack |
| Get by ID | `memory_get_by_id` | Retrieve a specific memory |
| Delete one | `memory_delete_by_id` | Permanent deletion (Sept 9, 2026+ memories only) |
| Delete batch | `memory_delete_all` | Delete by agent_id / run_id / datapack_id |
| Promote to KB | `memory_promote` | Move private memory to shared knowledge base (one-way) |

### Knowledge base
| Operation | MCP tool | Description |
|---|---|---|
| Upload document | `knowledgebase_upload_document` | Request S3 presigned URL, PUT file bytes |
| Status polling | `knowledgebase_document_status` | Poll until indexing completes |
| Delete document | `knowledgebase_delete_document` | Remove document (owner/maintainer/uploader only) |
| Query KB | `context_search(force_source="knowledge_base")` | Search indexed KB documents |

Six fraud playbook documents are maintained in `kb_playbooks/`: `login_channel.md`, `device_channel.md`, `reset_channel.md`, `support_channel.md`, `transaction_channel.md`, `risk_rules.md`. Upload with `python main.py --upload-kb`.

### Artifacts
| Operation | MCP tool | Description |
|---|---|---|
| Store artifact | `artifact_put` | Upload file, returns content hash |
| Retrieve artifact | `artifact_get` | Get file back by hash (resets expiry clock) |
| Put + remember | `put_artifact_and_remember` | Upload artifact and save hash as named memory |
| Get by memory name | `get_artifact_by_memory_name` | Cross-agent artifact retrieval via shared memory |

### Traces & observability
- Every MCP call is traced with **trace_id**, latency, estimated tokens, and error status
- Traces exported in Meko's native span format to `traces/<investigation_id>.json`
- Trace persistence for resumability across sessions (`save_trace` / `load_trace`)
- Content token governance: `meko_retrieval_content_token_budget` halts investigations when exceeded

---

## Package structure

```
src/fraud_detection/
    domain.py           # event, label, case, evidence, decision models
    ingestion.py        # validation, normalization, idempotency
    orchestration.py    # deterministic supervisor: triggers, state machine, budgets
    agents/             # scoped agents: login, device, reset, support, transaction, correlator
    baseline.py         # deterministic rules and velocity features
    policy.py           # versioned decisions, thresholds, abstention
    meko_adapter.py     # MCP transport + trace observability (enrichment only)
    audit.py            # append-only decision record interface
    analyst.py          # analyst copilot: case briefs, trace explanation, pattern lookup
    mcp_server.py       # MCP server exposing analyst capabilities
    storage.py          # SQLite durable storage (Phase 3)
    stream.py           # durable event stream with replay/DLQ
    outbox.py           # outbox pattern with retry/dead-letter
    monitoring.py       # SLO collection and snapshot
    settings.py         # validated configuration
    cli.py              # local fixture/replay entry point
tests/
    unit/               # unit tests
    contract/           # MCP schema and label contract tests
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

---

## Run

### Phase 1 end-to-end synthetic flow (shadow mode — no action executed)

```powershell
python main.py
```

Or via the installed script:

```powershell
fraud-detection
```

### Upload fraud playbooks to Meko knowledge base

```powershell
python main.py --upload-kb
```

### Specify a custom database path

```powershell
python main.py --db=fraud_detection.db
```

### Analyst copilot via MCP server

```powershell
python -m fraud_detection.mcp_server
```

The MCP server exposes analyst tools: `generate_case_brief`, `explain_trace`, `explain_investigation`, `lookup_patterns`, `query_knowledge`, `get_artifact`, `draft_case_note`, `draft_customer_communication`, `draft_regulator_explanation`, `build_triage_queue`, `capture_feedback`, `edit_draft`, `sign_draft`, `get_draft_edit_rate`.

---

## Running tests

```powershell
python -m pip install pytest
python -m pytest tests/ -v
python -m pytest tests/contract/ -v   # MCP schema contracts
python -m pytest tests/unit/ -v       # unit tests
```

---

## Constraints (Phase 1)

- Synthetic or approved de-identified signals only — no production signals
- Shadow mode: recommendations are non-actionable (review/abstain only)
- No containment/action credentials or executable action path exists in Phase 1
- Meko integration credentials permitted for hosted memory/KB writes/searches only
