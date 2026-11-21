# Meko Memory Gaps Closure Plan

## Overview

This plan closes the gaps between the project's current Meko integration and the full Meko Memory lifecycle defined in the official docs (https://docs.mekodata.ai/concepts/memory). The project currently implements only `memory_add` and `context_search`; all other memory operations (search, listing, update, deletion, promotion, auto-extraction) are missing.

---

## Goals & Constraints

### Goals
- Add `memory_search` — scoped memory-only retrieval separate from `context_search`
- Add `memory_update` — change existing facts without creating duplicates
- Fix conversation-per-signal anti-pattern so Meko's built-in dedup and auto-extraction work across signals
- Add `memory_get_all` / `memory_get_by_id` — enumerate and retrieve stored memories
- Add `memory_promote` — move confirmed attacker patterns from private memory to shared KB / Collective Memory
- Add `memory_delete_by_id` / `memory_delete_all` — permanent deletion (Sept 9, 2026+ limitation)
- Add memory size governance — track token/content size to prevent LLM context bloat

### Constraints
- All Meko operations go through the hosted MCP endpoint — cannot bypass or mock
- Must not introduce executable action paths; memory is enrichment only
- Must preserve the deterministic supervisor / policy boundary
- Must maintain auditability: every memory op should be traceable
- Production signals require explicit privacy/security approval before sending; this plan covers synthetic / approved de-identified data

### Affected Boundaries
- `src/fraud_detection/meko_adapter.py` — primary adapter; all memory ops live here
- `src/fraud_detection/mcp_server.py` — MCP server tools (case brief, pattern lookup, feedback) — may need minor consumer-side changes
- `src/fraud_detection/agents/` — agent constructors accept `MekoAdapter`; no changes needed if adapter surface is stable
- `src/fraud_detection/cli.py` — end-to-end flow runner; Phase 1 exit criteria need baseline comparison still valid after changes
- `settings.py` — already has `meko_api_key`, `meko_datapack_id`, `meko_mcp_url`; no new config keys needed
- `audit.log` — every new memory operation should log its scope and result

---

## Detailed Task List

### Task 1: Add `memory_search` to MekoAdapter

**What:** Implement `memory_search(query, *, limit=10, agent_id="meko_agent")` that calls Meko's `memory_search` tool (as opposed to `context_search` which searches memory + KB + conversations). This returns only the user's private memories in the selected datapack.

**Why:** The docs distinguish `memory_search` (memories only) from `context_search` (memory + KB + conversations). Currently the project only uses `context_search`. Adding `memory_search` enables targeted "what do we know about this account from prior signals?" retrieval without knowledge-base interference.

**How:**
- Add `async def memory_search(self, query: str, *, limit: int = 10, agent_id: str = "meko_agent") -> Any` to `MekoAdapter`
- Call `session.call_tool("memory_search", args)` where args includes `query`, `limit`, `agent_id`, and `datapack_id` (from settings)
- Return parsed results (matches with `score`, `raw_similarity_score`)
- Update `cli.py` Phase 1 to demonstrate `memory_search` vs `context_search` difference in the baseline comparison section

**Dependencies:**
- Meko MCP server must support `memory_search` tool (docs confirm it does)
- The `limit` parameter is critical — docs warn broad memory searches bloat LLM context

**Validation:**
- After `python main.py`, verify that `memory_search` returns only memories (no KB / conversation results) and `context_search` returns the union of all three sources in separate buckets.

---

### Task 2: Add `memory_update` to MekoAdapter

**What:** Implement `memory_update(memory_id: str, text: str, *, agent_id: str = "meko_agent")` that calls Meko's `memory_update` tool to modify an existing stored memory's text content.

**Why:** Docs say: "`memory_add` stores the text as written and doesn't check for an existing copy, so adding the same text twice stores it twice. To change a fact that's already stored, use `memory_update` instead of adding it again."

**How:**
- Add `async def memory_update(self, memory_id: str, text: str, *, agent_id: str = "meko_agent") -> Any` to `MekoAdapter`
- Call `session.call_tool("memory_update", args)` where args includes `memory_id`, `text`, `agent_id`, `datapack_id`
- Return the updated memory record

**Dependencies:**
- Memory ID must be tracked somewhere. Options:
  a) Return memory ID from `memory_add` and store it alongside the signal in project-local state (e.g., in the investigation record or a mapping dict)
  b) Extract memory ID from the result of `memory_add` and pass it forward

**Validation:**
- After writing a signal via `write_signal`, call `memory_update` with a modified text and verify the searchable content changes while the memory ID stays the same.
- Verify that a second `memory_add` with the same text does NOT create a duplicate after `memory_update` is used.

---

### Task 3: Fix Conversation-Per-Signal Anti-Pattern

**What:** Refactor `write_signal()` to batch related signals into shared conversations instead of creating one conversation per signal. This enables Meko's built-in `conversation_add_message` deduplication and automatic LLM extraction of durable facts.

**Why:** Currently `write_signal()` calls `create_conversation` + `memory_add` for each individual signal. Because each signal is isolated in its own conversation, the server-side deduplication (exact/semantic duplicate detection) never fires across signals. The docs explicitly note that turns saved close together can still store a fact more than once because extraction runs in the background after each turn is saved — but this only works if turns share a conversation.

**How:**
- Add a new method `batch_write_signals(signals: list[dict], shared_conversation_id: Optional[str] = None)` to `MekoAdapter`
- If `shared_conversation_id` is provided, reuse that conversation for all signals; otherwise, create one conversation per signal (backward-compatible default)
- Within a shared conversation, call `memory_add` for each signal's text — the server will dedupe exact/semantic duplicates across the turns in that conversation
- Update `cli.py` `write_signal` calls in the Phase 1 flow to use batch mode when appropriate (e.g., all 5 signals in one investigation share one conversation)

**Dependencies:**
- Must not break existing `write_signal` API — keep it working as before (one conversation per signal) as default
- The `record_decision` path (`conversation_add_message`) should also benefit from shared conversations for cross-signal dedup

**Validation:**
- After `python main.py`, verify that running the flow twice writes each signal memory only once (dedup working) when using shared conversation, and still works (but may duplicate) with per-signal conversations.
- Verify that `conversation_add_message` in `record_decision` can extract durable facts across signals when they share a conversation.

---

### Task 4: Add `memory_get_all` and `memory_get_by_id` to MekoAdapter

**What:** Implement `memory_get_all(*, page: int | None = None, page_size: int | None = None)` and `memory_get_by_id(memory_id: str)` that call Meko's respective tools.

**Why:** The project writes signals to memory but has no way to later review, audit, or retrieve what was stored. Analysts cannot list memories to see what signals past agents recorded. The docs say `memory_get_all` returns a page of memories with total page count; omitting `page` returns only the newest page.

**How:**
- Add `async def memory_get_all(self, *, page: int | None = None, page_size: int | None = None) -> Any` to `MekoAdapter`
- Add `async def memory_get_by_id(self, memory_id: str) -> Any` to `MekoAdapter`
- Both call their respective MCP tools with `datapack_id` from settings
- Return parsed results

**Dependencies:**
- None beyond the MCP server tool contract

**Validation:**
- After `python main.py`, verify `memory_get_all` returns the 5 signals written earlier, pageable.
- Verify `memory_get_by_id` retrieves a specific memory by its ID (returned from `memory_add`).

---

### Task 5: Add `memory_delete_by_id` and `memory_delete_all` to MekoAdapter

**What:** Implement `memory_delete_by_id(memory_id: str)` and `memory_delete_all(*, agent_id: str | None = None, datapack_id: str | None = None, run_id: str | None = None)`.

**Why:** The docs say deletion is only available for memories created on or after September 9, 2026. Older memories can't be deleted. `memory_delete_all` removes memories written under one `agent_id` (optionally narrowed by `run_id`/conversation ID), deleting only the caller's memories. Returns `deleted_count` and `complete` flag — if incomplete, call again to continue.

**How:**
- Add `async def memory_delete_by_id(self, memory_id: str) -> Any` to `MekoAdapter`
- Add `async def memory_delete_all(self, *, agent_id: str | None = None, datapack_id: str | None = None, run_id: str | None = None) -> Any` to `MekoAdapter`
- Both call their respective MCP tools
- `memory_delete_all` returns `{deleted_count, complete}` — if `complete` is False, the caller should call again to continue the batch deletion
- Handle the Sept 9, 2026 limitation: no deletion of older memories (this is a server-side constraint; the tool may return an error for old memories)

**Dependencies:**
- Must log deletion operations to audit.log with scope (which memories deleted, when, why)
- Must respect the Sept 9, 2026 rule — if the server rejects deletion of older memories, catch the error and surface a clear message

**Validation:**
- After `python main.py`, verify that `memory_delete_by_id` on a recently written memory removes it, and that attempting on an older (simulated) memory fails gracefully.
- Verify `memory_delete_all` with no `agent_id` deletes the `meko_agent` bucket; with `agent_id` deletes only that agent's memories.
- Verify the `complete` return flag and re-call pattern.

---

### Task 6: Add `memory_promote` to MekoAdapter

**What:** Implement `memory_promote(memory_ids: list[str], *, agent_id: str = "meko_agent")` that calls Meko's `memory_promote` tool to move selected private memories into the datapack's shared knowledge base and Collective Memory.

**Why:** The docs say datapack owners and maintainers can use `memory_promote` to move private memories into shared knowledge. This is how confirmed attacker patterns move from private memory into the knowledge base (aligned with challenge.md's "Knowledge base: Fraud playbooks and risk rules"). Promotion is one-way and irreversible via MCP.

**How:**
- Add `async def memory_promote(self, memory_ids: list[str], *, agent_id: str = "meko_agent") -> Any` to `MekoAdapter`
- Before promoting, the caller should:
  1. Retrieve and show the exact memories to promote (use `memory_get_by_id`)
  2. Explain that datapack members will find the promoted knowledge and private records will be removed
  3. Ask for explicit confirmation
  4. Call `memory_promote` only after confirmation
- Return the promotion result

**Dependencies:**
- Must enforce the governance flow: show memories → explain impact → get confirmation → promote
- The `memory_promote` tool itself is one-way; the adapter should not reverse it

**Validation:**
- After `python main.py`, simulate: write a signal, call `memory_get_by_id` to show it, then call `memory_promote` with explicit analyst confirmation, verify it moves to shared KB and is no longer in private memory search (but `memory_search` still returns it alongside private per docs).

---

### Task 7: Add Memory Size Governance

**What:** Track the token/content size of retrieved memories to prevent LLM context bloat, and expose a mechanism to set `memory_search.limit` per investigation budget.

**Why:** Docs warn: "Retrieving all memories or running a broad memory search can add substantial content to your LLM context. Set `memory_search.limit` to return fewer search results when appropriate."

**How:**
- Add a `meko_retrieval_content_tokens` counter to `InvestigationContext` in `orchestration.py` (parallel to existing `meko_retrievals_used`)
- In `MekoAdapter`, have `memory_search` and `context_search` return not just results but also an estimated token count
- Update `orchestrator.record_tokens()` or add `orchestrator.record_meko_retrieval_content_tokens()` to record content-size budget usage
- In `cli.py` Phase 1, show memory content size alongside the existing `match_quality` and budget exhausted messages
- Add a config or environment variable `MEKO_MAX_RETRIEVAL_TOKENS` (default 500 or similar) that the orchestrator checks before allowing a memory search; if exceeded, produce an explicit degraded/abstain state

**Dependencies:**
- Orchestrator already tracks `meko_retrievals_used`; adding content-token tracking is additive
- Must not break existing budget enforcement

**Validation:**
- After `python main.py`, verify that the Phase 1 output shows memory content token usage (e.g., "Meko retrieval: 3 calls, ~240 tokens").
- Verify that when `MEKO_MAX_RETRIEVAL_TOKENS` is set low, the system produces a degraded/abstain state rather than proceeding with a massive context injection.

---

## Rollout & Migration Path

### Phase 1 — Immediate (behind feature flags)
- Deploy Tasks 1–3 (memory_search, memory_update, batch conversations) with feature flags default OFF
- Run existing test suite; ensure per-signal conversation mode still works as before
- Monitor audit.log for any new operation patterns

### Phase 2 — Opt-in
- Enable Tasks 4–5 (get_all/get_by_id, delete) behind feature flags
- Add UI or MCP tooling for analysts to list/retrieve/delete their memories
- Validate deletion of test memories only (Sept 9, 2026+)

### Phase 3 — Promote + governance
- Enable Task 6 (memory_promote) behind explicit fraud-owner approval flow
- Enable Task 7 (token governance) with reasonable defaults
- Document the full memory lifecycle for analysts and fraud owners

### Rollback
- All tasks are behind feature flags; flip the flag off to revert
- No database schema changes — all ops are MCP tool calls to the hosted service
- Audit.log captures before/after state for any rollback investigation

---

## Open Questions / Decisions Needed

1. **Memory ID tracking for `memory_update`** — Should the project store the memory ID returned from `memory_add` alongside each signal in the investigation record? Or should we rely on the server to look up memories by content matching? *Recommended: store the memory ID from `memory_add` result in the investigation's evidence_refs or a new field.*

2. **Conversation batching scope** — Should all 5 signals in an investigation share one conversation, or should batching be configurable per signal group? *Recommended: one shared conversation per investigation for the Phase 1 synthetic flow; configurable per workflow.*

3. **`MEKO_MAX_RETRIEVAL_TOKENS` default value** — What token budget is reasonable for a Phase 1 investigation? *Recommended: start with 500 tokens (configurable via settings), adjustable per deployment.*

4. **Deletion of pre-Sept-2026 memories** — The server will reject deletion of memories created before Sept 9, 2026. Should the adapter surface a specific error type, or a generic "deletion not available" message? *Recommended: catch the specific error and return a clear `MemoryDeletionNotAvailableError` with the memory creation timestamp if available.*

5. **Promotion governance flow** — Should `memory_promote` be automatic after analyst feedback labeling something as confirmed fraud, or should it always require a separate explicit step? *Recommended: always require explicit confirmation step (show memories → explain impact → get confirmation) as docs specify.*

---

## Success Criteria

After implementing all tasks and running `python main.py` end-to-end:

- [ ] `memory_search` returns only private memories (no KB/conversation results)
- [ ] `context_search` returns union of memory + KB + conversations in separate buckets
- [ ] Running the flow twice dedupes signal memories when using shared conversations
- [ ] `memory_get_all` lists the 5 signals written, pageable
- [ ] `memory_get_by_id` retrieves a specific memory by ID
- [ ] `memory_delete_by_id` removes a recently written memory; older memories fail gracefully
- [ ] `memory_delete_all` with no `agent_id` deletes the `meko_agent` bucket
- [ ] `memory_promote` with explicit confirmation moves memories to shared KB
- [ ] Memory content token count is tracked and displayed in Phase 1 output
- [ ] `MEKO_MAX_RETRIEVAL_TOKENS` budget enforcement produces degraded/abstain when exceeded

---

## Next Steps

1. Implement Task 1 (`memory_search`) in `meko_adapter.py` — highest priority, enables all downstream memory-awareness
2. Implement Task 3 (batch conversations) — critical for dedup and auto-extraction
3. Implement Task 2 (`memory_update`) — prevents duplicate signals when facts change
4. Implement Tasks 4–5 (`get_all`/`get_by_id`/`delete`) — observability and cleanup
5. Implement Task 6 (`memory_promote`) — closes the gap to knowledge base / Collective Memory
6. Implement Task 7 (token governance) — prevents LLM context bloat
7. Run `python main.py` and verify all success criteria
8. Gradually enable features behind flags per the rollout path

---