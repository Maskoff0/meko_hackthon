# Analyst Efficiency: Where Time Goes and What Claude or any MCP client Does

## Where analyst time goes

Most analyst time is reconstruction: pulling the account's timeline across four systems, figuring out why the agents flagged it, checking whether a similar attack happened before, and writing the case note. Claude or MCP client can help with all of those, and none of them require Claude or MCP client to decide anything.

## 1. Case briefs on demand

When an analyst opens an investigation, Claude or any MCP client produces a one-screen brief from the decision log and Meko context:

- what happened, as an ordered timeline with source systems
- which signals drove the score, and how confident each agent was
- matching prior incidents, with incident IDs
- what's still unknown

Every claim in the brief links back to an event ID or trace ID. If Claude or any MCP client can't cite it, it doesn't go in the brief. Analysts can click through to verify.

## 2. Trace explanation

Agent decisions are often hard to read. Claude(MCP client) translates a trace into plain language, for example: "step-up triggered because the login came from a new device two hours after 40 failed attempts from a related IP." The raw trace stays the record of truth.

## 3. Pattern lookup

Instead of an analyst searching by hand, Claude(MCP client) runs hybrid retrieval against the knowledge base and past confirmed cases, and says what's similar and what's different. This is where Meko's search does the work.

## 4. Drafting, not deciding

Claude(MCP client) drafts the case note, the customer communication, and the regulator-facing explanation. The analyst edits and signs. Drafts are stored as drafts, never as the official record.

## 5. Triage ordering

Claude(MCP client) summarizes the queue and explains why an investigation is ranked high, using the score and the signals behind it. The ranking itself stays with the deterministic scoring logic, so the analyst sees one consistent ordering.

## 6. Feedback capture

When an analyst disagrees with a recommendation, Claude asks one structured question: why? The answer becomes a labelled outcome, for example "false positive: known travel." This feeds the feedback loop that improves detection quality over time.

## Guardrails

- **Read-only by default.** Claude can create pending requests and drafts, but it cannot approve containment or write to the official record.
- **Cited claims.** Every factual claim in an output cites a source ID.
- **Untrusted text.** Attacker-controlled text (payee names, support messages) is marked as data so it cannot steer the brief.
- **Logging.** Every brief and draft generation is logged with the analyst ID.
- **Measured benefit.** Track time from case open to decision, and the rate at which analysts edit Claude's drafts. A high edit rate means the output isn't helping.

## What to build first

The case brief with citations, delivered through the MCP server. It gives the most time savings with the least risk, and it is easy to measure against current average handling time.
