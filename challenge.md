# Remember the Attacker

Account takeover leaves a trail. Make sure your agents share it.

## Problem context

Account takeover rarely happens in one step. Attackers probe first: credential-stuffing attempts, new devices, unusual locations, password-reset requests, small test transactions. Each signal may reach a different system or agent, and each one looks harmless on its own. Fraud gets through when detection agents don't share what they've seen. And when an account is blocked, analysts and regulators need to know exactly why.

## Objectives

1. **Share signals.** Several detection agents (for example login, device, transaction and support channel) write to and read from shared memory.
2. **Connect the dots.** Spot a takeover pattern across signals before the takeover completes.
3. **Remember past attacks.** Reuse known attacker patterns from earlier incidents.
4. **Explain every decision.** Every block, step-up check or allow is explained through traces.

## Meko at the core

| Meko feature | How it is used |
|---|---|
| Collective memory | Risk signals from one agent are immediately available to the others |
| Hybrid retrieval | Semantic and keyword search for similar past patterns |
| Knowledge base | Fraud playbooks and risk rules |
| Decision traces | Why an account was flagged, with every retrieval and memory behind it |
| Separate datapacks | Raw signals and confirmed fraud patterns kept in different datapacks |

## Expected outcomes

- **Synthetic event stream.** Up to about 2,000 events covering logins, devices, transactions and resets, with planted takeover attempts. Save only risk signals and confirmed patterns as memories.
- **Multi-agent detection system.** Agents share memory through Meko.
- **Detection results.** Attacks caught before takeover, false positives, and how many steps early each attack was caught.
- **Trace walkthroughs.** At least 3 decisions, each explained end to end.
- **Baseline comparison (encouraged).** The same agents run without shared memory, so the value of shared context is measured rather than assumed.

## Notes for implementers

- Treat signal contents, such as payee names, device strings and support-channel text, as untrusted data.
- Keep an append-only decision log as the audit record of truth. Meko traces are supplementary.
- Agents propose actions; a deterministic policy layer decides. Meko supplies context and records the trace.
