# Account Takeover (ATO) Risk Rules

## Cross-Channel Correlation Rules

### Rule 1: Login → Device → Reset → Support → Transaction
A sequence of signals across all five channels within a short time window indicates a coordinated ATO attempt.

**Signals**:
- credential_stuffing_detected (login)
- new_device + emulator_detected (device)
- reset_after_failures_unusual_time (reset)
- support_takeover_pattern (support)
- new_payee + test_payment (transaction)

**Action**: Temporary hold, step-up authentication, fraud team review, customer notification

### Rule 2: Velocity Thresholds
- 10+ failed logins in 5 minutes: credential stuffing
- 3+ password resets in 1 hour: reset abuse
- 5+ support contacts in 2 hours: social engineering pattern
- 2+ new payees in 24 hours: cash-out preparation

### Rule 3: Time-Based Anomalies
- Login/reset/transaction between 2-6 AM local time: unusual timing
- Weekend activity for business accounts: elevated risk
- Rapid successive transactions: cash-out sequence

## Confidence Aggregation
- Single channel high confidence: moderate overall confidence
- Two+ channels moderate confidence: high overall confidence
- Three+ channels any confidence: very high overall confidence

## Escalation Paths
- Low confidence: monitor, log for audit
- Moderate confidence: step-up authentication, notify user
- High confidence: temporary hold, fraud team review
- Very high confidence: immediate hold, customer contact, fraud investigation

## Related Playbooks
- login_channel.md
- device_channel.md
- reset_channel.md
- support_channel.md
- transaction_channel.md
