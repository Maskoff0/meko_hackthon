# Account Takeover (ATO) Playbook — Transaction Channel

## Overview
Detects account takeover attempts through transaction-related signals.

## Signals
- **New payee**: First-time payment to a new recipient
- **Test payment**: Small test payment before larger transfer
- **Limit change**: Credit/debit limit increase request
- **Cash-out sequence**: Rapid movement of funds to external accounts

## Reason Codes
- `new_payee` — payment to previously unseen recipient
- `test_payment` — small test transaction before larger transfer
- `limit_change` — credit/debit limit increase
- `cash_out_sequence` — rapid fund movement

## Confidence Thresholds
- New payee + test payment: high confidence (>= 0.8)
- New payee only: moderate confidence (>= 0.6)
- Limit change only: low confidence (>= 0.4)

## Recommended Actions
- New payee + test payment: step-up authentication, temporary hold, notify user
- New payee only: email verification, transaction delay
- Limit change only: require MFA, notify user of limit change

## Related Playbooks
- login_channel.md — credential stuffing may precede fraudulent transactions
- device_channel.md — new device often used for fraudulent transactions
