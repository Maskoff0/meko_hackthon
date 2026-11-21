# Account Takeover (ATO) Playbook — Login Channel

## Overview
Detects credential-based account takeover attempts through the login channel.

## Signals
- **Credential stuffing**: 10+ failed logins in a short window, or failure rate >= 0.8
- **Elevated failed logins**: 5-9 failed logins
- **Minor login failures**: 1-4 failed logins
- **New location**: Login from a previously unseen geographic location
- **New IP**: Login from a previously unseen IP address

## Reason Codes
- `failed_login_velocity` — high volume of failed login attempts
- `high_failure_rate` — failure rate exceeds threshold
- `new_location` — login from new geographic location
- `new_ip` — login from new IP address

## Confidence Thresholds
- >= 0.8: credential_stuffing_detected (high confidence)
- >= 0.6: elevated_failed_logins (moderate confidence)
- >= 0.3: minor_login_failures (low confidence)
- < 0.3: no_login_anomaly

## Recommended Actions
- credential_stuffing_detected: step-up authentication, temporary hold, notify user
- elevated_failed_logins: monitor closely, require MFA on next login
- minor_login_failures: log for audit, no immediate action

## Related Playbooks
- device_channel.md — new device / emulator detection
- reset_channel.md — password reset after failures
- support_channel.md — support takeover patterns
- transaction_channel.md — new payee, test payments, limit changes
