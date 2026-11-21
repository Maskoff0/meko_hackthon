# Account Takeover (ATO) Playbook — Reset Channel

## Overview
Detects account takeover attempts through password reset signals.

## Signals
- **Reset after failures**: Password reset requested after failed login attempts
- **Unusual time**: Password reset at unusual hours (e.g., 2-6 AM local time)
- **Multiple resets**: 3+ password resets in a short window
- **Multiple contacts**: Multiple support contacts about the same account

## Reason Codes
- `password_reset_after_failures` — reset requested after login failures
- `password_reset_unusual_time` — reset at unusual hours
- `multiple_reset_requests` — 3+ resets in short window
- `multiple_support_contacts` — repeated support contacts

## Confidence Thresholds
- Reset after failures + unusual time: high confidence (>= 0.75)
- Multiple resets: moderate confidence (>= 0.6)
- Single reset at unusual time: low confidence (>= 0.4)

## Recommended Actions
- Reset after failures + unusual time: step-up authentication, temporary hold, notify user via alternate channel
- Multiple resets: require identity verification, block further resets for 24h
- Single reset at unusual time: email notification, monitor for follow-up activity

## Related Playbooks
- login_channel.md — credential stuffing precedes reset
- support_channel.md — support takeover patterns often follow resets
