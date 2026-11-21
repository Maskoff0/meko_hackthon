# Account Takeover (ATO) Playbook — Support Channel

## Overview
Detects account takeover attempts through social engineering of support staff.

## Signals
- **Password reset after failures**: Support-initiated reset following login failures
- **Unusual timing**: Support contact at unusual hours
- **Multiple reset requests**: Repeated reset requests in short window
- **Multiple contacts**: Repeated support contacts about same issue

## Reason Codes
- `reset_after_failures_unusual_time` — reset after failures at unusual time
- `support_takeover_pattern` — pattern consistent with social engineering
- `multiple_reset_requests` — 3+ reset requests
- `multiple_support_contacts` — repeated support contacts

## Confidence Thresholds
- Support takeover pattern: high confidence (>= 0.75)
- Multiple reset requests: moderate confidence (>= 0.6)
- Single unusual contact: low confidence (>= 0.4)

## Recommended Actions
- Support takeover pattern: identity verification required, temporary hold, fraud team review
- Multiple reset requests: block automated resets, require manual verification
- Single unusual contact: flag for review, monitor account activity

## Related Playbooks
- reset_channel.md — reset signals often come through support
- login_channel.md — credential stuffing may precede support contact
