# Account Takeover (ATO) Playbook — Device Channel

## Overview
Detects account takeover attempts through device-related signals.

## Signals
- **New device**: First-time login from an unrecognized device
- **Emulator detected**: Login from an emulator or virtual device
- **Device fingerprint change**: Significant change in device attributes

## Reason Codes
- `new_device` — login from previously unseen device
- `emulator_detected` — login from emulator/virtual environment
- `device_fingerprint_change` — significant device attribute change

## Confidence Thresholds
- New device + emulator: high confidence (>= 0.85)
- New device only: moderate confidence (>= 0.65)
- Device fingerprint change: low confidence (>= 0.4)

## Recommended Actions
- New device + emulator: step-up authentication, device challenge, temporary hold
- New device only: email verification, notify user of new device
- Device fingerprint change: monitor for additional signals

## Related Playbooks
- login_channel.md — credential stuffing, failed logins
- reset_channel.md — password reset after failures
