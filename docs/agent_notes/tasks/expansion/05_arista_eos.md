# Task: Arista EOS Parser & Checks

## Status
- [x] Completed (Parser implemented, inheriting from IOS; plugin check implemented)

## Priority
MEDIUM — Dominant switch OS in enterprise data centers.

## Source of Truth
- Arista EOS Security Guidelines
- CIS Arista EOS Benchmark v1.0.0

## Architecture Notes
- Expected deviation: Reuses classic Cisco IOS configuration parser style directly, as EOS syntax is extremely aligned with Cisco CLI.

## Scope
- Device/vendor: Arista Networks
- OS version to support: EOS 4.x

## Parser Requirements
1. File location: `src/devices/arista/eos.py` (subclasses `CiscoIOSParser`)
2. Must extract:
   - [x] Hostname
   - [x] Management API configuration (`management api http-commands`)
   - [ ] Local users and passwords

## Plugin/Check Requirements
- [x] AR-01: Unsecured Management API — Check if HTTP management API is enabled without HTTPS, or if default tokens are used.
- [ ] AR-02: Cisco IOS classic checks compatibility.

## Acceptance Criteria
- [x] Registered in CLI as `ARISTA_EOS`.
