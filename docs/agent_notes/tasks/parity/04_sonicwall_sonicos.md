# Task: SonicWALL SonicOS Parser & Checks (Parity with Original Nipper-ng)

## Status
- [x] Completed (Parser implemented, security checks implemented, and verified with unit tests)

## Priority
MEDIUM — SonicWALL firewalls are heavily used in SMB (Small and Medium Business) sectors.

## Source of Truth
- Original nipper-ng reference: `reference\nipper-ng-original\libnipper-0.12.6\SonicWALL-SonicOS`

## Scope
- Device/vendor: SonicWALL
- OS/firmware: SonicOS 6.x / 7.x

## Parser Requirements
1. File location: `src/devices/sonicwall/sonicos.py`

## Plugin/Check Requirements
- [x] SW-01: HTTP Management Enabled
- [x] SW-02: Default Admin Credentials
- [x] SW-03: Weak Encryption for VPNs

