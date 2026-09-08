# Task: CheckPoint Firewall-1 (FW1) Parser & Checks (Parity with Original Nipper-ng)

## Status
- [x] Completed (Implemented parser scaffold, recursive directory-based parsing, and initial security plugins)

## Priority
CRITICAL — CheckPoint remains a major enterprise firewall player.

## Source of Truth
- Original nipper-ng reference: `reference\nipper-ng-original\libnipper-0.12.6\CheckPoint`

## Scope
- Device/vendor: CheckPoint FW1

## Parser Requirements
1. File location: `src/devices/checkpoint/fw1.py`

## Plugin/Check Requirements
- [x] CP-01: Insecure Object Definitions
- [x] CP-02: Broad Filter Rules
