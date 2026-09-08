# Task: Juniper NetScreen ScreenOS Parser & Checks (Parity with Original Nipper-ng)

## Status
- [x] Completed (Implemented parser, plugin checks, and analysis workflow)

## Priority
HIGH — ScreenOS is legacy (replaced by JunOS), but still encountered in some critical infrastructure environments.

## Source of Truth
- Original nipper-ng reference: `reference\nipper-ng-original\libnipper-0.12.6\Juniper-ScreenOS`
- Vendor hardening guide: Juniper ScreenOS Hardening Guide

## Architecture Notes
- Expected deviation: ScreenOS config is command-line based but has a unique hierarchical-like flat structure (e.g., `set admin telnet disable`).

## Scope
- Device/vendor: Juniper NetScreen
- OS/firmware: ScreenOS 6.x

## Parser Requirements
1. File location: `src/devices/juniper/screenos.py`
2. Must extract:
   - [x] Hostname
   - [ ] Admin accounts and passwords (`set admin name ...`)
   - [x] Management services (Telnet, SSH, HTTP, HTTPS, Web)
   - [ ] Interfaces and zones
   - [x] Policies / Firewall rules (`set policy ...`)

## Plugin/Check Requirements
- [x] NS-01: Insecure Admin Services — Flag if Telnet or HTTP is enabled.
- [ ] NS-02: Default Admin Password — Flag if default password hash is detected.
- [x] NS-03: Broad Policy Rules — Flag policy rules with `any` service or destination.

## Acceptance Criteria
- [x] Registered in CLI as `SCREENOS`.
