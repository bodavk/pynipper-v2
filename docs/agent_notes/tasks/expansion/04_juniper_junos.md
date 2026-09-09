# Task: Juniper Networks JunOS Parser & Checks

## Status
- [x] Completed (Parser implemented, security checks implemented, and verified with unit tests)

## Priority
HIGH — Standard operating system for Juniper's routers and EX/QFX switches.

## Source of Truth
- JunOS Security Configuration Guide
- CIS Juniper OS Benchmark v1.0.0
- DISA Juniper JunOS STIG

## Architecture Notes
- Expected deviation: JunOS uses flat `set` commands or brace-based hierarchy `{ }`. If parsing hierarchical braces, a bracket balancing tokenizer is required. To simplify first iteration, we can support parsing the output of `show configuration | display set` (linear line-by-line parsing).

## Scope
- Device/vendor: Juniper Networks
- OS version to support: JunOS 21.x / 22.x

## Parser Requirements
1. File location: `src/devices/juniper/junos.py`
2. Must extract (assuming `display set` syntax):
   - [x] Hostname (`set system host-name ...`)
   - [x] Login accounts and authentication classes (`set system login ...`)
   - [x] Management services (SSH, Telnet, Web-management)
   - [x] Firewall filters / ACLs (`set firewall family ...`)

## Plugin/Check Requirements
- [x] JUN-01: Insecure Web / CLI management — Flag if HTTP or Telnet services are enabled.
- [x] JUN-02: Broad Firewall Filters — Flag filters that permit any source/destination without logging enabled.
- [x] JUN-03: SSH Root Login — Flag if root login is permitted via SSH.

## Acceptance Criteria
- [x] Registered in CLI as `JUNOS`.
