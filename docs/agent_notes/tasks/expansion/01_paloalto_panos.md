# Task: Palo Alto Networks PAN-OS Parser & Checks

## Status
- [x] Completed (Parser implemented, security checks implemented, and verified with unit tests)

## Priority
CRITICAL — Palo Alto is the leading next-generation enterprise firewall provider.

## Source of Truth
- PAN-OS XML Configuration Schema
- Palo Alto Best Practice Assessment (BPA) guides
- CIS Palo Alto Networks Firewall Benchmark v1.0.0

## Architecture Notes
- Which existing parser(s)/plugin(s) most closely resemble this one: None. This is the first XML-based structured parser.
- Expected deviation: PAN-OS configs are native XML. It will use Python's built-in `xml.etree.ElementTree` rather than regex line parsing.

## Scope
- Device/vendor: Palo Alto Networks
- OS version to support: PAN-OS 10.x / 11.x
- Config dialect quirks: Full config is formatted in deeply nested XML tags.

## Parser Requirements
1. File location: `src/devices/paloalto/panos.py`
2. Must extract:
   - [x] Hostname (`/config/devices/entry/system/hostname`)
   - [x] Admin accounts and roles (`/config/mgt-config/users`)
   - [x] DNS, NTP, Syslog servers configuration
   - [x] Management profile services (allowed HTTP, SSH, Telnet, HTTPS, Ping)
   - [x] Security rules (Source, Destination, Application, Service, Action)
   - [x] Interfaces and zones

## Plugin/Check Requirements
- [x] PAN-01: Insecure Management Interfaces — Flag if HTTP, Telnet, or clear-text management is enabled in any interface management profile.
- [x] PAN-02: Broad Security Rules — Flag rules where Source Zone is `any`, Destination Zone is `any`, and Service is `any` combined with `allow`.
- [x] PAN-03: Missing Syslog Forwarding — Check if syslog profiles are configured and associated with security rules.
- [x] PAN-04: Default Admin Credentials / Insecure Passwords — Check user database for legacy/weak parameters.

## Test Requirements
- [x] Clean XML config with strong profile security.
- [x] Vulnerable XML config with HTTP allowed on management, any-any-any security rules, and missing syslogs.
- [x] Unit tests for XML extraction and plugin rules.

## Acceptance Criteria
- [x] Registered in CLI as `PAN_OS`.
- [x] Parser handles XML nesting with no recursion faults.
