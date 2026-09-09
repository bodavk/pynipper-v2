# Task: HP ProCurve Switch Parser & Checks (Parity with Original Nipper-ng)

## Status
- [x] Completed (Parser implemented, security checks implemented, and verified with unit tests)

## Priority
HIGH — HP ProCurve (and modern ArubaOS-S) switches are common in campus networks. Auditing their configuration is highly relevant for internal network security.

## Source of Truth
- Original nipper-ng reference: `reference\nipper-ng-original\libnipper-0.12.6\HP-ProCurve`
- Vendor hardening guide: HP Switch Security Hardening Guide (CIS HP ProCurve Benchmark)

## Architecture Notes
- Which existing parser(s)/plugin(s) most closely resemble this one: None. This is the first non-Cisco device.
- Expected deviation: HP ProCurve uses a different CLI syntax than Cisco. We need a new base class or adapter for HP configuration parsing.

## Scope
- Device/vendor: HP (ProCurve / ArubaOS-S)
- OS/firmware versions to support: K/YA/YB branches
- Config dialect quirks: Flat configuration but uses different delimiters and keywords (e.g., `vlan 1 ip address ...` instead of interface blocks).

## Parser Requirements
1. File location: `src/devices/hp/procurve.py`
2. Must extract at minimum the following sections:
   - [x] Hostname
   - [x] Local users / passwords (`password manager user ...`)
   - [x] SNMP settings
   - [x] SSH/Telnet/console/management access config
   - [x] Logging settings (`logging <ip>`)
   - [x] VLANs and IP addresses

## Plugin/Check Requirements
- [x] HP-01: Telnet Enabled — Check if Telnet management is active.
- [x] HP-02: SNMP Default Communities — Check for default community strings.
- [x] HP-03: Insecure Web Management — Check if HTTP (clear-text) is enabled instead of HTTPS.
- [x] HP-04: Lack of SSH Key Exchange Hardening — Check SSH cipher/KEX settings.

## Test Requirements
- [x] One clean HP configuration sample.
- [x] One vulnerable HP configuration sample.
- [x] Parser and plugin unit tests.

## Acceptance Criteria
- [x] Registered in CLI as `HP_PROCURVE`.
- [x] Correctly parses HP VLAN-centric interface configurations.

