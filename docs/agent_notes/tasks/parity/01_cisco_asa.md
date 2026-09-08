# Task: Cisco ASA Firewall Parser & Checks (Parity with Original Nipper-ng)

## Status
- [x] Completed (Implemented Cisco ASA parser and checks, validated with tests and report generation)

## Priority
CRITICAL — Cisco ASA firewalls are still widely deployed in enterprise networks. Securing management access, ACLs, and VPN settings on these devices is high-value.

## Source of Truth
- Original nipper-ng reference: `reference\nipper-ng-original\libnipper-0.12.6\Cisco-Security-ASA`
- Vendor hardening guide: Cisco ASA Series Hardening Guide (CIS Cisco ASA Firewall Benchmark v4.1.0)

## Architecture Notes
- Which existing parser(s)/plugin(s) most closely resemble this one: `src/analyze/cisco/ios/cisco_parser/parse_config.py`. ASA syntax is similar to IOS but has significant differences (e.g., names, object-groups, unified ACLs).
- Expected deviation: ASA uses `object-group` for ACLs which requires a more complex parser than standard IOS flat ACLs.

## Scope
- Device/vendor: Cisco ASA
- OS/firmware versions to support: 9.x
- Config dialect quirks: No line-continuation, but uses block-like structures for crypto maps and object-groups.

## Parser Requirements
1. File location: `src/devices/cisco/asa.py`
2. Must extract at minimum the following sections:
   - [x] Hostname / device identity
   - [x] Local user accounts (including `username ... privilege ... password ...`)
   - [x] Enable password (`enable password ...`)
   - [x] AAA / RADIUS / TACACS+ server configuration
   - [x] SNMP config (`snmp-server host ...`, communities)
   - [x] SSH/Telnet management access (`ssh ...`, `telnet ...`)
   - [x] Logging config (`logging host ...`, console, buffered)
   - [x] Interfaces (`interface ...`, `nameif`, `security-level`)
   - [x] ACLs / Object-groups (`access-list ...`, `object-group ...`)
   - [x] VPN/crypto config (`crypto ikev3/ikev2 ...`, tunnel-groups)
   - [x] NTP config (`ntp server ...`)

## Plugin/Check Requirements
List of checks based on original nipper-ng ASA audit capabilities:
   - [x] ASA-01: Telnet Enabled — Telnet is clear-text and should be disabled.
   - [x] ASA-02: Weak Enable Password — Flag if enable password is weak or default.
   - [x] ASA-03: Insecure SNMP Communities — Flag "public" or "private" community strings.
   - [x] ASA-04: Unrestricted SSH Access — Check if SSH is allowed from `0.0.0.0`.
   - [x] ASA-05: Missing Logging Configuration — Flag if syslog is not configured.
   - [x] ASA-06: Insecure SSL/TLS Versions — Check for SSLv3/TLS1.0 enabled for management.
   - [x] ASA-07: Wide Open ACLs — Flag `any any` rules on interfaces with low security levels.

## Test Requirements
- [x] At least one clean/secure sample config (minimal findings)
- [x] At least one intentionally-vulnerable sample config (all checks triggered)
- [x] Unit tests for the parser's extraction logic
- [x] Unit tests for each plugin (assert Finding objects)

## Acceptance Criteria
- [x] Parser handles ASA `object-group` expansion correctly
- [x] All plugins produce correct findings on the vulnerable sample
- [x] Registered in device factory / CLI `-d` as `ASA`
- [x] Documentation updated in `docs/SUPPORTED_DEVICES.md`
