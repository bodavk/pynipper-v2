# Task: Fortinet FortiOS Parser & Checks

## Status
- [ ] Not started

## Priority
CRITICAL — FortiGate firewalls are highly prevalent across all segments of network security.

## Source of Truth
- FortiOS Command Reference
- CIS Fortinet Fortigate Benchmark v1.0.0
- DISA Fortinet FortiGate STIG

## Architecture Notes
- Which existing parser(s)/plugin(s) most closely resemble this one: Cisco IOS parser, but uses `config <module>` ... `edit <name>` ... `set <prop>` ... `next` ... `end` block structures.
- Expected deviation: Parser must maintain a block hierarchy state to contextualize properties (e.g. knowing which firewall policy a set rule belongs to).

## Scope
- Device/vendor: Fortinet
- OS version to support: FortiOS 7.x
- Config dialect quirks: Block-nested CLI format.

## Parser Requirements
1. File location: `src/devices/fortinet/fortios.py`
2. Must extract:
   - [ ] Hostname (`config system global` -> `set hostname <name>`)
   - [ ] Administrators and administrative access (`config system admin`)
   - [ ] DNS, NTP, and Syslog setups
   - [ ] Firewall Policies (`config firewall policy`)
   - [ ] SSL/TLS administrative settings

## Plugin/Check Requirements
- [ ] FT-01: Weak Administrative Access — Check if HTTP or Telnet is permitted for admin access (`set admin-port`, `set admin-sport`).
- [ ] FT-02: Broad Firewall Policies — Check for policy entries with source/destination `all` combined with service `ALL` and action `accept`.
- [ ] FT-03: Insecure TLS Settings — Flag if TLS 1.0 or 1.1 is enabled for administrative HTTPS access.
- [ ] FT-04: Lack of System Logging — Flag if syslog is not configured or disabled.

## Test Requirements
- [ ] Hardened FortiOS config sample.
- [ ] Insecure FortiOS config sample (all checks triggered).
- [ ] Parser block state tracker unit tests.
- [ ] Audit rule verification tests.

## Acceptance Criteria
- [ ] Registered in CLI as `FORTIOS`.
- [ ] Correctly resolves nesting without loss of scope context.
