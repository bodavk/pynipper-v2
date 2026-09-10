# Changelog for Agent

All notable changes made by the autonomous agent to `bodavk/pynipper-v2`.

## [Unreleased]
- Added a version-gated Cisco IOS-family baseline for AAA/accounting, management lines, credential storage, SNMP, logging, NTP, banners, legacy services, interface protections, control-plane policing, and VPN cryptography.
- Added a version-gated Cisco ASA baseline for management AAA/accounting, local credentials, ASDM source/certificate controls, NTP, threat detection, uRPF, VPN cryptography, and failover authentication through the single ASA pipeline.
- Completed the target-vendor correctness wave: FortiOS interface/VDOM exposure and effective policy/TLS/logging checks, Check Point rule-boundary evaluation, and typed effective Junos and ScreenOS detections.
- Completed the remaining parser-correctness wave: Junos hierarchical and `display set` inputs now share one effective model, and ScreenOS now resolves interfaces, manager restrictions, users, objects, and policy continuations/removals.
- Completed the Cisco correctness wave: effective-state IOS HTTP/SSH rules, exact IOS version preservation, typed ASA management/logging/TLS/ACL/SNMP/credential checks, and scope-aware IOS-XE MACsec/crypto analysis composed with the IOS baseline.
- Refactored architecture: Implemented `BaseDeviceParser` interface for pluggable parsing.
- Implemented parsers and infrastructure for:
  - Palo Alto PAN-OS
  - Fortinet FortiOS
  - Cisco IOS-XE
  - Juniper JunOS
  - Arista EOS
- Implemented and verified initial security plugins for all above devices.
- Automated testing: Configured `pytest` in CI (`.github/workflows/build-python.yml`) and added comprehensive test suite for all plugins.
- Completed initial parity checks for SonicWALL SonicOS (SW-01) and HP ProCurve (HP-01).
