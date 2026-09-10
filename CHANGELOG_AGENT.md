# Changelog for Agent

All notable changes made by the autonomous agent to `bodavk/pynipper-v2`.

## [Unreleased]
- Cleaned the inherited architecture by removing obsolete ASA pipeline wrappers and duplicate plugins, standalone IOS parsing helpers, vendor-specific issue and registry compatibility modules, unused generated test artifacts, and an unused dependency. IOS now uses explicit deterministic plugin registration through the shared `BasePlugin` contract. Replaced the inherited README/status/contribution/security content, added current architecture and extension guides, modernized the offline HTML report, corrected the CLI `--offline` flag to disable online advisory lookup as documented, and replaced inherited Python 3.6-era/unconfigured workflows with the permanent cross-platform regression gate and supported CodeQL action.
- Added a permanent paired regression corpus for Cisco IOS, IOS-XE, ASA, FortiOS, Junos, ScreenOS, and Check Point FW1, with exact duplicate-preserving rule-ID snapshots and a reusable full-regression command that validates every target public parser/plugin pipeline before running the complete test suite. The cumulative result is documented in `docs/agent_notes/FINAL_QUALITY_REPORT.md`; secondary vendors remain explicitly partial.
- Expanded the Check Point FW1 offline-policy baseline with typed ordered layers, rules, network/service objects and nested groups; legacy anonymous-name compatibility; explicit cleanup and stealth checks; broad, risky, negated, untracked, expired, disabled, and broadly installed rule checks; conservative same-layer shadow/redundancy analysis; and unresolved rule/group reference detection. The documentation now distinguishes static export findings from compiled, installed, dynamic-object, hit-count, and cross-layer state that the files cannot prove.
- Expanded the FortiGate baseline with VDOM/global-aware administrator trust, remote authentication and MFA, password/lockout/session policy, management crypto/certificates, active SNMPv3, authenticated NTP, policy logging/inspection, local/remote log filtering and secondary logging destinations, FortiGuard/firmware posture, unused interface/service, and DoS rules. FortiOS 7.x absence findings use documented defaults; older and unversioned exports remain explicit-state only, and parser evidence now redacts secrets centrally.
- Expanded the Juniper baseline: Junos now checks centralized authentication, login lockout, local credential storage, explicit SSH algorithms, legacy services, SNMPv1/v2c and SNMPv3 security, remote logging, authenticated NTP, Routing Engine filters, and redirects; ScreenOS now checks EOL posture, management restrictions and timeouts, SSHv2/HTTPS state, known default credentials, banners, effective syslog/SNMP/NTP, high-risk policy logging, and referenced VPN proposal cryptography.
- Added optional security references to the neutral finding schema and render serialized references and evidence in reports, allowing new controls to cite the vendor documentation used for their semantics and remediation.
- Normalized effective Junos and ScreenOS logging and cryptographic configuration, including ScreenOS global SSL activation and ordered set/unset handling with secret-redacted evidence.
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
