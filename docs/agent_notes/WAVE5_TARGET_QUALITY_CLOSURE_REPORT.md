# Wave 5 Report — Target Quality Closure

Report date: 2026-09-10

## Summary

Wave 5 is verified complete. Every finding-construction path in all seven target pipelines now serializes references, including the older focused Cisco IOS, Cisco IOS-XE, Cisco ASA, Fortinet FortiOS, Juniper Junos, and Juniper ScreenOS plugins and the previously misdocumented Cisco IOS/ASA baseline helpers. The permanent target corpus grew from 14 to 20 configurations with sanitized syntax and effective-state variants. The public regression gate now validates emitted target references as well as exact finding snapshots.

No rule IDs, severity levels, thresholds, or detection semantics were intentionally changed in this wave.

## Verified True (with evidence)

- All 14 target plugin source files pass an AST-level invariant that every `Finding(...)` call supplies `references=`.
- All declared focused reference constants are HTTPS URLs on Cisco, Fortinet, or Juniper documentation domains.
- Every finding encountered through the permanent public pipelines has at least one HTTPS reference.
- The six new inputs exercise ordered enable/disable and set/unset state, alternate IOS SSH spelling, named and IPv6 VTY restrictions, removed ASA management grants, quoted FortiOS values, disabled policies, unused weak crypto objects, native hierarchical Junos, inactive Junos terms, and a recoverable malformed ScreenOS line.
- Exact snapshots pass for all 20 corpus inputs.

Focused verification:

```text
89 passed, 1 warning in 0.65s
```

Full verification:

```text
340 passed, 1 warning in 2.11s
Regression corpus passed: 20 configurations
```

The warning is the existing Windows pytest-cache permission warning and does not represent a test failure.

## Fixed This Session

### Finding references

- IOS HTTP findings cite Cisco's HTTP/HTTPS web-server configuration guide.
- IOS SSH findings cite Cisco's Secure Shell configuration guide.
- IOS-XE MACsec findings cite Cisco's MACsec/MKA guide; active IKE/IPsec findings cite Cisco's security and VPN guide.
- ASA management, enable-password, SNMP, logging, TLS, and access-rule findings cite their corresponding Cisco guide or command-reference pages.
- FortiOS management, firewall-policy, administrative TLS, and centralized-logging findings cite the corresponding Fortinet administration or CLI guides.
- Junos management, attached-filter, and root-SSH findings cite Juniper remote-access, management-filter, and SSH references.
- ScreenOS management and policy findings cite Juniper's maintained ScreenOS 6.3 documentation collection.

### Enforcement

- Added `tests/test_focused_plugin_references.py` to prevent uncited target-plugin `Finding` constructors and reject non-authoritative or non-HTTPS focused reference constants.
- The public regression runner now fails when any emitted target finding lacks an HTTPS source or contains an insecure external reference URL.
- Corrected an older inventory mismatch by adding Cisco's IOS hardening guide to the IOS baseline helper and Cisco's maintained ASA configuration-guide collection to the ASA baseline helper.

### Permanent corpus

- Added one syntax/effective-state fixture for each older focused platform.
- Updated the manifest with exact observed results and kept the per-platform corpus-count assertion explicit: three inputs for each older focused platform and two for Check Point FW1.
- The ASA, FortiOS, and ScreenOS variants intentionally retain one, three, and one baseline findings respectively; these are exact expected results rather than fixture-cleanliness claims.

## Source Material

Primary vendor documentation was verified during this wave. Representative sources include:

- Cisco IOS XE HTTP Services: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-17/https-xe-17-book/HTTP_1-1_Web_Server_and_Client.html
- Cisco IOS XE Secure Shell: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html
- Cisco IOS XE MACsec/MKA: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/macsec/configuration/xe-3s/macsec-xe-3s-book.html
- Cisco ASA management, SNMP, logging, TLS, and access-rule guides under https://www.cisco.com/c/en/us/td/docs/security/asa/
- Fortinet FortiGate administration and CLI documentation under https://docs.fortinet.com/document/fortigate/7.6.5/
- Juniper Junos and ScreenOS documentation under https://www.juniper.net/documentation/

## Architecture Deviations Introduced (if any)

None. References use the existing neutral `Finding.references` field, focused plugins retain their existing organization, and corpus validation remains in the established public-pipeline runner.

The source-level AST invariant is a new test convention, not a runtime architecture change. It covers all target plugin files; stricter vendor-domain evaluation of individual constants remains focused on the older plugin files named by Wave 5.

## Open Questions for Human

`NEEDS_HUMAN_REVIEW`: the new fixtures are sanitized, purpose-built representations of real export syntax patterns; they are not derived from confidential customer files. When customer-derived edge cases are available, remove all secrets and identifying data, review expected findings explicitly, and add them without replacing these deterministic fixtures.

`NEEDS_HUMAN_REVIEW`: vendor documentation paths are authoritative but versioned. Review links opportunistically during future rule maintenance in case vendors retire or redirect older documentation pages.

## Recommended Next Steps

Stop at the Wave 5 boundary. With human approval, begin Wave 6 with PAN-OS parser scope/reference reconstruction, effective policy semantics, and a paired permanent corpus. Keep HP/ArubaOS-Switch, SonicOS, and Arista EOS described as basic until their own Level-2 acceptance gates pass.
