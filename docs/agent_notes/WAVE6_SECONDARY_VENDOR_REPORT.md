# Wave 6 Secondary-Vendor Correctness Report

Date: 2026-09-10

## Outcome

Wave 6 replaces the four secondary-vendor placeholder implementations with tested correctness baselines. T-007, T-010, T-011, T-019, T-022, T-024, and T-027 are complete. T-030 and T-032 have verified core baseline slices but remain open for the advanced categories listed below. This report does not claim that the four platforms have the same breadth as the seven prioritized target platforms.

## PAN-OS

- Replaced isolated XPath checks with a namespace-tolerant typed XML model for devices, vsys, interfaces, zones, management-profile definitions and attachments, security rule order/state, log-forwarding profile references, administrators, password policy, DNS, NTP, SNMPv3, and metadata.
- Resolves management profiles within their owning device, preventing same-named profiles on different devices from cross-resolving.
- Separates dataplane interface profiles from explicitly configured dedicated-MGT services and retains permitted-IP and zone context.
- Evaluates only enabled allow rules and requires all wildcard dimensions before reporting an unrestricted rule. Logging and security-profile checks resolve same-vsys attachments.
- Treats Panorama device-group/template inheritance as explicit unknown and emits a single informational confidence finding rather than pretending the individual file is effective merged state.
- Added core administrator, DNS/NTP, SNMPv3, password, management, policy logging, and inspection findings with Palo Alto documentation references.

Remaining T-030 work: management certificate and TLS profile validation, content/firmware update posture, broader remote system/threat log forwarding, and further platform-specific controls.

## ArubaOS-Switch / HP ProCurve

- Replaced substring matches with exact, ordered positive/negative command handling for Telnet, SSH, HTTP WebAgent, and HTTPS WebAgent.
- Unknown releases no longer inherit fabricated service defaults. The documented default table is applied only to AOS-S 16.10; other releases require explicit commands.
- Parses model/release headers, local manager/operator users with redacted evidence, authorized managers, centralized AAA methods, SNMP communities, SNMPv3 users, SSH cipher/KEX/MAC mutations, syslog, and SNTP.
- Default-community matching is exact, so names such as `public-readers` do not produce a default-community finding. Later `no` commands remove effective objects.
- SSH algorithm findings run only when SSH is enabled and the suite is known from the supported default table or explicit commands.

Remaining T-032 work: advanced interface/port security, certificate posture, additional authorization/accounting cases, and release-family-specific defaults beyond 16.10.

## SonicOS

- Defined the supported input as plain-text SonicOS 7 E-CLI output from `show current-config custom` (or the equivalent CLI export API).
- Rejects the former invented `set service/admin/vpn` test dialect, legacy/binary preferences exports, SonicOS 6.x, and unidentifiable text before analysis.
- Parses firmware/product/hostname metadata, interface zone and management attachment, enabled/disabled access rules, active VPN policies and complete proposal fields, syslog, NTP, SNMPv3, and explicit threat-service state.
- Replaced broad text searches with object-bound management, access-rule logging/breadth, and referenced active VPN proposal findings.
- Does not infer whether the built-in administrator password remains unchanged because the supported current-config export does not prove that fact; normalized administrator state is explicit unknown.

Remaining T-032 work: certificate/TLS posture, firmware lifecycle/advisory correlation, additional security-service applicability/licensing, administrator/role detail where safely exported, and more customer-derived E-CLI grammar variants.

## Arista EOS

- Reconstructs each `management api http-commands` block and its effective shutdown state, HTTP and HTTPS protocols, VRF scope, and IPv4/IPv6 service ACLs.
- HTTPS text outside the eAPI block cannot satisfy the rule, inactive definitions do not report exposure, and HTTP/HTTPS are evaluated independently.
- Adds EOS metadata, local-user redaction, centralized AAA, SNMP community/SNMPv3, remote syslog, and NTP state.
- Findings cover clear-text or HTTPS-disabled eAPI, missing service ACLs, local-only management authentication, exact default communities, missing secure SNMPv3 replacement, logging, and time sources.

Remaining T-032 work: deeper role/authorization, SSH algorithm and VRF posture, management-interface controls, certificates, control-plane policing/ACLs, and firmware posture.

## Permanent regression coverage

The corpus increased from 20 to 32 configurations and now exercises eleven public pipelines. New cases are:

- PAN-OS vulnerable, secure, and Panorama-inheritance XML.
- AOS-S 16.10 vulnerable and secure configurations plus an unknown-release case.
- Arista EOS vulnerable and secure configurations plus an inactive eAPI block.
- SonicOS 7 vulnerable and secure E-CLI configurations plus disabled rule/VPN objects.

The corpus runner constructs parsers through the public registry, requests normalized state, invokes public processors, compares exact duplicate-preserving rule IDs and counts, rejects duplicate rule/evidence identities, and requires an HTTPS reference on every emitted finding.

Verification evidence:

```text
Regression corpus passed: 32 configurations
364 passed, 1 warning in 1.41s
```

The warning is the pre-existing Windows pytest-cache permission warning and is unrelated to parser or finding behavior.

## Explicit limitations and human review

- `NEEDS_HUMAN_REVIEW`: PAN-OS uses a 12-character project password minimum; Palo Alto documents a product minimum of eight. Replace the project threshold with the approved organizational benchmark if different.
- `NEEDS_HUMAN_REVIEW`: the AOS-S weak SSH list is the project cryptographic policy applied to the algorithms documented for 16.10. Review it against the organization's interoperability and cryptographic standards.
- SonicOS support intentionally excludes WebUI `.exp` preference files and SonicOS 6.x E-CLI. These inputs now fail loudly rather than returning a misleading empty analysis.
- PAN-OS Panorama inheritance is not reconstructed from a single export. Use a merged effective device configuration or supply the complete Panorama hierarchy.
- Add anonymized customer-derived fixtures as they become available; current permanent cases are sanitized, purpose-built examples of documented vendor syntax.
