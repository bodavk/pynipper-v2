# Wave 7 Secondary Baseline Closure Report

Date: 2026-09-10

## Outcome

Wave 7 closes T-030 and T-032 at a deliberately bounded static-analysis level. The four secondary platforms now combine the Wave 6 correctness models with additional management TLS, update, authorization, interface, SSH, time-security, and security-service dependency checks. Completion does not mean universal vendor coverage or parity with a live scanner.

## PAN-OS — T-030

- Parses shared and vsys-local SSL/TLS service profiles, including certificate, minimum TLS version, maximum TLS version, scope, and evidence.
- Resolves each local device's management `ssl-tls-service-profile` attachment and distinguishes a missing attachment, dangling reference, missing certificate, and weak/unspecified minimum TLS version as separate root causes.
- Recognizes the PAN-OS 11 direct TLS 1.3 management mode and certificate fields without treating it as an older profile attachment.
- Parses recurring dynamic-update schedules and requires the Applications and Threats action to be `download-and-install`; download-only and absent schedules remain findings.
- Parses device-level system-event syslog forwarding separately from security-rule traffic-log forwarding.
- Normalizes parsed SSL/TLS minimum-version evidence.
- Skips local absence checks when Panorama hierarchy is present and unresolved.

Sources: Palo Alto Networks SSL/TLS Service Profile, Device Setup Management, threat-prevention update, log-forwarding, and CLI hierarchy documentation.

Static limit: the XML does not establish whether a certificate is currently valid, correctly issued for the hostname, or near expiry. Software-version metadata is retained, but whether a release is currently supported is time-sensitive and requires a maintained advisory/lifecycle data source.

## ArubaOS-Switch / HP ProCurve — T-032

- Parses effective AAA accounting statements with ordered `no` removal and reports centralized management authentication without any active accounting target.
- Parses `password configuration-control`, including the documented AOS-S 16.10 disabled default, and reports local manager/operator credentials that are outside an enabled complexity policy.
- Parses configured VLAN lists and DHCP-snooping VLAN lists with guarded single, comma-separated, and range expansion plus ordered removal.
- Reports non-default configured VLANs missing DHCP snooping only for the supported AOS-S 16.10 default family; unknown releases remain unknown rather than inheriting the default.

Source: Aruba 2530 Access Security Guide for ArubaOS-Switch 16.10, including AAA accounting, Password Complexity, and Advanced Threat Protection/DHCP snooping sections.

Static limit: the analyzer does not guess endpoint/uplink roles, so it does not report per-port trust or port-security absence without role evidence. Default tables remain intentionally limited to AOS-S 16.10.

## Arista EOS — T-032

- Parses explicit `management ssh` blocks for empty-password policy, cipher, key-exchange, MAC, and IPv4/IPv6 service ACL statements.
- Applies ordered `no`/`default` removal and reports explicitly permitted empty passwords, explicitly listed weak algorithms, and explicit SSH policy blocks without service ACLs.
- Parses centralized `aaa authorization exec` and reports centralized login authentication that lacks centralized exec authorization.
- Normalizes explicitly configured SSH cryptographic algorithms.
- Does not invent the platform's implicit SSH suite when no explicit management SSH policy is exported.

Sources: current Arista EOS Session Management Commands, ACLs and Route Maps, User Security, and Control Plane Security documentation.

Static limit: the parser cannot validate an SSL profile's runtime state, certificate/key match, expiry, or trust chain from running configuration alone. `NEEDS_HUMAN_REVIEW`: align the project weak-SSH lists with the organization's approved cryptographic policy.

## SonicOS 7 E-CLI — T-032

- Replaces address-only NTP state with typed server records containing authentication and redacted source evidence.
- Preserves ordered `no ntp-server` removal and distinguishes no time source from configured but unauthenticated time sources.
- Extends explicit security-service state to Cloud Gateway Anti-Virus and Capture ATP.
- Reports Capture ATP enabled while Gateway Anti-Virus or Cloud Gateway Anti-Virus is explicitly disabled, following SonicWall's documented dependency.
- Removes the earlier unsupported claim that every explicitly disabled service is known to be licensed; unknown or absent licensing state is not treated as disabled.

Sources: SonicOS/X 7 CLI, System, Capture ATP, and Security Services documentation.

Static limit: the supported current-config export does not reliably prove the selected administration certificate's validity or service subscription state, and only SonicOS 7 E-CLI text is accepted. Firmware currency is time-sensitive and is not inferred from a hard-coded version list.

## Verification

Focused Wave 7 suite:

```text
30 passed, 1 warning in 0.34s
```

Permanent public-pipeline gate:

```text
367 passed, 1 warning in 1.42s
Regression corpus passed: 32 configurations
```

The corpus continues to exercise eleven public pipelines and exact duplicate-preserving finding snapshots. Wave 7 changes raise the vulnerable snapshots to PAN-OS 14, ArubaOS-Switch 12, Arista EOS 11, and SonicOS 10 findings; their secure and edge-case configurations remain at the explicitly expected counts. Every emitted corpus finding has at least one HTTPS source and unique rule/evidence identity.

The warning is the existing Windows pytest-cache permission warning and is unrelated to parser or detection behavior.

## Closure and next planning boundary

All tasks in `DETECTION_AUDIT_TASKS.md` are now complete at their documented static-analysis boundary. The next program should be planned separately using observed customer syntax, measured false-positive/false-negative feedback, and a deliberate choice among legacy dialects, new platforms, or an opt-in live-state/advisory capability.
