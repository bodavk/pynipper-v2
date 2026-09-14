# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Added release-gated ScreenOS 6.3 effective default-policy and session-control analysis. The parser now distinguishes console/Telnet, WebUI, remote-administrator and policy/user authentication-server timeouts, resolves only active AAA bindings (including policy-context syntax), honors set/unset/disable ordering, reports unresolved active server references, and preserves unknown state for unqualified releases; NTP authentication and zone-screen adequacy remain explicitly deferred.
- Added distinct FortiOS IPv4/IPv6 local-in and Junos SRX zone-pair policy models, plus attachment-driven FortiOS/Junos IKE/IPsec reference resolution. New checks conservatively report unrestricted local management, fully resolved wildcard SRX permits, explicit legacy VPN transforms, and broken active reference chains while excluding inactive/unreferenced objects, cross-scope name leakage, unexpanded inheritance, built-in proposal assumptions, secrets, and live negotiation claims.
- Added scoped effective inspection-profile analysis for active PAN-OS and FortiOS rules, including group expansion, local/shared and VDOM/global precedence, cross-scope isolation, empty and explicitly non-blocking content, unresolved references, controller uncertainty, disabled/unbound suppression, and public-pipeline coverage.
- Added PAN-OS and ASA management-certificate assessment: scoped attachment/object resolution, local DER/PEM parsing, explicit frozen-time validity, SAN identity, public key/signature policy, and validation to approved exported SHA-256 trust anchors without retaining certificate or private-key payloads.
- Added FortiOS 7.4+ typed administrative RADIUS profile/binding analysis for RadSec CA and server-identity validation, RadSec TLS minimum versions, explicit message-authenticator disablement, source/interface/VRF evidence, operator-declared protected paths, and secret-free findings; unbound profiles, older releases, and unknown legacy transport paths remain ungraded.
- Added role-aware IOS/XE and AOS-S switch-edge records and checks for unintended access-edge trunks/trust, VLAN DHCP/ARP protection, IP source validation/Dynamic IP Lockdown, and port security; corrected IOS-XE MACsec applicability so ordinary access ports are not blanket-scoped.
- Added a validated immutable assessment-policy context across every public analyzer and processor, including explicit interface roles, post-analysis category exclusions, CLI JSON loading, and policy/exclusion metadata in HTML and JSON reports.
- Added role-aware IOS/XE CDP/LLDP and Junos LLDP trust-boundary checks; findings require an explicitly external active interface and honor global/local disablement, direction, shutdown state, and unknown/internal/voice-fabric roles.
- Added typed IOS/XE and Junos BGP/OSPF routing-trust analysis with peer/group authentication inheritance, key-chain rollover evidence, AF/VRF or routing-instance isolation, shutdown/passive handling, external-peer import/export and prefix-limit checks, conservative unknown state, and secret-redacted findings.
- Added typed, effective SNMPv3 user/group/view/manager relationships across IOS/XE, ASA, AOS-S, EOS, PAN-OS and SonicOS; checks now evaluate every active user independently, resolve access scope, preserve hidden-key uncertainty, qualify ASA/PAN-OS algorithms by release, honor inactive agents/removals, and redact all SNMP credentials.
- Added typed, per-association authenticated time analysis across PAN-OS, AOS-S, EOS, IOS/XE, ASA, Junos and SonicOS; separated FortiOS authentication and algorithm causes, added release-qualified PAN-OS/ASA/EOS policy, resolved trusted keys/NTS profiles, and redacted all time-key material.
- Added typed IOS/IOS-XE management-line, AAA authorization, AUX and explicit SSH-suite/key metadata analysis, plus protocol-specific ASA AAA, console-timeout and release-aware SSH checks; preserved unknown release state and kept current ASA logic gated away from PIX.
- Added typed, per-destination Junos syslog selector/scope metadata and an independent event-coverage finding; verified FortiOS logging filters remain isolated by destination, activation state, and VDOM.
- Added conservative PAN-OS findings for explicitly disabled password-history and username-inclusion protections while preserving malformed, absent, and Panorama-inherited values as unknown.
- Added a release-qualified applicability register for every incomplete/unknown standards-matrix cell, resolving FortiOS and EOS source-version ambiguity and documenting blocked export/source boundaries.
- Added parser-owned, secret-free credential format/default metadata for IOS/XE, ASA, Junos, ScreenOS, and EOS; added EOS local-credential findings and corrected ASA legacy MD5 `encrypted` storage so it no longer passes as secure.
- Extended Check Point FW1 same-layer shadow and redundancy analysis from object-name containment to bounded, fully resolved subnet, address-range, protocol, and port containment while preserving unknown-state and scope safeguards.
- Replaced inherited project documentation with current pynipper-v2 architecture, extension, support, validation, contribution, and security guidance.
- Made Cisco IOS plugin registration explicit and deterministic, matching the other public platform processors.
- Corrected `--offline` so it actually disables external advisory lookup.
- Modernized the generated HTML report language and removed its runtime jQuery dependency.
- Replaced inherited Python 3.6-era automation with a current cross-platform full-regression workflow and supported CodeQL workflow; removed unconfigured third-party service and obsolete lint workflows.

### Removed

- Removed superseded ASA wrapper pipelines, duplicate legacy ASA plugins, unused compatibility parser/issue/registry modules, obsolete generated test-output fixtures, and an unused runtime dependency.

The entries below are retained as historical release notes from the original pynipper-ng project.

## [0.2.0 ALPHA] - 2022-01-27

### Changed
- Changes in code architecture: new package structure and new plugins creation
- Improve CI workflow: security controls, QA analysis, build checks

### Fixed
- HTTP plugin analysis: fix in HTTP rules detection


## [0.1.1 ALPHA] - 2021-05-01

### Added
- PIP install package

### Fixed
- Setup script to install the tool
- Multiple installation errors due to import modules
- Pynipper-ng modules bugs

## [0.1.0 ALPHA] - 2021-04-11

### Added
- CLI basic scan of Cisco IOS missconfigurations
- First scan modules: SSH & HTTP administration vulnerabilities
- Integration with Cisco API to get IOS vulnerabilities of device version
- JSON & HTML report

### Changed

### Deprecated

### Removed

### Fixed

### Security

