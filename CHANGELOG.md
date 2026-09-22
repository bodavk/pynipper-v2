# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Junos SRX now audits an explicit global `permit-all` default security policy as unmatched transit traffic and includes that fallback in normalized policy coverage (RV-011). IOS/IOS-XE and EOS now classify additional effective RADIUS, line-password, and literal TerminAttr secret storage with redacted evidence (RV-006); IOS also reports exact known-default plaintext enable/line values and effective default SNMP communities separately from generic storage/protocol findings (RV-007). ScreenOS VPN anti-replay (RV-008) remains evidence-gated pending a release-specific vendor command reference.
- EOS NTP now reports explicit server associations lacking both a key binding and NTS profile even when the export omits the software release (RV-005). Incomplete key and SSL-profile options remain unknown; configured key references with unknown global authentication remain ungraded. Added VRF, removal, malformed-input, redaction, and public CLI coverage.
- Real-world validation follow-up: IOS/IOS-XE now overlays effective line ranges and reports explicit active console/AUX/TTY/VTY idle timeouts above ten minutes while preserving disabled, reset, malformed, and unknown states (RV-004); ASA WebVPN requires a resolved interface attachment before evaluating explicit inbound SSL protocol and cipher policy, reporting obsolete versions and weak suites separately (RV-001); unrendered PAN-OS/FortiOS deployment templates carry incomplete-input coverage and suppress absence-only findings while retaining explicit risks (RV-009); PAN-OS management complexity and effective system syslog forwarding resolve their actual XML hierarchy and profile bindings (RV-003); ASA weak IPsec transform findings require an interface-attached static/dynamic crypto-map binding, with unresolved active references reported separately (RV-002). Added focused synthetic and external-sample CLI validation.
- Fixed FortiOS `end` inside edited tables, including nested and repeated VDOM sections (RV-012). FortiOS syntax failures now produce JSON/HTML coverage marked `parse_error`, omit input values from diagnostics, and exit with status 2. Local disk/memory logging is represented separately from remote forwarding; the existing remote-logging finding now describes that scope accurately (RV-010). Added sanitized parser, public CLI, redaction, and logging-state regression cases. Unresolved-template completeness handling remains separate work under RV-009.
- Expanded the bounded standards follow-up: ASA now resolves attached MPF class connection limits and flags explicit zero/unlimited or invalid values without inventing a safe finite rate; Junos resolves administrative RADIUS/RadSec authentication and accounting server transport, trusted-CA/client-certificate bindings and explicit Message-Authenticator disablement; FortiOS resolves active HTTPS `admin-server-cert` to exported public local/CA certificate material for static validity, SAN identity, algorithm and approved-anchor assessment. Unattached/unused objects, unknown inherited paths, absent certificate inventory and inactive HTTPS remain ungraded. Added adversarial tests for the public pipelines, redaction and unknown-state boundaries.
- Completed GAP-022’s additive report layer across all public pipelines. HTML and JSON now include a versioned normalized coverage ledger, parser/input provenance, scope diagnostics, a concise severity-prioritized remediation summary, and optional allowlisted configuration inventory controlled by `report_inventory`. Inventory is off by default and can include only known interfaces, management services, policies, and logging destinations; evidence, users, credentials, certificate material, and raw configuration are excluded. Unknown/unsupported/parse-error/excluded state and empty findings are explicitly not presented as passed controls. Reports now write UTF-8 and escape advisory summaries instead of trusting embedded markup.
- Added a bounded IOS/IOS-XE normalized report adapter. It exposes explicit VTY/HTTP(S) management endpoints and ACL references, secret-free local-user metadata, ordered interface state/address mutations, effectively attached IPv4/IPv6 interface ACL rules and control-plane classes, effective syslog destinations, and configured SSH version/algorithm/key-size metadata. Unattached ACLs, removed destinations, device-model metadata and omitted service defaults remain absent or unknown rather than being presented as effective controls; opt-in inventory serialization remains evidence- and credential-free.
- Deepened existing FortiOS and Junos normalized reporting without changing the report schema: FortiOS inventory now includes both IPv4 and IPv6 transit-policy sections and preserves explicit traffic-logging state, while Junos inventory includes SRX zone-pair policies alongside stateless firewall-filter terms with native order, activation, zone scope, application and logging evidence.
- Expanded bounded GAP-020 policy-effectiveness sharing across Check Point FW1, PAN-OS, Cisco ASA, FortiOS, Junos SRX, ScreenOS and SonicOS. A typed common layer proves IPv4/IPv6 and protocol/port containment without converting unresolved state to `Any`; every adapter retains native order, scope and predicate gates. ASA resolves static host/subnet/range objects, nested network/service/protocol groups and selected unambiguous named ports; FortiOS adds VDOM/global static address and service groups; Junos adds zone/global address books and custom/predefined applications; ScreenOS adds zone/global address plus nested service groups; and SonicOS resolves E-CLI static IPv4/IPv6 address objects/groups and bounded service objects/groups while preserving zone, family, schedule and extra-predicate gates. These adapters emit independent disabled/broad-service hygiene where applicable and stable proven redundant/shadowed findings. Dynamic/FQDN, inherited, scheduled, negated, source-port-constrained or otherwise unsupported predicates, object cycles and incomplete references block proof. Same-action redundancy also requires behavior equivalence so logging, NAT, inspection and authentication differences are retained. Adversarial cases cover containment versus overlap, IPv6, bindings/scopes, cycles, unknowns and bounded performance; runtime-unused claims remain excluded.
- Added the separately qualified IOS/IOS-XE interface-ACL adapter to GAP-020. It follows only effective IPv4 `ip access-group` and IPv6 `traffic-filter` attachments, honors explicit sequence order, and proves literal host/prefix/contiguous-wildcard plus bounded protocol/port containment. Standard ACL semantics and selected unambiguous port names are supported; object references, noncontiguous wildcards, source ports, time ranges, fragments, TCP flags and other extension predicates block proof. Same-action redundancy requires equivalent logging behavior, and different interfaces/directions/families are never cross-compared.
- Completed bounded GAP-018 shared offline credential-property evaluation for IOS/IOS-XE, ASA, Junos, ScreenOS, and EOS. Vendor parsers still classify native storage and discard values, while one versioned evaluator now produces independent storage, exact-default, optional SHA-256 blocklist, and policy-driven plaintext-length states. The assessment policy accepts a 1–1024 plaintext minimum and exact blocklist digests; comparisons occur inside the parser and reports expose only the blocklist count. Unicode plaintext length, malformed/unknown encodings, hash-only exclusion, effective account overrides, policy provenance, and secret-free evidence have adversarial coverage. Reversible decoding, cross-account reuse, and cracking-tool export remain outside this layer.
- Completed the bounded GAP-027 configuration-management delivery. IOS/IOS-XE now separates archive destination/trigger state from configuration-command logging, key suppression and syslog notification; Junos resolves ordered archive sites, transfer scheduling, routing-instance and accounting/syslog change-audit evidence; FortiOS 7.x resolves recurring backup auto-scripts and supported destinations. A validated assessment-policy field distinguishes unknown or externally managed backups from an explicit on-device requirement. FTP/TFTP and other qualified clear-text transports, incomplete device-side automation, and missing IOS/Junos change audit are reported with credential-sanitized evidence, while transfer success, retention, integrity and recovery remain outside static claims.
- Completed the bounded GAP-026 control-plane/DoS delivery for IOS, IOS-XE, Junos, Arista EOS, and FortiOS. IOS/XE now follows active control-plane input attachments through policy maps, classes, ACL selectors and policing/drop actions; Junos resolves active `lo0` family filters, ordered terms and complete discard policers; EOS evaluates attached control-plane ACLs and exported custom classes while preserving the always-attached `copp-system-policy` and omitted built-in classes as platform-managed; FortiOS models each enabled IPv4/IPv6 DoS anomaly independently, including pass/block action, logging and explicit/default/invalid threshold state. Undefined, empty, wrong-family, removed, inactive, unreferenced and no-op objects receive adversarial coverage. Configured numeric rates are retained but their workload adequacy remains a human decision.
- Completed GAP-017 with bounded Junos, PAN-OS, ArubaOS-S, SonicOS 7, and Arista EOS administrative-policy slices. Junos adds typed login-class/user timeout inheritance, pre-login notice state, RADIUS/TACACS+ accounting events/destinations, and explicit J-Web limits. PAN-OS adds administrator role/authentication-profile resolution with MFA evidence, explicit banner/acknowledgement, idle/lockout/session controls, and attachment-driven PAN-OS 10+ management SSH profiles. ArubaOS-S adds ordered manager/operator credential state, per-channel login/enable methods, independent remote CLI/serial/WebAgent idle timeouts, MOTD state, and independent WebAgent plaintext/TLS service resolution. SonicOS adds built-in and local administrator/MFA state, recursive role membership, user-authentication method and local-fallback state, password constraints, login lockout/session controls, CLI connection banners, and active HTTPS TLS/certificate selection. EOS adds typed role/default-role resolution, ordered authentication/EXEC/all-command authorization and accounting, lockout, console/SSH/Telnet timers, distinct login/MOTD banners, and active eAPI SSL-profile/certificate/TLS-version resolution. All preserve unsupported releases, hidden credentials, malformed values, disputed defaults and external/runtime state as unknown instead of inventing findings; SonicOS 7.3 omissions specifically remain unknown because upgraded and newly installed appliances can have different defaults.
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

