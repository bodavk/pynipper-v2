# Standards blind-spot findings

Audit completed against the workspace source on 2026-09-11 and maintained through the 2026-09-14 remediation cycle. Live source verification was performed on 2026-09-10–14. This is a static capability audit, not a certification or exploit test.

## Ground truth and conventions

The [registry](../../src/devices/registry.py) exposes **14 canonical IDs and 11 distinct parser/analyzer pairs**. IOS_SWITCH, IOS_ROUTER and IOS_CATALYST share IOS. PIX and ASA share the ASA pipeline: this proves dispatch, not independently verified PIX dialect support. The remaining IDs are FORTIOS, JUNOS, SCREENOS, CHECKPOINT_FW1, PAN_OS, HP_PROCURVE, SONICOS, IOS_XE and ARISTA_EOS.

The [architecture](../ARCHITECTURE.md), [extension guide](../EXTENDING.md), [contribution guide](../../CONTRIBUTING.md), [parser contract](NORMALIZED_PARSER_CONTRACT.md), [device guide](../../src/devices/README.md) and [analyzer guide](../../src/analyze/README.md) agree on parser-owned effective state, typed records, explicit knowledge states, explicit registration, stable namespaced Finding IDs, sanitized evidence and authoritative references. Source confirms those interfaces; not every implementation has the same normalized depth. In particular IOS and ASA inherit the base unknown normalized configuration rather than a complete common adapter. Some processors explicitly instantiate one plugin rather than using the documented tuple convention. Neither point warrants an unrelated refactor in this audit.

[ROADMAP](../ROADMAP.md), [SUPPORTED_DEVICES](../SUPPORTED_DEVICES.md) and [existing parity matrix](01_gap_matrix.md) are tracking claims, not evidence of complete standards coverage. The source supports expanded bounded baselines; it does not support interpreting “closed” as all hardening categories complete. The named DETECTION_AUDIT_FINDINGS.md and DETECTION_AUDIT_TASKS.md were absent on initial inspection and final recheck; no reusable task-file template was located. Suspected defects in already implemented conditions are kept out of this audit; future work must cross-link a detection audit if one appears.

## Standards register and applicability

A current catalogue entry is evidence of a published benchmark version, not access to its control text. Live CIS catalogues list: [Cisco](https://www.cisecurity.org/benchmark/cisco) IOS16/17 v2.0.0, IOS-XE16 v2.2.0, IOS-XE17 v2.2.1 and ASA9.x v1.1.0; [Fortinet](https://www.cisecurity.org/benchmark/fortinet) FortiGate7.4.x v1.0.1 and7.0.x v1.4.0; [Palo Alto](https://www.cisecurity.org/benchmark/palo_alto_networks) Firewall 11 v1.2.0 and Firewall10 v1.3.0; [Juniper](https://www.cisecurity.org/benchmark/juniper) Juniper OS v2.1.0; the [CIS catalogue](https://www.cisecurity.org/cis-benchmarks) also lists Arista EOS v1.0.0 and Check Point Firewall v1.1.0. Full benchmark PDFs/control numbering were not verified, so no CIS control IDs or compliance claims are invented. Vendor guidance provides the control intent below. No DISA STIG currency or V-ID is asserted; the request allows CIS, STIG **and/or** official vendor guides.

Latest published benchmark, latest available vendor guide, software support lifecycle, and applicability to a supplied export are separate facts. A universal newest standard could not be confirmed for every legacy platform. NEEDS_RESEARCH means the source/revision/control remains unresolved; NEEDS_HUMAN_REVIEW means a retrieved source's deployment/release applicability needs a decision. These flags are prerequisites in the task file.

| ID | Official document | Version/revision and applicability | Sections used | URL |
|---|---|---|---|---|
| <a id="S-IOS"></a>S-IOS | Cisco Guide to Harden Cisco IOS Devices; Secure SNMP; IOS XE 17 SNMP Configuration Guide | Hardening document 13608 updated 2024-09-12; current SNMP guidance verified 2026-09-13. SHA-2 begins at IOS XE 17.10.1a only on the documented supported platforms, so generic IOS/XE SHA-1 is not universally graded as obsolete | Management Plane: AAA, SNMP, NTP, configuration change logging; SNMPv3 authPriv users, groups, views and source ACLs; Control/Data Plane protections | [Hardening](https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html); [Secure SNMP](https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/20370-snmpsecurity-20370.html); [IOS XE SNMP](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/snmp/configuration/xe-17-x/snmp-xe-17-book/nm-snmp-cfg-snmp-support.html) |
| <a id="S-XE"></a>S-XE | Cisco IOS XE Software Hardening Guide; Secure Shell Algorithm Configuration | Live hardening guide plus SSH algorithm guide updated 2026-04-24, verified 2026-09-13; algorithm defaults and removals vary by XE release | Management Plane, including AAA authorization; explicit SSH cipher, MAC, KEX and host-key commands/default notes | [Hardening](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening); [SSH algorithms](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/security-vpn/security-vpn/m_sec-secure-shell-algorithm-ccc.html) |
| <a id="S-ASA"></a>S-ASA | Cisco Firewall Best Practices; ASA 9.24 Management Guide; ASA AAA, SSH and NTP command references; ASA 9.17 SNMP Guide | Live best-practices plus current management/command references verified 2026-09-13; current ASA scope is not authority for PIX. SNMP SHA-256 begins at 9.14(1); SHA-224/SHA-384 and removal of MD5/DES begin at 9.16(1) | Management access, console timeout, protocol AAA, SSH suites, NTP key trust, and SNMPv3 user/group/host scope with release-qualified algorithms | [Best practices](https://sec.cloudapps.cisco.com/security/center/resources/firewall_best_practices); [Management](https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config/admin-management.html); [AAA](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/aa-ac-commands.html); [SSH](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/S/asa-command-ref-S/so-st-commands.html); [NTP](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/n-commands.html); [SNMP](https://www.cisco.com/c/en/us/td/docs/security/asa/asa917/configuration/general/asa-917-general-config/monitor-snmp.html) |
| <a id="S-PIX"></a>S-PIX | Cisco PIX Firewall Configuration Guide: Configuring the PIX Firewall | Version 5.0 archived guide; NEEDS_RESEARCH for latest archived applicable guide and NEEDS_HUMAN_REVIEW for each PIX dialect | Steps 12, 15–17: management, logging, access lists and AAA | [Official source](https://www.cisco.com/en/US/docs/security/pix/pix50/configuration/guide/config.html) |
| <a id="S-FGT"></a>S-FGT | FortiOS Best Practices: Hardening; FortiOS CLI references for local-in and IPsec phase configuration; config log syslogd filter | 8.0.0 hardening, explicit 7.2 local-in/IKE/IPsec syntax, and 7.6.0 syslog fields verified through 2026-09-14. Register the releases separately; do not backport 8.0 defaults to 7.x fixtures | Administrator/system settings, IPv4/IPv6 local-in policy, explicit phase1/phase2 transforms and bindings, DoS, backups, and syslog filter fields | [Hardening](https://docs.fortinet.com/document/fortigate/8.0.0/best-practices/555436/hardening); [local-in](https://docs.fortinet.com/document/fortigate/7.2.1/cli-reference/328620/config-firewall-local-in-policy); [local-in IPv6](https://docs.fortinet.com/document/fortigate/7.2.0/cli-reference/329620/config-firewall-local-in-policy6); [phase1](https://docs.fortinet.com/document/fortigate/7.2.0/cli-reference/365620/config-vpn-ipsec-phase1); [phase2-interface](https://docs.fortinet.com/document/fortigate/7.2.2/cli-reference/372620/config-vpn-ipsec-phase2-interface); [syslog filter](https://docs.fortinet.com/document/fortigate/7.6.0/cli-reference/273422104/config-log-syslogd-filter) |
| <a id="S-RAD"></a>S-RAD | FortiOS Administration Guide: Configuring a RADIUS server; FortiOS 7.4 New Features: Add RADSec client support | 7.6.5 current behavior plus verified 7.4.0 introduction boundary; live documentation, no publication date displayed | RADIUS/RadSec transport, CA/server identity, TLS minimum and message-authenticator configuration | [Current guide](https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/759080/configuring-a-radius-server); [7.4 introduction](https://docs.fortinet.com/document/fortigate/7.4.0/new-features/729374/add-radsec-client-support) |
| <a id="S-JUN"></a>S-JUN | Hardening Junos Devices Checklist, companion to This Week: Hardening Junos Devices, Second Edition; Junos NTP Authentication Keys | Checklist copyright 2015, two pages; second edition remains listed in vendor book catalogue. Current NTP key/type/trust guidance verified 2026-09-13 and preserves documented MD5-only platform exceptions; do not adopt the checklist's obsolete SHA1 storage advice | Chapter 4 checklist: management, access, authentication, routing and firewall filters; Chapter 2 physical ports; per-association NTP key authentication and trusted-key resolution | [Hardening checklist](https://www.juniper.net/assets/us/en/local/pdf/books/tw-hardening-junos-devices-checklist.pdf); [NTP authentication](https://www.juniper.net/documentation/us/en/software/junos/time-mgmt/topics/concept/ntp-authentication-keys.html) |
| <a id="S-SRX"></a>S-SRX | Junos OS Security Policy Configuration; IPsec VPN Configuration Overview; IKE/IPsec proposal reference; RFC 8247 | Current vendor pages and RFC verified 2026-09-14. Applicable to explicit supported SRX configuration only; built-in proposal-set contents and negotiated runtime state are not inferred | Zone-pair security policy, address/application matching and defaults, VPN attachment/reference chains, and explicit legacy algorithm classification | [Security policies](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html); [VPN overview](https://www.juniper.net/documentation/us/en/software/junos/vpn-ipsec/topics/topic-map/security-ipsec-vpn-configuration-overview.html); [proposal reference](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-proposal.html); [RFC 8247](https://www.rfc-editor.org/rfc/rfc8247.html) |
| <a id="S-SCR"></a>S-SCR | ScreenOS 6.3.0 Documentation catalogue; *Security Device CLI Reference Guide: IPv4 Command Descriptions*; *Administration*; *Fundamentals*; *User Authentication*; ScreenOS 6.3.0r27 Release Notes | Catalogue metadata and the official portable archive were recovered 2026-09-14. Individual core-manual URLs currently redirect to the archive page, so exact default-policy and timeout semantics were checked against an archived CLI-reference mirror and pinned legacy implementation; the official migration guide confirms default-deny/default-permit-all behavior and the official r27 release notes corroborate the corrected `set admin auth web timeout 0` syntax. Applicability is limited to identified 6.3 exports | Explicit unmatched-policy default plus console/Telnet, WebUI and bound authentication-server timeout semantics. NTP authentication and zone-screen adequacy remain research/policy-gated | [6.3 catalogue](https://www.juniper.net/documentation/product/us/en/screenos/6.3.0/); [IPv4 CLI reference URL](https://www.juniper.net/documentation/software/screenos/screenos6.3.0/630_ipv4_cli.pdf); [migration guide](https://www.juniper.net/assets/jp/jp/local/pdf/service-descriptions/9060154-en.pdf); [r27 release notes](https://www.juniper.net/documentation/software/screenos/screenos6.3.0/rn-630r27-rev01.pdf); [archived CLI-reference mirror](https://manualzz.com/doc/21898000/juniper-networks-security-device-cli-reference-guide) |
| <a id="S-CP"></a>S-CP | Check Point Gateway and Management Hardening Administration Guide | HTML introduction dated 2026-06-01; applicable R81.20, R82, R82.10. PDF variant dated 2026-05-04; use HTML revision | Gaia OS Hardening; Administrator Identity and Access Control; Decreasing Gateway Exposure with Policy | [Official source](https://sc1.checkpoint.com/documents/Check_Point_Gateway_and_Management_Hardening/Content/CP-Hardening/Introduction.htm?TocPath=_____3) |
| <a id="S-PAN"></a>S-PAN | PAN-OS Administrative Access Best Practices: Deploy Administrative Access Best Practices | Version 10.1 guide still offered by current PAN-OS catalogue; not proof 10.1 software is supported | Management interface isolation, administrators, external services | [Official source](https://docs.paloaltonetworks.com/best-practices/10-1/administrative-access-best-practices/administrative-access-best-practices/deploy-administrative-access-best-practices) |
| <a id="S-PAN-M"></a>S-PAN-M | PAN-OS Help: Device > Setup > Management | 12.1 body verified 2026-09-11; selector lists 12.2 but its direct body was not verified. Explicit fields are qualified; older/default inference still requires review | Minimum Password Complexity; username inclusion and password reuse; Authentication and General Settings; banners; TLS service profile | [Official source](https://origin-docs.paloaltonetworks.com/ngfw/help/12-1/device/device-setup-management) |
| <a id="S-PAN-N"></a>S-PAN-N | Perform the Initial Setup and Configuration for NGFWs; PAN-OS 12.1 Management Features | Current live guides verified 2026-09-13; authentication defaults to none, Autokey is legacy, and PAN-OS 12.1.2 introduced SHA-256/SHA-512 symmetric authentication | Configure date and time (NTP), per-server authentication and release algorithm boundary | [Initial setup](https://docs.paloaltonetworks.com/ngfw/getting-started/initial-setup-configuration-ngfws); [12.1 feature](https://docs.paloaltonetworks.com/ngfw/release-notes/12-1/features-introduced-in-pan-os/management-features) |
| <a id="S-PAN-P"></a>S-PAN-P | Security Policy Rule Best Practices | Current unversioned vendor best practices, release applicability must be resolved per feature | Least privilege, Security profiles, logging, rule optimization | [Official source](https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/security-policy-best-practices/deploy-security-policy-best-practices/security-policy-rule-best-practices) |
| <a id="S-HP"></a>S-HP | Aruba 2930M/F Access Security Guide and SNMPv3 User Commands for AOS-S Switch 16.11 | 16.11 HTML; SNMPv3 command page verified 2026-09-13. Parser defaults remain limited to 16.10 and product applicability excludes AOS-CX | Access security, authorized managers, SNMPv3 per-user MD5/SHA authentication and DES/AES privacy | [Access security](https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/ASG/WC/content/home.htm); [SNMPv3 users](https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/WC/content/common%20files/snm-use-com.htm) |
| <a id="S-HP-N"></a>S-HP-N | AOS-S 16.11 Management and Configuration Guide: SNTP server and authentication | 16.11 KB/WC/YA-YB family pages verified 2026-09-13; supported 16.10/16.11 running-config syntax is qualified, unknown release/family remains unknown | Global SNTP authentication, configured/trusted MD5 keys and per-server key association | [Server binding](https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/KB/content/kb/snt-ser.htm); [Key configuration](https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/WC/content/wc/cnf-key-ide-aut-mod-etc.htm); [Requirements](https://arubanetworking.hpe.com/techdocs/AOS-S/16.10/MCG/KB/content/kb/req-ena-snt-cli-aut.htm) |
| <a id="S-HP-L2"></a>S-HP-L2 | AOS-S 16.11 Access Security Guide: Dynamic ARP protection | 16.11, Aruba 2540/YC; extend only to verified product families | Dynamic ARP protection and IP-to-MAC validation | [Official source](https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/ASG/YC/content/common%20files/dyn-arp-pro.htm) |
| <a id="S-SON"></a>S-SON | SonicOS 7.3 Device Settings Administration Guide | Introduction labels May 2026, SonicOS 7.3. SNMPv3 group/access page verified 2026-09-13; E-CLI export coverage remains narrower than all GUI relationships | Administration, Time, Certificates, SNMPv3 users/groups/access | [Guide](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7.3-device_settings/Content/introduction.htm); [SNMPv3 access](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7.3-device_settings/Content/SNMP/snmpv3-groups-access.htm) |
| <a id="S-SON-P"></a>S-SON-P | SonicOS 7.3 Device Settings: Configuring Password Compliance | 7.3, same guide family; policies need organization/release selection | Login Security, password compliance and CLI login attempts | [Official source](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7.3-device_settings/Content/System_Administration/Multiple_Administrator/password-compliance-configuration.htm) |
| <a id="S-EOS"></a>S-EOS | EOS User Manual: Security and SNMP | Security pages label 4.36.2F; SNMP 4.36 manual verified 2026-09-13 | User, Control Plane and Data Plane Security; SNMPv3 users/groups/views and per-VRF IPv4/IPv6 agent ACLs | [Security index](https://www.arista.com/en/um-eos/eos-security); [Control Plane Security](https://www.arista.com/en/um-eos/eos-control-plane-security); [User Security](https://www.arista.com/en/um-eos/eos-user-security); [SNMP](https://www.arista.com/en/um-eos/eos-snmp) |
| <a id="S-EOS-N"></a>S-EOS-N | EOS User Manual: System Clock and Time Protocols; NTP over TLS TOI | 4.36.2F manual and feature history verified 2026-09-13; NTS introduced in EOS 4.35.0F, while older releases retain symmetric-key capability | Per-server/VRF NTP keys, global authentication, trusted keys and NTS SSL profiles | [Manual](https://www.arista.com/en/um-eos/eos-system-clock-and-time-protocols); [NTS introduction](https://www.arista.com/en/support/toi/tag/ntp) |

## Platform-by-control-category matrix

P = partial implementation of category intent; I = implemented for a narrowly defined control (see appendix), not benchmark compliance; A = absent check; U = uncertain applicability or unavailable export evidence; N = not applicable to the analyzed object. Broad categories below intentionally receive P even when individual checks are fully implemented. No N is assigned merely because a parser lacks a field. For policy-only FW1, OS categories are U, not a claim that the gateway has no such controls.

| Pipeline / dialect | Admin | AAA | Credentials | SNMP | Logging | Time | Banners | Services | Routing | Filtering | Crypto | Certificates | Discovery | Control plane |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| IOS (three registered IDs) | P | P | P | P | P | P | P | P | A | P | P | A | A | P |
| IOS-XE | P | P | P | P | P | P | P | P | A | P | P | A | A | P |
| ASA | P | P | P | P | P | P | A | P | A | P | P | P | U | P |
| PIX (ASA pipeline; independent dialect unproven) | U | U | U | U | U | U | U | U | U | U | U | U | U | U |
| FortiOS | P | P | P | P | P | P | A | P | A | P | P | P | A | P |
| Junos | P | P | P | P | P | P | A | P | A | P | P | A | A | P |
| ScreenOS | P | P | P | P | P | P | P | P | A | P | P | A | U | A |
| Check Point FW1 policy export | U | U | U | U | P | U | U | U | U | P | U | U | U | U |
| PAN-OS local XML | P | P | P | P | P | P | A | P | A | P | P | P | A | A |
| HP_PROCURVE / AOS-S | P | P | P | P | P | P | A | P | A | A | P | A | A | A |
| SonicOS7 custom E-CLI | P | A | A | P | P | P | A | P | A | P | P | A | U | A |
| EOS | P | P | P | P | P | P | A | P | A | P | P | A | A | A |

All positive cells are supported by the corresponding parser/plugin rows in the appendix. EOS credentials P denotes empty-password policy only; it is not value-strength coverage. IOS/EOS filtering P includes management ACL attachment checks; HP authorized-manager restrictions are counted under Admin, not an ACL engine. FW1 Logging P means rule tracking only. Junos Filtering P covers separate attached stateless-filter and bounded SRX zone-pair checks, not complete installed-policy analysis. SonicOS Crypto P means VPN proposals, not management TLS. Control-plane P on ASA includes threat detection/uRPF, not evaluated CoPP. Remaining A/U cells map to STD-027/GAP-001 when a more specific finding has not established an applicable requirement.

## Findings

The stable STD anchors below are the source of task links. Missing detection, missing semantic parser evidence, unsupported export and operational-data needs are stated separately. A check's existence does not imply that all unknown or malformed input behavior is correct; that is the detection audit's remit.

<a id="STD-001"></a>
### CROSS-CUTTING — AAA server transport and identity protection

**Finding ID:** STD-001

**Standard reference:** [S-RAD](#S-RAD); [S-PAN](#S-PAN); [S-JUN](#S-JUN). See the register for document/version, access date and applicability.

**Current coverage:** FortiOS 7.4+ resolves administrative RADIUS profile bindings and detects concrete RadSec CA/server-identity and TLS-minimum failures plus explicit UDP/TCP message-authenticator disablement. Declared protected paths and unknown paths remain distinct. IOS/ASA/Junos/HP/EOS/PAN-OS central-auth checks still establish bindings or existence, not protected AAA transport.

**What's missing:** Equivalent current-source parser evidence for IOS/XE, ASA, Junos, AOS-S, EOS and PAN-OS; FortiOS non-administrative consumers, certificate material/chain validation, and live tunnel routing remain outside this bounded delivery. UDP alone is not sufficient evidence of an unsafe deployment.

**Why it matters:** Remote authentication can be configured while its network path or server identity remains unprotected. Do not claim every legacy AAA protocol has a supported TLS equivalent.

<a id="STD-002"></a>
### CROSS-CUTTING — Routing neighbor authentication and route acceptance policy

**Finding ID:** STD-002

**Standard reference:** [S-IOS](#S-IOS); [S-XE](#S-XE); [S-JUN](#S-JUN); [S-EOS](#S-EOS). See the register for document/version, access date and applicability.

**Current coverage:** IOS/XE and Junos now evaluate effective BGP neighbor authentication, explicitly external import/export policy and prefix-limit presence, plus active non-passive OSPFv2 interface authentication. Peer-group/group inheritance, shutdown/disable state, VRF/routing-instance and address-family scope are parser-owned. Unknown role, algorithm and unexpanded inheritance remain ungraded.

**What's missing:** EIGRP/RIP and other routing-capable platforms still require protocol- and release-specific parser evidence and policy. Dynamic-neighbor ranges, IOS template inheritance beyond classic peer groups, OSPFv3/IPsec, and live accepted-route state are not inferred. Check Point policy-only exports cannot answer Gaia routing controls.

**Why it matters:** Misconfigured routing trust can admit false routes or exhaust resources. Corroborated by reachable legacy IOS routing checks (LEG-003), without importing obsolete recommendations.

<a id="STD-003"></a>
### CROSS-CUTTING — Discovery protocol exposure at trust boundaries

**Finding ID:** STD-003

**Standard reference:** [S-IOS](#S-IOS); [S-JUN](#S-JUN), Chapter 4 LLDP item; [S-HP-L2](#S-HP-L2) is not a discovery authority. See the register for document/version, access date and applicability.

**Current coverage:** IOS/XE evaluates effective CDP and directional LLDP exposure, while Junos evaluates effective LLDP all-interface/specific-interface state. Findings require an active interface explicitly classified `external` by the assessment policy; unknown/internal/voice-fabric roles remain clear or unassessed.

**What's missing:** EOS/AOS-S/FortiOS and other platforms require their own applicable source sections and typed inheritance/direction evidence before expansion. Runtime neighbors and whether an external link operationally requires discovery remain outside static configuration evidence. Do not declare all discovery insecure.

**Why it matters:** Topology and device information can leave intended links. A required internal LLDP deployment must not generate a blanket finding. Corroborated for IOS by LEG-003.

<a id="STD-004"></a>
### CROSS-CUTTING — Management certificate material and identity policy

**Finding ID:** STD-004

**Standard reference:** [S-PAN-M](#S-PAN-M), General Settings; [S-JUN](#S-JUN), J-Web; [S-SON](#S-SON), Certificates. See the register for document/version, access date and applicability.

**Current coverage:** PAN-OS resolves active management TLS/profile references to correctly scoped certificate objects, and ASA resolves effective management SSL assignments to trustpoint objects and identity-vs-CA certificate-chain entries. Both pipelines parse exported public PEM/DER material and can assess SAN identity, explicit-time validity, public-key/signature policy and chains to explicitly approved exported SHA-256 anchors. They distinguish unresolved, missing and malformed material and keep absent assessment inputs unknown. FortiOS detects a factory certificate.

**What's missing:** Equivalent exported-material resolution is not yet implemented for FortiOS, Junos or SonicOS. Remote served-certificate, client trust-store and revocation observation belongs to the opt-in live track in GAP-025. Static configuration cannot prove what a service currently presents, and self-signing alone is not a universal vulnerability.

**Why it matters:** An attached profile can still name missing, weak or unsuitable certificate material. Configuration proves neither the certificate served today nor the client's trust store.

<a id="STD-005"></a>
### CROSS-CUTTING — Credential value strength beyond known-bad literals

**Finding ID:** STD-005

**Standard reference:** [S-IOS](#S-IOS), password sections; [S-JUN](#S-JUN), User Authentication; [S-SON-P](#S-SON-P). See the register for document/version, access date and applicability.

**Current coverage:** Partial, not universal absence. IOS/XE and Junos classify weak storage; ASA detects plaintext plus short literal lists; ScreenOS checks empty/default literals and known hashes. FortiOS/PAN-OS/HP check password policies. None is a shared value-strength engine.

**What's missing:** Missing detection: distinguish storage format, available plaintext length, policy compliance, exact default fingerprints and optional blocklist checks. ASA and ScreenOS blacklists cannot classify arbitrary weak values; EOS has parsed users but no comparable strength checks, SonicOS users are unknown. Never infer plaintext length from a hash; algorithm policy is a separate dimension.

**Why it matters:** Unlisted weak values remain invisible. Legacy configurable structural checks corroborate this gap (LEG-005); historical composition requirements are not automatically a modern password policy.

<a id="STD-006"></a>
### CROSS-CUTTING — Authenticated time coverage and key resolution

**Finding ID:** STD-006

**Standard reference:** [S-JUN](#S-JUN); [S-PAN-N](#S-PAN-N); [S-HP-N](#S-HP-N); [S-EOS-N](#S-EOS-N). See the register for document/version, access date and applicability.

**Current coverage:** Typed per-association authentication now covers PAN-OS, AOS-S, EOS, IOS/XE, ASA, Junos and SonicOS, while FortiOS retains equivalent per-object VDOM-aware evaluation. Each active source is checked independently for effective authentication and resolved key/trust or NTS profile state. PAN-OS 12.1.2, EOS 4.35.0F and ASA 9.13 algorithm boundaries are explicit; Junos and older AOS-S/EOS/ASA platform capabilities are preserved. Weak algorithms are a separate root cause where a verified stronger alternative exists. Key material is sanitized before analysis.

**What's missing:** ScreenOS time-protocol authentication remains blocked on a verified archived NTP section and representative dialect fixtures. Exact Junos Feature Explorer support varies by hardware and release beyond the maintained MD5-only exceptions, so unknown combinations are not promoted to SHA-256-capable. Static exports cannot establish successful synchronization, remote-server identity, packet authentication success, reachability or current certificate validity for NTS.

**Why it matters:** A configured time source is not necessarily authenticated. Key association, algorithm support and authentication success are different claims; the last needs operational evidence.

<a id="STD-007"></a>
### CROSS-CUTTING — SNMP access and algorithm coverage beyond secure-user existence

**Finding ID:** STD-007

**Standard reference:** [S-IOS](#S-IOS), SNMP; [S-JUN](#S-JUN), Management Services; [S-HP](#S-HP), access security. See the register for document/version, access date and applicability.

**Current coverage:** Bounded implementation complete: IOS/XE resolves effective v3 users, groups, views and source ACLs; ASA resolves active user/group/host bindings with release-qualified algorithms; AOS-S and EOS evaluate every active user plus manager/VRF scope; PAN-OS and SonicOS evaluate every user only where SNMP is attached to an active management surface. Existing FortiOS/Junos per-user checks and community findings remain independent.

**What's missing:** Static exports cannot establish successful authentication, packet confidentiality, ACL reachability or live MIB authorization. Hidden/omitted keys remain unknown. IOS XE SHA-2 requires exact platform/release qualification; PAN-OS and the supported SonicOS E-CLI export do not expose a complete portable VACM/group/view model. Junos view/filter depth remains partial rather than a universal least-privilege claim.

**Why it matters:** One secure user does not establish least privilege or protect all enabled SNMP access. Unknown algorithm defaults must remain unknown.

<a id="STD-008"></a>
### CROSS-CUTTING — Control-plane policy contents and service rate limits

**Finding ID:** STD-008

**Standard reference:** [S-IOS](#S-IOS)/[S-XE](#S-XE), CoPP; [S-JUN](#S-JUN), Firewall Filter; [S-EOS](#S-EOS), Control Plane Security; [S-FGT](#S-FGT), DoS. See the register for document/version, access date and applicability.

**Current coverage:** Partial: IOS/XE sees service-policy input; Junos sees lo0 input filter; FortiOS checks WAN DoS attachment/blocking anomaly/logging; ASA basic threat detection and uRPF exist.

**What's missing:** Missing intent: resolve attached class/filter/policer/anomaly definitions, traffic classes and explicit actions/rates; add EOS native control-plane coverage. Separate self-traffic from transit DoS. ScreenOS screens, PAN-OS zone protection and SonicOS flood protection require platform-specific research and evidence. Traffic-appropriate rate adequacy needs human context.

**Why it matters:** Attachment alone can overstate protection. Never treat every platform as lacking CoPP or apply router CoPP syntax to firewalls.

<a id="STD-009"></a>
### CROSS-CUTTING — Protected configuration backup and change auditing

**Finding ID:** STD-009

**Standard reference:** [S-IOS](#S-IOS), configuration change logging; [S-XE](#S-XE), Software Configuration Management; [S-JUN](#S-JUN), secure configuration backups; [S-FGT](#S-FGT). See the register for document/version, access date and applicability.

**Current coverage:** No plugin checks secure automated backup destinations or configuration-change auditing. Generic remote syslog checks exist.

**What's missing:** Add static archive/backup configuration, transport/destination and change-audit settings to typed native records, beginning IOS/XE and Junos. FortiOS scope requires version confirmation. Successful backups, retention, integrity of stored copies and external monitoring require operational evidence.

**Why it matters:** A device can satisfy remote logging checks while configuration changes are unaudited and recovery copies unprotected.

<a id="STD-010"></a>
### IOS / IOS-XE — Administrative service, AAA and session depth

**Finding ID:** STD-010

**Standard reference:** [S-IOS](#S-IOS)/[S-XE](#S-XE), Management Plane. See the register for document/version, access date and applicability.

**Current coverage:** HTTP cleartext/access/auth checks and typed, effective console/AUX/TTY/VTY state now cover per-line input/output transport, explicit unlimited timeouts, IPv4/IPv6 access-class attachments, login methods, and EXEC/privilege-15 command authorization. Named AAA methods and custom server groups are resolved before they count as protection. Explicit weak SSH cipher/MAC/KEX/host-key selections and explicit RSA modulus below 2048 bits are detected. AUX exposure is role-specific and disabled lines do not emit authentication or authorization findings.

**What's missing:** An approved platform/release-specific upper bound is still required before finite-but-excessive session timeouts can be judged. Absent or reset SSH suites and unexported key metadata remain unknown where release defaults are not safely established. Access-class names are preserved per line and address family, but ACL semantic effectiveness and VRF-aware reachability remain future work.

**Why it matters:** Secure protocol presence and a global AAA declaration do not establish least-privilege administrative access. Session/auxiliary depth is corroborated by LEG-003.

<a id="STD-011"></a>
### IOS / IOS-XE — Switch edge and data-plane protections

**Finding ID:** STD-011

**Standard reference:** [S-IOS](#S-IOS)/[S-XE](#S-XE), Data Plane. See the register for document/version, access date and applicability.

**Current coverage:** Source routing, redirects and proxy ARP checks exist. IOS/XE now resolves switchport/access-VLAN state, DHCP snooping, DAI, trust, IP Source Guard and port security for interfaces explicitly classified `access-edge`. Routed, uplink and unknown-role ports do not receive access-edge findings. IOS-XE MACsec evaluates explicit uplink/external scope or configured MKA/MACsec intent rather than every switchport.

**What's missing:** Additional switch families, IPv6 ND/DHCPv6 protection, static-binding semantics and platform-specific feature limitations need their own sources and fixtures. Explicit directed-broadcast exposure also needs a check. Static configuration cannot prove learned binding-table contents or physical endpoint identity.

**Why it matters:** Management hardening leaves Layer 2 spoofing and unintended trunks unassessed. Legacy IOS port/trunk checks corroborate useful depth, not exact old defaults.

<a id="STD-012"></a>
### ASA / PIX — Management sessions and banner depth

**Finding ID:** STD-012

**Standard reference:** [S-ASA](#S-ASA), Management Plane; [S-PIX](#S-PIX) archival applicability unresolved. See the register for document/version, access date and applicability.

**Current coverage:** ASA checks telnet, broad SSH grants, effective HTTPS service state, HTTP sources, TLS minimum, credentials and banners. It now evaluates protocol-specific administrative authentication and supported SSH/Telnet accounting bindings against defined server groups, the effective console timeout, release-qualified SSH protocol defaults, and explicitly selected weak SSH encryption/integrity/key-exchange algorithms.

**What's missing:** The static export cannot establish live AAA availability or successful accounting delivery. Absent algorithm settings and malformed/unexported state remain unknown when a safe release default is unavailable; no arbitrary finite-timeout ceiling is imposed. PIX defaults and legacy syntax remain NEEDS_HUMAN_REVIEW, and current ASA 9.x administrative-depth checks are explicitly gated away from PIX despite the shared parser.

**Why it matters:** Remote sessions can remain weak or long-lived despite passing grant checks. Legacy PIX SSH version/timeout checks corroborate the ASA-family omission (LEG-004).

<a id="STD-013"></a>
### FortiOS / PAN-OS — Effective security profile content

**Finding ID:** STD-013

**Standard reference:** [S-FGT](#S-FGT), security settings; [S-PAN-P](#S-PAN-P), Security profiles. See the register for document/version, access date and applicability.

**Current coverage:** FortiOS internet-bound accept policies require UTM plus a resolvable individual threat profile or profile group; profile groups expand through same-VDOM then global/root scope. PAN-OS enabled allow rules resolve individual profiles and groups through same-vsys then shared scope. Both distinguish unresolved, empty and explicitly non-blocking attached objects while ignoring disabled rules and unbound definitions.

**What's missing:** License/subscription health, signature/content freshness and actual runtime inspection require operational evidence. Panorama and FortiManager inheritance is not merged from an individual export. Additional profile families and version-specific implicit defaults remain conservative. FortiOS local-in is now separate from profile inspection; IPv6 transit-policy/profile coverage still needs its own model.

**Why it matters:** A policy can name an empty, permissive or unresolved protection profile. License validity and real inspection are operational questions.

<a id="STD-014"></a>
### FortiOS — Local-in policy and VPN scope

**Finding ID:** STD-014

**Standard reference:** [S-FGT](#S-FGT), including versioned local-in and phase configuration references; [RFC 8247](https://www.rfc-editor.org/rfc/rfc8247.html) for the bounded explicit legacy-algorithm classification.

**Current coverage:** Typed, VDOM-aware IPv4/IPv6 local-in records are separate from transit policy. Enabled accept rules are conservatively checked for exact wildcard source and sensitive management service under an explicit always schedule. Typed active phase2-to-phase1 bindings resolve same-scope proposals, DH, PFS and replay state; explicit legacy transforms and unresolved chains have separate findings.

**What's missing:** Local-in address/service-group expansion, nontrivial schedule semantics, dynamic/controller-provided selectors, phase1-only and dial-up applicability, built-in/default proposal contents, live negotiation, peer identity and runtime reachability remain unassessed. Static configuration does not prove policy installation or an active security association.

**Why it matters:** Management services and VPN endpoints can remain permissive despite transit-policy and admin TLS checks. The implemented model closes the explicit static cases without presenting runtime VPN health as configuration proof.

<a id="STD-015"></a>
### Junos — Login classes, accounting, banners and J-Web sessions

**Finding ID:** STD-015

**Standard reference:** [S-JUN](#S-JUN), Access/User Authentication Security. See the register for document/version, access date and applicability.

**Current coverage:** Root SSH, remote auth order, retry/lockout, superuser credentials, explicit SSH algorithms and legacy services exist. No login-class authorization/idle timeout, accounting, warning-banner or J-Web HTTPS/session restriction checks.

**What's missing:** Add typed login classes/bindings and J-Web settings. Existing effective statement list can support early banner/accounting checks; class inheritance and service attachments need parser APIs. Revalidate 2015 cryptographic advice before policy constants.

**Why it matters:** A centralized identity can retain excessive privilege or unrestricted sessions. No external AAA authorization success can be inferred from static declarations.

<a id="STD-016"></a>
### Junos — SRX stateful policies and VPN configuration

**Finding ID:** STD-016

**Standard reference:** [S-SRX](#S-SRX), including the current VPN/proposal references and RFC 8247 legacy-algorithm guidance.

**Current coverage:** Stateless firewall-filter analysis and SRX stateful policy analysis are distinct. Typed SRX records preserve zone pairs, order, active state, zone/global address-book expansion, application/application-set resolution, permit action and VPN attachment. Attached or interface-bound VPNs resolve gateway, IKE and IPsec policy/proposal chains; broad resolved permits, explicit legacy transforms and unresolved chains use distinct findings.

**What's missing:** Global security policies, dynamic addresses and applications, richer service semantics, scheduler/policy options, controller/group inheritance expansion, effective policy installation, live session/SA negotiation and peer identity remain unassessed. Built-in proposal-set contents are intentionally vendor-default/unknown rather than guessed.

**Why it matters:** A Junos registration now supports a bounded SRX static model, but it still must not imply complete policy installation or live VPN assessment. Shared names such as policy and filter retain different semantics.

<a id="STD-017"></a>
### ScreenOS — Bounded 6.3 session/default-policy depth; time and screens remain open

**Finding ID:** STD-017

**Standard reference:** [S-SCR](#S-SCR), qualified for the explicit ScreenOS 6.3 default-policy and timeout subset; legacy LEG-004 independently confirms the same capabilities. See the register for document/version, access date and applicability.

**Current coverage:** Existing checks cover manager sources, retries, SSHv2, HTTPS/cipher, SNMP communities, default credentials, banner, syslog/NTP presence, policy logging and referenced weak VPN proposals. For identified 6.3 exports, typed state now additionally detects explicit `default-permit-all`, resolves distinct console/Telnet and WebUI timeouts, and follows active administrator, default-user, policy and dot1x authentication-server bindings. Unbound servers and disabled policies are excluded; unresolved active references have a separate finding.

**What's missing:** Authenticated NTP and zone-screen contents/adequacy still require recoverable authoritative sections, representative syntax and an approved policy threshold. Routing and certificate applicability also remains open. Runtime authentication success is not static configuration state. Scope EOL migration advice separately and do not turn a Junos screen statement into a ScreenOS requirement.

**Why it matters:** The high-confidence legacy policy/session gap is closed without pretending every ScreenOS release shares 6.3 defaults or that remaining platform capabilities are verified.

<a id="STD-018"></a>
### Check Point FW1 — System hardening lies outside the supported export

**Finding ID:** STD-018

**Standard reference:** [S-CP](#S-CP), Gaia OS Hardening and Administrator Identity and Access Control. See the register for document/version, access date and applicability.

**Current coverage:** Policy/object exports cover access rules; parser does not ingest Gaia OS users, AAA, SSH, NTP, SNMP, certificates or routing settings.

**What's missing:** Unsupported-export gap: define optional offline Gaia/gateway/management input association, version identity and provenance before adding system checks. Keep absent OS data UNKNOWN/UNSUPPORTED. Current R81.20/R82 guide cannot silently certify older rules.C semantics.

**Why it matters:** No policy findings is not a hardened gateway verdict. The present export cannot answer most system control categories.

<a id="STD-019"></a>
### Check Point FW1 — Semantic network and service containment

**Finding ID:** STD-019

**Standard reference:** [S-CP](#S-CP), Decreasing Gateway Exposure with Policy; LEG-006/LEG-007. See the register for document/version, access date and applicability.

**Current coverage:** Current baseline already finds redundant/shadowed same-layer rules using expanded object-name sets, plus breadth, risky services, cleanup, stealth, time and references.

**What's missing:** Missing semantic subnet/range/port containment and rigorous multi-layer/negation handling. Use parsed network/service definitions; unknown/dynamic objects prevent proof. Runtime-unused rules require counters and observation windows.

**Why it matters:** Different object names can denote overlapping traffic. Do not describe shadow detection as absent or static redundancy as evidence that a rule receives no traffic.

<a id="STD-020"></a>
### PAN-OS — Unused password-policy and content-schedule evidence

**Finding ID:** STD-020

**Standard reference:** [S-PAN-M](#S-PAN-M), Minimum Password Complexity; [S-PAN-P](#S-PAN-P); NEEDS_RESEARCH for exact per-content update schedules. See the register for document/version, access date and applicability.

**Current coverage:** Password policy now reports explicit disabled password history and username-inclusion blocking with separate stable findings, while malformed, absent and unexpanded Panorama values remain unknown. Update parsing includes anti-virus/WildFire families, but only the independently qualified Applications and Threats schedule is assessed; optional-family entitlement, cadence and freshness remain unassessed.

**What's missing:** Add applicable history/username policy checks with verified thresholds; evaluate each supported relevant content family after feature/license/configuration prerequisites are documented. Reuse parsed state before adding new exports.

**Why it matters:** A partially evaluated policy can appear sufficient while other documented safeguards are ineffective. A schedule does not prove content freshness or entitlement.

<a id="STD-021"></a>
### PAN-OS — Administrative enforcement and warning notices

**Finding ID:** STD-021

**Standard reference:** [S-PAN](#S-PAN)/[S-PAN-M](#S-PAN-M), Authentication Settings and banners. See the register for document/version, access date and applicability.

**Current coverage:** All-local admin warning and length/class policy exist; management access/TLS checks exist. No admin lockout/MFA/session/banner or SSH-profile policy evaluation.

**What's missing:** Add local/global effective auth and admin role/profile evidence, login attempts/lockout/idle timeout, banner and version-supported SSH suites. Panorama inheritance remains explicit unknown unless expanded export is supplied.

**Why it matters:** Central authentication presence does not demonstrate strong authentication or bounded privileges/sessions.

<a id="STD-022"></a>
### HP_PROCURVE (ArubaOS-Switch) — Authentication, TLS and Layer 2 depth

**Finding ID:** STD-022

**Standard reference:** [S-HP](#S-HP); [S-HP-L2](#S-HP-L2); [S-HP-N](#S-HP-N). See the register for document/version, access date and applicability.

**Current coverage:** 16.10-specific service defaults, explicit SSH algorithm checks, AAA/accounting, password-control flag, remote logging, SNTP servers and VLAN DHCP snooping exist. AOS-S 16.10/16.11 now resolves tagged/untagged membership, DHCP/ARP trust, ARP-protected VLANs, Dynamic IP Lockdown and port security for explicitly classified access edges without duplicating the VLAN DHCP finding.

**What's missing:** Per-line/role authentication policy, session/banner and certificate/TLS policy remain open. Broader product-family/version tables, DHCPv6/ND protections, binding-database contents and non-2530/2930/3810/5400R syntax need dedicated fixtures. Do not substitute AOS-CX manuals.

**Why it matters:** A single enabled safeguard does not protect each access port or administrative channel. Unrecognized versions already remain unknown; preserve that behavior.

<a id="STD-023"></a>
### SonicOS — Administrator and credential policy evidence

**Finding ID:** STD-023

**Standard reference:** [S-SON](#S-SON)/[S-SON-P](#S-SON-P), Administration and Password Compliance. See the register for document/version, access date and applicability.

**Current coverage:** SonicOS7 E-CLI checks interfaces/rules/VPN/SNMP/logging/NTP/security-service flags. get_users returns empty native list and normalized users are unknown; no administrative AAA/password/session/banner/TLS checks.

**What's missing:** Extend the supported custom export with typed admin/password/AAA/session records and release-specific defaults. Implement enabled/effective policy checks and active service TLS policy. Reject incompatible preference exports rather than treating absent fields as secure.

**Why it matters:** A scan currently says little about administrators who can change the firewall. New SonicOS controls need actual7.x fixture evidence, not old legacy parser reuse.

<a id="STD-024"></a>
### EOS — Administrative and operational baseline depth

**Finding ID:** STD-024

**Standard reference:** [S-EOS](#S-EOS), User Security and Control Plane Security; [S-EOS-N](#S-EOS-N). See the register for document/version, access date and applicability.

**Current coverage:** eAPI protocol/ACL, some central auth/exec authorization, explicit SSH algorithms/empty passwords/ACL, SNMP and log/NTP host checks exist. Central-auth check is tied to active eAPI.

**What's missing:** Missing management-channel-wide AAA/accounting/credential/session/banner checks, TLS/certificate policy, per-VRF management ACL contents and time authentication. Parsed IOS-style users do not currently receive credential-strength analysis. Control plane/routing/discovery are STD-002/003/008.

**Why it matters:** CLI administration and service attachments can remain under-audited when eAPI is inactive. EOS is not covered merely because its parser inherits IOS.

<a id="STD-025"></a>
### CROSS-CUTTING — Logging scope, severity, transport and audit events

**Finding ID:** STD-025

**Standard reference:** [S-IOS](#S-IOS), logging/configuration changes; [S-JUN](#S-JUN), Management Services; [S-PAN-P](#S-PAN-P), logging. See the register for document/version, access date and applicability.

**Current coverage:** All pipelines except OS-less FW1 have some remote logging presence. IOS/ASA severity, FortiOS per-destination/VDOM event filtering, PAN-OS system/profile references and several firewall rule-log checks are implemented. Junos now models each effective remote host's facility/severity selectors, explicit transport metadata and routing-instance scope, and reports incomplete authorization/interactive-command coverage per destination.

**What's missing:** Per-source event classes on other platforms, secure-transport policy, destination resolution, release-appropriate timestamps and source-interface coverage where not modeled. Junos unknown/default transport remains unknown. Log delivery and retention require operational evidence.

**Why it matters:** One destination cannot establish sufficient evidence for investigation. Do not describe logging as absent or prescribe transport a platform does not support.

<a id="STD-026"></a>
### CROSS-CUTTING — Export scope and unknown coverage are not visible enough in reports

**Finding ID:** STD-026

**Standard reference:** [S-CP](#S-CP) export mismatch; [S-SRX](#S-SRX); [S-PAN-M](#S-PAN-M) template scope; local architecture contract; LEG-009. See the register for document/version, access date and applicability.

**Current coverage:** Finding schema has evidence/references and reports have scope prose. PAN-OS emits a specific Panorama-unknown finding. Most unsupported categories/fields are not summarized as report coverage.

**What's missing:** Add optional, explicit coverage metadata for assessed/unsupported/unknown categories, release and export provenance. IOS/ASA normalized getter inherits base unknown, so common adapters require investigation before reuse. Report unassessed categories separately from vulnerabilities.

**Why it matters:** Readers may equate no findings with comprehensive assessment. This is an assurance/report-interface gap, not a new security check.

<a id="STD-027"></a>
### CROSS-CUTTING — Remaining category applicability requires bounded research

**Finding ID:** STD-027

**Standard reference:** NEEDS_RESEARCH: platform-specific banner, discovery, routing, DoS and VPN sources noted in matrix. See the register for document/version, access date and applicability.

**Current coverage:** The matrix records A where no check exists and U where dialect/export applicability is unresolved. No rule is proposed solely because a category is on a checklist.

**What's missing:** Complete per-platform control maps for remaining A/U cells under GAP-001; mark true nonapplicability only with a role/export rationale. In particular do not invent banners on exports that cannot contain them or modern algorithms on PIX/ScreenOS.

**Why it matters:** An explicit research backlog prevents source absence from becoming an unjustified product requirement.

## Appendix A — Source inventory and interpretation

All parser, plugin, processor, analyzer, shared-model, CLI and report implementations under src were read before external standards research. Source paths below are relative to this document; function names and original line numbers make check claims reproducible. Source was inspected, not executed as a live-device test. The existing corpus is evidence of intended scope, not a substitute for source review.

### Parser evidence and export limits

| Pipeline | Parser source | Effective evidence and limits |
|---|---|---|
| IOS | [ios.py](../../src/devices/cisco/ios.py) | Ordered interface/line/global commands, AAA, service flags, users, crypto. IOS aliases share grammar. Native methods drive plugins; common normalized getter remains base unknown. |
| IOS-XE | [iosxe.py](../../src/devices/cisco/iosxe.py) | Thin IOS subclass reusing version and native configuration access. The IOS-XE plugin resolves MKA/MACsec/keychain and proposal attachments directly from the native tree; no dedicated typed IOS-XE record API exists. Inheritance does not make every IOS default valid on every XE version. |
| ASA/PIX | [asa.py](../../src/devices/cisco/asa.py) | Typed grants, interfaces/security levels, credentials, SNMP, ACL entries, bindings. ACL objects/ports and old PIX conduit grammar are not a full semantic model. Base normalized unknown. |
| FortiOS | [fortios.py](../../src/devices/fortinet/fortios.py) | Ordered nested config/edit/set/unset/append/select/unselect/delete/rename/move; global and VDOM scope; sanitized field evidence. Typed transit inspection, IPv4/IPv6 local-in and same-VDOM phase2-to-phase1 records remain separate; group/schedule and live VPN semantics are bounded as documented. |
| Junos | [junos.py](../../src/devices/juniper/junos.py) | Hierarchical/set/delete/deactivate/activate effective statements; unexpanded apply-groups identified. Typed users, stateless filters, SRX zone-pair policies, address/application resolution, attached VPN reference chains, logging and crypto. Global/dynamic policies and runtime installation/SA state are not modeled. |
| ScreenOS | [screenos.py](../../src/devices/juniper/screenos.py) | Set/unset effective commands, interface management, objects/services and policies. Identified 6.3 exports expose typed unmatched-policy and independent active console/WebUI/auth-server timeout/reference state. No authenticated-time or zone-screen semantic API. |
| FW1 | [fw1.py](../../src/devices/checkpoint/fw1.py), [S-expression parser](../../src/devices/checkpoint/parser.py) | objects*.C and rules.C/rulebases exports; typed layers/rules, groups, IP/netmask/range/services. No Gaia OS or compiled/runtime policy. |
| PAN-OS | [panos.py](../../src/devices/paloalto/panos.py) | Local device/vsys XML, management attachments, password settings, schedule families and forwarding. Panorama inheritance flagged. TLS profiles contain certificate references, not evaluated certificate material. |
| AOS-S | [procurve.py](../../src/devices/hp/procurve.py) | Ordered service flags, users, v3 algorithm users, AAA, password flag, logging/SNTP, VLAN/snooping. Known defaults limited to16.10; not AOS-CX. |
| SonicOS | [sonicos.py](../../src/devices/sonicwall/sonicos.py) | SonicOS7 custom E-CLI with version/export validation; interfaces/rules/VPN/log/NTP/auth/service flags. Legacy preferences rejected; users normalized unknown. |
| EOS | [eos.py](../../src/devices/arista/eos.py) | IOS-derived native parsing plus eAPI VRFs, explicit SSH/SNMP and normalized state. Only EOS processor rules execute, not all inherited IOS plugins. |

### Complete check-method inventory

Rule IDs below are actual literals or source expressions for generated IDs, not proposed names. Methods containing several IDs are itemized by trigger in the final column. Prefix-only literals accompany generated expressions where source constructs the ID. Helper functions do not constitute additional checks. All are reached by the explicit corresponding processor. Version-known baseline gates apply to IOS, ASA, Junos and selected ScreenOS checks; explicit-state checks outside those gates still run. FortiOS defaults are version/scoped; HP defaults are16.10 only. All depend on effective parser state, so an unsupported export is not equivalent to a secure configuration.

| Source / method (line at audit) | Existing rule IDs | Actual conditions, scope, dependencies and limits |
|---|---|---|
| [arista/arista_checks_plugin.py](../../src/analyze/arista/plugins/arista_checks_plugin.py) — `check_management_api`:35 | `arista.eos.eapi.https_disabled`; `arista.eos.eapi.insecure_http`; `arista.eos.eapi.source_restriction` | Active eAPI HTTP, HTTPS disabled, missing eAPI ACL reference per active VRF. Does not resolve ACL contents. |
| [arista/arista_checks_plugin.py](../../src/analyze/arista/plugins/arista_checks_plugin.py) — `check_authentication`:86 | `arista.eos.authentication.centralized` | Central authentication check only with active eAPI; CLI-only scope not comprehensive. |
| [arista/arista_checks_plugin.py](../../src/analyze/arista/plugins/arista_checks_plugin.py) — `check_ssh_and_authorization`:107 | `arista.eos.authorization.exec`; `arista.eos.ssh.empty_passwords`; `arista.eos.ssh.source_restriction`; `arista.eos.ssh.weak_algorithms` | Exec authorization with central auth; explicit SSH empty-password permission, weak algorithms, missing service ACL. No full AAA method/role evaluation. |
| [arista/arista_checks_plugin.py](../../src/analyze/arista/plugins/arista_checks_plugin.py) — `check_snmp` | `arista.eos.snmp.default_community`; `arista.eos.snmp.secure_user_missing`; `arista.eos.snmp.v3_access_scope`; `arista.eos.snmp.v3_protection`; `arista.eos.snmp.v3_reference`; `arista.eos.snmp.v3_weak_algorithm` | Every active default-VRF v3 user resolves group security, read/write view and agent ACL; disabled default-VRF agent and removed objects are ignored. Hidden keys stay unknown. |
| [arista/arista_checks_plugin.py](../../src/analyze/arista/plugins/arista_checks_plugin.py) — `check_operations` | `arista.eos.logging.remote_destination`; `arista.eos.ntp.authentication`; `arista.eos.ntp.authentication_reference`; `arista.eos.ntp.servers`; `arista.eos.ntp.weak_algorithm` | Per-server/VRF symmetric-key and NTS profile resolution; NTS and stronger-algorithm expectations begin at verified EOS 4.35.0F. |
| [fw1/fw1_baseline_plugin.py](../../src/analyze/checkpoint/plugins/fw1_baseline_plugin.py) — `check_cleanup_rules`:196 | `checkpoint.fw1.layer.cleanup_untracked`; `checkpoint.fw1.layer.explicit_cleanup_missing` | Type-aware explicit cleanup and tracking per layer, respecting application versus network/implicit semantics. |
| [fw1/fw1_baseline_plugin.py](../../src/analyze/checkpoint/plugins/fw1_baseline_plugin.py) — `check_stealth_rules`:254 | `checkpoint.fw1.layer.stealth_rule_missing` | Requires gateway-targeted deny rule in relevant layer; not a compiled enforcement proof. |
| [fw1/fw1_baseline_plugin.py](../../src/analyze/checkpoint/plugins/fw1_baseline_plugin.py) — `check_rule_hygiene`:296 | `checkpoint.fw1.policy.disabled_permissive_rule`; `checkpoint.fw1.policy.expired_rule` | Disabled permissive rules and literal expired time objects; disabled configuration is not runtime-unused traffic. |
| [fw1/fw1_baseline_plugin.py](../../src/analyze/checkpoint/plugins/fw1_baseline_plugin.py) — `check_rule_scope_and_tracking`:351 | `checkpoint.fw1.policy.install_scope_any`; `checkpoint.fw1.policy.negated_accept`; `checkpoint.fw1.policy.overly_broad_accept`; `checkpoint.fw1.policy.risky_service_exposure`; `checkpoint.fw1.policy.sensitive_accept_untracked` | At least two Any dimensions; risky service ports, negated accepts, Any install targets and sensitive untracked accepts. |
| [fw1/fw1_baseline_plugin.py](../../src/analyze/checkpoint/plugins/fw1_baseline_plugin.py) — `check_shadowing`:464 | `checkpoint.fw1.policy.redundant_rule`; `checkpoint.fw1.policy.shadowed_rule` | Same-layer, positive object-name set containment after group expansion; equal time/VPN/through/install scope. Same action redundant, different action shadowed. No CIDR/port semantic containment. |
| [fw1/fw1_baseline_plugin.py](../../src/analyze/checkpoint/plugins/fw1_baseline_plugin.py) — `check_references`:527 | `checkpoint.fw1.object.unresolved_group_member`; `checkpoint.fw1.policy.unresolved_reference` | Unresolved rule references and group members; dynamic/external resolution not supplied by config. |
| [fw1/fw1_checks_plugin.py](../../src/analyze/checkpoint/plugins/fw1_checks_plugin.py) — `check_broad_filter_rules`:29 | `checkpoint.fw1.policy.broad_accept` | Any source/destination/service allow, excluding recognized final application cleanup exception. |
| [asa/asa_checks_plugin.py](../../src/analyze/cisco/asa/plugins/asa_checks_plugin.py) — `check_telnet`:42 | `cisco.asa.management.telnet` | Every effective Telnet management grant. |
| [asa/asa_checks_plugin.py](../../src/analyze/cisco/asa/plugins/asa_checks_plugin.py) — `check_enable_credential`:59 | `cisco.asa.credentials.weak_enable_password` | Plaintext enable credentials or recognized default literals cisco/cisco123/admin/password; no arbitrary plaintext-strength analysis. |
| [asa/asa_checks_plugin.py](../../src/analyze/cisco/asa/plugins/asa_checks_plugin.py) — `check_snmp` | `cisco.asa.snmp.default_community`; `cisco.asa.snmp.legacy_version`; `cisco.asa.snmp.v3_protection`; `cisco.asa.snmp.v3_reference`; `cisco.asa.snmp.v3_weak_algorithm`; `cisco.asa.snmp.write_community` | Default/RW communities and legacy hosts remain separate; each host-bound active v3 user resolves its group and algorithms. SHA-1 is graded only from 9.14; unbound users are inactive, not exposed. |
| [asa/asa_checks_plugin.py](../../src/analyze/cisco/asa/plugins/asa_checks_plugin.py) — `check_unrestricted_ssh`:156 | `cisco.asa.management.unrestricted_ssh` | Any-source SSH grant on low-trust interface, excluding management-like names; no actual ACL reachability. |
| [asa/asa_checks_plugin.py](../../src/analyze/cisco/asa/plugins/asa_checks_plugin.py) — `check_logging`:180 | `cisco.asa.logging.missing`; `cisco.asa.logging.severity` | Logging enabled and host present; trap numeric level at least6. No TLS delivery or per-class audit verification. |
| [asa/asa_checks_plugin.py](../../src/analyze/cisco/asa/plugins/asa_checks_plugin.py) — `check_ssl_version`:229 | `cisco.asa.tls.minimum_version` | Explicit SSLv3/TLS1.0/TLS1.1 minimum settings; omitted defaults not fully graded. |
| [asa/asa_checks_plugin.py](../../src/analyze/cisco/asa/plugins/asa_checks_plugin.py) — `check_wide_open_acls`:248 | `cisco.asa.acl.broad_inbound_permit` | Bound inbound ACL on low-trust interface with permit any source/destination; no object/port semantic engine. |
| [asa/baseline_plugin.py](../../src/analyze/cisco/asa/plugins/baseline_plugin.py) — `check_aaa`:46 | `cisco.asa.aaa.management_accounting`; `cisco.asa.aaa.management_authentication` | Version-known baseline: management authentication and management accounting bindings exist; no server transport or complete channel/method resolution. |
| [asa/baseline_plugin.py](../../src/analyze/cisco/asa/plugins/baseline_plugin.py) — `check_local_users`:83 | `cisco.asa.credentials.local_user_storage` | Plaintext local password or recognized cisco/admin/password literals; encrypted/PBKDF2 marker not a password-strength proof. |
| [asa/baseline_plugin.py](../../src/analyze/cisco/asa/plugins/baseline_plugin.py) — `check_http_management`:100 | `cisco.asa.management.certificate`; `cisco.asa.management.http_sources`; `cisco.asa.management.unrestricted_http` | HTTP activation/grants, unrestricted sources, certificate trustpoint name. Does not parse certificate material. |
| [asa/baseline_plugin.py](../../src/analyze/cisco/asa/plugins/baseline_plugin.py) — `check_ntp` | `cisco.asa.ntp.authentication`; `cisco.asa.ntp.servers`; `cisco.asa.ntp.weak_algorithm` | Each server resolves global authentication, configured/trusted key and binding; stronger-algorithm policy begins at ASA 9.13. |
| [asa/baseline_plugin.py](../../src/analyze/cisco/asa/plugins/baseline_plugin.py) — `check_threat_detection`:161 | `cisco.asa.threat_detection.basic` | Requires basic threat-detection declaration; no resource limit effectiveness. |
| [asa/baseline_plugin.py](../../src/analyze/cisco/asa/plugins/baseline_plugin.py) — `check_reverse_path`:173 | `cisco.asa.interface.reverse_path` | Requires reverse-path verification on low-trust interfaces. |
| [asa/baseline_plugin.py](../../src/analyze/cisco/asa/plugins/baseline_plugin.py) — `check_vpn_crypto`:191 | `cisco.asa.crypto.legacy_transform`; `cisco.asa.crypto.legacy_vpn` | Weak IKE and transform algorithm tokens; not negotiated state. |
| [asa/baseline_plugin.py](../../src/analyze/cisco/asa/plugins/baseline_plugin.py) — `check_failover`:221 | `cisco.asa.failover.authentication` | When failover enabled, requires failover authentication key; no key value-strength analysis. |
| [ios/baseline_plugin.py](../../src/analyze/cisco/ios/plugins/baseline_plugin.py) — `check_aaa`:69 | `cisco.ios.aaa.accounting`; `cisco.ios.aaa.login_authentication`; `cisco.ios.aaa.new_model` | Version-known baseline. Requires aaa new-model; when enabled, at least one login authentication method and exec/commands accounting. Does not resolve per-line method lists or authorization. |
| [ios/baseline_plugin.py](../../src/analyze/cisco/ios/plugins/baseline_plugin.py) — `check_management_lines`:113 | `cisco.ios.console.session_timeout`; `cisco.ios.vty.authentication`; `cisco.ios.vty.session_timeout`; `cisco.ios.vty.telnet` | Per VTY: absent/telnet/all input transport, missing local/method authentication, explicitly unlimited timeout; console explicit exec-timeout 0 0. Finite excessive timeouts and AUX not checked. |
| [ios/baseline_plugin.py](../../src/analyze/cisco/ios/plugins/baseline_plugin.py) — `check_credentials`:189 | `cisco.ios.credentials.enable_storage`; `cisco.ios.credentials.local_storage` | Local password or secret type0/5/7 and enable password/secret0/5/7 flagged; algorithm-type changes interpretation. No plaintext length/blocklist/reuse assessment. |
| [ios/baseline_plugin.py](../../src/analyze/cisco/ios/plugins/baseline_plugin.py) — `check_snmp` | `cisco.ios.snmp.legacy_community`; `cisco.ios.snmp.v3_access_scope`; `cisco.ios.snmp.v3_protection`; `cisco.ios.snmp.v3_reference`; `cisco.ios.snmp.v3_weak_algorithm` | Every legacy community remains independent. Effective v3 users resolve group security, read/write views and user/group ACLs; broad roots account for exclusions. SHA-2 is not universally required without exact IOS XE platform evidence. |
| [ios/baseline_plugin.py](../../src/analyze/cisco/ios/plugins/baseline_plugin.py) — `check_logging`:263 | `cisco.ios.logging.remote_destination`; `cisco.ios.logging.severity` | Missing remote host; trap severity missing/unparsed or below informational (numeric6). No delivery, timestamps or transport verification. |
| [ios/baseline_plugin.py](../../src/analyze/cisco/ios/plugins/baseline_plugin.py) — `check_ntp` | `cisco.ios.ntp.authentication`; `cisco.ios.ntp.servers` | Each server/peer and VRF resolves global authentication, configured key, trust and binding; algorithm is retained but not graded without exact release policy. |
| [ios/baseline_plugin.py](../../src/analyze/cisco/ios/plugins/baseline_plugin.py) — `check_banner`:339 | `cisco.ios.banner.login` | Requires login or motd banner presence. Does not validate legal wording or deployment jurisdiction. |
| [ios/baseline_plugin.py](../../src/analyze/cisco/ios/plugins/baseline_plugin.py) — `check_unnecessary_services`:355 | `cisco.ios.services.unnecessary` | Explicit finger, TCP/UDP small servers and BOOTP enabled. Does not inventory all unnecessary services. |
| [ios/baseline_plugin.py](../../src/analyze/cisco/ios/plugins/baseline_plugin.py) — `check_interface_protections`:381 | `cisco.ios.interface.ip_hardening`; `cisco.ios.ip.source_route` | Global source-route lacking explicit disable; active IPv4-addressed interfaces lacking no redirects/proxy-arp. Role and IPv6 depth limited. |
| [ios/baseline_plugin.py](../../src/analyze/cisco/ios/plugins/baseline_plugin.py) — `check_control_plane`:419 | `cisco.ios.control_plane.copp` | Requires control-plane input service-policy attachment. Does not resolve policy-map/class-map/policer contents. |
| [ios/baseline_plugin.py](../../src/analyze/cisco/ios/plugins/baseline_plugin.py) — `check_crypto`:439 | `cisco.ios.crypto.legacy_ike`; `cisco.ios.crypto.legacy_ipsec` | IKE policies with DES/3DES, MD5/SHA or DH1/2/5/14; IPsec transform weak tokens. Fixed algorithm vocabulary, not complete negotiated policy. |
| [ios/http_plugin.py](../../src/analyze/cisco/ios/plugins/http_plugin.py) — `get_cisco_ios_http`:24 | `cisco.ios.http.cleartext_service` | HTTP enabled produces cleartext finding; HTTPS alone skips this plugin. |
| [ios/http_plugin.py](../../src/analyze/cisco/ios/plugins/http_plugin.py) — `get_cisco_ios_http_access_list`:41 | `cisco.ios.http.access_restriction` | When HTTP enabled, requires an HTTP access-class reference; does not resolve ACL contents. |
| [ios/http_plugin.py](../../src/analyze/cisco/ios/plugins/http_plugin.py) — `get_cisco_ios_http_auth`:61 | `cisco.ios.http.authentication` | When HTTP enabled, recognizes aaa/enable/local/tacacs authentication; no per-user authorization or transport. |
| [ios/ssh_plugin.py](../../src/analyze/cisco/ios/plugins/ssh_plugin.py) — `get_cisco_ios_ssh`:25 | `cisco.ios.ssh.protocol_version` | When SSH inferred enabled, protocol must be v2. |
| [ios/ssh_plugin.py](../../src/analyze/cisco/ios/plugins/ssh_plugin.py) — `get_cisco_ios_ssh_retries`:56 | `cisco.ios.ssh.authentication_retries` | SSH authentication retries >0 and <=5; parser default3. |
| [ios/ssh_plugin.py](../../src/analyze/cisco/ios/plugins/ssh_plugin.py) — `get_cisco_ios_ssh_timeout`:82 | `cisco.ios.ssh.negotiation_timeout` | SSH negotiation timeout <=60; parser default120; this is not idle session timeout. |
| [ios/ssh_plugin.py](../../src/analyze/cisco/ios/plugins/ssh_plugin.py) — `get_cisco_ios_vty_access_restriction`:108 | `cisco.ios.ssh.vty_access_restriction` | Each relevant VTY needs either IPv4 or IPv6 access-class name; no evaluation of address-family equivalence or traffic allowed. |
| [iosxe/iosxe_checks_plugin.py](../../src/analyze/cisco/iosxe/plugins/iosxe_checks_plugin.py) — `check_macsec`:58 | `cisco.iosxe.macsec.missing` | Active Ethernet-like switchports need MACsec plus MKA policy/keychain linkage and key material; cipher selection is checked with default AES128 semantics. This does not prove a live secure association. |
| [iosxe/iosxe_checks_plugin.py](../../src/analyze/cisco/iosxe/plugins/iosxe_checks_plugin.py) — `check_legacy_crypto`:191 | `cisco.iosxe.crypto.legacy_ikev1`; `cisco.iosxe.crypto.legacy_ikev2`; `cisco.iosxe.crypto.legacy_ipsec` | Referenced IKEv2 proposals: missing/weak encryption, PRF or DH, plus missing/weak integrity unless GCM supplies it; IKEv1 policy weak/missing algorithms; referenced crypto-map transforms. Unreferenced definitions are not equivalent to exposure. |
| [fortios/fortios_baseline_plugin.py](../../src/analyze/fortinet/plugins/fortios_baseline_plugin.py) — `check_administrators`:174 | `fortinet.fortios.admin.centralized_authentication`; `fortinet.fortios.admin.mfa`; `fortinet.fortios.admin.remote_group`; `fortinet.fortios.admin.trusted_hosts` | Enabled super_admin trusthosts; remote-user group; local MFA; centralized-auth warning for local privileged users with known7+ release. Not per-command role or protected-server transport. |
| [fortios/fortios_baseline_plugin.py](../../src/analyze/fortinet/plugins/fortios_baseline_plugin.py) — `check_password_and_session_policy`:266 | `fortinet.fortios.admin.lockout`; `fortinet.fortios.admin.session_timeout`; `fortinet.fortios.password_policy.disabled`; `fortinet.fortios.password_policy.weak` | Password policy enable/apply-to-admin, length12 and character classes/reuse; lockout threshold0/>3 or duration<60; admin timeout0/>10. Known-version defaults, not measured password values. |
| [fortios/fortios_baseline_plugin.py](../../src/analyze/fortinet/plugins/fortios_baseline_plugin.py) — `check_management_crypto`:374 | `f"fortinet.fortios.crypto.{field.replace('-', '_')}"`; `f"fortinet.fortios.ssh.weak_{field[4:].replace('-', '_')}"`; `fortinet.fortios.crypto.`; `fortinet.fortios.crypto.dh_parameters`; `fortinet.fortios.https.management_certificate`; `fortinet.fortios.ssh.weak_` | Explicit disabled strong-crypto, static SSL ciphers, SSHv1/CBC; DH<2048; weak explicit SSH lists; default factory admin-server-cert when HTTPS active and version known. No certificate material. |
| [fortios/fortios_baseline_plugin.py](../../src/analyze/fortinet/plugins/fortios_baseline_plugin.py) — `check_snmp`:459 | `fortinet.fortios.snmp.legacy_community`; `fortinet.fortios.snmp.secure_user_missing`; `fortinet.fortios.snmp.v3_security` | Active SNMP interface/agent scope: communities; each v3 user auth-priv, non-MD5/non-DES with credentials; secure user existence. Per-scope rather than global one-user shortcut. |
| [fortios/fortios_baseline_plugin.py](../../src/analyze/fortinet/plugins/fortios_baseline_plugin.py) — `check_ntp` | `fortinet.fortios.ntp.authentication`; `fortinet.fortios.ntp.custom_server_missing`; `fortinet.fortios.ntp.synchronization`; `fortinet.fortios.ntp.weak_algorithm` | Each custom server checks authentication/key/key-id independently; legacy algorithm is a separate finding. FortiGuard source semantics remain distinct from custom-key requirements. |
| [fortios/fortios_baseline_plugin.py](../../src/analyze/fortinet/plugins/fortios_baseline_plugin.py) — `check_logging_and_policy_profiles`:642 | `fortinet.fortios.logging.events_filtered`; `fortinet.fortios.policy.logging`; `fortinet.fortios.policy.security_profiles` | WAN outbound allow logtraffic all/utm plus UTM/profile-name presence; logging filter disabling anomaly/traffic/system/user. No profile content resolution. |
| [fortios/fortios_baseline_plugin.py](../../src/analyze/fortinet/plugins/fortios_baseline_plugin.py) — `check_updates_and_unused_services`:734 | `fortinet.fortios.firmware.automatic_updates`; `fortinet.fortios.fortiguard.automatic_updates`; `fortinet.fortios.interface.unused_enabled`; `fortinet.fortios.management.auxiliary_services` | Explicit disabled/manual FortiGuard updates; firmware auto disabled unless FortiManager; WAN CAPWAP/fabric/FGFM; heuristic apparently unused up interfaces. Does not prove runtime disuse. |
| [fortios/fortios_baseline_plugin.py](../../src/analyze/fortinet/plugins/fortios_baseline_plugin.py) — `check_dos_policies`:832 | `fortinet.fortios.dos.logging`; `fortinet.fortios.dos.no_blocking_anomaly`; `fortinet.fortios.dos.wan_policy_missing` | WAN DoS policy attachment, a blocking enabled anomaly and logging. No rate adequacy or complete coverage proof. |
| [fortios/fortios_baseline_plugin.py](../../src/analyze/fortinet/plugins/fortios_baseline_plugin.py) — `check_local_in_policy`; `check_ipsec_tunnels` | `fortinet.fortios.local_in.unrestricted_management`; `fortinet.fortios.vpn.unresolved`; `fortinet.fortios.vpn.weak_proposal` | Enabled IPv4/IPv6 local-in accepts with exact wildcard source, explicit always schedule and sensitive management service; active same-VDOM phase2/phase1 bindings with explicit legacy transforms or unresolved references. No group/schedule expansion, controller state or live negotiation. |
| [fortios/fortios_checks_plugin.py](../../src/analyze/fortinet/plugins/fortios_checks_plugin.py) — `check_admin_access`:44 | `fortinet.fortios.management.insecure_protocol` | Normalized active interfaces exposing HTTP/Telnet; effective VDOM/global scopes, not raw token occurrence. |
| [fortios/fortios_checks_plugin.py](../../src/analyze/fortinet/plugins/fortios_checks_plugin.py) — `check_broad_policies`:95 | `fortinet.fortios.policy.broad_accept` | Enabled accept transit firewall policy with all source/destination/service and always schedule. IPv6 transit and local-in remain separate engines; local-in is handled by the typed baseline check above. |
| [fortios/fortios_checks_plugin.py](../../src/analyze/fortinet/plugins/fortios_checks_plugin.py) — `check_tls_settings`:130 | `fortinet.fortios.tls.minimum_version` | Explicit weak management TLS minimum; does not inspect all VPN/TLS profiles. |
| [fortios/fortios_checks_plugin.py](../../src/analyze/fortinet/plugins/fortios_checks_plugin.py) — `check_syslog`:166 | `fortinet.fortios.logging.missing` | Requires usable scoped remote syslog/FortiAnalyzer/FortiCloud/manager logging destination, accounting for enabled state. |
| [hp/hp_checks_plugin.py](../../src/analyze/hp/plugins/hp_checks_plugin.py) — `check_management`:35 | `hp.procurve.management.http`; `hp.procurve.management.source_restriction`; `hp.procurve.management.telnet` | Active Telnet/HTTP and missing authorized-manager restriction. Service defaults only known AOS-S16.10. |
| [hp/hp_checks_plugin.py](../../src/analyze/hp/plugins/hp_checks_plugin.py) — `check_snmp` | `hp.procurve.snmp.community_access`; `hp.procurve.snmp.default_community`; `hp.procurve.snmp.secure_user_missing`; `hp.procurve.snmp.v3_access_scope`; `hp.procurve.snmp.v3_protection`; `hp.procurve.snmp.v3_weak_algorithm` | Every active v3 user is evaluated for SHA/AES protection and authorized-manager scope; explicit agent disablement suppresses stale-user findings and keys are never retained. |
| [hp/hp_checks_plugin.py](../../src/analyze/hp/plugins/hp_checks_plugin.py) — `check_ssh_crypto`:148 | `hp.procurve.ssh.weak_algorithms` | Weak configured algorithms or known16.10 defaults; unknown version does not invent defaults. |
| [hp/hp_checks_plugin.py](../../src/analyze/hp/plugins/hp_checks_plugin.py) — `check_operational_baseline`:182 | `hp.procurve.authentication.centralized` | Central management authentication presence. |
| [hp/hp_checks_plugin.py](../../src/analyze/hp/plugins/hp_checks_plugin.py) — `check_advanced_baseline` | `hp.procurve.ntp.authentication`; `hp.procurve.ntp.key_resolution`; `hp.procurve.ntp.servers` plus existing advanced-baseline IDs | Supported AOS-S 16.10/16.11 SNTP sources resolve global authentication, configured/trusted MD5 key and per-server binding; unknown release/family stays unknown. |
| [junos/baseline_plugin.py](../../src/analyze/juniper/junos/plugins/baseline_plugin.py) — `check_authentication`:120 | `juniper.junos.authentication.centralized`; `juniper.junos.authentication.lockout`; `juniper.junos.authentication.login_attempts`; `juniper.junos.authentication.super_user`; `juniper.junos.authentication.weak_storage` | Known version/parser scope: radius/tacplus order, retries>3, missing lockout, superuser missing auth, plaintext/$1$/$9$/$md5$ storage. No login-class timeout/accounting/password-policy checks. |
| [junos/baseline_plugin.py](../../src/analyze/juniper/junos/plugins/baseline_plugin.py) — `check_ssh_algorithms`:228 | `f"juniper.junos.ssh.weak_{field.replace('-', '_')}"`; `juniper.junos.ssh.weak_` | Explicit weak cipher/MAC/KEX/hostkey sets; defaults not universal across releases. |
| [junos/baseline_plugin.py](../../src/analyze/juniper/junos/plugins/baseline_plugin.py) — `check_additional_services`:257 | `juniper.junos.services.legacy` | Effective ftp/finger/rlogin/rsh/xnm legacy service declarations. |
| [junos/baseline_plugin.py](../../src/analyze/juniper/junos/plugins/baseline_plugin.py) — `check_snmp`:283 | `juniper.junos.snmp.legacy_community`; `juniper.junos.snmp.v3_security` | Legacy communities; v3 authentication/privacy presence and weak MD5/DES/none. No complete access view/filter analysis. |
| [junos/baseline_plugin.py](../../src/analyze/juniper/junos/plugins/baseline_plugin.py) — `check_logging`:358 | `juniper.junos.logging.remote_destination` | Remote syslog existence; parser carries severity but this baseline does not evaluate its policy. |
| [junos/baseline_plugin.py](../../src/analyze/juniper/junos/plugins/baseline_plugin.py) — `check_ntp` | `juniper.junos.ntp.associations`; `juniper.junos.ntp.authentication`; `juniper.junos.ntp.weak_algorithm` | Each server/peer resolves key type/value/trust independently; MD5/SHA1 are graded where maintained platform exceptions do not limit support to MD5. No live time-exchange claim. |
| [junos/baseline_plugin.py](../../src/analyze/juniper/junos/plugins/baseline_plugin.py) — `check_routing_engine_filter`:428 | `juniper.junos.control_plane.lo0_filter` | Requires lo0 input filter attachment; does not inspect policer rates/allowed control traffic. |
| [junos/baseline_plugin.py](../../src/analyze/juniper/junos/plugins/baseline_plugin.py) — `check_redirects`:452 | `juniper.junos.interfaces.redirects` | Requires system no-redirects effective declaration. |
| [junos/junos_checks_plugin.py](../../src/analyze/juniper/junos/plugins/junos_checks_plugin.py) — `check_management`:32 | `juniper.junos.management.insecure_protocol` | Effective Telnet/J-Web HTTP declarations; inherited apply-groups not automatically expanded. |
| [junos/junos_checks_plugin.py](../../src/analyze/juniper/junos/plugins/junos_checks_plugin.py) — `check_broad_filters`:69 | `juniper.junos.filter.broad_accept` | Attached stateless filter accept with unconstrained source/destination/protocol before a terminal catch-all. It remains separate from SRX stateful policy semantics and has no complete port model. |
| [junos/junos_checks_plugin.py](../../src/analyze/juniper/junos/plugins/junos_checks_plugin.py) — `check_stateful_policies`; `check_ipsec_vpns` | `juniper.junos.policy.broad_permit`; `juniper.junos.vpn.unresolved`; `juniper.junos.vpn.weak_proposal` | Active SRX zone-pair wildcard permits after static address/application resolution; attached or interface-bound VPN chains with explicit legacy proposals or unresolved references. Apply-groups, built-in proposal contents and live installation/negotiation remain unknown. |
| [junos/junos_checks_plugin.py](../../src/analyze/juniper/junos/plugins/junos_checks_plugin.py) — `check_ssh_root`:103 | `juniper.junos.ssh.root_login` | Explicit SSH root-login allow/deny-password flagged; not full auth-role model. |
| [screenos/screenos_baseline_plugin.py](../../src/analyze/juniper/plugins/screenos_baseline_plugin.py) — `check_lifecycle`:96 | `juniper.screenos.lifecycle.end_of_life` | Version-known ScreenOS baseline emits EOL warning; this is a lifecycle finding, not every hardening category. |
| [screenos/screenos_baseline_plugin.py](../../src/analyze/juniper/plugins/screenos_baseline_plugin.py) — `check_administration` | `juniper.screenos.administration.login_attempts`; `juniper.screenos.administration.manager_sources`; `juniper.screenos.administration.session_timeout`; `juniper.screenos.administration.web_session_timeout`; `juniper.screenos.administration.remote_session_timeout`; `juniper.screenos.authentication.session_timeout`; `juniper.screenos.authentication.server_reference`; `juniper.screenos.https.global_activation`; `juniper.screenos.https.legacy_cipher`; `juniper.screenos.ssh.protocol_version` | Management source restriction, failed attempts, SSHv2, SSL activation/ciphers, and release-gated ScreenOS 6.3 active console/Telnet, WebUI, administrator-AAA and policy/user auth-server timeout/reference state. |
| [screenos/screenos_baseline_plugin.py](../../src/analyze/juniper/plugins/screenos_baseline_plugin.py) — `check_credentials_and_banner`:232 | `juniper.screenos.administration.login_banner`; `juniper.screenos.credentials.default_or_empty` | Empty/default literals password/netscreen/admin/administrator or known14 hash fingerprints; warning banner presence. No arbitrary structural password-strength check. |
| [screenos/screenos_baseline_plugin.py](../../src/analyze/juniper/plugins/screenos_baseline_plugin.py) — `check_logging`:277 | `juniper.screenos.logging.remote_destination` | Remote syslog destination presence. |
| [screenos/screenos_baseline_plugin.py](../../src/analyze/juniper/plugins/screenos_baseline_plugin.py) — `check_snmp`:299 | `juniper.screenos.snmp.legacy_community` | Communities flagged with default/RW/missing corresponding manager evidence; no modern v3 algorithm model. |
| [screenos/screenos_baseline_plugin.py](../../src/analyze/juniper/plugins/screenos_baseline_plugin.py) — `check_ntp`:346 | `juniper.screenos.ntp.servers` | NTP server existence only. |
| [screenos/screenos_baseline_plugin.py](../../src/analyze/juniper/plugins/screenos_baseline_plugin.py) — `check_policy_logging`:364 | `juniper.screenos.policy.unlogged_permit` | Permits involving untrust/dmz/public or broad traffic need logging; no hit counts. |
| [screenos/screenos_baseline_plugin.py](../../src/analyze/juniper/plugins/screenos_baseline_plugin.py) — `check_policy_default` | `juniper.screenos.policy.default_permit` | Identified ScreenOS 6.3 export explicitly enables unmatched interzone/global permit; documented default deny does not emit an absence finding. |
| [screenos/screenos_baseline_plugin.py](../../src/analyze/juniper/plugins/screenos_baseline_plugin.py) — `check_vpn_crypto`:391 | `juniper.screenos.vpn.weak_proposal` | Referenced phase1/phase2 proposal tokens evaluated for weak algorithms. |
| [screenos/screenos_checks_plugin.py](../../src/analyze/juniper/plugins/screenos_checks_plugin.py) — `_management_finding`:21 | `juniper.screenos.management.http`; `juniper.screenos.management.telnet` | Helper emits HTTP/Telnet management findings for effective interface exposure; rule IDs selected from protocol. |
| [screenos/screenos_checks_plugin.py](../../src/analyze/juniper/plugins/screenos_checks_plugin.py) — `check_broad_policy_rules`:84 | `juniper.screenos.policy.broad_permit` | Enabled permit rule with any source/destination/service, in its source/destination zones. |
| [panos/panos_checks_plugin.py](../../src/analyze/paloalto/plugins/panos_checks_plugin.py) — `check_management`:71 | `f'paloalto.panos.management.{protocol}'`; `paloalto.panos.management.`; `paloalto.panos.management.unrestricted_secure_service` | Attached interface management profiles/dedicated MGT enabled HTTP/Telnet; unrestricted secure service on untrusted/MGT scope. |
| [panos/panos_checks_plugin.py](../../src/analyze/paloalto/plugins/panos_checks_plugin.py) — `check_administration`:125 | `paloalto.panos.admin.centralized_authentication` | Warning when administrators all use local authentication; no remote transport or MFA enforcement. |
| [panos/panos_checks_plugin.py](../../src/analyze/paloalto/plugins/panos_checks_plugin.py) — `check_platform_services` | `paloalto.panos.ntp.authentication`; `paloalto.panos.ntp.servers`; `paloalto.panos.ntp.weak_algorithm`; `paloalto.panos.snmp.secure_user_missing`; `paloalto.panos.snmp.v3_protection`; `paloalto.panos.snmp.v3_weak_algorithm` plus DNS IDs | Primary/secondary NTP and every SNMPv3 user are independent. SNMP users are graded only when an attached management surface enables SNMP; empty secret elements remain redacted/unexported. |
| [panos/panos_checks_plugin.py](../../src/analyze/paloalto/plugins/panos_checks_plugin.py) — `check_management_tls`:200 | `paloalto.panos.management.certificate_missing`; `paloalto.panos.management.tls_minimum_version`; `paloalto.panos.management.tls_profile_missing`; `paloalto.panos.management.tls_profile_unresolved` | Attached TLS profile missing/unresolved, missing certificate reference, minimum below TLS1.2. Certificate name is not material resolution. |
| [panos/panos_checks_plugin.py](../../src/analyze/paloalto/plugins/panos_checks_plugin.py) — `check_updates_and_system_logging`:305 | `paloalto.panos.logging.system_forwarding`; `paloalto.panos.updates.threat_content` | Threat-content schedule must download-and-install; system forwarding must exist. Other parsed content schedule families not checked. |
| [panos/panos_checks_plugin.py](../../src/analyze/paloalto/plugins/panos_checks_plugin.py) — `check_security_rules` | `paloalto.panos.policy.broad_allow`; `paloalto.panos.policy.log_forwarding`; `paloalto.panos.policy.security_profiles`; `paloalto.panos.policy.security_profile_unresolved`; `paloalto.panos.policy.security_profile_ineffective`; `paloalto.panos.policy.session_logging` | Enabled allow rules retain match dimensions and logging, then resolve individual/group profile attachments in same-vsys/shared precedence. Attached empty, explicitly allow/alert-only, or unresolved local objects are reported; disabled, unbound and unknown Panorama-inherited objects are not. |
| [panos/panos_checks_plugin.py](../../src/analyze/paloalto/plugins/panos_checks_plugin.py) — `check_password_policy`:440 | `paloalto.panos.credentials.password_complexity` | Policy enabled, minimum length12, character class minima1. Parsed history_count and blocks_username unused. |
| [panos/panos_checks_plugin.py](../../src/analyze/paloalto/plugins/panos_checks_plugin.py) — `check_panorama_scope`:474 | `paloalto.panos.analysis.panorama_inheritance_unknown` | Explicit analysis finding for unexpanded Panorama inheritance; local XML is not merged controller state. |
| [sonicos/sonicos_checks_plugin.py](../../src/analyze/sonicwall/plugins/sonicos_checks_plugin.py) — `check_management`:45 | `sonicwall.sonicos.management.external_interface`; `sonicwall.sonicos.management.http` | HTTP on interfaces; HTTPS/SSH/SNMP on external interfaces. Native7.x E-CLI format gate. |
| [sonicos/sonicos_checks_plugin.py](../../src/analyze/sonicwall/plugins/sonicos_checks_plugin.py) — `check_access_rules`:86 | `sonicwall.sonicos.policy.broad_allow`; `sonicwall.sonicos.policy.logging` | Enabled broad all allow and allow rule logging disabled; no generalized shadow/semantic address engine. |
| [sonicos/sonicos_checks_plugin.py](../../src/analyze/sonicwall/plugins/sonicos_checks_plugin.py) — `check_vpn`:131 | `sonicwall.sonicos.vpn.weak_proposal` | Enabled VPN proposal weak suites; no full management TLS analysis. |
| [sonicos/sonicos_checks_plugin.py](../../src/analyze/sonicwall/plugins/sonicos_checks_plugin.py) — `check_operations` | `sonicwall.sonicos.capture_atp.dependencies`; `sonicwall.sonicos.logging.remote_destination`; `sonicwall.sonicos.ntp.authentication`; `sonicwall.sonicos.ntp.servers`; `sonicwall.sonicos.security_services.disabled`; `sonicwall.sonicos.snmp.secure_user_missing`; `sonicwall.sonicos.snmp.v3_protection`; `sonicwall.sonicos.snmp.v3_weak_algorithm` | Every custom NTP source and each visible SNMPv3 user is independent. SNMP users are graded only when an interface enables SNMP; evidence never contains authentication/privacy material. |

### Orchestration, shared interfaces, CLI and reporting

The [registry](../../src/devices/registry.py) resolves lazy parser/analyzer paths. [analyze_device](../../src/analyze/analyze_device.py) dispatches the selected ID. The public processor/analyzer implementations in cisco/ios, cisco/iosxe, cisco/asa, fortinet, juniper (ScreenOS), juniper/junos, checkpoint, paloalto, hp, sonicwall and arista explicitly select the plugins listed above. IOS-XE composes IOS checks plus its own; EOS does not run IOS plugins just because its parser inherits IOS.

[BaseDeviceParser](../../src/devices/common/base_parser.py) and [models](../../src/devices/common/models.py) distinguish KNOWN empty from UNKNOWN, UNSUPPORTED and PARSE_ERROR. [BasePlugin](../../src/analyze/common/base_plugin.py) supplies the plugin interface; [Finding](../../src/analyze/common/issue.py) carries rule_id, device, title, observation, impact, recommendation, severity, exploitability, evidence and references. New checks must retain those contracts. Do not add a parallel issue schema.

[main.py](../../src/main.py) exposes device, input, output filename, HTML/JSON output type, configuration and offline options. There is no general target-CIDR selector, rule-policy profile or report-section selector. IOS's [advisory service](../../src/analyze/cisco/ios/api/cisco_ios_vulns_service.py) and [API client](../../src/analyze/cisco/ios/api/cisco_vuln.py) are external advisory integration, not configuration controls. Other analyzers' empty advisory lists are placeholders, not working vendor vulnerability feeds.

[report.py](../../src/report/report.py), [report types](../../src/report/common/types.py), [HTML template](../../src/report/templates/html_template.html), stylesheet and impact-color script were reviewed. JSON serializes findings plus metadata/advisories; HTML includes scope prose, finding detail and advisories. Finding remediation, exploitability and authoritative references already exist. Neither output provides a complete sanitized configuration inventory, category coverage ledger or legacy-style explanatory appendices.

### Public pipeline source manifest

| Registered IDs | Analyzer | Processor and explicit plugin imports |
|---|---|---|
| IOS_SWITCH, IOS_ROUTER, IOS_CATALYST | [analyze_cisco_device](../../src/analyze/cisco/ios/analyze_cisco_device.py) | [process_cisco_ios_conf.py](../../src/analyze/cisco/ios/core/process_cisco_ios_conf.py) —  |
| PIX, ASA | [analyze_asa_device](../../src/analyze/cisco/asa/analyze_asa_device.py) | [process_asa_conf.py](../../src/analyze/cisco/asa/core/process_asa_conf.py) —  |
| SCREENOS | [analyze_juniper_device](../../src/analyze/juniper/analyze_juniper_device.py) | [process_screenos_conf.py](../../src/analyze/juniper/core/process_screenos_conf.py) —  |
| SONICOS | [analyze_sonicwall_device](../../src/analyze/sonicwall/analyze_sonicwall_device.py) | [process_sonicos_conf.py](../../src/analyze/sonicwall/core/process_sonicos_conf.py) —  |
| CHECKPOINT_FW1 | [analyze_checkpoint_fw1_device](../../src/analyze/checkpoint/analyze_checkpoint_fw1_device.py) | [process_checkpoint_fw1_conf.py](../../src/analyze/checkpoint/core/process_checkpoint_fw1_conf.py) —  |
| HP_PROCURVE | [analyze_hp_device](../../src/analyze/hp/analyze_hp_device.py) | [process_hp_conf.py](../../src/analyze/hp/core/process_hp_conf.py) —  |
| PAN_OS | [analyze_panos_device](../../src/analyze/paloalto/analyze_panos_device.py) | [process_panos_conf.py](../../src/analyze/paloalto/core/process_panos_conf.py) —  |
| FORTIOS | [analyze_fortinet_device](../../src/analyze/fortinet/analyze_fortinet_device.py) | [process_fortios_conf.py](../../src/analyze/fortinet/core/process_fortios_conf.py) —  |
| IOS_XE | [analyze_iosxe_device](../../src/analyze/cisco/iosxe/analyze_iosxe_device.py) | [process_iosxe_conf.py](../../src/analyze/cisco/iosxe/core/process_iosxe_conf.py) —  |
| JUNOS | [analyze_junos_device](../../src/analyze/juniper/junos/analyze_junos_device.py) | [process_junos_conf.py](../../src/analyze/juniper/junos/core/process_junos_conf.py) —  |
| ARISTA_EOS | [analyze_arista_device](../../src/analyze/arista/analyze_arista_device.py) | [process_arista_conf.py](../../src/analyze/arista/core/process_arista_conf.py) —  |

### Cross-cutting candidate disposition

| Suggested candidate | Source-derived disposition |
|---|---|
| AAA transport | GAP-012 implements bounded FortiOS 7.4+ administrative RADIUS/RadSec transport and identity checks; other platforms and live path/certificate validation remain STD-001 gaps. |
| NTP authentication | Already implemented on several pipelines; key/algorithm and platform gaps are STD-006. |
| SNMPv3 algorithms | GAP-008 closes the bounded per-user/group/view/manager relationship scope; runtime reachability, hidden-key verification and remaining export-specific VACM depth stay explicit STD-007 limits. |
| Certificate validation | Attachment checks exist; material/identity vs live served chain split is STD-004. |
| CDP/LLDP | GAP-010 implements explicit-role IOS/XE CDP/LLDP and Junos LLDP boundary checks; other platforms, inferred roles and runtime neighbors remain STD-003 gaps. |
| Control-plane policing/rate limiting | Attachment and several firewall defenses exist; content and platform depth is STD-008. |
| Structural credentials vs blacklist | IOS/Junos storage and several policy checks exist. ASA/ScreenOS default lists leave arbitrary strength unassessed; STD-005. |
| ACL effectiveness | FW1 already has bounded redundancy/shadowing; broaden semantics and platforms, STD-019 and LEG-006/007. |

## Audit validation and boundaries

Every registered ID maps to a matrix row and a reviewed parser/analyzer pair. Every executable check method has a source/ID/condition entry. All 27 findings are linked from remediation tasks. Internal document anchors and relative source links are checked at delivery. The detection-audit files were absent on final recheck. No source or regression snapshot is changed; no regression-pass claim is made for this documentation-only audit. Future implementation must run the established full regression gate.

Unresolved standards are deliberately not silently completed: ScreenOS manuals, independently supported PIX releases, full CIS control text, several release/default mappings and the remaining A/U matrix cells are research prerequisites under GAP-001. This audit is complete as a source-grounded findings and implementation plan; those prerequisites prevent speculative rules from being treated as ready to code.
