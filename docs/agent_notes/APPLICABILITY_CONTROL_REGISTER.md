# Applicability and Control Source Register

Last verified: 2026-09-14

This register closes the research deliverable in GAP-001. It qualifies every `A` and `U` cell in the standards coverage matrix before a detector is allowed to turn absence into a finding. It is intentionally conservative: a current vendor guide can prove that a control exists, but it cannot prove that an older release used the same default, nor that a partial export contains the authoritative state.

## Dispositions

- `VERIFIED-PARSER-GAP`: an official source defines the control and a supported fixture family can carry relevant evidence; the named remediation task may implement it.
- `RELEASE-REVIEW`: an official source defines the control, but its release does not match all supported fixtures. Only explicit configuration may be assessed until release applicability is reviewed.
- `EXPORT-ABSENT`: the supported export does not expose enough state. Absence must remain unknown until a richer export/parser exists.
- `DIALECT-UNQUALIFIED`: no representative fixture/parser contract exists for the legacy dialect. Similar vendor syntax is not sufficient.
- `SOURCE-UNAVAILABLE`: the official library was found, but the required manual body could not be retrieved and verified.
- `POLICY-REVIEW`: vendor evidence supports a control, but its threshold or organizational requirement is reserved for human approval.

## Verified primary sources

| ID | Official title and release | Relevant sections | URL | Result |
|---|---|---|---|---|
| CS-IOS | *Cisco Guide to Harden Cisco IOS Devices*, current web revision | management plane, passwords, logging, routing protocols, ACLs and services | <https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html> | Retrieved. Applicable to explicit IOS configuration; release-specific defaults are not inferred. |
| CS-XE | *Cisco IOS XE Hardening Guide*, current web revision | management, control and data planes | <https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening> | Retrieved. Applicable to explicit IOS-XE configuration; release-specific defaults are not inferred. |
| CS-ASA | *Cisco Guide to Securing the Cisco ASA Firewall*, current web revision | management, logging, filtering and routing-plane protection | <https://sec.cloudapps.cisco.com/security/center/resources/firewall_best_practices> | Retrieved. Applicable to explicit ASA configuration. |
| CS-PIX | *Cisco PIX Firewall and VPN Configuration Guide, Version 5.0* | AAA, Telnet, syslog and access lists | <https://www.cisco.com/en/US/docs/security/pix/pix50/configuration/guide/config.html> | Retrieved, but no PIX fixture/parser contract exists. Source availability does not qualify the dialect. |
| CS-FGT | *FortiOS 8.0.0 Best Practices — Hardening* | administrative access, logging, local-in policy, strong cryptography and password storage | <https://docs.fortinet.com/document/fortigate/8.0.0/best-practices/555436/hardening> | Retrieved. The prior 7.6 URL/body mismatch is resolved by registering 8.0.0 explicitly. No 8.0 default is backported to 7.x fixtures. |
| CS-FGT-POLICY-VPN | *FortiOS 7.2 CLI Reference — local-in-policy/local-in-policy6 and IPsec phase1/phase2-interface* | explicit IPv4/IPv6 local-in fields, phase bindings, proposals, DH/PFS and replay options | <https://docs.fortinet.com/document/fortigate/7.2.1/cli-reference/328620/config-firewall-local-in-policy> | Retrieved. Qualifies explicit 7.2 CLI syntax only; local-in group expansion, defaults and live negotiation are not inferred. Companion references: [IPv6 local-in](https://docs.fortinet.com/document/fortigate/7.2.0/cli-reference/329620/config-firewall-local-in-policy6), [phase1](https://docs.fortinet.com/document/fortigate/7.2.0/cli-reference/365620/config-vpn-ipsec-phase1), [phase2-interface](https://docs.fortinet.com/document/fortigate/7.2.2/cli-reference/372620/config-vpn-ipsec-phase2-interface). |
| CS-FGT-SYSLOG | *FortiOS 7.6.0 CLI Reference — config log syslogd filter* | per-destination severity and event-family filters | <https://docs.fortinet.com/document/fortigate/7.6.0/cli-reference/273422104/config-log-syslogd-filter> | Retrieved. Qualifies explicit filter fields for the 7.6 command family. |
| CS-JUN | *Day One: Hardening Junos Devices, 2nd Edition* (2015) | management access, logging, banners, routing authentication and certificates | <https://www.juniper.net/assets/us/en/local/pdf/books/tw-hardening-junos-devices-checklist.pdf> | Retrieved. Still useful for control presence, but its SHA-1 password-storage recommendation is obsolete and expressly rejected. It is not an algorithm baseline. |
| CS-JUN-LOG | *System Logging Overview* and current Junos CLI reference | remote hosts, facility/severity selectors and message routing | <https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/system-logging.html> | Retrieved. Qualifies explicit modern syslog selector semantics. |
| CS-SRX | *Security Policies User Guide — Security Policy Configuration*, current Junos documentation | SRX policy construction, address/application matching and omitted-application behavior | <https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html> | Retrieved. Applicable only when the fixture exposes explicit SRX policy state; controller inheritance and installation remain unknown. |
| CS-SRX-VPN | *IPsec VPN Configuration Overview* and current IKE/IPsec proposal reference; RFC 8247 | VPN-to-gateway/policy/proposal relationships and explicit algorithm fields | <https://www.juniper.net/documentation/us/en/software/junos/vpn-ipsec/topics/topic-map/security-ipsec-vpn-configuration-overview.html> | Retrieved. Qualifies static attached reference chains and an explicit legacy-algorithm subset. Built-in proposal-set contents and live negotiated SAs are not inferred. Companion references: [proposal statement](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-proposal.html), [RFC 8247](https://www.rfc-editor.org/rfc/rfc8247.html). |
| CS-SCR | *ScreenOS 6.3.0 Documentation* catalogue; *Security Device CLI Reference Guide: IPv4 Command Descriptions*; *Administration*; *Fundamentals*; *User Authentication*; ScreenOS 6.3.0r27 Release Notes | unmatched-policy behavior; console/Telnet, WebUI and named authentication-server timeout/binding commands | <https://www.juniper.net/documentation/product/us/en/screenos/6.3.0/> | Catalogue metadata and official portable archive recovered 2026-09-14. Core manual URLs currently redirect to the archive page, so the bounded semantics were cross-checked against an [archived CLI-reference mirror](https://manualzz.com/doc/21898000/juniper-networks-security-device-cli-reference-guide) and pinned legacy behavior; the official [migration guide](https://www.juniper.net/assets/jp/jp/local/pdf/service-descriptions/9060154-en.pdf) confirms default-deny/default-permit-all behavior and official r27 notes corroborate the corrected WebUI timeout spelling. Qualified only for identified 6.3 exports. NTP-authentication and screen-policy requirements remain unresolved. |
| CS-CP | *Check Point Gateway and Management Hardening Administration Guide* | Gaia hardening, administrator identity and gateway exposure | <https://sc1.checkpoint.com/documents/Check_Point_Gateway_and_Management_Hardening/Content/CP-Hardening/Introduction.htm> | R81.20/R82/R82.10 and 2026 revision identified. FW1 policy exports do not contain Gaia/system posture; those cells remain export-limited. |
| CS-PAN-M | *PAN-OS 12.1 Device > Setup > Management* | minimum password complexity, username inclusion, password reuse and update schedules | <https://origin-docs.paloaltonetworks.com/ngfw/help/12-1/device/device-setup-management> | Retrieved. The selector advertises 12.2, but a direct 12.2 body was not verified. Only explicit fields are qualified; no 12.2/default inference is allowed. |
| CS-PAN-P | *Security Policy Rule Best Practices*, current best-practices guide | session-end logging and log-forwarding profiles | <https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/security-policy-best-practices/deploy-security-policy-best-practices/security-policy-rule-best-practices> | Retrieved. Qualifies explicit rule logging fields. |
| CS-HP | *ArubaOS-Switch 16.11 Access Security Guide* | management access, filtering and layer-2 protection | <https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/ASG/WC/content/home.htm> | Retrieved. Parser applicability remains bounded to documented release families; other defaults are unknown. |
| CS-SON | *SonicOS 7.3 Device Settings Administration Guide* (May 2026) | administration, users, services and certificates | <https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7.3-device_settings/Content/introduction.htm> | Retrieved. Explicit 7.3 evidence is qualified; older-release defaults are not inferred. |
| CS-EOS | *EOS 4.36.2F Security* and *User Security* | management security, AAA, credentials and control-plane functions | <https://www.arista.com/en/um-eos/eos-security> | Retrieved. The former 4.36.2F index/4.36.1F child mismatch is resolved: both pages now identify 4.36.2F. |

Full CIS benchmark text was not available in the verified source set. This project must therefore not introduce CIS control identifiers or claim CIS conformance from this register. Licensed benchmark mapping is a separate human-reviewed activity.

## Matrix-cell qualification

The fixture column identifies the evidence family, not proof that every control is present.

| Platform | `A` / `U` categories covered | Disposition and implementation boundary | Fixture or evidence |
|---|---|---|---|
| Cisco IOS | Routing | `VERIFIED-PARSER-GAP` (`CS-IOS`, GAP-009): assess only explicit routing process/interface evidence. | `../../tests/test_data/regression/cisco_ios/` |
| Cisco IOS | Certificates; Discovery | `VERIFIED-PARSER-GAP` (`CS-IOS`, GAP-013/GAP-010): typed state must precede findings; absent unsupported subtrees remain unknown. | `../../tests/test_data/regression/cisco_ios/` |
| Cisco IOS-XE | Routing | `VERIFIED-PARSER-GAP` (`CS-XE`, GAP-009): assess explicit routing evidence only. | `../../tests/test_data/regression/cisco_iosxe/` |
| Cisco IOS-XE | Certificates; Discovery | `VERIFIED-PARSER-GAP` (`CS-XE`, GAP-013/GAP-010): parser support precedes checks. | `../../tests/test_data/regression/cisco_iosxe/` |
| Cisco ASA | Banners; Routing | `VERIFIED-PARSER-GAP` (`CS-ASA`, GAP-006/GAP-009): explicit configuration only. | `../../tests/test_data/regression/cisco_asa/` |
| Cisco ASA | Discovery | `EXPORT-ABSENT` (`CS-ASA`, GAP-010): current fixtures do not qualify discovery state; absence is unknown. | `../../tests/test_data/regression/cisco_asa/` |
| Cisco PIX | Admin; AAA; Credentials; SNMP; Logging; Time; Banners; Services; Routing; Filtering; Crypto; Certificates; Discovery; Control plane | `DIALECT-UNQUALIFIED` (`CS-PIX`): no representative PIX fixture or parser contract. IOS/ASA similarity is not a substitute. | No PIX fixture; defer until a representative export is supplied. |
| FortiOS | Banners; Routing; Discovery | `RELEASE-REVIEW` (`CS-FGT`, GAP-017/GAP-009/GAP-010): FortiOS 8.0 establishes the controls, but only explicit fields may be assessed in older fixtures. | `../../tests/test_data/regression/fortios/` |
| Junos | Banners; Routing; Certificates; Discovery | `VERIFIED-PARSER-GAP` (`CS-JUN`, `CS-SRX`, GAP-006/GAP-009/GAP-013/GAP-010). The 2015 SHA-1 recommendation is excluded; current crypto policy needs current algorithm sources. | `../../tests/test_data/regression/junos/` |
| ScreenOS | AAA | `RELEASE-REVIEW` (`CS-SCR`, GAP-016 complete): identified 6.3 exports may assess explicit/default timeout values and active administrator, user, policy and dot1x auth-server bindings. Unknown releases, runtime authentication outcome and absent unexported state remain unknown. | `../../tests/test_data/regression/screenos/`; `../../tests/test_screenos_gap016.py` |
| ScreenOS | Routing; Certificates; Control plane | `SOURCE-UNAVAILABLE` (`CS-SCR`, GAP-001/GAP-026): recovered evidence does not qualify routing, certificate or zone-screen/control-plane requirements. Existing explicit checks may remain; new absence or adequacy findings are blocked. | `../../tests/test_data/regression/screenos/` |
| ScreenOS | Discovery | `SOURCE-UNAVAILABLE` plus `EXPORT-ABSENT` (`CS-SCR`, GAP-010): neither source semantics nor fixture coverage is sufficient. | `../../tests/test_data/regression/screenos/` |
| Check Point FW1 | Admin; AAA; Credentials; SNMP; Time; Banners; Services; Routing; Crypto; Certificates; Discovery; Control plane | `EXPORT-ABSENT` (`CS-CP`, GAP-024): a policy export cannot prove Gaia/system configuration. Require a separate Gaia/system export with provenance. | `../../tests/test_data/regression/checkpoint_fw1/` |
| PAN-OS | Banners; Routing; Discovery; Control plane | `RELEASE-REVIEW` (`CS-PAN-M`, GAP-017/GAP-009/GAP-010/GAP-026): current source qualifies explicit fields, not absence under Panorama or unverified release defaults. | `../../tests/test_data/regression/panos/` |
| HP ProCurve / ArubaOS-S | Banners; Routing; Filtering; Certificates; Discovery; Control plane | `RELEASE-REVIEW` (`CS-HP`, GAP-017/GAP-009/GAP-011/GAP-013/GAP-010/GAP-026): assess explicit supported-family syntax; unknown products/releases remain unknown. | `../../tests/test_data/regression/hp_procurve/` |
| SonicOS | AAA; Credentials; Banners; Routing; Certificates; Control plane | `RELEASE-REVIEW` (`CS-SON`, GAP-017/GAP-009/GAP-013/GAP-026): 7.3 evidence is verified; do not infer older defaults. | `../../tests/test_data/regression/sonicos/` |
| SonicOS | Discovery | `EXPORT-ABSENT` (`CS-SON`, GAP-010): fixture/export support does not establish authoritative discovery state. | `../../tests/test_data/regression/sonicos/` |
| Arista EOS | Banners; Routing; Certificates; Discovery; Control plane | `VERIFIED-PARSER-GAP` (`CS-EOS`, GAP-017/GAP-009/GAP-013/GAP-010/GAP-026): index and child security pages agree on 4.36.2F. | `../../tests/test_data/regression/arista_eos/` |

## Human-reserved decisions

These items are deliberately not converted into detector constants:

1. Organization-specific minimum password-history counts, password ages and content-update intervals. Vendor examples are not universal audit thresholds.
2. Licensed CIS benchmark identifiers and profile applicability.
3. Whether older FortiOS, PAN-OS, SonicOS and ArubaOS-S releases may inherit any documented newer-release default.
4. Which ScreenOS sources, syntax and policy thresholds qualify authenticated NTP, zone screens, routing and certificate checks beyond the completed 6.3 session/default-policy subset.
5. Which Gaia export format is required alongside Check Point policy packages for system-posture auditing.

Until those decisions are approved, detectors may report explicit disablement or explicit insecure values supported by the sources above, but must preserve absent, inherited, unsupported and unexpanded state as unknown.
