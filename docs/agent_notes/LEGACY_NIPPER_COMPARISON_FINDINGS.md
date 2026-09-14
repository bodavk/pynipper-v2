# Legacy nipper comparison findings

Audit date: 2026-09-11. The authoritative comparison is Kali's package source, accessed through GitLab API/archive/raw content without running Git. Only the three requested Markdown documents are produced.

## Provenance and substantive tree differences

- Project: [kalilinux/packages/nipper-ng](https://gitlab.com/kalilinux/packages/nipper-ng), GitLab project 11903913, default branch kali/master.
- Examined revision: [9e802e9217185813e73eba39e61d459365d758d0](https://gitlab.com/kalilinux/packages/nipper-ng/-/commit/9e802e9217185813e73eba39e61d459365d758d0), committed2025-12-10T07:45:37Z.
- Package version: [debian/changelog](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/debian/changelog), **0.11.10-1kali3**, dated 10 December 2025. Access2026-09-10–11.
- [Makefile](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/Makefile) builds the C implementation rooted at nipper.c. It does **not** build the repository's local libnipper 0.12.6 reference.
- The archive and local [0.11.10 tree](../../reference/nipper-ng-original/0.11.10/README) have 200 common files, all identical after CRLF/LF normalization. They are not raw-byte identical because of line endings. Kali adds 14 packaging files. The inspected [GCC15 signal-handler patch](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/debian/patches/Fix-signature-for-stdinTimeout.patch) changes stdinTimeout's signature to accept an int signal argument; it does not add audit capabilities.
- The separate local [libnipper 0.12.6](../../reference/nipper-ng-original/libnipper-0.12.6/libnipper.cpp) is materially different C++ library code. Its factory, filter engine and TODO were checked independently. Local-only features are explicitly labeled below.

Pinned Kali paths below are exact archive paths. Equivalent local 0.11.10 files were used for detailed reading after content comparison established identity modulo line endings. Archive inspection stayed in memory; no downloaded reference tree was added to the workspace. This audit verifies reachable source paths, not successful builds/execution of historical binaries.

## Complete device/dialect dispatch comparison

Evidence: [CLI parser](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-cmdoptions.c) and [main input/report dispatch](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/nipper.c), compared with [current registry](../../src/devices/registry.py). A shared handler is not an independent dialect certification.

| Kali CLI device family | Reachable legacy implementation | Current counterpart | Assessment |
|---|---|---|---|
| IOS router | IOS/process.c + IOS/report.c | IOS_ROUTER | Shared IOS pipeline; depth differs. |
| IOS switch | IOS/process.c + IOS/report.c | IOS_SWITCH | Role option rather than separate parser. |
| IOS Catalyst | IOS/process.c + IOS/report.c | IOS_CATALYST | Shared IOS pipeline; switch controls incomplete. |
| PIX firewall | PIX/process.c + PIX/report.c | PIX → ASA parser/analyzer | Registered; historical syntax coverage not separately established. |
| ASA firewall | PIX/process.c + PIX/report.c | ASA | Modern ASA-family baseline; legacy branch behavior is not inherited. |
| FWSM firewall | PIX/process.c + PIX/report.c | None | Missing dialect with device-specific branches. |
| Catalyst CatOS | NMP/process.c + NMP/report.c | None | Missing old switch grammar. |
| Catalyst NMP | NMP/process.c + NMP/report.c | None | Shares legacy engine with CatOS, not another complete engine. |
| Cisco CSS | CSS/process.c + CSS/report.c | None | Missing grammar. |
| Juniper ScreenOS | ScreenOS/process.c + ScreenOS/report.c | SCREENOS | Present, different checks/effective-state handling. |
| Nortel Passport | Passport/process.c + Passport/report.c | None | Missing filter-oriented grammar. |
| Bay Networks Accelar | Passport/process.c + Passport/report.c | None | Passport-family alias/branch, not independent broad analysis. |
| SonicWall SonicOS | SonicOS/process.c + SonicOS/report.c | SONICOS | Old export versus current7.x custom E-CLI: not interchangeable. |
| Check Point FW1 | FW1/process.c + FW1/report.c | CHECKPOINT_FW1 | Offline policy/object overlap; current has added hygiene depth. |
| Nokia IP | FW1/process.c + FW1/report.c | No Nokia name | Legacy dispatch analyzes FW1 policy data; do not infer full IPSO OS support. |

Kali exposes 15 selections, with substantial shared processing. Current 14 canonical IDs share 11 pipelines. Current IOS_XE, FORTIOS, JUNOS, PAN_OS, HP_PROCURVE and ARISTA_EOS have no direct Kali 0.11.10 counterparts. Raw selection counts therefore misrepresent both breadth and depth.

The local 0.12.6 factory reaches CSS, CatOS, NMP, ASA, FWSM, PIX, IOS Catalyst/router, ScreenOS, Check Point firewall/management, Nokia IP, Passport, Nortel RoutingSwitch, Accelar, HP ProCurve, SonicOS and3Com SuperStack3 Firewall. Check Point firewall/management are separate library device roles. NortelRoutingSwitch inherits Passport;3Com firewall inherits SonicOS. The latter is specifically a **firewall**, not generic3Com switch support. Template-Device and TODO platform names are excluded.

## Source-verified security category breadth

The legacy column below counts conditional security issue registration and called analysis, not configuration-report table titles. Current controls and exact rule IDs are fully listed in [the standards appendix](STANDARDS_BLINDSPOT_FINDINGS.md#appendix-a--source-inventory-and-interpretation).

| Overlap | Reachable Kali security breadth | Current breadth and important limits |
|---|---|---|
| IOS three selections | [IOS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/report.c): credential dictionary/strength/storage; AAA/lines/AUX/HTTP/SSH; SNMP; ACL hygiene; logging; extra legacy services; interface redirects/proxyARP/uRPF; routing auth; CDP; trunk/port security; banner; selected old software/config defaults. | Adds bounded NTP auth/CoPP/crypto baseline; lacks routing trust/discovery/switchport pack and structural value engine. IOS-XE adds modern MACsec/IKEv2 absent from legacy. |
| PIX/ASA (FWSM shares old engine) | [PIX/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/PIX/report.c): software table, dictionary/strength, SSH timeout/version/management, SNMP, ACL hygiene, floodguard and uRPF. | Adds management AAA/accounting, HTTP trustpoint/source, NTP, TLS, IKE/IPsec, failover key and threat detection. Remaining SSH/session/value-strength gaps; old PIX/FWSM syntax not proven by ASA parser. |
| ScreenOS | [ScreenOS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/ScreenOS/report.c): dictionary/strength, SNMP, default-allow/no-policy and shared ACL hygiene, auth timeouts, HTTP redirect, manager source and SSHv1. | Adds effective management exposure, retries, banner, syslog/NTP presence, referenced VPN algorithms, policy logging and EOL. GAP-016 restores release-gated ScreenOS 6.3 explicit default-policy and distinct active admin/user/auth-server timeout depth. Structural credential values, authenticated NTP and screens/DoS remain outside this claim. |
| FW1 / Nokia policy input | [FW1/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/FW1/report.c), common/nipper-acl.c: policy hygiene; rich object/service tables are report content. | Current adds layer-aware cleanup/stealth, disabled/expired rules, install scope/negation/risky services, references, bounded redundancy/shadowing. Modern fork is deeper in several policy categories; neither input proves Gaia OS hardening. |
| SonicOS | [SonicOS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/SonicOS/report.c): shared access-rule analysis; general/service tables are configuration content. | Current7.x adds interface management, rule logging, VPN suites, SNMP, logging/NTP auth and security-service dependencies. Legacy is not a broader administrator auditor simply because it prints services. |

Nonoverlapping legacy engines were also checked: [NMP/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/NMP/report.c) registers dictionary/strength, timeout, redirects, CDP and ICMP-unreachable findings; [CSS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/CSS/report.c) SNMP, Telnet, ACL hygiene/disabled ACLs; [Passport/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/Passport/report.c) filter hygiene. Their printed VLAN/port/SNMP/services tables are not all security checks. No standards rule for an unsupported platform is imported solely from this historical code.

## Findings

<a id="LEG-001"></a>
### Device parity — Missing legacy dialects are not a raw device-count target

**Finding ID:** LEG-001

**Source:** gitlab.com/kalilinux/packages/nipper-ng, pinned revision above: [common/nipper-cmdoptions.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-cmdoptions.c); [nipper.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/nipper.c); [NMP/process.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/NMP/process.c); [CSS/process.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/CSS/process.c); [Passport/process.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/Passport/process.c); [PIX/process.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/PIX/process.c).

**What the original tool does:** CLI-selected CatOS/NMP, CSS, FWSM and Passport/Accelar reach actual processors and reports. Nokia IP maps to FW1 policy processing; it is not an independent complete IPSO audit. See the complete dispatch table.

**What pynipper-v2 currently does:** Registry lacks CatOS/NMP/CSS/FWSM/Passport/Accelar/Nokia names; PIX is registered through ASA. Current 14 IDs share 11 pipelines and add several modern OS families.

**Assessed value:** Low priority compared with current-platform depth. GAP-023 requires sample exports, user demand and ongoing maintenance justification. Do not add aliases as evidence of dialect support.

<a id="LEG-002"></a>
### Device parity — SonicOS and PIX registration conceals export differences

**Finding ID:** LEG-002

**Source:** gitlab.com/kalilinux/packages/nipper-ng, pinned revision above: [SonicOS/process.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/SonicOS/process.c); [PIX/process.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/PIX/process.c); [common/nipper-cmdoptions.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-cmdoptions.c).

**What the original tool does:** Older SonicOS preference-style exports and historical PIX syntax are processed in the legacy trees; PIX family processing branches on device/version. It does not support the fork's new SonicOS7 custom E-CLI grammar by implication.

**What pynipper-v2 currently does:** SonicOS parser explicitly requires SonicOS7 custom E-CLI; PIX shares current ASA parsing. The regression corpus has ASA examples but no separate PIX family corpus establishing old grammar coverage.

**Assessed value:** A compatibility boundary worth documenting now; new adapters later only with real fixtures. Broad support labels are not a reason to feed old preferences through the7.x parser. GAP-023.

<a id="LEG-003"></a>
### Check-category breadth — IOS has useful missing administrative, routing and switch controls

**Finding ID:** LEG-003

**Source:** gitlab.com/kalilinux/packages/nipper-ng, pinned revision above: [IOS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/report.c); [IOS/process-router.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/process-router.c); [IOS/process-interface.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/process-interface.c); [IOS/process-line.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/process-line.c); [IOS/report-router.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/report-router.c).

**What the original tool does:** Reachable security sections cover AUX/line timeouts and keepalives, routing authentication, CDP, port/trunk security and extra interface/services controls, alongside credentials/AAA/SNMP/ACLs. Configuration-only route/NAT tables are distinct from those security sections.

**What pynipper-v2 currently does:** IOS/XE baseline handles AAA, HTTP/SSH, weak credential storage, legacy communities, remote logging, authenticated NTP, banner, selected services, redirects/proxyARP, CoPP attachment and legacy crypto; XE adds MACsec. It now also resolves classic BGP peer-group authentication and per-AF/VRF policy/prefix-limit state plus explicit-interface OSPFv2 authentication. Discovery and switch-edge depth remain open (STD-003/010/011), while EIGRP/RIP and advanced routing inheritance remain bounded future work under STD-002.

**Assessed value:** High value where corroborated by current Cisco guidance: routing trust, scoped discovery, sessions and switch edges. Do not port BGP damping, IP classless or obsolete service recommendations mechanically. GAP-006/009/010/011.

<a id="LEG-004"></a>
### Check-category breadth — PIX/ASA and ScreenOS have narrower remaining depth gaps

**Finding ID:** LEG-004

**Source:** gitlab.com/kalilinux/packages/nipper-ng, pinned revision above: [PIX/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/PIX/report.c); [PIX/process-ssh.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/PIX/process-ssh.c); [ScreenOS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/ScreenOS/report.c); [ScreenOS/process.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/ScreenOS/process.c).

**What the original tool does:** PIX reports SSH version and configurable excessive session timeout as security findings, plus credentials/SNMP/ACL/uRPF/floodguard. ScreenOS reports auth-session/server timeout and default-allow/no-policy conditions, plus credential, SNMP, manager source and SSH issues.

**What pynipper-v2 currently does:** ASA has modern TLS/VPN/AAA/NTP additions but no SSH session/version pack. ScreenOS 6.3 now has typed explicit default-policy and distinct active console/Telnet, WebUI, administrator and policy/user authentication-server timeout analysis, in addition to retries, banner, logging and VPN checks. No claim legacy is uniformly deeper.

**Assessed value:** GAP-006 and the bounded GAP-016 subset are implemented. Remaining ScreenOS authenticated-time and screen/DoS depth still depends on recovered source and representative syntax. Do not treat HTTP redirect recommendation as a substitute for disabling HTTP.

<a id="LEG-005"></a>
### Feature — Structural credential auditing and John export

**Finding ID:** LEG-005

**Source:** gitlab.com/kalilinux/packages/nipper-ng, pinned revision above: [common/nipper-common.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-common.c); [common/nipper-cmdoptions.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-cmdoptions.c); [IOS/process-username.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/process-username.c); [IOS/process-enable.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/process-enable.c); [IOS/process-line.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/process-line.c); [nipper.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/nipper.c).

**What the original tool does:** simplePassword checks exact built-in/external dictionary entries; passwordStrength checks configurable length and character classes. Type7 reversal supplies plaintext to strength checks. IOS type5 hashes enter addJohnPassword; main writes username:hash lines when --john is requested. This is export integration, not execution of John or recovered passwords. Other secret contexts call the shared helpers, as listed below.

**What pynipper-v2 currently does:** Storage-format checks and some password-policy flags exist, but no shared configurable value-strength/dictionary engine, reversible-value analysis or explicit cracking-tool export. ASA/ScreenOS literal/default fingerprint lists are narrower than arbitrary structural checks.

**Assessed value:** High value for safe offline strength/storage analysis; later opt-in export for authorized credential assessment. Hashes cannot reveal plaintext length. Do not copy historical composition policy as a universal modern standard or put recovered secrets in reports. GAP-003/018/019; STD-005.

<a id="LEG-006"></a>
### Feature — Shared ACL hygiene breadth across platforms

**Finding ID:** LEG-006

**Source:** gitlab.com/kalilinux/packages/nipper-ng, pinned revision above: [common/nipper-acl.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-acl.c); [common/nipper-cmdoptions.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-cmdoptions.c); [IOS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/report.c); [PIX/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/PIX/report.c); [ScreenOS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/ScreenOS/report.c); [FW1/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/FW1/report.c); [SonicOS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/SonicOS/report.c).

**What the original tool does:** rulesAudit evaluates rule dimensions such as Any/network sources/destinations, service ranges, disabled entries, logging and terminal deny behavior, gated by device capabilities/options. Group handling feeds those predicates. The C function does not implement pairwise semantic shadow/redundancy or runtime usage counters.

**What pynipper-v2 currently does:** Several plugins recognize broad permits; FW1 adds disabled/expired/risky services/install scope/logging/cleanup and bounded redundancy/shadowing. Other platforms lack much of that shared depth. Some parsers only retain names or simple strings.

**Assessed value:** High reuse but substantial semantic prerequisites: extend native evidence before a shared engine. GAP-004/020. Do not label every partial overlap as a shadow or disabled rules as unused traffic. STD-019.

<a id="LEG-007"></a>
### Feature — Deeper static overlap analysis exists only in local libnipper 0.12.6

**Finding ID:** LEG-007

**Source:** Local-reference-only libnipper 0.12.6; not present in Kali 0.11.10: [device/filter/filter-security.cpp](../../reference/nipper-ng-original/libnipper-0.12.6/device/filter/filter-security.cpp); [device/filter/filter-security-report.cpp](../../reference/nipper-ng-original/libnipper-0.12.6/device/filter/filter-security-report.cpp); [device/reportgen/report.cpp](../../reference/nipper-ng-original/libnipper-0.12.6/device/reportgen/report.cpp); [libnipper.cpp](../../reference/nipper-ng-original/libnipper-0.12.6/libnipper.cpp).

**What the original tool does:** The local newer library's reachable Filter::generateSecurityReport compares protocol/zone/host/port overlaps and records duplicate/contradictory rules; it marks entries after a catch-all deny with the appropriate conditions. Report generation calls the filter analysis when present. This code is absent from the pinned Kali C archive. Its overlap logic is not a proof of complete modern policy semantics.

**What pynipper-v2 currently does:** FW1's same-layer name-set containment is a real implemented subset; other platform checks are predominantly per-rule. No shared semantic network/port containment engine or static post-terminal unreachable-rule facility across platforms.

**Assessed value:** Useful design evidence for GAP-020, explicitly not a Kali capability claim. Define stronger correctness criteria than copying old overlap heuristics. Runtime-unused rules remain the opt-in track, GAP-025.

<a id="LEG-008"></a>
### Feature — Configurable audit policy and contextual scoping

**Finding ID:** LEG-008

**Source:** gitlab.com/kalilinux/packages/nipper-ng, pinned revision above: [common/nipper-cmdoptions.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-cmdoptions.c); [common/nipper-acl.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-acl.c); [common/nipper-config.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-config.c).

**What the original tool does:** Supports credential thresholds/dictionary, connection timeout and ACL check toggles, edge/internal device use and model override. Report expansion/selection controls affect presentation. No arbitrary target-CIDR or general selected-config-section analysis option was found in the command parser; remote cisco-ip selects acquisition, not audit CIDR scope.

**What pynipper-v2 currently does:** main.py chooses device/input/output/config/offline. No typed per-scan audit policy, explicit role override, scoped selection or report-section policy. Some plugins infer trust roles from interface/zone names.

**Assessed value:** A bounded policy/context interface is useful to reduce hard-coded assumptions; retain deterministic defaults and expose active policy in report. Arbitrary CIDR targeting is a new proposal requiring user value/semantics research, not restored parity. GAP-021.

<a id="LEG-009"></a>
### Feature — Configuration inventories and explanatory report content

**Finding ID:** LEG-009

**Source:** gitlab.com/kalilinux/packages/nipper-ng, pinned revision above: [IOS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/IOS/report.c); [ScreenOS/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/ScreenOS/report.c); [FW1/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/FW1/report.c); [common/nipper-report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-report.c); [common/nipper-cmdoptions.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-cmdoptions.c).

**What the original tool does:** Registers configuration sections for interfaces, users, services, ACLs/objects and, by platform, routing/NAT/AAA/SNMP/time. Appendices include glossary/abbreviations, common ports, logging levels, timezone and tool version; report section controls exist. Tables showing settings are not additional security checks.

**What pynipper-v2 currently does:** HTML/JSON include metadata, scope prose, findings, remediation/exploitability/evidence/references and optional advisories. No complete sanitized configuration inventory, coverage ledger or selective explanatory appendix content. Executive summary is not established as a functioning legacy feature.

**Assessed value:** Useful medium-priority report content, independent of output format. Prefer decision-relevant inventories/coverage and concise remediation summary over static encyclopedia appendices. Local TODO explicitly asks about an executive summary, so it must not be counted as implemented parity. GAP-022, STD-026.

<a id="LEG-010"></a>
### Feature — Remote acquisition and historical vulnerability data

**Finding ID:** LEG-010

**Source:** gitlab.com/kalilinux/packages/nipper-ng, pinned revision above: [common/nipper-snmp.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-snmp.c); [common/nipper-cmdoptions.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/common/nipper-cmdoptions.c); [nipper.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/nipper.c); [PIX/report.c](https://gitlab.com/kalilinux/packages/nipper-ng/-/blob/9e802e9217185813e73eba39e61d459365d758d0/PIX/report.c).

**What the original tool does:** Non-Windows conditional CLI supports Cisco SNMP read/write and TFTP configuration acquisition. Legacy reports also contain fixed software vulnerability tables. Acquisition can change device transfer state; static historical tables are not a current vulnerability service.

**What pynipper-v2 currently does:** The fork analyzes supplied files, with optional IOS Cisco advisory API. Other analyzer advisory arrays do not implement live vendor feeds. No SNMP/TFTP collector is exposed.

**Assessed value:** Separate opt-in expansion track only. Modern authenticated offline-import/acquisition design and feed freshness require research. Do not restore insecure collection for parity or claim live-state findings from configs. GAP-025; fixed legacy advisory thresholds are not modern policy.

<a id="LEG-011"></a>
### Feature — Templates, aliases and TODOs must not inflate capability claims

**Finding ID:** LEG-011

**Source:** Local-reference-only libnipper 0.12.6; not present in Kali 0.11.10: [libnipper.cpp](../../reference/nipper-ng-original/libnipper-0.12.6/libnipper.cpp); [Template-Device/device.cpp](../../reference/nipper-ng-original/libnipper-0.12.6/Template-Device/device.cpp); [3Com-SuperStack3-Firewall/device.h](../../reference/nipper-ng-original/libnipper-0.12.6/3Com-SuperStack3-Firewall/device.h); [Nortel-RoutingSwitch/device.h](../../reference/nipper-ng-original/libnipper-0.12.6/Nortel-RoutingSwitch/device.h); [TODO](../../reference/nipper-ng-original/libnipper-0.12.6/TODO).

**What the original tool does:** Local factory instantiates HPProCurve, ThreeComSuperStackFW and NortelRoutingSwitch;3Com inherits SonicOS and NortelRoutingSwitch inherits Passport. These are reachable aliases/adapters, not proof of independent full dialect depth. Template-Device is not a registered supported platform. TODO lists unimplemented features, including executive summary, shared-password analysis, configuration diffs, several exports and future platforms.

**What pynipper-v2 currently does:** HP/AOS-S is independently implemented now;3Com/NortelRoutingSwitch absent. The fork also lacks some TODO proposals, but absence of a proposal is not a lost implemented capability.

**Assessed value:** GAP-023 may investigate local-only dialect value; GAP-001 records unresolved applicability. Do not create mandatory parity tasks for templates, declarations or TODO text. No code port is required to adopt a verified concept.

## Credential and ACL evidence details

The concrete IOS credential path is process-username.c: type7 is reversed, type5 remains unknown plaintext and is offered to addJohnPassword, type0 is plaintext; only available nonempty plaintext proceeds to simplePassword/passwordStrength. Similar calls occur in process-enable.c, process-line.c, process-aaa.c, process-tacacs.c, process-ntp.c, process-keychain.c, process-ftp.c, process-router.c and process-interface.c. This establishes shared-secret contexts beyond login passwords. It does not establish support for modern hash formats or successful cracking.

Kali common/nipper-acl.c:rulesAudit performs single-rule breadth/logging/disabled/final-rule checks, adjusted for device capabilities. The newer local device/filter/filter-security.cpp implements pairwise host/port/protocol comparisons and post-terminal bookkeeping, and device/reportgen/report.cpp calls it. That implementation is reachable library behavior, while Template-Device prose and TODO items are not. Neither inspected implementation consumes per-rule traffic hit history to prove runtime disuse.

Unused objects or disabled rules, unreferenced ACLs, syntactically unreachable rules and zero-hit rules are four different assertions. A future report must name the assertion it can prove. A rule can be redundant in static semantics yet have historical hits; a zero-hit rule may protect rare necessary traffic.

## Prioritization and validation

Standards plus implemented legacy evidence independently corroborate IOS routing/session/discovery/switch depth, ASA sessions, structural credentials and useful ACL hygiene. AAA transport is a standards/source gap, but no verified legacy AAA-transport detector was found; it is not double-corroborated. Certificate validity and live hit counts also must not be credited to legacy report labels.

All 11 LEG anchors have remediation links. GAP-023 covers missing dialects only after fixture/value gates; GAP-025 is the optional operational track. No task restores a TODO feature merely for parity. Current source evidence, stable findings and future tests take priority over preserving old algorithms or severity values.

