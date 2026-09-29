# High-risk configuration coverage: implementation backlog

Reviewed **2026-09-22** against the current source, after the recent parser and detection upgrades. This is the authoritative security-coverage backlog; it replaces the overlapping broad detection bullets in [TODO](../TODO.md). It specifies future implementation, not changes made during this review. No Git commands were used. Existing detection defects and external samples remain in [real-world findings](REALWORLD_VALIDATION_FINDINGS.md); completed remediation is reconciled in [validation tasks](REALWORLD_VALIDATION_TASKS.md).

Backlog extended **2026-09-26** following a new source review and targeted synthetic probes. This update schedules work only; it does not mark the new stages implemented. The current queue below overrides historical wave ordering for remaining work.

## Scope and execution contract

There are **16 registered IDs and 13 parser/analyzer pipelines**, including F5 BIG-IP and Check Point Gaia OS (added 2026-09-25). IOS aliases share one implementation; PIX shares ASA code but does not thereby have independently verified dialect coverage. Source authority is [registry](../../src/devices/registry.py), not historical roadmap claims.

Priorities are implementation priorities: **P1** closes a high-impact exposure or an important prerequisite; **P2** covers selected medium risks or evidence qualification; **P3** is lower direct security relevance or workflow convenience. DISA High/CAT I and Medium/CAT II are source severities, not this project's priority scale. CIS Level 1/2 describes profiles, not vulnerability severity. Do not manufacture a Critical rating because a source has no such rating. Final finding severity depends on the proven unsafe state and exposure.

Selected medium issues matter because they commonly weaken administrative authentication, log integrity, routing trust, or access-edge isolation. No multi-stage attack scoring engine is requested. Low-value cosmetic controls, blanket benchmark parity, live scanning, password cracking, and speculative new platforms are outside this backlog.

Every task uses the fields below. A task marked **Evidence gate** starts with the stated research/fixture deliverable; it does not authorize speculative detections. A ready task may still require release-specific syntax qualification before absence/default assertions. Follow [Architecture](../ARCHITECTURE.md), [Extending](../EXTENDING.md), [Assessment policy](../ASSESSMENT_POLICY.md), and [Supported devices](../SUPPORTED_DEVICES.md). These guides require separate approval for organization-specific thresholds or unverified benchmark mappings: build explicit-state detection first, and leave those profile decisions as prerequisites for the future implementing agent.

Mandatory implementation rules, incorporated into **every** task:

- Parsers resolve effective order, negation, inheritance, scope, references and bindings; plugins consume typed records and do not reopen files. Prefer a vendor record unless a shared concept is genuinely needed. Explicitly register any new plugin.
- Preserve `KNOWN`, `UNKNOWN`, `UNSUPPORTED`, and `PARSE_ERROR`; distinguish configured, enabled, bound, and operational. Missing data, unmerged controller state and unsupported predicates cannot establish safety or a missing control. Release-gate defaults. Use explicit assessment roles, never an interface/profile name as proof of trust.
- Keep stable existing rule IDs. Add distinct IDs only for distinct unsafe states, with sanitized source/line evidence and authoritative references. Existing JSON/HTML finding and coverage interfaces are sufficient unless a task explicitly states otherwise. Add no default network calls.
- **Mandatory tests:** unsafe positive, secure negative, override/removal/inheritance, malformed and unknown, inactive/unbound, assessment/export scope, secret redaction, and installed public CLI JSON/HTML. Test the meaningful combinations for the feature; explicitly justify genuinely inapplicable cases. Include adversarial fixtures that defeat presence-only checks.
- After implementation run `.\.venv\Scripts\python.exe scripts\run_full_regression.py` from the repository root. Review intentional snapshot changes; never regenerate expectations to hide a regression. Each task's acceptance criteria include this gate.

## Current execution priorities — 2026-09-26

This queue prioritizes **remaining work**, not already completed stages. P1 = priority security work (administrative compromise, authentication bypass, route injection, or false assurance about those controls); P2 = medium/deployment-specific hardening or assessment assurance; P3 = lower security relevance/auditor convenience. Evidence/fixture gates still apply. Preserve stable task IDs even when execution order changes. Existing P1 SC-003/008/009/013/014/015/025/031/034/035/039/041 stages remain priority wherever genuinely unfinished and evidence-ready.

| Priority | Remaining work and rationale |
|---|---|
| **P1 — direct high-impact configuration risks** | [SC-046](#sc-046) effective management ACLs; [SC-026](#sc-026) unsafe management APIs; [SC-011](#sc-011) privileged API identities; [SC-047](#sc-047) SRX host-inbound administration; [SC-013](#sc-013) VPN authentication and exposed legacy VPN; [SC-005](#sc-005) explicit RIPv1/IS-IS trust; [SC-043](#sc-043) accurate risky-service permissions. These can enable administrative access, credential exposure, route manipulation or sensitive-service access. |
| **P1 — offline operating requirement** | [SC-045](#sc-045): eliminate implicit outbound advisory requests from ordinary audits. This is a data-handling/product requirement, not a device misconfiguration or Critical vulnerability. |
| **P2 — deployment-dependent security depth** | [SC-048](#sc-048) IPv6 access-edge/dual-stack controls; multicast and additional address families in [SC-005](#sc-005); DNS in [SC-026](#sc-026). Promote an affected deployment stage to P1 when supplied scope proves an untrusted control-plane or management bypass. Do not prioritize unused protocols. |
| **P2 — assurance** | [SC-049](#sc-049) per-control coverage and manual-review inventory, after direct high-risk misses; this reduces false assurance without adding a device vulnerability. |
| **P3 — lower direct security relevance** | [SC-050](#sc-050) batch manifests and offline comparisons. Improve auditor efficiency after ready P1/P2 detection work. |

The 2026-09-26 review proposals were merged as follows: A3/A10 into SC-026; A4 into SC-011; A6 into SC-013; A7/A9 into SC-005; A11 into SC-043. New A1/A2/A5/A8/A12/A13 work is SC-045/046/047/048/049/050 respectively. No duplicate A-series implementation backlog exists. All existing completed scope remains recorded. **SC-044 insecure defaults is unchanged and remains separately owned.**

Offline boundary for every task: consume only supplied configuration/backup/companion artifacts and approved local datasets. No device connection, active probe, DNS lookup, live certificate revocation fetch or automated remote-file retrieval. Historical PT-010/SC-022 data-acquisition work must be separated from the audit path through SC-045; source research by developers is not an audit runtime feature.

## Standards and release applicability

The original standards catalog below was accessed **2026-09-22**; sources in the explicitly dated extensions were reviewed **2026-09-26**. STIG Viewer is the user-requested mirror of DISA text; vendor command documentation determines parser grammar. Catalog version is not an OS version. Some date-addressed STIG pages render newer revisions; record the displayed revision and rule ID when implementing. Catalog currency below was checked against the [STIG catalog](https://www.stigviewer.com/stigs); this is not a certification or an exhaustive control-by-control compliance claim.

| Family | Published benchmark identified | Applicability to this tool |
|---|---|---|
| IOS router/switch | Router NDM V3R8, switch NDM V3R8; router RTR V3R4; switch L2 V3R2; switch RTR V3R3 | IOS roles differ; qualify each command/default to exported release. Do not apply L2 endpoint controls to router WAN links. |
| IOS-XE | Router NDM V3R7, router RTR V3R5; switch NDM V3R6, switch L2 V3R2, switch RTR V3R4 | Shared IOS implementation is not proof of identical defaults. Role and release qualification required. |
| ASA / PIX | ASA FW V2R1, NDM V2R5, VPN V2R2 | ASA role-specific controls. Modern ASA benchmarks do not establish PIX 6.x behavior. |
| FortiOS | FortiGate NDM V1R5 and Firewall V1R4, 2025-11-19; CIS FortiOS 7.4.x v1.0.1, 7.0.x v1.4.0 | Qualify actual FortiOS release, VDOM and feature availability. [Official CIS listing](https://www.cisecurity.org/benchmark/fortinet). |
| Junos | SRX NDM V3R3, ALG V3R3, VPN V3R2, IDPS V2R1; EX NDM V2R5, RTR V2R1 | SRX security processing does not apply to EX merely because both use Junos. Current CIS archive/status not confirmed: `NEEDS_RESEARCH`. |
| ScreenOS | No current ScreenOS-specific benchmark confirmed | Legacy vendor 6.2/6.3 evidence is required; SRX STIGs are intent crosswalks only. Lifecycle warning already exists. |
| Check Point FW1 | CIS Check Point Firewall v1.1.0 covered R75–R80 Gaia; historical v1.0 covered NGX/R65 SecurePlatform | Existing objects.C/rules.C input is policy-only. [CIS release notice](https://www.cisecurity.org/insights/blog/cis-benchmarks-june-2020-update). Current publication/archive status `NEEDS_RESEARCH`; neither benchmark establishes Gaia evidence in a policy export. |
| PAN-OS | NDM V3R3, ALG V3R4, IDPS V3R2; CIS PAN-OS 11 v1.2.0 and PAN-OS 10 v1.3.0 | Local XML supported; incomplete Panorama inheritance remains unknown. [CIS catalog](https://www.cisecurity.org/cis-benchmarks). |
| HP_PROCURVE | No exact current AOS-S benchmark confirmed; CIS Aruba CX v1.0.0 is a different OS | Existing AOS-S 16.10/16.11 grammar only. [CIS CX announcement](https://www.cisecurity.org/insights/blog/cis-benchmarks-august-2026-update) must not be used as AOS-S syntax evidence. |
| SonicOS | No exact current SonicOS STIG/CIS benchmark confirmed | SonicOS 7 custom E-CLI only. Generic firewall/IDPS intent plus vendor documentation; old preference exports are unsupported. |
| EOS | Arista MLS EOS 4.x NDM V2R2, 2025-02-20; CIS Arista EOS v1.0.0 announced September 2026 | [Official CIS announcement](https://www.cisecurity.org/insights/blog/cis-benchmarks-september-2026-update). Current full CIS control text not obtained; no invented section numbers. |
| F5 BIG-IP | TMOS NDM V1R2, ALG V1R3; Firewall/VPN/DNS V1R1; CIS F5 Networks v1.0.0 | Current adapter is basic TMOS SCF/tmsh, not UCS/F5OS. LTM, AFM, APM and WAF roles must be separately qualified. |

Full current CIS PDFs were not acquired. Public CIS pages establish publication metadata, not detailed control coverage. CIS-specific requirements or crosswalks requiring those PDFs remain `NEEDS_RESEARCH`; unresolved local applicability remains `NEEDS_HUMAN_REVIEW`. No exact CIS compliance mapping is claimed.

### Control evidence used by tasks

These are specific control references, not instructions to copy example configurations or universal thresholds. Source grades are given only where verified.

| Ref | Control and source | Use / limit |
|---|---|---|
| S01 | [IOS-XE NDM V-215854](https://stigviewer.com/stigs/cisco_ios_xe_router_ndm/2021-03-26/finding/V-215854), High; [V-215832](https://www.stigviewer.com/stigs/cisco_ios_xe_router_ndm/2024-11-25/finding/V-215832), High | Effective centralized AAA and protected stored credentials. Revalidate older AAA rule text against current NDM edition before enforcing exact topology. Credential classification already exists. |
| S02 | [IOS-XE L2 V-220649](https://www.stigviewer.com/stigs/cisco_ios_xe_switch_l2s/2025-05-19/finding/V-220649), High; [V-220656](https://www.stigviewer.com/stigs/cisco_ios_xe_switch_l2s/2025-05-19/finding/V-220656), Medium | Endpoint authentication and BPDU protection on applicable access ports. Other switch families need vendor crosswalk qualification. |
| S03 | [IOS-XE RTR V3R5](https://www.stigviewer.com/stigs/cisco_ios_xe_router_rtr/2025-08-14/MAC-3_Public), V-216645; [zero-touch V-220994](https://www.stigviewer.com/stigs/cisco_ios_xe_switch_rtr/2024-06-06/finding/V-220994), Medium | Routing authentication/key management and deployment-time services on commissioned equipment. Key lifetime requires explicit assessment time and applicable policy. |
| S04 | [ASA VPN V-239968](https://www.stigviewer.com/stigs/cisco_asa_vpn/2024-08-22/finding/V-239968), High; [ASA VPN](https://www.stigviewer.com/stigs/cisco_asa_vpn), V-239957/V-239959 | Remote-access certificate authentication; exact VPN cryptographic policy is deeper than obsolete-algorithm blacklists. Certificate-specific DoD requirement is not a universal equivalence to arbitrary MFA. |
| S05 | [PAN ALG V-228860](https://www.stigviewer.com/stigs/palo_alto_networks_alg/2025-03-12/finding/V-228860), High | Bound zone/DoS protection; documented alternative protection paths matter. |
| S06 | [PAN ALG V-228872](https://www.stigviewer.com/stigs/palo_alto_networks_alg/2025-03-12/finding/V-228872); [V-228861](https://www.stigviewer.com/stigs/palo_alto_networks_alg/2025-03-12/finding/V-228861) | Required threat profile types and blocking policy by threat severity; an attached profile name is insufficient. |
| S07 | [Firewall SRG V-206694](https://www.stigviewer.com/stigs/firewall_security_requirements_guide/2024-12-04/finding/V-206694), High | Default deny. Generic intent; platform-specific implicit policy and legitimate intrazone behavior still require vendor evidence. |
| S08 | [SRX ALG V-214531](https://www.stigviewer.com/stigs/juniper_srx_services_gateway_alg/2024-12-19/finding/V-214531), High; [SRX IDPS V-214612](https://www.stigviewer.com/stigs/juniper_srx_services_gateway_idps/2024-06-10/finding/V-214612), Medium | Bound screens and effective IDP action. SRX-only, not EX. |
| S09 | [FortiGate FW V-234143](https://www.stigviewer.com/stigs/fortinet_fortigate_firewall/2025-11-19/finding/V-234143), High; [NDM V-234216](https://www.stigviewer.com/stigs/fortinet_fortigate_ndm/2025-11-19/finding/V-234216), High | Effective administrative permissions, including log deletion. Authorized roles require explicit policy; runtime execution is not proven by config. |
| S10 | [FortiGate FW V-234141](https://www.stigviewer.com/stigs/fortinet_fortigate_firewall/2025-11-19/finding/V-234141), Medium | Protected remote logging, beyond destination/filter presence. |
| S11 | [EOS V-255949](https://www.stigviewer.com/stigs/arista_mls_eos_4x_ndm/2025-02-20/finding/V-255949); [V-255954](https://www.stigviewer.com/stigs/arista_mls_eos_4x_ndm/2025-02-20/finding/V-255954); [V-255962](https://www.stigviewer.com/stigs/arista_mls_eos_4x_ndm/2025-02-20/finding/V-255962) | Lockout, password minimum and logging verbosity. STIG lockout 3/900 differs from current 5/300; do not silently replace generic policy with STIG policy. |
| S12 | [F5 NDM V-266079](https://www.stigviewer.com/stigs/f5_bigip_tmos_ndm/2025-06-12/finding/V-266079), High; [V-266085](https://www.stigviewer.com/stigs/f5_bigip_tmos_ndm/2025-06-12/finding/V-266085), High; [V-266067](https://www.stigviewer.com/stigs/f5_bigip_tmos_ndm/2025-06-12/finding/V-266067), High | Remote AAA binding, interactive MFA and role permissions. Static RADIUS configuration does not prove an MFA challenge occurs. |
| S13 | [F5 ALG V1R3](https://www.stigviewer.com/stigs/f5_bigip_tmos_alg/v/V1R3), V-266139/V-266149; [NDM V-266094](https://www.stigviewer.com/stigs/f5_bigip_tmos_ndm/2025-06-12/finding/V-266094) | TLS protection, conditional application inspection and revocation configuration. Module and release applicability required. |
| S14 | [SonicOS 7 Security Services guide](https://www.sonicwall.com/techdocs/pdf/sonicos-7-0-0-0-security_services.pdf), IPS configuration and zone enablement (p.35) | Global enablement, zone attachment and exclusions are different evidence. Vendor source, not a SonicOS STIG. |
| S15 | [Historical official Check Point CIS v1.0](https://www.cisecurity.org/-/jssmedia/Project/cisecurity/cisecurity/data/media/files/uploads/2017/04/CIS_Checkpoint_Benchmark_v10.pdf), section 3.6 | Anti-spoof intent in older FW1-era deployments. Requalify object schema/release; not evidence of modern Gaia support. |
| S16 | [F5 NDM V-266080](https://www.stigviewer.com/stigs/f5_bigip_tmos_ndm/2025-06-12/finding/V-266080), High; [FortiGate NDM V-234193](https://www.stigviewer.com/stigs/fortinet_fortigate_ndm/2025-11-19/finding/V-234193), High | Supported software lifecycle. Version strings alone cannot determine current support or vulnerability. |

## Current coverage and explicit per-device work

This table describes **implemented subsets**, not complete coverage of a category. General coverage is already substantial: credential metadata/default checks, SSH/TLS algorithms, SNMP, authenticated time, logging, AAA and bounded static ACL effectiveness exist across many families. Reimplementing them would waste effort. The source appendix identifies their actual entry points.

| Registered device ID | Source-verified coverage to retain | Remaining prioritized tasks |
|---|---|---|
| IOS_SWITCH | Management-line authentication/authorization/timeouts, effective VTY AAA binding/bypass/accounting and empty-group checks, HTTP/SSH, credentials, SNMP, logging/config archive, NTP, interface/CoPP, BGP/OSPF, ACL effectiveness, selected DHCP/ARP/access-edge checks | [SC-001](#sc-001) member/release qualification only, [SC-003](#sc-003), [SC-004](#sc-004), [SC-005](#sc-005), [SC-006](#sc-006), [SC-021](#sc-021), [SC-022](#sc-022); Wave 4: [SC-025](#sc-025), [SC-026](#sc-026), [SC-027](#sc-027), [SC-028](#sc-028), [SC-029](#sc-029), [SC-031](#sc-031), [SC-033](#sc-033), [SC-034](#sc-034), [SC-035](#sc-035), [SC-036](#sc-036), [SC-037](#sc-037), [SC-044](#sc-044) |
| IOS_ROUTER | Same pipeline; role-appropriate routing/interface/management checks, not evidence of L2 endpoint role | [SC-001](#sc-001) member/release qualification only, [SC-005](#sc-005), [SC-006](#sc-006), [SC-021](#sc-021), [SC-022](#sc-022); Wave 4: [SC-026](#sc-026), [SC-027](#sc-027), [SC-028](#sc-028), [SC-031](#sc-031), [SC-033](#sc-033), [SC-034](#sc-034), [SC-035](#sc-035), [SC-036](#sc-036), [SC-037](#sc-037), [SC-044](#sc-044) |
| IOS_CATALYST | Same IOS pipeline; alias does not add independent checks | [SC-001](#sc-001), [SC-003](#sc-003), [SC-004](#sc-004), [SC-005](#sc-005), [SC-006](#sc-006), [SC-021](#sc-021), [SC-022](#sc-022); Wave 4: [SC-025](#sc-025), [SC-026](#sc-026), [SC-027](#sc-027), [SC-028](#sc-028), [SC-029](#sc-029), [SC-031](#sc-031), [SC-033](#sc-033), [SC-034](#sc-034), [SC-035](#sc-035), [SC-036](#sc-036), [SC-037](#sc-037), [SC-044](#sc-044) |
| IOS_XE | IOS baseline plus XE/MACsec/crypto additions | [SC-001](#sc-001), switch-role [SC-003](#sc-003)/[SC-004](#sc-004), [SC-005](#sc-005), [SC-006](#sc-006), [SC-021](#sc-021), [SC-022](#sc-022); Wave 4: [SC-025](#sc-025), [SC-026](#sc-026), [SC-027](#sc-027), [SC-028](#sc-028), [SC-029](#sc-029), [SC-031](#sc-031), [SC-032](#sc-032), [SC-033](#sc-033), [SC-034](#sc-034), [SC-035](#sc-035), [SC-036](#sc-036), [SC-037](#sc-037), [SC-044](#sc-044) |
| ASA | AAA, SSH/HTTP source restrictions, credentials, SNMP/log/NTP, MPF/uRPF, active SSL and bound IPsec transforms, ACL effectiveness, failover authentication | [SC-002](#sc-002), [SC-013](#sc-013), [SC-021](#sc-021), [SC-022](#sc-022); Wave 4: [SC-031](#sc-031), [SC-032](#sc-032), [SC-034](#sc-034), [SC-035](#sc-035), [SC-036](#sc-036), [SC-037](#sc-037), [SC-043](#sc-043), [SC-044](#sc-044) |
| PIX | Registry alias to ASA; independent old-dialect parsing remains uncertain, including externally observed bound ACL misses | [SC-020](#sc-020) first; do not blindly inherit modern ASA task applicability; Wave 4: [SC-044](#sc-044) |
| FORTIOS | Management/administrator/session/password/crypto/cert checks, including bound custom write-capable profile trusted-host/MFA coverage; SNMP/NTP, logging destinations/events, profile attachment/content summaries, DoS, local-in, VPN, backup/update configuration | [SC-009](#sc-009), [SC-011](#sc-011) authorized log-role policy only, [SC-012](#sc-012), [SC-013](#sc-013), [SC-022](#sc-022); Wave 4: [SC-031](#sc-031), [SC-032](#sc-032), [SC-033](#sc-033), [SC-034](#sc-034), [SC-035](#sc-035), [SC-037](#sc-037), [SC-038](#sc-038), [SC-039](#sc-039), [SC-040](#sc-040), [SC-043](#sc-043), [SC-044](#sc-044) |
| JUNOS | SRX policy/default deny/IPsec; administrative classes/AAA/SSH/SNMP/log/NTP, lo0 protection, BGP/OSPF and discovery | EX-only [SC-003](#sc-003)/[SC-004](#sc-004), [SC-005](#sc-005), SRX-only [SC-010](#sc-010), [SC-021](#sc-021), [SC-022](#sc-022); stateless-filter research remains in TODO; Wave 4: later stages of [SC-028](#sc-028), [SC-033](#sc-033) |
| SCREENOS | Legacy admin/password/logging/SNMP, NTP-server presence, policy/session/default-policy subset, VPN proposals and lifecycle warning | [SC-019](#sc-019), plus existing [RV-008](REALWORLD_VALIDATION_TASKS.md#rv-008); no duplicate lifecycle task |
| CHECKPOINT_FW1 | Policy objects, broad rules, cleanup/stealth, tracking/install scope and bounded static rule analysis | [SC-017](#sc-017); OS posture is the separate `CHECKPOINT_GAIA` family ([SC-023](#sc-023)); Wave 4: [SC-034](#sc-034), [SC-043](#sc-043), [SC-044](#sc-044) |
| CHECKPOINT_GAIA | Telnet, SNMP communities/version/v3 level, password policy (lockout, history, complexity, length), Clish idle timeout, login banner | [SC-023](#sc-023) remainder: remote AAA, NTP, syslog, web UI; Wave 4: [SC-030](#sc-030), [SC-038](#sc-038) |
| PAN_OS | Management/admin/password/lockout/AAA/SSH/TLS/certs/SNMP/NTP, update/log forwarding, rule hygiene/effectiveness, explicit interzone-default allow overrides and inspection attachment summaries | [SC-008](#sc-008), [SC-009](#sc-009), [SC-013](#sc-013), [SC-022](#sc-022) |
| HP_PROCURVE | AOS-S management/AAA/manager-operator/password/SSH/SNMP, logging/NTP and DHCP/DAI/source-lockdown/port-security subset | [SC-003](#sc-003), [SC-004](#sc-004), routing-role [SC-005](#sc-005), [SC-012](#sc-012), [SC-021](#sc-021), [SC-022](#sc-022) |
| SONICOS | E-CLI management/admin, access rules/effectiveness, VPN algorithms, logging/NTP/SNMP, global security services and Capture ATP dependencies | [SC-013](#sc-013), [SC-018](#sc-018), [SC-021](#sc-021), [SC-022](#sc-022) |
| ARISTA_EOS | eAPI/TLS-profile/SSH, admin roles/AAA/authz/accounting/session/lockout/banner, SNMP/credentials/authenticated NTP/CoPP | [SC-002](#sc-002), [SC-003](#sc-003), [SC-004](#sc-004), [SC-005](#sc-005), [SC-012](#sc-012), [SC-021](#sc-021), [SC-022](#sc-022); Wave 4: later stages of [SC-028](#sc-028), [SC-030](#sc-030), [SC-033](#sc-033) |
| F5_BIGIP | Explicit management source/redirect/idle settings, tmsh audit, password-enforcement and zero-lockout/minimum-length checks, plaintext local-user password storage, active remote-auth empty-server and LDAP SSL/peer-check disablement, remote-syslog-none, bound ClientSSL allow-non-SSL, AFM default-accept, bound inactive/transparent ASM policies | [SC-014](#sc-014), [SC-015](#sc-015), [SC-016](#sc-016), [SC-022](#sc-022), conditional-module [SC-024](#sc-024); Wave 4: [SC-030](#sc-030), [SC-031](#sc-031), [SC-032](#sc-032), [SC-033](#sc-033), [SC-034](#sc-034), [SC-036](#sc-036), [SC-037](#sc-037), [SC-041](#sc-041), [SC-042](#sc-042), [SC-043](#sc-043), [SC-044](#sc-044) |

Administrative access, AAA, credentials, SNMP, logging, time, services, routing, filtering, crypto, certificates, discovery and control-plane protection were considered. Banners already have checks on several families and are not a priority expansion here. Missing routing/L2 functions on appliances that do not use those roles are not automatically applicable. Certificate selection is not equivalent to certificate validation; algorithm blacklists are not credential-value checks; configured backup/update schedules are not proof of successful operation. No missing checks are inferred simply from an absent category name in a plugin.

The platform table above records the original task mapping and subsequent adapter additions. Cross-platform SC-045/049/050 apply to every registered ID; SC-046 adds IOS/XE management depth, SC-047 applies only to SRX JUNOS, and SC-048 lists its independently qualified switching stages. API/DNS, identity and protocol expansions are included in SC-026/011/005/013/043 rather than new duplicate tasks.

## Wave 1 — deepen existing evidence and close exposed decision gaps

Prioritize effective administrative privilege, bypassed authorization and default-permit behavior. Reuse established scope and profile resolvers. These are small-to-moderate extensions with immediate value; none requires a new platform.

Implementation update: SC-001 resolves effective VTY AAA bindings across overlapping line ranges and detects explicit authorization bypass, unbound/disabled accounting and undefined/empty named groups; member availability and benchmark topology thresholds remain unknown/evidence-gated. SC-002 has bounded explicit ASA local lockout/password-minimum and active SSH/ASDM idle coverage plus EOS explicit ineffective global minimum coverage; named EOS profiles, concurrent-session policy and benchmark thresholds remain open. SC-007 detects explicit PAN-OS interzone-default allow overrides in local and shared XML scopes, with local precedence and unmerged Panorama state left unknown. SC-009 has bounded PAN-OS first-broad-selector critical/high allow/alert detection for attached anti-spyware and vulnerability profiles and FortiOS first-broad, explicitly enabled critical/high IPS pass/monitor detection for attached sensors; signature exceptions, unqualified vendor defaults and required-function assessment policy remain open. SC-011 binds FortiOS administrators to exported custom access profiles and applies existing source-restriction/MFA checks to proven write-capable roles. SC-011's authorized log-administrator comparison remains open pending an explicit assessment policy; unresolved profiles are not classified as read-only. SC-012 now distinguishes explicitly cleartext or weak-TLS active FortiOS syslog destinations from reliable-TCP delivery, detects explicit EOS remote-trap or local-buffer thresholds that exclude error-severity events, and detects AOS-S remote Event Log suppression or explicit major-only filters; broader severity policy remains open.

<a id="sc-001"></a>
### SC-001 — Resolve effective IOS AAA authorization and accounting

**Task ID and Title:** SC-001 — Bound AAA method chains, server membership and accounting.

**Priority:** P1.

**Status:** Bounded explicit VTY binding/bypass/accounting/empty-group implementation complete; server-member usability beyond configured presence and benchmark topology thresholds require release/source qualification.

**Source of Truth:** S01; [IOS baseline](../../src/analyze/cisco/ios/plugins/baseline_plugin.py), `check_aaa` and `check_management_lines`. Accounting currently accepts any matching declaration; `backend_resolves` rejects `none` for authentication but not authorization and accepts named group existence without complete usable membership.

**Linked Findings:** Source gap above; this is deeper AAA coverage, not another missing-AAA rule.

**Dependencies:** Qualify IOS/IOS-XE method ordering, `if-authenticated`, local fallback and named server-group grammar.

**Architecture/Convention Notes:** Extend parser-owned per-line effective AAA; preserve existing management findings and deduplicate overlapping conditions.

**Concrete Requirements:** IOS_SWITCH, IOS_ROUTER, IOS_CATALYST, IOS_XE. Resolve active line login/exec/command authorization and accounting to concrete lists and usable server references. Identify explicitly authorization-free chains, unbound accounting declarations and unusable referenced groups. Distinguish configured fallback from demonstrably unauthenticated access; do not label all local fallback insecure. Missing external server state is unknown, not proof of availability. No CLI change; typed binding/method outcomes may be added.

**Test Requirements:** Mandatory suite plus a valid unbound accounting list, `none` authorization, empty named group, local emergency fallback and overlapping VTY ranges.

**Acceptance Criteria:** A declaration elsewhere cannot satisfy the active line's control; secure fallback remains correctly classified and unknown backend state never claims successful AAA.

<a id="sc-002"></a>
### SC-002 — Complete ASA/EOS administrative password and session policies

**Task ID and Title:** SC-002 — Brute-force resistance and effective session limits.

**Priority:** P2, common administrative compromise enablers.

**Status:** Bounded explicit ASA and EOS controls implemented; named EOS password-profile bindings, concurrent-session policy and benchmark-specific thresholds remain evidence/approval-gated.

**Source of Truth:** S11; ASA NDM catalog above; [ASA baseline](../../src/analyze/cisco/asa/plugins/baseline_plugin.py) `check_aaa`/SSH management checks; [EOS checks](../../src/analyze/arista/plugins/arista_checks_plugin.py). ASA console-zero checking is not complete SSH/ASDM policy; EOS already has lockout but uses 5 attempts/300 seconds and lacks password-minimum assessment.

**Linked Findings:** These source limitations; retain implemented IOS timeouts and existing EOS lockout checks.

**Dependencies:** Pin applicable ASA password-policy/aaa lockout and SSH/HTTP idle syntax; approve a named benchmark profile before applying its exact thresholds.

**Architecture/Convention Notes:** Parser-owned effective values and scope; reuse assessment policy rather than new CLI switches per threshold.

**Concrete Requirements:** ASA and ARISTA_EOS. Add ASA supported local password/lockout and active SSH/ASDM idle policies; add EOS password minimum and profile-specific lockout/concurrent-session requirements. Explicit disabled protections are assessable independently; missing defaults require known releases. External identity-provider password policy stays unknown. Interface change only if a validated, approved profile selector is needed; preserve generic defaults.

**Test Requirements:** Mandatory suite plus default resets, remote-only authentication, safe emergency accounts and generic-versus-STIG profile outcomes.

**Acceptance Criteria:** No duplicate EOS lockout finding, no blanket local-password finding for externally governed users, and no silently changed generic threshold.

<a id="sc-007"></a>
### SC-007 — Include PAN-OS default security-rule overrides

**Task ID and Title:** SC-007 — Effective interzone fallback policy.

**Priority:** P1.

**Status:** Implemented for explicit local-vsys/shared XML interzone-default overrides; implicit and unmerged Panorama defaults remain unknown.

**Source of Truth:** S07; [PAN parser](../../src/devices/paloalto/panos.py) and [checks](../../src/analyze/paloalto/plugins/panos_checks_plugin.py) assess named rules but do not model `default-security-rules`/`interzone-default` overrides.

**Linked Findings:** Missing implicit-policy evidence, distinct from implemented named broad-allow checks and Junos default-policy remediation.

**Dependencies:** Vendor documentation for local versus Panorama-pushed default-rule inheritance.

**Architecture/Convention Notes:** Add a typed per-vsys effective default policy and normalized coverage item; do not fabricate an ordinary ordered user rule.

**Concrete Requirements:** PAN_OS. Resolve explicit interzone-default action and override precedence. Emit a high-risk default-permit finding when effective interzone allow is proven. Treat intrazone default separately, not automatically as the same vulnerability. Unknown/unmerged inherited defaults remain unknown. Existing JSON/HTML interfaces suffice.

**Test Requirements:** Mandatory suite plus named restrictive rules with permissive fallback, secure interzone deny, normal intrazone allow, multiple vsys and unmerged Panorama overrides.

**Acceptance Criteria:** Explicit interzone allow is reported even with no named rules; normal intrazone behavior is not falsely classified as unrestricted interzone access.

<a id="sc-009"></a>
### SC-009 — Evaluate threat-specific inspection actions

**Task ID and Title:** SC-009 — Required profile types, severity selectors and exceptions.

**Priority:** P1.

**Status:** Bounded PAN-OS and FortiOS explicit critical/high selector actions implemented. FortiOS now also reports explicit IP exemptions on the first broad blocking high/critical selector attached to an active accept policy; signature-ID exceptions without known severity, unqualified vendor defaults and required-function policy remain open.

**Source of Truth:** S06, [Fortinet IPS sensor CLI](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/353620), [Fortinet signature ordering](https://docs.fortinet.com/document/fortigate/6.4.10/administration-guide/213498/signature-based-defense), [PAN parser](../../src/devices/paloalto/panos.py) `get_security_profile_definitions`/`_profile_threat_selectors`, and [Forti parser](../../src/devices/fortinet/fortios.py) `_ips_selectors`. Both now retain bounded ordered severity selectors, but signature exception severity and required profile sets are unresolved.

**Linked Findings:** Partial existing inspection coverage, not absent profile resolution.

**Dependencies:** Retain existing policy-to-profile/group resolvers; qualify built-in profiles by release and approve required profile sets by role.

**Architecture/Convention Notes:** Store per-threat type/severity/action/exception records; plugins must not infer protection from a profile name.

**Concrete Requirements:** PAN_OS and FORTIOS. Detect critical/high threat selectors explicitly allowed or only alerted on active assessed traffic, even if another selector blocks. Resolve exception precedence and required AV/IPS/antispyware members independently; a URL-only profile must not satisfy all threat functions. Unknown vendor-default actions remain unknown. Respect explicit assessment scope instead of name-based external-interface assumptions. Extend assessment context only for approved required-function policy; no separate output format.

**Test Requirements:** Mandatory suite plus low-severity block/high-severity alert, an overriding permit exception, group missing one required function, disabled policy and same-name profiles in different scopes.

**Acceptance Criteria:** Mixed profiles cannot conceal a proven high-threat bypass; informational/low-signature exceptions are not automatically high-risk findings.

<a id="sc-011"></a>
### SC-011 — Resolve custom FortiOS administrator permissions

**Task ID and Title:** SC-011 — Effective accprofile privileges and log administration.

**Priority:** P1 — broadly trusted privileged API identities can expose configuration write access; preserve existing custom-role checks.

**Status:** Implemented for bound write-capable custom roles and existing trusted-host/MFA checks. Organization-specific log-administrator grading is not scheduled, per the 2026-09-25 maintainer decision. **Research 2026-09-25:** FortiOS 7.4 [`config system accprofile`](https://docs.fortinet.com/document/fortigate/7.4.1/cli-reference/2620/config-system-accprofile): groups default to `none`; `loggrp read-write`, or `custom` with `loggrp-permission` `config`/`data-access` `read-write`, grants log write rights. Syntax was verified, but the later maintainer decision excludes authorized-log-role policy grading.

**2026-09-26 extension (A4):** API identities remain unassessed. A synthetic `system api-user` using `super_admin` with an explicit any-address trusted host added no findings. Existing `system admin` custom-role checks remain implemented. The maintainer decision not to grade log-administrator rights against an organization role list remains in force.


**Source of Truth:** S09; [Forti baseline](../../src/analyze/fortinet/plugins/fortios_baseline_plugin.py) `check_administrators` classifies privilege using `profile == "super_admin"`; no effective custom `accprofile`/`loggrp` analysis.

[FortiOS administrator checks](../../src/analyze/fortinet/plugins/fortios_baseline_plugin.py), `check_administrators`; [FortiOS 7.2.2 API-user reference](https://docs.fortinet.com/document/fortigate/7.2.2/cli-reference/17620/config-system-api-user), reviewed 2026-09-26, documents the distinct API-user profile, VDOM, trusted-host and peer-authentication fields.


**Linked Findings:** Custom roles can escape existing privileged-account trusted-host/MFA checks.

**Dependencies:** FortiOS release-specific accprofile permissions and global/VDOM scoping; API-user schema and effective trusted-host/peer-authentication evidence. Do not require an organization log-role list.

**Architecture/Convention Notes:** Parser resolves role definitions; reuse existing administrator findings for newly recognized equivalent privileges.

**Concrete Requirements:** FORTIOS. Parse custom profiles and their write/admin permissions, including log-management permissions; bind enabled local/remote admin entries. Apply existing source restriction/MFA checks to genuinely privileged custom roles. Organization-specific excess log-deletion/configuration privilege grading is excluded by the maintainer decision; role resolution remains relevant to the existing source/MFA checks. Unknown profiles are unresolved, never ordinary read-only users. Typed role records required; no new CLI unless approved role policy needs an assessment-context field.

**Open P1 API-user stage:** FORTIOS. Parse `config system api-user` separately from interactive administrators. Resolve accprofile through the existing privilege resolver, VDOM scope, IPv4/IPv6 trusthost entries and explicitly configured peer-authentication references. Detect proven broadly trusted write-capable API identities; distinguish read-only and unresolved roles. Keep token values out of normal findings/inventory. Do not impose interactive MFA on machine identities or infer token age/rotation from unavailable evidence. Parser-owned typed API identity records are required; existing output interfaces suffice. Assess explicit broad grants now; defaults belong to the separate defaults work.


**Test Requirements:** Mandatory suite plus custom write role without trusted hosts, read-only role, scoped VDOM administrator, unresolved profile, disabled account and remote MFA of unknown status.

Add broad privileged API token, restricted token, read-only role, unresolved custom profile, same-name roles in different scopes, IPv4/IPv6 independence, peer-auth reference and API-key redaction cases.


**Acceptance Criteria:** Role names cannot bypass existing privileged-account protections; no claim that a configured permission was exercised at runtime.

API accounts cannot escape privilege/source auditing merely because they are outside `system admin`. Existing interactive checks remain stable; no organization-specific log-role policy is introduced.

<a id="sc-012"></a>
### SC-012 — Complete protected logging and useful event levels

**Task ID and Title:** SC-012 — Logging transport and effective severity filters.

**Priority:** P2; common loss of useful audit evidence.

**Status:** Bounded FortiOS explicit syslog transport, EOS error-severity gates and AOS-S remote Event Log/severity gates implemented; policy-selected broader event ranges and other transport/retention requirements remain open.

**Source of Truth:** S10, S11; [Forti syslog CLI](https://docs.fortinet.com/document/fortigate/7.4.5/cli-reference/141516630/config-log-syslogd-setting) distinguishes `mode` from `enc-algorithm`; Forti baseline `check_syslog_transport` now resolves explicitly enabled destinations and VDOM overrides. [Arista logging commands](https://www.arista.com/en/um-eos/eos-switch-administration-commands) establish inverted 0–7 severity thresholds and the distinct remote trap and local buffer destinations; EOS detects explicit exclusion of error-level events only. [AOS-S 16.11 severity commands](https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/KB/content/kb/cnf-sev-lev-eve-log.htm) and [debug operation](https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/YC/content/common%20files/cnf-deb-ope.htm) establish the separate major/error ordering, syslog destination and Event Log forwarding semantics implemented by [HP checks](../../src/analyze/hp/plugins/hp_checks_plugin.py).

**Linked Findings:** Preserve RV-010 local-versus-remote logging fix and current Forti event-filter rules.

**Dependencies:** Resolve destination activity/scope; verify supported encrypted transport syntax on each release. Do not require an unavailable AOS-S transport.

**Architecture/Convention Notes:** Typed sink transport, severity threshold and source scope; reuse existing evidence/report interfaces.

**Concrete Requirements:** FORTIOS: detect explicitly unprotected remote logging where protected transport is applicable, including reliable mode versus actual TLS distinction. ARISTA_EOS: assess active trap/buffer levels that exclude the selected security event range. HP_PROCURVE: qualify and implement equivalent explicit severity cases only. Unknown transport/profile defaults remain unknown; local buffer alone does not prove external retention. No online delivery test.

**Test Requirements:** Mandatory suite plus reliable-cleartext versus TLS, enabled versus disabled sink, per-VRF/VDOM destinations and inverted syslog severity ordering.

**Acceptance Criteria:** An enabled sink is not sufficient to pass transport/content policy, while secure alternative supported logging paths are respected.

## Wave 2 — high-value parser extensions for supported platforms

Implement by risk and fixture quality. Shared L2 and routing concepts offer reuse, but each vendor gets independent qualification and tests. Appliance-specific inspection and F5 administrative/TLS coverage have priority over marginal benchmark items.

<a id="sc-003"></a>
### SC-003 — Access-port network admission

**Task ID and Title:** SC-003 — Effective 802.1X and bypass modes.

**Priority:** P1 for explicitly assessed endpoint access ports.

**Status:** Bounded explicit IOS/XE assessed access-edge bypass checks implemented. An AOS-S stage was added on 2026-09-24: ordered `aaa port-access authenticator <ports> control authorized` (force authorized, per the AOS-S 16.10 access security guide) is reported on assessed access edges, and `control auto` or `no aaa port-access authenticator` overrides it. Missing-control policy, fallback/AAA effectiveness and the EOS/Junos EX grammar/fixtures remain open; the Arista 802.1X guide was not reachable for qualification. **Research 2026-09-25 (vendor docs read through the maintainer's browser):** Arista EOS 802.1X ([Control Plane Security, 802.1X Port Security](https://www.arista.com/en/um-eos/eos-control-plane-security)): `dot1x port-control force-authorized` disables authentication and is the default; `auto` enables it; `dot1x system-auth-control` enables it globally; multi-host mode admits any MAC after one supplicant. Juniper EX ([supplicant modes example](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/example/802-1x-pnac-single-supplicant-multiple-supplicant-configuring.html)): `supplicant single` admits all later devices without authentication; `single-secure` and `multiple` do not. The Junos default supplicant mode is not verified. The EOS and Junos stages are unblocked for explicit settings. **Implemented 2026-09-25:** EOS `arista.eos.layer2.access_edge.dot1x_force_authorized` and `dot1x_global_disabled` (explicit settings only); Junos EX `juniper.junos.layer2.access_edge.dot1x_single_supplicant`. The Junos default supplicant mode is still unverified, so an absent mode is not graded.

**Source of Truth:** S02; IOS `check_access_admission` now resolves explicit force-authorized, open and global-disable bypasses from parser-owned port records. HP `check_edge_protections`, EOS plugin and Junos baseline still lack effective 802.1X admission analysis despite existing DHCP/ARP/port-security subsets. [Cisco IOS-XE port-control guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_8021x/configuration/xe-3e/sec-usr-8021x-xe-3e-book/config-ieee-802x-pba.html) and [open-auth guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_8021x/configuration/xe-3e/sec-usr-8021x-xe-3e-book/sec-ieee-open-auth.html) qualify the bounded implementation.

**Linked Findings:** Missing network-admission control, not missing port security generally.

**Dependencies:** IOS/IOS-XE first, then AOS-S, EOS and Junos EX vendor guides. Cross-vendor STIG applicability requires qualification, not copied Cisco syntax.

**Architecture/Convention Notes:** Explicit access-edge roles from assessment context; typed global/service/port authentication and fallback bindings.

**Concrete Requirements:** IOS_SWITCH, IOS_CATALYST, switching IOS_XE, HP_PROCURVE, ARISTA_EOS, EX JUNOS. Resolve global authenticator enablement, port mode, active AAA association, forced-authorized/open modes and configured fallback. Detect proven unrestricted admission where authentication is required. MAB/guest/critical-auth exceptions need explicit site policy; do not call every exception high risk. Unknown role, inactive port or missing inherited state is unassessed. Reuse role interface; add no name heuristics.

**Test Requirements:** Mandatory suite plus globally enabled but port forced-authorized, secure port auth, voice/uplink exception, AAA unresolved and disabled edge.

**Acceptance Criteria:** Each vendor has its own public-pipeline fixtures; the global dot1x switch alone never satisfies per-port protection.

<a id="sc-004"></a>
### SC-004 — Access-edge BPDU protection

**Task ID and Title:** SC-004 — Effective spanning-tree edge protection.

**Priority:** P2; a common local foothold can disrupt a switched network.

**Status:** Bounded explicit IOS/XE assessed access-edge BPDU-guard inheritance/override and local filter-bypass checks implemented. The EOS mapping was added on 2026-09-24 from the Arista spanning-tree guide: the global `spanning-tree edge-port bpduguard default` applies to portfast ports, interface `spanning-tree bpduguard` takes precedence, and `portfast auto` stays unknown. The AOS-S mapping was also added: ordered `spanning-tree <ports|all> bpdu-protection` and `bpdu-filter`. Explicitly disabled protection, and protection combined with a filter (which makes the port ignore BPDUs), are reported on assessed access edges of verified 16.10/16.11 exports. Omitted-default conclusions and the Junos EX mapping remain open. **Research 2026-09-25:** Juniper [`bpdu-block-on-edge`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/bpdu-block-on-edge-edit-protocols-stp.html) at `[edit protocols (mstp|rstp|vstp)]` (default not enabled) and [`bpdu-block { interface (name | all); disable-timeout }`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/bpdu-block-edit-protocols-layer2-control.html) at `[edit protocols layer2-control]` (ELS) or `[edit ethernet-switching-options]` (legacy). The Junos EX stage is unblocked. **Implemented 2026-09-25:** `juniper.junos.layer2.access_edge.bpdu_protection_missing` (documented default: not enabled) for declared access-edge ports in ethernet-switching access mode; interface ranges stay unknown.

**Source of Truth:** S02; IOS/XE now resolves explicit global PortFast/BPDU-guard settings and per-port overrides in parser-owned records, using the [Cisco IOS LAN switching command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/lanswitch/command/lsw-cr-book/lsw-s2.html). AOS-S, EOS and Junos EX still require independent vendor-qualified mappings.

**Linked Findings:** Missing L2 control, independent of 802.1X.

**Dependencies:** Explicit access-edge role; release-specific global edge defaults and port overrides. Qualify root/loop guard separately if later added; they are not interchangeable with BPDU guard.

**Architecture/Convention Notes:** Parser owns global-to-port inheritance; share only normalized protection outcome.

**Concrete Requirements:** IOS_SWITCH, IOS_CATALYST, switching IOS_XE, HP_PROCURVE, ARISTA_EOS and EX JUNOS. Assess explicitly unprotected eligible edge ports, including local disable overriding global enable. Do not recommend BPDU guard on normal switch uplinks or treat BPDU filtering as equivalent without vendor proof. Unknown port role/default remains unknown. Existing role and report interfaces suffice.

**Test Requirements:** Mandatory suite plus global enable/local disable, secure inherited edge setting, trunk uplink, LAG membership and disabled port.

**Acceptance Criteria:** Findings identify the exact eligible port and effective missing/disabled protection; no blanket all-port recommendation.

<a id="sc-005"></a>
### SC-005 — Effective routing authentication and boundary policy

**Task ID and Title:** SC-005 — Expand routing trust beyond protocol/attachment presence.

**Priority:** P1 for explicit unauthenticated/weak routing trust capable of route injection; P2 for IPv6/VRF expansion and deployment-specific multicast controls. Implement the explicit RIPv1 gap before niche protocol breadth.

**Status:** Bounded IOS/XE classic default-VRF IPv4 RIPv2 and EIGRP authentication; direct external-BGP IPv4 prefix-list, route-map and AS-path filter-list missing-reference/sole-permit-all checks; and explicit-UTC, assessment-time-gated OSPF/RIP/EIGRP key-lifetime viability implemented. A named-mode EIGRP stage was added on 2026-09-25 from the Cisco EIGRP command reference and configuration guide: default-VRF `address-family ipv4 [unicast] autonomous-system N` under `router eigrp <name>`, with `af-interface default` inherited by every interface and a specific `af-interface` overriding it; `shutdown` and `passive-interface` under af-interface exclude the interface; `authentication mode md5` needs a populated `authentication key-chain`, and `authentication mode hmac-sha-256 [0|7] <key>` is accepted (the key is redacted and shown only in the `--show-secrets` appendix). A specific `no authentication ...` against an inherited default stays unknown. VRF/IPv6/multicast address families, named/VRF RIP, EOS/HP routing, broader filter effectiveness and other-platform/ambiguous-clock key-lifetime stages remain open. For the EOS BGP stage (2026-09-24), the peer-group and VRF grammar was confirmed from the Arista BGP guide, but IPv4-unicast default activation and the `maximum-routes` default could not be confirmed from accessible sources. Those two defaults decide which peers are active and whether a prefix-limit finding is valid, so the stage waits for that evidence. SC-005 remains partial. **Research 2026-09-25:** Arista [BGP chapter](https://www.arista.com/en/um-eos/eos-border-gateway-protocol-bgp): `bgp default ipv4-unicast` (all neighbors IPv4-active) is the switch default; `no neighbor maximum-routes` applies the system default of 256000, and only `maximum-routes 0` removes the limit. Cisco [RIP command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_rip/command/irr-cr-book/irr-cr-rip.html): the VRF example sets `version 2` inside each `address-family ipv4 vrf`, and timers are explicitly not inherited; `version` inheritance is not stated, so a VRF stage should only assess address families with their own `version 2`. **Implemented 2026-09-25:** IOS RIP VRF stage for `address-family ipv4 vrf` blocks that set their own `version 2`. **EOS BGP stage implemented 2026-09-25** (default VRF, IPv4 unicast; `vrf` blocks and other address families are left out). Peers are active by default unless `no bgp default ipv4-unicast`, and `address-family ipv4` activation is then required. `neighbor <x> peer group <g>` inheritance is followed. Rules: `authentication` (no `neighbor password`); `inbound_policy`/`outbound_policy` on external peers; `missing_route_map`, which is a documented default because EOS permits all routes for a misconfigured route map unless `bgp missing-policy ... action deny`; `permit_all_route_map`; and `prefix_limit_disabled` for an explicit `maximum-routes 0`. A missing `maximum-routes` is not graded, because the default is 256000.

**2026-09-26 extension (review proposals A7/A9):** Existing implemented stages remain complete. Explicit RIPv1, IS-IS, IPv6 routing and multicast stages below are open. A synthetic explicit IOS RIPv1 instance returned zero RIP interface records and no routing finding; the parser currently retains only version-2 RIP scopes.


**Source of Truth:** S03; IOS `check_routing` covers BGP/OSPF plus bounded classic RIPv2 and EIGRP interface/key-chain slices, using the [Cisco IOS RIP command reference](https://www.cisco.com/c/en/us/td/docs/ios/iproute_rip/command/reference/irr_book/irr_rip.html), [Cisco EIGRP command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_eigrp/command/ire-cr-book/ire-i1.html), and [Cisco EIGRP passive-interface FAQ](https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/13681-eigrpfaq.html). Narrow BGP effects follow [Cisco's explicit prefix-list permit-all example](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/ip-routing/b-ip-routing/m_irg-external-sp-0.html), [route-map no-match semantics](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/ip-routing/b-ip-routing/m_iri-iprouting.html), and the [Cisco AS-path filter command reference](https://www.cisco.com/c/en/us/td/docs/ios/iproute_bgp/command/reference/irg_book/irg_bgp2.html); most routing filter forms still test attachment presence only. Junos baseline has BGP/OSPF; EOS/HP plugins lack equivalent routing-security analysis.

Additional evidence: [IOS RIP resolver](../../src/devices/cisco/ios.py), `get_rip_interfaces` (version-2 scope filter); [Junos routing parser](../../src/devices/juniper/junos.py), bounded OSPFv2 records. [RFC 2453](https://www.rfc-editor.org/rfc/rfc2453.html) documents RIPv1 authentication limitations; [Cisco IS-IS reference](https://www.cisco.com/c/en/us/td/docs/ios/iproute_isis/command/reference/irs_book/irs_is1.html) distinguishes authentication scopes; [Cisco Secure IP Multicast Deployments](https://www.cisco.com/c/en/us/support/docs/ip/ip-multicast/218004-secure-ip-multicast-deployments.html) establishes PIM control/filtering intent. Sources reviewed 2026-09-26.


**Linked Findings:** Different platform coverage depths; do not claim BGP/OSPF checks are absent everywhere.

**Dependencies:** Representative sanitized routing exports; explicit external-neighbor/interface roles; approved prefix policy and assessment time for time-sensitive checks.

**Architecture/Convention Notes:** Parser resolves inheritance, address family, peer groups, passive state, keys and filter ordering. Reuse bounded set analysis only for supported predicates.

**Concrete Requirements:** (1) IOS IDs/IOS_XE: active EIGRP/RIP authentication and explicit weak/null mode; (2) EOS and routing-capable HP_PROCURVE: BGP/OSPF active auth and bound external filters; (3) IOS/IOS_XE/JUNOS/EOS: detect proven permit-all/nonrestrictive attached routing filters, missing referenced filters and unusable key-chain lifetimes. Unknown complex policy is not automatically empty or safe. Do not require BGP authentication on dormant templates. Interface change only for approved expected-prefix/key-time policy in assessment context.

Additional independently deliverable stages, preserving completed BGP/EIGRP/RIPv2 behavior:

1. **P1 — explicit RIPv1:** IOS IDs/IOS_XE first. Resolve configured send/receive versions, active interface/network attachment and passive/shutdown state; detect explicit v1 participation or v1 fallback without relying on omitted defaults. Do not silently discard an explicitly unsupported protocol from coverage.
2. **P1 — IS-IS authentication:** IOS/IOS-XE first, then separately qualified JUNOS/ARISTA_EOS. Resolve active interface/process bindings, Level 1/2, hello versus database authentication, explicit text/disabled modes and key references. Assess HMAC usage in its protocol context rather than copying password-hash policy.
3. **P2 — IPv6/VRF depth:** extend supported OSPFv3 and routing address families with their actual authentication mechanisms and override rules. Unknown IPsec/authentication-trailer or inheritance state stays unknown; do not infer IPv6 protection from IPv4 checks.
4. **P2 — multicast control:** IOS/IOS-XE first. Resolve PIM-enabled interfaces, neighbor filters, RP/BSR controls, multicast boundaries and configured MSDP peers/authentication. Report proven overly broad filters or inappropriate participation on explicitly assessed endpoint/external interfaces. Missing site topology or unsupported predicates remain unassessed; multicast use alone is not a vulnerability.

Parsers own each new protocol's typed effective state. Existing role/context interfaces suffice initially; approved expected-peer/prefix policy needs an explicit context extension only when required. No routing-neighbor queries, multicast probes or live topology discovery. Omitted/default-setting tables remain SC-044, outside these stages.


**Test Requirements:** Mandatory suite plus peer inheritance override, IPv4/IPv6 independence, passive interface, permit-all route map with a name, unresolved prefix list, unsupported predicate and expired versus future-valid key.

Additional fixtures: explicit RIPv1 versus authenticated v2; v1 receive override; shutdown/passive interfaces; IS-IS L1/L2 and hello/database differences; unbound key chain; IPv6-only/VRF routing; PIM permit-all versus restrictive neighbor filter; untrusted edge versus authorized multicast uplink. All require unknown-state, redaction and public-pipeline tests.


**Acceptance Criteria:** Track and test each numbered adapter stage separately; attachment names alone cannot establish effective filtering, and no runtime-neighbor assertion is made.

Each stage has qualified vendor grammar and its own fixtures; a recognized unassessed routing feature is disclosed rather than silently omitted. No unsupported family is represented as protected and no configured adjacency is represented as observed live.

<a id="sc-006"></a>
### SC-006 — Deployment-time automatic configuration services

**Task ID and Title:** SC-006 — Unsafe automatic configuration on commissioned IOS devices.

**Priority:** P2.

**Status:** Bounded 15.x-or-later IOS/XE explicit TFTP boot host/network retrieval implemented when assessment policy declares the device commissioned. A CNS stage was added on 2026-09-24: an effective `cns config initial|partial <host>` without `encrypt` uses HTTP per the Cisco CNS command syntax (default port 80, or 443 with SSL) and is reported on commissioned devices, with ordered `no cns config` removal and the endpoint redacted. PnP, other protocols and unqualified release/default interactions remain evidence-gated. SC-006 remains partial.

**Source of Truth:** S03 zero-touch control; IOS `check_unnecessary_services` covers finger/small servers/BOOTP. The bounded boot-config slice follows the [Cisco IOS XE configuration-file guide](https://www.cisco.com/c/en/us/td/docs/ios/ios_xe/fundamentals/configuration/guide/TIPs_conversion/config_mgmt_xe_3s_Book/cf_config-files_xe.html) and [Cisco IOS boot command reference](https://www.cisco.com/c/en/us/td/docs/ios/fundamentals/command/reference/cf_book/cf_a1.html), which qualifies the `no service config` interaction on modern releases. CNS/PnP remain open.

**Linked Findings:** Missing service intent; do not duplicate existing unused-service findings.

**Dependencies:** Qualify `service config`, CNS and PnP separately against actual IOS/XE releases and secure enrollment alternatives.

**Architecture/Convention Notes:** Vendor-specific typed enrollment/service state; explicit commissioning status if required in assessment context.

**Concrete Requirements:** IOS_SWITCH, IOS_ROUTER, IOS_CATALYST, IOS_XE. Detect proven enabled untrusted/unauthenticated configuration retrieval on devices explicitly assessed as commissioned. Distinguish disabled services, secured managed enrollment and unknown default discovery. No finding merely because a harmless CNS-related token appears. No new CLI switch outside a justified assessment-policy field.

**Test Requirements:** Mandatory suite plus authenticated controller, provisioning exception, explicit disable, URL/key redaction and unknown release default.

**Acceptance Criteria:** Each implemented service has vendor evidence and bound endpoint/security interpretation; no blanket prohibition on legitimate provisioning.

<a id="sc-008"></a>
### SC-008 — PAN-OS zone and DoS protection

**Task ID and Title:** SC-008 — Bound flood, malformed-packet and spoofing protections.

**Priority:** P1.

**Status:** Bounded local-firewall stage implemented for a resolved zone-protection profile with explicit SYN, UDP or ICMP flood disablement or a scan entry set to `allow` on a zone containing an interface assigned the external assessment role. A possible local DoS protect rule suppresses flood findings but not scan-allow findings; unmerged Panorama/template state suppresses both. Alert-only scan entries are not findings because the vendor documents alerting as a valid action. Explicit ICMPv6 and other-IP flood disablement was added on 2026-09-24 (flood types named in the PAN-OS zone-protection documentation). Still open: required protection, SCTP INIT (release-dependent), malformed/spoofed-packet settings, and exact DoS policy applicability.

**Source of Truth:** S05; PAN parser/plugin currently lack zone-protection/DoS models and evaluation.

**Linked Findings:** Missing protection plane, not the existing broad security-policy detector.

**Dependencies:** Qualified zone profile, DoS policy, address matching and rule precedence; explicit untrusted ingress scope. Document accepted alternative protection paths from the control.

**Architecture/Convention Notes:** Typed zone-to-profile and DoS-rule bindings, with individual protections/actions; no plugin XML traversal.

**Concrete Requirements:** PAN_OS. Evaluate required ingress protection on assessed zones and explicit disabled/alert-only critical protections; resolve same-vsys/shared scope and DoS alternatives. Distinguish configured flood limits from demonstrated capacity. No invented universal packet-rate threshold. Missing Panorama definitions or unsupported matching stay unknown. Reuse roles and output; add minimal zone-role input only if existing roles cannot express it.

**Test Requirements:** Mandatory suite plus unbound strong profile, attached disabled protection, applicable DoS alternative, multiple zones/vsys and unknown threshold policy.

**Acceptance Criteria:** A strong unused profile cannot satisfy an exposed zone; policy alternatives are honored without claiming runtime attack resistance.

<a id="sc-010"></a>
### SC-010 — SRX screens and active IDP policy

**Task ID and Title:** SC-010 — Zone-bound screens and blocking IDP.

**Priority:** P1 screens; P2 IDP ineffective-action depth.

**Status:**
- **Stage A (started):** active zone-to-screen binding, explicit deactivated SYN/UDP/ICMP-flood options, and UDP/ICMP-flood alarm-only state are covered for assessed external SRX zones.
- **Stage B (first increment, 2026-09-24):** the parser resolves IDP policies applied by active permit rules, both direct `idp-policy` and the legacy global `active-policy`. The plugin reports a resolved applied policy whose every active IPS rule has an explicit non-blocking action (`no-action`, `ignore-connection`, `mark-diffserv`, `class-of-service`; Junos IPS action reference).
- **Not graded:** `recommended` actions, missing or ambiguous actions, unresolved or inherited policies, EX models, and attack-object/terminal-rule precedence.
- **Still open:** other screen controls, required-protection absence, and per-attack-group blocking depth.

**Source of Truth:** S08; [Junos baseline](../../src/analyze/juniper/junos/plugins/baseline_plugin.py) and [parser](../../src/devices/juniper/junos.py) do not evaluate `security screen ids-option` or active bound IDP protection.

**Linked Findings:** Missing SRX inspection; retain implemented interzone-default, lo0, policy-effectiveness and IPsec checks.

**Dependencies:** Prove SRX role; zone attachment, IDP active-policy, security-rule application-services and applicable required protections. Two independently releasable stages.

**Architecture/Convention Notes:** Resolve set/delete/deactivate and apply-groups in the parser, using existing unknown inheritance behavior.

**Concrete Requirements:** JUNOS on SRX only. Stage A resolves screen definitions and zone binding, reporting explicit critical disablement/missing required bound protection in complete assessed scope. Stage B follows active IDP policy through permitting rules and effective signature/severity actions; detect explicit pass/ignore where blocking is required. Missing signature content/license/operational state is unknown; do not claim signatures are current. Existing scope/report interfaces suffice.

**Test Requirements:** Mandatory suite plus unbound screen, inherited protected zone, deactivated policy, inactive IDP declaration, ignore exception and EX negative.

**Acceptance Criteria:** Both stages identify the active scope and action; declarations alone never establish protection and EX receives no SRX absence findings.

<a id="sc-013"></a>
### SC-013 — Remote-access VPN authentication and authorization

**Task ID and Title:** SC-013 — Effective remote-access authentication chain and access restriction.

**Priority:** P1 for remote-access authentication bypass, exposed PPTP and proven cleartext credentials; P2 for deployment-specific PPP/L2TP extensions where exposure is not yet established.

**Status:** Bounded ASA WebVPN explicit group-URL/AAA-only finding under an opt-in client-certificate policy implemented. Default/alias/IPsec entry points, fallback and authorization-filter resolution, and other-vendor stages remain evidence-gated. SC-013 remains partial.

**2026-09-26 extension (A6):** Legacy PPTP and PPP authentication stages are open. Explicit FortiOS PPTP gateway enablement produced no relevant finding in a synthetic processor run. Existing ASA client-certificate and other implemented VPN stages remain intact.


**Source of Truth:** S04; ASA SSL/IPsec checks inspect crypto but not effective remote-access tunnel-group/group-policy authentication. FortiOS, PAN-OS and SonicOS adapters do not provide equivalent complete remote-access auth-chain evaluation.

Additional sources reviewed 2026-09-26: [FortiOS 7.4.1 PPTP gateway reference](https://docs.fortinet.com/document/fortigate/7.4.1/cli-reference/336620/config-vpn-pptp), [Cisco PAP security explanation](https://www.cisco.com/c/en/us/support/docs/wan/point-to-point-protocol-ppp/10313-config-pap.html), and [Microsoft PPTP/L2TP deprecation guidance](https://techcommunity.microsoft.com/blog/windowsservernewsandbestpractices/pptp-and-l2tp-deprecation-a-new-era-of-secure-connectivity/4263956). Current VPN plugin paths assess IPsec/IKE/SSL properties without equivalent PPTP/PPP analysis.


**Linked Findings:** Separate from completed RV-001/RV-002; TLS strength does not establish user authentication.

**Dependencies:** ASA release-specific tunnel-group inheritance and reachable WebVPN; then Forti SSL-VPN, PAN GlobalProtect and Sonic remote-access vendor sources/fixtures. Verify feature availability; newer Forti releases/models may remove SSL-VPN functions.

**Architecture/Convention Notes:** Typed listener-to-portal/group/auth/profile/access-filter relationships; do not infer MFA from a RADIUS/SAML server name.

**Concrete Requirements:** ASA, then FORTIOS/PAN_OS/SONICOS. Resolve active remote-access entry points, effective authentication choices, fallback, certificate requirement and bound authorization filters. Report explicit password-only paths under an applicable approved stronger-auth policy and proven unrestricted authorization against explicit expected scope. Certificate-specific ASA STIG policy stays distinct from generic MFA. Omitted identity-provider policy is unknown. Add minimal approved remote-access policy context, not live authentication attempts.

**Open legacy-protocol stages:** (1) FORTIOS: detect explicitly enabled PPTP gateway and qualified active PPTP client configuration. (2) IOS IDs/IOS_XE: resolve VPDN, virtual-template and active PPP interface relationships, authentication method ordering and fallback. Detect explicit PAP on a proven unprotected path and source-qualified weak fallback. (3) ASA and other already-supported families only after export/grammar qualification: distinguish L2TP alone from L2TP over IPsec. Never claim outer-network credential exposure merely because PAP exists inside a protected tunnel. Missing outer-protection relationships remain unknown; unbound templates are not active services. Extend vendor typed VPN/authentication records, reuse existing JSON/HTML interfaces, and perform no connection or credential attempt.


**Test Requirements:** Mandatory suite plus inherited weak default group, secure certificate path, unbound portal, fallback bypass, unresolved external IdP and disabled VPN.

Add enabled/disabled PPTP, active versus unused virtual templates, PAP versus a qualified stronger method, weak fallback ordering, protected L2TP/IPsec, unresolved protection, malformed groups and credential-redaction cases.


**Acceptance Criteria:** Each vendor stage has its own source mapping and fixtures; reports state configured requirements, never that MFA was actually performed.

Explicit legacy VPN enablement is assessable independently of insecure defaults. Reports distinguish protocol weakness, authentication weakness and proven cleartext exposure; no live negotiated-session claim is made.

<a id="sc-014"></a>
### SC-014 — F5 administrative identity and privilege

**Task ID and Title:** SC-014 — TMOS users, roles, remote AAA and local policy.

**Priority:** P1.

**Status:** Bounded explicit password-policy login-lockout, zero-minimum-length and plaintext `auth user` storage checks implemented for saved TMOS exports. Active RADIUS/LDAP/TACACS+/certificate-LDAP source types detect provider objects that all explicitly set `servers none`; active LDAP/certificate-LDAP providers also detect explicit `ssl disabled` or, separately, `ssl-check-peer disabled` on SSL/StartTLS when all exported provider objects have configured servers and matching weak state. Missing/unresolved providers, unknown TLS values and external protected paths remain unknown. Effective roles, full remote AAA bindings and other local constraints remain open after syntax/fixture qualification.

**Source of Truth:** S12; [F5 parser](../../src/devices/f5/bigip.py) `_FIELDS`/`get_users` and [plugin](../../src/analyze/f5/plugins/bigip_checks_plugin.py). Current checks cover password enforcement toggle and explicit timers, not effective identity policy.

**Linked Findings:** Absent user/AAA analysis in the new adapter.

**Dependencies:** TMOS versioned `auth` object guides, partition/role semantics and sanitized saved exports; no UCS/F5OS expansion.

**Architecture/Convention Notes:** Typed effective users, remote-role mappings, active auth mode/server chain and credential metadata; never retain password hashes in evidence.

**Concrete Requirements:** F5_BIGIP. Detect unsafe enabled administrator access/role mappings, unprotected stored credentials where identifiable, explicit disabled lockout/password constraints, and incomplete active remote-auth bindings. Evaluate server redundancy only under qualified S12 profile; MFA backed by external systems remains unknown unless configuration proves a bypass. Resolve local fallback and emergency-account policy without declaring every local user unsafe. Existing findings/coverage interface, minimal policy context if approved.

**Test Requirements:** Mandatory suite plus unused remote server, active group mapping granting admin, restricted partition role, disabled user, masked hash and unresolved external MFA.

**Acceptance Criteria:** Administrative identity is assessed independently of the password-enforcement boolean; safe emergency fallback is preserved and remote-provider behavior is not invented.

<a id="sc-015"></a>
### SC-015 — F5 effective TLS and certificate protection

**Task ID and Title:** SC-015 — Management, ClientSSL and ServerSSL policy chains.

**Priority:** P1.

**Status:** Management stage implemented (2026-09-24): an explicit `sys httpd ssl-protocol` is resolved with Apache mod_ssl `SSLProtocol` semantics and reported when it enables SSLv2/SSLv3/TLS 1.0/TLS 1.1. An explicit `ssl-ciphersuite` made only of literal OpenSSL suite names is reported when it offers 3DES/DES/RC4/NULL/export/MD5 suites. Keyword or exclusion lists and omitted, release-dependent defaults stay ungraded; for example, the pre-14.0 default enabled TLS 1.0. ClientSSL/ServerSSL protocol and cipher resolution through `defaults-from`, F5 cipher-string/cipher-group semantics and certificate material remain open.

**Source of Truth:** S13; F5 parser currently resolves bound ClientSSL `allow-non-ssl`; it does not evaluate offered protocols/ciphers or certificate trust. Vendor [ClientSSL reference](https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/ltm/ltm_profile_client-ssl.html) and management references are already in the plugin.

**Linked Findings:** Missing crypto depth; retain existing cleartext finding.

**Dependencies:** Profile `defaults-from` chains, cipher groups/strings, partition names and active virtual profile direction; supported public certificate objects.

**Architecture/Convention Notes:** Parser resolves inheritance with cycle/unresolved states. Reuse common certificate assessment with explicit time/identity/trust inputs.

**Concrete Requirements:** F5_BIGIP. Assess active management and bound frontend protocols/weak suites. Separately assess backend ServerSSL certificate verification and plaintext backend use only where encrypted backend policy is explicitly required. Resolve public certificates when present; flag proven expired/weak or identity-invalid material under supplied context. SCF referring to absent files stays unknown; never open arbitrary referenced paths or inspect private keys. Existing report interface; no live TLS connection.

**Test Requirements:** Mandatory suite plus inherited weak parent/local override, unbound profile, same name across partitions, certificate file reference without material, disabled virtual and absent assessment time.

**Acceptance Criteria:** Direction and attachment are stated; defaults are release-qualified and no configured certificate is represented as the one observed on a live endpoint.

<a id="sc-016"></a>
### SC-016 — F5 management SNMP and trusted time

**Task ID and Title:** SC-016 — Bound SNMP access and authenticated NTP associations.

**Priority:** P1 unrestricted writable SNMP; P2 other management/time weaknesses.

**Status:** SNMP stage implemented (2026-09-24) from the TMOS `sys snmp` reference. Findings need an exported, reachable `allowed-addresses` scope (not loopback-only or `none`); the documented default is 127/localhost and is not graded. With that scope the tool reports: an any-address scope combined with communities; per-community well-known default names or `rw` access; and SNMPv3 users without `auth-privacy` or with MD5/DES. Community strings and user keys never leave the parser. NTP authentication remains an evidence gate: `sys ntp` has no key properties, and keys are only configurable through the unsupported raw `include` option, so configured servers are not graded. **Research 2026-09-25:** F5 [K14120](https://my.f5.com/manage/s/article/K14120): NTP authentication is not supported in tmsh or the GUI and is configured only through `sys ntp include` (`server <ip> key <n>` plus `trustedkey <n>`); keys live in `/etc/ntp/keys`, outside the export; tmsh `servers` entries "are for unencrypted NTP". A bounded NTP stage is unblocked: tmsh `servers` are unauthenticated by documentation; key existence stays unknown. **Implemented 2026-09-25:** `f5.bigip.ntp.unauthenticated_server` for tmsh `servers` entries and for `include` servers without a trusted key. A missing NTP configuration is not graded, because SCF completeness for `sys ntp` is not qualified.

**Source of Truth:** F5 NDM benchmark above; F5 parser `_FIELDS` and plugin have no SNMP/NTP analysis. Qualify exact NDM control text and TMOS `sys snmp`/`sys ntp` documentation before selecting policy thresholds.

**Linked Findings:** Missing protocol evidence rather than a defective existing detector.

**Dependencies:** Sanitized TMOS fixtures; verify how NTP authentication survives supported exports.

**Architecture/Convention Notes:** Reuse normalized SNMP and time records if sufficient; preserve effective access restrictions and unknown defaults.

**Concrete Requirements:** F5_BIGIP. Detect explicit default/weak community access, writable broad grants and inappropriate noAuth/noPriv users under active SNMP state. Resolve each active NTP server's authentication references if supported by export; configured servers alone cannot establish trusted time. Unsupported authentication evidence yields unassessed coverage. No CLI change or operational query.

**Test Requirements:** Mandatory suite plus read-only restricted community, writable unrestricted community, bound v3 security level, disabled service, unbound time key and secret redaction.

**Acceptance Criteria:** SNMP permissions and source scope are distinguished; unsupported NTP configuration never generates a fabricated missing-key finding.

<a id="sc-018"></a>
### SC-018 — SonicOS effective zone inspection

**Task ID and Title:** SC-018 — Zone/protocol activation and security-service exclusions.

**Priority:** P1 proven complete inspection bypass; P2 narrower content gaps.

**Status:** Vendor intent verified; E-CLI grammar qualification required. A research attempt on 2026-09-24 confirmed that IPS is enabled per zone (Object > Match Objects > Zones, "Enable IPS"), in addition to global enablement. The SonicWall CLI reference and knowledge-base pages were not machine-readable (bot protection), so the E-CLI zone syntax is still unverified. A sanitized `show current-config custom` export with zone security-service lines is needed before implementation. **Research 2026-09-25:** The SonicOS API schema names the zone attributes `intrusion_prevention`, `gateway_anti_virus`, `anti_spyware` and `app_control`. The CLI reference PDF is still unavailable to the tooling; the E-CLI export syntax remains unverified. **Implemented 2026-09-25 from the [SonicOS/X 7 E-CLI Reference Guide](https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf):** Zone mode switches `intrusion-prevention`/`gateway-anti-virus`/`anti-spyware` and their `no` forms; `sonicwall.sonicos.zone.security_service_disabled` is reported for an explicitly disabled service on a zone with an enabled interface when the global service is not itself disabled. Global services now also read the documented Config-mode blocks (`intrusion-prevention`, `gateway-antivirus`, `anti-spyware`, `capture-atp` with a child `enable`/`no enable`). The one-line `<service> enable` form used by the older fixtures was never documented and is kept only for compatibility. Zone defaults, protocol direction and exclusions stay open.

**Source of Truth:** S14; [Sonic plugin](../../src/analyze/sonicwall/plugins/sonicos_checks_plugin.py) `check_operations` checks global security-service toggles and Capture ATP dependencies; [parser](../../src/devices/sonicwall/sonicos.py) does not establish equivalent effective zone/protocol inspection.

**Linked Findings:** Partial inspection coverage; do not recreate global disabled-service checks.

**Dependencies:** SonicOS 7 supported custom E-CLI exports with zone enablement, applicable protocol inspection and exclusion lists. Generic SRG crosswalk only until an exact benchmark is established.

**Architecture/Convention Notes:** Typed per-service zone activation and exclusions; use explicit assessed traffic scope rather than zone names alone.

**Concrete Requirements:** SONICOS. Follow globally enabled IPS/antivirus/antispyware to applicable zones/protocols. Detect explicit disabled required zone protection and exclusions proven to cover the assessed traffic. Preserve vendor semantics of inbound/outbound protocol inspection. Unknown license/signature/runtime state stays unknown; an exclusion list's mere existence is not a vulnerability. Existing report/role interfaces suffice.

**Test Requirements:** Mandatory suite plus global-on/zone-off, narrow authorized exclusion, any-address bypass, protocol direction, disabled zone and unsupported old preference export.

**Acceptance Criteria:** Global enablement cannot alone establish active inspection; findings identify proven affected scope without inventing license or traffic state.

<a id="sc-021"></a>
### SC-021 — Separate crypto blacklists from qualified policy and certificate checks

**Task ID and Title:** SC-021 — Bound crypto-policy depth and certificate evidence.

**Priority:** P1 explicit weak active crypto; P2 additional certificate/policy constraints.

**Status:** IOS/XE selected HTTPS trustpoint public-certificate assessment and opt-in exact approved ASA IKE DH alternatives on enabled policy families implemented as bounded increments; An ASA PFS stage was added on 2026-09-24. An explicit `set pfs groupN` on a static crypto-map entry attached to an interface, or on a dynamic-map entry referenced by an attached map, is reported for the project's existing legacy group set (1/2/5/14; the ASA command reference removed 1/2/5 from IKE in 9.15). `set pfs` without a group is release-dependent and is not graded. ASA integrity depth and the other platform stages remain evidence/policy-gated. SC-021 remains partial.

**Source of Truth:** S04 VPN controls and source-linked platform crypto/certificate methods below. Existing obsolete-algorithm checks do not establish exact DH/hash/key-size policy or certificate validation. EOS eAPI TLS-profile selection is not full public-certificate assessment.

**Linked Findings:** Partial crypto coverage; credential-value blacklists, credential storage formats and negotiated algorithm policy remain distinct.

**Dependencies:** Inventory exact current rule thresholds before each increment. Qualify approved release/profile policy; use existing certificate evaluator and explicit assessment time/identities/trust anchors. Coordinate F5 through SC-015.

**Architecture/Convention Notes:** Parser owns active proposal/profile/certificate binding. Do not duplicate existing weak-algorithm IDs or mutate generic policy silently.

**Concrete Requirements:** Implement the bounded adapter stages below. Prioritize active management and VPN trust; no new blanket decryption requirement. Missing certificate material or ambiguous profile inheritance remains unknown. Small policy-selector extension only after approval; no claim of FIPS validation from algorithm choices.

| Adapter stage | Required evidence and concrete detection increment |
|---|---|
| ASA VPN | Extend effective bound proposals to the qualified S04 profile's allowed DH/integrity policy, including supported alternatives and PFS where applicable. Existing group 1/2/5/14 and SHA/MD5 findings remain; test a nonblacklisted group such as 15 against an explicitly selected minimum-16 profile. Do not blindly compare elliptic-curve group numbers numerically. |
| ARISTA_EOS management | Follow active eAPI SSL-profile certificate declarations to public certificate material when supplied; evaluate time, intended identity and trust with explicit context. Existing profile/certificate-presence and TLS 1.0/1.1 findings remain. A filename alone cannot establish expiry or trust. |
| IOS_SWITCH / IOS_ROUTER / IOS_CATALYST / IOS_XE HTTPS | Qualify and parse the active HTTP secure-server trustpoint binding and exported public certificate chain. Assess weak public keys/signatures and context-dependent expiry/identity only for the selected chain. Do not grade unused trustpoints or request private-key export. |
| JUNOS management | Qualify active HTTPS local-certificate/system-generated selection and public-material availability independently from existing RadSec certificate-binding checks. Assess the active management identity when evidence exists; file-only or operationally stored material remains unknown. |
| SONICOS management | Extend existing selected self-signed certificate-type assessment to public certificate properties only if the supported E-CLI or a separately qualified companion export contains them. Keep type selection and cryptographic validity distinct. |
| HP_PROCURVE management | First establish whether AOS-S 16.10/16.11 saved exports expose the active HTTPS certificate and relevant public properties. If not, deliver explicit unsupported coverage rather than a detector; a new companion input requires a separate scoped contract. |

FORTIOS, PAN_OS and ASA management already have public-certificate assessment; they are **not** assigned duplicate certificate implementations here. Additional crypto-policy mappings on those paths require a separately demonstrated concrete gap, not a generic expansion instruction. F5 is owned by SC-015.

**Test Requirements:** Mandatory suite plus nonblacklisted-but-profile-disallowed proposal, unbound weak proposal, valid generic-versus-strict profile, absent public material and explicit assessment-time boundary.

**Acceptance Criteria:** Each increment has a named active binding, source-qualified exact policy and separate tests; no claim that all crypto or all certificates are covered by finishing the first adapter.

## Wave 3 — legacy and export qualification

These are smaller-demand or evidence-limited tracks. Do not hold ready current-platform tasks for them. Genuine unavailable input must become honest coverage, not speculative security findings.

<a id="sc-017"></a>
### SC-017 — FW1 anti-spoof topology and implied policy

**Task ID and Title:** SC-017 — Effective firewall policy beyond explicit rule rows.

**Priority:** P1 impact, evidence-gated implementation.

**Status:** Evidence gate for exact FW1 export schema/release.

**Source of Truth:** S15 and S07; [FW1 parser](../../src/devices/checkpoint/fw1.py), [baseline](../../src/analyze/checkpoint/plugins/fw1_baseline_plugin.py). Explicit rules/cleanup/stealth/install-scope analysis does not model interface anti-spoof topology or implied/global rules.

**Linked Findings:** Missing policy evidence, not missing basic cleanup/stealth detectors.

**Dependencies:** Sanitized matched objects.C/rules.C plus documented global properties for the target release. Do not substitute Gaia CLI syntax.

**Architecture/Convention Notes:** Model implied rule ordering and install targets separately before merging into bounded effective-policy analysis.

**Concrete Requirements:** CHECKPOINT_FW1. Parse interface topology, anti-spoof enabled/action scope and exported implied-rule controls where available. Detect explicitly disabled applicable anti-spoofing and proven broad implied permits. If implied rules are unavailable, disclose that explicit policy coverage excludes them; do not claim complete default-deny compliance. No OS posture inference or registry addition. Optional companion file needs a provenance-checked input contract.

**Test Requirements:** Mandatory suite plus anti-spoof detect-only versus prevent, explicit deny overridden by documented implied permit order, different install targets and missing global properties.

**Acceptance Criteria:** The implemented subset names its exact export revision; unavailable implied policy produces bounded coverage rather than invented permit/deny behavior.

<a id="sc-019"></a>
### SC-019 — Qualify ScreenOS screens and authenticated time

**Task ID and Title:** SC-019 — Legacy zone protection and time evidence.

**Priority:** P2; limited legacy maintenance scope.

**Status:** Evidence gate.

**Source of Truth:** [ScreenOS baseline](../../src/analyze/juniper/plugins/screenos_baseline_plugin.py) `check_ntp` checks server presence; no zone-screen evaluation. S08 is motivation only, not ScreenOS grammar. [RV-008](REALWORLD_VALIDATION_TASKS.md#rv-008) separately owns anti-replay research.

**Linked Findings:** Missing legacy parser/control evidence; existing lifecycle/default-policy/session checks are retained.

**Dependencies:** Obtain authenticated vendor 6.2/6.3 command references, supported defaults and sanitized exports. Demonstrate actual user/fixture demand before broadening this EOL platform.

**Architecture/Convention Notes:** Keep ScreenOS independent from Junos; effective set/unset zone bindings and time associations in typed parser records.

**Concrete Requirements:** SCREENOS. First document supported screen protections, bindings and time authentication capability by release. Then detect explicit disabled required zone protections and supported unauthenticated time associations only in complete assessed scope. Unsupported time authentication remains unsupported. Do not introduce modern SNMPv3 assumptions or duplicate lifecycle warnings. No new CLI interface.

**Test Requirements:** Mandatory suite after qualification, with set/unset override, bound/unbound screen, restricted trusted zone and unknown release.

**Acceptance Criteria:** Research stage yields a source/fixture decision; no new finding ships without ScreenOS-specific semantics. Anti-replay remains RV-008, not a duplicate task.

<a id="sc-020"></a>
### SC-020 — Qualify PIX independently from ASA

**Task ID and Title:** SC-020 — Honest legacy PIX ACL and management coverage.

**Priority:** P1 coverage integrity; new security checks remain evidence-gated.

**Status:** Evidence gate with a reproduced historical coverage concern.

**Source of Truth:** [RW-020](REALWORLD_VALIDATION_FINDINGS.md#RW-020), [registry](../../src/devices/registry.py) and ASA parser shared by PIX. Old PIX examples with bound ACLs yielded zero known policies.

**Linked Findings:** Existing external detection concern, referenced rather than duplicated as a new vulnerability.

**Dependencies:** Vendor PIX 6.3 syntax and representative fixtures; explicit decision whether maintenance demand justifies independent support. ASA STIG is not applicable evidence for old defaults.

**Architecture/Convention Notes:** No registry alias may imply dialect parity; choose a qualified compatibility layer or explicit unsupported export result.

**Concrete Requirements:** PIX. Establish supported ACL/object/interface binding and core management grammar, including NAT-era differences. Make known unsupported input disclose unassessed filtering rather than successful empty coverage. Only then add source-qualified high-impact cleartext management, unrestricted access and broad bound-policy detections. Existing coverage interface should suffice; distinct parser registration only if qualification requires it.

**Test Requirements:** Mandatory suite plus sanitized RW-020 command forms, legitimate zero-policy export, unsupported release, ASA regression negatives and complete-versus-snippet input.

**Acceptance Criteria:** PIX support claims match tested dialects; zero parsed policies never silently implies complete secure filtering on a known unsupported export.

<a id="sc-023"></a>
### SC-023 — Qualify optional Check Point OS posture input

**Task ID and Title:** SC-023 — Separate gateway/management OS evidence from policy exports.

**Priority:** P2 prerequisite to high-risk management checks.

**Status:** First stage implemented 2026-09-25 as a separate family, `CHECKPOINT_GAIA` (`-d checkpoint-gaia`), for the Gaia Clish `show configuration` output. Checks come from the R81 Gaia Administration Guide (Network-Access, SNMP, Password Policy, Session, Messages pages): Telnet on, SNMP default/read-write communities and `agent-version any`, SNMPv3 below authPriv, deny-on-fail off (documented default), history checking off, complexity 1, minimum length below 8, idle timeout above 10 minutes, banner off. A companion-file design was dropped because the Gaia export is self-contained and needs no policy provenance. Remaining (maintainer-approved 2026-09-25): validation against a real export; management source restriction (`add allowed-client`); web UI TLS and port; SSH server ciphers; RADIUS/TACACS+ servers and their keys; NTP authentication; remote syslog destinations and transport; and the Gaia items of [SC-030](#sc-030) (bash shells, expert password) and [SC-038](#sc-038) (ClusterXL CCP encryption).

**Source of Truth:** Check Point benchmark applicability table; FW1 parser accepts policy export, not a Gaia operating-system configuration. No source supports grading OS AAA/SNMP/time/TLS from that input.

**Linked Findings:** Unsupported evidence scope, not a missing policy parser field.

**Dependencies:** Verify current benchmark status, exact Gaia/export release, export availability and maintenance value. `NEEDS_RESEARCH` for benchmark currency; `NEEDS_HUMAN_REVIEW` for deployment applicability.

**Architecture/Convention Notes:** Design a provenance-checked companion artifact with gateway identity/release match, separate completeness and no overwrite of policy provenance.

**Concrete Requirements:** CHECKPOINT_FW1 plus explicitly qualified future companion input. Deliver an input contract and representative fixture first, then separate implementation subtasks for high-risk administrative authentication, management reachability and weak management crypto that the input can actually prove. Do not create fictitious absence findings during policy-only scans. This task explicitly requires an input-interface design; a new device ID is not assumed.

**Test Requirements:** Contract tests for mismatched gateway/release, missing companion, malformed input and redaction; mandatory implementation suite when a parser stage is authorized.

**Acceptance Criteria:** Policy-only analysis remains valid with OS posture unassessed; companion support and benchmark mapping are explicit before detectors are scheduled.

<a id="sc-024"></a>
### SC-024 — Qualify F5 module-specific protection

**Task ID and Title:** SC-024 — AFM/APM/WAF scope and active-policy evidence.

**Priority:** P2 prerequisite; proven bypasses may warrant P1 implementation later.

**Status:** First stage implemented 2026-09-25 from F5 documentation: `f5.bigip.afm.default_accept` (AFM provisioned and `tm.fw.defaultaction` accept, or absent: ADC mode is the default, F5 ID813165), `f5.bigip.asm.inactive_policy` and `f5.bigip.asm.transparent_policy` for ASM policies bound to an enabled virtual server through an `ltm policy` enable action. Remaining: validation against a real export; APM access-policy bypass; AFM rule contents.

**Source of Truth:** S13 and F5 Firewall/VPN benchmarks in catalog; current adapter covers basic TMOS/LTM, not module-specific policy effectiveness.

**Linked Findings:** Missing module evidence, not proof every BIG-IP needs AFM, APM and WAF.

**Dependencies:** Real sanitized SCF/tmsh exports, provisioning/module identity, active virtual-to-policy binding, license evidence limitations and intended deployment role.

**Architecture/Convention Notes:** Extend supported saved-export grammar only; UCS and F5OS stay separate unqualified formats.

**Concrete Requirements:** F5_BIGIP. Produce a module-by-export feasibility matrix and exact high-risk candidates: explicit bypass/transparent-only enforcement on an assessed protective path, unrestricted AFM default policy, or APM authentication bypass where demonstrable. Split each verified candidate into a bounded detector subtask with control ID, objects, bindings, unknown handling and fixtures. Do not implement broad missing-module rules from a basic LTM export. Existing report interface; module-role context only if justified.

**Test Requirements:** Positive bound bypass, secure enforcement, inactive policy, absent module, incomplete export and redaction fixtures for each qualified candidate, then mandatory suite.

**Acceptance Criteria:** Research establishes which controls can actually be evaluated; no generic WAF/AFM/APM absence finding ships without role and evidence.

## Wave 4 — cleartext protocols, credential protection and attack-simplifying settings

Added **2026-09-25** at the maintainer's request. Scope: services and settings that send secrets or management traffic in clear text, store credentials so they can be recovered, or otherwise make an attacker's job easier. **Cisco (IOS, IOS-XE, ASA, PIX), FortiGate, Check Point (FW1 and Gaia) and F5 BIG-IP come first**, for current and legacy releases; other families are listed as later stages only where the same state exists.

Every task below is an **evidence gate**: the sources named are *candidate* sources recorded when the task was written and must be read and cited (URL, release, default) before code is written. Syntax, defaults and release applicability are `NEEDS_RESEARCH` until then. The mandatory implementation rules at the top of this file apply unchanged. Absent settings produce findings only where a vendor documents an insecure default for the exported release (`DOCUMENTED_DEFAULT`), or where the task says a required setting is missing (`REQUIRED_SETTING_MISSING`).

Not scheduled (maintainer decision, 2026-09-25): SNMPv1/v2c community checks for PAN-OS and SonicOS, and SonicOS Telnet management. Gaia OS remote AAA, NTP, syslog, web UI and allowed clients are owned by [SC-023](#sc-023); F5 APM by [SC-024](#sc-024).

| Task | Priority | Title | First families |
|---|---|---|---|
| [SC-025](#sc-025) | P1 | Smart Install (`vstack`) exposure | IOS, IOS-XE switches |
| [SC-026](#sc-026) | P2 | IOS legacy and cleartext services, IOS-XE insecure gNMI | IOS, IOS-XE |
| [SC-027](#sc-027) | P2 | IOS HTTPS server TLS version and ciphers | IOS, IOS-XE |
| [SC-028](#sc-028) | P2 | First-hop redundancy (HSRP/VRRP/GLBP) authentication | IOS, IOS-XE; later EOS, Junos |
| [SC-029](#sc-029) | P2 | VTP domain protection | IOS, IOS-XE switches |
| [SC-030](#sc-030) | P2 | Root login and privileged shell exposure | F5, Check Point Gaia; later EOS |
| [SC-031](#sc-031) | P1 | Cleartext or weakly protected AAA transport | IOS, ASA, FortiOS, F5 |
| [SC-032](#sc-032) | P2 | Cleartext log transport | IOS-XE, ASA, FortiOS, F5 |
| [SC-033](#sc-033) | P2 | NTP service exposure (serving and control queries) | IOS, FortiOS, F5; later EOS, Junos |
| [SC-034](#sc-034) | P1 | IKEv1 aggressive mode with pre-shared keys | IOS, ASA, FortiOS, F5; Check Point sample-gated |
| [SC-035](#sc-035) | P1 | Recoverable stored secrets | IOS, ASA, FortiOS |
| [SC-036](#sc-036) | P2 | Credentials embedded outside credential stores | IOS, ASA, F5 |
| [SC-037](#sc-037) | P2 | SNMP notification communities | IOS, ASA, FortiOS, F5 |
| [SC-038](#sc-038) | P2 | FortiGate HA heartbeat authentication and encryption | FortiOS; Check Point ClusterXL research |
| [SC-039](#sc-039) | P1 | FortiGate SSL-VPN exposure and hardening | FortiOS |
| [SC-040](#sc-040) | P2 | FortiGate physical and boot-time recovery paths | FortiOS |
| [SC-041](#sc-041) | P1 | F5 self-IP port lockdown | F5 |
| [SC-042](#sc-042) | P2 | F5 data-plane TLS and persistence information leaks | F5 |
| [SC-043](#sc-043) | P2 | Risky cleartext services allowed by firewall policy | Check Point FW1, ASA, FortiOS, F5 virtuals |
| [SC-044](#sc-044) | P2 | Release-gated insecure defaults on legacy releases | IOS 12.x, ASA 8.x, PIX, FortiOS 5.x/6.0, BIG-IP 11.x/12.x, FW1 R6x/R7x |

<a id="sc-025"></a>
### SC-025 — Smart Install (`vstack`) exposure

**Task ID and Title:** SC-025 — Report an enabled Cisco Smart Install client/director.

**Priority:** P1. Smart Install accepts unauthenticated commands on TCP 4786 that can replace the configuration or image; it has been used in mass exploitation.

**Status:** First stage implemented 2026-09-26: `cisco.ios.services.smart_install` for an effective `vstack` line (IOS and IOS-XE). Source: cisco-sa-20180409-smi (releases with CSCvd36820 show `vstack` when enabled and `no vstack` when disabled; older releases showed neither, so absence stays unknown) and cisco-sa-20170214-smi. Remaining: a release-gated default for pre-CSCvd36820 switch releases ([SC-044](#sc-044)).

**Source of Truth:** Candidates: Cisco advisories on Smart Install protocol misuse (cisco-sa-20170214-smi) and CVE-2018-0171 (cisco-sa-20180328-smi2); Cisco IOS hardening guidance; IOS-XE switch NDM STIG entries for Smart Install, if present.

**Linked Findings:** None existing; `cisco.ios.services.unnecessary` does not cover `vstack`.

**Dependencies:** Per-release default (enabled by default on many older switch releases, disabled in later ones; `no vstack` appears in exports where it was turned off). Which platforms support the feature at all (switches, not routers).

**Architecture/Convention Notes:** IOS parser exposes the effective `vstack` state and release; plugin in the IOS baseline. Routers and unknown platforms stay unknown, never "secure".

**Concrete Requirements:** IOS_SWITCH, IOS_CATALYST, IOS_XE. Explicit `vstack` → finding (`EXPLICIT_VALUE`). No `vstack`/`no vstack` line → `DOCUMENTED_DEFAULT` finding only on a release the vendor documents as enabled by default; otherwise unknown. `vstack director` also reported.

**Test Requirements:** Mandatory suite, including explicit on, explicit off, absent on a default-on release, absent on a default-off release and a router export.

**Acceptance Criteria:** No finding from absence unless a cited source documents the default for the exported release.

<a id="sc-026"></a>
### SC-026 — IOS legacy and cleartext services, IOS-XE insecure gNMI

**Task ID and Title:** SC-026 — Extend `cisco.ios.services.unnecessary` and add insecure model-driven management.

**Priority:** P1 for cleartext or authentication-bypassing network management APIs; P2 for bounded DNS exposure and remaining legacy service breadth. DNS is a risk only when the unsafe service/access combination is proven.

**Status:** Implemented 2026-09-26 (explicit states only): `services.unnecessary` now resolves `no` removal and adds `service pad`, `ip finger`, `ip identd` and `mop enabled` on interfaces that are not shut down; new `cisco.ios.services.remote_shell` (`ip rcmd rsh-enable`/`rcp-enable`), `cisco.ios.services.tftp_server` (`tftp-server`) and `cisco.ios.management.insecure_protocol` for IOS-XE `gnxi server`. Sources: Cisco IOS hardening guide, IOS XE File Transfer Services guide, IOS XE Programmability gNMI guide, IOS XE Security Warnings Reference. Remaining: `ip dns server`, release-gated defaults ([SC-044](#sc-044)). Update 2026-09-26: `ip dns server` was not added — the IOS DNS configuration guide gives no security guidance or default for it, so no vendor-backed rule exists yet.

**2026-09-26 extensions (A3/A10):** Keep the implemented IOS legacy-service and insecure gNMI stages. **Junos REST HTTP and classic JET gRPC clear-text stages implemented 2026-09-28:** explicit non-loopback HTTP addresses produce a clear-text transport finding; REST listener records retain port and allowed sources. The gRPC check requires both an explicit valid network address and port; its typed record retains routing instance and skip-authentication metadata without claiming authentication bypass. Both preserve inactive/malformed/inherited uncertainty. Omitted listener defaults, gRPC authentication-bypass/TLS interactions, EOS management gRPC, effective NETCONF/RESTCONF restrictions and bounded DNS exposure remain open. DNS enablement alone still does not prove an open resolver.


**Source of Truth:** Candidates: Cisco Guide to Harden Cisco IOS Devices; IOS command references for each command; IOS-XE programmability guide (gNMI `gnxi server` vs `gnxi secure-server`); IOS/IOS-XE NDM STIGs.

Additional evidence: [Junos service inventory](../../src/devices/juniper/junos.py), `get_services`, and legacy-service plugin lack REST/gRPC evaluation. [Juniper REST API configuration](https://www.juniper.net/documentation/us/en/software/junos/rest-api/topics/task/rest-api-configuring.html) recommends HTTPS; [Junos telemetry guide](https://www.juniper.net/documentation/us/en/software/junos/interfaces-telemetry/interfaces-telemetry.pdf) documents explicit gRPC cleartext and authentication bypass. [RFC 5358](https://www.rfc-editor.org/rfc/rfc5358.html) supplies restricted-recursion intent; [FortiOS DNS-server reference](https://docs.fortinet.com/document/fortigate/6.2.4/cli-reference/103620/system-dns-server) supplies initial listener/mode syntax. Reviewed 2026-09-26; qualify exact deployment releases before implementation.


**Linked Findings:** Current list covers only `service finger`, `service tcp-small-servers`, `service udp-small-servers`, `ip bootp server`.

**Dependencies:** Release defaults for `service pad`, `ip bootp server`, `mop enabled` (interface), `ip finger` (newer syntax of `service finger`). Which of these the exported release still supports.

**Architecture/Convention Notes:** Keep one aggregated rule for classic small services; give distinct IDs only for distinct risks (a cleartext file server and a DNS resolver are different from finger).

**Concrete Requirements:** IOS IDs and IOS_XE. Candidates: `service pad`, `ip finger`, `ip identd`, `mop enabled` on an active interface, `ip rcmd rsh-enable` / `ip rcmd rcp-enable` (cleartext remote shell and copy), `tftp-server` (cleartext file server), `ip dns server` (open resolver), IOS-XE `gnxi server` / insecure gNMI listener. Release-gated `DOCUMENTED_DEFAULT` only where sourced (see also [SC-044](#sc-044)).

**P1 automation/API stages:** JUNOS first: resolve REST HTTP and explicit gRPC cleartext/authentication-bypass network listeners. ARISTA_EOS next: qualify gRPC/gNMI transport/authentication/listener restrictions. IOS_XE: assess effective NETCONF/RESTCONF access restrictions beyond existing `gnxi server`. Parse listener address/port, VRF, transport, authentication, inheritance and attached restrictions as typed evidence. Distinguish local-only sockets and disabled listeners. NETCONF/RESTCONF are not inherently unsafe; detect the unsafe property. Reuse SC-046 for management ACL resolution, and leave unresolved authentication/transport state unknown.

**P2 DNS stages:** FORTIOS interface-bound DNS and IOS/IOS_XE DNS server first; PAN_OS/JUNOS only after independent grammar qualification. Resolve explicit recursive/forwarding mode, listener/interface and applicable source restrictions. Report proven permission for arbitrary untrusted clients, not every `ip dns server` line. Separate DNS clients, internal resolvers, authoritative-only service and forwarding services. Qualify zone-transfer controls only where exported. Do not issue DNS queries. Missing topology/access-filter semantics stay unknown. Existing roles/output suffice; parser-owned endpoint/service records are required.

These additions supersede the original shorthand equating `ip dns server` with an open resolver. No additional omitted/default-setting rules are requested; SC-044 remains separately owned.


**Test Requirements:** Mandatory suite per command, including `no` removal and interface scope for `mop`.

Add Junos REST HTTP/HTTPS, gRPC bypass versus authenticated TLS, local-only socket, disabled listener, IPv4/IPv6/VRF restrictions and unknown inherited profile; DNS client-only, authoritative-only, restricted internal resolver, explicitly broad forwarding/recursive service and unresolved source ACL. Apply the mandatory public-pipeline/redaction suite.


**Acceptance Criteria:** Each new command cites a vendor source; no default assumed across release trains.

A network API is assessed independently of interactive SSH/J-Web. DNS findings prove configured service admission, not Internet reachability. Secure APIs and ordinary DNS clients are not classified as unsafe merely because they are enabled.

<a id="sc-027"></a>
### SC-027 — IOS HTTPS server TLS version and ciphers

**Task ID and Title:** SC-027 — Weak TLS on the IOS/IOS-XE HTTPS management server.

**Priority:** P2.

**Status:** Implemented 2026-09-26: `cisco.ios.tls.minimum_version` (`ip http tls-version TLSv1.0|TLSv1.1`) and `cisco.ios.tls.weak_cipher` (SHA-1, DES/3DES, RC4, MD5, NULL/export suites in `ip http secure-ciphersuite`), only while `ip http secure-server` is enabled. Source: Cisco IOS XE Security Warnings Reference. Absent settings stay unassessed.

**Source of Truth:** Candidates: IOS-XE HTTP server configuration guide (`ip http tls-version`, `ip http secure-ciphersuite`); IOS-XE NDM STIG TLS entries.

**Linked Findings:** IOS already checks the HTTPS certificate (`cisco.ios.management.https_*`) but not protocol version or cipher suites. ASA, FortiOS, PAN-OS, F5 and EOS already have equivalent checks.

**Dependencies:** Per-release default TLS versions and cipher lists; only when `ip http secure-server` is effective.

**Architecture/Convention Notes:** Reuse the existing HTTPS binding resolution; follow the rule-ID pattern of other families (`tls.minimum_version`, `tls.weak_cipher`).

**Concrete Requirements:** IOS IDs and IOS_XE. Explicit TLS 1.0/1.1 or legacy/export/RC4/3DES cipher suites → finding. Absent settings → documented default only where sourced.

**Test Requirements:** Mandatory suite; secure-server disabled suppresses the finding.

**Acceptance Criteria:** Same severity model as the ASA `tls.*` rules.

<a id="sc-028"></a>
### SC-028 — First-hop redundancy authentication

**Task ID and Title:** SC-028 — HSRP, VRRP and GLBP groups without authentication or with plain-text authentication.

**Priority:** P2. A host on the segment can take over the default gateway and intercept traffic.

**Status:** First stage implemented 2026-09-26 for IOS/IOS-XE: `cisco.ios.fhrp.authentication` for HSRP, VRRPv2 and GLBP groups on interfaces that are not shut down, when no MD5 authentication is configured (missing setting) or plain-text authentication is explicit. VRRPv3 (`vrrp N address-family`) is not assessed. Sources: IOS FHRP command reference, Cisco HSRP guide. Remaining: EOS and Junos VRRP. Update 2026-09-26: Junos `juniper.junos.fhrp.authentication` for VRRP groups on enabled interfaces without `authentication-type md5` (default none) or with `simple`; skipped when `protocols vrrp version-3` is set (Junos CLI reference). Arista EOS: the vendor VRRP page could not be read (access blocked), so EOS stays open.

**Source of Truth:** Candidates: IOS First Hop Redundancy Protocols configuration guides (`standby authentication md5`, `vrrp authentication`, `glbp authentication`); router STIG entries on FHRP authentication; later Arista EOS VRRP and Junos VRRP references.

**Linked Findings:** None.

**Dependencies:** VRRPv3 (RFC 5798) removed authentication, so a v3 group cannot be reported for missing authentication. Plain-text (`authentication text`) is weaker than MD5 key chains.

**Architecture/Convention Notes:** Parser returns typed FHRP groups per interface with protocol, version and auth mode; key strings redacted. Only groups on enabled interfaces are assessed.

**Concrete Requirements:** First IOS IDs and IOS_XE; later ARISTA_EOS and JUNOS. Plain-text auth → finding (`EXPLICIT_VALUE`). No auth on HSRP/GLBP/VRRPv2 → finding with the documented no-authentication default. VRRPv3 → not applicable.

**Test Requirements:** Mandatory suite, including VRRPv3, shutdown interface, key-chain reference that does not resolve.

**Acceptance Criteria:** Role-neutral: the finding states that the segment must be trusted for the risk to be low.

<a id="sc-029"></a>
### SC-029 — VTP domain protection

**Task ID and Title:** SC-029 — VTP server/client mode without a domain password.

**Priority:** P2. A rogue switch with a higher revision can overwrite or delete the VLAN database.

**Status:** Blocked by export evidence (checked 2026-09-26). The Catalyst VTP guide states that only VTP mode and domain name are saved in the running configuration (and only in transparent mode); the VTP password lives in the VLAN database and is shown only by `show vtp password`. A running-config export therefore cannot prove that a password is missing. Revisit only with a companion `show vtp status`/`show vtp password` input.

**Source of Truth:** Candidates: Catalyst VTP configuration guides (VTP v1/v2 `vtp password`, VTP v3 primary server and hidden password); switch L2 STIG entries.

**Linked Findings:** None.

**Dependencies:** Whether exports record VTP mode and password (VTP settings are partly stored in `vlan.dat`, not always in the running configuration); per-release default mode (server).

**Architecture/Convention Notes:** If the export does not show VTP state, report unknown, never a finding.

**Concrete Requirements:** IOS_SWITCH, IOS_CATALYST and IOS_XE switches. Running-config alone cannot establish whether a VTP password exists. Do not implement a missing-password finding from an absent `vtp password` line. Qualify a supplied companion export with mode/version/domain and password-presence evidence before assessment; never request a live command or expose a password. Transparent/off and VTP v3 require their own applicability. The documented export-evidence block takes precedence over the superseded presence-only proposal.

**Test Requirements:** Mandatory suite including a router export and an export with no VTP lines.

**Acceptance Criteria:** No finding from VTP absence alone.

<a id="sc-030"></a>
### SC-030 — Root login and privileged shell exposure

**Task ID and Title:** SC-030 — Direct root access and general-purpose shells for administrators.

**Priority:** P2.

**Status:** First stage implemented 2026-09-26: F5 `auth.root_login_enabled` (explicit `sys db systemauth.disablerootlogin false`), `auth.user_bash_shell`, `auth.remote_default_admin` (explicit `auth remote-user default-role admin`; default no-access) and `password_policy.history_disabled` (enforcement on, `password-memory` 0 or default 0); Gaia `auth.user_bash_shell`. Sources: tmsh auth user/remote-user/password-policy references, F5 DevCentral lockdown article, Gaia Users page. Remaining: root-login default (no F5 statement of the default found), Gaia expert password, EOS.

**Source of Truth:** Candidates: F5 articles on disabling root login (`sys db systemauth.disablerootlogin`), user terminal access (`shell bash` vs `tmsh`) and remote-user default role/console access (`auth remote-user`); F5 NDM STIG; Check Point Gaia Administration Guide (users, shell, expert password).

**Linked Findings:** `juniper.junos.ssh.root_login`.

**Dependencies:** Documented defaults per release (F5 allows root login by default on many releases; verify).

**Architecture/Convention Notes:** F5 and Gaia parsers already model users; extend records with shell and role, no secret values.

**Concrete Requirements:** F5_BIGIP: root SSH login allowed (explicit `false` or documented default); local users with `shell bash`; `auth remote-user` with `default-role admin` or `remote-console-access` bash; password history disabled (`auth password-policy password-memory 0`). CHECKPOINT_GAIA: non-admin users with `/bin/bash`, no expert password where the export shows it. Later ARISTA_EOS if a root/bash equivalent is sourced. IOS/ASA/FortiOS have no root account and are not applicable.

**Test Requirements:** Mandatory suite.

**Acceptance Criteria:** Each state cites its vendor source; administrators who need bash for operational reasons are covered by the recommendation text, not suppressed.

<a id="sc-031"></a>
### SC-031 — Cleartext or weakly protected AAA transport

**Task ID and Title:** SC-031 — TACACS+/RADIUS without keys, LDAP without TLS, RADIUS without Message-Authenticator.

**Priority:** P1. Administrator passwords travel in these exchanges.

**Status:** First stage implemented 2026-09-26: `cisco.ios.aaa.tacacs_key_missing` (TACACS+ server used by an AAA method list, no per-server or global key; RFC 8907 §4.5 forbids unobfuscated mode), `cisco.asa.aaa.tacacs_key_missing` and `cisco.asa.aaa.ldap_cleartext` (bound server groups; ASA command reference `ldap-over-ssl`), `fortinet.fortios.aaa.ldap_cleartext` (`secure` default disable per the 7.4 CLI reference) and `fortinet.fortios.aaa.ldap_server_identity`, for LDAP servers referenced by a user group. Remaining: IOS LDAP, RADIUS Message-Authenticator for IOS/ASA/F5. Update 2026-09-26: RADIUS Message-Authenticator for IOS/ASA/F5 was researched; Cisco's Blast-RADIUS mitigation note gives no device-side CLI and points to RADIUS over (D)TLS, so no rule was added.

**Source of Truth:** Candidates: IOS AAA configuration guides (`tacacs server` / `radius server` `key`, `ldap server` secure mode); ASA CLI book 1 AAA chapter (`ldap-over-ssl enable`, `key`); FortiOS `config user ldap` (`set secure disable|starttls|ldaps`, `server-identity-check`); CVE-2024-3596 (BlastRADIUS) vendor advisories for Cisco, F5 and Fortinet; F5 remote-auth RADIUS/TACACS+ references.

**Linked Findings:** FortiOS and Junos already check RADIUS Message-Authenticator and RadSec; F5 already checks LDAP `ssl disabled` and peer checks. Keep those IDs.

**Dependencies:** Only servers bound to an active administrative or user-authentication method are assessed. Key presence is visible even when the value is masked.

**Architecture/Convention Notes:** Server records carry `key_present`, transport and binding; values stay redacted. Reuse existing AAA binding resolution.

**Concrete Requirements:** IOS IDs, IOS_XE, ASA: bound TACACS+/RADIUS server without a key; LDAP server bound without TLS; RADIUS without Message-Authenticator where the release supports it. FORTIOS: `config user ldap` `secure disable` on a server used by an admin or user group, and `server-identity-check disable`. F5_BIGIP: RADIUS Message-Authenticator stage if sourced. Check Point Gaia AAA belongs to [SC-023](#sc-023).

**Test Requirements:** Mandatory suite, including unbound servers and masked keys.

**Acceptance Criteria:** Unbound or unresolved servers never produce findings.

<a id="sc-032"></a>
### SC-032 — Cleartext log transport

**Task ID and Title:** SC-032 — Remote logging without transport protection where the platform offers it.

**Priority:** P2. Logs reveal usernames, addresses and events and can be forged or suppressed in transit.

**Status:** First stage implemented 2026-09-26: `cisco.asa.logging.remote_cleartext` (logging host without `secure`; ASA command reference) and FortiAnalyzer `logging.remote_weak_tls` (`enc-algorithm low`) and `logging.remote_identity_unverified` (`certificate-verification disable`). Remaining: IOS-XE syslog over TLS (platform and release support not yet qualified), F5 syslog TLS.

**Source of Truth:** Candidates: IOS-XE `logging host ... transport tls`; ASA `logging host ... tcp/port secure`; FortiOS `config log fortianalyzer setting` (`enc-algorithm`, `reliable`); F5 remote syslog over TLS (syslog-ng include) articles; FortiGate FW STIG V-234141 (S10).

**Linked Findings:** S10.

**Dependencies:** Whether the exported release supports protected transport; do not report platforms that have no option.

**Architecture/Convention Notes:** Extend existing logging destination records with transport and protection state.

**Concrete Requirements:** IOS_XE (IOS only where supported), ASA, FORTIOS (FortiAnalyzer/FortiCloud destinations), F5_BIGIP (if the include-based TLS path can be parsed reliably, otherwise unknown).

**Test Requirements:** Mandatory suite.

**Acceptance Criteria:** Plain UDP syslog on platforms without a TLS option is informational at most, not a finding.

<a id="sc-033"></a>
### SC-033 — NTP service exposure

**Task ID and Title:** SC-033 — Device serves NTP or answers NTP control queries without restriction.

**Priority:** P2. Unrestricted mode 6/7 queries enable amplification attacks and information disclosure.

**Status:** First stage implemented 2026-09-26: `cisco.ios.ntp.server_exposed` (NTP configured, no `ntp access-group`; the command reference documents full access by default) and `fortinet.fortios.ntp.server_exposed` (`server-mode enable` on a WAN-role interface). Remaining: F5, EOS, Junos.

**Source of Truth:** Candidates: IOS NTP configuration guide (`ntp access-group peer|serve|serve-only|query-only`, `ntp allow mode control`, default behaviour when a server is configured); FortiOS `config system ntp` (`set server-mode enable`, `set interface`); F5 NTP `restrict` via include; later EOS `ntp serve`, Junos NTP.

**Linked Findings:** Existing NTP checks cover authentication and server presence, not serving.

**Dependencies:** Release defaults for serving (IOS answers once it is synchronised; verify).

**Architecture/Convention Notes:** Separate "serves time" from "authenticated upstream".

**Concrete Requirements:** IOS IDs, IOS_XE: serving/control without `ntp access-group`. FORTIOS: `server-mode enable` on an assessed external interface. F5_BIGIP: only if restrict lines are parsed reliably. Later ARISTA_EOS, JUNOS.

**Test Requirements:** Mandatory suite, including interface role context.

**Acceptance Criteria:** Internal-only serving is not reported without an assessed external role.

<a id="sc-034"></a>
### SC-034 — IKEv1 aggressive mode with pre-shared keys

**Task ID and Title:** SC-034 — Aggressive mode exposes a hash of the pre-shared key to offline cracking.

**Priority:** P1 for gateways with pre-shared-key peers.

**Status:** First stage implemented 2026-09-26: `cisco.ios.vpn.ike_aggressive_mode` (IKEv1 pre-shared keys and no `crypto isakmp aggressive-mode disable`; the command reference says IOS processes all aggressive-mode SAs otherwise), `cisco.asa.vpn.ike_aggressive_mode` (IKEv1 enabled on an interface, IKEv1 PSK tunnel group, no `crypto ikev1 am-disable`/`crypto isakmp am-disable`; default enabled per the command reference), `fortinet.fortios.vpn.ike_aggressive_mode` (explicit `mode aggressive`, IKEv1, PSK; CLI defaults main/1/psk) and `f5.bigip.vpn.ike_aggressive_mode` (`net ipsec ike-peer` mode aggressive with pre-shared-key, version v1 default). Remaining: Check Point (sample-gated).

**Source of Truth:** Candidates: IOS `crypto isakmp aggressive-mode disable`; ASA `crypto ikev1 am-disable` (default behaviour per release); FortiOS phase1 `set mode aggressive`; F5 `net ipsec ike-peer` `mode aggressive`; Check Point VPN community "aggressive mode" setting; NIST SP 800-77r1.

**Linked Findings:** Existing weak-proposal checks cover algorithms, not the exchange mode.

**Dependencies:** Only IKEv1 with pre-shared-key authentication; certificate-authenticated peers are not affected in the same way.

**Architecture/Convention Notes:** Reuse existing IKE/tunnel resolution per family.

**Concrete Requirements:** IOS IDs, IOS_XE, ASA, FORTIOS, F5_BIGIP; CHECKPOINT_FW1 once a sanitized sample is available.

**Test Requirements:** Mandatory suite, including IKEv2-only and certificate-authenticated peers.

**Acceptance Criteria:** Only active tunnels/peers are assessed.

<a id="sc-035"></a>
### SC-035 — Recoverable stored secrets

**Task ID and Title:** SC-035 — Secrets stored so that anyone with the configuration file can recover them.

**Priority:** P1. Configuration backups are commonly shared; recoverable keys turn a leaked file into working credentials.

**Status:** First stage implemented 2026-09-26: IOS `credentials.tacacs_key_storage`, `isakmp_pre_shared_key_storage` and `keyring_pre_shared_key_storage` (type 0/7; type 6 per the IOS XE Encrypted Preshared Key guide), ASA `credentials.tunnel_group_pre_shared_key_storage` and `aaa_server_key_storage` (clear-text value in a `more system:running-config` export; `*****` is masked/unknown, `8 ...` encrypted with the master passphrase), and FortiOS `credentials.private_data_storage` (non-administrator `ENC` secrets without `private-data-encryption`, FG-IR-19-007). Remaining: legacy FortiOS `AK1` administrator hashes (hash-format source not yet obtained), ASA empty enable default ([SC-044](#sc-044)). Update 2026-09-26: `fortinet.fortios.credentials.admin_hash_storage` on FortiOS 7.6.1+ for administrator hashes other than PBKDF2 (`PB2`); Fortinet's Enhanced administrator password security page documents SH2 (SHA256) and conversion at next login. `AK1` on older releases remains unsourced.

**Source of Truth:** Candidates: IOS `key config-key password-encrypt` + `password encryption aes` (type 6); ASA `key config-key password-encryption` + `password encryption aes`; FortiOS `config system global set private-data-encryption` and Fortinet PSIRT FG-IR-19-007 (CVE-2019-6693, static key for backup secrets); FortiOS admin password hash formats (legacy `AK1` vs `SH2`).

**Linked Findings:** `cisco.ios.credentials.*`, `cisco.asa.credentials.*`, `f5.bigip.credentials.local_plaintext`.

**Dependencies:** Which secret types each mechanism protects on the exported release; the master key itself is never in the export.

**Architecture/Convention Notes:** Parser reports storage type per secret without values (type 0/7/6, `ENC`, hash prefix).

**Concrete Requirements:** IOS IDs, IOS_XE: type 0 or 7 pre-shared, TACACS+/RADIUS or routing keys while type 6 is available → finding. ASA: equivalent. FORTIOS: `private-data-encryption` disabled while secrets are present; legacy `AK1` administrator hashes. ASA empty or default enable password on releases where that is the default (see [SC-044](#sc-044)).

**Test Requirements:** Mandatory suite; evidence must never contain the stored value.

**Acceptance Criteria:** Reversible storage is never described as a plaintext password unless it is one.

<a id="sc-036"></a>
### SC-036 — Credentials embedded outside credential stores

**Task ID and Title:** SC-036 — Passwords in URLs, file-transfer settings and health monitors.

**Priority:** P2.

**Status:** First stage implemented 2026-09-26 for IOS/IOS-XE: `credentials.ftp_client_storage` (`ip ftp password`), `credentials.http_client_storage` (`ip http client password`) and `credentials.url_storage` (`user:password@` in any URL); evidence is redacted. Source: Cisco IOS XE Security Warnings Reference. Remaining: ASA URLs, F5 monitors with basic-auth headers. Update 2026-09-26: F5 `credentials.monitor_storage` for HTTP/HTTPS monitors whose send string has an `Authorization: Basic` header (tmsh ltm monitor http reference); evidence is redacted.

**Source of Truth:** Candidates: IOS `ip ftp username/password`, `ip http client username/password`, `archive path` and `boot system` URL syntax; ASA `boot config`/URL-based settings; F5 `ltm monitor http/https` `send` strings with `Authorization: Basic` and monitor `username`/`password` properties.

**Linked Findings:** `cisco.ios.configuration.archive_transport` (cleartext transport, not embedded credentials).

**Dependencies:** How each platform masks these values in exports.

**Architecture/Convention Notes:** Redact the credential part of URLs and headers in evidence and inventory; expose them in `--show-secrets` only through parser-owned secret lines.

**Concrete Requirements:** IOS IDs, IOS_XE, ASA: `user:password@` in any file-transfer URL; `ip ftp password`; `ip http client password`. F5_BIGIP: monitors sending basic-auth headers or storing monitor passwords in clear.

**Test Requirements:** Mandatory suite with redaction tests for every new pattern.

**Acceptance Criteria:** No credential text reaches normal report evidence.

<a id="sc-037"></a>
### SC-037 — SNMP notification communities

**Task ID and Title:** SC-037 — SNMPv1/v2c traps and informs send the community string in clear text.

**Priority:** P2.

**Status:** Implemented 2026-09-26 for IOS/IOS-XE as `cisco.ios.snmp.legacy_version` (v1/v2c notification targets; version 1 when unspecified). ASA was already covered by `cisco.asa.snmp.legacy_version`. Remaining: FortiOS and F5 trap targets. Update 2026-09-26: F5 `snmp.legacy_version` for `sys snmp traps` targets with explicit version 1/2c. FortiOS SNMP communities (which also carry traps) are already reported by `snmp.legacy_community`.

**Source of Truth:** Candidates: IOS `snmp-server host ... version 1|2c <community>`; ASA `snmp-server host ... community`; FortiOS `config system snmp community` `config hosts` with `ha-direct`/trap settings; F5 `sys snmp traps`.

**Linked Findings:** Existing SNMP checks cover polling communities and v3 users.

**Dependencies:** None beyond syntax per release.

**Architecture/Convention Notes:** Separate notification targets from agent access.

**Concrete Requirements:** IOS IDs, IOS_XE, ASA, FORTIOS, F5_BIGIP: notification target using v1/v2c → finding; v3 with authPriv → none.

**Test Requirements:** Mandatory suite.

**Acceptance Criteria:** A device that only sends v3 notifications produces no finding.

<a id="sc-038"></a>
### SC-038 — FortiGate HA heartbeat authentication and encryption

**Task ID and Title:** SC-038 — HA cluster traffic, including configuration synchronisation, without authentication or encryption.

**Priority:** P2.

**Status:** Implemented 2026-09-26 for FortiOS: `fortinet.fortios.ha.heartbeat_protection` when HA mode is a-p/a-a and heartbeat authentication or encryption is disabled (both default disable per the 7.4 CLI reference). Remaining: Check Point ClusterXL CCP encryption (not visible in Gaia exports so far).

**Source of Truth:** Candidates: FortiOS `config system ha` (`set authentication`, `set encryption`, `set password`); FortiGate NDM STIG; Check Point ClusterXL CCP encryption (research; may not be visible in Gaia exports).

**Linked Findings:** `cisco.asa.failover.authentication`.

**Dependencies:** Only when HA mode is active (`set mode a-p|a-a`).

**Architecture/Convention Notes:** FortiOS parser record for HA.

**Concrete Requirements:** FORTIOS: HA active with `authentication disable` or `encryption disable` (explicit or documented default). CHECKPOINT_GAIA: only if the export shows CCP encryption state.

**Test Requirements:** Mandatory suite including standalone mode.

**Acceptance Criteria:** Standalone units produce no finding.

<a id="sc-039"></a>
### SC-039 — FortiGate SSL-VPN exposure and hardening

**Task ID and Title:** SC-039 — Weak or broadly exposed SSL-VPN portal.

**Priority:** P1. The SSL-VPN portal is internet-facing and has a long history of pre-authentication vulnerabilities.

**Status:** First stage implemented 2026-09-26 for an active SSL-VPN (`source-interface` set, status not disabled): `fortinet.fortios.sslvpn.legacy_tls`, `weak_algorithm`, `factory_certificate` and `unlimited_login_attempts`, explicit values only (7.4 CLI reference defaults: tls1-2, high, login-attempt-limit 2). Remaining: release-gated defaults for 6.x, MFA for VPN users.

**Source of Truth:** Candidates: FortiOS `config vpn ssl settings` reference (`ssl-min-proto-ver`, `servercert`, `source-interface`, `source-address`, `login-attempt-limit`, `login-block-time`, `reqclientcert`, `algorithm`, `banned-cipher`); CIS FortiOS 7.x benchmark SSL-VPN items; FortiOS release notes on SSL-VPN tunnel-mode removal (release gating).

**Linked Findings:** `fortinet.fortios.tls.minimum_version` covers administrative HTTPS only.

**Dependencies:** SSL-VPN active only when `source-interface` is set and a policy references the `ssl.root` interface.

**Architecture/Convention Notes:** Typed SSL-VPN settings record; reuse certificate resolution for `servercert`.

**Concrete Requirements:** FORTIOS: TLS below 1.2; factory self-signed certificate (`Fortinet_Factory`); `source-address all` on an external interface; login-attempt limit disabled; `algorithm low`.

**Test Requirements:** Mandatory suite including inactive SSL-VPN settings.

**Acceptance Criteria:** Inactive SSL-VPN settings produce no finding.

<a id="sc-040"></a>
### SC-040 — FortiGate physical and boot-time recovery paths

**Task ID and Title:** SC-040 — Maintainer account and USB auto-install.

**Priority:** P2. Needs physical access, but removes the need for any credential.

**Status:** Partly implemented 2026-09-26: `fortinet.fortios.system.usb_auto_install` for explicit `auto-install-config`/`auto-install-image enable` (default disable in 7.4). `admin-maintainer` is not listed in the 7.4 `config system global` reference, so no check was added.

**Source of Truth:** Candidates: FortiOS `config system global set admin-maintainer`; `config system auto-install` (`auto-install-config`, `auto-install-image`); CIS FortiOS benchmark items for both; documented defaults per release.

**Linked Findings:** None.

**Dependencies:** Documented defaults (both reportedly enabled by default; verify).

**Architecture/Convention Notes:** Low severity; recommendation mentions physical security.

**Concrete Requirements:** FORTIOS only. IOS `service config` is already covered by `cisco.ios.services.tftp_boot_config`.

**Test Requirements:** Mandatory suite.

**Acceptance Criteria:** Severity stays low; findings state the physical-access precondition.

<a id="sc-041"></a>
### SC-041 — F5 self-IP port lockdown

**Task ID and Title:** SC-041 — Management services reachable on data-plane self IPs.

**Priority:** P1. Exploitation of the configuration utility and iControl REST (for example CVE-2020-5902, CVE-2022-1388, CVE-2023-46747) relies on reaching them; self IPs with `allow-service all` or `default` expose them on traffic VLANs.

**Status:** Implemented 2026-09-26: `f5.bigip.management.self_ip_port_lockdown` for `allow-service all` (high), `default` or a custom list with TCP 22/443 (medium). Sources: tmsh `net self` reference (default none), K17333 (default set includes SSH and HTTPS), K23605346 (CVE-2022-1388 via self IPs). Remaining: validation against a real export.

**Source of Truth:** Candidates: F5 article on port lockdown behaviour (default service list per release); F5 security advisories for the CVEs above (mitigation: set self-IP port lockdown to none); F5 NDM STIG.

**Linked Findings:** `f5.bigip.http.unrestricted_sources` covers the management port, not self IPs.

**Dependencies:** Default `allow-service` value and the "default" service list per release; floating vs non-floating self IPs.

**Architecture/Convention Notes:** New parser record for `net self` with address, VLAN, floating flag and allow-service list.

**Concrete Requirements:** F5_BIGIP: `allow-service all` → finding; `default` or an explicit list containing TCP 22/443 (or the configuration utility port) → finding; absent → documented default per release.

**Test Requirements:** Mandatory suite including a list with only non-management services.

**Acceptance Criteria:** HA-required services in a custom list are not reported.

<a id="sc-042"></a>
### SC-042 — F5 data-plane TLS and persistence information leaks

**Task ID and Title:** SC-042 — Weak client-side TLS, unvalidated server-side TLS and unencrypted persistence cookies on active virtual servers.

**Priority:** P2.

**Status:** First stage implemented 2026-09-26: `f5.bigip.ltm.clientssl_weak_cipher` (positive weak tokens in the explicit cipher string of a client SSL profile on an enabled virtual server) and `f5.bigip.ltm.cookie_unencrypted` (insert/rewrite cookie persistence with explicit `cookie-encryption disabled`; K6917 describes the decodable IP/port encoding). Remaining: server-side certificate validation (policy-gated), release-dependent DEFAULT cipher strings.

**Source of Truth:** Candidates: F5 client SSL profile reference (`options`, `ciphers`), server SSL profile reference (`peer-cert-mode`, `authenticate-name`, `ca-file`), cookie persistence profile (`cookie-encryption`) and F5 articles on cookie persistence revealing pool member addresses; F5 ALG STIG (S13).

**Linked Findings:** `f5.bigip.ltm.clientssl_cleartext_enabled`; SC-024 module checks.

**Dependencies:** Only profiles bound to enabled virtual servers; release defaults for ciphers and protocol options.

**Architecture/Convention Notes:** Extend the existing virtual-to-profile resolution.

**Concrete Requirements:** F5_BIGIP: bound client SSL allowing SSLv3/TLS 1.0/1.1 or weak ciphers; bound server SSL with `peer-cert-mode ignore` (policy-gated, since backends are often trusted); insert-mode cookie persistence without encryption.

**Test Requirements:** Mandatory suite including unbound profiles.

**Acceptance Criteria:** Server-side validation is only reported when the assessment policy asks for it.

<a id="sc-043"></a>
### SC-043 — Risky cleartext services allowed by firewall policy

**Task ID and Title:** SC-043 — Shared catalogue of risky services and consistent detection across firewalls.

**Priority:** P1 for proven untrusted access to management/data services; correct classification and ordering before expanding coverage. P2 for further catalogue breadth and additional adapter rollout.

**Status:** Implemented 2026-09-26: shared catalogue `src/analyze/common/risky_services.py` (FTP, Telnet, TFTP, SMB/NetBIOS, RDP, VNC, X11, rlogin/rsh/rexec, SNMP, LDAP, POP3/IMAP, MS SQL, Oracle, MySQL, PostgreSQL, Redis, MongoDB, Docker API) used by Check Point FW1 (unchanged rule ID), new `cisco.asa.acl.risky_service_exposure` (bound active permit from any source with eq/range ports) and `fortinet.fortios.policy.risky_service_exposure` (accept policy from source all with resolved service ports). Ranges wider than 1024 ports are left to the broad-service rules. Remaining: F5 virtual servers on clear-text ports. Update 2026-09-26: F5 `ltm.risky_service_exposure` for enabled virtual servers listening on a catalogued port with source 0.0.0.0/0 (the default).

**2026-09-26 extension (A11):** Existing catalogue integrations remain implemented; effective-exposure accuracy is open. A synthetic F5 UDP/23 virtual was reported as Telnet because the endpoint record omits transport and the plugin combines TCP/UDP matches.


**Source of Truth:** Candidates: IANA service registry; CISA and vendor guidance on exposed SMB, RDP, Telnet, FTP, SNMP and database ports; Firewall SRG (S07).

[F5 endpoint accessor](../../src/devices/f5/bigip.py), `get_virtual_endpoints`; [F5 exposure check](../../src/analyze/f5/plugins/bigip_checks_plugin.py); [shared catalogue](../../src/analyze/common/risky_services.py); ASA/FortiOS policy checks and [bounded policy semantics](../../src/devices/common/policy_semantics.py). These support a configuration-level conclusion, not proof of end-to-end reachability.


**Linked Findings:** `checkpoint.fw1.policy.risky_service_exposure`, `*.policy.broad_service` (these only catch "any service").

**Dependencies:** Only active accept rules from broad or assessed-external sources; service object resolution already exists per family.

**Architecture/Convention Notes:** Move the catalogue to `src/analyze/common` so every firewall uses the same list; keep the Check Point rule ID.

**Concrete Requirements:** Extend the catalogue (SNMP 161/162, LDAP 389, POP3 110, IMAP 143, X11 6000+, MSSQL 1433, MySQL 3306, PostgreSQL 5432, Oracle 1521, Redis 6379, MongoDB 27017, Docker 2375, Telnet 23, FTP 21, TFTP 69). Apply to CHECKPOINT_FW1, ASA/PIX ACLs bound to interfaces, FORTIOS policies, and F5 virtual servers listening on cleartext administrative ports.

**Open accuracy/depth stages:** Preserve TCP/UDP/IP-protocol identity in F5 endpoint records and all catalogue adapters; never identify UDP/23 as TCP Telnet. Separate exposed sensitive services from proven cleartext application traffic. Before asserting effective permitted access, consider supported preceding denies, negation, schedules and policy predicates; unknown dependencies yield a potential/unassessed result rather than a proven exposure claim. Extend literal-any matching to auditor-declared untrusted source ranges using existing object/service containment. Disclose unmodeled NAT, upstream controls and application TLS; a database port alone does not establish cleartext traffic. Start ASA/FORTIOS/F5/CHECKPOINT_FW1, then add other adapters only with equivalent evidence. Reuse typed policy records; add protocol to F5 endpoint API and explicit expected source-scope input only if needed. Expand catalogue entries such as RPC/NFS or rsync only after authoritative semantic qualification.


**Test Requirements:** Mandatory suite, including named service objects and port ranges.

Add UDP/23 versus TCP/23, restrictive versus complete prior deny, partially overlapping deny, negated sources/services, time-scoped rules with and without assessment time, named groups, explicit untrusted subnet, protected application on a catalogued port and unresolved NAT. Retain disabled/unbound, scope and redaction coverage.


**Acceptance Criteria:** Existing Check Point snapshots change only by intentional catalogue additions.

Protocol-correct catalogue matches and proven policy outcomes are required. Potential exposure, configured permission and cleartext transport are distinct claims. Finishing the F5 protocol fix does not close the other depth stages.

<a id="sc-044"></a>
### SC-044 — Release-gated insecure defaults on legacy releases

**Task ID and Title:** SC-044 — Documented insecure defaults for old releases still found in production.

**Priority:** P2.

**Status:** First stage implemented 2026-09-26 for IOS: `cisco.ios.services.legacy_default` when the `version` train is older than 12.1 (finger on by default before 12.1(5)) or 11.x (TCP/UDP small servers on by default before 12.0) and the export does not disable them (Cisco IOS hardening guide). Remaining: ASA 8.x, PIX, FortiOS 5.x/6.0, BIG-IP 11.x/12.x and FW1 default tables.

**Research table (2026-09-28):** [INSECURE_DEFAULTS_BY_RELEASE.md](INSECURE_DEFAULTS_BY_RELEASE.md) — per-vendor, per-release default settings with sources, confidence and implementation status (IOS/IOS-XE, ASA/PIX, FortiOS, BIG-IP, Check Point Gaia/FW1; secondary Junos/PAN-OS/AOS/EOS). It lists vendor conflicts and existing rules whose absence logic needs a release gate. Use it as the input for the remaining stages.

**Update 2026-09-29:** Second stage implemented from the research table: 76 of the 109 primary-vendor rows are `impl` (IOS/IOS-XE, ASA/PIX, FortiOS 6.4.14+, BIG-IP, Gaia), each emitting `FindingBasis.DOCUMENTED_DEFAULT` with the row's source. Tests: `tests/test_sc044_defaults_{ios,asa,fortios,f5,gaia}.py`. Remaining: rows marked CONFLICT (ASA-07, F5-15, F5-21, IOS-XE VTY), unverified hash comparisons (ASA-10/11, F5-16, PAN-02), FortiOS < 6.4.14, sample-dependent FW1 rows (CP-12–17) and the secondary families.

**Source of Truth:** Candidates: IOS 12.x configuration guides (`ip http server`, `service pad`, `ip bootp server`, `mop enabled`, `vstack` defaults); ASA 8.x/9.x (`ssl server-version`, `ssh version`, `crypto ikev1 am-disable`, blank enable password); PIX 6.x (see [SC-020](#sc-020)); FortiOS 5.x/6.0 (`strong-crypto`, `admin-https-ssl-versions`, `AK1` hashes); BIG-IP 11.x/12.x (client SSL `DEFAULT` cipher string including SSLv3, self-IP lockdown default); Check Point FW1 R6x/R7x policy defaults (see [SC-017](#sc-017)).

**Linked Findings:** Release gating already used for FortiOS 7.x defaults and AOS-S 16.10/16.11.

**Dependencies:** Reliable release extraction from each export.

**Architecture/Convention Notes:** Keep default tables next to the parser that uses them, with the source URL and release range for each entry.

**Concrete Requirements:** Feed the tasks above ([SC-025](#sc-025)–[SC-043](#sc-043)) with per-release defaults; this task does not add rule IDs of its own.

**Test Requirements:** One fixture per release family and default boundary.

**Acceptance Criteria:** An unknown release never inherits a default from another release train.

## Separate opt-in data track

<a id="sc-022"></a>
### SC-022 — Versioned software-support evidence

**Task ID and Title:** SC-022 — Reproducible lifecycle assessment from a maintained dataset.

**Priority:** P2 design prerequisite for high-impact unsupported-software findings.

**Status:** Evidence/data-maintenance gate; independent of Waves 1–3. **First stage implemented 2026-09-25 (maintainer decision: only an externally maintained, free API source):** `src/advisories/lifecycle.py` uses [endoflife.date](https://endoflife.date/docs/api/v1/) for `fortios`, `panos`, `cisco-ios-xe` and `big-ip`. The match is exact on the release cycle, dates are compared with the assessment date, and the source URL and dataset generation time are shown. The result is shown with the software advisories (opt-in `--cve-lookup`, replayable from the bundle), not as a configuration finding. Other families are reported as not covered.

**Source of Truth:** S16; existing version extraction and ScreenOS lifecycle check do not supply maintained release support dates for all products.

**Linked Findings:** Missing external lifecycle evidence; this is not another configuration-key check or CVE scanner.

**Dependencies:** Official per-product lifecycle publications, model/release distinctions, support-contract caveats, dataset maintenance owner and explicit assessment date.

**Architecture/Convention Notes:** Default scans remain offline/deterministic. If implemented, accept a versioned bundled or explicitly supplied dataset with provenance, validity and revision; never silently query vendors.

**Concrete Requirements:** IOS IDs, IOS_XE, ASA, FORTIOS, JUNOS, PAN_OS, HP_PROCURVE, SONICOS, ARISTA_EOS, F5_BIGIP. Evaluate only unambiguous product/model/release matches. Unknown model, stale dataset or ambiguous extended support yields unknown. PIX/ScreenOS handling follows their legacy tasks; CHECKPOINT_FW1 cannot identify gateway OS from policy alone. Explicit opt-in data/time interface required; security patch/CVE equivalence is out of scope.

**Test Requirements:** Mandatory suite plus support end boundary, stale data, multiple product branches, contract exception, unknown model and frozen-time reproducibility.

**Acceptance Criteria:** Every result cites dataset/source/date and exact match; no version string alone is declared unsupported or vulnerable.

## Additional offline security and assessment tasks — 2026-09-26

These tasks continue numbering after SC-044. Their execution order is governed by the current priority queue, not their position after the historical waves. They do not extend the separately owned insecure-defaults database.

<a id="sc-045"></a>
### SC-045 — Enforce offline auditing by default

**Task ID and Title:** SC-045 — Separate network-free configuration auditing from advisory-data acquisition.

**Priority:** P1 operating/data-handling requirement. This is not a device vulnerability severity; an audit must not implicitly contact an external service.

**Status:** Implemented 2026-09-26. Default dispatch is offline, the Cisco analyzer no longer invokes openVuln, and the shared analyzer helper rejects online requests. Advisory fetching is a separate explicit command; local bundle replay and error reporting remain available. Public JSON/HTML tests cover all 16 IDs with socket/DNS/HTTP access prohibited and fake Cisco credentials.

**Source of Truth:** [CLI dispatch](../../src/main.py), `main`; [legacy Cisco advisory service](../../src/analyze/cisco/ios/api/cisco_ios_vulns_service.py), `get_api_vulnerabilities`; the user's explicit offline-product requirement. Outbound calls occur when the legacy path is enabled and Cisco credentials are configured. Existing NVD bundle replay is already available.

**Linked Findings:** Review A1; [PT-010](PRACTICAL_TESTING_TASKS.md#pt-010) and [SC-022](#sc-022) contain related acquisition/replay work, not justification for implicit network access.

**Dependencies:** Inventory all advisory clients and input/report paths; preserve local bundle compatibility. Decide the explicit acquisition interface within the established CLI conventions without making ordinary audits dependent on it.

**Architecture/Convention Notes:** Keep audit dispatch and parsers network-free. Retain supplied bundle provenance and separate advisory status from configuration findings. No device connection is ever added. Network acquisition, if retained, belongs to a separate explicit command/workflow.

**Concrete Requirements:** All 16 registered IDs. Remove implicit legacy Cisco lookup from ordinary audit execution; absence of `--offline` must no longer grant network authorization. Ordinary audits and local bundle replay must perform no HTTP calls, DNS resolution, revocation retrieval or remote referenced-file fetching. Make CLI help/README behavior consistent and define compatibility/deprecation for old flags. A missing or mismatched bundle yields unavailable/unknown advisories while configuration analysis continues. Do not remove offline advisory replay or introduce a device scanner.

**Test Requirements:** Run each public device pipeline with socket/DNS/HTTP access prohibited, including configured fake Cisco credentials, default flags, explicit offline mode, valid bundle replay and invalid/stale bundles. Verify no network access and valid JSON/HTML configuration reports; never use live credentials or APIs in these tests. Apply the regression gate.

**Acceptance Criteria:** A user can audit any supported export without knowing a special offline flag; no audit path silently contacts a vendor or device. Any retained data-fetch operation requires a separate explicit invocation.

<a id="sc-046"></a>
### SC-046 — Resolve effective management source restrictions

**Task ID and Title:** SC-046 — Evaluate attached management ACLs per service and address family.

**Priority:** P1 — a permissive attachment can leave administrative services broadly accessible while the present check finds no missing restriction.

**Status:** Standard IPv4 stage implemented 2026-09-28: permit-all ACLs bound to active SSH VTY and HTTP/HTTPS are reported, with ordered ACL removals and overlapping VTY transport/ACL mutations. Bounded extended IPv4 SSH stage implemented the same day: named/numbered IP/TCP rules with universal destinations and no port predicates, including ordering, removals and replacements. HTTP remains standard-only. Destination-specific VTY behavior is release-dependent ([Cisco CSCuw89081 explanation](https://www.cisco.com/c/en/us/support/docs/ip/telnet/116101-problem-telnet-00.html)); those rules, port/state/time predicates and unresolved objects stay unsupported. Active unresolved/unsupported IPv4 attachments now produce sanitized manual-review notes through existing JSON/HTML coverage diagnostics, independently of plugin order and respecting rule exclusions. Broader extended predicates, independent IPv6 applicability and other adapters remain open. No end-to-end reachability is inferred.

**Source of Truth:** [IOS SSH plugin](../../src/analyze/cisco/ios/plugins/ssh_plugin.py), `get_cisco_ios_vty_access_restriction`; [HTTP plugin](../../src/analyze/cisco/ios/plugins/http_plugin.py), `get_cisco_ios_http_access_list`; [IOS parser](../../src/devices/cisco/ios.py), `has_inbound_access_class` accepts IPv4 OR IPv6 presence. [Cisco IOS-XE hardening guide](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening) recommends restricted management access; [RFC 9099](https://www.rfc-editor.org/rfc/rfc9099.html) supports independent IPv6 protection.

**Linked Findings:** Review A2. Related AAA bindings in [SC-001](#sc-001), routing filters in [SC-005](#sc-005), API endpoints in [SC-026](#sc-026); those do not replace management ACL evaluation.

**Dependencies:** Reuse bounded ACL/object semantics; qualify management attachment behavior, VRF and IPv4/IPv6 listener applicability. Unknown or undefined references must not be interpreted as permit-all without vendor proof.

**Architecture/Convention Notes:** Parser resolves ordered ACL contents and service/line binding. Use typed outcomes for restrictive, proven permit-all, unresolved and unsupported; retain existing missing-attachment rule IDs and avoid duplicate findings for one condition.

**Concrete Requirements:** IOS_SWITCH, IOS_ROUTER, IOS_CATALYST, IOS_XE first. Evaluate every applicable active VTY and HTTP(S) access restriction, not just its name. Detect proven permit-all filters and separately report unresolved references as unassessed coverage. Evaluate IPv4 and IPv6 separately when each service/address family is applicable. Handle earlier denies, overrides, standard/extended ACL grammar and supported predicates. Add ARISTA_EOS and other adapters only after verifying equivalent attachment-only limitations. Existing finding/coverage output suffices; extend parser binding records as needed. Do not claim end-to-end Internet reachability or grade omitted defaults.

**Test Requirements:** Restrictive versus permit-any ACL, unresolved reference, earlier deny, unsupported predicate, overlapping VTY ranges, HTTP and HTTPS independently, dual-stack service with only one family protected, VRF binding, disabled service, unknown applicability, source redaction and public CLI/regression.

**Acceptance Criteria:** An ACL name is never sufficient evidence of effective source restriction, and one address family's filter cannot satisfy another's protection. Unknown references do not become invented active exposure.

<a id="sc-047"></a>
### SC-047 — Resolve Junos SRX host-inbound access

**Task ID and Title:** SC-047 — Audit traffic addressed to SRX services independently from transit policy.

**Priority:** P1 — broad admission to enabled administrative services can expose the firewall itself despite restrictive transit rules.

**Status:** Open. Source review found no effective host-inbound evaluator in the current Junos parser/plugins.

**Source of Truth:** [Junos parser](../../src/devices/juniper/junos.py), [baseline](../../src/analyze/juniper/junos/plugins/baseline_plugin.py) and [policy plugin](../../src/analyze/juniper/junos/plugins/junos_checks_plugin.py). Juniper's [host-inbound system-service reference](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-system-service-zone-host-inbound-traffic.html), reviewed 2026-09-26, distinguishes `all`, `any-service`, exceptions and interface-level behavior.

**Linked Findings:** Review A5; distinct from screen/IDP work in [SC-010](#sc-010), and complementary to API checks in [SC-026](#sc-026).

**Dependencies:** Confirm SRX role, explicit external/interface assessment roles, zone membership, inheritance and supported attached interface/loopback filter semantics. Qualify logical-system scope before expanding beyond local exports.

**Architecture/Convention Notes:** Parser owns zone/interface precedence, set/delete/deactivate/apply-groups and service bindings. Keep host-inbound state separate from transit policy. No inference from zone names such as `untrust` alone.

**Concrete Requirements:** JUNOS on SRX. Resolve zone/interface `host-inbound-traffic system-services` and routing-protocol permissions, including explicit `all`, `any-service` and exceptions. Combine admission with configured enabled services and assessed interface roles. Detect proven broad administrative admission; account for supported restrictive interface/lo0 filters before calling access unrestricted. An allowed service is not necessarily enabled, and transit default deny does not protect device-local traffic. Unknown inheritance or complex filters remain unknown/potential exposure. Add typed host-inbound records; existing JSON/HTML and assessment roles suffice initially.

**Test Requirements:** Broad versus narrow service list; `all` versus `any-service`; interface override and exception; disabled/unconfigured service; restrictive lo0 filter; explicit external versus internal role; deactivated groups, malformed references, EX negative, redaction and public-pipeline/regression tests.

**Acceptance Criteria:** The report distinguishes device-local admission from transit filtering and identifies the exact service/interface scope. It never equates a host-inbound permission with an observed running listener.

<a id="sc-048"></a>
### SC-048 — Audit IPv6 first-hop protection and address-family parity

**Task ID and Title:** SC-048 — RA Guard, DHCPv6 Guard and independently assessed dual-stack controls.

**Priority:** P2 by default, promoted to P1 for supplied deployments with a proven untrusted IPv6 gateway/DHCP or administrative-access bypass. Unused IPv6 functions do not justify high-priority absence findings.

**Status:** Open; current IPv6 inventory/filtering support is partial, not absent. No dedicated RA Guard/DHCPv6 Guard evaluator was identified.

**Source of Truth:** Current IOS/XE, AOS-S, EOS and Junos edge-check methods; [RFC 9099](https://www.rfc-editor.org/rfc/rfc9099.html) and [RFC 7113](https://www.rfc-editor.org/info/rfc7113/) support first-hop protection and its limitations. Exact vendor/release attachment grammar must be qualified independently.

**Linked Findings:** Review A8; promotes the former generic IPv6 access-edge TODO into a bounded task. Coordinate [SC-003](#sc-003)/[SC-004](#sc-004), management-family checks in [SC-046](#sc-046), and routing families in [SC-005](#sc-005); do not duplicate their detectors.

**Dependencies:** Explicit access-edge/uplink/router roles, supplied IPv6 deployment scope, vendor policy/interface attachment evidence and sanitized exports. Do not infer omitted defaults or hardware enforcement capability.

**Architecture/Convention Notes:** Parser-owned per-port protection policy, device role and inheritance; normalized outcomes only where semantics match across vendors. Reuse assessment roles; any required IPv6-use declaration must be explicit.

**Concrete Requirements:** Switching IOS_XE first, then qualified IOS_SWITCH/IOS_CATALYST, HP_PROCURVE, ARISTA_EOS and EX JUNOS. Resolve attached RA/DHCPv6 guard policies and explicit router/server/trusted modes or disablements. Detect inappropriate trusted infrastructure roles on assessed endpoint ports and proven local bypasses. Add paired IPv4/IPv6 fixtures for applicable existing management/filtering checks across adapters, including firewall families. Preserve required ICMPv6 operation; no blanket ICMPv6 blocking recommendation. Missing role/policy and unproven fragment-bypass resistance remain unknown; no packet transmission or vulnerability assertion from hardware assumptions.

**Test Requirements:** Endpoint marked router/server, legitimate uplink, protected endpoint, local override, unused/unbound policy, inactive port, LAG/inheritance unknown, IPv6-only and dual-stack cases, malformed syntax, redaction and public CLI/regression.

**Acceptance Criteria:** Explicit IPv6 trust bypasses are assessed separately from IPv4 controls; normal routers/uplinks are not falsely flagged. Unsupported address-family coverage is disclosed, not treated as secure.

<a id="sc-049"></a>
### SC-049 — Add per-control assessment outcomes and manual-review coverage

**Task ID and Title:** SC-049 — Explain assessed, unassessed and unsupported security controls.

**Priority:** P2 assurance work, after direct high-risk detection gaps. This improves audit reliability rather than identifying a new device vulnerability.

**Status:** Open. Current coverage reports normalized field knowledge states; it does not consistently record every control's eligibility/outcome.

**Source of Truth:** [Coverage builder](../../src/report/coverage.py), `_FIELDS` and `build_report_context`; [finding model](../../src/analyze/common/issue.py); [assessment context](../../src/common/assessment.py). The RIPv1 and management-API probes showed how configured unassessed features can be absent from finding output. [CIS Control 12](https://www.cisecurity.org/controls/network-infrastructure-management) supplies the configuration-management rationale, not a claimed compliance score.

**Linked Findings:** Review A12; complements [PT-009](PRACTICAL_TESTING_TASKS.md#pt-009). Finding basis explains why a finding exists, not why a control produced none.

**Dependencies:** Define versioned control metadata and typed outcome contract, then migrate an explicit initial set of high-risk rules. Backward-compatible JSON/HTML extension and coverage semantics require design before bulk migration.

**Architecture/Convention Notes:** Keep control metadata/platform applicability separate from findings. A parser supplies evidence/unknown states; a check records its outcome. Never derive a pass merely from absence of a finding. Do not incorporate or duplicate SC-044's default database.

**Concrete Requirements:** All registered IDs. Represent finding, evaluated-without-finding, unknown, unsupported, excluded and not-applicable outcomes with prerequisites/reasons. Track role, export completeness, companion input, supported grammar and explicit assessment time. Add a sanitized 'Configured features requiring manual review' section for recognized unsupported security constructs; recognition must not pretend to understand their full semantics. Record rule/control version, supported platforms and authoritative references. Unmigrated checks must be visibly unavailable rather than silently evaluated. Changes affect typed analysis results and additive versioned JSON/HTML coverage, not just presentation text.

**Test Requirements:** Same control with unsafe/safe/unknown/unsupported/excluded/not-applicable inputs; missing prerequisites; unknown inherited policy; recognized unsupported routing/API feature; unmigrated plugin; stable schema compatibility; no secret/raw payload leakage; public pipeline and regression.

**Acceptance Criteria:** An auditor can distinguish a safely assessed control from one never assessed. Coverage is not represented as benchmark certification or a vulnerability severity, and broad normalized-field knowledge never implies all related checks ran.

<a id="sc-050"></a>
### SC-050 — Add offline batch manifests and assessment comparison

**Task ID and Title:** SC-050 — Reproducible multi-device audits and supplied-export comparisons.

**Priority:** P3 — lower direct security relevance; schedule after evidence-ready P1/P2 checks. This is audit-efficiency work.

**Status:** Open. Current CLI primarily handles one artifact/device and one report.

**Source of Truth:** [CLI](../../src/main.py), [registry](../../src/devices/registry.py), [report generation](../../src/report/report.py), existing JSON/coverage interfaces and user workflow of receiving multiple configuration exports.

**Linked Findings:** Review A13; builds on [SC-045](#sc-045) offline enforcement and [SC-049](#sc-049) assessment outcomes. Does not replace existing per-device output or auto-detection.

**Dependencies:** Manifest schema, stable explicit device/object identity, deterministic rule/policy version provenance and conservative comparison semantics. Accurate resolved-versus-unassessed comparison depends on SC-049 or equally explicit coverage evidence.

**Architecture/Convention Notes:** Thin orchestration over existing registry/pipelines; no second detection engine. Keep output separate from supplied inputs, fail safely on duplicate paths/identities, preserve per-device error isolation and never retrieve artifacts automatically.

**Concrete Requirements:** All supported families, including directory-style FW1 exports. Accept a local manifest of input paths, device identity/family, export scope and assessment-policy path. Produce individual reports plus a consolidated index. Record input hashes, tool/rule-set and assessment-policy identity and local advisory-bundle provenance. Compare two supplied assessment sets as new, unchanged, resolved or no longer assessable using stable rule/object keys rather than display titles. A missing artifact, changed exclusion or reduced parser coverage must not be called remediation. Add explicit CLI/manifest and versioned comparison-output contracts. No live discovery, hostname resolution, device login or remote acquisition.

**Test Requirements:** Mixed-family batch, FW1 directory artifact, duplicate device/output, malformed manifest, one-device failure isolation, stable ordering/hashes, safe output paths, comparison across unknown/excluded/missing inputs, changed policy/rule versions, secret masking and public CLI/regression.

**Acceptance Criteria:** Batch output reproduces equivalent individual offline audits; comparisons never claim a risk was fixed merely because its evidence disappeared. No audit input is overwritten and no device/network access occurs.

## Source appendix and audit validation

Source evidence below is the current implementation boundary. Method names are supplied because line numbers move as planned work lands. Parser records and registered plugin bodies were inspected together; negative findings above are scoped to those paths, not based only on documentation/search keywords.

| Pipeline | Parser | Actual analyzer entry points and limits relevant to this backlog |
|---|---|---|
| IOS | [ios.py](../../src/devices/cisco/ios.py) | [baseline](../../src/analyze/cisco/ios/plugins/baseline_plugin.py): `check_aaa`, `check_management_lines`, `check_ssh_policy`, `check_acl_effectiveness`, `check_credentials`, `check_snmp`, `check_logging`, `check_configuration_management`, `check_ntp`, `check_banner`, `check_unnecessary_services`, `check_interface_protections`, `check_control_plane`, `check_crypto`, `check_routing`, `check_discovery`, `check_switch_edge`; dedicated HTTP/SSH plugins remain registered. Presence/attachment limitations are detailed in SC-001/005. |
| IOS-XE | [iosxe.py](../../src/devices/cisco/iosxe.py) | Shared IOS baseline plus [XE plugin directory](../../src/analyze/cisco/iosxe/plugins); do not count aliases as independent dialect breadth. |
| ASA/PIX | [asa.py](../../src/devices/cisco/asa.py) | [baseline](../../src/analyze/cisco/asa/plugins/baseline_plugin.py), [ASA checks](../../src/analyze/cisco/asa/plugins/asa_checks_plugin.py): AAA, credentials, service reachability, SNMP/logging, ACL policy, bound TLS/IPsec, NTP/MPF/uRPF/failover. Remote-access user authentication differs from these crypto checks. |
| FortiOS | [fortios.py](../../src/devices/fortinet/fortios.py) | [baseline](../../src/analyze/fortinet/plugins/fortios_baseline_plugin.py): `check_administrators`, password/session, management crypto/certificates, SNMP/NTP, logging/profiles, policy effectiveness, backups, updates/services, DoS, AAA transport, local-in, IPsec. [Additional checks](../../src/analyze/fortinet/plugins/fortios_checks_plugin.py) cover basic management/broad policies/TLS/syslog. |
| Junos | [junos.py](../../src/devices/juniper/junos.py) | [baseline](../../src/analyze/juniper/junos/plugins/baseline_plugin.py), [plugins](../../src/analyze/juniper/junos/plugins): administrative and routing baseline plus SRX stateful policy/IPsec. SRX screens/IDP and EX access-edge admission are separate missing functions. |
| ScreenOS | [screenos.py](../../src/devices/juniper/screenos.py) | [baseline](../../src/analyze/juniper/plugins/screenos_baseline_plugin.py), [plugins](../../src/analyze/juniper/plugins): legacy management, policy, VPN and operations; time server existence is not authenticated association evidence. |
| Check Point | [fw1.py](../../src/devices/checkpoint/fw1.py) | [baseline](../../src/analyze/checkpoint/plugins/fw1_baseline_plugin.py), [plugins](../../src/analyze/checkpoint/plugins): policy content and static effectiveness, not Gaia system posture. |
| PAN-OS | [panos.py](../../src/devices/paloalto/panos.py) | [checks](../../src/analyze/paloalto/plugins/panos_checks_plugin.py): management, AAA/password/session, SSH/TLS/certs/SNMP/NTP, operations/logs and named policy/inspection. Explicit interzone-default override and first broad high/critical anti-spyware/vulnerability selector actions are covered; exception severity, required profile sets, zone/DoS protection and many profile defaults remain open. |
| AOS-S | [procurve.py](../../src/devices/hp/procurve.py) | [checks](../../src/analyze/hp/plugins/hp_checks_plugin.py): `check_ssh_crypto`, `check_operational_baseline`, `check_administrative_policy`, `check_advanced_baseline`, `check_edge_protections` alongside basic management checks. AOS-CX not included. |
| SonicOS | [sonicos.py](../../src/devices/sonicwall/sonicos.py) | [checks](../../src/analyze/sonicwall/plugins/sonicos_checks_plugin.py): `check_management`, `check_administration`, `check_access_rules`, `check_policy_effectiveness`, `check_vpn`, `check_operations`; global protection is not zone/protocol effectiveness. |
| EOS | [eos.py](../../src/devices/arista/eos.py) | [checks](../../src/analyze/arista/plugins/arista_checks_plugin.py): administrative/services/crypto/SNMP/AAA/time/CoPP; no equivalent routing or access-edge admission evaluation. |
| F5 | [bigip.py](../../src/devices/f5/bigip.py) | [checks](../../src/analyze/f5/plugins/bigip_checks_plugin.py) `analyze`: bounded explicit-setting/credential-storage/remote-auth-provider/bound-cleartext checks. `_FIELDS`, user, remote-auth, profile and virtual records define the small supported evidence set. |

Deferred intentionally: generic banner wording, low-severity GTSM-only expansion, wholesale disablement of discovery on all ports, speculative SSL decryption mandates, runtime-unused ACL detection, signature freshness, live MFA/certificate revocation verification and successful backup proof. Those need different scope or operational evidence. Existing static ACL effectiveness, stored-secret classification, known-default credential checks and report coverage are retained, not relisted as absent capabilities.

Validation of this documentation refresh: 65 tests in `tests/test_realworld*.py` and 36 ASA-baseline/credential tests passed (101 focused tests total). The only warning concerned pytest cache write permission. This supports removing completed RV work; it is not a full regression run or proof of complete benchmark compliance. Runtime code, schemas and snapshots were not changed. Task/source links and all 15 registry IDs were checked during final document validation.


Documentation update validation (2026-09-26): seven review proposals were merged into five existing tasks, and six distinct tasks were added as SC-045 through SC-050 (50 total). New task stages remain open. This update makes no code, runtime schema or snapshot changes; historical test counts above are not new test runs. SC-044 was preserved unchanged. Task numbering, required fields and local links were checked for this update.
