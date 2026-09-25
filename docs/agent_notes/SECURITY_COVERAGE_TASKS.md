# High-risk configuration coverage: implementation backlog

Reviewed **2026-09-22** against the current source, after the recent parser and detection upgrades. This is the authoritative security-coverage backlog; it replaces the overlapping broad detection bullets in [TODO](../TODO.md). It specifies future implementation, not changes made during this review. No Git commands were used. Existing detection defects and external samples remain in [real-world findings](REALWORLD_VALIDATION_FINDINGS.md); completed remediation is reconciled in [validation tasks](REALWORLD_VALIDATION_TASKS.md).

## Scope and execution contract

There are **15 registered IDs and 12 parser/analyzer pipelines**, including F5 BIG-IP. IOS aliases share one implementation; PIX shares ASA code but does not thereby have independently verified dialect coverage. Source authority is [registry](../../src/devices/registry.py), not historical roadmap claims.

Priorities are implementation priorities: **P1** closes a high-impact exposure or an important prerequisite; **P2** covers selected medium risks or evidence qualification. DISA High/CAT I and Medium/CAT II are source severities, not this project's priority scale. CIS Level 1/2 describes profiles, not vulnerability severity. Do not manufacture a Critical rating because a source has no such rating. Final finding severity depends on the proven unsafe state and exposure.

Selected medium issues matter because they commonly weaken administrative authentication, log integrity, routing trust, or access-edge isolation. No multi-stage attack scoring engine is requested. Low-value cosmetic controls, blanket benchmark parity, live scanning, password cracking, and speculative new platforms are outside this backlog.

Every task uses the fields below. A task marked **Evidence gate** starts with the stated research/fixture deliverable; it does not authorize speculative detections. A ready task may still require release-specific syntax qualification before absence/default assertions. Follow [Architecture](../ARCHITECTURE.md), [Extending](../EXTENDING.md), [Assessment policy](../ASSESSMENT_POLICY.md), and [Supported devices](../SUPPORTED_DEVICES.md). These guides require separate approval for organization-specific thresholds or unverified benchmark mappings: build explicit-state detection first, and leave those profile decisions as prerequisites for the future implementing agent.

Mandatory implementation rules, incorporated into **every** task:

- Parsers resolve effective order, negation, inheritance, scope, references and bindings; plugins consume typed records and do not reopen files. Prefer a vendor record unless a shared concept is genuinely needed. Explicitly register any new plugin.
- Preserve `KNOWN`, `UNKNOWN`, `UNSUPPORTED`, and `PARSE_ERROR`; distinguish configured, enabled, bound, and operational. Missing data, unmerged controller state and unsupported predicates cannot establish safety or a missing control. Release-gate defaults. Use explicit assessment roles, never an interface/profile name as proof of trust.
- Keep stable existing rule IDs. Add distinct IDs only for distinct unsafe states, with sanitized source/line evidence and authoritative references. Existing JSON/HTML finding and coverage interfaces are sufficient unless a task explicitly states otherwise. Add no default network calls.
- **Mandatory tests:** unsafe positive, secure negative, override/removal/inheritance, malformed and unknown, inactive/unbound, assessment/export scope, secret redaction, and installed public CLI JSON/HTML. Test the meaningful combinations for the feature; explicitly justify genuinely inapplicable cases. Include adversarial fixtures that defeat presence-only checks.
- After implementation run `.\.venv\Scripts\python.exe scripts\run_full_regression.py` from the repository root. Review intentional snapshot changes; never regenerate expectations to hide a regression. Each task's acceptance criteria include this gate.

## Standards and release applicability

All online sources below were accessed **2026-09-22**. STIG Viewer is the user-requested mirror of DISA text; vendor command documentation determines parser grammar. Catalog version is not an OS version. Some date-addressed STIG pages render newer revisions; record the displayed revision and rule ID when implementing. Catalog currency below was checked against the [STIG catalog](https://www.stigviewer.com/stigs); this is not a certification or an exhaustive control-by-control compliance claim.

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
| IOS_SWITCH | Management-line authentication/authorization/timeouts, effective VTY AAA binding/bypass/accounting and empty-group checks, HTTP/SSH, credentials, SNMP, logging/config archive, NTP, interface/CoPP, BGP/OSPF, ACL effectiveness, selected DHCP/ARP/access-edge checks | [SC-001](#sc-001) member/release qualification only, [SC-003](#sc-003), [SC-004](#sc-004), [SC-005](#sc-005), [SC-006](#sc-006), [SC-021](#sc-021), [SC-022](#sc-022) |
| IOS_ROUTER | Same pipeline; role-appropriate routing/interface/management checks, not evidence of L2 endpoint role | [SC-001](#sc-001) member/release qualification only, [SC-005](#sc-005), [SC-006](#sc-006), [SC-021](#sc-021), [SC-022](#sc-022) |
| IOS_CATALYST | Same IOS pipeline; alias does not add independent checks | [SC-001](#sc-001), [SC-003](#sc-003), [SC-004](#sc-004), [SC-005](#sc-005), [SC-006](#sc-006), [SC-021](#sc-021), [SC-022](#sc-022) |
| IOS_XE | IOS baseline plus XE/MACsec/crypto additions | [SC-001](#sc-001), switch-role [SC-003](#sc-003)/[SC-004](#sc-004), [SC-005](#sc-005), [SC-006](#sc-006), [SC-021](#sc-021), [SC-022](#sc-022) |
| ASA | AAA, SSH/HTTP source restrictions, credentials, SNMP/log/NTP, MPF/uRPF, active SSL and bound IPsec transforms, ACL effectiveness, failover authentication | [SC-002](#sc-002), [SC-013](#sc-013), [SC-021](#sc-021), [SC-022](#sc-022) |
| PIX | Registry alias to ASA; independent old-dialect parsing remains uncertain, including externally observed bound ACL misses | [SC-020](#sc-020) first; do not blindly inherit modern ASA task applicability |
| FORTIOS | Management/administrator/session/password/crypto/cert checks, including bound custom write-capable profile trusted-host/MFA coverage; SNMP/NTP, logging destinations/events, profile attachment/content summaries, DoS, local-in, VPN, backup/update configuration | [SC-009](#sc-009), [SC-011](#sc-011) authorized log-role policy only, [SC-012](#sc-012), [SC-013](#sc-013), [SC-022](#sc-022) |
| JUNOS | SRX policy/default deny/IPsec; administrative classes/AAA/SSH/SNMP/log/NTP, lo0 protection, BGP/OSPF and discovery | EX-only [SC-003](#sc-003)/[SC-004](#sc-004), [SC-005](#sc-005), SRX-only [SC-010](#sc-010), [SC-021](#sc-021), [SC-022](#sc-022); stateless-filter research remains in TODO |
| SCREENOS | Legacy admin/password/logging/SNMP, NTP-server presence, policy/session/default-policy subset, VPN proposals and lifecycle warning | [SC-019](#sc-019), plus existing [RV-008](REALWORLD_VALIDATION_TASKS.md#rv-008); no duplicate lifecycle task |
| CHECKPOINT_FW1 | Policy objects, broad rules, cleanup/stealth, tracking/install scope and bounded static rule analysis | [SC-017](#sc-017), [SC-023](#sc-023); OS AAA/credentials/SNMP/time/cert state unavailable in policy-only input |
| PAN_OS | Management/admin/password/lockout/AAA/SSH/TLS/certs/SNMP/NTP, update/log forwarding, rule hygiene/effectiveness, explicit interzone-default allow overrides and inspection attachment summaries | [SC-008](#sc-008), [SC-009](#sc-009), [SC-013](#sc-013), [SC-022](#sc-022) |
| HP_PROCURVE | AOS-S management/AAA/manager-operator/password/SSH/SNMP, logging/NTP and DHCP/DAI/source-lockdown/port-security subset | [SC-003](#sc-003), [SC-004](#sc-004), routing-role [SC-005](#sc-005), [SC-012](#sc-012), [SC-021](#sc-021), [SC-022](#sc-022) |
| SONICOS | E-CLI management/admin, access rules/effectiveness, VPN algorithms, logging/NTP/SNMP, global security services and Capture ATP dependencies | [SC-013](#sc-013), [SC-018](#sc-018), [SC-021](#sc-021), [SC-022](#sc-022) |
| ARISTA_EOS | eAPI/TLS-profile/SSH, admin roles/AAA/authz/accounting/session/lockout/banner, SNMP/credentials/authenticated NTP/CoPP | [SC-002](#sc-002), [SC-003](#sc-003), [SC-004](#sc-004), [SC-005](#sc-005), [SC-012](#sc-012), [SC-021](#sc-021), [SC-022](#sc-022) |
| F5_BIGIP | Explicit management source/redirect/idle settings, tmsh audit, password-enforcement and zero-lockout/minimum-length checks, plaintext local-user password storage, active remote-auth empty-server and LDAP SSL/peer-check disablement, remote-syslog-none, bound ClientSSL allow-non-SSL | [SC-014](#sc-014), [SC-015](#sc-015), [SC-016](#sc-016), [SC-022](#sc-022), conditional-module [SC-024](#sc-024) |

Administrative access, AAA, credentials, SNMP, logging, time, services, routing, filtering, crypto, certificates, discovery and control-plane protection were considered. Banners already have checks on several families and are not a priority expansion here. Missing routing/L2 functions on appliances that do not use those roles are not automatically applicable. Certificate selection is not equivalent to certificate validation; algorithm blacklists are not credential-value checks; configured backup/update schedules are not proof of successful operation. No missing checks are inferred simply from an absent category name in a plugin.

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

**Priority:** P1.

**Status:** Implemented for bound write-capable custom roles and existing trusted-host/MFA checks; authorized log-administrator policy remains open pending explicit applicability.

**Source of Truth:** S09; [Forti baseline](../../src/analyze/fortinet/plugins/fortios_baseline_plugin.py) `check_administrators` classifies privilege using `profile == "super_admin"`; no effective custom `accprofile`/`loggrp` analysis.

**Linked Findings:** Custom roles can escape existing privileged-account trusted-host/MFA checks.

**Dependencies:** FortiOS release-specific accprofile permissions and global/VDOM scoping; explicit authorized-role policy for organizational privilege restrictions.

**Architecture/Convention Notes:** Parser resolves role definitions; reuse existing administrator findings for newly recognized equivalent privileges.

**Concrete Requirements:** FORTIOS. Parse custom profiles and their write/admin permissions, including log-management permissions; bind enabled local/remote admin entries. Apply existing source restriction/MFA checks to genuinely privileged custom roles. Assess excess log-deletion/configuration privileges only against explicit authorized scope. Unknown profiles are unresolved, never ordinary read-only users. Typed role records required; no new CLI unless approved role policy needs an assessment-context field.

**Test Requirements:** Mandatory suite plus custom write role without trusted hosts, read-only role, scoped VDOM administrator, unresolved profile, disabled account and remote MFA of unknown status.

**Acceptance Criteria:** Role names cannot bypass existing privileged-account protections; no claim that a configured permission was exercised at runtime.

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

**Status:** Bounded explicit IOS/XE assessed access-edge bypass checks implemented. An AOS-S stage was added on 2026-09-24: ordered `aaa port-access authenticator <ports> control authorized` (force authorized, per the AOS-S 16.10 access security guide) is reported on assessed access edges, and `control auto` or `no aaa port-access authenticator` overrides it. Missing-control policy, fallback/AAA effectiveness and the EOS/Junos EX grammar/fixtures remain open; the Arista 802.1X guide was not reachable for qualification.

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

**Status:** Bounded explicit IOS/XE assessed access-edge BPDU-guard inheritance/override and local filter-bypass checks implemented. The EOS mapping was added on 2026-09-24 from the Arista spanning-tree guide: the global `spanning-tree edge-port bpduguard default` applies to portfast ports, interface `spanning-tree bpduguard` takes precedence, and `portfast auto` stays unknown. The AOS-S mapping was also added: ordered `spanning-tree <ports|all> bpdu-protection` and `bpdu-filter`. Explicitly disabled protection, and protection combined with a filter (which makes the port ignore BPDUs), are reported on assessed access edges of verified 16.10/16.11 exports. Omitted-default conclusions and the Junos EX mapping remain open.

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

**Priority:** P1 for unauthenticated active routing; P2 for policy/key-lifetime depth.

**Status:** Bounded IOS/XE classic default-VRF IPv4 RIPv2 and EIGRP authentication; direct external-BGP IPv4 prefix-list, route-map and AS-path filter-list missing-reference/sole-permit-all checks; and explicit-UTC, assessment-time-gated OSPF/RIP/EIGRP key-lifetime viability implemented. A named-mode EIGRP stage was added on 2026-09-25 from the Cisco EIGRP command reference and configuration guide: default-VRF `address-family ipv4 [unicast] autonomous-system N` under `router eigrp <name>`, with `af-interface default` inherited by every interface and a specific `af-interface` overriding it; `shutdown` and `passive-interface` under af-interface exclude the interface; `authentication mode md5` needs a populated `authentication key-chain`, and `authentication mode hmac-sha-256 [0|7] <key>` is accepted (the key is redacted and shown only in the `--show-secrets` appendix). A specific `no authentication ...` against an inherited default stays unknown. VRF/IPv6/multicast address families, named/VRF RIP, EOS/HP routing, broader filter effectiveness and other-platform/ambiguous-clock key-lifetime stages remain open. For the EOS BGP stage (2026-09-24), the peer-group and VRF grammar was confirmed from the Arista BGP guide, but IPv4-unicast default activation and the `maximum-routes` default could not be confirmed from accessible sources. Those two defaults decide which peers are active and whether a prefix-limit finding is valid, so the stage waits for that evidence. SC-005 remains partial.

**Source of Truth:** S03; IOS `check_routing` covers BGP/OSPF plus bounded classic RIPv2 and EIGRP interface/key-chain slices, using the [Cisco IOS RIP command reference](https://www.cisco.com/c/en/us/td/docs/ios/iproute_rip/command/reference/irr_book/irr_rip.html), [Cisco EIGRP command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_eigrp/command/ire-cr-book/ire-i1.html), and [Cisco EIGRP passive-interface FAQ](https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/13681-eigrpfaq.html). Narrow BGP effects follow [Cisco's explicit prefix-list permit-all example](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/ip-routing/b-ip-routing/m_irg-external-sp-0.html), [route-map no-match semantics](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/ip-routing/b-ip-routing/m_iri-iprouting.html), and the [Cisco AS-path filter command reference](https://www.cisco.com/c/en/us/td/docs/ios/iproute_bgp/command/reference/irg_book/irg_bgp2.html); most routing filter forms still test attachment presence only. Junos baseline has BGP/OSPF; EOS/HP plugins lack equivalent routing-security analysis.

**Linked Findings:** Different platform coverage depths; do not claim BGP/OSPF checks are absent everywhere.

**Dependencies:** Representative sanitized routing exports; explicit external-neighbor/interface roles; approved prefix policy and assessment time for time-sensitive checks.

**Architecture/Convention Notes:** Parser resolves inheritance, address family, peer groups, passive state, keys and filter ordering. Reuse bounded set analysis only for supported predicates.

**Concrete Requirements:** (1) IOS IDs/IOS_XE: active EIGRP/RIP authentication and explicit weak/null mode; (2) EOS and routing-capable HP_PROCURVE: BGP/OSPF active auth and bound external filters; (3) IOS/IOS_XE/JUNOS/EOS: detect proven permit-all/nonrestrictive attached routing filters, missing referenced filters and unusable key-chain lifetimes. Unknown complex policy is not automatically empty or safe. Do not require BGP authentication on dormant templates. Interface change only for approved expected-prefix/key-time policy in assessment context.

**Test Requirements:** Mandatory suite plus peer inheritance override, IPv4/IPv6 independence, passive interface, permit-all route map with a name, unresolved prefix list, unsupported predicate and expired versus future-valid key.

**Acceptance Criteria:** Track and test each numbered adapter stage separately; attachment names alone cannot establish effective filtering, and no runtime-neighbor assertion is made.

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

**Priority:** P1.

**Status:** Bounded ASA WebVPN explicit group-URL/AAA-only finding under an opt-in client-certificate policy implemented. Default/alias/IPsec entry points, fallback and authorization-filter resolution, and other-vendor stages remain evidence-gated. SC-013 remains partial.

**Source of Truth:** S04; ASA SSL/IPsec checks inspect crypto but not effective remote-access tunnel-group/group-policy authentication. FortiOS, PAN-OS and SonicOS adapters do not provide equivalent complete remote-access auth-chain evaluation.

**Linked Findings:** Separate from completed RV-001/RV-002; TLS strength does not establish user authentication.

**Dependencies:** ASA release-specific tunnel-group inheritance and reachable WebVPN; then Forti SSL-VPN, PAN GlobalProtect and Sonic remote-access vendor sources/fixtures. Verify feature availability; newer Forti releases/models may remove SSL-VPN functions.

**Architecture/Convention Notes:** Typed listener-to-portal/group/auth/profile/access-filter relationships; do not infer MFA from a RADIUS/SAML server name.

**Concrete Requirements:** ASA, then FORTIOS/PAN_OS/SONICOS. Resolve active remote-access entry points, effective authentication choices, fallback, certificate requirement and bound authorization filters. Report explicit password-only paths under an applicable approved stronger-auth policy and proven unrestricted authorization against explicit expected scope. Certificate-specific ASA STIG policy stays distinct from generic MFA. Omitted identity-provider policy is unknown. Add minimal approved remote-access policy context, not live authentication attempts.

**Test Requirements:** Mandatory suite plus inherited weak default group, secure certificate path, unbound portal, fallback bypass, unresolved external IdP and disabled VPN.

**Acceptance Criteria:** Each vendor stage has its own source mapping and fixtures; reports state configured requirements, never that MFA was actually performed.

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

**Status:** SNMP stage implemented (2026-09-24) from the TMOS `sys snmp` reference. Findings need an exported, reachable `allowed-addresses` scope (not loopback-only or `none`); the documented default is 127/localhost and is not graded. With that scope the tool reports: an any-address scope combined with communities; per-community well-known default names or `rw` access; and SNMPv3 users without `auth-privacy` or with MD5/DES. Community strings and user keys never leave the parser. NTP authentication remains an evidence gate: `sys ntp` has no key properties, and keys are only configurable through the unsupported raw `include` option, so configured servers are not graded.

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

**Status:** Vendor intent verified; E-CLI grammar qualification required. A research attempt on 2026-09-24 confirmed that IPS is enabled per zone (Object > Match Objects > Zones, "Enable IPS"), in addition to global enablement. The SonicWall CLI reference and knowledge-base pages were not machine-readable (bot protection), so the E-CLI zone syntax is still unverified. A sanitized `show current-config custom` export with zone security-service lines is needed before implementation.

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

**Status:** Research/design only until sources and fixtures are available.

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

**Status:** Research/design only.

**Source of Truth:** S13 and F5 Firewall/VPN benchmarks in catalog; current adapter covers basic TMOS/LTM, not module-specific policy effectiveness.

**Linked Findings:** Missing module evidence, not proof every BIG-IP needs AFM, APM and WAF.

**Dependencies:** Real sanitized SCF/tmsh exports, provisioning/module identity, active virtual-to-policy binding, license evidence limitations and intended deployment role.

**Architecture/Convention Notes:** Extend supported saved-export grammar only; UCS and F5OS stay separate unqualified formats.

**Concrete Requirements:** F5_BIGIP. Produce a module-by-export feasibility matrix and exact high-risk candidates: explicit bypass/transparent-only enforcement on an assessed protective path, unrestricted AFM default policy, or APM authentication bypass where demonstrable. Split each verified candidate into a bounded detector subtask with control ID, objects, bindings, unknown handling and fixtures. Do not implement broad missing-module rules from a basic LTM export. Existing report interface; module-role context only if justified.

**Test Requirements:** Positive bound bypass, secure enforcement, inactive policy, absent module, incomplete export and redaction fixtures for each qualified candidate, then mandatory suite.

**Acceptance Criteria:** Research establishes which controls can actually be evaluated; no generic WAF/AFM/APM absence finding ships without role and evidence.

## Separate opt-in data track

<a id="sc-022"></a>
### SC-022 — Versioned software-support evidence

**Task ID and Title:** SC-022 — Reproducible lifecycle assessment from a maintained dataset.

**Priority:** P2 design prerequisite for high-impact unsupported-software findings.

**Status:** Evidence/data-maintenance gate; independent of Waves 1–3.

**Source of Truth:** S16; existing version extraction and ScreenOS lifecycle check do not supply maintained release support dates for all products.

**Linked Findings:** Missing external lifecycle evidence; this is not another configuration-key check or CVE scanner.

**Dependencies:** Official per-product lifecycle publications, model/release distinctions, support-contract caveats, dataset maintenance owner and explicit assessment date.

**Architecture/Convention Notes:** Default scans remain offline/deterministic. If implemented, accept a versioned bundled or explicitly supplied dataset with provenance, validity and revision; never silently query vendors.

**Concrete Requirements:** IOS IDs, IOS_XE, ASA, FORTIOS, JUNOS, PAN_OS, HP_PROCURVE, SONICOS, ARISTA_EOS, F5_BIGIP. Evaluate only unambiguous product/model/release matches. Unknown model, stale dataset or ambiguous extended support yields unknown. PIX/ScreenOS handling follows their legacy tasks; CHECKPOINT_FW1 cannot identify gateway OS from policy alone. Explicit opt-in data/time interface required; security patch/CVE equivalence is out of scope.

**Test Requirements:** Mandatory suite plus support end boundary, stale data, multiple product branches, contract exception, unknown model and frozen-time reproducibility.

**Acceptance Criteria:** Every result cites dataset/source/date and exact match; no version string alone is declared unsupported or vulnerable.

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
