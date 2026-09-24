# Device analysis

Analyzers run focused plugin classes against a `BaseDeviceParser` and return vendor-neutral `Finding` objects with stable rule IDs, severity, exploitability, source evidence, and optional security references.

## Verified target-platform coverage

| Platform | Implemented analysis |
|---|---|
| Cisco IOS | Effective HTTP/SSH, per-line transport/timeout/access-class, resolved AAA authentication/authorization plus explicit authorization-bypass, unbound/disabled accounting and unusable named-group checks, AUX, credential, per-user/group/view/source-scoped SNMPv3, logging, per-association authenticated NTP, BGP neighbor authentication and external-peer route policy/prefix limits plus bounded direct IPv4 prefix-list effects, OSPFv2 and bounded active classic RIPv2/EIGRP interface authentication, explicitly external CDP/LLDP exposure, bounded assessed access-edge 802.1X and BPDU-guard bypass checks, banner, service, interface, control-plane, and VPN baseline rules |
| Cisco IOS-XE | IOS-family management-line/AAA/SSH composition plus explicit access-edge DHCP snooping, DAI, source guard, port-security, trunk/trust, 802.1X and BPDU-guard bypass checks; MACsec requires an explicit uplink/external role or configured MKA/MACsec intent, alongside active IKE/IPsec checks |
| Cisco ASA | Single deduplicated pipeline for effective management services, protocol-specific AAA, explicit local lockout/password minimum and active SSH/ASDM idle policy, console sessions, release-aware SSH, logging, TLS, ACL, plaintext/legacy-MD5/PBKDF2 credential storage, per-user/group/host-scoped and release-aware SNMPv3, per-server authenticated NTP, management SSL trustpoint/chain and policy-driven public X.509 assessment, threat detection, uRPF, VPN, and failover controls; current ASA 9.x defaults are not applied to PIX |
| Fortinet FortiOS | VDOM-aware management and policy checks plus administrator trust/MFA/remote authentication for built-in super_admin and resolved custom write-capable profiles, FortiOS 7.4+ administrative RADIUS/RadSec transport, password/session controls, management crypto, SNMPv3, authenticated NTP, remote syslog cleartext/weak-TLS state, updates, unused interfaces/services, active-policy UTM group/member resolution and explicit first-broad high/critical IPS pass/monitor checks, distinct IPv4/IPv6 unrestricted local-in management detection, attached same-VDOM IKE/IPsec proposal/reference checks, and DoS protection |
| Check Point FW1 | Typed ordered-layer analysis for broad/risky/negated access, explicit cleanup and gateway stealth rules, tracking and install scope, disabled/expired rules, conservative same-layer subnet/range/protocol/port shadowing and redundancy, and unresolved object/service/group references |
| Juniper Junos | Effective services, SSH root access and algorithms, authentication, credentials, named-user login-class and CLI idle-timeout resolution, pre-login notices, remote-auth accounting events/destinations, explicit J-Web session bounds, attached stateless filters, SRX zone-pair broad-permit analysis with static address/application resolution, attached/interface-bound IKE/IPsec proposal/reference checks, SNMP, logging, authenticated NTP, BGP neighbor authentication and external-peer route policy/prefix limits, OSPFv2 interface authentication, explicitly external LLDP exposure, Routing Engine protection, and redirect controls |
| Juniper ScreenOS | Effective management/policy checks plus EOL, source restriction, SSHv2/HTTPS, default credential, banner, syslog, SNMP, NTP presence, policy logging, and referenced VPN crypto controls; ScreenOS 6.3 additionally separates console/Telnet, WebUI, administrator-AAA and policy/user auth-server timeout checks and detects explicit default-permit policy state |

## Verified secondary-platform static baselines

| Platform | Implemented analysis |
|---|---|
| Palo Alto PAN-OS | Attached dataplane and dedicated-MGT services, source restrictions, ordered rules and explicit interzone-default allow overrides, session/traffic/system log forwarding, same-vsys/shared security profile group/member resolution with empty/non-blocking/unresolved findings and explicit critical/high first-broad-selector allow/alert checks, administrator role/authentication-profile resolution and MFA evidence, explicit banner/session/lockout controls, applied PAN-OS 10+ management SSH profile checks, password complexity, DNS, release-aware NTP, SNMPv3, scoped management X.509 assessment, content updates, and explicit Panorama confidence |
| HP/ArubaOS-Switch | Version-aware Telnet/WebAgent, independent plaintext/TLS state, authorized managers, centralized AAA/accounting, ordered manager/operator protection and per-channel login/enable methods, MOTD and remote CLI/serial/WebAgent idle-timeout checks, local password control, exact SNMP community state and independently evaluated v3 users, effective SSH suites, effective remote logging and explicit Event Log/severity exclusion checks, per-server SNTP key/trust resolution, configured-VLAN DHCP snooping, and explicit access-edge tagged/trust/ARP/source-lockdown/port-security checks |
| SonicWall SonicOS 7 | Per-interface management/zone exposure, typed access-rule logging/breadth, active VPN suites, independently evaluated active SNMPv3 users, syslog, authenticated NTP, explicit threat-service state and Capture ATP dependencies, plus administrator role/MFA, authentication method/local fallback, password constraints, login/session controls, CLI banner, and active HTTPS TLS/certificate selection; 7.3 custom-export omissions remain unknown and unsupported formats stop before analysis |
| Arista EOS | Active eAPI HTTP/HTTPS, shutdown, VRF/service-ACL and attached TLS-profile checks; local no-password/plaintext/legacy-MD5 credential storage and undefined-role detection; centralized login, EXEC/all-command authorization and accounting; lockout, applicable session idle timeout and pre-login banner; explicit ineffective global password minimum for proven local administrator login, with named profiles ungraded; explicit SSH empty-password/algorithm/service-ACL policy; independently evaluated SNMPv3 users/groups/views/VRF ACLs; syslog destinations and explicit trap/buffer thresholds that exclude error events; and release-aware symmetric/NTS time authentication |

## Basic platform support

| Platform | Implemented analysis |
|---|---|
| F5 BIG-IP TMOS | Explicit management SSH source/idle state, HTTP configuration utility source/redirect state, console and tmsh idle timeouts, tmsh command auditing, local password-policy enforcement, standard remote-syslog server state, and enabled virtual servers with attached enabled Client SSL profiles that allow non-SSL traffic. No absence-based defaults, broader LTM policy analysis, iRules, APM/AFM/WAF, F5OS, or runtime state assessment. |

T-030 and T-032 are closed at this bounded static-analysis scope. These are not claims of the same breadth as the seven target platforms: an explicit assessment time can grade exported certificate material, but the certificate actually served, revocation, runtime authorization outcome, licensing/subscription state, installed policy, negotiated VPN security associations, peer identity, and time-sensitive firmware support cannot be established from the supported configuration files alone.

Check Point analysis is intentionally limited to what matching offline exports prove. It does not claim the policy was successfully compiled or installed, resolve runtime dynamic-object membership, use hit counts, or detect conflicts across different ordered/inline layers. Expiry findings require a directly exported literal date. Shadow/redundancy findings require positive non-negated fields with matching time, VPN, through, compatible install-on scope, and completely resolved static network and service semantics; partial overlap is not reported as full containment.

Every finding constructed by the twelve corpus pipelines now includes at least one authoritative vendor-documentation URL. A source-level test rejects any covered plugin `Finding` construction without references, and the permanent public-pipeline corpus rejects emitted findings without an HTTPS source or with an insecure external URL.

## Plugin requirements

- Extend `BasePlugin`.
- Accept a parser object rather than reopening the configuration file.
- Evaluate ordered effective state, including negation, disablement, deletion, attachment, and scope.
- Emit one root cause per stable rule ID and preserve object-specific evidence.
- Pass parser `ConfigEvidence` objects as evidence so reports cite source line numbers; processors call `attach_source_lines` before filtering.
- Make sure every rule ID maps to reader guidance in `src/analyze/common/guidance.py`.
- Redact credentials, communities, keys, and other secrets before they become evidence.
- Cite the vendor guide or control source in `Finding.references` for every check.
- Add true-positive, true-negative, override, unknown/not-applicable, and public-pipeline tests.

Processors register plugins explicitly; executable plugin discovery by filename is not supported. See [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) for the execution flow and [`docs/EXTENDING.md`](../../docs/EXTENDING.md) for the complete extension checklist.
