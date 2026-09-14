# Device analysis

Analyzers run focused plugin classes against a `BaseDeviceParser` and return vendor-neutral `Finding` objects with stable rule IDs, severity, exploitability, source evidence, and optional security references.

## Verified target-platform coverage

| Platform | Implemented analysis |
|---|---|
| Cisco IOS | Effective HTTP/SSH, per-line transport/timeout/access-class, resolved AAA authentication/authorization, AUX, credential, per-user/group/view/source-scoped SNMPv3, logging, per-association authenticated NTP, BGP neighbor authentication and external-peer route policy/prefix limits, OSPFv2 interface authentication, explicitly external CDP/LLDP exposure, banner, service, interface, control-plane, and VPN baseline rules |
| Cisco IOS-XE | IOS-family management-line/AAA/SSH composition plus explicit access-edge DHCP snooping, DAI, source guard, port-security and trunk/trust checks; MACsec requires an explicit uplink/external role or configured MKA/MACsec intent, alongside active IKE/IPsec checks |
| Cisco ASA | Single deduplicated pipeline for effective management services, protocol-specific AAA, console sessions, release-aware SSH, logging, TLS, ACL, plaintext/legacy-MD5/PBKDF2 credential storage, per-user/group/host-scoped and release-aware SNMPv3, per-server authenticated NTP, management SSL trustpoint/chain and policy-driven public X.509 assessment, threat detection, uRPF, VPN, and failover controls; current ASA 9.x defaults are not applied to PIX |
| Fortinet FortiOS | VDOM-aware management and policy checks plus administrator trust/MFA/remote authentication, FortiOS 7.4+ administrative RADIUS/RadSec transport, password/session controls, management crypto, SNMPv3, authenticated NTP, logging, updates, unused interfaces/services, active-policy UTM group/member resolution, distinct IPv4/IPv6 unrestricted local-in management detection, attached same-VDOM IKE/IPsec proposal/reference checks, and DoS protection |
| Check Point FW1 | Typed ordered-layer analysis for broad/risky/negated access, explicit cleanup and gateway stealth rules, tracking and install scope, disabled/expired rules, conservative same-layer subnet/range/protocol/port shadowing and redundancy, and unresolved object/service/group references |
| Juniper Junos | Effective services, SSH root access and algorithms, authentication, credentials, attached stateless filters, SRX zone-pair broad-permit analysis with static address/application resolution, attached/interface-bound IKE/IPsec proposal/reference checks, SNMP, logging, authenticated NTP, BGP neighbor authentication and external-peer route policy/prefix limits, OSPFv2 interface authentication, explicitly external LLDP exposure, Routing Engine protection, and redirect controls |
| Juniper ScreenOS | Effective management/policy checks plus EOL, source restriction, SSHv2/HTTPS, default credential, banner, syslog, SNMP, NTP presence, policy logging, and referenced VPN crypto controls; ScreenOS 6.3 additionally separates console/Telnet, WebUI, administrator-AAA and policy/user auth-server timeout checks and detects explicit default-permit policy state |

## Verified secondary-platform static baselines

| Platform | Implemented analysis |
|---|---|
| Palo Alto PAN-OS | Attached dataplane and dedicated-MGT services, source restrictions, ordered rules, session/traffic/system log forwarding, same-vsys/shared security profile group/member resolution with empty/non-blocking/unresolved findings, administrator authentication, password complexity, DNS, release-aware NTP, SNMPv3, scoped management X.509 assessment, content updates, and explicit Panorama confidence |
| HP/ArubaOS-Switch | Version-aware Telnet/WebAgent, authorized managers, centralized AAA and accounting, local password control, exact SNMP community state and independently evaluated v3 users, effective SSH suites, remote logging, per-server SNTP key/trust resolution, configured-VLAN DHCP snooping, and explicit access-edge tagged/trust/ARP/source-lockdown/port-security checks |
| SonicWall SonicOS 7 | Per-interface management/zone exposure, typed access-rule logging/breadth, active VPN suites, independently evaluated active SNMPv3 users, syslog, authenticated NTP, explicit threat-service state, and Capture ATP dependencies; unsupported formats stop before analysis |
| Arista EOS | Active eAPI HTTP/HTTPS, shutdown, VRF and service ACL scope, local no-password/plaintext/legacy-MD5 credential storage, centralized authentication and exec authorization, explicit SSH empty-password/algorithm/service-ACL policy, independently evaluated SNMPv3 users/groups/views/VRF ACLs, syslog, and release-aware symmetric/NTS time authentication |

T-030 and T-032 are closed at this bounded static-analysis scope. These are not claims of the same breadth as the seven target platforms: an explicit assessment time can grade exported certificate material, but the certificate actually served, revocation, runtime authorization outcome, licensing/subscription state, installed policy, negotiated VPN security associations, peer identity, and time-sensitive firmware support cannot be established from the supported configuration files alone.

Check Point analysis is intentionally limited to what matching offline exports prove. It does not claim the policy was successfully compiled or installed, resolve runtime dynamic-object membership, use hit counts, or detect conflicts across different ordered/inline layers. Expiry findings require a directly exported literal date. Shadow/redundancy findings require positive non-negated fields with matching time, VPN, through, compatible install-on scope, and completely resolved static network and service semantics; partial overlap is not reported as full containment.

Every finding constructed by the eleven corpus pipelines now includes at least one authoritative vendor-documentation URL. A source-level test rejects any covered plugin `Finding` construction without references, and the permanent public-pipeline corpus rejects emitted findings without an HTTPS source or with an insecure external URL.

## Plugin requirements

- Extend `BasePlugin`.
- Accept a parser object rather than reopening the configuration file.
- Evaluate ordered effective state, including negation, disablement, deletion, attachment, and scope.
- Emit one root cause per stable rule ID and preserve object-specific evidence.
- Redact credentials, communities, keys, and other secrets before they become evidence.
- Cite the vendor guide or control source in `Finding.references` for every check.
- Add true-positive, true-negative, override, unknown/not-applicable, and public-pipeline tests.

Processors register plugins explicitly; executable plugin discovery by filename is not supported. See [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) for the execution flow and [`docs/EXTENDING.md`](../../docs/EXTENDING.md) for the complete extension checklist.
