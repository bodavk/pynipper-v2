# Device analysis

Analyzers run focused plugin classes against a `BaseDeviceParser` and return vendor-neutral `Finding` objects with stable rule IDs, severity, exploitability, source evidence, and optional security references.

## Verified target-platform coverage

| Platform | Implemented analysis |
|---|---|
| Cisco IOS | Effective HTTP and SSH checks plus AAA, management-line, credential, SNMP, logging, NTP, banner, service, interface, control-plane, and VPN baseline rules |
| Cisco IOS-XE | IOS-family composition plus active, scope-aware MACsec, IKE, and IPsec checks |
| Cisco ASA | Single deduplicated pipeline for management, logging, TLS, ACL, credentials, SNMP, AAA, NTP, certificates, threat detection, uRPF, VPN, and failover controls |
| Fortinet FortiOS | VDOM-aware management and policy checks plus administrator trust/MFA/remote authentication, password/lockout/session controls, management TLS/SSH/certificates, SNMPv3, authenticated NTP, local/remote logging filters and secondary destinations, FortiGuard/firmware updates, unused interfaces/services, policy logging/security profiles, and DoS protection |
| Check Point FW1 | Typed ordered-layer analysis for broad/risky/negated access, explicit cleanup and gateway stealth rules, tracking and install scope, disabled/expired rules, conservative same-layer shadowing/redundancy, and unresolved object/service/group references |
| Juniper Junos | Effective services, SSH root access and algorithms, authentication, credentials, attached filters, SNMP, logging, authenticated NTP, Routing Engine protection, and redirect controls |
| Juniper ScreenOS | Effective management/policy checks plus EOL, source restriction, timeout, SSHv2/HTTPS, default credential, banner, syslog, SNMP, NTP, policy logging, and referenced VPN crypto controls |

## Verified secondary-platform static baselines

| Platform | Implemented analysis |
|---|---|
| Palo Alto PAN-OS | Attached dataplane and dedicated-MGT services, source restrictions, ordered rules, session/traffic/system log forwarding, security profiles, administrator authentication, password complexity, DNS/NTP, SNMPv3, management TLS/certificate resolution, automatic threat-content installation, and explicit Panorama confidence |
| HP/ArubaOS-Switch | Version-aware Telnet/WebAgent, authorized managers, centralized AAA and accounting, local password control, exact SNMP community/v3 state, effective SSH suites, remote logging, SNTP, and configured-VLAN DHCP snooping |
| SonicWall SonicOS 7 | Per-interface management/zone exposure, typed access-rule logging/breadth, active VPN suites, SNMPv3, syslog, authenticated NTP, explicit threat-service state, and Capture ATP dependencies; unsupported formats stop before analysis |
| Arista EOS | Active eAPI HTTP/HTTPS, shutdown, VRF and service ACL scope, centralized authentication and exec authorization, explicit SSH empty-password/algorithm/service-ACL policy, SNMP community/v3, syslog, and NTP |

T-030 and T-032 are closed at this bounded static-analysis scope. These are not claims of the same breadth as the seven target platforms: live certificate validity, runtime authorization outcome, licensing/subscription state, and time-sensitive firmware support cannot be established from the supported configuration files alone.

Check Point analysis is intentionally limited to what matching offline exports prove. It does not claim the policy was successfully compiled or installed, resolve runtime dynamic-object membership, use hit counts, or detect conflicts across different ordered/inline layers. Expiry findings require a directly exported literal date, and shadow/redundancy findings require positive non-negated fields with matching time, VPN, through, and compatible install-on scope.

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
