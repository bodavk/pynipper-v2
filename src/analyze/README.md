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

PAN-OS, HP ProCurve/ArubaOS-Switch, SonicOS, and Arista EOS currently retain basic plugins. Their task-list entries define the parser and correctness work required before they can be described as equivalent to the target-platform baselines.

Check Point analysis is intentionally limited to what matching offline exports prove. It does not claim the policy was successfully compiled or installed, resolve runtime dynamic-object membership, use hit counts, or detect conflicts across different ordered/inline layers. Expiry findings require a directly exported literal date, and shadow/redundancy findings require positive non-negated fields with matching time, VPN, through, and compatible install-on scope.

## Plugin requirements

- Extend `BasePlugin`.
- Accept a parser object rather than reopening the configuration file.
- Evaluate ordered effective state, including negation, disablement, deletion, attachment, and scope.
- Emit one root cause per stable rule ID and preserve object-specific evidence.
- Redact credentials, communities, keys, and other secrets before they become evidence.
- Cite the vendor guide or control source in `Finding.references` for new checks.
- Add true-positive, true-negative, override, unknown/not-applicable, and public-pipeline tests.

Processors register plugins explicitly; executable plugin discovery by filename is not supported. See [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) for the execution flow and [`docs/EXTENDING.md`](../../docs/EXTENDING.md) for the complete extension checklist.
