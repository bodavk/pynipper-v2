# Outside-project configuration validation

Audit started 2026-09-21. This document separates the independent, pre-scan assessments below from the later scanner results. The inputs were selected from public network-deployment or published configuration examples because they represent supported export families, without consulting the tool's findings first. Source links and SHA-256 identify the exact downloaded bytes. An external template or excerpt is labelled as such; missing lines in one are not evidence that a deployed device lacks a control. "Ground truth" here means a concrete, observable security concern in the supplied text, with uncertainty stated where site context could change the judgment. No repository test fixture is used.

The current checkout contains no `docs/agent_notes/GAP_REMEDIATION_TASKS.md`, standards, legacy or detection-audit task file. I checked [the current improvement list](../TODO.md) to avoid duplicating planned coverage. The [registry](../../src/devices/registry.py) has 14 canonical IDs and 11 pipelines; IOS_SWITCH, IOS_ROUTER and IOS_CATALYST share IOS, while PIX and ASA share ASA. A successful scan under an alias does not establish that an independently different historical dialect is understood.

The documented editable installation succeeded after granting package-index access; an initial sandboxed attempt failed solely while fetching build dependencies. `pynipper-ng --help` exited 0 and listed all 14 IDs plus aliases and the documented HTML/JSON, offline and assessment-policy flags. This is an environment/network prerequisite, not a product defect. The smoke and per-config invocations/results appear below after capture. All scanner invocations use the installed public command with `--offline`.

**Run method and limits.** On 2026-09-21, the installed `.venv\Scripts\pynipper-ng.exe` accepted all 14 canonical device flags in 36 successful JSON invocations and one failed FortiOS invocation across 31 distinct inputs. Each invocation used `--device <ID> --input <absolute temporary path> --output-type JSON --output-filename <absolute temporary report path> --offline`; generated stdout and the complete JSON report follow under that case, with report SHA-256 for byte-level verification. Stderr was empty for all 36 successful scans; the failed FortiOS invocation emitted the complete traceback below. An additional trivial IOS input (`version 15.0`, `hostname smoke`) produced a 21,594-byte HTML report with exit code 0, confirming both documented formats; its smoke input is not used as field evidence. All input files lived under `%TEMP%\pynipper-realworld-2026-09-21`, outside this repository. Two HP and two PIX inputs are transcribed excerpts; absence claims on those are unsupported. SonicOS and Check Point have two explicitly synthetic fallback inputs each. RW-031 is an unresolved deployment template and its crash is recorded without claiming a deployed firewall was affected. The Check Point fallbacks yielded zero parsed policies, so their detection accuracy is **not established**. No Git command or code/test-fixture change was made.

| Canonical ID | Independently assessed input cases | Qualification |
| --- | --- | --- |
| IOS_SWITCH | [RW-001](#RW-001), [RW-012](#RW-012), [RW-027](#RW-027) | Catalyst 3650 / two classic 2960 |
| IOS_ROUTER | [RW-002](#RW-002), [RW-017](#RW-017), [RW-026](#RW-026) | ASR IOS-XE alias / IOSv / classic 2901 |
| IOS_CATALYST | [RW-001](#RW-001), [RW-012](#RW-012), [RW-027](#RW-027) | Same IOS parser as IOS_SWITCH |
| PIX | [RW-020](#RW-020), [RW-021](#RW-021) | Real PIX 6.3 syntax, shared ASA parser |
| ASA | [RW-003](#RW-003), [RW-008](#RW-008) | ASA 9.3 excerpt / 9.2 Azure sample |
| SCREENOS | [RW-004](#RW-004), [RW-016](#RW-016) | Azure sample / Juniper operator post |
| SONICOS | [RW-022](#RW-022), [RW-023](#RW-023) | **SYNTHETIC** fallback only |
| CHECKPOINT_FW1 | [RW-024](#RW-024), [RW-025](#RW-025) | **SYNTHETIC**, parsing indeterminate |
| HP_PROCURVE | [RW-018](#RW-018), [RW-019](#RW-019) | Two HPE operator excerpts |
| PAN_OS | [RW-006](#RW-006), [RW-010](#RW-010), [RW-030](#RW-030) | Two vendor samples / loadable baseline |
| FORTIOS | [RW-007](#RW-007), [RW-011](#RW-011), [RW-031](#RW-031) | Public baseline template / export / AWS deployment template; RW-031 crashes |
| IOS_XE | [RW-001](#RW-001), [RW-002](#RW-002) | Switch and router running configs |
| JUNOS | [RW-014](#RW-014), [RW-015](#RW-015), [RW-029](#RW-029) | SRX samples; [RW-013](#RW-013) parse-error control |
| ARISTA_EOS | [RW-005](#RW-005), [RW-009](#RW-009), [RW-028](#RW-028) | Three intended leaf configs in one lab |

## Pre-scan ground truth, recorded before any scanner run

<a id="RW-001"></a>
### IOS_XE / IOS_SWITCH / IOS_CATALYST — Published Catalyst 3650 home-switch running configuration

**Provenance:** [Cisco 3650 switch config for home network](https://gist.github.com/sensai-of-rootbeer/2a6a4342668e3003396deda76a0cc49a), downloaded as the gist's raw file; SHA-256 `41A6CBB40B74CB91B461BEB662612D828D1FCFAB5C10978F20A0812347584BC4`. This is a posted, redacted running configuration, not a repository fixture. IOS-XE classification follows its WS-C3650 provision statement; the two IOS switch IDs are also run to test their documented shared path. The redacted `password` placeholders do not establish their actual values.

**Ground truth (established before running the tool):**
- Lines 321–323 enable both cleartext HTTP and HTTPS administration; HTTP can expose credentials/session data when reachable. [Cisco IOS XE hardening guidance](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening) recommends secure management protocols.
- Line 329 configures an SNMP community (`WORD`) with read-only access. That is legacy community-based management rather than authenticated/private SNMPv3; the literal may be a redaction and is not scored as a known default password.
- Lines 347–354 set a 90-minute VTY idle timeout. The [IOS XE guide's EXEC Timeout section](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening) documents a ten-minute default and idle-session risk. A site could choose another approved limit, but 90 minutes is materially long for interactive administration.
- The username line explicitly uses reversible type-7 storage. Its actual value is redacted, so only the storage property is scored; the enable-secret placeholder cannot be judged.
- This is a full `show running-config` capture with no NTP server, remote logging destination or VTY source ACL. They are hardening deficiencies on a remotely managed switch, although reachability and external monitoring topology are unknown. They are recorded separately from the explicit unsafe commands.

**Tool output (actual, unedited):**

**RW001-XE CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Cisco IOS-XE)
[2/4] Fetching IOS-XE API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW001-XE.json
```

**RW001-XE generated JSON report (SHA-256 `0FC519F781DBF5F68E5B7C02F54C90625945C8B02F93ECA17CD3E2B4D4EDE902`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "IOS_XE",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "IOS running configuration does not provide reliable model metadata",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 4,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 57,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoIOSXEParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:21:56.324098",
        "device-type": "IOS_XE",
        "hostname": "Switch"
    },
    "remediation-summary": {
        "finding-count": 24,
        "priority-actions": [
            {
                "recommendation": "Disable it with 'no ip http server' and use HTTPS or SSH for remote administration.",
                "rule-id": "cisco.ios.http.cleartext_service",
                "severity": "High",
                "title": "Clear-text HTTP management service enabled"
            },
            {
                "recommendation": "Restrict management sources with 'ip http access-class <ACL>' or disable HTTP.",
                "rule-id": "cisco.ios.http.access_restriction",
                "severity": "High",
                "title": "HTTP management access is unrestricted"
            },
            {
                "recommendation": "Enforce SSHv2 with 'ip ssh version 2'.",
                "rule-id": "cisco.ios.ssh.protocol_version",
                "severity": "High",
                "title": "SSH protocol version 2 is not enforced"
            },
            {
                "recommendation": "Configure an 'aaa authentication login' method list with an appropriate local fallback.",
                "rule-id": "cisco.ios.aaa.login_authentication",
                "severity": "High",
                "title": "AAA login authentication method list is missing"
            },
            {
                "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
                "rule-id": "cisco.ios.vty.authentication",
                "severity": "High",
                "title": "VTY authentication is not explicitly bound"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 11,
            "Low": 1,
            "Medium": 12
        }
    },
    "security-audit": {
        "9.0.0. Clear-text HTTP management service enabled": {
            "device": "IOS_XE",
            "ease": "An attacker with access to the management traffic path can observe or alter clear-text HTTP traffic.",
            "evidence": [
                "ip http server"
            ],
            "exploitability": "An attacker with access to the management traffic path can observe or alter clear-text HTTP traffic.",
            "impact": "Administrative credentials and sessions can be exposed to interception or modification.",
            "observation": "The IOS HTTP management server is explicitly enabled.",
            "recommendation": "Disable it with 'no ip http server' and use HTTPS or SSH for remote administration.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-17/https-xe-17-book/HTTP_1-1_Web_Server_and_Client.html"
            ],
            "rule_id": "cisco.ios.http.cleartext_service",
            "severity": "High",
            "title": "Clear-text HTTP management service enabled"
        },
        "9.0.1. HTTP management access is unrestricted": {
            "device": "IOS_XE",
            "ease": "An attacker only needs network reachability to attempt authentication or exploit the HTTP service.",
            "evidence": [
                "ip http server"
            ],
            "exploitability": "An attacker only needs network reachability to attempt authentication or exploit the HTTP service.",
            "impact": "Untrusted networks may be able to reach the device management service.",
            "observation": "The enabled HTTP server has no effective 'ip http access-class' restriction.",
            "recommendation": "Restrict management sources with 'ip http access-class <ACL>' or disable HTTP.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-17/https-xe-17-book/HTTP_1-1_Web_Server_and_Client.html"
            ],
            "rule_id": "cisco.ios.http.access_restriction",
            "severity": "High",
            "title": "HTTP management access is unrestricted"
        },
        "9.0.10. VTY administrative authorization is incomplete": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 5 15",
                "exec-timeout 90 0",
                "transport input ssh",
                "transport output ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
            "observation": "line vty 5 15 lacks resolved EXEC authorization, privilege-15 command authorization.",
            "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authorization",
            "severity": "High",
            "title": "VTY administrative authorization is incomplete"
        },
        "9.0.11. Console authentication is not explicitly secured": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line con 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Physical or terminal-server access may reach an unintended authentication path.",
            "observation": "line con 0 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.console.authentication",
            "severity": "High",
            "title": "Console authentication is not explicitly secured"
        },
        "9.0.12. Auxiliary management line is not fully disabled": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line aux 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unused AUX port can provide an additional local, modem, or reverse-terminal management path.",
            "observation": "line aux 0 does not combine 'no exec', 'transport input none', and 'transport output none'.",
            "recommendation": "Disable the AUX line using the complete Cisco hardening sequence unless it has an approved operational use.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.auxiliary.enabled",
            "severity": "High",
            "title": "Auxiliary management line is not fully disabled"
        },
        "9.0.13. Active auxiliary line lacks resolved authentication": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line aux 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A reachable AUX session may use an unintended or line-password authentication path.",
            "observation": "line aux 0 is not disabled and lacks a resolvable local or AAA login binding.",
            "recommendation": "Disable the line or bind it to a tested AAA login method.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.auxiliary.authentication",
            "severity": "High",
            "title": "Active auxiliary line lacks resolved authentication"
        },
        "9.0.14. Legacy SNMP community configured": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "snmp-server community <redacted> ro"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Community-based SNMP lacks modern per-user authentication and privacy protections.",
            "observation": "An SNMPv1/v2c community uses community-based SNMP. The value is redacted.",
            "recommendation": "Migrate to SNMPv3 authPriv, restrict managers, and remove v1/v2c communities.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.snmp.legacy_community",
            "severity": "Medium",
            "title": "Legacy SNMP community configured"
        },
        "9.0.15. Remote logging destination is missing": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No logging host command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Events may be lost during compromise or device failure and unavailable to central monitoring.",
            "observation": "No active remote syslog destination is configured.",
            "recommendation": "Configure one or more protected remote logging hosts.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.logging.remote_destination",
            "severity": "Medium",
            "title": "Remote logging destination is missing"
        },
        "9.0.16. Configuration-change logging is disabled": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "archive log config logging enable absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative changes can lack a local per-user, per-session command history.",
            "observation": "The effective archive log-config state does not enable configuration-change logging.",
            "recommendation": "Enable 'archive / log config / logging enable', suppress keys, and notify syslog.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html"
            ],
            "rule_id": "cisco.ios.configuration.change_logging",
            "severity": "Medium",
            "title": "Configuration-change logging is disabled"
        },
        "9.0.17. NTP synchronization is not configured": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No ntp server or peer command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Inaccurate time undermines event correlation, certificates, and forensic timelines.",
            "observation": "No NTP server or peer is configured.",
            "recommendation": "Configure multiple trusted NTP servers.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.servers",
            "severity": "Medium",
            "title": "NTP synchronization is not configured"
        },
        "9.0.18. IP source routing is not explicitly disabled": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "no ip source-route absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Source-routed packets can bypass expected routing paths and trust boundaries on applicable releases.",
            "observation": "The configuration does not contain the IOS 'no ip source-route' hardening command.",
            "recommendation": "Configure 'no ip source-route'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ip.source_route",
            "severity": "Medium",
            "title": "IP source routing is not explicitly disabled"
        },
        "9.0.19. Layer-3 interface hardening is incomplete": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Loopback1",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Loopback1 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "9.0.2. SSH protocol version 2 is not enforced": {
            "device": "IOS_XE",
            "ease": "An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            "evidence": [
                "line vty 0 4",
                "line vty 5 15"
            ],
            "exploitability": "An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            "impact": "SSHv1 has fundamental protocol weaknesses and permits downgrade exposure where compatibility mode is allowed.",
            "observation": "The reachable SSH service uses compatibility mode (SSHv1 and SSHv2).",
            "recommendation": "Enforce SSHv2 with 'ip ssh version 2'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.protocol_version",
            "severity": "High",
            "title": "SSH protocol version 2 is not enforced"
        },
        "9.0.20. Layer-3 interface hardening is incomplete": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Loopback2",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Loopback2 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "9.0.21. Layer-3 interface hardening is incomplete": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Vlan1",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Vlan1 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "9.0.22. Layer-3 interface hardening is incomplete": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Vlan99",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Vlan99 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "9.0.23. Control-plane policing is not attached": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No control-plane service-policy input"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Unrestricted control-plane traffic can contribute to CPU exhaustion and management outages.",
            "observation": "No input service policy is attached under control-plane configuration.",
            "recommendation": "Deploy a validated Control Plane Policing policy appropriate for the platform role.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/quality-of-service/quality-of-service/m_qos-plcshp-ctrl-pln-plc-0.html"
            ],
            "rule_id": "cisco.ios.control_plane.copp",
            "severity": "Medium",
            "title": "Control-plane policing is not attached"
        },
        "9.0.3. SSH negotiation timeout is unsafe": {
            "device": "IOS_XE",
            "ease": "A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            "evidence": [
                "effective documented default: 120"
            ],
            "exploitability": "A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            "impact": "Long unauthenticated negotiations consume management-plane resources and leave sessions open unnecessarily.",
            "observation": "The effective SSH negotiation timeout is 120 seconds; the policy maximum is 60 seconds.",
            "recommendation": "Configure 'ip ssh time-out <1-60>'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.negotiation_timeout",
            "severity": "Low",
            "title": "SSH negotiation timeout is unsafe"
        },
        "9.0.4. SSH VTY access is not source-restricted": {
            "device": "IOS_XE",
            "ease": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "evidence": [
                "line vty 0 4",
                "line vty 5 15"
            ],
            "exploitability": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "impact": "Any source with network reachability can attempt to access the SSH management service.",
            "observation": "At least one SSH-enabled VTY range lacks an inbound IPv4 or IPv6 access-class.",
            "recommendation": "Apply 'access-class <ACL> in' or 'ipv6 access-class <ACL> in' to every SSH-enabled VTY range.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.vty_access_restriction",
            "severity": "Medium",
            "title": "SSH VTY access is not source-restricted"
        },
        "9.0.5. AAA login authentication method list is missing": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "aaa new-model"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Management lines may fall back to an unintended authentication behavior.",
            "observation": "AAA is enabled but no login authentication method list is configured.",
            "recommendation": "Configure an 'aaa authentication login' method list with an appropriate local fallback.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.aaa.login_authentication",
            "severity": "High",
            "title": "AAA login authentication method list is missing"
        },
        "9.0.6. Administrative AAA accounting is missing": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "aaa new-model"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative activity may not be attributable or centrally auditable.",
            "observation": "AAA is enabled but no EXEC or command accounting method is configured.",
            "recommendation": "Configure start-stop EXEC and command accounting to a resilient AAA service.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.aaa.accounting",
            "severity": "Medium",
            "title": "Administrative AAA accounting is missing"
        },
        "9.0.7. VTY authentication is not explicitly bound": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4",
                "exec-timeout 90 0",
                "transport input ssh",
                "transport output ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "The line may use an unintended password-only or default authentication path.",
            "observation": "line vty 0 4 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authentication",
            "severity": "High",
            "title": "VTY authentication is not explicitly bound"
        },
        "9.0.8. VTY administrative authorization is incomplete": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4",
                "exec-timeout 90 0",
                "transport input ssh",
                "transport output ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
            "observation": "line vty 0 4 lacks resolved EXEC authorization, privilege-15 command authorization.",
            "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authorization",
            "severity": "High",
            "title": "VTY administrative authorization is incomplete"
        },
        "9.0.9. VTY authentication is not explicitly bound": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 5 15",
                "exec-timeout 90 0",
                "transport input ssh",
                "transport output ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "The line may use an unintended password-only or default authentication path.",
            "observation": "line vty 5 15 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authentication",
            "severity": "High",
            "title": "VTY authentication is not explicitly bound"
        }
    },
    "vulnerabilities": []
}
```

**RW001-SW CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng
[2/4] Fetching Cisco API information
[2/4] Cisco API disable.
[3/4] Checking missconfiguration vulnerabilities
[3/4] Scanning configuration file using the following IOS plugins: ['PluginHTTP', 'PluginSSH', 'PluginIOSBaseline']
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW001-SW.json
```

**RW001-SW generated JSON report (SHA-256 `3BB51674ECF9BD54C773C51DABF57564CE45D2A97334DAE4683CE15806DDFE73`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "IOS_SWITCH",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "IOS running configuration does not provide reliable model metadata",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 4,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 57,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoIOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:21:56.857474",
        "device-type": "IOS_SWITCH",
        "hostname": "Switch"
    },
    "remediation-summary": {
        "finding-count": 24,
        "priority-actions": [
            {
                "recommendation": "Disable it with 'no ip http server' and use HTTPS or SSH for remote administration.",
                "rule-id": "cisco.ios.http.cleartext_service",
                "severity": "High",
                "title": "Clear-text HTTP management service enabled"
            },
            {
                "recommendation": "Restrict management sources with 'ip http access-class <ACL>' or disable HTTP.",
                "rule-id": "cisco.ios.http.access_restriction",
                "severity": "High",
                "title": "HTTP management access is unrestricted"
            },
            {
                "recommendation": "Enforce SSHv2 with 'ip ssh version 2'.",
                "rule-id": "cisco.ios.ssh.protocol_version",
                "severity": "High",
                "title": "SSH protocol version 2 is not enforced"
            },
            {
                "recommendation": "Configure an 'aaa authentication login' method list with an appropriate local fallback.",
                "rule-id": "cisco.ios.aaa.login_authentication",
                "severity": "High",
                "title": "AAA login authentication method list is missing"
            },
            {
                "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
                "rule-id": "cisco.ios.vty.authentication",
                "severity": "High",
                "title": "VTY authentication is not explicitly bound"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 11,
            "Low": 1,
            "Medium": 12
        }
    },
    "security-audit": {
        "2.0.0. Clear-text HTTP management service enabled": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with access to the management traffic path can observe or alter clear-text HTTP traffic.",
            "evidence": [
                "ip http server"
            ],
            "exploitability": "An attacker with access to the management traffic path can observe or alter clear-text HTTP traffic.",
            "impact": "Administrative credentials and sessions can be exposed to interception or modification.",
            "observation": "The IOS HTTP management server is explicitly enabled.",
            "recommendation": "Disable it with 'no ip http server' and use HTTPS or SSH for remote administration.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-17/https-xe-17-book/HTTP_1-1_Web_Server_and_Client.html"
            ],
            "rule_id": "cisco.ios.http.cleartext_service",
            "severity": "High",
            "title": "Clear-text HTTP management service enabled"
        },
        "2.0.1. HTTP management access is unrestricted": {
            "device": "IOS_SWITCH",
            "ease": "An attacker only needs network reachability to attempt authentication or exploit the HTTP service.",
            "evidence": [
                "ip http server"
            ],
            "exploitability": "An attacker only needs network reachability to attempt authentication or exploit the HTTP service.",
            "impact": "Untrusted networks may be able to reach the device management service.",
            "observation": "The enabled HTTP server has no effective 'ip http access-class' restriction.",
            "recommendation": "Restrict management sources with 'ip http access-class <ACL>' or disable HTTP.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-17/https-xe-17-book/HTTP_1-1_Web_Server_and_Client.html"
            ],
            "rule_id": "cisco.ios.http.access_restriction",
            "severity": "High",
            "title": "HTTP management access is unrestricted"
        },
        "2.0.10. VTY administrative authorization is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 5 15",
                "exec-timeout 90 0",
                "transport input ssh",
                "transport output ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
            "observation": "line vty 5 15 lacks resolved EXEC authorization, privilege-15 command authorization.",
            "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authorization",
            "severity": "High",
            "title": "VTY administrative authorization is incomplete"
        },
        "2.0.11. Console authentication is not explicitly secured": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line con 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Physical or terminal-server access may reach an unintended authentication path.",
            "observation": "line con 0 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.console.authentication",
            "severity": "High",
            "title": "Console authentication is not explicitly secured"
        },
        "2.0.12. Auxiliary management line is not fully disabled": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line aux 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unused AUX port can provide an additional local, modem, or reverse-terminal management path.",
            "observation": "line aux 0 does not combine 'no exec', 'transport input none', and 'transport output none'.",
            "recommendation": "Disable the AUX line using the complete Cisco hardening sequence unless it has an approved operational use.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.auxiliary.enabled",
            "severity": "High",
            "title": "Auxiliary management line is not fully disabled"
        },
        "2.0.13. Active auxiliary line lacks resolved authentication": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line aux 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A reachable AUX session may use an unintended or line-password authentication path.",
            "observation": "line aux 0 is not disabled and lacks a resolvable local or AAA login binding.",
            "recommendation": "Disable the line or bind it to a tested AAA login method.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.auxiliary.authentication",
            "severity": "High",
            "title": "Active auxiliary line lacks resolved authentication"
        },
        "2.0.14. Legacy SNMP community configured": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "snmp-server community <redacted> ro"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Community-based SNMP lacks modern per-user authentication and privacy protections.",
            "observation": "An SNMPv1/v2c community uses community-based SNMP. The value is redacted.",
            "recommendation": "Migrate to SNMPv3 authPriv, restrict managers, and remove v1/v2c communities.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.snmp.legacy_community",
            "severity": "Medium",
            "title": "Legacy SNMP community configured"
        },
        "2.0.15. Remote logging destination is missing": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No logging host command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Events may be lost during compromise or device failure and unavailable to central monitoring.",
            "observation": "No active remote syslog destination is configured.",
            "recommendation": "Configure one or more protected remote logging hosts.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.logging.remote_destination",
            "severity": "Medium",
            "title": "Remote logging destination is missing"
        },
        "2.0.16. Configuration-change logging is disabled": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "archive log config logging enable absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative changes can lack a local per-user, per-session command history.",
            "observation": "The effective archive log-config state does not enable configuration-change logging.",
            "recommendation": "Enable 'archive / log config / logging enable', suppress keys, and notify syslog.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html"
            ],
            "rule_id": "cisco.ios.configuration.change_logging",
            "severity": "Medium",
            "title": "Configuration-change logging is disabled"
        },
        "2.0.17. NTP synchronization is not configured": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No ntp server or peer command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Inaccurate time undermines event correlation, certificates, and forensic timelines.",
            "observation": "No NTP server or peer is configured.",
            "recommendation": "Configure multiple trusted NTP servers.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.servers",
            "severity": "Medium",
            "title": "NTP synchronization is not configured"
        },
        "2.0.18. IP source routing is not explicitly disabled": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "no ip source-route absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Source-routed packets can bypass expected routing paths and trust boundaries on applicable releases.",
            "observation": "The configuration does not contain the IOS 'no ip source-route' hardening command.",
            "recommendation": "Configure 'no ip source-route'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ip.source_route",
            "severity": "Medium",
            "title": "IP source routing is not explicitly disabled"
        },
        "2.0.19. Layer-3 interface hardening is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Loopback1",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Loopback1 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.2. SSH protocol version 2 is not enforced": {
            "device": "IOS_SWITCH",
            "ease": "An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            "evidence": [
                "line vty 0 4",
                "line vty 5 15"
            ],
            "exploitability": "An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            "impact": "SSHv1 has fundamental protocol weaknesses and permits downgrade exposure where compatibility mode is allowed.",
            "observation": "The reachable SSH service uses compatibility mode (SSHv1 and SSHv2).",
            "recommendation": "Enforce SSHv2 with 'ip ssh version 2'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.protocol_version",
            "severity": "High",
            "title": "SSH protocol version 2 is not enforced"
        },
        "2.0.20. Layer-3 interface hardening is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Loopback2",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Loopback2 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.21. Layer-3 interface hardening is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Vlan1",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Vlan1 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.22. Layer-3 interface hardening is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Vlan99",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Vlan99 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.23. Control-plane policing is not attached": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No control-plane service-policy input"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Unrestricted control-plane traffic can contribute to CPU exhaustion and management outages.",
            "observation": "No input service policy is attached under control-plane configuration.",
            "recommendation": "Deploy a validated Control Plane Policing policy appropriate for the platform role.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/quality-of-service/quality-of-service/m_qos-plcshp-ctrl-pln-plc-0.html"
            ],
            "rule_id": "cisco.ios.control_plane.copp",
            "severity": "Medium",
            "title": "Control-plane policing is not attached"
        },
        "2.0.3. SSH negotiation timeout is unsafe": {
            "device": "IOS_SWITCH",
            "ease": "A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            "evidence": [
                "effective documented default: 120"
            ],
            "exploitability": "A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            "impact": "Long unauthenticated negotiations consume management-plane resources and leave sessions open unnecessarily.",
            "observation": "The effective SSH negotiation timeout is 120 seconds; the policy maximum is 60 seconds.",
            "recommendation": "Configure 'ip ssh time-out <1-60>'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.negotiation_timeout",
            "severity": "Low",
            "title": "SSH negotiation timeout is unsafe"
        },
        "2.0.4. SSH VTY access is not source-restricted": {
            "device": "IOS_SWITCH",
            "ease": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "evidence": [
                "line vty 0 4",
                "line vty 5 15"
            ],
            "exploitability": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "impact": "Any source with network reachability can attempt to access the SSH management service.",
            "observation": "At least one SSH-enabled VTY range lacks an inbound IPv4 or IPv6 access-class.",
            "recommendation": "Apply 'access-class <ACL> in' or 'ipv6 access-class <ACL> in' to every SSH-enabled VTY range.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.vty_access_restriction",
            "severity": "Medium",
            "title": "SSH VTY access is not source-restricted"
        },
        "2.0.5. AAA login authentication method list is missing": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "aaa new-model"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Management lines may fall back to an unintended authentication behavior.",
            "observation": "AAA is enabled but no login authentication method list is configured.",
            "recommendation": "Configure an 'aaa authentication login' method list with an appropriate local fallback.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.aaa.login_authentication",
            "severity": "High",
            "title": "AAA login authentication method list is missing"
        },
        "2.0.6. Administrative AAA accounting is missing": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "aaa new-model"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative activity may not be attributable or centrally auditable.",
            "observation": "AAA is enabled but no EXEC or command accounting method is configured.",
            "recommendation": "Configure start-stop EXEC and command accounting to a resilient AAA service.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.aaa.accounting",
            "severity": "Medium",
            "title": "Administrative AAA accounting is missing"
        },
        "2.0.7. VTY authentication is not explicitly bound": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4",
                "exec-timeout 90 0",
                "transport input ssh",
                "transport output ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "The line may use an unintended password-only or default authentication path.",
            "observation": "line vty 0 4 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authentication",
            "severity": "High",
            "title": "VTY authentication is not explicitly bound"
        },
        "2.0.8. VTY administrative authorization is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4",
                "exec-timeout 90 0",
                "transport input ssh",
                "transport output ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
            "observation": "line vty 0 4 lacks resolved EXEC authorization, privilege-15 command authorization.",
            "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authorization",
            "severity": "High",
            "title": "VTY administrative authorization is incomplete"
        },
        "2.0.9. VTY authentication is not explicitly bound": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 5 15",
                "exec-timeout 90 0",
                "transport input ssh",
                "transport output ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "The line may use an unintended password-only or default authentication path.",
            "observation": "line vty 5 15 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authentication",
            "severity": "High",
            "title": "VTY authentication is not explicitly bound"
        }
    },
    "vulnerabilities": []
}
```

**RW001-CAT CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng
[2/4] Fetching Cisco API information
[2/4] Cisco API disable.
[3/4] Checking missconfiguration vulnerabilities
[3/4] Scanning configuration file using the following IOS plugins: ['PluginHTTP', 'PluginSSH', 'PluginIOSBaseline']
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW001-CAT.json
```

**RW001-CAT generated JSON report (SHA-256 `52027A00D50900ED736FB83E790E1A55473B97492E13B1C78894D09C78C0BEB9`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "IOS_CATALYST",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "IOS running configuration does not provide reliable model metadata",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 4,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 57,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoIOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:21:57.394364",
        "device-type": "IOS_CATALYST",
        "hostname": "Switch"
    },
    "remediation-summary": {
        "finding-count": 24,
        "priority-actions": [
            {
                "recommendation": "Disable it with 'no ip http server' and use HTTPS or SSH for remote administration.",
                "rule-id": "cisco.ios.http.cleartext_service",
                "severity": "High",
                "title": "Clear-text HTTP management service enabled"
            },
            {
                "recommendation": "Restrict management sources with 'ip http access-class <ACL>' or disable HTTP.",
                "rule-id": "cisco.ios.http.access_restriction",
                "severity": "High",
                "title": "HTTP management access is unrestricted"
            },
            {
                "recommendation": "Enforce SSHv2 with 'ip ssh version 2'.",
                "rule-id": "cisco.ios.ssh.protocol_version",
                "severity": "High",
                "title": "SSH protocol version 2 is not enforced"
            },
            {
                "recommendation": "Configure an 'aaa authentication login' method list with an appropriate local fallback.",
                "rule-id": "cisco.ios.aaa.login_authentication",
                "severity": "High",
                "title": "AAA login authentication method list is missing"
            },
            {
                "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
                "rule-id": "cisco.ios.vty.authentication",
                "severity": "High",
                "title": "VTY authentication is not explicitly bound"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 11,
            "Low": 1,
            "Medium": 12
        }
    },
    "security-audit": {
        "2.0.0. Clear-text HTTP management service enabled": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with access to the management traffic path can observe or alter clear-text HTTP traffic.",
            "evidence": [
                "ip http server"
            ],
            "exploitability": "An attacker with access to the management traffic path can observe or alter clear-text HTTP traffic.",
            "impact": "Administrative credentials and sessions can be exposed to interception or modification.",
            "observation": "The IOS HTTP management server is explicitly enabled.",
            "recommendation": "Disable it with 'no ip http server' and use HTTPS or SSH for remote administration.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-17/https-xe-17-book/HTTP_1-1_Web_Server_and_Client.html"
            ],
            "rule_id": "cisco.ios.http.cleartext_service",
            "severity": "High",
            "title": "Clear-text HTTP management service enabled"
        },
        "2.0.1. HTTP management access is unrestricted": {
            "device": "IOS_CATALYST",
            "ease": "An attacker only needs network reachability to attempt authentication or exploit the HTTP service.",
            "evidence": [
                "ip http server"
            ],
            "exploitability": "An attacker only needs network reachability to attempt authentication or exploit the HTTP service.",
            "impact": "Untrusted networks may be able to reach the device management service.",
            "observation": "The enabled HTTP server has no effective 'ip http access-class' restriction.",
            "recommendation": "Restrict management sources with 'ip http access-class <ACL>' or disable HTTP.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-17/https-xe-17-book/HTTP_1-1_Web_Server_and_Client.html"
            ],
            "rule_id": "cisco.ios.http.access_restriction",
            "severity": "High",
            "title": "HTTP management access is unrestricted"
        },
        "2.0.10. VTY administrative authorization is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 5 15",
                "exec-timeout 90 0",
                "transport input ssh",
                "transport output ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
            "observation": "line vty 5 15 lacks resolved EXEC authorization, privilege-15 command authorization.",
            "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authorization",
            "severity": "High",
            "title": "VTY administrative authorization is incomplete"
        },
        "2.0.11. Console authentication is not explicitly secured": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line con 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Physical or terminal-server access may reach an unintended authentication path.",
            "observation": "line con 0 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.console.authentication",
            "severity": "High",
            "title": "Console authentication is not explicitly secured"
        },
        "2.0.12. Auxiliary management line is not fully disabled": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line aux 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unused AUX port can provide an additional local, modem, or reverse-terminal management path.",
            "observation": "line aux 0 does not combine 'no exec', 'transport input none', and 'transport output none'.",
            "recommendation": "Disable the AUX line using the complete Cisco hardening sequence unless it has an approved operational use.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.auxiliary.enabled",
            "severity": "High",
            "title": "Auxiliary management line is not fully disabled"
        },
        "2.0.13. Active auxiliary line lacks resolved authentication": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line aux 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A reachable AUX session may use an unintended or line-password authentication path.",
            "observation": "line aux 0 is not disabled and lacks a resolvable local or AAA login binding.",
            "recommendation": "Disable the line or bind it to a tested AAA login method.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.auxiliary.authentication",
            "severity": "High",
            "title": "Active auxiliary line lacks resolved authentication"
        },
        "2.0.14. Legacy SNMP community configured": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "snmp-server community <redacted> ro"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Community-based SNMP lacks modern per-user authentication and privacy protections.",
            "observation": "An SNMPv1/v2c community uses community-based SNMP. The value is redacted.",
            "recommendation": "Migrate to SNMPv3 authPriv, restrict managers, and remove v1/v2c communities.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.snmp.legacy_community",
            "severity": "Medium",
            "title": "Legacy SNMP community configured"
        },
        "2.0.15. Remote logging destination is missing": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No logging host command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Events may be lost during compromise or device failure and unavailable to central monitoring.",
            "observation": "No active remote syslog destination is configured.",
            "recommendation": "Configure one or more protected remote logging hosts.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.logging.remote_destination",
            "severity": "Medium",
            "title": "Remote logging destination is missing"
        },
        "2.0.16. Configuration-change logging is disabled": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "archive log config logging enable absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative changes can lack a local per-user, per-session command history.",
            "observation": "The effective archive log-config state does not enable configuration-change logging.",
            "recommendation": "Enable 'archive / log config / logging enable', suppress keys, and notify syslog.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html"
            ],
            "rule_id": "cisco.ios.configuration.change_logging",
            "severity": "Medium",
            "title": "Configuration-change logging is disabled"
        },
        "2.0.17. NTP synchronization is not configured": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No ntp server or peer command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Inaccurate time undermines event correlation, certificates, and forensic timelines.",
            "observation": "No NTP server or peer is configured.",
            "recommendation": "Configure multiple trusted NTP servers.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.servers",
            "severity": "Medium",
            "title": "NTP synchronization is not configured"
        },
        "2.0.18. IP source routing is not explicitly disabled": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "no ip source-route absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Source-routed packets can bypass expected routing paths and trust boundaries on applicable releases.",
            "observation": "The configuration does not contain the IOS 'no ip source-route' hardening command.",
            "recommendation": "Configure 'no ip source-route'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ip.source_route",
            "severity": "Medium",
            "title": "IP source routing is not explicitly disabled"
        },
        "2.0.19. Layer-3 interface hardening is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Loopback1",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Loopback1 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.2. SSH protocol version 2 is not enforced": {
            "device": "IOS_CATALYST",
            "ease": "An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            "evidence": [
                "line vty 0 4",
                "line vty 5 15"
            ],
            "exploitability": "An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            "impact": "SSHv1 has fundamental protocol weaknesses and permits downgrade exposure where compatibility mode is allowed.",
            "observation": "The reachable SSH service uses compatibility mode (SSHv1 and SSHv2).",
            "recommendation": "Enforce SSHv2 with 'ip ssh version 2'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.protocol_version",
            "severity": "High",
            "title": "SSH protocol version 2 is not enforced"
        },
        "2.0.20. Layer-3 interface hardening is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Loopback2",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Loopback2 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.21. Layer-3 interface hardening is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Vlan1",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Vlan1 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.22. Layer-3 interface hardening is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Vlan99",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Vlan99 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.23. Control-plane policing is not attached": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No control-plane service-policy input"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Unrestricted control-plane traffic can contribute to CPU exhaustion and management outages.",
            "observation": "No input service policy is attached under control-plane configuration.",
            "recommendation": "Deploy a validated Control Plane Policing policy appropriate for the platform role.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/quality-of-service/quality-of-service/m_qos-plcshp-ctrl-pln-plc-0.html"
            ],
            "rule_id": "cisco.ios.control_plane.copp",
            "severity": "Medium",
            "title": "Control-plane policing is not attached"
        },
        "2.0.3. SSH negotiation timeout is unsafe": {
            "device": "IOS_CATALYST",
            "ease": "A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            "evidence": [
                "effective documented default: 120"
            ],
            "exploitability": "A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            "impact": "Long unauthenticated negotiations consume management-plane resources and leave sessions open unnecessarily.",
            "observation": "The effective SSH negotiation timeout is 120 seconds; the policy maximum is 60 seconds.",
            "recommendation": "Configure 'ip ssh time-out <1-60>'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.negotiation_timeout",
            "severity": "Low",
            "title": "SSH negotiation timeout is unsafe"
        },
        "2.0.4. SSH VTY access is not source-restricted": {
            "device": "IOS_CATALYST",
            "ease": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "evidence": [
                "line vty 0 4",
                "line vty 5 15"
            ],
            "exploitability": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "impact": "Any source with network reachability can attempt to access the SSH management service.",
            "observation": "At least one SSH-enabled VTY range lacks an inbound IPv4 or IPv6 access-class.",
            "recommendation": "Apply 'access-class <ACL> in' or 'ipv6 access-class <ACL> in' to every SSH-enabled VTY range.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.vty_access_restriction",
            "severity": "Medium",
            "title": "SSH VTY access is not source-restricted"
        },
        "2.0.5. AAA login authentication method list is missing": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "aaa new-model"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Management lines may fall back to an unintended authentication behavior.",
            "observation": "AAA is enabled but no login authentication method list is configured.",
            "recommendation": "Configure an 'aaa authentication login' method list with an appropriate local fallback.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.aaa.login_authentication",
            "severity": "High",
            "title": "AAA login authentication method list is missing"
        },
        "2.0.6. Administrative AAA accounting is missing": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "aaa new-model"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative activity may not be attributable or centrally auditable.",
            "observation": "AAA is enabled but no EXEC or command accounting method is configured.",
            "recommendation": "Configure start-stop EXEC and command accounting to a resilient AAA service.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.aaa.accounting",
            "severity": "Medium",
            "title": "Administrative AAA accounting is missing"
        },
        "2.0.7. VTY authentication is not explicitly bound": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4",
                "exec-timeout 90 0",
                "transport input ssh",
                "transport output ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "The line may use an unintended password-only or default authentication path.",
            "observation": "line vty 0 4 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authentication",
            "severity": "High",
            "title": "VTY authentication is not explicitly bound"
        },
        "2.0.8. VTY administrative authorization is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4",
                "exec-timeout 90 0",
                "transport input ssh",
                "transport output ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
            "observation": "line vty 0 4 lacks resolved EXEC authorization, privilege-15 command authorization.",
            "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authorization",
            "severity": "High",
            "title": "VTY administrative authorization is incomplete"
        },
        "2.0.9. VTY authentication is not explicitly bound": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 5 15",
                "exec-timeout 90 0",
                "transport input ssh",
                "transport output ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "The line may use an unintended password-only or default authentication path.",
            "observation": "line vty 5 15 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authentication",
            "severity": "High",
            "title": "VTY authentication is not explicitly bound"
        }
    },
    "vulnerabilities": []
}
``` — scanner not run when this list was written.

**Classification:**
- Detected correctly: HTTP administration, legacy SNMP, absent NTP/remote logging, and unrestricted VTY/HTTP sources. The IOS_XE, IOS_SWITCH and IOS_CATALYST outputs have the same substantive 24 checks.
- Detected but degraded: none of the explicit ground-truth items.
- Missed entirely: 90-minute VTY idle timeout and reversible type-7 local-user storage.
- False positives: no definite one established from this complete but sanitized export; some auxiliary/CoPP/default-state findings require release and platform confirmation.
- Crashes/failures: none.

<a id="RW-002"></a>
### IOS_XE / IOS_ROUTER — Published ASR-1002-X BRAS running configuration

**Provenance:** [Cisco ASR-1002-X BRAS configuration](https://gist.github.com/dwinurhadia/c53f05658c37718245dcacaad3e6e592), raw gist; SHA-256 `985579B3233363E775D9755A03C3988D6F2CD6CAF9108769CBA19117E5A3AC5A`. Posted redacted running configuration, version 16.3. IOS_ROUTER is additionally run as a compatibility/alias path.

**Ground truth (established before running the tool):**
- Lines 261–264 set `transport input all` on both VTY ranges, allowing Telnet alongside SSH. Cleartext remote administration is a direct exposure on any reachable management path.
- Line 235 configures an SNMP community, even though its value is redacted. That retains legacy community authentication.
- Lines 245 and 249 use reversible type-7 RADIUS keys; the masked key bytes cannot support value-strength claims.
- Lines 252–253 attach a `control-plane` stanza with no input service policy. This leaves no explicitly configured control-plane filter/policer in the supplied configuration; whether a platform-managed default exists is unknown.
- No remote log host or NTP server appears in the full posted configuration. These are visibility/time-integrity concerns, with any external collection or appliance default treated as unknown rather than proven absent.

**Tool output (actual, unedited):**

**RW002-XE CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Cisco IOS-XE)
[2/4] Fetching IOS-XE API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW002-XE.json
```

**RW002-XE generated JSON report (SHA-256 `A05D425317A6DA3BAD3299AE973E6F00488550C1AB77734A42B9E109A7EA2DCE`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "IOS_XE",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "IOS running configuration does not provide reliable model metadata",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 10,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoIOSXEParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:21:57.838645",
        "device-type": "IOS_XE",
        "hostname": "Cisco-ASR-1002-X-BRAS"
    },
    "remediation-summary": {
        "finding-count": 18,
        "priority-actions": [
            {
                "recommendation": "Configure an 'aaa authentication login' method list with an appropriate local fallback.",
                "rule-id": "cisco.ios.aaa.login_authentication",
                "severity": "High",
                "title": "AAA login authentication method list is missing"
            },
            {
                "recommendation": "Configure 'transport input ssh' on every VTY range.",
                "rule-id": "cisco.ios.vty.telnet",
                "severity": "High",
                "title": "VTY permits clear-text Telnet"
            },
            {
                "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
                "rule-id": "cisco.ios.vty.authentication",
                "severity": "High",
                "title": "VTY authentication is not explicitly bound"
            },
            {
                "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
                "rule-id": "cisco.ios.vty.authorization",
                "severity": "High",
                "title": "VTY administrative authorization is incomplete"
            },
            {
                "recommendation": "Configure 'transport input ssh' on every VTY range.",
                "rule-id": "cisco.ios.vty.telnet",
                "severity": "High",
                "title": "VTY permits clear-text Telnet"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 10,
            "Low": 1,
            "Medium": 7
        }
    },
    "security-audit": {
        "9.0.0. AAA login authentication method list is missing": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "aaa new-model"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Management lines may fall back to an unintended authentication behavior.",
            "observation": "AAA is enabled but no login authentication method list is configured.",
            "recommendation": "Configure an 'aaa authentication login' method list with an appropriate local fallback.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.aaa.login_authentication",
            "severity": "High",
            "title": "AAA login authentication method list is missing"
        },
        "9.0.1. Administrative AAA accounting is missing": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "aaa new-model"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative activity may not be attributable or centrally auditable.",
            "observation": "AAA is enabled but no EXEC or command accounting method is configured.",
            "recommendation": "Configure start-stop EXEC and command accounting to a resilient AAA service.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.aaa.accounting",
            "severity": "Medium",
            "title": "Administrative AAA accounting is missing"
        },
        "9.0.10. Active auxiliary line lacks resolved authentication": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line aux 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A reachable AUX session may use an unintended or line-password authentication path.",
            "observation": "line aux 0 is not disabled and lacks a resolvable local or AAA login binding.",
            "recommendation": "Disable the line or bind it to a tested AAA login method.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.auxiliary.authentication",
            "severity": "High",
            "title": "Active auxiliary line lacks resolved authentication"
        },
        "9.0.11. Legacy SNMP community configured": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "snmp-server community <redacted> ro"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Community-based SNMP lacks modern per-user authentication and privacy protections.",
            "observation": "An SNMPv1/v2c community uses community-based SNMP. The value is redacted.",
            "recommendation": "Migrate to SNMPv3 authPriv, restrict managers, and remove v1/v2c communities.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.snmp.legacy_community",
            "severity": "Medium",
            "title": "Legacy SNMP community configured"
        },
        "9.0.12. Remote logging destination is missing": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No logging host command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Events may be lost during compromise or device failure and unavailable to central monitoring.",
            "observation": "No active remote syslog destination is configured.",
            "recommendation": "Configure one or more protected remote logging hosts.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.logging.remote_destination",
            "severity": "Medium",
            "title": "Remote logging destination is missing"
        },
        "9.0.13. Configuration-change logging is disabled": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "archive log config logging enable absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative changes can lack a local per-user, per-session command history.",
            "observation": "The effective archive log-config state does not enable configuration-change logging.",
            "recommendation": "Enable 'archive / log config / logging enable', suppress keys, and notify syslog.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html"
            ],
            "rule_id": "cisco.ios.configuration.change_logging",
            "severity": "Medium",
            "title": "Configuration-change logging is disabled"
        },
        "9.0.14. NTP synchronization is not configured": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No ntp server or peer command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Inaccurate time undermines event correlation, certificates, and forensic timelines.",
            "observation": "No NTP server or peer is configured.",
            "recommendation": "Configure multiple trusted NTP servers.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.servers",
            "severity": "Medium",
            "title": "NTP synchronization is not configured"
        },
        "9.0.15. Login warning banner is missing": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No banner login or banner motd command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Users may not receive the organization's required authorized-use and monitoring notice.",
            "observation": "No login or message-of-the-day warning banner is configured.",
            "recommendation": "Configure an approved legal warning with 'banner login'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.banner.login",
            "severity": "Low",
            "title": "Login warning banner is missing"
        },
        "9.0.16. IP source routing is not explicitly disabled": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "no ip source-route absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Source-routed packets can bypass expected routing paths and trust boundaries on applicable releases.",
            "observation": "The configuration does not contain the IOS 'no ip source-route' hardening command.",
            "recommendation": "Configure 'no ip source-route'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ip.source_route",
            "severity": "Medium",
            "title": "IP source routing is not explicitly disabled"
        },
        "9.0.17. Control-plane policing is not attached": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No control-plane service-policy input"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Unrestricted control-plane traffic can contribute to CPU exhaustion and management outages.",
            "observation": "No input service policy is attached under control-plane configuration.",
            "recommendation": "Deploy a validated Control Plane Policing policy appropriate for the platform role.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/quality-of-service/quality-of-service/m_qos-plcshp-ctrl-pln-plc-0.html"
            ],
            "rule_id": "cisco.ios.control_plane.copp",
            "severity": "Medium",
            "title": "Control-plane policing is not attached"
        },
        "9.0.2. VTY permits clear-text Telnet": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Remote administrative credentials and commands may traverse the network without encryption.",
            "observation": "line vty 0 4 does not explicitly restrict inbound transport to SSH.",
            "recommendation": "Configure 'transport input ssh' on every VTY range.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.telnet",
            "severity": "High",
            "title": "VTY permits clear-text Telnet"
        },
        "9.0.3. VTY authentication is not explicitly bound": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "The line may use an unintended password-only or default authentication path.",
            "observation": "line vty 0 4 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authentication",
            "severity": "High",
            "title": "VTY authentication is not explicitly bound"
        },
        "9.0.4. VTY administrative authorization is incomplete": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
            "observation": "line vty 0 4 lacks resolved EXEC authorization, privilege-15 command authorization.",
            "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authorization",
            "severity": "High",
            "title": "VTY administrative authorization is incomplete"
        },
        "9.0.5. VTY permits clear-text Telnet": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 5 15"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Remote administrative credentials and commands may traverse the network without encryption.",
            "observation": "line vty 5 15 does not explicitly restrict inbound transport to SSH.",
            "recommendation": "Configure 'transport input ssh' on every VTY range.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.telnet",
            "severity": "High",
            "title": "VTY permits clear-text Telnet"
        },
        "9.0.6. VTY authentication is not explicitly bound": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 5 15"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "The line may use an unintended password-only or default authentication path.",
            "observation": "line vty 5 15 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authentication",
            "severity": "High",
            "title": "VTY authentication is not explicitly bound"
        },
        "9.0.7. VTY administrative authorization is incomplete": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 5 15"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
            "observation": "line vty 5 15 lacks resolved EXEC authorization, privilege-15 command authorization.",
            "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authorization",
            "severity": "High",
            "title": "VTY administrative authorization is incomplete"
        },
        "9.0.8. Console authentication is not explicitly secured": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line con 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Physical or terminal-server access may reach an unintended authentication path.",
            "observation": "line con 0 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.console.authentication",
            "severity": "High",
            "title": "Console authentication is not explicitly secured"
        },
        "9.0.9. Auxiliary management line is not fully disabled": {
            "device": "IOS_XE",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line aux 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unused AUX port can provide an additional local, modem, or reverse-terminal management path.",
            "observation": "line aux 0 does not combine 'no exec', 'transport input none', and 'transport output none'.",
            "recommendation": "Disable the AUX line using the complete Cisco hardening sequence unless it has an approved operational use.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.auxiliary.enabled",
            "severity": "High",
            "title": "Auxiliary management line is not fully disabled"
        }
    },
    "vulnerabilities": []
}
```

**RW002-ROUTER CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng
[2/4] Fetching Cisco API information
[2/4] Cisco API disable.
[3/4] Checking missconfiguration vulnerabilities
[3/4] Scanning configuration file using the following IOS plugins: ['PluginHTTP', 'PluginSSH', 'PluginIOSBaseline']
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW002-ROUTER.json
```

**RW002-ROUTER generated JSON report (SHA-256 `6249914418071DD7688EFFD451DC262BEEF7ADE53664D6E0664471FE33FAB42F`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "IOS_ROUTER",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "IOS running configuration does not provide reliable model metadata",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 10,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoIOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:21:58.346634",
        "device-type": "IOS_ROUTER",
        "hostname": "Cisco-ASR-1002-X-BRAS"
    },
    "remediation-summary": {
        "finding-count": 18,
        "priority-actions": [
            {
                "recommendation": "Configure an 'aaa authentication login' method list with an appropriate local fallback.",
                "rule-id": "cisco.ios.aaa.login_authentication",
                "severity": "High",
                "title": "AAA login authentication method list is missing"
            },
            {
                "recommendation": "Configure 'transport input ssh' on every VTY range.",
                "rule-id": "cisco.ios.vty.telnet",
                "severity": "High",
                "title": "VTY permits clear-text Telnet"
            },
            {
                "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
                "rule-id": "cisco.ios.vty.authentication",
                "severity": "High",
                "title": "VTY authentication is not explicitly bound"
            },
            {
                "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
                "rule-id": "cisco.ios.vty.authorization",
                "severity": "High",
                "title": "VTY administrative authorization is incomplete"
            },
            {
                "recommendation": "Configure 'transport input ssh' on every VTY range.",
                "rule-id": "cisco.ios.vty.telnet",
                "severity": "High",
                "title": "VTY permits clear-text Telnet"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 10,
            "Low": 1,
            "Medium": 7
        }
    },
    "security-audit": {
        "2.0.0. AAA login authentication method list is missing": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "aaa new-model"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Management lines may fall back to an unintended authentication behavior.",
            "observation": "AAA is enabled but no login authentication method list is configured.",
            "recommendation": "Configure an 'aaa authentication login' method list with an appropriate local fallback.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.aaa.login_authentication",
            "severity": "High",
            "title": "AAA login authentication method list is missing"
        },
        "2.0.1. Administrative AAA accounting is missing": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "aaa new-model"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative activity may not be attributable or centrally auditable.",
            "observation": "AAA is enabled but no EXEC or command accounting method is configured.",
            "recommendation": "Configure start-stop EXEC and command accounting to a resilient AAA service.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.aaa.accounting",
            "severity": "Medium",
            "title": "Administrative AAA accounting is missing"
        },
        "2.0.10. Active auxiliary line lacks resolved authentication": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line aux 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A reachable AUX session may use an unintended or line-password authentication path.",
            "observation": "line aux 0 is not disabled and lacks a resolvable local or AAA login binding.",
            "recommendation": "Disable the line or bind it to a tested AAA login method.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.auxiliary.authentication",
            "severity": "High",
            "title": "Active auxiliary line lacks resolved authentication"
        },
        "2.0.11. Legacy SNMP community configured": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "snmp-server community <redacted> ro"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Community-based SNMP lacks modern per-user authentication and privacy protections.",
            "observation": "An SNMPv1/v2c community uses community-based SNMP. The value is redacted.",
            "recommendation": "Migrate to SNMPv3 authPriv, restrict managers, and remove v1/v2c communities.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.snmp.legacy_community",
            "severity": "Medium",
            "title": "Legacy SNMP community configured"
        },
        "2.0.12. Remote logging destination is missing": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No logging host command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Events may be lost during compromise or device failure and unavailable to central monitoring.",
            "observation": "No active remote syslog destination is configured.",
            "recommendation": "Configure one or more protected remote logging hosts.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.logging.remote_destination",
            "severity": "Medium",
            "title": "Remote logging destination is missing"
        },
        "2.0.13. Configuration-change logging is disabled": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "archive log config logging enable absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative changes can lack a local per-user, per-session command history.",
            "observation": "The effective archive log-config state does not enable configuration-change logging.",
            "recommendation": "Enable 'archive / log config / logging enable', suppress keys, and notify syslog.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html"
            ],
            "rule_id": "cisco.ios.configuration.change_logging",
            "severity": "Medium",
            "title": "Configuration-change logging is disabled"
        },
        "2.0.14. NTP synchronization is not configured": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No ntp server or peer command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Inaccurate time undermines event correlation, certificates, and forensic timelines.",
            "observation": "No NTP server or peer is configured.",
            "recommendation": "Configure multiple trusted NTP servers.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.servers",
            "severity": "Medium",
            "title": "NTP synchronization is not configured"
        },
        "2.0.15. Login warning banner is missing": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No banner login or banner motd command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Users may not receive the organization's required authorized-use and monitoring notice.",
            "observation": "No login or message-of-the-day warning banner is configured.",
            "recommendation": "Configure an approved legal warning with 'banner login'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.banner.login",
            "severity": "Low",
            "title": "Login warning banner is missing"
        },
        "2.0.16. IP source routing is not explicitly disabled": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "no ip source-route absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Source-routed packets can bypass expected routing paths and trust boundaries on applicable releases.",
            "observation": "The configuration does not contain the IOS 'no ip source-route' hardening command.",
            "recommendation": "Configure 'no ip source-route'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ip.source_route",
            "severity": "Medium",
            "title": "IP source routing is not explicitly disabled"
        },
        "2.0.17. Control-plane policing is not attached": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No control-plane service-policy input"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Unrestricted control-plane traffic can contribute to CPU exhaustion and management outages.",
            "observation": "No input service policy is attached under control-plane configuration.",
            "recommendation": "Deploy a validated Control Plane Policing policy appropriate for the platform role.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/quality-of-service/quality-of-service/m_qos-plcshp-ctrl-pln-plc-0.html"
            ],
            "rule_id": "cisco.ios.control_plane.copp",
            "severity": "Medium",
            "title": "Control-plane policing is not attached"
        },
        "2.0.2. VTY permits clear-text Telnet": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Remote administrative credentials and commands may traverse the network without encryption.",
            "observation": "line vty 0 4 does not explicitly restrict inbound transport to SSH.",
            "recommendation": "Configure 'transport input ssh' on every VTY range.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.telnet",
            "severity": "High",
            "title": "VTY permits clear-text Telnet"
        },
        "2.0.3. VTY authentication is not explicitly bound": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "The line may use an unintended password-only or default authentication path.",
            "observation": "line vty 0 4 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authentication",
            "severity": "High",
            "title": "VTY authentication is not explicitly bound"
        },
        "2.0.4. VTY administrative authorization is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
            "observation": "line vty 0 4 lacks resolved EXEC authorization, privilege-15 command authorization.",
            "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authorization",
            "severity": "High",
            "title": "VTY administrative authorization is incomplete"
        },
        "2.0.5. VTY permits clear-text Telnet": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 5 15"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Remote administrative credentials and commands may traverse the network without encryption.",
            "observation": "line vty 5 15 does not explicitly restrict inbound transport to SSH.",
            "recommendation": "Configure 'transport input ssh' on every VTY range.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.telnet",
            "severity": "High",
            "title": "VTY permits clear-text Telnet"
        },
        "2.0.6. VTY authentication is not explicitly bound": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 5 15"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "The line may use an unintended password-only or default authentication path.",
            "observation": "line vty 5 15 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind each VTY range to a named AAA login method or explicit local authentication.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authentication",
            "severity": "High",
            "title": "VTY authentication is not explicitly bound"
        },
        "2.0.7. VTY administrative authorization is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 5 15"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
            "observation": "line vty 5 15 lacks resolved EXEC authorization, privilege-15 command authorization.",
            "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authorization",
            "severity": "High",
            "title": "VTY administrative authorization is incomplete"
        },
        "2.0.8. Console authentication is not explicitly secured": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line con 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Physical or terminal-server access may reach an unintended authentication path.",
            "observation": "line con 0 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.console.authentication",
            "severity": "High",
            "title": "Console authentication is not explicitly secured"
        },
        "2.0.9. Auxiliary management line is not fully disabled": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line aux 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unused AUX port can provide an additional local, modem, or reverse-terminal management path.",
            "observation": "line aux 0 does not combine 'no exec', 'transport input none', and 'transport output none'.",
            "recommendation": "Disable the AUX line using the complete Cisco hardening sequence unless it has an approved operational use.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.auxiliary.enabled",
            "severity": "High",
            "title": "Auxiliary management line is not fully disabled"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: VTY Telnet on both ranges, legacy SNMP, absent NTP/remote logging, and the lack of an attached CoPP policy (with platform-default caveat). IOS_XE and IOS_ROUTER agree.
- Detected but degraded: none of the explicit items.
- Missed entirely: reversible type-7 RADIUS-key storage.
- False positives: none definite; auxiliary, AAA and banner findings were not independently resolved from this posted configuration.
- Crashes/failures: none.

<a id="RW-003"></a>
### ASA — Public remote-access VPN/ACL example

**Provenance:** [ACL for internet access](https://gist.github.com/thorr18/3ac10e38dc14d5933d375541744ecf40), raw gist; SHA-256 `50F1979EA3075500F59103586FE7387F4AE8D193D7914750F40BEE1E53DE8F8B`. The example identifies ASA 9.3(2) and includes outside ACL, VPN and SSL settings. Treat it as an example, not proof it is an entire running export.

**Ground truth (established before running the tool):**
- `access-list ACL_OUTSIDE_IN extended permit ip any any` is bound inbound to the `outside` interface. It permits all IPv4 protocols from every source to every destination at that filter layer, an explicit high-risk perimeter exposure. NAT and later inspection can change actual reachability, which the static text cannot prove.
- `ssl server-version tlsv1-only` on an enabled outside WebVPN endpoint permits only old TLS 1.0. [Cisco ASA VPN guidance](https://www.cisco.com/c/en/us/td/docs/security/asa/asa923/configuration/vpn/asa-923-vpn-config/vpn-params.html) documents supported stronger protocol minimums; this example's setting is obsolete.
- `ssl encryption des-sha1 3des-sha1 aes128-sha1 aes256-sha1` explicitly offers DES and 3DES suites for the VPN service; those choices weaken confidentiality. The AES entries do not neutralize the weak offered choices.
- The trustpoint name `SelfsignedCert` does not prove the actual certificate is self-signed or expired; no certificate-material finding is asserted. The two split-tunnel /1 entries collectively cover all IPv4 addresses and are not labelled an inadvertent split tunnel.

**Tool output (actual, unedited):**

**RW003-ASA CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (ASA)
[3/4] Checking missconfiguration vulnerabilities
[3/4] Scanning configuration file using the following ASA plugins: ['PluginASAChecks', 'PluginASABaseline']
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW003-ASA.json
```

**RW003-ASA generated JSON report (SHA-256 `CACDBB44DD0F341D07D937B78FDEB478423FA9A32BCCC44F9443B87F46546CDC`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "ASA",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "ASA hardware model is not parsed from the supported configuration export",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoASAParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:21:58.798558",
        "device-type": "ASA",
        "hostname": "ACTUNNEL_ASA"
    },
    "remediation-summary": {
        "finding-count": 6,
        "priority-actions": [
            {
                "recommendation": "Replace the ACE with explicit source, destination, and service constraints.",
                "rule-id": "cisco.asa.acl.broad_inbound_permit",
                "severity": "Critical",
                "title": "Broad inbound permit on a low-trust interface"
            },
            {
                "recommendation": "Narrow the rule and enable an appropriate reviewed logging level and interval.",
                "rule-id": "cisco.asa.acl.broad_permit_unlogged",
                "severity": "Medium",
                "title": "Broad ACL permit lacks explicit logging"
            },
            {
                "recommendation": "Set a finite console timeout that meets the approved administrative-session policy.",
                "rule-id": "cisco.asa.console.session_timeout",
                "severity": "Medium",
                "title": "ASA console session timeout is disabled"
            },
            {
                "recommendation": "Configure multiple trusted NTP servers.",
                "rule-id": "cisco.asa.ntp.servers",
                "severity": "Medium",
                "title": "NTP synchronization is not configured"
            },
            {
                "recommendation": "Enable and tune basic threat detection for the platform and traffic profile.",
                "rule-id": "cisco.asa.threat_detection.basic",
                "severity": "Medium",
                "title": "Basic threat detection is disabled"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "Critical": 1,
            "Low": 1,
            "Medium": 4
        }
    },
    "security-audit": {
        "2.0.0. Remote security logging is not operational": {
            "device": "ASA",
            "ease": "An attacker may operate with reduced likelihood of centralized detection.",
            "evidence": [
                "No active logging host"
            ],
            "exploitability": "An attacker may operate with reduced likelihood of centralized detection.",
            "impact": "Security events may not be retained for monitoring, investigation, or audit.",
            "observation": "Centralized logging is unavailable because logging is disabled.",
            "recommendation": "Enable logging and configure at least one reachable remote 'logging host'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/monitor-syslog.html"
            ],
            "rule_id": "cisco.asa.logging.missing",
            "severity": "Low",
            "title": "Remote security logging is not operational"
        },
        "2.0.1. Broad inbound permit on a low-trust interface": {
            "device": "ASA",
            "ease": "Reachable attackers can target any destination allowed by routing and the broad ACE.",
            "evidence": [
                "access-list ACL_OUTSIDE_IN extended permit ip any any",
                "access-group ACL_OUTSIDE_IN in interface outside"
            ],
            "exploitability": "Reachable attackers can target any destination allowed by routing and the broad ACE.",
            "impact": "The rule can defeat the firewall boundary for the permitted protocol.",
            "observation": "ACL 'ACL_OUTSIDE_IN' permits ip from any source to any destination on 'outside'.",
            "recommendation": "Replace the ACE with explicit source, destination, and service constraints.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/firewall/asa-firewall-cli/access-rules.html"
            ],
            "rule_id": "cisco.asa.acl.broad_inbound_permit",
            "severity": "Critical",
            "title": "Broad inbound permit on a low-trust interface"
        },
        "2.0.2. Broad ACL permit lacks explicit logging": {
            "device": "ASA",
            "ease": "Malicious traffic can blend into an unrestricted flow with reduced policy-hit visibility.",
            "evidence": [
                "access-list ACL_OUTSIDE_IN extended permit ip any any",
                "access-group ACL_OUTSIDE_IN in interface outside"
            ],
            "exploitability": "Malicious traffic can blend into an unrestricted flow with reduced policy-hit visibility.",
            "impact": "Traffic crossing a highly permissive boundary may lack rule-level audit records.",
            "observation": "Broad permit entry 1 in ACL 'ACL_OUTSIDE_IN' has no explicit log option.",
            "recommendation": "Narrow the rule and enable an appropriate reviewed logging level and interval.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/firewall/asa-firewall-cli/access-rules.html"
            ],
            "rule_id": "cisco.asa.acl.broad_permit_unlogged",
            "severity": "Medium",
            "title": "Broad ACL permit lacks explicit logging"
        },
        "2.0.3. ASA console session timeout is disabled": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "console timeout defaults to 0"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "An unattended privileged console session can remain available indefinitely.",
            "observation": "The effective console timeout is 0 minutes, so authenticated serial or enable sessions do not time out.",
            "recommendation": "Set a finite console timeout that meets the approved administrative-session policy.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config/admin-management.html"
            ],
            "rule_id": "cisco.asa.console.session_timeout",
            "severity": "Medium",
            "title": "ASA console session timeout is disabled"
        },
        "2.0.4. NTP synchronization is not configured": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "No ntp server command"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Incorrect time weakens event correlation, certificate validation, and forensic timelines.",
            "observation": "No NTP server is configured.",
            "recommendation": "Configure multiple trusted NTP servers.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/n-commands.html"
            ],
            "rule_id": "cisco.asa.ntp.servers",
            "severity": "Medium",
            "title": "NTP synchronization is not configured"
        },
        "2.0.5. Basic threat detection is disabled": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "threat-detection basic-threat absent or negated"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Scanning, rate anomalies, and attack indicators may receive reduced local visibility.",
            "observation": "The effective ASA configuration does not enable basic threat detection.",
            "recommendation": "Enable and tune basic threat detection for the platform and traffic profile.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.threat_detection.basic",
            "severity": "Medium",
            "title": "Basic threat detection is disabled"
        }
    },
    "vulnerabilities": []
}
```

**RW003-PIX CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (ASA)
[3/4] Checking missconfiguration vulnerabilities
[3/4] Scanning configuration file using the following ASA plugins: ['PluginASAChecks', 'PluginASABaseline']
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW003-PIX.json
```

**RW003-PIX generated JSON report (SHA-256 `EE1716AA5A22839B9114A3132AFD6055EED3F97F9FF171029DF6DF92EA9800EF`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "PIX",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "ASA hardware model is not parsed from the supported configuration export",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoASAParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:21:59.254847",
        "device-type": "PIX",
        "hostname": "ACTUNNEL_ASA"
    },
    "remediation-summary": {
        "finding-count": 3,
        "priority-actions": [
            {
                "recommendation": "Replace the ACE with explicit source, destination, and service constraints.",
                "rule-id": "cisco.asa.acl.broad_inbound_permit",
                "severity": "Critical",
                "title": "Broad inbound permit on a low-trust interface"
            },
            {
                "recommendation": "Narrow the rule and enable an appropriate reviewed logging level and interval.",
                "rule-id": "cisco.asa.acl.broad_permit_unlogged",
                "severity": "Medium",
                "title": "Broad ACL permit lacks explicit logging"
            },
            {
                "recommendation": "Enable logging and configure at least one reachable remote 'logging host'.",
                "rule-id": "cisco.asa.logging.missing",
                "severity": "Low",
                "title": "Remote security logging is not operational"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "Critical": 1,
            "Low": 1,
            "Medium": 1
        }
    },
    "security-audit": {
        "2.0.0. Remote security logging is not operational": {
            "device": "PIX",
            "ease": "An attacker may operate with reduced likelihood of centralized detection.",
            "evidence": [
                "No active logging host"
            ],
            "exploitability": "An attacker may operate with reduced likelihood of centralized detection.",
            "impact": "Security events may not be retained for monitoring, investigation, or audit.",
            "observation": "Centralized logging is unavailable because logging is disabled.",
            "recommendation": "Enable logging and configure at least one reachable remote 'logging host'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/monitor-syslog.html"
            ],
            "rule_id": "cisco.asa.logging.missing",
            "severity": "Low",
            "title": "Remote security logging is not operational"
        },
        "2.0.1. Broad inbound permit on a low-trust interface": {
            "device": "PIX",
            "ease": "Reachable attackers can target any destination allowed by routing and the broad ACE.",
            "evidence": [
                "access-list ACL_OUTSIDE_IN extended permit ip any any",
                "access-group ACL_OUTSIDE_IN in interface outside"
            ],
            "exploitability": "Reachable attackers can target any destination allowed by routing and the broad ACE.",
            "impact": "The rule can defeat the firewall boundary for the permitted protocol.",
            "observation": "ACL 'ACL_OUTSIDE_IN' permits ip from any source to any destination on 'outside'.",
            "recommendation": "Replace the ACE with explicit source, destination, and service constraints.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/firewall/asa-firewall-cli/access-rules.html"
            ],
            "rule_id": "cisco.asa.acl.broad_inbound_permit",
            "severity": "Critical",
            "title": "Broad inbound permit on a low-trust interface"
        },
        "2.0.2. Broad ACL permit lacks explicit logging": {
            "device": "PIX",
            "ease": "Malicious traffic can blend into an unrestricted flow with reduced policy-hit visibility.",
            "evidence": [
                "access-list ACL_OUTSIDE_IN extended permit ip any any",
                "access-group ACL_OUTSIDE_IN in interface outside"
            ],
            "exploitability": "Malicious traffic can blend into an unrestricted flow with reduced policy-hit visibility.",
            "impact": "Traffic crossing a highly permissive boundary may lack rule-level audit records.",
            "observation": "Broad permit entry 1 in ACL 'ACL_OUTSIDE_IN' has no explicit log option.",
            "recommendation": "Narrow the rule and enable an appropriate reviewed logging level and interval.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/firewall/asa-firewall-cli/access-rules.html"
            ],
            "rule_id": "cisco.asa.acl.broad_permit_unlogged",
            "severity": "Medium",
            "title": "Broad ACL permit lacks explicit logging"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: Critical outside-bound all-IP permit and its missing per-rule logging. The ASA report has six findings; PIX alias on this ASA 9.3 text has only three and does not establish historical PIX support.
- Detected but degraded: none.
- Missed entirely: TLSv1-only WebVPN server and offered DES/3DES SSL suites.
- False positives: logging, NTP, basic threat-detection and console-timeout absence claims rely on global commands missing from a partial VPN/ACL example; actual device state is unknown, so these are scope-invalid rather than proven deployed weaknesses.
- Crashes/failures: none.

<a id="RW-004"></a>
### SCREENOS — Microsoft Azure SSG site-to-site VPN sample

**Provenance:** [Azure VPN configuration sample for Juniper SSG ScreenOS 6.2](https://github.com/Azure/Azure-vpn-config-samples/blob/master/Juniper/Current/SSG/juniper-ssg-screenos-6.2_get_config.txt), raw published example; SHA-256 `15D6572AF66FA878BF3ED424DF6DFC5DF880C8A51B1B663E1661EDA896606C35`. It is a sample `get config` capture with placeholders and a prompt/header. No guessed replacement values are introduced.

**Ground truth (established before running the tool):**
- Line 107 configures the active Azure VPN with `no-replay`. The [ScreenOS CLI reference's replay/no-replay command description](https://manualzz.com/doc/21898000/juniper-networks-security-device-cli-reference-guide) defines this as disabled IPsec replay protection. That permits replays of captured tunnel packets if an attacker can inject them. The reference is an archived reproduction; vendor-hosted revision remains to be confirmed.
- `unset ike dos-protection` at line 98 explicitly removes IKE DoS protection on a configuration with an external IKE gateway. This is a contextual risk, since upstream defenses and ScreenOS defaults are not established; record as provisional rather than a definite vulnerability.
- `set interface ethernet0/0 ip manageable` places management capability on the Untrust interface. Actual exposed protocols and manager-source restrictions require evaluation, so this is an exposure concern, not a standalone proof that credentials are reachable from the Internet.
- The `set admin password` and preshared secret values are public sample text, but their encoding/strength is not independently established. The permissive Trust→Untrust policy may be intentional egress and is not scored without a requirement.

**Tool output (actual, unedited):**

**RW004 CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Juniper ScreenOS)
[2/4] Fetching Juniper API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW004.json
```

**RW004 generated JSON report (SHA-256 `14BE4DFF6A9B450003B9B77CD1EC5E40BA6C5D2D76EE582F807D2671236E99D1`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "SCREENOS",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "ScreenOS hostname is not present",
                "knowledge-state": "unknown",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "ScreenOS model metadata is not present",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "ScreenOS version metadata is not present",
                "knowledge-state": "unknown",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 6,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 3,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "JuniperScreenOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:21:59.523140",
        "device-type": "SCREENOS",
        "hostname": "juniper-device"
    },
    "remediation-summary": {
        "finding-count": 5,
        "priority-actions": [
            {
                "recommendation": "Replace Any source, destination, and service values with explicit objects and enable session logging.",
                "rule-id": "juniper.screenos.policy.broad_permit",
                "severity": "Critical",
                "title": "Broad Policy Rule Detected"
            },
            {
                "recommendation": "Replace Any with the smallest required services or reviewed service group.",
                "rule-id": "juniper.screenos.policy.broad_service",
                "severity": "Medium",
                "title": "ScreenOS policy is unrestricted by service"
            },
            {
                "recommendation": "Replace Any with the smallest required services or reviewed service group.",
                "rule-id": "juniper.screenos.policy.broad_service",
                "severity": "Medium",
                "title": "ScreenOS policy is unrestricted by service"
            },
            {
                "recommendation": "Enable appropriate session logging and send the resulting events to a protected remote destination.",
                "rule-id": "juniper.screenos.policy.unlogged_permit",
                "severity": "Medium",
                "title": "High-risk permit policy is not logged"
            },
            {
                "recommendation": "Enable appropriate session logging and send the resulting events to a protected remote destination.",
                "rule-id": "juniper.screenos.policy.unlogged_permit",
                "severity": "Medium",
                "title": "High-risk permit policy is not logged"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "Critical": 1,
            "Medium": 4
        }
    },
    "security-audit": {
        "4.0.0. Broad Policy Rule Detected": {
            "device": "SCREENOS",
            "ease": "Any source in the source zone can target any destination and service in the destination zone.",
            "evidence": [
                "set policy id 1 from \"Trust\" to \"Untrust\"  \"Any\" \"Any\" \"ANY\" permit",
                "set policy id 1"
            ],
            "exploitability": "Any source in the source zone can target any destination and service in the destination zone.",
            "impact": "The policy allows unrestricted traffic between its source and destination zones.",
            "observation": "Enabled policy ID 1 at position 2 permits Any source, Any destination, and Any service from zone 'Trust' to 'Untrust'; tracking is 'not configured'.",
            "recommendation": "Replace Any source, destination, and service values with explicit objects and enable session logging.",
            "references": [
                "https://www.juniper.net/documentation/product/us/en/screenos/6.3.0/"
            ],
            "rule_id": "juniper.screenos.policy.broad_permit",
            "severity": "Critical",
            "title": "Broad Policy Rule Detected"
        },
        "4.0.1. ScreenOS policy is unrestricted by service": {
            "device": "SCREENOS",
            "ease": "A matching source can attempt any service reachable in the destination zone.",
            "evidence": [
                "set policy id 3 from \"Untrust\" to \"Trust\"  \"azure-networks-1\" \"onprem-networks-1\" \"ANY\" permit",
                "set policy id 3"
            ],
            "exploitability": "A matching source can attempt any service reachable in the destination zone.",
            "impact": "Unnecessary protocols and destination ports can cross the zone boundary.",
            "observation": "Enabled policy ID 3 at position 0 permits Any service within its address scope from zone 'Untrust' to 'Trust'.",
            "recommendation": "Replace Any with the smallest required services or reviewed service group.",
            "references": [
                "https://www.juniper.net/documentation/product/us/en/screenos/6.3.0/"
            ],
            "rule_id": "juniper.screenos.policy.broad_service",
            "severity": "Medium",
            "title": "ScreenOS policy is unrestricted by service"
        },
        "4.0.2. ScreenOS policy is unrestricted by service": {
            "device": "SCREENOS",
            "ease": "A matching source can attempt any service reachable in the destination zone.",
            "evidence": [
                "set policy id 2 from \"Trust\" to \"Untrust\"  \"onprem-networks-1\" \"azure-networks-1\" \"ANY\" permit",
                "set policy id 2"
            ],
            "exploitability": "A matching source can attempt any service reachable in the destination zone.",
            "impact": "Unnecessary protocols and destination ports can cross the zone boundary.",
            "observation": "Enabled policy ID 2 at position 1 permits Any service within its address scope from zone 'Trust' to 'Untrust'.",
            "recommendation": "Replace Any with the smallest required services or reviewed service group.",
            "references": [
                "https://www.juniper.net/documentation/product/us/en/screenos/6.3.0/"
            ],
            "rule_id": "juniper.screenos.policy.broad_service",
            "severity": "Medium",
            "title": "ScreenOS policy is unrestricted by service"
        },
        "4.1.0. High-risk permit policy is not logged": {
            "device": "SCREENOS",
            "ease": "An attacker with network reachability or configuration access may exploit this legacy-platform weakness.",
            "evidence": [
                "set policy id 3 from \"Untrust\" to \"Trust\"  \"azure-networks-1\" \"onprem-networks-1\" \"ANY\" permit",
                "set policy id 3"
            ],
            "exploitability": "An attacker with network reachability or configuration access may exploit this legacy-platform weakness.",
            "impact": "Security-relevant permitted traffic may be unavailable for monitoring and incident investigation.",
            "observation": "Enabled policy ID 3 permits traffic from 'Untrust' to 'Trust' without session logging.",
            "recommendation": "Enable appropriate session logging and send the resulting events to a protected remote destination.",
            "references": [
                "https://www.juniper.net/documentation/product/us/en/screenos/6.3.0/"
            ],
            "rule_id": "juniper.screenos.policy.unlogged_permit",
            "severity": "Medium",
            "title": "High-risk permit policy is not logged"
        },
        "4.1.1. High-risk permit policy is not logged": {
            "device": "SCREENOS",
            "ease": "An attacker with network reachability or configuration access may exploit this legacy-platform weakness.",
            "evidence": [
                "set policy id 1 from \"Trust\" to \"Untrust\"  \"Any\" \"Any\" \"ANY\" permit",
                "set policy id 1"
            ],
            "exploitability": "An attacker with network reachability or configuration access may exploit this legacy-platform weakness.",
            "impact": "Security-relevant permitted traffic may be unavailable for monitoring and incident investigation.",
            "observation": "Enabled policy ID 1 permits traffic from 'Trust' to 'Untrust' without session logging.",
            "recommendation": "Enable appropriate session logging and send the resulting events to a protected remote destination.",
            "references": [
                "https://www.juniper.net/documentation/product/us/en/screenos/6.3.0/"
            ],
            "rule_id": "juniper.screenos.policy.unlogged_permit",
            "severity": "Medium",
            "title": "High-risk permit policy is not logged"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: unrestricted service on the two Azure tunnel policies is reported, but the finding's security value is conditional on intended VPN traffic.
- Detected but degraded: the Trust-to-Untrust any/any/ANY egress rule receives Critical broad-permit severity without knowing whether open egress is the approved policy.
- Missed entirely: active VPN no-replay. IKE DoS-protection omission remains a provisional, source-qualified concern.
- False positives: no strictly provable one; egress breadth and unlogged VPN rules require policy context.
- Crashes/failures: none.

<a id="RW-005"></a>
### ARISTA_EOS — Community AVD EVPN webinar leaf configuration

**Provenance:** [Arista NetDevOps community AVD webinar LEAF2A intended config](https://github.com/arista-netdevops-community/avd-evpn-webinar-june-11/blob/master/intended/configs/LEAF2A.cfg), raw published deployment output; SHA-256 `6901A86B155E483DAF60E25A368D1D10E2EE3DBB5FF55AB1B06E7921E7E5EAB2`. Lab/intended config, not a claim about an unknown production device.

**Ground truth (established before running the tool):**
- Lines 26–28 set two NTP servers without `ntp authenticate`, trusted keys or server key bindings in this complete intended configuration. The [EOS NTP authentication guide](https://www.arista.com/en/um-eos/eos-system-clock-and-time-protocols) describes authentication as an available safeguard; this is an explicit gap in trusted time-source configuration, subject to site policy.
- Line 30 stores the RADIUS shared key as reversible type 7. The literal key is deliberately not repeated here; no password-value claim is made.
- The intended configuration enables eAPI and SSH only under a named MGMT VRF. There is no service ACL in the eAPI/SSH sections; whether the MGMT VRF is externally reachable is unknown, so an unrestricted-source claim is provisional. Remote login uses a RADIUS group with local fallback; absence of explicit exec authorization may limit central role enforcement, but EOS release defaults and lab role policy are unresolved, so this is not a definite ground-truth item.

**Tool output (actual, unedited):**

**RW005 CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Arista EOS)
[2/4] Fetching Arista API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW005.json
```

**RW005 generated JSON report (SHA-256 `40D29639D584CC0F26C1EA223604AE9E5E484887FBB1ACA6DDF57FB4558E1ADB`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "ARISTA_EOS",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Model metadata absent",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "EOS version absent",
                "knowledge-state": "unknown",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 3,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "detail": "EOS interface roles are not normalized in this revision",
                "item-count": null,
                "knowledge-state": "unknown",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "detail": "EOS is not parsed as a firewall policy platform",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "AristaEOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:21:59.960999",
        "device-type": "ARISTA_EOS",
        "hostname": "LEAF2A"
    },
    "remediation-summary": {
        "finding-count": 7,
        "priority-actions": [
            {
                "recommendation": "Configure 'aaa authorization commands all default' using the approved service and controlled fallback.",
                "rule-id": "arista.eos.authorization.commands",
                "severity": "High",
                "title": "Centralized login lacks command authorization"
            },
            {
                "recommendation": "Apply explicit IPv4 and, where applicable, IPv6 service ACLs to each enabled eAPI VRF.",
                "rule-id": "arista.eos.eapi.source_restriction",
                "severity": "Medium",
                "title": "eAPI endpoint lacks a service ACL"
            },
            {
                "recommendation": "Configure default EXEC and all-command accounting to TACACS+, RADIUS, or protected syslog.",
                "rule-id": "arista.eos.authentication.accounting",
                "severity": "Medium",
                "title": "Centralized administrative access lacks complete accounting"
            },
            {
                "recommendation": "Attach a named SSL profile with an approved certificate and TLS 1.2 or 1.3 policy.",
                "rule-id": "arista.eos.eapi.tls_profile",
                "severity": "Medium",
                "title": "eAPI HTTPS lacks an explicit SSL profile"
            },
            {
                "recommendation": "Apply IPv4 and, where applicable, IPv6 access groups in management SSH configuration for each management VRF.",
                "rule-id": "arista.eos.ssh.source_restriction",
                "severity": "Medium",
                "title": "Explicit SSH service policy lacks access groups"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 1,
            "Medium": 6
        }
    },
    "security-audit": {
        "11.0.0. eAPI endpoint lacks a service ACL": {
            "device": "ARISTA_EOS",
            "ease": "Any host with VRF reachability can probe the service or attempt authentication.",
            "evidence": [
                "management api http-commands",
                "vrf MGMT",
                "no shutdown"
            ],
            "exploitability": "Any host with VRF reachability can probe the service or attempt authentication.",
            "impact": "All routed clients in the endpoint VRF can attempt API access.",
            "observation": "The active eAPI endpoint in VRF 'MGMT' has no IPv4 or IPv6 access-group.",
            "recommendation": "Apply explicit IPv4 and, where applicable, IPv6 service ACLs to each enabled eAPI VRF.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-acls-and-route-maps"
            ],
            "rule_id": "arista.eos.eapi.source_restriction",
            "severity": "Medium",
            "title": "eAPI endpoint lacks a service ACL"
        },
        "11.0.1. Centralized login lacks command authorization": {
            "device": "ARISTA_EOS",
            "ease": "A compromised account can receive broader CLI access than the identity service intended.",
            "evidence": [
                "centralized login authentication without all-command authorization"
            ],
            "exploitability": "A compromised account can receive broader CLI access than the identity service intended.",
            "impact": "Authenticated users may execute commands outside the intended central or local RBAC policy.",
            "observation": "Remote login authentication is configured without an effective default all-command authorization method list.",
            "recommendation": "Configure 'aaa authorization commands all default' using the approved service and controlled fallback.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-user-security"
            ],
            "rule_id": "arista.eos.authorization.commands",
            "severity": "High",
            "title": "Centralized login lacks command authorization"
        },
        "11.0.2. Centralized administrative access lacks complete accounting": {
            "device": "ARISTA_EOS",
            "ease": "A compromised administrator can act with reduced centralized evidence.",
            "evidence": [
                "default EXEC/all-command accounting incomplete"
            ],
            "exploitability": "A compromised administrator can act with reduced centralized evidence.",
            "impact": "Login sessions or executed commands may lack an independent audit trail.",
            "observation": "Default AAA accounting is missing for: commands-all, exec.",
            "recommendation": "Configure default EXEC and all-command accounting to TACACS+, RADIUS, or protected syslog.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-user-security"
            ],
            "rule_id": "arista.eos.authentication.accounting",
            "severity": "Medium",
            "title": "Centralized administrative access lacks complete accounting"
        },
        "11.0.3. eAPI HTTPS lacks an explicit SSL profile": {
            "device": "ARISTA_EOS",
            "ease": "Administrators may receive an unexpected certificate or negotiate an unintended legacy protocol.",
            "evidence": [
                "management api http-commands",
                "vrf MGMT",
                "no shutdown"
            ],
            "exploitability": "Administrators may receive an unexpected certificate or negotiate an unintended legacy protocol.",
            "impact": "Certificate identity and TLS-version policy remain dependent on an implicit service default.",
            "observation": "The active HTTPS eAPI endpoint in VRF 'MGMT' does not attach an SSL profile.",
            "recommendation": "Attach a named SSL profile with an approved certificate and TLS 1.2 or 1.3 policy.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-control-plane-security",
                "https://www.arista.com/en/um-eos/eos-session-management-commands"
            ],
            "rule_id": "arista.eos.eapi.tls_profile",
            "severity": "Medium",
            "title": "eAPI HTTPS lacks an explicit SSL profile"
        },
        "11.0.4. Explicit SSH service policy lacks access groups": {
            "device": "ARISTA_EOS",
            "ease": "A reachable attacker can probe the daemon, guess credentials, or target SSH implementation flaws.",
            "evidence": [
                "management ssh",
                "vrf MGMT",
                "no shutdown"
            ],
            "exploitability": "A reachable attacker can probe the daemon, guess credentials, or target SSH implementation flaws.",
            "impact": "Every routed source that can reach the switch can attempt SSH authentication.",
            "observation": "A management SSH block is configured without an IPv4 or IPv6 service ACL.",
            "recommendation": "Apply IPv4 and, where applicable, IPv6 access groups in management SSH configuration for each management VRF.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-acls-and-route-maps",
                "https://www.arista.com/en/um-eos/eos-session-management-commands"
            ],
            "rule_id": "arista.eos.ssh.source_restriction",
            "severity": "Medium",
            "title": "Explicit SSH service policy lacks access groups"
        },
        "11.0.5. Centralized login lacks exec authorization": {
            "device": "ARISTA_EOS",
            "ease": "A compromised or overprivileged account can exercise commands not constrained by centralized authorization.",
            "evidence": [
                "centralized login authentication without aaa authorization exec"
            ],
            "exploitability": "A compromised or overprivileged account can exercise commands not constrained by centralized authorization.",
            "impact": "Authenticated users may receive locally determined command access that is broader than central policy intends.",
            "observation": "RADIUS or TACACS+ login authentication is configured without an active centralized exec authorization method.",
            "recommendation": "Configure AAA exec authorization through the approved central service with a controlled local fallback.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-security"
            ],
            "rule_id": "arista.eos.authorization.exec",
            "severity": "Medium",
            "title": "Centralized login lacks exec authorization"
        },
        "11.0.6. No remote syslog destination is configured": {
            "device": "ARISTA_EOS",
            "ease": "An attacker with device access benefits from reduced external evidence.",
            "evidence": [
                "remote logging destination absent"
            ],
            "exploitability": "An attacker with device access benefits from reduced external evidence.",
            "impact": "Security events may be lost through local rollover or device compromise.",
            "observation": "No active 'logging host' destination was found.",
            "recommendation": "Configure protected, redundant remote syslog destinations.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-security"
            ],
            "rule_id": "arista.eos.logging.remote_destination",
            "severity": "Medium",
            "title": "No remote syslog destination is configured"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: none of the two definite NTP/key-storage issues.
- Detected but degraded: service-ACL findings identify the absence of explicit restrictions but cannot prove exposure outside the MGMT VRF.
- Missed entirely: NTP authentication and reversible RADIUS key storage.
- False positives: no definite one; AAA authorization and remote logging judgments require the operator's management policy.
- Crashes/failures: none.

<a id="RW-006"></a>
### PAN_OS — Palo Alto Networks bootstrap XML template

**Provenance:** [Palo Alto Networks panos-bootstrapper bootstrap XML](https://github.com/PaloAltoNetworks/panos-bootstrapper/blob/master/bootstrapper/templates/import/bootstrap/bootstrap.xml), raw vendor-published Jinja deployment template; SHA-256 `5169D75826F0BECBA2BC6C82C2888365B05EC3D3D550265C3A8E433BC41326B9`. It has unresolved `{{ ... }}` placeholders and targets PAN-OS 8.0.0; a scan of it tests template parsing, not a deployed firewall. Only explicit template choices are assessed.

**Ground truth (established before running the tool):**
- The threat-content recurring schedule selects `download-only` rather than installation. If deployed without another installation mechanism, new threat definitions would not become active automatically. This is a conditional design concern; deployment automation could install them elsewhere.
- The template disables HTTP and Telnet, so neither is ground truth. The administrator username/password are Jinja placeholders; hash algorithm, actual value and account privilege safety cannot be assessed as deployed values.
- No absence-based findings for rule logging, NTP, syslog or certificate validity are asserted, because the template is not a complete rendered export.

**Tool output (actual, unedited):**

**RW006 CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Palo Alto PAN-OS)
[2/4] Fetching PAN-OS API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW006.json
```

**RW006 generated JSON report (SHA-256 `2970016EDB11458F62A600BDF140C770EA1D7537ADB2EC87F8641417D041BA52`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "PAN_OS",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "PAN-OS model metadata was not present",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "PaloAltoPANOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:22:00.301629",
        "device-type": "PAN_OS",
        "hostname": "{{ hostname }}"
    },
    "remediation-summary": {
        "finding-count": 7,
        "priority-actions": [
            {
                "recommendation": "Enable password complexity and require at least 12 characters with uppercase, lowercase, numeric, and special-character minima, or apply the approved organizational benchmark.",
                "rule-id": "paloalto.panos.credentials.password_complexity",
                "severity": "High",
                "title": "Management password complexity is insufficient"
            },
            {
                "recommendation": "Configure a recurring Applications and Threats update schedule using download-and-install with an approved rollout threshold.",
                "rule-id": "paloalto.panos.updates.threat_content",
                "severity": "High",
                "title": "Threat content is not scheduled for automatic installation"
            },
            {
                "recommendation": "Use RADIUS, SAML, TACACS+, or another approved external authentication profile, with a controlled emergency local account.",
                "rule-id": "paloalto.panos.admin.centralized_authentication",
                "severity": "Medium",
                "title": "Administrators use local-only authentication"
            },
            {
                "recommendation": "Configure an organization-approved login banner on the management interface.",
                "rule-id": "paloalto.panos.admin.login_banner",
                "severity": "Medium",
                "title": "Administrative login banner is missing"
            },
            {
                "recommendation": "Configure Device Log Settings for system events and send relevant severities to protected centralized syslog destinations.",
                "rule-id": "paloalto.panos.logging.system_forwarding",
                "severity": "Medium",
                "title": "System events lack a syslog forwarding destination"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 2,
            "Low": 2,
            "Medium": 3
        }
    },
    "security-audit": {
        "7.0.0. Management password complexity is insufficient": {
            "device": "PAN_OS",
            "ease": "An attacker with management reachability can target accounts protected by the weak local policy.",
            "evidence": [
                "password-complexity absent"
            ],
            "exploitability": "An attacker with management reachability can target accounts protected by the weak local policy.",
            "impact": "Weak local administrator passwords are more susceptible to guessing and credential attacks.",
            "observation": "The local administrator password policy is unsafe: complexity is absent or disabled; minimum length is below 12 or unparseable; uppercase character minimum is below 1 or unparseable; lowercase character minimum is below 1 or unparseable; numeric character minimum is below 1 or unparseable; special character minimum is below 1 or unparseable.",
            "recommendation": "Enable password complexity and require at least 12 characters with uppercase, lowercase, numeric, and special-character minima, or apply the approved organizational benchmark.",
            "references": [
                "https://origin-docs.paloaltonetworks.com/ngfw/help/12-1/device/device-setup-management"
            ],
            "rule_id": "paloalto.panos.credentials.password_complexity",
            "severity": "High",
            "title": "Management password complexity is insufficient"
        },
        "7.0.1. Administrators use local-only authentication": {
            "device": "PAN_OS",
            "ease": "Compromise of a local credential can provide firewall access independently of central identity controls.",
            "evidence": [
                "mgt-config user {{ ADMINISTRATOR_USERNAME }}"
            ],
            "exploitability": "Compromise of a local credential can provide firewall access independently of central identity controls.",
            "impact": "Local-only accounts reduce centralized revocation, policy enforcement, and authentication auditability.",
            "observation": "Every parsed administrator account uses the local authentication database.",
            "recommendation": "Use RADIUS, SAML, TACACS+, or another approved external authentication profile, with a controlled emergency local account.",
            "references": [
                "https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/manage-firewall-administrators/administrative-authentication"
            ],
            "rule_id": "paloalto.panos.admin.centralized_authentication",
            "severity": "Medium",
            "title": "Administrators use local-only authentication"
        },
        "7.0.2. Administrative login banner is missing": {
            "device": "PAN_OS",
            "ease": "Missing legal or acceptable-use notice can weaken deterrence and incident-response support.",
            "evidence": [
                "localhost.localdomain: administrative management settings"
            ],
            "exploitability": "Missing legal or acceptable-use notice can weaken deterrence and incident-response support.",
            "impact": "Administrators are not shown an approved access warning before authentication.",
            "observation": "No login banner is configured for device scope 'localhost.localdomain'.",
            "recommendation": "Configure an organization-approved login banner on the management interface.",
            "references": [
                "https://origin-docs.paloaltonetworks.com/ngfw/help/12-1/device/device-setup-management"
            ],
            "rule_id": "paloalto.panos.admin.login_banner",
            "severity": "Medium",
            "title": "Administrative login banner is missing"
        },
        "7.0.3. No NTP servers are configured": {
            "device": "PAN_OS",
            "ease": "Inconsistent time reduces the reliability of monitoring and forensic timelines.",
            "evidence": [
                "deviceconfig system ntp-servers absent"
            ],
            "exploitability": "Inconsistent time reduces the reliability of monitoring and forensic timelines.",
            "impact": "Incorrect timestamps hinder log correlation, authentication, and certificate validation.",
            "observation": "Neither a primary nor secondary NTP server address was found in local device configuration.",
            "recommendation": "Configure redundant trusted primary and secondary NTP servers.",
            "references": [
                "https://docs.paloaltonetworks.com/ngfw/getting-started/initial-setup-configuration-ngfws"
            ],
            "rule_id": "paloalto.panos.ntp.servers",
            "severity": "Low",
            "title": "No NTP servers are configured"
        },
        "7.0.4. No DNS servers are configured": {
            "device": "PAN_OS",
            "ease": "Loss of dependable resolution can weaken availability and monitoring integrations.",
            "evidence": [
                "deviceconfig system dns-setting servers absent"
            ],
            "exploitability": "Loss of dependable resolution can weaken availability and monitoring integrations.",
            "impact": "Name resolution failures can disrupt update, logging, authentication, and security-service connectivity.",
            "observation": "Neither a primary nor secondary management-plane DNS server was found.",
            "recommendation": "Configure approved primary and secondary DNS resolvers for the management plane.",
            "references": [
                "https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-1-configure-cli-command-hierarchy"
            ],
            "rule_id": "paloalto.panos.dns.servers",
            "severity": "Low",
            "title": "No DNS servers are configured"
        },
        "7.0.5. Threat content is not scheduled for automatic installation": {
            "device": "PAN_OS",
            "ease": "Attackers may use techniques covered by signatures that have not yet been installed.",
            "evidence": [
                "localhost.localdomain: update-schedule threats weekly download-only"
            ],
            "exploitability": "Attackers may use techniques covered by signatures that have not yet been installed.",
            "impact": "Threat signatures and decoders can remain stale even when update packages are downloaded.",
            "observation": "No recurring Applications and Threats schedule with action 'download-and-install' was parsed.",
            "recommendation": "Configure a recurring Applications and Threats update schedule using download-and-install with an approved rollout threshold.",
            "references": [
                "https://docs.paloaltonetworks.com/advanced-threat-prevention/administration/configure-threat-prevention/set-up-antivirus-anti-spyware-and-vulnerability-protection"
            ],
            "rule_id": "paloalto.panos.updates.threat_content",
            "severity": "High",
            "title": "Threat content is not scheduled for automatic installation"
        },
        "7.0.6. System events lack a syslog forwarding destination": {
            "device": "PAN_OS",
            "ease": "An attacker who compromises the firewall benefits from reduced off-device audit evidence.",
            "evidence": [
                "deviceconfig system log-settings system syslog destination absent"
            ],
            "exploitability": "An attacker who compromises the firewall benefits from reduced off-device audit evidence.",
            "impact": "Administrative, update, high-availability, and system events may remain only on the appliance.",
            "observation": "No device-level system log match entry sends events to a syslog server profile.",
            "recommendation": "Configure Device Log Settings for system events and send relevant severities to protected centralized syslog destinations.",
            "references": [
                "https://docs.paloaltonetworks.com/ngfw/administration/monitoring/configure-log-forwarding"
            ],
            "rule_id": "paloalto.panos.logging.system_forwarding",
            "severity": "Medium",
            "title": "System events lack a syslog forwarding destination"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: download-only threat-content update schedule is reported as High, conditional on no external installer.
- Detected but degraded: none.
- Missed entirely: no definite additional issue can be asserted from unresolved Jinja values.
- False positives: password complexity, centralized auth, banner, DNS, NTP and system forwarding are all absence-based findings on an unrendered bootstrap template; they do not establish a deployed appliance's posture.
- Crashes/failures: none.

<a id="RW-007"></a>
### FORTIOS — Public FortiGate hardening deployment template

**Provenance:** [KevinGuenay FortiGate baseline configuration](https://github.com/KevinGuenay/fortigate-baseline/blob/main/resources/configurations/fortigate_baseline.conf), raw published template; SHA-256 `8F699AC75583D9ED3949F8D41ADABA248C8DF5C7E32A49C151C6EA9C5B990B63`. The placeholders, repeated editable sections and `edit 0` make it a deployment template, not a literal appliance backup. It is selected as published operational guidance, not because it targets a known scanner rule.

**Ground truth (established before running the tool):**
- The template selects custom NTP servers but does not set association authentication or key IDs in its NTP block. If applied as-is under a policy requiring authenticated custom time, those associations would be unauthenticated. The placeholder server identities prevent a claim about actual runtime time sources.
- The template sets a strong password-policy length and disables Telnet management; those are not weaknesses. Password/trusthost placeholders and uninstantiated firewall objects cannot be judged as actual weak values or destinations.
- Because this is a collection of hardening commands with placeholders, missing logging/certificate/DoS configuration is not interpreted as absent from any full device. A scanner finding based solely on absent sections would be a scope problem for this input.

**Tool output (actual, unedited):**

**RW007 CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Fortinet FortiOS)
[2/4] Fetching Fortinet API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW007.json
```

**RW007 generated JSON report (SHA-256 `F22B98F520F7C76F93CBE927C8747B5D999822C02EBC2EF2F00257D08E5BE0CE`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "FORTIOS",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Hostname is absent",
                "knowledge-state": "unknown",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "FortiGate model is absent from config-version header",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "FortiOS config-version header is absent",
                "knowledge-state": "unknown",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 3,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 3,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "FortiOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:22:00.622019",
        "device-type": "FORTIOS",
        "hostname": "fortigate-device"
    },
    "remediation-summary": {
        "finding-count": 3,
        "priority-actions": [
            {
                "recommendation": "Enable an approved FortiToken, email, SMS, or organization-approved federated MFA method.",
                "rule-id": "fortinet.fortios.admin.mfa",
                "severity": "High",
                "title": "Privileged local administrator lacks MFA"
            },
            {
                "recommendation": "Enable at least one supported centralized logging target and configure its destination and filters.",
                "rule-id": "fortinet.fortios.logging.missing",
                "severity": "Medium",
                "title": "Lack of System Logging"
            },
            {
                "recommendation": "Enable NTPv4 authentication with a complete SHA-256 key binding where supported.",
                "rule-id": "fortinet.fortios.ntp.authentication",
                "severity": "Medium",
                "title": "Custom NTP server authentication is weak"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 1,
            "Medium": 2
        }
    },
    "security-audit": {
        "8.0.0. Lack of System Logging": {
            "device": "FORTIOS",
            "ease": "Reduced centralized visibility makes malicious activity harder to detect and investigate.",
            "evidence": [
                "No supported logging target configured"
            ],
            "exploitability": "Reduced centralized visibility makes malicious activity harder to detect and investigate.",
            "impact": "Security events may not reach a centralized audit and monitoring system.",
            "observation": "No enabled and usable syslog, FortiAnalyzer, FortiManager, or FortiCloud destination was found.",
            "recommendation": "Enable at least one supported centralized logging target and configure its destination and filters.",
            "references": [
                "https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/250999/log-settings-and-targets"
            ],
            "rule_id": "fortinet.fortios.logging.missing",
            "severity": "Medium",
            "title": "Lack of System Logging"
        },
        "8.1.0. Privileged local administrator lacks MFA": {
            "device": "FORTIOS",
            "ease": "An attacker with reachability or administrative access may exploit the effective weakness.",
            "evidence": [
                "edit \"<###PLACEHOLDER_ADMIN-NAME###>\""
            ],
            "exploitability": "An attacker with reachability or administrative access may exploit the effective weakness.",
            "impact": "A stolen password alone may be sufficient for privileged access.",
            "observation": "Local super_admin account '<###PLACEHOLDER_ADMIN-NAME###>' in scope 'root' has no enabled two-factor method.",
            "recommendation": "Enable an approved FortiToken, email, SMS, or organization-approved federated MFA method.",
            "references": [
                "https://docs.fortinet.com/document/fortigate/7.2.11/administration-guide/14906/administrator-account-options",
                "https://docs.fortinet.com/document/fortigate/7.2.0/cli-reference/16620/config-system-admin"
            ],
            "rule_id": "fortinet.fortios.admin.mfa",
            "severity": "High",
            "title": "Privileged local administrator lacks MFA"
        },
        "8.1.1. Custom NTP server authentication is weak": {
            "device": "FORTIOS",
            "ease": "An attacker with reachability or administrative access may exploit the effective weakness.",
            "evidence": [
                "edit 0"
            ],
            "exploitability": "An attacker with reachability or administrative access may exploit the effective weakness.",
            "impact": "An unauthenticated or weakly authenticated time source can spoof device time.",
            "observation": "NTP server '0' in scope 'root' has authentication disabled; key material is redacted.",
            "recommendation": "Enable NTPv4 authentication with a complete SHA-256 key binding where supported.",
            "references": [
                "https://docs.fortinet.com/document/fortigate/7.2.11/administration-guide/512210/setting-the-system-time",
                "https://docs.fortinet.com/document/fortigate/7.2.11/administration-guide/336196/cryptographic-hash-function-authentication-support"
            ],
            "rule_id": "fortinet.fortios.ntp.authentication",
            "severity": "Medium",
            "title": "Custom NTP server authentication is weak"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: unauthenticated custom NTP is reported.
- Detected but degraded: none.
- Missed entirely: no definite weakness beyond the conditional NTP choice.
- False positives: local-admin MFA and system-logging absence are not knowable from a placeholder deployment template with incomplete sections.
- Crashes/failures: none.


<a id="RW-008"></a>
### ASA — Microsoft Azure ASA 9.2 site-to-site VPN running-config sample

**Provenance:** [Azure ASA show running-config sample](https://github.com/Azure/Azure-vpn-config-samples/blob/master/Cisco/Current/ASA/ASA_9.1_and_above_Show_running-config.txt); raw SHA-256 `C1027FD12D4DB67736C84F5C42B5C3C4898FF04770EE2E4546B44D94E2AE23A6`. Published sample with masked addresses and preshared key, rather than an unaltered production export.

**Ground truth, before scan:** `console timeout 0` disables console idle logout. The bound IKEv1 policy uses DH group 2, a legacy finite-field group; the crypto-map binds only the AES-256/SHA transform, so the other declared 3DES/DES/MD5 transforms are **not** asserted active. `ssh key-exchange group dh-group1-sha1` is explicitly weak if SSH is enabled, but no `ssh <source>` grant is present, so runtime exposure is unresolved. `http server enable` is ASA's ASDM HTTPS server and is not called cleartext HTTP. The full published sample lacks an external logging destination and NTP server; sample omission limits the claim.

**Tool output (actual, unedited):**

**RW008-ASA CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (ASA)
[3/4] Checking missconfiguration vulnerabilities
[3/4] Scanning configuration file using the following ASA plugins: ['PluginASAChecks', 'PluginASABaseline']
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW008-ASA.json
```

**RW008-ASA generated JSON report (SHA-256 `98EB2E0F9E61D5760A65E9E6D0E659FB26C7CEDF6336CFB73886B68D6AA83151`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "ASA",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "ASA hardware model is not parsed from the supported configuration export",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoASAParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:45:45.226593",
        "device-type": "ASA",
        "hostname": "ciscoasa"
    },
    "remediation-summary": {
        "finding-count": 19,
        "priority-actions": [
            {
                "recommendation": "Replace the credential with a unique secret stored using a supported strong hash format.",
                "rule-id": "cisco.asa.credentials.weak_enable_password",
                "severity": "High",
                "title": "Unsafe enable credential storage"
            },
            {
                "recommendation": "Bind the protocol to LOCAL with a defined local user, or to a defined resilient AAA server group with an appropriate LOCAL fallback.",
                "rule-id": "cisco.asa.aaa.management_authentication",
                "severity": "High",
                "title": "Management authentication binding is unresolved"
            },
            {
                "recommendation": "Use AES-GCM/AES-256, SHA-256 or stronger, and approved modern DH groups.",
                "rule-id": "cisco.asa.crypto.legacy_vpn",
                "severity": "High",
                "title": "VPN policy uses legacy cryptography"
            },
            {
                "recommendation": "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
                "rule-id": "cisco.asa.crypto.legacy_transform",
                "severity": "High",
                "title": "IPsec transform-set uses legacy cryptography"
            },
            {
                "recommendation": "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
                "rule-id": "cisco.asa.crypto.legacy_transform",
                "severity": "High",
                "title": "IPsec transform-set uses legacy cryptography"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 14,
            "Low": 1,
            "Medium": 4
        }
    },
    "security-audit": {
        "2.0.0. Unsafe enable credential storage": {
            "device": "ASA",
            "ease": "Default values are easily guessed; plaintext values are exposed if the configuration is obtained.",
            "evidence": [
                "enable password <redacted> encrypted"
            ],
            "exploitability": "Default values are easily guessed; plaintext values are exposed if the configuration is obtained.",
            "impact": "A recoverable or default credential can enable administrative privilege escalation.",
            "observation": "The enable credential uses format 'encrypted', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate exact-default comparison is 'not_evaluated' and the blocklist comparison was not evaluated against a supplied credential blocklist. The secret value has been redacted.",
            "recommendation": "Replace the credential with a unique secret stored using a supported strong hash format.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/e-commands.html"
            ],
            "rule_id": "cisco.asa.credentials.weak_enable_password",
            "severity": "High",
            "title": "Unsafe enable credential storage"
        },
        "2.0.1. Remote security logging is not operational": {
            "device": "ASA",
            "ease": "An attacker may operate with reduced likelihood of centralized detection.",
            "evidence": [
                "No active logging host"
            ],
            "exploitability": "An attacker may operate with reduced likelihood of centralized detection.",
            "impact": "Security events may not be retained for monitoring, investigation, or audit.",
            "observation": "Centralized logging is unavailable because logging is disabled.",
            "recommendation": "Enable logging and configure at least one reachable remote 'logging host'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/monitor-syslog.html"
            ],
            "rule_id": "cisco.asa.logging.missing",
            "severity": "Low",
            "title": "Remote security logging is not operational"
        },
        "2.0.10. IPsec transform-set uses legacy cryptography": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "crypto ipsec ikev1 transform-set ESP-AES-128-MD5 esp-aes esp-md5-hmac"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Legacy transforms weaken protected VPN traffic.",
            "observation": "An IPsec transform-set includes a legacy encryption or integrity algorithm.",
            "recommendation": "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.crypto.legacy_transform",
            "severity": "High",
            "title": "IPsec transform-set uses legacy cryptography"
        },
        "2.0.11. IPsec transform-set uses legacy cryptography": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "crypto ipsec ikev1 transform-set ESP-AES-192-SHA esp-aes-192 esp-sha-hmac"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Legacy transforms weaken protected VPN traffic.",
            "observation": "An IPsec transform-set includes a legacy encryption or integrity algorithm.",
            "recommendation": "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.crypto.legacy_transform",
            "severity": "High",
            "title": "IPsec transform-set uses legacy cryptography"
        },
        "2.0.12. IPsec transform-set uses legacy cryptography": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "crypto ipsec ikev1 transform-set ESP-AES-192-MD5 esp-aes-192 esp-md5-hmac"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Legacy transforms weaken protected VPN traffic.",
            "observation": "An IPsec transform-set includes a legacy encryption or integrity algorithm.",
            "recommendation": "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.crypto.legacy_transform",
            "severity": "High",
            "title": "IPsec transform-set uses legacy cryptography"
        },
        "2.0.13. IPsec transform-set uses legacy cryptography": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "crypto ipsec ikev1 transform-set ESP-AES-256-SHA esp-aes-256 esp-sha-hmac"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Legacy transforms weaken protected VPN traffic.",
            "observation": "An IPsec transform-set includes a legacy encryption or integrity algorithm.",
            "recommendation": "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.crypto.legacy_transform",
            "severity": "High",
            "title": "IPsec transform-set uses legacy cryptography"
        },
        "2.0.14. IPsec transform-set uses legacy cryptography": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "crypto ipsec ikev1 transform-set ESP-AES-256-MD5 esp-aes-256 esp-md5-hmac"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Legacy transforms weaken protected VPN traffic.",
            "observation": "An IPsec transform-set includes a legacy encryption or integrity algorithm.",
            "recommendation": "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.crypto.legacy_transform",
            "severity": "High",
            "title": "IPsec transform-set uses legacy cryptography"
        },
        "2.0.15. IPsec transform-set uses legacy cryptography": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "crypto ipsec ikev1 transform-set ESP-3DES-SHA esp-3des esp-sha-hmac"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Legacy transforms weaken protected VPN traffic.",
            "observation": "An IPsec transform-set includes a legacy encryption or integrity algorithm.",
            "recommendation": "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.crypto.legacy_transform",
            "severity": "High",
            "title": "IPsec transform-set uses legacy cryptography"
        },
        "2.0.16. IPsec transform-set uses legacy cryptography": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "crypto ipsec ikev1 transform-set ESP-3DES-MD5 esp-3des esp-md5-hmac"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Legacy transforms weaken protected VPN traffic.",
            "observation": "An IPsec transform-set includes a legacy encryption or integrity algorithm.",
            "recommendation": "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.crypto.legacy_transform",
            "severity": "High",
            "title": "IPsec transform-set uses legacy cryptography"
        },
        "2.0.17. IPsec transform-set uses legacy cryptography": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "crypto ipsec ikev1 transform-set ESP-DES-SHA esp-des esp-sha-hmac"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Legacy transforms weaken protected VPN traffic.",
            "observation": "An IPsec transform-set includes a legacy encryption or integrity algorithm.",
            "recommendation": "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.crypto.legacy_transform",
            "severity": "High",
            "title": "IPsec transform-set uses legacy cryptography"
        },
        "2.0.18. IPsec transform-set uses legacy cryptography": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "crypto ipsec ikev1 transform-set ESP-DES-MD5 esp-des esp-md5-hmac"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Legacy transforms weaken protected VPN traffic.",
            "observation": "An IPsec transform-set includes a legacy encryption or integrity algorithm.",
            "recommendation": "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.crypto.legacy_transform",
            "severity": "High",
            "title": "IPsec transform-set uses legacy cryptography"
        },
        "2.0.2. Management authentication binding is unresolved": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "active http management grant"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Management access may rely on an unintended authentication path or an unavailable server group.",
            "observation": "Active HTTP management is missing for its AAA authentication binding.",
            "recommendation": "Bind the protocol to LOCAL with a defined local user, or to a defined resilient AAA server group with an appropriate LOCAL fallback.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/aa-ac-commands.html"
            ],
            "rule_id": "cisco.asa.aaa.management_authentication",
            "severity": "High",
            "title": "Management authentication binding is unresolved"
        },
        "2.0.3. ASA console session timeout is disabled": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "console timeout 0"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "An unattended privileged console session can remain available indefinitely.",
            "observation": "The effective console timeout is 0 minutes, so authenticated serial or enable sessions do not time out.",
            "recommendation": "Set a finite console timeout that meets the approved administrative-session policy.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config/admin-management.html"
            ],
            "rule_id": "cisco.asa.console.session_timeout",
            "severity": "Medium",
            "title": "ASA console session timeout is disabled"
        },
        "2.0.4. ASDM/HTTPS trustpoint is not explicitly assigned": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "http server enable"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Administrators may receive an untrusted or unintended device certificate.",
            "observation": "The management web server is enabled without an explicit SSL trustpoint assignment.",
            "recommendation": "Enroll a managed certificate and assign it with 'ssl trust-point'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.management.certificate",
            "severity": "Medium",
            "title": "ASDM/HTTPS trustpoint is not explicitly assigned"
        },
        "2.0.5. NTP synchronization is not configured": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "No ntp server command"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Incorrect time weakens event correlation, certificate validation, and forensic timelines.",
            "observation": "No NTP server is configured.",
            "recommendation": "Configure multiple trusted NTP servers.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/n-commands.html"
            ],
            "rule_id": "cisco.asa.ntp.servers",
            "severity": "Medium",
            "title": "NTP synchronization is not configured"
        },
        "2.0.6. Reverse-path verification is missing": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "interface outside"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Spoofed source addresses may cross the firewall boundary without an interface-level routing check.",
            "observation": "Low-trust interface 'outside' does not have uRPF reverse-path verification enabled.",
            "recommendation": "Configure 'ip verify reverse-path interface <nameif>' after validating asymmetric routing requirements.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.interface.reverse_path",
            "severity": "Medium",
            "title": "Reverse-path verification is missing"
        },
        "2.0.7. VPN policy uses legacy cryptography": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "crypto ikev1 policy 5",
                "group 2"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Weak VPN algorithms reduce confidentiality, integrity, or key-exchange strength.",
            "observation": "crypto ikev1 policy 5 contains legacy encryption, integrity, or Diffie-Hellman selections.",
            "recommendation": "Use AES-GCM/AES-256, SHA-256 or stronger, and approved modern DH groups.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.crypto.legacy_vpn",
            "severity": "High",
            "title": "VPN policy uses legacy cryptography"
        },
        "2.0.8. IPsec transform-set uses legacy cryptography": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "crypto ipsec ikev1 transform-set azure-ipsec-proposal-set esp-aes-256 esp-sha-hmac"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Legacy transforms weaken protected VPN traffic.",
            "observation": "An IPsec transform-set includes a legacy encryption or integrity algorithm.",
            "recommendation": "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.crypto.legacy_transform",
            "severity": "High",
            "title": "IPsec transform-set uses legacy cryptography"
        },
        "2.0.9. IPsec transform-set uses legacy cryptography": {
            "device": "ASA",
            "ease": "An attacker with management or data-plane reachability may exploit this condition.",
            "evidence": [
                "crypto ipsec ikev1 transform-set ESP-AES-128-SHA esp-aes esp-sha-hmac"
            ],
            "exploitability": "An attacker with management or data-plane reachability may exploit this condition.",
            "impact": "Legacy transforms weaken protected VPN traffic.",
            "observation": "An IPsec transform-set includes a legacy encryption or integrity algorithm.",
            "recommendation": "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html",
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/vpn/asa-924-vpn-config.pdf"
            ],
            "rule_id": "cisco.asa.crypto.legacy_transform",
            "severity": "High",
            "title": "IPsec transform-set uses legacy cryptography"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: disabled console idle logout and weak bound IKEv1 group 2.
- Detected but degraded: the active AES-256/SHA-1 transform is identified as legacy without distinguishing its SHA-1 concern from cipher strength.
- Missed entirely: the explicitly weak SSH key exchange, if SSH is actually granted; no SSH grant appears, so this is a conditional gap.
- False positives: ten unbound transform declarations receive High-severity active-sounding findings even though only azure-ipsec-proposal-set is selected by the outside crypto map. The evidence for the 11th transform is bound and should remain assessed.
- Crashes/failures: none.

<a id="RW-009"></a>
### ARISTA_EOS — Second community AVD EVPN leaf

**Provenance:** [Arista NetDevOps LEAF1A intended configuration](https://github.com/arista-netdevops-community/avd-evpn-webinar-june-11/blob/master/intended/configs/LEAF1A.cfg); raw SHA-256 `DC21086BA2FED07888FE46ACBB2D3FF8B62042A6D924E8C2B258C2AF6C1DF60D`. Separate device in the same published lab design, hence a dialect check rather than an independent operator population.

**Ground truth, before scan:** The two NTP servers have no NTP authentication or key binding in the complete intended configuration. The RADIUS server uses reversible type-7 key storage. The `TerminAttr` daemon command contains a literal ingestion authentication key in plaintext; the value is intentionally not repeated in this document. As a lab/intended configuration, reachability and actual credential reuse are unknown.

**Tool output (actual, unedited):**

**RW009-EOS CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Arista EOS)
[2/4] Fetching Arista API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW009-EOS.json
```

**RW009-EOS generated JSON report (SHA-256 `B5BCAC663924A26AF3E452D4551713148A122E28A97A9CDAF203D49779F62401`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "ARISTA_EOS",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Model metadata absent",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "EOS version absent",
                "knowledge-state": "unknown",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 3,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "detail": "EOS interface roles are not normalized in this revision",
                "item-count": null,
                "knowledge-state": "unknown",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "detail": "EOS is not parsed as a firewall policy platform",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "AristaEOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:45:45.679031",
        "device-type": "ARISTA_EOS",
        "hostname": "LEAF1A"
    },
    "remediation-summary": {
        "finding-count": 7,
        "priority-actions": [
            {
                "recommendation": "Configure 'aaa authorization commands all default' using the approved service and controlled fallback.",
                "rule-id": "arista.eos.authorization.commands",
                "severity": "High",
                "title": "Centralized login lacks command authorization"
            },
            {
                "recommendation": "Apply explicit IPv4 and, where applicable, IPv6 service ACLs to each enabled eAPI VRF.",
                "rule-id": "arista.eos.eapi.source_restriction",
                "severity": "Medium",
                "title": "eAPI endpoint lacks a service ACL"
            },
            {
                "recommendation": "Configure default EXEC and all-command accounting to TACACS+, RADIUS, or protected syslog.",
                "rule-id": "arista.eos.authentication.accounting",
                "severity": "Medium",
                "title": "Centralized administrative access lacks complete accounting"
            },
            {
                "recommendation": "Attach a named SSL profile with an approved certificate and TLS 1.2 or 1.3 policy.",
                "rule-id": "arista.eos.eapi.tls_profile",
                "severity": "Medium",
                "title": "eAPI HTTPS lacks an explicit SSL profile"
            },
            {
                "recommendation": "Apply IPv4 and, where applicable, IPv6 access groups in management SSH configuration for each management VRF.",
                "rule-id": "arista.eos.ssh.source_restriction",
                "severity": "Medium",
                "title": "Explicit SSH service policy lacks access groups"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 1,
            "Medium": 6
        }
    },
    "security-audit": {
        "11.0.0. eAPI endpoint lacks a service ACL": {
            "device": "ARISTA_EOS",
            "ease": "Any host with VRF reachability can probe the service or attempt authentication.",
            "evidence": [
                "management api http-commands",
                "vrf MGMT",
                "no shutdown"
            ],
            "exploitability": "Any host with VRF reachability can probe the service or attempt authentication.",
            "impact": "All routed clients in the endpoint VRF can attempt API access.",
            "observation": "The active eAPI endpoint in VRF 'MGMT' has no IPv4 or IPv6 access-group.",
            "recommendation": "Apply explicit IPv4 and, where applicable, IPv6 service ACLs to each enabled eAPI VRF.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-acls-and-route-maps"
            ],
            "rule_id": "arista.eos.eapi.source_restriction",
            "severity": "Medium",
            "title": "eAPI endpoint lacks a service ACL"
        },
        "11.0.1. Centralized login lacks command authorization": {
            "device": "ARISTA_EOS",
            "ease": "A compromised account can receive broader CLI access than the identity service intended.",
            "evidence": [
                "centralized login authentication without all-command authorization"
            ],
            "exploitability": "A compromised account can receive broader CLI access than the identity service intended.",
            "impact": "Authenticated users may execute commands outside the intended central or local RBAC policy.",
            "observation": "Remote login authentication is configured without an effective default all-command authorization method list.",
            "recommendation": "Configure 'aaa authorization commands all default' using the approved service and controlled fallback.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-user-security"
            ],
            "rule_id": "arista.eos.authorization.commands",
            "severity": "High",
            "title": "Centralized login lacks command authorization"
        },
        "11.0.2. Centralized administrative access lacks complete accounting": {
            "device": "ARISTA_EOS",
            "ease": "A compromised administrator can act with reduced centralized evidence.",
            "evidence": [
                "default EXEC/all-command accounting incomplete"
            ],
            "exploitability": "A compromised administrator can act with reduced centralized evidence.",
            "impact": "Login sessions or executed commands may lack an independent audit trail.",
            "observation": "Default AAA accounting is missing for: commands-all, exec.",
            "recommendation": "Configure default EXEC and all-command accounting to TACACS+, RADIUS, or protected syslog.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-user-security"
            ],
            "rule_id": "arista.eos.authentication.accounting",
            "severity": "Medium",
            "title": "Centralized administrative access lacks complete accounting"
        },
        "11.0.3. eAPI HTTPS lacks an explicit SSL profile": {
            "device": "ARISTA_EOS",
            "ease": "Administrators may receive an unexpected certificate or negotiate an unintended legacy protocol.",
            "evidence": [
                "management api http-commands",
                "vrf MGMT",
                "no shutdown"
            ],
            "exploitability": "Administrators may receive an unexpected certificate or negotiate an unintended legacy protocol.",
            "impact": "Certificate identity and TLS-version policy remain dependent on an implicit service default.",
            "observation": "The active HTTPS eAPI endpoint in VRF 'MGMT' does not attach an SSL profile.",
            "recommendation": "Attach a named SSL profile with an approved certificate and TLS 1.2 or 1.3 policy.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-control-plane-security",
                "https://www.arista.com/en/um-eos/eos-session-management-commands"
            ],
            "rule_id": "arista.eos.eapi.tls_profile",
            "severity": "Medium",
            "title": "eAPI HTTPS lacks an explicit SSL profile"
        },
        "11.0.4. Explicit SSH service policy lacks access groups": {
            "device": "ARISTA_EOS",
            "ease": "A reachable attacker can probe the daemon, guess credentials, or target SSH implementation flaws.",
            "evidence": [
                "management ssh",
                "vrf MGMT",
                "no shutdown"
            ],
            "exploitability": "A reachable attacker can probe the daemon, guess credentials, or target SSH implementation flaws.",
            "impact": "Every routed source that can reach the switch can attempt SSH authentication.",
            "observation": "A management SSH block is configured without an IPv4 or IPv6 service ACL.",
            "recommendation": "Apply IPv4 and, where applicable, IPv6 access groups in management SSH configuration for each management VRF.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-acls-and-route-maps",
                "https://www.arista.com/en/um-eos/eos-session-management-commands"
            ],
            "rule_id": "arista.eos.ssh.source_restriction",
            "severity": "Medium",
            "title": "Explicit SSH service policy lacks access groups"
        },
        "11.0.5. Centralized login lacks exec authorization": {
            "device": "ARISTA_EOS",
            "ease": "A compromised or overprivileged account can exercise commands not constrained by centralized authorization.",
            "evidence": [
                "centralized login authentication without aaa authorization exec"
            ],
            "exploitability": "A compromised or overprivileged account can exercise commands not constrained by centralized authorization.",
            "impact": "Authenticated users may receive locally determined command access that is broader than central policy intends.",
            "observation": "RADIUS or TACACS+ login authentication is configured without an active centralized exec authorization method.",
            "recommendation": "Configure AAA exec authorization through the approved central service with a controlled local fallback.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-security"
            ],
            "rule_id": "arista.eos.authorization.exec",
            "severity": "Medium",
            "title": "Centralized login lacks exec authorization"
        },
        "11.0.6. No remote syslog destination is configured": {
            "device": "ARISTA_EOS",
            "ease": "An attacker with device access benefits from reduced external evidence.",
            "evidence": [
                "remote logging destination absent"
            ],
            "exploitability": "An attacker with device access benefits from reduced external evidence.",
            "impact": "Security events may be lost through local rollover or device compromise.",
            "observation": "No active 'logging host' destination was found.",
            "recommendation": "Configure protected, redundant remote syslog destinations.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-security"
            ],
            "rule_id": "arista.eos.logging.remote_destination",
            "severity": "Medium",
            "title": "No remote syslog destination is configured"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: none of the three explicit ground-truth properties.
- Detected but degraded: none.
- Missed entirely: unauthenticated NTP, reversible type-7 RADIUS key, and plaintext TerminAttr ingestion token. Token reuse/reachability is unknown.
- False positives: no definite one established; source-restriction and AAA role assertions depend on MGMT VRF topology and EOS policy.
- Crashes/failures: none.

<a id="RW-010"></a>
### PAN_OS — Vendor's full Iron Skillet PAN-OS 10.1 XML

**Provenance:** [Palo Alto Networks Iron Skillet loadable full configuration](https://github.com/PaloAltoNetworks/iron-skillet/blob/panos_v10.1/loadable_configs/sample-mgmt-static/panos/iron_skillet_panos_full.xml); raw SHA-256 `20A248972AFB27C82AF12A71304219389454D6D684B529CD111C5F270ADCED34`. Vendor security baseline sample, not a deployed device.

**Ground truth, before scan:** This sample explicitly enables password complexity, sets NTP servers, a login banner, and system-log syslog forwarding. These are useful **negative controls**: an absence finding for one would be incorrect. Weak `default` IKE/IPsec crypto profiles (3DES/SHA-1/group2) are present, but no bound VPN gateway using them was established; they are not scored as active weak VPN. Deployment-specific account hashes and actual reachable management paths are not inferred from a loadable baseline.

**Tool output (actual, unedited):**

**RW010-PAN CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Palo Alto PAN-OS)
[2/4] Fetching PAN-OS API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW010-PAN.json
```

**RW010-PAN generated JSON report (SHA-256 `04F7F9F7F0532AAA730FAA0D4B922CB70D810AE27B979B0EFD369A190F93B54E`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "PAN_OS",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "PAN-OS model metadata was not present",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 7,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "PaloAltoPANOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:45:46.030026",
        "device-type": "PAN_OS",
        "hostname": "panos-01"
    },
    "remediation-summary": {
        "finding-count": 6,
        "priority-actions": [
            {
                "recommendation": "Enable password complexity and require at least 12 characters with uppercase, lowercase, numeric, and special-character minima, or apply the approved organizational benchmark.",
                "rule-id": "paloalto.panos.credentials.password_complexity",
                "severity": "High",
                "title": "Management password complexity is insufficient"
            },
            {
                "recommendation": "Use RADIUS, SAML, TACACS+, or another approved external authentication profile, with a controlled emergency local account.",
                "rule-id": "paloalto.panos.admin.centralized_authentication",
                "severity": "Medium",
                "title": "Administrators use local-only authentication"
            },
            {
                "recommendation": "Configure complete per-server symmetric-key authentication using an algorithm supported by the installed PAN-OS release.",
                "rule-id": "paloalto.panos.ntp.authentication",
                "severity": "Medium",
                "title": "NTP association is not authenticated"
            },
            {
                "recommendation": "Configure complete per-server symmetric-key authentication using an algorithm supported by the installed PAN-OS release.",
                "rule-id": "paloalto.panos.ntp.authentication",
                "severity": "Medium",
                "title": "NTP association is not authenticated"
            },
            {
                "recommendation": "Configure Device Log Settings for system events and send relevant severities to protected centralized syslog destinations.",
                "rule-id": "paloalto.panos.logging.system_forwarding",
                "severity": "Medium",
                "title": "System events lack a syslog forwarding destination"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 1,
            "Low": 1,
            "Medium": 4
        }
    },
    "security-audit": {
        "7.0.0. Management password complexity is insufficient": {
            "device": "PAN_OS",
            "ease": "An attacker with management reachability can target accounts protected by the weak local policy.",
            "evidence": [
                "password-complexity absent"
            ],
            "exploitability": "An attacker with management reachability can target accounts protected by the weak local policy.",
            "impact": "Weak local administrator passwords are more susceptible to guessing and credential attacks.",
            "observation": "The local administrator password policy is unsafe: complexity is absent or disabled; minimum length is below 12 or unparseable; uppercase character minimum is below 1 or unparseable; lowercase character minimum is below 1 or unparseable; numeric character minimum is below 1 or unparseable; special character minimum is below 1 or unparseable.",
            "recommendation": "Enable password complexity and require at least 12 characters with uppercase, lowercase, numeric, and special-character minima, or apply the approved organizational benchmark.",
            "references": [
                "https://origin-docs.paloaltonetworks.com/ngfw/help/12-1/device/device-setup-management"
            ],
            "rule_id": "paloalto.panos.credentials.password_complexity",
            "severity": "High",
            "title": "Management password complexity is insufficient"
        },
        "7.0.1. Administrators use local-only authentication": {
            "device": "PAN_OS",
            "ease": "Compromise of a local credential can provide firewall access independently of central identity controls.",
            "evidence": [
                "mgt-config user adminuser"
            ],
            "exploitability": "Compromise of a local credential can provide firewall access independently of central identity controls.",
            "impact": "Local-only accounts reduce centralized revocation, policy enforcement, and authentication auditability.",
            "observation": "Every parsed administrator account uses the local authentication database.",
            "recommendation": "Use RADIUS, SAML, TACACS+, or another approved external authentication profile, with a controlled emergency local account.",
            "references": [
                "https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/manage-firewall-administrators/administrative-authentication"
            ],
            "rule_id": "paloalto.panos.admin.centralized_authentication",
            "severity": "Medium",
            "title": "Administrators use local-only authentication"
        },
        "7.0.2. Login banner acknowledgement is not enforced": {
            "device": "PAN_OS",
            "ease": "An unauthorized user can proceed directly to authentication without accepting the displayed notice.",
            "evidence": [
                "localhost.localdomain: administrative management settings"
            ],
            "exploitability": "An unauthorized user can proceed directly to authentication without accepting the displayed notice.",
            "impact": "The warning can be bypassed without affirmative acknowledgement.",
            "observation": "A login banner exists in device scope 'localhost.localdomain', but administrators are not explicitly required to acknowledge it.",
            "recommendation": "Enable Force Admins to Acknowledge Login Banner.",
            "references": [
                "https://origin-docs.paloaltonetworks.com/ngfw/help/12-1/device/device-setup-management"
            ],
            "rule_id": "paloalto.panos.admin.login_banner_acknowledgement",
            "severity": "Low",
            "title": "Login banner acknowledgement is not enforced"
        },
        "7.0.3. NTP association is not authenticated": {
            "device": "PAN_OS",
            "ease": "A network-positioned attacker may spoof NTP responses if routing and filtering permit it.",
            "evidence": [
                "localhost.localdomain: primary NTP server 0.pool.ntp.org; authentication none"
            ],
            "exploitability": "A network-positioned attacker may spoof NTP responses if routing and filtering permit it.",
            "impact": "Unauthenticated time responses can corrupt log chronology and time-dependent security behavior.",
            "observation": "The primary NTP server '0.pool.ntp.org' in scope 'localhost.localdomain' lacks a complete authentication configuration.",
            "recommendation": "Configure complete per-server symmetric-key authentication using an algorithm supported by the installed PAN-OS release.",
            "references": [
                "https://docs.paloaltonetworks.com/ngfw/getting-started/initial-setup-configuration-ngfws"
            ],
            "rule_id": "paloalto.panos.ntp.authentication",
            "severity": "Medium",
            "title": "NTP association is not authenticated"
        },
        "7.0.4. NTP association is not authenticated": {
            "device": "PAN_OS",
            "ease": "A network-positioned attacker may spoof NTP responses if routing and filtering permit it.",
            "evidence": [
                "localhost.localdomain: secondary NTP server 1.pool.ntp.org; authentication none"
            ],
            "exploitability": "A network-positioned attacker may spoof NTP responses if routing and filtering permit it.",
            "impact": "Unauthenticated time responses can corrupt log chronology and time-dependent security behavior.",
            "observation": "The secondary NTP server '1.pool.ntp.org' in scope 'localhost.localdomain' lacks a complete authentication configuration.",
            "recommendation": "Configure complete per-server symmetric-key authentication using an algorithm supported by the installed PAN-OS release.",
            "references": [
                "https://docs.paloaltonetworks.com/ngfw/getting-started/initial-setup-configuration-ngfws"
            ],
            "rule_id": "paloalto.panos.ntp.authentication",
            "severity": "Medium",
            "title": "NTP association is not authenticated"
        },
        "7.0.5. System events lack a syslog forwarding destination": {
            "device": "PAN_OS",
            "ease": "An attacker who compromises the firewall benefits from reduced off-device audit evidence.",
            "evidence": [
                "deviceconfig system log-settings system syslog destination absent"
            ],
            "exploitability": "An attacker who compromises the firewall benefits from reduced off-device audit evidence.",
            "impact": "Administrative, update, high-availability, and system events may remain only on the appliance.",
            "observation": "No device-level system log match entry sends events to a syslog server profile.",
            "recommendation": "Configure Device Log Settings for system events and send relevant severities to protected centralized syslog destinations.",
            "references": [
                "https://docs.paloaltonetworks.com/ngfw/administration/monitoring/configure-log-forwarding"
            ],
            "rule_id": "paloalto.panos.logging.system_forwarding",
            "severity": "Medium",
            "title": "System events lack a syslog forwarding destination"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: the two unauthenticated NTP associations (these were independent concerns, not a failed negative control).
- Detected but degraded: no definite issue.
- Missed entirely: none of the definite pre-scan vulnerabilities; this vendor baseline's inactive weak default crypto profiles were intentionally not scored.
- False positives: High-severity password-complexity finding says the element is absent although mgt-config/password-complexity explicitly enables it; Medium system-forwarding finding ignores shared/log-settings/system with an active syslog profile. The local-only administrator finding is a policy choice, and banner acknowledgement is distinct from banner presence.
- Crashes/failures: none.

<a id="RW-011"></a>
### FORTIOS — Published FortiOS 5.02 configuration export

**Provenance:** [FortiGate configuration file published for parser work](https://github.com/ChoBon/Parse-fortigate-configuration-files/blob/master/cfg1.txt); raw SHA-256 `8CF39CAEC2618C0E3E1326E73F2316E46395ACC6EC6F745E1810313C99788DC5`. It has a FortiOS export header and many full sections, but is an older sample and may be sanitized.

**Ground truth, before scan:** `port1` explicitly permits administrative `http` and `telnet` alongside HTTPS/SSH; no trusted-host scope is visible. Cleartext access is an observable risk if that interface is reachable. Disk logging is enabled; a finding that logging is entirely missing would be wrong, though remote logging is not established. `config system admin` is empty in the supplied export, so actual admin MFA cannot be determined. This old release's lifecycle status is outside static configuration testing.

**Tool output (actual, unedited):**

**RW011-FORTI CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Fortinet FortiOS)
[2/4] Fetching Fortinet API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW011-FORTI.json
```

**RW011-FORTI generated JSON report (SHA-256 `24C12E82F0F04F0E32A9D0EA27A2AB8082D654035C199CE3C7DA16D64344D9A6`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "FORTIOS",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Hostname is absent",
                "knowledge-state": "unknown",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 5,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 12,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "FortiOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:45:46.392111",
        "device-type": "FORTIOS",
        "hostname": "fortigate-device"
    },
    "remediation-summary": {
        "finding-count": 3,
        "priority-actions": [
            {
                "recommendation": "Remove http from this interface's allowaccess list and use HTTPS or SSH with restricted administrator trusted hosts.",
                "rule-id": "fortinet.fortios.management.insecure_protocol",
                "severity": "High",
                "title": "Weak Administrative Access"
            },
            {
                "recommendation": "Remove telnet from this interface's allowaccess list and use HTTPS or SSH with restricted administrator trusted hosts.",
                "rule-id": "fortinet.fortios.management.insecure_protocol",
                "severity": "High",
                "title": "Weak Administrative Access"
            },
            {
                "recommendation": "Enable at least one supported centralized logging target and configure its destination and filters.",
                "rule-id": "fortinet.fortios.logging.missing",
                "severity": "Medium",
                "title": "Lack of System Logging"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 2,
            "Medium": 1
        }
    },
    "security-audit": {
        "8.0.0. Weak Administrative Access": {
            "device": "FORTIOS",
            "ease": "An attacker with reachability to the named interface can intercept or attempt access to the insecure service.",
            "evidence": [
                "set allowaccess ping https ssh http telnet"
            ],
            "exploitability": "An attacker with reachability to the named interface can intercept or attempt access to the insecure service.",
            "impact": "Clear-text administrative traffic can expose credentials and device-management activity.",
            "observation": "HTTP management is enabled on interface 'port1' in VDOM/scope 'root' (unspecified); at least one enabled administrator has no effective trusted-host restriction.",
            "recommendation": "Remove http from this interface's allowaccess list and use HTTPS or SSH with restricted administrator trusted hosts.",
            "references": [
                "https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/616955/configuring-ports"
            ],
            "rule_id": "fortinet.fortios.management.insecure_protocol",
            "severity": "High",
            "title": "Weak Administrative Access"
        },
        "8.0.1. Weak Administrative Access": {
            "device": "FORTIOS",
            "ease": "An attacker with reachability to the named interface can intercept or attempt access to the insecure service.",
            "evidence": [
                "set allowaccess ping https ssh http telnet"
            ],
            "exploitability": "An attacker with reachability to the named interface can intercept or attempt access to the insecure service.",
            "impact": "Clear-text administrative traffic can expose credentials and device-management activity.",
            "observation": "TELNET management is enabled on interface 'port1' in VDOM/scope 'root' (unspecified); at least one enabled administrator has no effective trusted-host restriction.",
            "recommendation": "Remove telnet from this interface's allowaccess list and use HTTPS or SSH with restricted administrator trusted hosts.",
            "references": [
                "https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/616955/configuring-ports"
            ],
            "rule_id": "fortinet.fortios.management.insecure_protocol",
            "severity": "High",
            "title": "Weak Administrative Access"
        },
        "8.0.2. Lack of System Logging": {
            "device": "FORTIOS",
            "ease": "Reduced centralized visibility makes malicious activity harder to detect and investigate.",
            "evidence": [
                "No supported logging target configured"
            ],
            "exploitability": "Reduced centralized visibility makes malicious activity harder to detect and investigate.",
            "impact": "Security events may not reach a centralized audit and monitoring system.",
            "observation": "No enabled and usable syslog, FortiAnalyzer, FortiManager, or FortiCloud destination was found.",
            "recommendation": "Enable at least one supported centralized logging target and configure its destination and filters.",
            "references": [
                "https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/250999/log-settings-and-targets"
            ],
            "rule_id": "fortinet.fortios.logging.missing",
            "severity": "Medium",
            "title": "Lack of System Logging"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: cleartext HTTP and Telnet management on port1, as two High findings.
- Detected but degraded: disk logging is enabled, yet a Medium finding titled Lack of System Logging uses absence of a supported logging target; if the intended control is remote logging, the title/description must say so.
- Missed entirely: no other definite pre-scan flaw.
- False positives: the unqualified claim that system logging is absent conflicts with enabled disk logging.
- Crashes/failures: none.

<a id="RW-012"></a>
### IOS_SWITCH — Published Catalyst 2960 running configuration

**Provenance:** [Oxidized switch2 capture](https://github.com/tmullaly/oxidized/blob/master/switch2); raw SHA-256 `D53950F3E8251F0FA67151720080911E69C57AF3F5837A8279ED205A62E0E017`. External archived capture, IOS 15.0(2)SE11; its file publicly discloses encoded password hashes and a RADIUS key, which are not copied here.

**Ground truth, before scan:** `snmp-server community public RO` exposes a known default read-only community if reachable. `aaa group server radius IAS` has an unencrypted literal shared key in the public capture. VTY 0–4 permit SSH only and VTY 5–15 are `no exec`/`transport input none`, so a Telnet finding would be wrong. HTTP/HTTPS servers are explicitly disabled and remote logging is configured, making useful negative controls. The capture includes NTP servers without authentication; their trust boundary is unknown.

**Tool output (actual, unedited):**

**RW012-IOS CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng
[2/4] Fetching Cisco API information
[2/4] Cisco API disable.
[3/4] Checking missconfiguration vulnerabilities
[3/4] Scanning configuration file using the following IOS plugins: ['PluginHTTP', 'PluginSSH', 'PluginIOSBaseline']
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW012-IOS.json
```

**RW012-IOS generated JSON report (SHA-256 `12A5D12FB5B559A23F0597D6731D3B6C93284030BBC28FC27B301539C615839C`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "IOS_SWITCH",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "IOS running configuration does not provide reliable model metadata",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 10,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoIOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:45:46.915100",
        "device-type": "IOS_SWITCH",
        "hostname": "switch2"
    },
    "remediation-summary": {
        "finding-count": 18,
        "priority-actions": [
            {
                "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
                "rule-id": "cisco.ios.vty.authorization",
                "severity": "High",
                "title": "VTY administrative authorization is incomplete"
            },
            {
                "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
                "rule-id": "cisco.ios.console.authentication",
                "severity": "High",
                "title": "Console authentication is not explicitly secured"
            },
            {
                "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
                "rule-id": "cisco.ios.credentials.local_storage",
                "severity": "High",
                "title": "Local credential uses weak storage"
            },
            {
                "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
                "rule-id": "cisco.ios.credentials.local_storage",
                "severity": "High",
                "title": "Local credential uses weak storage"
            },
            {
                "recommendation": "Replace it with a strong 'enable secret' algorithm and remove the enable password.",
                "rule-id": "cisco.ios.credentials.enable_storage",
                "severity": "High",
                "title": "Enable credential uses weak storage"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 5,
            "Low": 2,
            "Medium": 11
        }
    },
    "security-audit": {
        "2.0.0. SSH VTY access is not source-restricted": {
            "device": "IOS_SWITCH",
            "ease": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "impact": "Any source with network reachability can attempt to access the SSH management service.",
            "observation": "At least one SSH-enabled VTY range lacks an inbound IPv4 or IPv6 access-class.",
            "recommendation": "Apply 'access-class <ACL> in' or 'ipv6 access-class <ACL> in' to every SSH-enabled VTY range.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.vty_access_restriction",
            "severity": "Medium",
            "title": "SSH VTY access is not source-restricted"
        },
        "2.0.1. VTY administrative authorization is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4",
                "authorization exec userAuthorization",
                "login authentication userAuthentication",
                "transport input ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
            "observation": "line vty 0 4 lacks resolved privilege-15 command authorization.",
            "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authorization",
            "severity": "High",
            "title": "VTY administrative authorization is incomplete"
        },
        "2.0.10. NTP authentication is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 74.6.168.73"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '74.6.168.73' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.11. NTP authentication is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 162.248.241.94"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '162.248.241.94' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.12. NTP authentication is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 69.89.207.99"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '69.89.207.99' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.13. NTP authentication is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 68.183.107.237"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '68.183.107.237' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.14. Login warning banner is missing": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No banner login or banner motd command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Users may not receive the organization's required authorized-use and monitoring notice.",
            "observation": "No login or message-of-the-day warning banner is configured.",
            "recommendation": "Configure an approved legal warning with 'banner login'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.banner.login",
            "severity": "Low",
            "title": "Login warning banner is missing"
        },
        "2.0.15. IP source routing is not explicitly disabled": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "no ip source-route absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Source-routed packets can bypass expected routing paths and trust boundaries on applicable releases.",
            "observation": "The configuration does not contain the IOS 'no ip source-route' hardening command.",
            "recommendation": "Configure 'no ip source-route'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ip.source_route",
            "severity": "Medium",
            "title": "IP source routing is not explicitly disabled"
        },
        "2.0.16. Layer-3 interface hardening is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Vlan10",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Vlan10 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.17. Control-plane policing is not attached": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No control-plane service-policy input"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Unrestricted control-plane traffic can contribute to CPU exhaustion and management outages.",
            "observation": "No input service policy is attached under control-plane configuration.",
            "recommendation": "Deploy a validated Control Plane Policing policy appropriate for the platform role.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/quality-of-service/quality-of-service/m_qos-plcshp-ctrl-pln-plc-0.html"
            ],
            "rule_id": "cisco.ios.control_plane.copp",
            "severity": "Medium",
            "title": "Control-plane policing is not attached"
        },
        "2.0.2. Console authentication is not explicitly secured": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line con 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Physical or terminal-server access may reach an unintended authentication path.",
            "observation": "line con 0 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.console.authentication",
            "severity": "High",
            "title": "Console authentication is not explicitly secured"
        },
        "2.0.3. Local credential uses weak storage": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "username oxy secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
            "observation": "User 'oxy' uses 'secret' storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. The credential is redacted.",
            "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.local_storage",
            "severity": "High",
            "title": "Local credential uses weak storage"
        },
        "2.0.4. Local credential uses weak storage": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "username admin secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
            "observation": "User 'admin' uses 'secret' storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. The credential is redacted.",
            "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.local_storage",
            "severity": "High",
            "title": "Local credential uses weak storage"
        },
        "2.0.5. Enable credential uses weak storage": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "enable secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Configuration disclosure can expose or accelerate recovery of the privileged credential.",
            "observation": "The enable credential uses storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. Its value is redacted.",
            "recommendation": "Replace it with a strong 'enable secret' algorithm and remove the enable password.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.enable_storage",
            "severity": "High",
            "title": "Enable credential uses weak storage"
        },
        "2.0.6. Legacy SNMP community configured": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "snmp-server community <redacted> ro"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Community-based SNMP lacks modern per-user authentication and privacy protections.",
            "observation": "An SNMPv1/v2c community uses community-based SNMP, an exact default community. The value is redacted.",
            "recommendation": "Migrate to SNMPv3 authPriv, restrict managers, and remove v1/v2c communities.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.snmp.legacy_community",
            "severity": "Medium",
            "title": "Legacy SNMP community configured"
        },
        "2.0.7. Remote logging severity is insufficient": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "logging host 10.20.0.28"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative and security-relevant informational events may not be centralized.",
            "observation": "The remote logging threshold is 'not configured'.",
            "recommendation": "Configure 'logging trap informational' unless policy explicitly requires a different threshold.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.logging.severity",
            "severity": "Low",
            "title": "Remote logging severity is insufficient"
        },
        "2.0.8. Configuration-change logging is disabled": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "archive log config logging enable absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative changes can lack a local per-user, per-session command history.",
            "observation": "The effective archive log-config state does not enable configuration-change logging.",
            "recommendation": "Enable 'archive / log config / logging enable', suppress keys, and notify syslog.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html"
            ],
            "rule_id": "cisco.ios.configuration.change_logging",
            "severity": "Medium",
            "title": "Configuration-change logging is disabled"
        },
        "2.0.9. NTP authentication is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 97.107.128.165"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '97.107.128.165' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        }
    },
    "vulnerabilities": []
}
```

**RW012-CAT CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng
[2/4] Fetching Cisco API information
[2/4] Cisco API disable.
[3/4] Checking missconfiguration vulnerabilities
[3/4] Scanning configuration file using the following IOS plugins: ['PluginHTTP', 'PluginSSH', 'PluginIOSBaseline']
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW012-CAT.json
```

**RW012-CAT generated JSON report (SHA-256 `561BC3E0165AED0946AB48A3D7A1FBA062239E665DBE590C64A5227186DE53E6`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "IOS_CATALYST",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "IOS running configuration does not provide reliable model metadata",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 10,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoIOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:01:14.994864",
        "device-type": "IOS_CATALYST",
        "hostname": "switch2"
    },
    "remediation-summary": {
        "finding-count": 18,
        "priority-actions": [
            {
                "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
                "rule-id": "cisco.ios.vty.authorization",
                "severity": "High",
                "title": "VTY administrative authorization is incomplete"
            },
            {
                "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
                "rule-id": "cisco.ios.console.authentication",
                "severity": "High",
                "title": "Console authentication is not explicitly secured"
            },
            {
                "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
                "rule-id": "cisco.ios.credentials.local_storage",
                "severity": "High",
                "title": "Local credential uses weak storage"
            },
            {
                "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
                "rule-id": "cisco.ios.credentials.local_storage",
                "severity": "High",
                "title": "Local credential uses weak storage"
            },
            {
                "recommendation": "Replace it with a strong 'enable secret' algorithm and remove the enable password.",
                "rule-id": "cisco.ios.credentials.enable_storage",
                "severity": "High",
                "title": "Enable credential uses weak storage"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 5,
            "Low": 2,
            "Medium": 11
        }
    },
    "security-audit": {
        "2.0.0. SSH VTY access is not source-restricted": {
            "device": "IOS_CATALYST",
            "ease": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "impact": "Any source with network reachability can attempt to access the SSH management service.",
            "observation": "At least one SSH-enabled VTY range lacks an inbound IPv4 or IPv6 access-class.",
            "recommendation": "Apply 'access-class <ACL> in' or 'ipv6 access-class <ACL> in' to every SSH-enabled VTY range.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.vty_access_restriction",
            "severity": "Medium",
            "title": "SSH VTY access is not source-restricted"
        },
        "2.0.1. VTY administrative authorization is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4",
                "authorization exec userAuthorization",
                "login authentication userAuthentication",
                "transport input ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
            "observation": "line vty 0 4 lacks resolved privilege-15 command authorization.",
            "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authorization",
            "severity": "High",
            "title": "VTY administrative authorization is incomplete"
        },
        "2.0.10. NTP authentication is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 74.6.168.73"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '74.6.168.73' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.11. NTP authentication is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 162.248.241.94"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '162.248.241.94' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.12. NTP authentication is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 69.89.207.99"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '69.89.207.99' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.13. NTP authentication is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 68.183.107.237"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '68.183.107.237' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.14. Login warning banner is missing": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No banner login or banner motd command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Users may not receive the organization's required authorized-use and monitoring notice.",
            "observation": "No login or message-of-the-day warning banner is configured.",
            "recommendation": "Configure an approved legal warning with 'banner login'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.banner.login",
            "severity": "Low",
            "title": "Login warning banner is missing"
        },
        "2.0.15. IP source routing is not explicitly disabled": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "no ip source-route absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Source-routed packets can bypass expected routing paths and trust boundaries on applicable releases.",
            "observation": "The configuration does not contain the IOS 'no ip source-route' hardening command.",
            "recommendation": "Configure 'no ip source-route'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ip.source_route",
            "severity": "Medium",
            "title": "IP source routing is not explicitly disabled"
        },
        "2.0.16. Layer-3 interface hardening is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Vlan10",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Vlan10 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.17. Control-plane policing is not attached": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No control-plane service-policy input"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Unrestricted control-plane traffic can contribute to CPU exhaustion and management outages.",
            "observation": "No input service policy is attached under control-plane configuration.",
            "recommendation": "Deploy a validated Control Plane Policing policy appropriate for the platform role.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/quality-of-service/quality-of-service/m_qos-plcshp-ctrl-pln-plc-0.html"
            ],
            "rule_id": "cisco.ios.control_plane.copp",
            "severity": "Medium",
            "title": "Control-plane policing is not attached"
        },
        "2.0.2. Console authentication is not explicitly secured": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line con 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Physical or terminal-server access may reach an unintended authentication path.",
            "observation": "line con 0 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.console.authentication",
            "severity": "High",
            "title": "Console authentication is not explicitly secured"
        },
        "2.0.3. Local credential uses weak storage": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "username oxy secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
            "observation": "User 'oxy' uses 'secret' storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. The credential is redacted.",
            "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.local_storage",
            "severity": "High",
            "title": "Local credential uses weak storage"
        },
        "2.0.4. Local credential uses weak storage": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "username admin secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
            "observation": "User 'admin' uses 'secret' storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. The credential is redacted.",
            "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.local_storage",
            "severity": "High",
            "title": "Local credential uses weak storage"
        },
        "2.0.5. Enable credential uses weak storage": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "enable secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Configuration disclosure can expose or accelerate recovery of the privileged credential.",
            "observation": "The enable credential uses storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. Its value is redacted.",
            "recommendation": "Replace it with a strong 'enable secret' algorithm and remove the enable password.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.enable_storage",
            "severity": "High",
            "title": "Enable credential uses weak storage"
        },
        "2.0.6. Legacy SNMP community configured": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "snmp-server community <redacted> ro"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Community-based SNMP lacks modern per-user authentication and privacy protections.",
            "observation": "An SNMPv1/v2c community uses community-based SNMP, an exact default community. The value is redacted.",
            "recommendation": "Migrate to SNMPv3 authPriv, restrict managers, and remove v1/v2c communities.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.snmp.legacy_community",
            "severity": "Medium",
            "title": "Legacy SNMP community configured"
        },
        "2.0.7. Remote logging severity is insufficient": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "logging host 10.20.0.28"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative and security-relevant informational events may not be centralized.",
            "observation": "The remote logging threshold is 'not configured'.",
            "recommendation": "Configure 'logging trap informational' unless policy explicitly requires a different threshold.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.logging.severity",
            "severity": "Low",
            "title": "Remote logging severity is insufficient"
        },
        "2.0.8. Configuration-change logging is disabled": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "archive log config logging enable absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative changes can lack a local per-user, per-session command history.",
            "observation": "The effective archive log-config state does not enable configuration-change logging.",
            "recommendation": "Enable 'archive / log config / logging enable', suppress keys, and notify syslog.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html"
            ],
            "rule_id": "cisco.ios.configuration.change_logging",
            "severity": "Medium",
            "title": "Configuration-change logging is disabled"
        },
        "2.0.9. NTP authentication is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 97.107.128.165"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '97.107.128.165' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: legacy SNMP, weak type-5 local/enable hash storage, and unauthenticated NTP; both IOS_SWITCH and IOS_CATALYST runs agree.
- Detected but degraded: public is treated only as a Medium legacy community, whereas HP and PIX reports explicitly identify the known default at High. The plain RADIUS shared key is not distinguished from protected storage.
- Missed entirely: exposed unencrypted RADIUS shared-key storage and the known weak public community value as a distinct risk. SSH-only/disabled VTY lines, disabled HTTP and configured remote log were correctly left without absence findings.
- False positives: remote logging severity is judged insufficient without a site threshold; source has a logging host, so this is not a missing-host error.
- Crashes/failures: none.

<a id="RW-013"></a>
### JUNOS — Published Ansible EVPN spine candidate configuration

**Provenance:** [JNPRAutomate spine-01 configuration](https://github.com/JNPRAutomate/ansible-junos-evpn-vxlan/blob/master/config/spine-01.conf); raw SHA-256 `5D31BAAF619E3F5C4C3067BECD0341AF6011A41ED7BBF964545F944F5A3432A0`. Generated candidate includes an unresolved `<subnet mask>` placeholder and at least one apparent missing semicolon; it is **not** a verified committed Junos export.

**Ground truth, before scan:** `snmp community public` with read-only authorization is explicitly present. SSH and NETCONF-over-SSH are enabled and an NTP server and login banner are configured. These explicit positives can be checked; missing statements cannot establish deployed deficiencies in a non-committable candidate. The community value is known/default if this candidate were applied.

**Tool output (actual, unedited):**

**RW013-JUNOS CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Juniper JunOS)
[2/4] Fetching JunOS API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW013-JUNOS.json
```

**RW013-JUNOS generated JSON report (SHA-256 `445AAB9F18844C65AC83B39A18CDF6230337D0AD3888C75520445DB37796F6F4`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "JUNOS",
        "diagnostics": [
            "line 50: missing semicolon before closing brace"
        ],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "line 50: missing semicolon before closing brace",
                "knowledge-state": "parse_error",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "line 50: missing semicolon before closing brace",
                "knowledge-state": "parse_error",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "line 50: missing semicolon before closing brace",
                "knowledge-state": "parse_error",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "detail": "line 50: missing semicolon before closing brace",
                "item-count": null,
                "knowledge-state": "parse_error",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "detail": "line 50: missing semicolon before closing brace",
                "item-count": null,
                "knowledge-state": "parse_error",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "detail": "line 50: missing semicolon before closing brace",
                "item-count": null,
                "knowledge-state": "parse_error",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "detail": "line 50: missing semicolon before closing brace",
                "item-count": null,
                "knowledge-state": "parse_error",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "detail": "line 50: missing semicolon before closing brace",
                "item-count": null,
                "knowledge-state": "parse_error",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "detail": "line 50: missing semicolon before closing brace",
                "item-count": null,
                "knowledge-state": "parse_error",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "JunOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 17:45:47.232555",
        "device-type": "JUNOS",
        "hostname": "junos-device"
    },
    "remediation-summary": {
        "finding-count": 0,
        "priority-actions": [],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {}
    },
    "security-audit": {},
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: none; no security checks ran because the candidate has a syntax error.
- Detected but degraded: none.
- Missed entirely: not assessable; the public file has a missing semicolon at line 50 and an unresolved subnet-mask placeholder.
- False positives: none. Coverage reports parse_error for every field and includes the line-50 diagnostic; zero findings are not represented as a clean bill of health.
- Crashes/failures: no crash; graceful parse-error report.

<a id="RW-014"></a>
### JUNOS — Microsoft Azure SRX 12.1 show-configuration sample

**Provenance:** [Azure SRX show configuration](https://github.com/Azure/Azure-vpn-config-samples/blob/master/Juniper/Current/SRX/juniper-srx-junos_12.1_show_configuration.txt), raw SHA-256 `AB9A15388A6424330AF0D375699914B4C2A657D381AA1881121ADACA6F68F353`; published sanitized sample, not a production asset.

**Ground truth (established before running the tool):** `system services telnet` and `web-management http` are explicitly enabled, and the Internal zone grants `ssh` and `telnet` host-inbound access. That creates cleartext administrative paths on the permitted interface, though reachability from outside the zone is not claimed. The web-management idle timeout is 60 minutes, long for administration. The bound Azure IKE proposal uses SHA-1 and the tunnel uses a preshared key, but the full cryptographic security judgment depends on peer/platform release; no password strength claim is made from the encoded sample value.

**Tool output (actual, unedited):**

**RW014-JUNOS CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Juniper JunOS)
[2/4] Fetching JunOS API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW014-JUNOS.json
```

**RW014-JUNOS generated JSON report (SHA-256 `C7C36356CB5578EB22E49E2F8CEBA937E4B45A818946FBEBC8C70900CDC11671`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "JUNOS",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Model metadata is not present",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Version metadata is not present",
                "knowledge-state": "unknown",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 4,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 10,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 3,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 5,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "JunOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:01:11.216643",
        "device-type": "JUNOS",
        "hostname": "Azure_SRX"
    },
    "remediation-summary": {
        "finding-count": 7,
        "priority-actions": [
            {
                "recommendation": "Replace wildcard address and application matches with explicitly required objects and applications, preserving an ordered terminal deny policy.",
                "rule-id": "juniper.junos.policy.broad_permit",
                "severity": "Critical",
                "title": "Broad SRX security policy permits all traffic"
            },
            {
                "recommendation": "Delete system services telnet and use SSH or HTTPS with source restrictions.",
                "rule-id": "juniper.junos.management.insecure_protocol",
                "severity": "High",
                "title": "Insecure Management Service Enabled"
            },
            {
                "recommendation": "Delete system services http and use SSH or HTTPS with source restrictions.",
                "rule-id": "juniper.junos.management.insecure_protocol",
                "severity": "High",
                "title": "Insecure Management Service Enabled"
            },
            {
                "recommendation": "Use AES or an approved AEAD mode, SHA-256 or stronger integrity, and DH group 14 or an approved stronger group on both peers.",
                "rule-id": "juniper.junos.vpn.weak_proposal",
                "severity": "High",
                "title": "Attached SRX IPsec VPN permits weak cryptography"
            },
            {
                "recommendation": "Replace application any with the smallest required custom or predefined applications.",
                "rule-id": "juniper.junos.policy.broad_application",
                "severity": "Medium",
                "title": "SRX security policy is unrestricted by application"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "Critical": 1,
            "High": 3,
            "Low": 1,
            "Medium": 2
        }
    },
    "security-audit": {
        "10.0.0. Insecure Management Service Enabled": {
            "device": "JUNOS",
            "ease": "An attacker on the management traffic path may intercept credentials or sessions.",
            "evidence": [
                "set system services telnet",
                "set security zones security-zone Internal interfaces vlan.1 host-inbound-traffic system-services telnet"
            ],
            "exploitability": "An attacker on the management traffic path may intercept credentials or sessions.",
            "impact": "The management protocol does not provide adequate transport confidentiality.",
            "observation": "The effective Junos configuration enables TELNET management; HTTPS-only configuration does not trigger this rule.",
            "recommendation": "Delete system services telnet and use SSH or HTTPS with source restrictions.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-software-remote-access-overview.html"
            ],
            "rule_id": "juniper.junos.management.insecure_protocol",
            "severity": "High",
            "title": "Insecure Management Service Enabled"
        },
        "10.0.1. Insecure Management Service Enabled": {
            "device": "JUNOS",
            "ease": "An attacker on the management traffic path may intercept credentials or sessions.",
            "evidence": [
                "set system services web-management http interface vlan.1",
                "set security zones security-zone Internal interfaces vlan.1 host-inbound-traffic system-services http"
            ],
            "exploitability": "An attacker on the management traffic path may intercept credentials or sessions.",
            "impact": "The management protocol does not provide adequate transport confidentiality.",
            "observation": "The effective Junos configuration enables HTTP management; HTTPS-only configuration does not trigger this rule.",
            "recommendation": "Delete system services http and use SSH or HTTPS with source restrictions.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-software-remote-access-overview.html"
            ],
            "rule_id": "juniper.junos.management.insecure_protocol",
            "severity": "High",
            "title": "Insecure Management Service Enabled"
        },
        "10.0.2. Broad SRX security policy permits all traffic": {
            "device": "JUNOS",
            "ease": "Any source entering the source zone can attempt any application toward any destination in the destination zone allowed by routing and surrounding controls.",
            "evidence": [
                "set security policies from-zone Internal to-zone Internet policy All_Internal_Internet match source-address any",
                "set security policies from-zone Internal to-zone Internet policy All_Internal_Internet match destination-address any",
                "set security policies from-zone Internal to-zone Internet policy All_Internal_Internet match application any",
                "set security policies from-zone Internal to-zone Internet policy All_Internal_Internet then permit"
            ],
            "exploitability": "Any source entering the source zone can attempt any application toward any destination in the destination zone allowed by routing and surrounding controls.",
            "impact": "The stateful policy does not restrict hosts or applications within its zone-pair scope.",
            "observation": "Active policy 'All_Internal_Internet' at position 1 from zone 'Internal' to 'Internet' permits wildcard sources, wildcard destinations, and any.",
            "recommendation": "Replace wildcard address and application matches with explicitly required objects and applications, preserving an ordered terminal deny policy.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html"
            ],
            "rule_id": "juniper.junos.policy.broad_permit",
            "severity": "Critical",
            "title": "Broad SRX security policy permits all traffic"
        },
        "10.0.3. SRX security policy is unrestricted by application": {
            "device": "JUNOS",
            "ease": "A source matching the address scope can attempt any application reachable in the destination zone.",
            "evidence": [
                "set security policies from-zone Internal to-zone Internet policy azure-security-Internal-to-Internet-0 match source-address onprem-networks-1",
                "set security policies from-zone Internal to-zone Internet policy azure-security-Internal-to-Internet-0 match destination-address azure-networks-1",
                "set security policies from-zone Internal to-zone Internet policy azure-security-Internal-to-Internet-0 match application any",
                "set security policies from-zone Internal to-zone Internet policy azure-security-Internal-to-Internet-0 then permit"
            ],
            "exploitability": "A source matching the address scope can attempt any application reachable in the destination zone.",
            "impact": "Unnecessary protocols and destination ports can cross the zone boundary.",
            "observation": "Active policy 'azure-security-Internal-to-Internet-0' at position 2 from zone 'Internal' to 'Internet' permits any application within its address scope.",
            "recommendation": "Replace application any with the smallest required custom or predefined applications.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-reordering-policies.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-address-books-sets.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/policy-application-sets-configuration.html"
            ],
            "rule_id": "juniper.junos.policy.broad_application",
            "severity": "Medium",
            "title": "SRX security policy is unrestricted by application"
        },
        "10.0.4. SRX security policy is redundant": {
            "device": "JUNOS",
            "ease": "A conflicting shadowed policy can give reviewers a false impression of enforced zone access control.",
            "evidence": [
                "set security policies from-zone Internal to-zone Internet policy azure-security-Internal-to-Internet-0 match source-address onprem-networks-1",
                "set security policies from-zone Internal to-zone Internet policy azure-security-Internal-to-Internet-0 match destination-address azure-networks-1",
                "set security policies from-zone Internal to-zone Internet policy azure-security-Internal-to-Internet-0 match application any",
                "set security policies from-zone Internal to-zone Internet policy azure-security-Internal-to-Internet-0 then permit",
                "set security policies from-zone Internal to-zone Internet policy All_Internal_Internet match source-address any",
                "set security policies from-zone Internal to-zone Internet policy All_Internal_Internet match destination-address any",
                "set security policies from-zone Internal to-zone Internet policy All_Internal_Internet match application any",
                "set security policies from-zone Internal to-zone Internet policy All_Internal_Internet then permit"
            ],
            "exploitability": "A conflicting shadowed policy can give reviewers a false impression of enforced zone access control.",
            "impact": "The later policy cannot alter first-match enforcement for the statically proven traffic scope and obscures policy intent.",
            "observation": "Policy 'azure-security-Internal-to-Internet-0' at position 2 in zone pair 'Internal' to 'Internet' is fully covered by earlier policy 'All_Internal_Internet' at position 1 with equivalent behavior.",
            "recommendation": "Remove or reorder the policy after validating address-book, application, logging, tunnel and operational intent.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-reordering-policies.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-address-books-sets.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/policy-application-sets-configuration.html"
            ],
            "rule_id": "juniper.junos.policy.redundant_rule",
            "severity": "Low",
            "title": "SRX security policy is redundant"
        },
        "10.0.5. SRX security policy is unrestricted by application": {
            "device": "JUNOS",
            "ease": "A source matching the address scope can attempt any application reachable in the destination zone.",
            "evidence": [
                "set security policies from-zone Internet to-zone Internal policy azure-security-Internet-to-Internal-0 match source-address azure-networks-1",
                "set security policies from-zone Internet to-zone Internal policy azure-security-Internet-to-Internal-0 match destination-address onprem-networks-1",
                "set security policies from-zone Internet to-zone Internal policy azure-security-Internet-to-Internal-0 match application any",
                "set security policies from-zone Internet to-zone Internal policy azure-security-Internet-to-Internal-0 then permit"
            ],
            "exploitability": "A source matching the address scope can attempt any application reachable in the destination zone.",
            "impact": "Unnecessary protocols and destination ports can cross the zone boundary.",
            "observation": "Active policy 'azure-security-Internet-to-Internal-0' at position 1 from zone 'Internet' to 'Internal' permits any application within its address scope.",
            "recommendation": "Replace application any with the smallest required custom or predefined applications.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-reordering-policies.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-address-books-sets.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/policy-application-sets-configuration.html"
            ],
            "rule_id": "juniper.junos.policy.broad_application",
            "severity": "Medium",
            "title": "SRX security policy is unrestricted by application"
        },
        "10.0.6. Attached SRX IPsec VPN permits weak cryptography": {
            "device": "JUNOS",
            "ease": "An attacker capable of recording or interfering with tunnel negotiation or ciphertext may benefit from the explicitly permitted legacy transforms.",
            "evidence": [
                "set security ipsec vpn azure-ipsec-vpn bind-interface st0.0",
                "set security ipsec vpn azure-ipsec-vpn ike gateway azure-gateway",
                "set security ipsec vpn azure-ipsec-vpn ike ipsec-policy azure-vpn-policy",
                "set security ike gateway azure-gateway ike-policy azure-policy",
                "set security ike gateway azure-gateway address 40.X.X.X",
                "set security ike gateway azure-gateway external-interface fe-0/0/0.0",
                "set security ike gateway azure-gateway version v2-only",
                "set security ike policy azure-policy mode main",
                "set security ike policy azure-policy proposals azure-proposal",
                "set security ike policy azure-policy pre-shared-key <redacted> <redacted>",
                "set security ipsec policy azure-vpn-policy proposals azure-ipsec-proposal",
                "set security ike proposal azure-proposal authentication-method pre-shared-keys",
                "set security ike proposal azure-proposal dh-group group2",
                "set security ike proposal azure-proposal authentication-algorithm sha1",
                "set security ike proposal azure-proposal encryption-algorithm aes-256-cbc",
                "set security ike proposal azure-proposal lifetime-seconds 28800",
                "set security ipsec proposal azure-ipsec-proposal protocol esp",
                "set security ipsec proposal azure-ipsec-proposal authentication-algorithm hmac-sha1-96",
                "set security ipsec proposal azure-ipsec-proposal encryption-algorithm aes-256-cbc",
                "set security ipsec proposal azure-ipsec-proposal lifetime-seconds 27000"
            ],
            "exploitability": "An attacker capable of recording or interfering with tunnel negotiation or ciphertext may benefit from the explicitly permitted legacy transforms.",
            "impact": "Legacy encryption, integrity algorithms, or small Diffie-Hellman groups weaken the confidentiality and integrity of the VPN.",
            "observation": "Active VPN 'azure-ipsec-vpn' resolves to authentication hmac-sha1-96, sha1; DH/PFS group2.",
            "recommendation": "Use AES or an approved AEAD mode, SHA-256 or stronger integrity, and DH group 14 or an approved stronger group on both peers.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/vpn-ipsec/topics/topic-map/security-ipsec-vpn-configuration-overview.html",
                "https://www.rfc-editor.org/rfc/rfc8247.html"
            ],
            "rule_id": "juniper.junos.vpn.weak_proposal",
            "severity": "High",
            "title": "Attached SRX IPsec VPN permits weak cryptography"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: Telnet and HTTP management, with evidence tying services to a host-inbound zone grant; the attached VPN's weak proposal is also identified.
- Detected but degraded: a Critical broad permit is an Internal-to-Internet egress rule, whose risk depends on intended policy. The redundant-rule finding is static proof about rule order, not observed usage.
- Missed entirely: 60-minute web-management idle timeout; no site threshold was supplied, so this is a conditional timeout-policy gap.
- False positives: no definite one from this complete, sanitized sample.
- Crashes/failures: none.

<a id="RW-015"></a>
### JUNOS — Public SRX240H home/office dual-stack configuration

**Provenance:** [SRX240H dual-stack configuration](https://gist.github.com/jflemer/029636c4535bbf6f045b85fd25ab9154), gist raw revision `e9d9119badc045cb34baa7f1805973ef9c995cc6`; SHA-256 `2ADD22300C0438B719896FDECF9DB617F7C57C411D3E4AF9D8102EE77E43491C`. Commented placeholders mean the file is a shared candidate, not verified running state.

**Ground truth (established before running the tool):** The configured administrator class has a 30-minute idle timeout. The SSH key-exchange list includes `group-exchange-sha1`; if that proposal is accepted by the target release, the SSH service still offers a SHA-1 exchange alongside stronger options. Three NTP servers have no association authentication in the supplied text, but site policy and platform support are unverified. The explicit `root-login deny` and SSH v2 are negative controls, not vulnerabilities. Commented authentication values cannot be assessed as live secrets.

**Tool output (actual, unedited):**

**RW015-JUNOS CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Juniper JunOS)
[2/4] Fetching JunOS API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW015-JUNOS.json
```

**RW015-JUNOS generated JSON report (SHA-256 `FFFFD741C3C3B51A6E30402F3D071E3FED884AAD0BFE272278CD3203FF513CC8`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "JUNOS",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Model metadata is not present",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 5,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 19,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 7,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "JunOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:01:11.538673",
        "device-type": "JUNOS",
        "hostname": "srx"
    },
    "remediation-summary": {
        "finding-count": 17,
        "priority-actions": [
            {
                "recommendation": "Add explicit source, destination, and protocol matches before accepting traffic.",
                "rule-id": "juniper.junos.filter.broad_accept",
                "severity": "Critical",
                "title": "Broad Firewall Filter"
            },
            {
                "recommendation": "Remove the weak ciphers values and retain only algorithms approved by organizational policy.",
                "rule-id": "juniper.junos.ssh.weak_ciphers",
                "severity": "High",
                "title": "Weak SSH ciphers explicitly enabled"
            },
            {
                "recommendation": "Remove the weak key-exchange values and retain only algorithms approved by organizational policy.",
                "rule-id": "juniper.junos.ssh.weak_key_exchange",
                "severity": "High",
                "title": "Weak SSH key exchange explicitly enabled"
            },
            {
                "recommendation": "Replace application any with the smallest required custom or predefined applications.",
                "rule-id": "juniper.junos.policy.broad_application",
                "severity": "Medium",
                "title": "SRX security policy is unrestricted by application"
            },
            {
                "recommendation": "Replace application any with the smallest required custom or predefined applications.",
                "rule-id": "juniper.junos.policy.broad_application",
                "severity": "Medium",
                "title": "SRX security policy is unrestricted by application"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "Critical": 1,
            "High": 2,
            "Low": 1,
            "Medium": 13
        }
    },
    "security-audit": {
        "10.0.0. Broad Firewall Filter": {
            "device": "JUNOS",
            "ease": "Any source can reach any destination and protocol within the attached filter scope.",
            "evidence": [
                "set firewall filter RE-PROTECT term ACCEPT then count ACCEPT-COUNT",
                "set firewall filter RE-PROTECT term ACCEPT then accept"
            ],
            "exploitability": "Any source can reach any destination and protocol within the attached filter scope.",
            "impact": "The term permits unrestricted traffic through every interface direction where the filter is attached.",
            "observation": "Attached inet filter 'RE-PROTECT' term 'ACCEPT' accepts all sources, destinations, and protocols at position 3; attachments: lo0:input.",
            "recommendation": "Add explicit source, destination, and protocol matches before accepting traffic.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/example/permitted-ip-configuring.html"
            ],
            "rule_id": "juniper.junos.filter.broad_accept",
            "severity": "Critical",
            "title": "Broad Firewall Filter"
        },
        "10.0.1. SRX security policy is unrestricted by application": {
            "device": "JUNOS",
            "ease": "A source matching the address scope can attempt any application reachable in the destination zone.",
            "evidence": [
                "set security policies from-zone trust to-zone untrust policy INTERNET match source-address NET-TRUST",
                "set security policies from-zone trust to-zone untrust policy INTERNET match destination-address any",
                "set security policies from-zone trust to-zone untrust policy INTERNET match application any",
                "set security policies from-zone trust to-zone untrust policy INTERNET then permit"
            ],
            "exploitability": "A source matching the address scope can attempt any application reachable in the destination zone.",
            "impact": "Unnecessary protocols and destination ports can cross the zone boundary.",
            "observation": "Active policy 'INTERNET' at position 4 from zone 'trust' to 'untrust' permits any application within its address scope.",
            "recommendation": "Replace application any with the smallest required custom or predefined applications.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-reordering-policies.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-address-books-sets.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/policy-application-sets-configuration.html"
            ],
            "rule_id": "juniper.junos.policy.broad_application",
            "severity": "Medium",
            "title": "SRX security policy is unrestricted by application"
        },
        "10.0.2. SRX security policy is unrestricted by application": {
            "device": "JUNOS",
            "ease": "A source matching the address scope can attempt any application reachable in the destination zone.",
            "evidence": [
                "set security policies from-zone GUEST to-zone untrust policy OTHER match source-address NET-GUEST",
                "set security policies from-zone GUEST to-zone untrust policy OTHER match destination-address any",
                "set security policies from-zone GUEST to-zone untrust policy OTHER match application any",
                "set security policies from-zone GUEST to-zone untrust policy OTHER then permit",
                "set security policies from-zone GUEST to-zone untrust policy OTHER then log session-init",
                "set security policies from-zone GUEST to-zone untrust policy OTHER then count"
            ],
            "exploitability": "A source matching the address scope can attempt any application reachable in the destination zone.",
            "impact": "Unnecessary protocols and destination ports can cross the zone boundary.",
            "observation": "Active policy 'OTHER' at position 3 from zone 'GUEST' to 'untrust' permits any application within its address scope.",
            "recommendation": "Replace application any with the smallest required custom or predefined applications.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-reordering-policies.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-address-books-sets.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/policy-application-sets-configuration.html"
            ],
            "rule_id": "juniper.junos.policy.broad_application",
            "severity": "Medium",
            "title": "SRX security policy is unrestricted by application"
        },
        "10.0.3. SRX security policy is unrestricted by application": {
            "device": "JUNOS",
            "ease": "A source matching the address scope can attempt any application reachable in the destination zone.",
            "evidence": [
                "set security policies from-zone untrust to-zone LOOPBACK policy VPN-TO-LOOPBACK match source-address NET-DYNAMIC-VPN",
                "set security policies from-zone untrust to-zone LOOPBACK policy VPN-TO-LOOPBACK match destination-address any",
                "set security policies from-zone untrust to-zone LOOPBACK policy VPN-TO-LOOPBACK match application any",
                "set security policies from-zone untrust to-zone LOOPBACK policy VPN-TO-LOOPBACK then permit",
                "set security policies from-zone untrust to-zone LOOPBACK policy VPN-TO-LOOPBACK then log session-init",
                "set security policies from-zone untrust to-zone LOOPBACK policy VPN-TO-LOOPBACK then count"
            ],
            "exploitability": "A source matching the address scope can attempt any application reachable in the destination zone.",
            "impact": "Unnecessary protocols and destination ports can cross the zone boundary.",
            "observation": "Active policy 'VPN-TO-LOOPBACK' at position 1 from zone 'untrust' to 'LOOPBACK' permits any application within its address scope.",
            "recommendation": "Replace application any with the smallest required custom or predefined applications.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-reordering-policies.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-address-books-sets.html",
                "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/policy-application-sets-configuration.html"
            ],
            "rule_id": "juniper.junos.policy.broad_application",
            "severity": "Medium",
            "title": "SRX security policy is unrestricted by application"
        },
        "10.1.0. Weak SSH ciphers explicitly enabled": {
            "device": "JUNOS",
            "ease": "An attacker with management-plane reachability may exploit the effective weakness.",
            "evidence": [
                "set system services ssh ciphers aes256-ctr aes256-cbc"
            ],
            "exploitability": "An attacker with management-plane reachability may exploit the effective weakness.",
            "impact": "Legacy SSH algorithms weaken confidentiality, integrity, or server authentication.",
            "observation": "The effective SSH ciphers list includes: aes256-cbc.",
            "recommendation": "Remove the weak ciphers values and retain only algorithms approved by organizational policy.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/ssh-edit-system.html"
            ],
            "rule_id": "juniper.junos.ssh.weak_ciphers",
            "severity": "High",
            "title": "Weak SSH ciphers explicitly enabled"
        },
        "10.1.1. Weak SSH key exchange explicitly enabled": {
            "device": "JUNOS",
            "ease": "An attacker with management-plane reachability may exploit the effective weakness.",
            "evidence": [
                "set system services ssh key-exchange dh-group14-sha1 ecdh-sha2-nistp256 ecdh-sha2-nistp384 group-exchange-sha2 group-exchange-sha1"
            ],
            "exploitability": "An attacker with management-plane reachability may exploit the effective weakness.",
            "impact": "Legacy SSH algorithms weaken confidentiality, integrity, or server authentication.",
            "observation": "The effective SSH key-exchange list includes: dh-group14-sha1, group-exchange-sha1.",
            "recommendation": "Remove the weak key-exchange values and retain only algorithms approved by organizational policy.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/ssh-edit-system.html"
            ],
            "rule_id": "juniper.junos.ssh.weak_key_exchange",
            "severity": "High",
            "title": "Weak SSH key exchange explicitly enabled"
        },
        "10.1.10. NTP authentication is incomplete": {
            "device": "JUNOS",
            "ease": "An attacker with management-plane reachability may exploit the effective weakness.",
            "evidence": [
                "set system ntp server 1.pool.ntp.org version 4"
            ],
            "exploitability": "An attacker with management-plane reachability may exploit the effective weakness.",
            "impact": "A spoofed time source can disrupt logs and time-sensitive security behavior.",
            "observation": "NTP server '1.pool.ntp.org' has no key binding.",
            "recommendation": "Configure authentication-key and trusted-key, then bind this association to the trusted key ID.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/time-mgmt/topics/concept/ntp-authentication-keys.html"
            ],
            "rule_id": "juniper.junos.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "10.1.11. NTP authentication is incomplete": {
            "device": "JUNOS",
            "ease": "An attacker with management-plane reachability may exploit the effective weakness.",
            "evidence": [
                "set system ntp server 2.pool.ntp.org version 4"
            ],
            "exploitability": "An attacker with management-plane reachability may exploit the effective weakness.",
            "impact": "A spoofed time source can disrupt logs and time-sensitive security behavior.",
            "observation": "NTP server '2.pool.ntp.org' has no key binding.",
            "recommendation": "Configure authentication-key and trusted-key, then bind this association to the trusted key ID.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/time-mgmt/topics/concept/ntp-authentication-keys.html"
            ],
            "rule_id": "juniper.junos.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "10.1.12. IPv4 redirects are not explicitly disabled": {
            "device": "JUNOS",
            "ease": "An attacker with management-plane reachability may exploit the effective weakness.",
            "evidence": [
                "system no-redirects absent"
            ],
            "exploitability": "An attacker with management-plane reachability may exploit the effective weakness.",
            "impact": "Protocol redirects can alter host forwarding decisions on applicable platforms.",
            "observation": "The effective configuration lacks system no-redirects.",
            "recommendation": "Configure system no-redirects, or document the platform-specific condition that makes it inapplicable.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/no-redirects-edit-system.html"
            ],
            "rule_id": "juniper.junos.interfaces.redirects",
            "severity": "Low",
            "title": "IPv4 redirects are not explicitly disabled"
        },
        "10.1.2. Centralized administrator authentication is not configured": {
            "device": "JUNOS",
            "ease": "An attacker with management-plane reachability may exploit the effective weakness.",
            "evidence": [
                "set system authentication-order password"
            ],
            "exploitability": "An attacker with management-plane reachability may exploit the effective weakness.",
            "impact": "Local-only authentication reduces centralized access control and accountability.",
            "observation": "The effective authentication order uses only local passwords or the local-password default.",
            "recommendation": "Configure RADIUS or TACACS+ first in authentication-order and retain a tested local fallback according to policy.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-os-authentication-order.html"
            ],
            "rule_id": "juniper.junos.authentication.centralized",
            "severity": "Medium",
            "title": "Centralized administrator authentication is not configured"
        },
        "10.1.3. Administrative account lockout is not configured": {
            "device": "JUNOS",
            "ease": "An attacker with management-plane reachability may exploit the effective weakness.",
            "evidence": [
                "system login retry-options lockout-period absent"
            ],
            "exploitability": "An attacker with management-plane reachability may exploit the effective weakness.",
            "impact": "Repeated password guessing is not interrupted by a timed account lockout.",
            "observation": "No effective login retry-options lockout-period is configured.",
            "recommendation": "Configure a policy-approved lockout-period and test the recovery procedure.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-os-login-settings.html"
            ],
            "rule_id": "juniper.junos.authentication.lockout",
            "severity": "Medium",
            "title": "Administrative account lockout is not configured"
        },
        "10.1.4. Pre-authentication login message is missing": {
            "device": "JUNOS",
            "ease": "An attacker with management-plane reachability may exploit the effective weakness.",
            "evidence": [
                "system login message absent"
            ],
            "exploitability": "An attacker with management-plane reachability may exploit the effective weakness.",
            "impact": "Users are not shown an approved access warning before supplying administrative credentials.",
            "observation": "No effective system login message is configured; a post-login announcement does not replace the pre-authentication notice.",
            "recommendation": "Configure an organization-approved system login message and retain announcements only for post-login information.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-os-login-settings.html"
            ],
            "rule_id": "juniper.junos.authentication.login_banner",
            "severity": "Medium",
            "title": "Pre-authentication login message is missing"
        },
        "10.1.5. Administrative login class has no effective idle timeout": {
            "device": "JUNOS",
            "ease": "An attacker with management-plane reachability may exploit the effective weakness.",
            "evidence": [
                "set system login user monitor uid 2333",
                "set system login user monitor class read-only"
            ],
            "exploitability": "An attacker with management-plane reachability may exploit the effective weakness.",
            "impact": "An abandoned authenticated CLI session can remain available indefinitely.",
            "observation": "Login class 'read-only', used by monitor, is not configured, so the documented default does not force idle logout.",
            "recommendation": "Apply a policy-approved nonzero idle-timeout through the user-defined class or supported global login setting.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-os-login-settings.html",
                "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/class-edit-system-login.html"
            ],
            "rule_id": "juniper.junos.authentication.idle_timeout",
            "severity": "Medium",
            "title": "Administrative login class has no effective idle timeout"
        },
        "10.1.6. J-Web concurrent sessions are not bounded": {
            "device": "JUNOS",
            "ease": "An attacker with management-plane reachability may exploit the effective weakness.",
            "evidence": [
                "set system services web-management https interface lo0.0 vlan.1 ge-0/0/15.0"
            ],
            "exploitability": "An attacker with management-plane reachability may exploit the effective weakness.",
            "impact": "Unbounded authenticated sessions can increase management-plane resource pressure and account-sharing exposure.",
            "observation": "J-Web is enabled without an explicit session-limit; the documented default permits an unlimited number of concurrent sessions.",
            "recommendation": "Configure a finite J-Web session-limit based on the number of authorized administrators.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/session-edit-system.html"
            ],
            "rule_id": "juniper.junos.administration.web_session_limit",
            "severity": "Medium",
            "title": "J-Web concurrent sessions are not bounded"
        },
        "10.1.7. Remote system logging is not configured": {
            "device": "JUNOS",
            "ease": "An attacker with management-plane reachability may exploit the effective weakness.",
            "evidence": [
                "system syslog host absent"
            ],
            "exploitability": "An attacker with management-plane reachability may exploit the effective weakness.",
            "impact": "Locally stored events can be lost during compromise or device failure.",
            "observation": "No effective system syslog host destination is present.",
            "recommendation": "Configure protected remote syslog destinations; use an approved transport on supported releases.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/system-logging.html"
            ],
            "rule_id": "juniper.junos.logging.remote_destination",
            "severity": "Medium",
            "title": "Remote system logging is not configured"
        },
        "10.1.8. Configuration changes lack an audit destination": {
            "device": "JUNOS",
            "ease": "An attacker with management-plane reachability may exploit the effective weakness.",
            "evidence": [
                "configuration change audit destination absent"
            ],
            "exploitability": "An attacker with management-plane reachability may exploit the effective weakness.",
            "impact": "Configuration changes can lack an independent attributable audit trail.",
            "observation": "Neither a resolved system-accounting change-log destination nor an active syslog change-log selector is configured.",
            "recommendation": "Send change-log events to a protected syslog destination or configure resolved RADIUS/TACACS+ system accounting.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/accounting-edit-system.html",
                "https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/system-logging.html"
            ],
            "rule_id": "juniper.junos.configuration.change_audit",
            "severity": "Medium",
            "title": "Configuration changes lack an audit destination"
        },
        "10.1.9. NTP authentication is incomplete": {
            "device": "JUNOS",
            "ease": "An attacker with management-plane reachability may exploit the effective weakness.",
            "evidence": [
                "set system ntp server 0.pool.ntp.org version 4"
            ],
            "exploitability": "An attacker with management-plane reachability may exploit the effective weakness.",
            "impact": "A spoofed time source can disrupt logs and time-sensitive security behavior.",
            "observation": "NTP server '0.pool.ntp.org' has no key binding.",
            "recommendation": "Configure authentication-key and trusted-key, then bind this association to the trusted key ID.",
            "references": [
                "https://www.juniper.net/documentation/us/en/software/junos/time-mgmt/topics/concept/ntp-authentication-keys.html"
            ],
            "rule_id": "juniper.junos.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: SHA-1 SSH key exchange and unauthenticated NTP are identified; root-login deny is not flagged.
- Detected but degraded: the SSH CBC cipher alert and Critical broad filter accept depend on protocol/version and term/attachment context. The class-idle finding points to a separate monitor user, not the administrator class's 30-minute setting.
- Missed entirely: the 30-minute administrator idle timeout if a stricter site policy applies; no policy threshold was supplied, so it is not a definite false negative.
- False positives: none conclusively established. The file is a shared candidate with commented secrets, not verified running state.
- Crashes/failures: none.

<a id="RW-016"></a>
### SCREENOS — Operator-posted Juniper SSG site-to-site VPN configuration

**Provenance:** [Juniper community SSG 5 VPN discussion](https://community.juniper.net/discussion/site-to-site-vpn-with-ssg-5), posted `get config` block extracted by replacing HTML `<br>` breaks; extracted SHA-256 `13793157AE10382C500CAF5EC252F60A4CD96B946022F39BAC2EE70B23456EA3`. The post is a troubleshooting example and may omit context.

**Ground truth (established before running the tool):** Line 104 attaches `no-replay` to the `CVPN` tunnel, disabling IPsec anti-replay per the [archived ScreenOS CLI command description](https://manualzz.com/doc/21898000/juniper-networks-security-device-cli-reference-guide). The same config explicitly `unset ike dos-protection`, a provisional DoS concern. Line 69 makes external ethernet0/0 manageable but grants only ping there in the visible commands; it is **not** treated as proof of external SSH access. A broad Trust-to-Untrust allow is likely intentional outbound access, not by itself a security flaw.

**Tool output (actual, unedited):**

**RW016-SCREEN CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Juniper ScreenOS)
[2/4] Fetching Juniper API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW016-SCREEN.json
```

**RW016-SCREEN generated JSON report (SHA-256 `BE0A7FE7890E595EC4B6707ED347568D5E3939ED602B715C743DC5FAE93879D8`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "SCREENOS",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "ScreenOS hostname is not present",
                "knowledge-state": "unknown",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "ScreenOS model metadata is not present",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "ScreenOS version metadata is not present",
                "knowledge-state": "unknown",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 5,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 3,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "JuniperScreenOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:01:11.789300",
        "device-type": "SCREENOS",
        "hostname": "juniper-device"
    },
    "remediation-summary": {
        "finding-count": 2,
        "priority-actions": [
            {
                "recommendation": "Replace Any source, destination, and service values with explicit objects and enable session logging.",
                "rule-id": "juniper.screenos.policy.broad_permit",
                "severity": "Critical",
                "title": "Broad Policy Rule Detected"
            },
            {
                "recommendation": "Enable appropriate session logging and send the resulting events to a protected remote destination.",
                "rule-id": "juniper.screenos.policy.unlogged_permit",
                "severity": "Medium",
                "title": "High-risk permit policy is not logged"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "Critical": 1,
            "Medium": 1
        }
    },
    "security-audit": {
        "4.0.0. Broad Policy Rule Detected": {
            "device": "SCREENOS",
            "ease": "Any source in the source zone can target any destination and service in the destination zone.",
            "evidence": [
                "set policy id 1 from \"Trust\" to \"Untrust\" \"Any\" \"Any\" \"ANY\" permit",
                "set policy id 1"
            ],
            "exploitability": "Any source in the source zone can target any destination and service in the destination zone.",
            "impact": "The policy allows unrestricted traffic between its source and destination zones.",
            "observation": "Enabled policy ID 1 at position 0 permits Any source, Any destination, and Any service from zone 'Trust' to 'Untrust'; tracking is 'not configured'.",
            "recommendation": "Replace Any source, destination, and service values with explicit objects and enable session logging.",
            "references": [
                "https://www.juniper.net/documentation/product/us/en/screenos/6.3.0/"
            ],
            "rule_id": "juniper.screenos.policy.broad_permit",
            "severity": "Critical",
            "title": "Broad Policy Rule Detected"
        },
        "4.1.0. High-risk permit policy is not logged": {
            "device": "SCREENOS",
            "ease": "An attacker with network reachability or configuration access may exploit this legacy-platform weakness.",
            "evidence": [
                "set policy id 1 from \"Trust\" to \"Untrust\" \"Any\" \"Any\" \"ANY\" permit",
                "set policy id 1"
            ],
            "exploitability": "An attacker with network reachability or configuration access may exploit this legacy-platform weakness.",
            "impact": "Security-relevant permitted traffic may be unavailable for monitoring and incident investigation.",
            "observation": "Enabled policy ID 1 permits traffic from 'Trust' to 'Untrust' without session logging.",
            "recommendation": "Enable appropriate session logging and send the resulting events to a protected remote destination.",
            "references": [
                "https://www.juniper.net/documentation/product/us/en/screenos/6.3.0/"
            ],
            "rule_id": "juniper.screenos.policy.unlogged_permit",
            "severity": "Medium",
            "title": "High-risk permit policy is not logged"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: broad unlogged Trust-to-Untrust permit is reported, but this is normally egress and may be intended.
- Detected but degraded: Critical breadth severity lacks approved egress context.
- Missed entirely: active no-replay on CVPN; IKE DoS protection disabled remains a provisional issue.
- False positives: none definitely proven. The posted line enabling SSH does not make it externally reachable: the Untrust interface exposes only ping in visible management settings.
- Crashes/failures: none.

<a id="RW-017"></a>
### IOS_ROUTER — Captured IOSv 15.6 router `show running-config`

**Provenance:** [Public Ansible network CLI session](https://gist.github.com/privateip/27177caa90005a59219c91bffeeac3d5), actual `stdout` field decoded from the posted JSON-like console record; extracted SHA-256 `13E69EEB34F31C14053572DDC755D1FFDDCC05A19C25811AF5120F67B2EE279C`. This is a CML/IOSv lab appliance, not production.

**Ground truth (established before running the tool):** The capture sets a cleartext `enable password` to the common training value `cisco`. VTY permits both Telnet and SSH, uses a common line password, and sets `exec-timeout 720 0` (12 hours). These are directly observable weak administration choices; although source addresses and lab exposure differ from production, they are real config properties. The full running export also has `no aaa new-model`; no central AAA is configured. The user hashes are not assumed cracked.

**Tool output (actual, unedited):**

**RW017-ROUTER CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng
[2/4] Fetching Cisco API information
[2/4] Cisco API disable.
[3/4] Checking missconfiguration vulnerabilities
[3/4] Scanning configuration file using the following IOS plugins: ['PluginHTTP', 'PluginSSH', 'PluginIOSBaseline']
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW017-ROUTER.json
```

**RW017-ROUTER generated JSON report (SHA-256 `18BB6E17AE0DA0B6A1FE80E1D776E0F1977CC08066651714D28D7BAAED18B62E`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "IOS_ROUTER",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "IOS running configuration does not provide reliable model metadata",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 5,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoIOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:01:12.239804",
        "device-type": "IOS_ROUTER",
        "hostname": "an-ios-01"
    },
    "remediation-summary": {
        "finding-count": 39,
        "priority-actions": [
            {
                "recommendation": "Enforce SSHv2 with 'ip ssh version 2'.",
                "rule-id": "cisco.ios.ssh.protocol_version",
                "severity": "High",
                "title": "SSH protocol version 2 is not enforced"
            },
            {
                "recommendation": "Enable AAA new-model and define a tested local fallback before applying it to management lines.",
                "rule-id": "cisco.ios.aaa.new_model",
                "severity": "High",
                "title": "Centralized AAA is not enabled"
            },
            {
                "recommendation": "Configure 'transport input ssh' on every VTY range.",
                "rule-id": "cisco.ios.vty.telnet",
                "severity": "High",
                "title": "VTY permits clear-text Telnet"
            },
            {
                "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
                "rule-id": "cisco.ios.console.authentication",
                "severity": "High",
                "title": "Console authentication is not explicitly secured"
            },
            {
                "recommendation": "Disable the AUX line using the complete Cisco hardening sequence unless it has an approved operational use.",
                "rule-id": "cisco.ios.auxiliary.enabled",
                "severity": "High",
                "title": "Auxiliary management line is not fully disabled"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 27,
            "Low": 1,
            "Medium": 11
        }
    },
    "security-audit": {
        "2.0.0. SSH protocol version 2 is not enforced": {
            "device": "IOS_ROUTER",
            "ease": "An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            "impact": "SSHv1 has fundamental protocol weaknesses and permits downgrade exposure where compatibility mode is allowed.",
            "observation": "The reachable SSH service uses compatibility mode (SSHv1 and SSHv2).",
            "recommendation": "Enforce SSHv2 with 'ip ssh version 2'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.protocol_version",
            "severity": "High",
            "title": "SSH protocol version 2 is not enforced"
        },
        "2.0.1. SSH negotiation timeout is unsafe": {
            "device": "IOS_ROUTER",
            "ease": "A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            "evidence": [
                "effective documented default: 120"
            ],
            "exploitability": "A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            "impact": "Long unauthenticated negotiations consume management-plane resources and leave sessions open unnecessarily.",
            "observation": "The effective SSH negotiation timeout is 120 seconds; the policy maximum is 60 seconds.",
            "recommendation": "Configure 'ip ssh time-out <1-60>'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.negotiation_timeout",
            "severity": "Low",
            "title": "SSH negotiation timeout is unsafe"
        },
        "2.0.10. Enable credential uses weak storage": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "enable password 0 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Configuration disclosure can expose or accelerate recovery of the privileged credential.",
            "observation": "The enable credential uses storage type '0', classified as 'plaintext' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. Its value is redacted.",
            "recommendation": "Replace it with a strong 'enable secret' algorithm and remove the enable password.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.enable_storage",
            "severity": "High",
            "title": "Enable credential uses weak storage"
        },
        "2.0.11. Remote logging destination is missing": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No logging host command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Events may be lost during compromise or device failure and unavailable to central monitoring.",
            "observation": "No active remote syslog destination is configured.",
            "recommendation": "Configure one or more protected remote logging hosts.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.logging.remote_destination",
            "severity": "Medium",
            "title": "Remote logging destination is missing"
        },
        "2.0.12. Configuration-change logging is disabled": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "archive log config logging enable absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative changes can lack a local per-user, per-session command history.",
            "observation": "The effective archive log-config state does not enable configuration-change logging.",
            "recommendation": "Enable 'archive / log config / logging enable', suppress keys, and notify syslog.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html"
            ],
            "rule_id": "cisco.ios.configuration.change_logging",
            "severity": "Medium",
            "title": "Configuration-change logging is disabled"
        },
        "2.0.13. NTP synchronization is not configured": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No ntp server or peer command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Inaccurate time undermines event correlation, certificates, and forensic timelines.",
            "observation": "No NTP server or peer is configured.",
            "recommendation": "Configure multiple trusted NTP servers.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.servers",
            "severity": "Medium",
            "title": "NTP synchronization is not configured"
        },
        "2.0.14. IP source routing is not explicitly disabled": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "no ip source-route absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Source-routed packets can bypass expected routing paths and trust boundaries on applicable releases.",
            "observation": "The configuration does not contain the IOS 'no ip source-route' hardening command.",
            "recommendation": "Configure 'no ip source-route'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ip.source_route",
            "severity": "Medium",
            "title": "IP source routing is not explicitly disabled"
        },
        "2.0.15. Layer-3 interface hardening is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Loopback0",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Loopback0 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.16. Layer-3 interface hardening is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface GigabitEthernet0/0",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface GigabitEthernet0/0 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.17. Layer-3 interface hardening is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface GigabitEthernet0/1",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface GigabitEthernet0/1 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.18. Layer-3 interface hardening is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface GigabitEthernet0/2",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface GigabitEthernet0/2 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.19. Layer-3 interface hardening is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface GigabitEthernet0/3",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface GigabitEthernet0/3 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.2. SSH VTY access is not source-restricted": {
            "device": "IOS_ROUTER",
            "ease": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "impact": "Any source with network reachability can attempt to access the SSH management service.",
            "observation": "At least one SSH-enabled VTY range lacks an inbound IPv4 or IPv6 access-class.",
            "recommendation": "Apply 'access-class <ACL> in' or 'ipv6 access-class <ACL> in' to every SSH-enabled VTY range.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.vty_access_restriction",
            "severity": "Medium",
            "title": "SSH VTY access is not source-restricted"
        },
        "2.0.20. Control-plane policing is not attached": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No control-plane service-policy input"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Unrestricted control-plane traffic can contribute to CPU exhaustion and management outages.",
            "observation": "No input service policy is attached under control-plane configuration.",
            "recommendation": "Deploy a validated Control Plane Policing policy appropriate for the platform role.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/quality-of-service/quality-of-service/m_qos-plcshp-ctrl-pln-plc-0.html"
            ],
            "rule_id": "cisco.ios.control_plane.copp",
            "severity": "Medium",
            "title": "Control-plane policing is not attached"
        },
        "2.0.21. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.1 remote-as 1",
                "neighbor 192.168.255.1 description iBGP peer nxos01",
                "neighbor 192.168.255.1 update-source Loopback0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.1 in ipv4 unicast, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.22. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.10 remote-as 1",
                "neighbor 192.168.255.10 description iBGP peer nxos9k01",
                "neighbor 192.168.255.10 update-source Loopback0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.10 in ipv4 unicast, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.23. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.11 remote-as 1",
                "neighbor 192.168.255.11 description iBGP peer nxos9k02",
                "neighbor 192.168.255.11 update-source Loopback0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.11 in ipv4 unicast, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.24. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.4 remote-as 1",
                "neighbor 192.168.255.4 description iBGP peer csr01",
                "neighbor 192.168.255.4 update-source Loopback0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.4 in ipv4 unicast, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.25. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.5 remote-as 1",
                "neighbor 192.168.255.5 description iBGP peer iosxr01",
                "neighbor 192.168.255.5 update-source Loopback0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.5 in ipv4 unicast, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.26. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.6 remote-as 1",
                "neighbor 192.168.255.6 description iBGP peer nxos02",
                "neighbor 192.168.255.6 update-source Loopback0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.6 in ipv4 unicast, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.27. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.7 remote-as 1",
                "neighbor 192.168.255.7 description iBGP peer csr02",
                "neighbor 192.168.255.7 update-source Loopback0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.7 in ipv4 unicast, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.28. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.8 remote-as 1",
                "neighbor 192.168.255.8 description iBGP peer ios02",
                "neighbor 192.168.255.8 update-source Loopback0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.8 in ipv4 unicast, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.29. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.9 remote-as 1",
                "neighbor 192.168.255.9 description iBGP peer iosxr02",
                "neighbor 192.168.255.9 update-source Loopback0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.9 in ipv4 unicast, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.3. Centralized AAA is not enabled": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "aaa new-model not present or negated"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authentication, authorization, and accounting policy may be inconsistent and locally controlled.",
            "observation": "The effective configuration does not enable 'aaa new-model'.",
            "recommendation": "Enable AAA new-model and define a tested local fallback before applying it to management lines.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.aaa.new_model",
            "severity": "High",
            "title": "Centralized AAA is not enabled"
        },
        "2.0.30. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.1 remote-as 1",
                "neighbor 192.168.255.1 description iBGP peer nxos01",
                "neighbor 192.168.255.1 update-source Loopback0",
                "neighbor 192.168.255.1 activate"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.1 in ipv4, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.31. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.10 remote-as 1",
                "neighbor 192.168.255.10 description iBGP peer nxos9k01",
                "neighbor 192.168.255.10 update-source Loopback0",
                "neighbor 192.168.255.10 activate"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.10 in ipv4, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.32. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.11 remote-as 1",
                "neighbor 192.168.255.11 description iBGP peer nxos9k02",
                "neighbor 192.168.255.11 update-source Loopback0",
                "neighbor 192.168.255.11 activate"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.11 in ipv4, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.33. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.4 remote-as 1",
                "neighbor 192.168.255.4 description iBGP peer csr01",
                "neighbor 192.168.255.4 update-source Loopback0",
                "neighbor 192.168.255.4 activate"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.4 in ipv4, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.34. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.5 remote-as 1",
                "neighbor 192.168.255.5 description iBGP peer iosxr01",
                "neighbor 192.168.255.5 update-source Loopback0",
                "neighbor 192.168.255.5 activate"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.5 in ipv4, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.35. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.6 remote-as 1",
                "neighbor 192.168.255.6 description iBGP peer nxos02",
                "neighbor 192.168.255.6 update-source Loopback0",
                "neighbor 192.168.255.6 activate"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.6 in ipv4, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.36. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.7 remote-as 1",
                "neighbor 192.168.255.7 description iBGP peer csr02",
                "neighbor 192.168.255.7 update-source Loopback0",
                "neighbor 192.168.255.7 activate"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.7 in ipv4, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.37. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.8 remote-as 1",
                "neighbor 192.168.255.8 description iBGP peer ios02",
                "neighbor 192.168.255.8 update-source Loopback0",
                "neighbor 192.168.255.8 activate"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.8 in ipv4, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.38. BGP neighbor authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "router bgp 1",
                "neighbor 192.168.255.9 remote-as 1",
                "neighbor 192.168.255.9 description iBGP peer iosxr02",
                "neighbor 192.168.255.9 update-source Loopback0",
                "neighbor 192.168.255.9 activate"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
            "observation": "BGP neighbor 192.168.255.9 in ipv4, VRF default has no authentication.",
            "recommendation": "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
            "references": [
                "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
            ],
            "rule_id": "cisco.ios.routing.bgp.authentication",
            "severity": "High",
            "title": "BGP neighbor authentication is incomplete"
        },
        "2.0.4. VTY permits clear-text Telnet": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4",
                "exec-timeout 720 0",
                "login local",
                "transport input telnet ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Remote administrative credentials and commands may traverse the network without encryption.",
            "observation": "line vty 0 4 does not explicitly restrict inbound transport to SSH.",
            "recommendation": "Configure 'transport input ssh' on every VTY range.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.telnet",
            "severity": "High",
            "title": "VTY permits clear-text Telnet"
        },
        "2.0.5. Console authentication is not explicitly secured": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line con 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Physical or terminal-server access may reach an unintended authentication path.",
            "observation": "line con 0 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.console.authentication",
            "severity": "High",
            "title": "Console authentication is not explicitly secured"
        },
        "2.0.6. Auxiliary management line is not fully disabled": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line aux 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unused AUX port can provide an additional local, modem, or reverse-terminal management path.",
            "observation": "line aux 0 does not combine 'no exec', 'transport input none', and 'transport output none'.",
            "recommendation": "Disable the AUX line using the complete Cisco hardening sequence unless it has an approved operational use.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.auxiliary.enabled",
            "severity": "High",
            "title": "Auxiliary management line is not fully disabled"
        },
        "2.0.7. Active auxiliary line lacks resolved authentication": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line aux 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A reachable AUX session may use an unintended or line-password authentication path.",
            "observation": "line aux 0 is not disabled and lacks a resolvable local or AAA login binding.",
            "recommendation": "Disable the line or bind it to a tested AAA login method.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.auxiliary.authentication",
            "severity": "High",
            "title": "Active auxiliary line lacks resolved authentication"
        },
        "2.0.8. Local credential uses weak storage": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "username cisco secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
            "observation": "User 'cisco' uses 'secret' storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. The credential is redacted.",
            "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.local_storage",
            "severity": "High",
            "title": "Local credential uses weak storage"
        },
        "2.0.9. Local credential uses weak storage": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "username ansible secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
            "observation": "User 'ansible' uses 'secret' storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. The credential is redacted.",
            "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.local_storage",
            "severity": "High",
            "title": "Local credential uses weak storage"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: cleartext enable-password storage, Telnet VTY, and absence of centralized AAA are reported.
- Detected but degraded: the storage alert does not distinguish the known training value cisco from an unknown password. The 18 BGP-neighbor authentication alerts may be valid for this lab but do not establish external peer trust.
- Missed entirely: 12-hour VTY idle timeout and the weak credential value itself.
- False positives: no definite one; auxiliary, CoPP and no-remote-log conditions need platform/lab context.
- Crashes/failures: none.

<a id="RW-018"></a>
### HP_PROCURVE — Posted 2626/2650 classroom switch configuration excerpt

**Provenance:** [HPE community 2626/2650 discussion](https://community.hpe.com/t5/switches-hubs-and-modems/vlan-dhcp-relay-ip-routing-hp-procurve-2626-2650/td-p/5178847), configuration lines manually transcribed from the published post, with unrelated VLANs and an email contact omitted; test-input SHA-256 `182730B40B5C057F9630B5C852838BECB66597C14863D70BE06F1F8FA1BEA2F2`. This is a faithful **excerpt**, not a complete export.

**Ground truth (established before running the tool):** `snmp-server community "public" Unrestricted` is a known/default community with broad MIB scope. The configured management VLAN/address may be reachable by other VLANs because routing is on, but any external reachability depends on upstream filtering. No missing logging/AAA/time claim can be inferred from this excerpt. `password manager` is present and does not reveal a value.

**Tool output (actual, unedited):**

**RW018-HP CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (HP ProCurve)
[2/4] Fetching HP API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW018-HP.json
```

**RW018-HP generated JSON report (SHA-256 `49B18F22BD46FB9DE74200B73D194FDF008D38544AD1537CFD8759C3F35C8759`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "HP_PROCURVE",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 4,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "detail": "AOS-S interface security is not normalized in this revision",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "detail": "AOS-S is not parsed as a firewall policy platform",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "HPProCurveParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:01:12.501012",
        "device-type": "HP_PROCURVE",
        "hostname": "D-K-IKTDrift-1-1"
    },
    "remediation-summary": {
        "finding-count": 4,
        "priority-actions": [
            {
                "recommendation": "Remove the default community and migrate management to authenticated, encrypted SNMPv3.",
                "rule-id": "hp.procurve.snmp.default_community",
                "severity": "High",
                "title": "Default SNMP community is configured"
            },
            {
                "recommendation": "Remove community-based management or limit it to read-only restricted access during SNMPv3 migration.",
                "rule-id": "hp.procurve.snmp.community_access",
                "severity": "High",
                "title": "SNMP community has broad or write-capable access"
            },
            {
                "recommendation": "Configure an SNMPv3 user with authentication and privacy, then disable SNMPv1/v2c access.",
                "rule-id": "hp.procurve.snmp.secure_user_missing",
                "severity": "Medium",
                "title": "No authenticated and private SNMPv3 user is configured"
            },
            {
                "recommendation": "Configure at least one protected remote syslog destination.",
                "rule-id": "hp.procurve.logging.remote_destination",
                "severity": "Medium",
                "title": "No remote syslog destination is configured"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 2,
            "Medium": 2
        }
    },
    "security-audit": {
        "6.0.0. Default SNMP community is configured": {
            "device": "HP_PROCURVE",
            "ease": "A reachable attacker can use the known string if network controls permit SNMP.",
            "evidence": [
                "credential configured"
            ],
            "exploitability": "A reachable attacker can use the known string if network controls permit SNMP.",
            "impact": "Widely known community names facilitate unauthorized SNMP access.",
            "observation": "The exact default SNMP community name 'public' is active.",
            "recommendation": "Remove the default community and migrate management to authenticated, encrypted SNMPv3.",
            "references": [
                "https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/Aruba%202530%20Access%20Security%20Guide%20for%20ArubaOS-Switch%2016.10.pdf"
            ],
            "rule_id": "hp.procurve.snmp.default_community",
            "severity": "High",
            "title": "Default SNMP community is configured"
        },
        "6.0.1. SNMP community has broad or write-capable access": {
            "device": "HP_PROCURVE",
            "ease": "An attacker requires SNMP reachability and the community value.",
            "evidence": [
                "credential configured"
            ],
            "exploitability": "An attacker requires SNMP reachability and the community value.",
            "impact": "SNMPv1/v2c community disclosure may permit broad read access or configuration changes.",
            "observation": "Community 'public' has manager access and is unrestricted.",
            "recommendation": "Remove community-based management or limit it to read-only restricted access during SNMPv3 migration.",
            "references": [
                "https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/Aruba%202530%20Access%20Security%20Guide%20for%20ArubaOS-Switch%2016.10.pdf"
            ],
            "rule_id": "hp.procurve.snmp.community_access",
            "severity": "High",
            "title": "SNMP community has broad or write-capable access"
        },
        "6.0.2. No authenticated and private SNMPv3 user is configured": {
            "device": "HP_PROCURVE",
            "ease": "A network-positioned attacker can capture or guess a community and query the device.",
            "evidence": [
                "credential configured"
            ],
            "exploitability": "A network-positioned attacker can capture or guess a community and query the device.",
            "impact": "SNMP management may rely on reusable clear-text community credentials.",
            "observation": "Community-based SNMP is active without a parsed SNMPv3 user using SHA authentication and AES privacy.",
            "recommendation": "Configure an SNMPv3 user with authentication and privacy, then disable SNMPv1/v2c access.",
            "references": [
                "https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/Aruba%202530%20Access%20Security%20Guide%20for%20ArubaOS-Switch%2016.10.pdf"
            ],
            "rule_id": "hp.procurve.snmp.secure_user_missing",
            "severity": "Medium",
            "title": "No authenticated and private SNMPv3 user is configured"
        },
        "6.0.3. No remote syslog destination is configured": {
            "device": "HP_PROCURVE",
            "ease": "An attacker who gains device access can benefit from reduced external evidence.",
            "evidence": [
                "remote logging destination absent"
            ],
            "exploitability": "An attacker who gains device access can benefit from reduced external evidence.",
            "impact": "Security events may be lost with local log rollover or device compromise.",
            "observation": "No active AOS-S 'logging <address>' destination was found.",
            "recommendation": "Configure at least one protected remote syslog destination.",
            "references": [
                "https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/Aruba%202530%20Access%20Security%20Guide%20for%20ArubaOS-Switch%2016.10.pdf"
            ],
            "rule_id": "hp.procurve.logging.remote_destination",
            "severity": "Medium",
            "title": "No remote syslog destination is configured"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: public community and unrestricted SNMP scope are both High.
- Detected but degraded: secure-SNMPv3 and remote-syslog absence checks use an excerpt, not an inventory of the full switch.
- Missed entirely: no other definite issue in the selected lines.
- False positives: absence-of-SNMPv3-user and remote-syslog conclusions are unproven on this excerpt; do not use them as field findings.
- Crashes/failures: none.

<a id="RW-019"></a>
### HP_PROCURVE — Posted 4204vl switch configuration excerpt

**Provenance:** [HPE community 4204vl discussion](https://community.hpe.com/t5/switches-hubs-and-modems/interconnecting-vlan-on-hp-procurve-4204vl-using-static-route/td-p/4390941), configuration lines manually transcribed from the operator's post, with unrelated VLANs omitted; test-input SHA-256 `E8FC21F4DB2B8B9E3B9069A64989282616A64BDB6C5BD0B8E06C8F7E6F7943BB`. A real posted **excerpt**, not a full export.

**Ground truth (established before running the tool):** Again `snmp-server community "public" Unrestricted` creates weak community-based management, subject to network reachability. `dhcp-snooping` and an authorized server are explicitly present and are negative controls. Password-manager/operator lines reveal no credential value. Missing config in this excerpt is unknown.

**Tool output (actual, unedited):**

**RW019-HP CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (HP ProCurve)
[2/4] Fetching HP API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW019-HP.json
```

**RW019-HP generated JSON report (SHA-256 `904BA17708482D839C33D05B56DC642F521601B6CC7D5113CBF3CE6AA7BF4BA6`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "HP_PROCURVE",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 4,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "detail": "AOS-S interface security is not normalized in this revision",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "detail": "AOS-S is not parsed as a firewall policy platform",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "HPProCurveParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:01:12.728375",
        "device-type": "HP_PROCURVE",
        "hostname": "ProCurve Switch 4204vl"
    },
    "remediation-summary": {
        "finding-count": 5,
        "priority-actions": [
            {
                "recommendation": "Remove the default community and migrate management to authenticated, encrypted SNMPv3.",
                "rule-id": "hp.procurve.snmp.default_community",
                "severity": "High",
                "title": "Default SNMP community is configured"
            },
            {
                "recommendation": "Remove community-based management or limit it to read-only restricted access during SNMPv3 migration.",
                "rule-id": "hp.procurve.snmp.community_access",
                "severity": "High",
                "title": "SNMP community has broad or write-capable access"
            },
            {
                "recommendation": "Configure an SNMPv3 user with authentication and privacy, then disable SNMPv1/v2c access.",
                "rule-id": "hp.procurve.snmp.secure_user_missing",
                "severity": "Medium",
                "title": "No authenticated and private SNMPv3 user is configured"
            },
            {
                "recommendation": "Configure at least one protected remote syslog destination.",
                "rule-id": "hp.procurve.logging.remote_destination",
                "severity": "Medium",
                "title": "No remote syslog destination is configured"
            },
            {
                "recommendation": "Configure redundant trusted SNTP servers and the appropriate time synchronization mode.",
                "rule-id": "hp.procurve.ntp.servers",
                "severity": "Low",
                "title": "No SNTP time source is configured"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 2,
            "Low": 1,
            "Medium": 2
        }
    },
    "security-audit": {
        "6.0.0. Default SNMP community is configured": {
            "device": "HP_PROCURVE",
            "ease": "A reachable attacker can use the known string if network controls permit SNMP.",
            "evidence": [
                "credential configured"
            ],
            "exploitability": "A reachable attacker can use the known string if network controls permit SNMP.",
            "impact": "Widely known community names facilitate unauthorized SNMP access.",
            "observation": "The exact default SNMP community name 'public' is active.",
            "recommendation": "Remove the default community and migrate management to authenticated, encrypted SNMPv3.",
            "references": [
                "https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/Aruba%202530%20Access%20Security%20Guide%20for%20ArubaOS-Switch%2016.10.pdf"
            ],
            "rule_id": "hp.procurve.snmp.default_community",
            "severity": "High",
            "title": "Default SNMP community is configured"
        },
        "6.0.1. SNMP community has broad or write-capable access": {
            "device": "HP_PROCURVE",
            "ease": "An attacker requires SNMP reachability and the community value.",
            "evidence": [
                "credential configured"
            ],
            "exploitability": "An attacker requires SNMP reachability and the community value.",
            "impact": "SNMPv1/v2c community disclosure may permit broad read access or configuration changes.",
            "observation": "Community 'public' has manager access and is unrestricted.",
            "recommendation": "Remove community-based management or limit it to read-only restricted access during SNMPv3 migration.",
            "references": [
                "https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/Aruba%202530%20Access%20Security%20Guide%20for%20ArubaOS-Switch%2016.10.pdf"
            ],
            "rule_id": "hp.procurve.snmp.community_access",
            "severity": "High",
            "title": "SNMP community has broad or write-capable access"
        },
        "6.0.2. No authenticated and private SNMPv3 user is configured": {
            "device": "HP_PROCURVE",
            "ease": "A network-positioned attacker can capture or guess a community and query the device.",
            "evidence": [
                "credential configured"
            ],
            "exploitability": "A network-positioned attacker can capture or guess a community and query the device.",
            "impact": "SNMP management may rely on reusable clear-text community credentials.",
            "observation": "Community-based SNMP is active without a parsed SNMPv3 user using SHA authentication and AES privacy.",
            "recommendation": "Configure an SNMPv3 user with authentication and privacy, then disable SNMPv1/v2c access.",
            "references": [
                "https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/Aruba%202530%20Access%20Security%20Guide%20for%20ArubaOS-Switch%2016.10.pdf"
            ],
            "rule_id": "hp.procurve.snmp.secure_user_missing",
            "severity": "Medium",
            "title": "No authenticated and private SNMPv3 user is configured"
        },
        "6.0.3. No remote syslog destination is configured": {
            "device": "HP_PROCURVE",
            "ease": "An attacker who gains device access can benefit from reduced external evidence.",
            "evidence": [
                "remote logging destination absent"
            ],
            "exploitability": "An attacker who gains device access can benefit from reduced external evidence.",
            "impact": "Security events may be lost with local log rollover or device compromise.",
            "observation": "No active AOS-S 'logging <address>' destination was found.",
            "recommendation": "Configure at least one protected remote syslog destination.",
            "references": [
                "https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/Aruba%202530%20Access%20Security%20Guide%20for%20ArubaOS-Switch%2016.10.pdf"
            ],
            "rule_id": "hp.procurve.logging.remote_destination",
            "severity": "Medium",
            "title": "No remote syslog destination is configured"
        },
        "6.0.4. No SNTP time source is configured": {
            "device": "HP_PROCURVE",
            "ease": "Poor time consistency reduces the reliability of forensic timelines.",
            "evidence": [
                "SNTP server absent"
            ],
            "exploitability": "Poor time consistency reduces the reliability of forensic timelines.",
            "impact": "Inaccurate timestamps hinder event correlation and certificate or authentication troubleshooting.",
            "observation": "No active 'sntp server' entry was found.",
            "recommendation": "Configure redundant trusted SNTP servers and the appropriate time synchronization mode.",
            "references": [
                "https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/KB/content/kb/snt-ser.htm"
            ],
            "rule_id": "hp.procurve.ntp.servers",
            "severity": "Low",
            "title": "No SNTP time source is configured"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: public and unrestricted SNMP community are both High.
- Detected but degraded: no definite explicit issue.
- Missed entirely: none in the selected lines.
- False positives: absence of SNMPv3 user, remote syslog and NTP source are unproven because the input is an excerpt.
- Crashes/failures: none.

<a id="RW-020"></a>
### PIX — Operator-posted PIX 501 version 6.3(5) configuration excerpt

**Provenance:** [Cisco community PIX 6.3 thread](https://community.cisco.com/t5/network-security/pix-6-3-configuration/td-p/1425718), exact selected lines manually transcribed from the posted `show run`; SHA-256 `68BF84EB5E6AF96317AE72C41B471687D5C70DECD4F1F47C9F7266D0CDD186FA`. The operator masked addresses and passwords; this test file is an **excerpt**.

**Ground truth (established before running the tool):** `ping_acl permit ip any any` is attached inbound to the outside interface, broad exposure at that filter. The operator's later hit counts show zero hits on this particular ACE, so exploitation is not established. `snmp-server community public` is a default community. `console timeout 0` disables idle logout. `logging on` with buffered warnings is local-only in the excerpt; no absence-based remote-logging claim is made. The encrypted password masks are not rated.

**Tool output (actual, unedited):**

**RW020-PIX CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (ASA)
[3/4] Checking missconfiguration vulnerabilities
[3/4] Scanning configuration file using the following ASA plugins: ['PluginASAChecks', 'PluginASABaseline']
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW020-PIX.json
```

**RW020-PIX generated JSON report (SHA-256 `FAF1C5E95A91E77A4292C9E9D33616C72EB1BC8AD3EB028AC306F5D4A78CB12C`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "PIX",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "ASA hardware model is not parsed from the supported configuration export",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "ASA software version is absent",
                "knowledge-state": "unknown",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoASAParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:01:13.148828",
        "device-type": "PIX",
        "hostname": "chq-mdf-fw-02"
    },
    "remediation-summary": {
        "finding-count": 3,
        "priority-actions": [
            {
                "recommendation": "Replace the credential with a unique secret stored using a supported strong hash format.",
                "rule-id": "cisco.asa.credentials.weak_enable_password",
                "severity": "High",
                "title": "Unsafe enable credential storage"
            },
            {
                "recommendation": "Remove SNMPv1/v2c defaults and prefer SNMPv3 with authentication and privacy.",
                "rule-id": "cisco.asa.snmp.default_community",
                "severity": "High",
                "title": "Default SNMP community configured"
            },
            {
                "recommendation": "Enable logging and configure at least one reachable remote 'logging host'.",
                "rule-id": "cisco.asa.logging.missing",
                "severity": "Low",
                "title": "Remote security logging is not operational"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 2,
            "Low": 1
        }
    },
    "security-audit": {
        "2.0.0. Unsafe enable credential storage": {
            "device": "PIX",
            "ease": "Default values are easily guessed; plaintext values are exposed if the configuration is obtained.",
            "evidence": [
                "enable password <redacted> encrypted"
            ],
            "exploitability": "Default values are easily guessed; plaintext values are exposed if the configuration is obtained.",
            "impact": "A recoverable or default credential can enable administrative privilege escalation.",
            "observation": "The enable credential uses format 'encrypted', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate exact-default comparison is 'not_evaluated' and the blocklist comparison was not evaluated against a supplied credential blocklist. The secret value has been redacted.",
            "recommendation": "Replace the credential with a unique secret stored using a supported strong hash format.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/e-commands.html"
            ],
            "rule_id": "cisco.asa.credentials.weak_enable_password",
            "severity": "High",
            "title": "Unsafe enable credential storage"
        },
        "2.0.1. Default SNMP community configured": {
            "device": "PIX",
            "ease": "The default value is publicly known.",
            "evidence": [
                "snmp-server community <redacted> ro"
            ],
            "exploitability": "The default value is publicly known.",
            "impact": "Default communities are routinely tried by automated discovery and attack tools.",
            "observation": "An exact default SNMP community is configured. Its value has been redacted.",
            "recommendation": "Remove SNMPv1/v2c defaults and prefer SNMPv3 with authentication and privacy.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa917/configuration/general/asa-917-general-config/monitor-snmp.html"
            ],
            "rule_id": "cisco.asa.snmp.default_community",
            "severity": "High",
            "title": "Default SNMP community configured"
        },
        "2.0.2. Remote security logging is not operational": {
            "device": "PIX",
            "ease": "An attacker may operate with reduced likelihood of centralized detection.",
            "evidence": [
                "No active logging host"
            ],
            "exploitability": "An attacker may operate with reduced likelihood of centralized detection.",
            "impact": "Security events may not be retained for monitoring, investigation, or audit.",
            "observation": "Centralized logging is unavailable because logging is disabled.",
            "recommendation": "Enable logging and configure at least one reachable remote 'logging host'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/monitor-syslog.html"
            ],
            "rule_id": "cisco.asa.logging.missing",
            "severity": "Low",
            "title": "Remote security logging is not operational"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: public SNMP community. The encoded enable password is identified as unsafe storage, but its masked value cannot be evaluated.
- Detected but degraded: no finding explains that a bound outside ACL contains permit ip any any.
- Missed entirely: bound universal outside permit and console timeout 0, both explicit in actual PIX 6.3 syntax.
- False positives: missing remote logging is not provable from a selected-line excerpt; logging on and buffered warnings are present locally.
- Crashes/failures: none; the report silently normalizes security-policies as known with item-count zero, a misleading coverage claim for this registered PIX dialect.

<a id="RW-021"></a>
### PIX — University of Valencia PIX 515E version 6.3(3) lab final configuration excerpt

**Provenance:** [University of Valencia PIX lab, Annex II](https://informatica.uv.es/it3guia/ARS/practicas/pix.pdf), published final lab configuration, selected lines manually transcribed; SHA-256 `4D26578AD3A109BEA1BE7165AB2AD90B76103C77E2622B7A1DB8172CCC2926E0`. It is an educational design, not production, and this test input is an **excerpt**.

**Ground truth (established before running the tool):** The outside-bound `outside_access_in` allows TCP from any source to a statically mapped DMZ host's Telnet port, exposing that host's cleartext login protocol. The same ACL permits ICMP any-to-any, a broad but context-dependent exposure. `snmp-server community public` uses a known community; `console timeout 0` disables idle logout. There is no claim that PIX itself accepts Telnet: `telnet timeout 5` only sets a timeout, and no manager-source grant was transcribed.

**Tool output (actual, unedited):**

**RW021-PIX CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (ASA)
[3/4] Checking missconfiguration vulnerabilities
[3/4] Scanning configuration file using the following ASA plugins: ['PluginASAChecks', 'PluginASABaseline']
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW021-PIX.json
```

**RW021-PIX generated JSON report (SHA-256 `0B5E8554C2490F781F52C452BB5C61F2C8979516CDC71684B4B405CDAB23FE31`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "PIX",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "ASA hardware model is not parsed from the supported configuration export",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "ASA software version is absent",
                "knowledge-state": "unknown",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoASAParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:01:13.576453",
        "device-type": "PIX",
        "hostname": "PIX"
    },
    "remediation-summary": {
        "finding-count": 2,
        "priority-actions": [
            {
                "recommendation": "Remove SNMPv1/v2c defaults and prefer SNMPv3 with authentication and privacy.",
                "rule-id": "cisco.asa.snmp.default_community",
                "severity": "High",
                "title": "Default SNMP community configured"
            },
            {
                "recommendation": "Enable logging and configure at least one reachable remote 'logging host'.",
                "rule-id": "cisco.asa.logging.missing",
                "severity": "Low",
                "title": "Remote security logging is not operational"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 1,
            "Low": 1
        }
    },
    "security-audit": {
        "2.0.0. Default SNMP community configured": {
            "device": "PIX",
            "ease": "The default value is publicly known.",
            "evidence": [
                "snmp-server community <redacted> ro"
            ],
            "exploitability": "The default value is publicly known.",
            "impact": "Default communities are routinely tried by automated discovery and attack tools.",
            "observation": "An exact default SNMP community is configured. Its value has been redacted.",
            "recommendation": "Remove SNMPv1/v2c defaults and prefer SNMPv3 with authentication and privacy.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa917/configuration/general/asa-917-general-config/monitor-snmp.html"
            ],
            "rule_id": "cisco.asa.snmp.default_community",
            "severity": "High",
            "title": "Default SNMP community configured"
        },
        "2.0.1. Remote security logging is not operational": {
            "device": "PIX",
            "ease": "An attacker may operate with reduced likelihood of centralized detection.",
            "evidence": [
                "No active logging host"
            ],
            "exploitability": "An attacker may operate with reduced likelihood of centralized detection.",
            "impact": "Security events may not be retained for monitoring, investigation, or audit.",
            "observation": "Centralized logging is unavailable because logging is disabled.",
            "recommendation": "Enable logging and configure at least one reachable remote 'logging host'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/monitor-syslog.html"
            ],
            "rule_id": "cisco.asa.logging.missing",
            "severity": "Low",
            "title": "Remote security logging is not operational"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: public SNMP community.
- Detected but degraded: none.
- Missed entirely: outside-to-DMZ Telnet permit, broad ICMP permit and disabled console idle timeout in actual PIX 6.3 syntax.
- False positives: remote logging absence is not provable from an excerpt. The report says zero known policies despite an explicit outside-bound ACL.
- Crashes/failures: none.

<a id="RW-022"></a>
### SONICOS — SYNTHETIC SonicOS 7.2 E-CLI fallback A

**Provenance:** **SYNTHETIC**, constructed after searches for public SonicOS 7 `show current-config custom` exports found CLI references, API examples and backup instructions but no verifiable plaintext appliance export. [SonicWall's E-CLI guide](https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf) defines this export family. Input SHA-256 `B343CBB79EF8B28757051818883DFAED56DF007BD28DE029432389E0B199F8CB`.

**Ground truth (established before running the tool), every deliberate unsafe choice:** Line 5 enables HTTP management on WAN X1 (cleartext admin interface). Line 8 creates an inbound WAN-to-LAN all-source/all-destination/all-service permit; line 10 disables logging for it. Line 12 configures an NTP server without authentication, but source trust is contextual. All addresses are documentation ranges. Other omissions in this short synthetic snippet do not establish device-wide absence.

**Tool output (actual, unedited):**

**RW022-SONIC CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (SonicWALL SonicOS)
[2/4] Fetching SonicWALL API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW022-SONIC.json
```

**RW022-SONIC generated JSON report (SHA-256 `940826BA38717332CE65C2DE8D25CEA466AA7332C84F62D6834E1DFD3B821D1D`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "SONICOS",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Hostname absent",
                "knowledge-state": "unknown",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Product metadata absent",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 3,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "detail": "E-CLI export cannot prove whether built-in administrator credentials are unchanged",
                "item-count": null,
                "knowledge-state": "unknown",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "detail": "VPN proposals remain available through vendor-specific typed records",
                "item-count": null,
                "knowledge-state": "unknown",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "SonicOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:01:13.829553",
        "device-type": "SONICOS",
        "hostname": "?"
    },
    "remediation-summary": {
        "finding-count": 12,
        "priority-actions": [
            {
                "recommendation": "Remove HTTP management from the interface and use HTTPS with an approved certificate.",
                "rule-id": "sonicwall.sonicos.management.http",
                "severity": "High",
                "title": "Clear-text HTTP management is enabled"
            },
            {
                "recommendation": "Remove management from external interfaces or constrain it with explicit source-specific access rules and upstream controls.",
                "rule-id": "sonicwall.sonicos.management.external_interface",
                "severity": "High",
                "title": "Management is enabled on an external-zone interface"
            },
            {
                "recommendation": "Require TOTP for privileged local administrators and maintain a separately controlled recovery procedure.",
                "rule-id": "sonicwall.sonicos.admin.mfa_missing",
                "severity": "High",
                "title": "Privileged local administrator does not require TOTP"
            },
            {
                "recommendation": "Enable user lockout with a conservative failed-attempt threshold and a controlled recovery process.",
                "rule-id": "sonicwall.sonicos.admin.lockout_disabled",
                "severity": "High",
                "title": "Administrator login lockout is disabled"
            },
            {
                "recommendation": "Set the SonicOS minimum password length to at least 12 characters and prefer longer passphrases.",
                "rule-id": "sonicwall.sonicos.password.minimum_length",
                "severity": "Medium",
                "title": "Administrative password minimum length is weak"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 4,
            "Low": 1,
            "Medium": 7
        }
    },
    "security-audit": {
        "5.0.0. Clear-text HTTP management is enabled": {
            "device": "SONICOS",
            "ease": "An attacker with management-path reachability can intercept clear-text traffic.",
            "evidence": [
                "interface X1",
                "zone WAN",
                "ip-address 203.0.113.2",
                "management http https ssh",
                "no shutdown"
            ],
            "exploitability": "An attacker with management-path reachability can intercept clear-text traffic.",
            "impact": "Administrative credentials and sessions can be exposed or modified in transit.",
            "observation": "Interface 'X1' in zone 'WAN' permits HTTP management.",
            "recommendation": "Remove HTTP management from the interface and use HTTPS with an approved certificate.",
            "references": [
                "https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-0-0-0-device_settings/Content/Topics/Management/management-ssh.htm",
                "https://www.sonicwall.com/techdocs/pdf/sonicos-7-0-0-0-system.pdf"
            ],
            "rule_id": "sonicwall.sonicos.management.http",
            "severity": "High",
            "title": "Clear-text HTTP management is enabled"
        },
        "5.0.1. Management is enabled on an external-zone interface": {
            "device": "SONICOS",
            "ease": "Any source allowed to reach the interface can probe the enabled services; inter-zone rules may add restrictions not reconstructed here.",
            "evidence": [
                "interface X1",
                "zone WAN",
                "ip-address 203.0.113.2",
                "management http https ssh",
                "no shutdown"
            ],
            "exploitability": "Any source allowed to reach the interface can probe the enabled services; inter-zone rules may add restrictions not reconstructed here.",
            "impact": "Internet- or partner-facing paths may expose the firewall management plane.",
            "observation": "Interface 'X1' in WAN permits https, ssh management.",
            "recommendation": "Remove management from external interfaces or constrain it with explicit source-specific access rules and upstream controls.",
            "references": [
                "https://www.sonicwall.com/techdocs/pdf/sonicos-7-0-0-0-system.pdf",
                "https://www.sonicwall.com/techdocs/pdf/sonicos-7-0-0-0-rules_and_policies.pdf"
            ],
            "rule_id": "sonicwall.sonicos.management.external_interface",
            "severity": "High",
            "title": "Management is enabled on an external-zone interface"
        },
        "5.0.10. No enabled syslog destination is configured": {
            "device": "SONICOS",
            "ease": "An attacker with appliance access benefits from reduced external evidence.",
            "evidence": [
                "enabled syslog destination absent"
            ],
            "exploitability": "An attacker with appliance access benefits from reduced external evidence.",
            "impact": "Security events may be lost through local rollover or appliance compromise.",
            "observation": "No enabled SonicOS syslog server was found.",
            "recommendation": "Configure and enable redundant protected syslog destinations.",
            "references": [
                "https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf"
            ],
            "rule_id": "sonicwall.sonicos.logging.remote_destination",
            "severity": "Medium",
            "title": "No enabled syslog destination is configured"
        },
        "5.0.11. NTP server lacks complete authentication": {
            "device": "SONICOS",
            "ease": "A network-positioned attacker may spoof NTP responses if routing and filtering permit it.",
            "evidence": [
                "ntp-server 203.0.113.10 no-auth; trust-key-no missing; key-number missing; key material missing"
            ],
            "exploitability": "A network-positioned attacker may spoof NTP responses if routing and filtering permit it.",
            "impact": "Unauthenticated time responses can corrupt log chronology and time-dependent authentication behavior.",
            "observation": "Active NTP server '203.0.113.10' lacks matching trust/key numbers, MD5 selection, or configured key material.",
            "recommendation": "Configure the platform-supported authenticated NTP fields for every custom server and restrict management-plane reachability.",
            "references": [
                "https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf"
            ],
            "rule_id": "sonicwall.sonicos.ntp.authentication",
            "severity": "Medium",
            "title": "NTP server lacks complete authentication"
        },
        "5.0.2. Privileged local administrator does not require TOTP": {
            "device": "SONICOS",
            "ease": "An attacker who obtains the local password does not need an independent authentication factor.",
            "evidence": [
                "SonicOS 7.0-7.2 documented default: built-in administrator TOTP disabled"
            ],
            "exploitability": "An attacker who obtains the local password does not need an independent authentication factor.",
            "impact": "A stolen or guessed password alone can authorize privileged firewall administration.",
            "observation": "Local full-admin account 'built-in administrator' has TOTP explicitly or unambiguously disabled.",
            "recommendation": "Require TOTP for privileged local administrators and maintain a separately controlled recovery procedure.",
            "references": [
                "https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf"
            ],
            "rule_id": "sonicwall.sonicos.admin.mfa_missing",
            "severity": "High",
            "title": "Privileged local administrator does not require TOTP"
        },
        "5.0.3. Administrative password minimum length is weak": {
            "device": "SONICOS",
            "ease": "An attacker can search a materially smaller password space.",
            "evidence": [
                "SonicOS 7.0-7.2 documented minimum-length default: 8"
            ],
            "exploitability": "An attacker can search a materially smaller password space.",
            "impact": "Short passwords reduce resistance to online guessing and offline cracking after credential disclosure.",
            "observation": "The effective minimum password length is 8, below the 12-character project baseline.",
            "recommendation": "Set the SonicOS minimum password length to at least 12 characters and prefer longer passphrases.",
            "references": [
                "https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-device_settings/Content/System_Administration/Multiple_Administrator/password-compliance-configuration.htm",
                "https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf"
            ],
            "rule_id": "sonicwall.sonicos.password.minimum_length",
            "severity": "Medium",
            "title": "Administrative password minimum length is weak"
        },
        "5.0.4. Administrative password complexity is not fully enabled": {
            "device": "SONICOS",
            "ease": "Password-spraying and credential-cracking attacks benefit from a less diverse password policy.",
            "evidence": [
                "SonicOS 7.0-7.2 documented password-complexity default: none"
            ],
            "exploitability": "Password-spraying and credential-cracking attacks benefit from a less diverse password policy.",
            "impact": "Locally managed passwords may be easier to guess or reuse across systems.",
            "observation": "The effective password complexity mode is 'none'.",
            "recommendation": "Require alphabetic, numeric, and symbolic characters for applicable administrator accounts.",
            "references": [
                "https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-device_settings/Content/System_Administration/Multiple_Administrator/password-compliance-configuration.htm",
                "https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf"
            ],
            "rule_id": "sonicwall.sonicos.password.complexity",
            "severity": "Medium",
            "title": "Administrative password complexity is not fully enabled"
        },
        "5.0.5. Administrator login lockout is disabled": {
            "device": "SONICOS",
            "ease": "A reachable attacker can sustain online password-guessing attempts.",
            "evidence": [
                "SonicOS 7.0-7.2 documented user-lockout default: disabled"
            ],
            "exploitability": "A reachable attacker can sustain online password-guessing attempts.",
            "impact": "Repeated password guesses are not stopped by the appliance lockout control.",
            "observation": "The effective administrator/user lockout control is disabled while a management service is active.",
            "recommendation": "Enable user lockout with a conservative failed-attempt threshold and a controlled recovery process.",
            "references": [
                "https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-device_settings/Content/System_Administration/Multiple_Administrator/login-constraints-configuring.htm",
                "https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf"
            ],
            "rule_id": "sonicwall.sonicos.admin.lockout_disabled",
            "severity": "High",
            "title": "Administrator login lockout is disabled"
        },
        "5.0.6. SSH connection notice is not configured": {
            "device": "SONICOS",
            "ease": "This is primarily a governance and legal-notice control rather than a direct technical exploit.",
            "evidence": [
                "SonicOS 7.0-7.2 documented CLI connection banner default: absent"
            ],
            "exploitability": "This is primarily a governance and legal-notice control rather than a direct technical exploit.",
            "impact": "Administrative users are not shown the organization's authorization and monitoring notice before login.",
            "observation": "SSH management is active without an effective pre-authentication CLI connection banner.",
            "recommendation": "Configure an approved 'cli banner connection' notice and validate it before the credential prompt.",
            "references": [
                "https://www.sonicwall.com/support/knowledge-base/modifying-the-sonicwall-login-banner-page-display/kA1VN0000000Ogg0AE",
                "https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf"
            ],
            "rule_id": "sonicwall.sonicos.admin.connection_banner",
            "severity": "Low",
            "title": "SSH connection notice is not configured"
        },
        "5.0.7. Web management uses the default self-signed certificate type": {
            "device": "SONICOS",
            "ease": "Users who bypass certificate warnings are more susceptible to management-plane impersonation.",
            "evidence": [
                "SonicOS 7.0-7.2 documented certificate-selection default: self-signed"
            ],
            "exploitability": "Users who bypass certificate warnings are more susceptible to management-plane impersonation.",
            "impact": "Administrators cannot rely on an organization-trusted identity chain to authenticate the firewall.",
            "observation": "HTTPS management is active and the effective certificate selection is self-signed.",
            "recommendation": "Install and select an organization-approved identity certificate with the correct DNS name and trust chain.",
            "references": [
                "https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-device_settings/Content/Management/security-certificate-selecting.htm",
                "https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf"
            ],
            "rule_id": "sonicwall.sonicos.management.self_signed_certificate",
            "severity": "Medium",
            "title": "Web management uses the default self-signed certificate type"
        },
        "5.0.8. Allow rule does not enable logging": {
            "device": "SONICOS",
            "ease": "Malicious traffic matching the rule can be harder to identify or reconstruct.",
            "evidence": [
                "access-rule ipv4 from WAN to LAN action allow source address Any service Any destination address Any schedule Always-On",
                "name \"Internet-to-LAN\"",
                "no logging"
            ],
            "exploitability": "Malicious traffic matching the rule can be harder to identify or reconstruct.",
            "impact": "Permitted connections may lack the telemetry needed for detection and investigation.",
            "observation": "Enabled allow rule 'Internet-to-LAN' at position 1 has logging disabled or absent.",
            "recommendation": "Enable logging on security-relevant allow rules and forward events to centralized storage.",
            "references": [
                "https://www.sonicwall.com/techdocs/pdf/sonicos-7-0-0-0-rules_and_policies.pdf",
                "https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf"
            ],
            "rule_id": "sonicwall.sonicos.policy.logging",
            "severity": "Medium",
            "title": "Allow rule does not enable logging"
        },
        "5.0.9. SonicOS access rule is unrestricted by service": {
            "device": "SONICOS",
            "ease": "A matching source can attempt any service reachable in the destination scope.",
            "evidence": [
                "access-rule ipv4 from WAN to LAN action allow source address Any service Any destination address Any schedule Always-On",
                "name \"Internet-to-LAN\"",
                "no logging"
            ],
            "exploitability": "A matching source can attempt any service reachable in the destination scope.",
            "impact": "Unnecessary protocols and destination ports can cross the policy boundary.",
            "observation": "Enabled access rule 'Internet-to-LAN' at position 1 permits Any service within its zone and address scope.",
            "recommendation": "Replace Any with the smallest required services or reviewed service group.",
            "references": [
                "https://www.sonicwall.com/techdocs/pdf/sonicos-7-0-0-0-rules_and_policies.pdf",
                "https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf"
            ],
            "rule_id": "sonicwall.sonicos.policy.broad_service",
            "severity": "Medium",
            "title": "SonicOS access rule is unrestricted by service"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: WAN HTTP management, external management interface, unauthenticated NTP, and absent rule logging are each recognized.
- Detected but degraded: the universal inbound WAN-to-LAN permit receives only a Medium broad-service alert, not a finding for all-source/all-destination/all-service access.
- Missed entirely: the explicit broad inbound permit as a distinct Critical exposure.
- False positives: absent syslog, administrator MFA/password/lockout/banner and certificate-selection claims are not established by this deliberately short synthetic input. Their 7.2 default assumptions require a genuine complete custom export.
- Crashes/failures: none.

<a id="RW-023"></a>
### SONICOS — SYNTHETIC SonicOS 7.3 E-CLI fallback B

**Provenance:** **SYNTHETIC**, second independently written short E-CLI example after the same unsuccessful public-export search; input SHA-256 `E96130FA94A45CDA764D2C31F587BEFA1FC782733527732531B13CF593D9EAFF`.

**Ground truth (established before running the tool), every deliberate unsafe choice:** Line 11 enables HTTPS management on WAN X1 without a source restriction in this snippet. This is a *potential* exposure, because a complete device export could have management policies not shown; it is not scored as a definite vulnerability. Outbound LAN-to-WAN allow has logging enabled and is intentional. No other vulnerability is asserted from omissions, especially because 7.3 defaults depend on install/upgrade history.

**Tool output (actual, unedited):**

**RW023-SONIC CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (SonicWALL SonicOS)
[2/4] Fetching SonicWALL API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW023-SONIC.json
```

**RW023-SONIC generated JSON report (SHA-256 `DE3FEC4C90541340FB46B1F47044DCEA0766EF48DF2AE637B00E460B7A0035E5`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "SONICOS",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Hostname absent",
                "knowledge-state": "unknown",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Product metadata absent",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 3,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "detail": "E-CLI export cannot prove whether built-in administrator credentials are unchanged",
                "item-count": null,
                "knowledge-state": "unknown",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "detail": "VPN proposals remain available through vendor-specific typed records",
                "item-count": null,
                "knowledge-state": "unknown",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "SonicOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:01:14.078895",
        "device-type": "SONICOS",
        "hostname": "?"
    },
    "remediation-summary": {
        "finding-count": 4,
        "priority-actions": [
            {
                "recommendation": "Remove management from external interfaces or constrain it with explicit source-specific access rules and upstream controls.",
                "rule-id": "sonicwall.sonicos.management.external_interface",
                "severity": "High",
                "title": "Management is enabled on an external-zone interface"
            },
            {
                "recommendation": "Replace Any with the smallest required services or reviewed service group.",
                "rule-id": "sonicwall.sonicos.policy.broad_service",
                "severity": "Medium",
                "title": "SonicOS access rule is unrestricted by service"
            },
            {
                "recommendation": "Configure and enable redundant protected syslog destinations.",
                "rule-id": "sonicwall.sonicos.logging.remote_destination",
                "severity": "Medium",
                "title": "No enabled syslog destination is configured"
            },
            {
                "recommendation": "Configure redundant trusted NTP servers and authenticate them where supported.",
                "rule-id": "sonicwall.sonicos.ntp.servers",
                "severity": "Low",
                "title": "No custom NTP server is configured"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 1,
            "Low": 1,
            "Medium": 2
        }
    },
    "security-audit": {
        "5.0.0. Management is enabled on an external-zone interface": {
            "device": "SONICOS",
            "ease": "Any source allowed to reach the interface can probe the enabled services; inter-zone rules may add restrictions not reconstructed here.",
            "evidence": [
                "interface X1",
                "zone WAN",
                "ip-address 198.51.100.2",
                "management https",
                "no shutdown"
            ],
            "exploitability": "Any source allowed to reach the interface can probe the enabled services; inter-zone rules may add restrictions not reconstructed here.",
            "impact": "Internet- or partner-facing paths may expose the firewall management plane.",
            "observation": "Interface 'X1' in WAN permits https management.",
            "recommendation": "Remove management from external interfaces or constrain it with explicit source-specific access rules and upstream controls.",
            "references": [
                "https://www.sonicwall.com/techdocs/pdf/sonicos-7-0-0-0-system.pdf",
                "https://www.sonicwall.com/techdocs/pdf/sonicos-7-0-0-0-rules_and_policies.pdf"
            ],
            "rule_id": "sonicwall.sonicos.management.external_interface",
            "severity": "High",
            "title": "Management is enabled on an external-zone interface"
        },
        "5.0.1. SonicOS access rule is unrestricted by service": {
            "device": "SONICOS",
            "ease": "A matching source can attempt any service reachable in the destination scope.",
            "evidence": [
                "access-rule ipv4 from LAN to WAN action allow source address Any service Any destination address Any schedule Always-On",
                "name \"Lab outbound\"",
                "logging"
            ],
            "exploitability": "A matching source can attempt any service reachable in the destination scope.",
            "impact": "Unnecessary protocols and destination ports can cross the policy boundary.",
            "observation": "Enabled access rule 'Lab outbound' at position 1 permits Any service within its zone and address scope.",
            "recommendation": "Replace Any with the smallest required services or reviewed service group.",
            "references": [
                "https://www.sonicwall.com/techdocs/pdf/sonicos-7-0-0-0-rules_and_policies.pdf",
                "https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf"
            ],
            "rule_id": "sonicwall.sonicos.policy.broad_service",
            "severity": "Medium",
            "title": "SonicOS access rule is unrestricted by service"
        },
        "5.0.2. No enabled syslog destination is configured": {
            "device": "SONICOS",
            "ease": "An attacker with appliance access benefits from reduced external evidence.",
            "evidence": [
                "enabled syslog destination absent"
            ],
            "exploitability": "An attacker with appliance access benefits from reduced external evidence.",
            "impact": "Security events may be lost through local rollover or appliance compromise.",
            "observation": "No enabled SonicOS syslog server was found.",
            "recommendation": "Configure and enable redundant protected syslog destinations.",
            "references": [
                "https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf"
            ],
            "rule_id": "sonicwall.sonicos.logging.remote_destination",
            "severity": "Medium",
            "title": "No enabled syslog destination is configured"
        },
        "5.0.3. No custom NTP server is configured": {
            "device": "SONICOS",
            "ease": "Inconsistent time reduces the reliability of security monitoring and forensic timelines.",
            "evidence": [
                "custom NTP server absent"
            ],
            "exploitability": "Inconsistent time reduces the reliability of security monitoring and forensic timelines.",
            "impact": "Incorrect timestamps hinder event correlation and authentication troubleshooting.",
            "observation": "No active SonicOS 'ntp-server' entry was found.",
            "recommendation": "Configure redundant trusted NTP servers and authenticate them where supported.",
            "references": [
                "https://www.sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf"
            ],
            "rule_id": "sonicwall.sonicos.ntp.servers",
            "severity": "Low",
            "title": "No custom NTP server is configured"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: external-zone HTTPS management is identified.
- Detected but degraded: no definite other issue.
- Missed entirely: none definite; the input intentionally contains no complete management access policy.
- False positives: absence-based syslog and NTP findings are unproven on a short synthetic snippet; broad-service on an intentional LAN-to-WAN allow is context-dependent, not necessarily a security violation.
- Crashes/failures: none.

<a id="RW-024"></a>
### CHECKPOINT_FW1 — SYNTHETIC broad policy fallback A

**Provenance:** **SYNTHETIC**, `rules.C` archive-shaped source made after searches for a public real FireWall-1 `rules.C`/`objects.C` export found only file descriptions and vendor migration discussions. [Check Point community discussion](https://community.checkpoint.com/t5/API-CLI-Discussion/Security-Audit-Report-Using-Nipper-tool/m-p/8037) confirms this legacy file family; input `rules.C` SHA-256 `C3B85DFE4F9B7ED19D77ED7253F9F5FC5055B82943A84D89956464000E9A598F`.

**Ground truth (established before running the tool), every deliberate unsafe choice:** Rule 1 (lines 2–9) accepts Any source to Any destination on Any service with tracking `none`, installed on Any gateway. It is a universal unlogged permit, making the following drop cleanup unreachable for matched traffic. The actual firewall installation/runtime state cannot be established from synthetic text. No other weakness is asserted.

**Tool output (actual, unedited):**

**RW024-CP CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (CheckPoint FW1)
[2/4] Fetching CheckPoint API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW024-CP.json
```

**RW024-CP generated JSON report (SHA-256 `AE1593B4311549EC985352211530FA0D36CB4F3D9CB1BF0D96A11D8B40DBA265`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "CHECKPOINT_FW1",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Management hostname is not present in these exports",
                "knowledge-state": "unknown",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Firewall-1 policy exports do not identify the gateway hardware model",
                "knowledge-state": "unsupported",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Check Point release metadata was not found in the located files",
                "knowledge-state": "unknown",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "detail": "Firewall-1 policy exports do not describe gateway management daemons",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "detail": "Administrator databases are outside the supported FW1 export set",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "detail": "Firewall-1 policy exports do not contain gateway interface state",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "detail": "Gateway logging destinations are outside the supported FW1 export set",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "detail": "Gateway cryptographic settings are outside the supported FW1 export set",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": 1,
        "input-kind": "directory",
        "parser": "CheckPointFW1Parser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:01:14.313811",
        "device-type": "CHECKPOINT_FW1",
        "hostname": "checkpoint-device"
    },
    "remediation-summary": {
        "finding-count": 0,
        "priority-actions": [],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {}
    },
    "security-audit": {},
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: none; parser coverage reports zero security policies.
- Detected but degraded: none.
- Missed entirely: **indeterminate**. The synthetic rules.C was accepted without diagnostics but yielded zero policies; without a verified vendor export this cannot be called a product false negative.
- False positives: none reported.
- Crashes/failures: no crash, but a success-shaped empty policy result on this fallback is not evidence that real Check Point exports are safely assessed.

<a id="RW-025"></a>
### CHECKPOINT_FW1 — SYNTHETIC Telnet admin-policy fallback B

**Provenance:** **SYNTHETIC**, second legacy export-shaped directory, `rules.C` SHA-256 `E6FE95FD74FDC3336B0E56CA4D9C241DDCFA23DA791E8420D5687EC16824B7A4`; `objects.C` SHA-256 `75440D4D1EB5AB7FD35A7BE79FA2FFCCA0C66AAB6EF32A9D7A04B51348BD4F38`. Same public-export search limitation as RW-024.

**Ground truth (established before running the tool), every deliberate unsafe choice:** Rule 1 (lines 2–9) accepts Telnet (service TCP/23 in `objects.C` lines 6–9) from Any source to the Management_Server host, exposing cleartext administration at policy level if that service exists and rule is installed. Rule 2 (lines 11–18) drops all remaining traffic with tracking `none`; whether logging denied traffic is required is site policy and not scored as definite. No claim is made that this invented gateway is deployed.

**Tool output (actual, unedited):**

**RW025-CP CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (CheckPoint FW1)
[2/4] Fetching CheckPoint API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW025-CP.json
```

**RW025-CP generated JSON report (SHA-256 `085E509F38E5C9A6BD15AF79D194017B28D6F243EC37A965AC565BD83789B94D`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "CHECKPOINT_FW1",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Management hostname is not present in these exports",
                "knowledge-state": "unknown",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Firewall-1 policy exports do not identify the gateway hardware model",
                "knowledge-state": "unsupported",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Check Point release metadata was not found in the located files",
                "knowledge-state": "unknown",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "detail": "Firewall-1 policy exports do not describe gateway management daemons",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "detail": "Administrator databases are outside the supported FW1 export set",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "detail": "Firewall-1 policy exports do not contain gateway interface state",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "detail": "Gateway logging destinations are outside the supported FW1 export set",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "detail": "Gateway cryptographic settings are outside the supported FW1 export set",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": 2,
        "input-kind": "directory",
        "parser": "CheckPointFW1Parser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:01:14.541127",
        "device-type": "CHECKPOINT_FW1",
        "hostname": "checkpoint-device"
    },
    "remediation-summary": {
        "finding-count": 0,
        "priority-actions": [],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {}
    },
    "security-audit": {},
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: none; parser coverage again reports zero security policies.
- Detected but degraded: none.
- Missed entirely: **indeterminate**. The synthetic file family is insufficiently verified to assert that the Telnet admin policy was parsed incorrectly.
- False positives: none reported.
- Crashes/failures: no crash; the missing fixture/provenance prevents a reliable Check Point detection conclusion.

<a id="RW-026"></a>
### IOS_ROUTER — Captured Cisco 2901 IOS 15.7 router

**Provenance:** [External Oxidized r1 capture](https://github.com/tmullaly/oxidized/blob/master/r1), raw SHA-256 `12876DEB44D14799632578C2A95663806FC5C276AFAD870B8AE7CDB816B86632`. Different device from that archive's 2960 switch captures, but the same operator/source family.

**Ground truth (established before running the tool):** `snmp-server community public RO` uses a known default community. Local/enable credentials use type-5 hashes, a legacy storage format; hash values are not tested or repeated. Five NTP servers are declared without association authentication. VTY input is SSH-only, HTTP is disabled and a logging host is present, so Telnet/HTTP/missing-remote-log findings would be wrong. `no aaa new-model` indicates no centralized AAA, but a small site may deliberately use local administration.

**Tool output (actual, unedited):**

**RW026-ROUTER CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng
[2/4] Fetching Cisco API information
[2/4] Cisco API disable.
[3/4] Checking missconfiguration vulnerabilities
[3/4] Scanning configuration file using the following IOS plugins: ['PluginHTTP', 'PluginSSH', 'PluginIOSBaseline']
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW026-ROUTER.json
```

**RW026-ROUTER generated JSON report (SHA-256 `B7C6BEAAC221BB7FD7F51E3D00AD139A26795D587CCC069B4AC38E0E319D8877`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "IOS_ROUTER",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "IOS running configuration does not provide reliable model metadata",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 6,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoIOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:35:54.137174",
        "device-type": "IOS_ROUTER",
        "hostname": "R1"
    },
    "remediation-summary": {
        "finding-count": 25,
        "priority-actions": [
            {
                "recommendation": "Enforce SSHv2 with 'ip ssh version 2'.",
                "rule-id": "cisco.ios.ssh.protocol_version",
                "severity": "High",
                "title": "SSH protocol version 2 is not enforced"
            },
            {
                "recommendation": "Enable AAA new-model and define a tested local fallback before applying it to management lines.",
                "rule-id": "cisco.ios.aaa.new_model",
                "severity": "High",
                "title": "Centralized AAA is not enabled"
            },
            {
                "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
                "rule-id": "cisco.ios.console.authentication",
                "severity": "High",
                "title": "Console authentication is not explicitly secured"
            },
            {
                "recommendation": "Disable the AUX line using the complete Cisco hardening sequence unless it has an approved operational use.",
                "rule-id": "cisco.ios.auxiliary.enabled",
                "severity": "High",
                "title": "Auxiliary management line is not fully disabled"
            },
            {
                "recommendation": "Disable the line or bind it to a tested AAA login method.",
                "rule-id": "cisco.ios.auxiliary.authentication",
                "severity": "High",
                "title": "Active auxiliary line lacks resolved authentication"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 8,
            "Low": 3,
            "Medium": 14
        }
    },
    "security-audit": {
        "2.0.0. SSH protocol version 2 is not enforced": {
            "device": "IOS_ROUTER",
            "ease": "An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            "impact": "SSHv1 has fundamental protocol weaknesses and permits downgrade exposure where compatibility mode is allowed.",
            "observation": "The reachable SSH service uses compatibility mode (SSHv1 and SSHv2).",
            "recommendation": "Enforce SSHv2 with 'ip ssh version 2'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.protocol_version",
            "severity": "High",
            "title": "SSH protocol version 2 is not enforced"
        },
        "2.0.1. SSH negotiation timeout is unsafe": {
            "device": "IOS_ROUTER",
            "ease": "A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            "evidence": [
                "effective documented default: 120"
            ],
            "exploitability": "A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            "impact": "Long unauthenticated negotiations consume management-plane resources and leave sessions open unnecessarily.",
            "observation": "The effective SSH negotiation timeout is 120 seconds; the policy maximum is 60 seconds.",
            "recommendation": "Configure 'ip ssh time-out <1-60>'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.negotiation_timeout",
            "severity": "Low",
            "title": "SSH negotiation timeout is unsafe"
        },
        "2.0.10. Legacy SNMP community configured": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "snmp-server community <redacted> ro"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Community-based SNMP lacks modern per-user authentication and privacy protections.",
            "observation": "An SNMPv1/v2c community uses community-based SNMP, an exact default community. The value is redacted.",
            "recommendation": "Migrate to SNMPv3 authPriv, restrict managers, and remove v1/v2c communities.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.snmp.legacy_community",
            "severity": "Medium",
            "title": "Legacy SNMP community configured"
        },
        "2.0.11. Remote logging severity is insufficient": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "logging host 10.20.0.28"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative and security-relevant informational events may not be centralized.",
            "observation": "The remote logging threshold is 'not configured'.",
            "recommendation": "Configure 'logging trap informational' unless policy explicitly requires a different threshold.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.logging.severity",
            "severity": "Low",
            "title": "Remote logging severity is insufficient"
        },
        "2.0.12. Configuration-change logging is disabled": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "archive log config logging enable absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative changes can lack a local per-user, per-session command history.",
            "observation": "The effective archive log-config state does not enable configuration-change logging.",
            "recommendation": "Enable 'archive / log config / logging enable', suppress keys, and notify syslog.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html"
            ],
            "rule_id": "cisco.ios.configuration.change_logging",
            "severity": "Medium",
            "title": "Configuration-change logging is disabled"
        },
        "2.0.13. NTP authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 74.6.168.73"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '74.6.168.73' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.14. NTP authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 69.89.207.99"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '69.89.207.99' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.15. NTP authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 97.107.128.165"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '97.107.128.165' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.16. NTP authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 68.183.107.237 minpoll 10"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '68.183.107.237' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.17. NTP authentication is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 162.248.241.94"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '162.248.241.94' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.18. Login warning banner is missing": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No banner login or banner motd command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Users may not receive the organization's required authorized-use and monitoring notice.",
            "observation": "No login or message-of-the-day warning banner is configured.",
            "recommendation": "Configure an approved legal warning with 'banner login'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.banner.login",
            "severity": "Low",
            "title": "Login warning banner is missing"
        },
        "2.0.19. IP source routing is not explicitly disabled": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "no ip source-route absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Source-routed packets can bypass expected routing paths and trust boundaries on applicable releases.",
            "observation": "The configuration does not contain the IOS 'no ip source-route' hardening command.",
            "recommendation": "Configure 'no ip source-route'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ip.source_route",
            "severity": "Medium",
            "title": "IP source routing is not explicitly disabled"
        },
        "2.0.2. SSH VTY access is not source-restricted": {
            "device": "IOS_ROUTER",
            "ease": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "impact": "Any source with network reachability can attempt to access the SSH management service.",
            "observation": "At least one SSH-enabled VTY range lacks an inbound IPv4 or IPv6 access-class.",
            "recommendation": "Apply 'access-class <ACL> in' or 'ipv6 access-class <ACL> in' to every SSH-enabled VTY range.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.vty_access_restriction",
            "severity": "Medium",
            "title": "SSH VTY access is not source-restricted"
        },
        "2.0.20. Layer-3 interface hardening is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Loopback0",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Loopback0 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.21. Layer-3 interface hardening is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface GigabitEthernet0/0",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface GigabitEthernet0/0 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.22. Layer-3 interface hardening is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface GigabitEthernet0/1",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface GigabitEthernet0/1 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.23. Layer-3 interface hardening is incomplete": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Serial0/0/0",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Serial0/0/0 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.24. Control-plane policing is not attached": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No control-plane service-policy input"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Unrestricted control-plane traffic can contribute to CPU exhaustion and management outages.",
            "observation": "No input service policy is attached under control-plane configuration.",
            "recommendation": "Deploy a validated Control Plane Policing policy appropriate for the platform role.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/quality-of-service/quality-of-service/m_qos-plcshp-ctrl-pln-plc-0.html"
            ],
            "rule_id": "cisco.ios.control_plane.copp",
            "severity": "Medium",
            "title": "Control-plane policing is not attached"
        },
        "2.0.3. Centralized AAA is not enabled": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "aaa new-model not present or negated"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authentication, authorization, and accounting policy may be inconsistent and locally controlled.",
            "observation": "The effective configuration does not enable 'aaa new-model'.",
            "recommendation": "Enable AAA new-model and define a tested local fallback before applying it to management lines.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.aaa.new_model",
            "severity": "High",
            "title": "Centralized AAA is not enabled"
        },
        "2.0.4. Console authentication is not explicitly secured": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line con 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Physical or terminal-server access may reach an unintended authentication path.",
            "observation": "line con 0 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.console.authentication",
            "severity": "High",
            "title": "Console authentication is not explicitly secured"
        },
        "2.0.5. Auxiliary management line is not fully disabled": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line aux 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "An unused AUX port can provide an additional local, modem, or reverse-terminal management path.",
            "observation": "line aux 0 does not combine 'no exec', 'transport input none', and 'transport output none'.",
            "recommendation": "Disable the AUX line using the complete Cisco hardening sequence unless it has an approved operational use.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.auxiliary.enabled",
            "severity": "High",
            "title": "Auxiliary management line is not fully disabled"
        },
        "2.0.6. Active auxiliary line lacks resolved authentication": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line aux 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A reachable AUX session may use an unintended or line-password authentication path.",
            "observation": "line aux 0 is not disabled and lacks a resolvable local or AAA login binding.",
            "recommendation": "Disable the line or bind it to a tested AAA login method.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.auxiliary.authentication",
            "severity": "High",
            "title": "Active auxiliary line lacks resolved authentication"
        },
        "2.0.7. Local credential uses weak storage": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "username oxy secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
            "observation": "User 'oxy' uses 'secret' storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. The credential is redacted.",
            "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.local_storage",
            "severity": "High",
            "title": "Local credential uses weak storage"
        },
        "2.0.8. Local credential uses weak storage": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "username admin secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
            "observation": "User 'admin' uses 'secret' storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. The credential is redacted.",
            "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.local_storage",
            "severity": "High",
            "title": "Local credential uses weak storage"
        },
        "2.0.9. Enable credential uses weak storage": {
            "device": "IOS_ROUTER",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "enable secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Configuration disclosure can expose or accelerate recovery of the privileged credential.",
            "observation": "The enable credential uses storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. Its value is redacted.",
            "recommendation": "Replace it with a strong 'enable secret' algorithm and remove the enable password.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.enable_storage",
            "severity": "High",
            "title": "Enable credential uses weak storage"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: legacy SNMP, type-5 local/enable storage, five unauthenticated NTP servers and absence of centralized AAA.
- Detected but degraded: public is reported only as generic Medium legacy SNMP, not the High known-default value identified for HP and PIX.
- Missed entirely: a distinct known-default community finding. SSH-only VTY, disabled HTTP and configured remote logging are correctly not reported as absent.
- False positives: no definite one established; remote logging severity is policy-dependent.
- Crashes/failures: none.

<a id="RW-027"></a>
### IOS_SWITCH / IOS_CATALYST — Captured second Catalyst 2960 IOS 15.0 switch

**Provenance:** [External Oxidized switch capture](https://github.com/tmullaly/oxidized/blob/master/switch), raw SHA-256 `068A0B0C13513D9A5D5CB366B6A16AE0AEDC35AEB670AFBD709A07BCEF96F7C7`. A second device from the same operator's network, so it adds distinct configuration text without independent deployment-population evidence.

**Ground truth (established before running the tool):** `snmp-server community public RO` is a known default community. Local/enable credentials use type-5 hashes; five configured NTP servers lack association authentication. HTTP servers are explicitly disabled; SSH-only VTY 0–4, disabled/no-exec VTY 5–15 and a configured remote logging host are negative controls. The file does not expose usable plaintext credential values for strength judgment.

**Tool output (actual, unedited):**

**RW027-SW CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng
[2/4] Fetching Cisco API information
[2/4] Cisco API disable.
[3/4] Checking missconfiguration vulnerabilities
[3/4] Scanning configuration file using the following IOS plugins: ['PluginHTTP', 'PluginSSH', 'PluginIOSBaseline']
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW027-SW.json
```

**RW027-SW generated JSON report (SHA-256 `8C9478C3C06EDEF82CBC8853E2C29A2066B27592F31A38084F28BCF394193A0C`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "IOS_SWITCH",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "IOS running configuration does not provide reliable model metadata",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 10,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoIOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:35:54.611850",
        "device-type": "IOS_SWITCH",
        "hostname": "switch"
    },
    "remediation-summary": {
        "finding-count": 20,
        "priority-actions": [
            {
                "recommendation": "Enforce SSHv2 with 'ip ssh version 2'.",
                "rule-id": "cisco.ios.ssh.protocol_version",
                "severity": "High",
                "title": "SSH protocol version 2 is not enforced"
            },
            {
                "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
                "rule-id": "cisco.ios.vty.authorization",
                "severity": "High",
                "title": "VTY administrative authorization is incomplete"
            },
            {
                "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
                "rule-id": "cisco.ios.console.authentication",
                "severity": "High",
                "title": "Console authentication is not explicitly secured"
            },
            {
                "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
                "rule-id": "cisco.ios.credentials.local_storage",
                "severity": "High",
                "title": "Local credential uses weak storage"
            },
            {
                "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
                "rule-id": "cisco.ios.credentials.local_storage",
                "severity": "High",
                "title": "Local credential uses weak storage"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 6,
            "Low": 3,
            "Medium": 11
        }
    },
    "security-audit": {
        "2.0.0. SSH protocol version 2 is not enforced": {
            "device": "IOS_SWITCH",
            "ease": "An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            "impact": "SSHv1 has fundamental protocol weaknesses and permits downgrade exposure where compatibility mode is allowed.",
            "observation": "The reachable SSH service uses compatibility mode (SSHv1 and SSHv2).",
            "recommendation": "Enforce SSHv2 with 'ip ssh version 2'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.protocol_version",
            "severity": "High",
            "title": "SSH protocol version 2 is not enforced"
        },
        "2.0.1. SSH negotiation timeout is unsafe": {
            "device": "IOS_SWITCH",
            "ease": "A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            "evidence": [
                "effective documented default: 120"
            ],
            "exploitability": "A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            "impact": "Long unauthenticated negotiations consume management-plane resources and leave sessions open unnecessarily.",
            "observation": "The effective SSH negotiation timeout is 120 seconds; the policy maximum is 60 seconds.",
            "recommendation": "Configure 'ip ssh time-out <1-60>'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.negotiation_timeout",
            "severity": "Low",
            "title": "SSH negotiation timeout is unsafe"
        },
        "2.0.10. Configuration-change logging is disabled": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "archive log config logging enable absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative changes can lack a local per-user, per-session command history.",
            "observation": "The effective archive log-config state does not enable configuration-change logging.",
            "recommendation": "Enable 'archive / log config / logging enable', suppress keys, and notify syslog.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html"
            ],
            "rule_id": "cisco.ios.configuration.change_logging",
            "severity": "Medium",
            "title": "Configuration-change logging is disabled"
        },
        "2.0.11. NTP authentication is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 97.107.128.165"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '97.107.128.165' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.12. NTP authentication is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 74.6.168.73"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '74.6.168.73' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.13. NTP authentication is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 162.248.241.94"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '162.248.241.94' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.14. NTP authentication is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 69.89.207.99"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '69.89.207.99' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.15. NTP authentication is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 68.183.107.237"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '68.183.107.237' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.16. Login warning banner is missing": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No banner login or banner motd command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Users may not receive the organization's required authorized-use and monitoring notice.",
            "observation": "No login or message-of-the-day warning banner is configured.",
            "recommendation": "Configure an approved legal warning with 'banner login'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.banner.login",
            "severity": "Low",
            "title": "Login warning banner is missing"
        },
        "2.0.17. IP source routing is not explicitly disabled": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "no ip source-route absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Source-routed packets can bypass expected routing paths and trust boundaries on applicable releases.",
            "observation": "The configuration does not contain the IOS 'no ip source-route' hardening command.",
            "recommendation": "Configure 'no ip source-route'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ip.source_route",
            "severity": "Medium",
            "title": "IP source routing is not explicitly disabled"
        },
        "2.0.18. Layer-3 interface hardening is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Vlan10",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Vlan10 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.19. Control-plane policing is not attached": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No control-plane service-policy input"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Unrestricted control-plane traffic can contribute to CPU exhaustion and management outages.",
            "observation": "No input service policy is attached under control-plane configuration.",
            "recommendation": "Deploy a validated Control Plane Policing policy appropriate for the platform role.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/quality-of-service/quality-of-service/m_qos-plcshp-ctrl-pln-plc-0.html"
            ],
            "rule_id": "cisco.ios.control_plane.copp",
            "severity": "Medium",
            "title": "Control-plane policing is not attached"
        },
        "2.0.2. SSH VTY access is not source-restricted": {
            "device": "IOS_SWITCH",
            "ease": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "impact": "Any source with network reachability can attempt to access the SSH management service.",
            "observation": "At least one SSH-enabled VTY range lacks an inbound IPv4 or IPv6 access-class.",
            "recommendation": "Apply 'access-class <ACL> in' or 'ipv6 access-class <ACL> in' to every SSH-enabled VTY range.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.vty_access_restriction",
            "severity": "Medium",
            "title": "SSH VTY access is not source-restricted"
        },
        "2.0.3. VTY administrative authorization is incomplete": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4",
                "authorization exec userAuthorization",
                "login authentication userAuthentication",
                "transport input ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
            "observation": "line vty 0 4 lacks resolved privilege-15 command authorization.",
            "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authorization",
            "severity": "High",
            "title": "VTY administrative authorization is incomplete"
        },
        "2.0.4. Console authentication is not explicitly secured": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line con 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Physical or terminal-server access may reach an unintended authentication path.",
            "observation": "line con 0 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.console.authentication",
            "severity": "High",
            "title": "Console authentication is not explicitly secured"
        },
        "2.0.5. Local credential uses weak storage": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "username oxy secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
            "observation": "User 'oxy' uses 'secret' storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. The credential is redacted.",
            "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.local_storage",
            "severity": "High",
            "title": "Local credential uses weak storage"
        },
        "2.0.6. Local credential uses weak storage": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "username admin secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
            "observation": "User 'admin' uses 'secret' storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. The credential is redacted.",
            "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.local_storage",
            "severity": "High",
            "title": "Local credential uses weak storage"
        },
        "2.0.7. Enable credential uses weak storage": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "enable secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Configuration disclosure can expose or accelerate recovery of the privileged credential.",
            "observation": "The enable credential uses storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. Its value is redacted.",
            "recommendation": "Replace it with a strong 'enable secret' algorithm and remove the enable password.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.enable_storage",
            "severity": "High",
            "title": "Enable credential uses weak storage"
        },
        "2.0.8. Legacy SNMP community configured": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "snmp-server community <redacted> ro"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Community-based SNMP lacks modern per-user authentication and privacy protections.",
            "observation": "An SNMPv1/v2c community uses community-based SNMP, an exact default community. The value is redacted.",
            "recommendation": "Migrate to SNMPv3 authPriv, restrict managers, and remove v1/v2c communities.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.snmp.legacy_community",
            "severity": "Medium",
            "title": "Legacy SNMP community configured"
        },
        "2.0.9. Remote logging severity is insufficient": {
            "device": "IOS_SWITCH",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "logging host 10.20.0.28"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative and security-relevant informational events may not be centralized.",
            "observation": "The remote logging threshold is 'not configured'.",
            "recommendation": "Configure 'logging trap informational' unless policy explicitly requires a different threshold.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.logging.severity",
            "severity": "Low",
            "title": "Remote logging severity is insufficient"
        }
    },
    "vulnerabilities": []
}
```

**RW027-CAT CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng
[2/4] Fetching Cisco API information
[2/4] Cisco API disable.
[3/4] Checking missconfiguration vulnerabilities
[3/4] Scanning configuration file using the following IOS plugins: ['PluginHTTP', 'PluginSSH', 'PluginIOSBaseline']
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW027-CAT.json
```

**RW027-CAT generated JSON report (SHA-256 `743C63916822EE4E410456AEB46986F5693E0F86714B0197F9EF5AA6346AB8F0`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "IOS_CATALYST",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "IOS running configuration does not provide reliable model metadata",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 10,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "CiscoIOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:35:55.072978",
        "device-type": "IOS_CATALYST",
        "hostname": "switch"
    },
    "remediation-summary": {
        "finding-count": 20,
        "priority-actions": [
            {
                "recommendation": "Enforce SSHv2 with 'ip ssh version 2'.",
                "rule-id": "cisco.ios.ssh.protocol_version",
                "severity": "High",
                "title": "SSH protocol version 2 is not enforced"
            },
            {
                "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
                "rule-id": "cisco.ios.vty.authorization",
                "severity": "High",
                "title": "VTY administrative authorization is incomplete"
            },
            {
                "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
                "rule-id": "cisco.ios.console.authentication",
                "severity": "High",
                "title": "Console authentication is not explicitly secured"
            },
            {
                "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
                "rule-id": "cisco.ios.credentials.local_storage",
                "severity": "High",
                "title": "Local credential uses weak storage"
            },
            {
                "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
                "rule-id": "cisco.ios.credentials.local_storage",
                "severity": "High",
                "title": "Local credential uses weak storage"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 6,
            "Low": 3,
            "Medium": 11
        }
    },
    "security-audit": {
        "2.0.0. SSH protocol version 2 is not enforced": {
            "device": "IOS_CATALYST",
            "ease": "An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An on-path attacker may be able to exploit SSHv1 weaknesses or force use of the legacy protocol.",
            "impact": "SSHv1 has fundamental protocol weaknesses and permits downgrade exposure where compatibility mode is allowed.",
            "observation": "The reachable SSH service uses compatibility mode (SSHv1 and SSHv2).",
            "recommendation": "Enforce SSHv2 with 'ip ssh version 2'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.protocol_version",
            "severity": "High",
            "title": "SSH protocol version 2 is not enforced"
        },
        "2.0.1. SSH negotiation timeout is unsafe": {
            "device": "IOS_CATALYST",
            "ease": "A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            "evidence": [
                "effective documented default: 120"
            ],
            "exploitability": "A reachable attacker can hold multiple unauthenticated SSH negotiations open.",
            "impact": "Long unauthenticated negotiations consume management-plane resources and leave sessions open unnecessarily.",
            "observation": "The effective SSH negotiation timeout is 120 seconds; the policy maximum is 60 seconds.",
            "recommendation": "Configure 'ip ssh time-out <1-60>'.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.negotiation_timeout",
            "severity": "Low",
            "title": "SSH negotiation timeout is unsafe"
        },
        "2.0.10. Configuration-change logging is disabled": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "archive log config logging enable absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative changes can lack a local per-user, per-session command history.",
            "observation": "The effective archive log-config state does not enable configuration-change logging.",
            "recommendation": "Enable 'archive / log config / logging enable', suppress keys, and notify syslog.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html"
            ],
            "rule_id": "cisco.ios.configuration.change_logging",
            "severity": "Medium",
            "title": "Configuration-change logging is disabled"
        },
        "2.0.11. NTP authentication is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 97.107.128.165"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '97.107.128.165' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.12. NTP authentication is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 74.6.168.73"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '74.6.168.73' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.13. NTP authentication is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 162.248.241.94"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '162.248.241.94' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.14. NTP authentication is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 69.89.207.99"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '69.89.207.99' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.15. NTP authentication is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "ntp server 68.183.107.237"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "A spoofed time source can disrupt logs and time-dependent security controls.",
            "observation": "NTP server '68.183.107.237' in VRF 'default' has no effective authenticated key binding.",
            "recommendation": "Enable NTP authentication and configure, trust, and bind a key for this association.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ntp.authentication",
            "severity": "Medium",
            "title": "NTP authentication is incomplete"
        },
        "2.0.16. Login warning banner is missing": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No banner login or banner motd command"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Users may not receive the organization's required authorized-use and monitoring notice.",
            "observation": "No login or message-of-the-day warning banner is configured.",
            "recommendation": "Configure an approved legal warning with 'banner login'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.banner.login",
            "severity": "Low",
            "title": "Login warning banner is missing"
        },
        "2.0.17. IP source routing is not explicitly disabled": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "no ip source-route absent"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Source-routed packets can bypass expected routing paths and trust boundaries on applicable releases.",
            "observation": "The configuration does not contain the IOS 'no ip source-route' hardening command.",
            "recommendation": "Configure 'no ip source-route'.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.ip.source_route",
            "severity": "Medium",
            "title": "IP source routing is not explicitly disabled"
        },
        "2.0.18. Layer-3 interface hardening is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "interface Vlan10",
                "no ip redirects",
                "no ip proxy-arp"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
            "observation": "interface Vlan10 lacks no ip redirects, no ip proxy-arp.",
            "recommendation": "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.interface.ip_hardening",
            "severity": "Medium",
            "title": "Layer-3 interface hardening is incomplete"
        },
        "2.0.19. Control-plane policing is not attached": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "No control-plane service-policy input"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Unrestricted control-plane traffic can contribute to CPU exhaustion and management outages.",
            "observation": "No input service policy is attached under control-plane configuration.",
            "recommendation": "Deploy a validated Control Plane Policing policy appropriate for the platform role.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/quality-of-service/quality-of-service/m_qos-plcshp-ctrl-pln-plc-0.html"
            ],
            "rule_id": "cisco.ios.control_plane.copp",
            "severity": "Medium",
            "title": "Control-plane policing is not attached"
        },
        "2.0.2. SSH VTY access is not source-restricted": {
            "device": "IOS_CATALYST",
            "ease": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "evidence": [
                "line vty 0 4"
            ],
            "exploitability": "An attacker can probe and brute-force SSH from any network permitted by upstream controls.",
            "impact": "Any source with network reachability can attempt to access the SSH management service.",
            "observation": "At least one SSH-enabled VTY range lacks an inbound IPv4 or IPv6 access-class.",
            "recommendation": "Apply 'access-class <ACL> in' or 'ipv6 access-class <ACL> in' to every SSH-enabled VTY range.",
            "references": [
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html"
            ],
            "rule_id": "cisco.ios.ssh.vty_access_restriction",
            "severity": "Medium",
            "title": "SSH VTY access is not source-restricted"
        },
        "2.0.3. VTY administrative authorization is incomplete": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line vty 0 4",
                "authorization exec userAuthorization",
                "login authentication userAuthentication",
                "transport input ssh"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
            "observation": "line vty 0 4 lacks resolved privilege-15 command authorization.",
            "recommendation": "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.vty.authorization",
            "severity": "High",
            "title": "VTY administrative authorization is incomplete"
        },
        "2.0.4. Console authentication is not explicitly secured": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "line con 0"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Physical or terminal-server access may reach an unintended authentication path.",
            "observation": "line con 0 lacks a resolvable local or AAA login binding.",
            "recommendation": "Bind the console to a tested AAA login method with an appropriate local recovery path.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.console.authentication",
            "severity": "High",
            "title": "Console authentication is not explicitly secured"
        },
        "2.0.5. Local credential uses weak storage": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "username oxy secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
            "observation": "User 'oxy' uses 'secret' storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. The credential is redacted.",
            "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.local_storage",
            "severity": "High",
            "title": "Local credential uses weak storage"
        },
        "2.0.6. Local credential uses weak storage": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "username admin secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
            "observation": "User 'admin' uses 'secret' storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. The credential is redacted.",
            "recommendation": "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.local_storage",
            "severity": "High",
            "title": "Local credential uses weak storage"
        },
        "2.0.7. Enable credential uses weak storage": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "enable secret 5 <credential redacted>"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Configuration disclosure can expose or accelerate recovery of the privileged credential.",
            "observation": "The enable credential uses storage type '5', classified as 'weak_hash' under credential policy 'pynipper-v2/default-v1'; the separate blocklist comparison was not evaluated against a supplied credential blocklist. Its value is redacted.",
            "recommendation": "Replace it with a strong 'enable secret' algorithm and remove the enable password.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.credentials.enable_storage",
            "severity": "High",
            "title": "Enable credential uses weak storage"
        },
        "2.0.8. Legacy SNMP community configured": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "snmp-server community <redacted> ro"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Community-based SNMP lacks modern per-user authentication and privacy protections.",
            "observation": "An SNMPv1/v2c community uses community-based SNMP, an exact default community. The value is redacted.",
            "recommendation": "Migrate to SNMPv3 authPriv, restrict managers, and remove v1/v2c communities.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.snmp.legacy_community",
            "severity": "Medium",
            "title": "Legacy SNMP community configured"
        },
        "2.0.9. Remote logging severity is insufficient": {
            "device": "IOS_CATALYST",
            "ease": "An attacker with management-plane or configuration access may exploit this weakness.",
            "evidence": [
                "logging host 10.20.0.28"
            ],
            "exploitability": "An attacker with management-plane or configuration access may exploit this weakness.",
            "impact": "Administrative and security-relevant informational events may not be centralized.",
            "observation": "The remote logging threshold is 'not configured'.",
            "recommendation": "Configure 'logging trap informational' unless policy explicitly requires a different threshold.",
            "references": [
                "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
            ],
            "rule_id": "cisco.ios.logging.severity",
            "severity": "Low",
            "title": "Remote logging severity is insufficient"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: type-5 credential storage and unauthenticated NTP; IOS_SWITCH and IOS_CATALYST runs agree.
- Detected but degraded: public community again receives only generic legacy-SNMP severity.
- Missed entirely: distinct known-default public community alert.
- False positives: no proven Telnet, HTTP or absent-remote-logging alert; the configured negative controls behave as expected.
- Crashes/failures: none.

<a id="RW-028"></a>
### ARISTA_EOS — Third intended EVPN leaf in the community AVD lab

**Provenance:** [Arista NetDevOps LEAF2B intended config](https://github.com/arista-netdevops-community/avd-evpn-webinar-june-11/blob/master/intended/configs/LEAF2B.cfg), raw SHA-256 `5BE52046C9C7ACD9F3837C5FE4E375EFFE15D2ECE0878A1E23676AA324A87DB8`. Same lab as RW-005 and RW-009; it tests another full intended device but does not count as independent operator corroboration.

**Ground truth (established before running the tool):** NTP servers under MGMT VRF have no authentication/key binding. The RADIUS key uses reversible type-7 storage and a running TerminAttr command contains a literal ingestion token; no token bytes are copied here. The console/management reachability and credential reuse of this lab are unknown. This is a corroborating input, not a new control hypothesis.

**Tool output (actual, unedited):**

**RW028-EOS CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Arista EOS)
[2/4] Fetching Arista API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW028-EOS.json
```

**RW028-EOS generated JSON report (SHA-256 `C4B0FCADA66DCAF7E5435552BF8BFAAFFE7DD25D8CC6750549C7FABA3C33DAB5`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "ARISTA_EOS",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Model metadata absent",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "EOS version absent",
                "knowledge-state": "unknown",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 1,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 3,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "detail": "EOS interface roles are not normalized in this revision",
                "item-count": null,
                "knowledge-state": "unknown",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "detail": "EOS is not parsed as a firewall policy platform",
                "item-count": null,
                "knowledge-state": "unsupported",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "AristaEOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:35:55.508703",
        "device-type": "ARISTA_EOS",
        "hostname": "LEAF2B"
    },
    "remediation-summary": {
        "finding-count": 7,
        "priority-actions": [
            {
                "recommendation": "Configure 'aaa authorization commands all default' using the approved service and controlled fallback.",
                "rule-id": "arista.eos.authorization.commands",
                "severity": "High",
                "title": "Centralized login lacks command authorization"
            },
            {
                "recommendation": "Apply explicit IPv4 and, where applicable, IPv6 service ACLs to each enabled eAPI VRF.",
                "rule-id": "arista.eos.eapi.source_restriction",
                "severity": "Medium",
                "title": "eAPI endpoint lacks a service ACL"
            },
            {
                "recommendation": "Configure default EXEC and all-command accounting to TACACS+, RADIUS, or protected syslog.",
                "rule-id": "arista.eos.authentication.accounting",
                "severity": "Medium",
                "title": "Centralized administrative access lacks complete accounting"
            },
            {
                "recommendation": "Attach a named SSL profile with an approved certificate and TLS 1.2 or 1.3 policy.",
                "rule-id": "arista.eos.eapi.tls_profile",
                "severity": "Medium",
                "title": "eAPI HTTPS lacks an explicit SSL profile"
            },
            {
                "recommendation": "Apply IPv4 and, where applicable, IPv6 access groups in management SSH configuration for each management VRF.",
                "rule-id": "arista.eos.ssh.source_restriction",
                "severity": "Medium",
                "title": "Explicit SSH service policy lacks access groups"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 1,
            "Medium": 6
        }
    },
    "security-audit": {
        "11.0.0. eAPI endpoint lacks a service ACL": {
            "device": "ARISTA_EOS",
            "ease": "Any host with VRF reachability can probe the service or attempt authentication.",
            "evidence": [
                "management api http-commands",
                "vrf MGMT",
                "no shutdown"
            ],
            "exploitability": "Any host with VRF reachability can probe the service or attempt authentication.",
            "impact": "All routed clients in the endpoint VRF can attempt API access.",
            "observation": "The active eAPI endpoint in VRF 'MGMT' has no IPv4 or IPv6 access-group.",
            "recommendation": "Apply explicit IPv4 and, where applicable, IPv6 service ACLs to each enabled eAPI VRF.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-acls-and-route-maps"
            ],
            "rule_id": "arista.eos.eapi.source_restriction",
            "severity": "Medium",
            "title": "eAPI endpoint lacks a service ACL"
        },
        "11.0.1. Centralized login lacks command authorization": {
            "device": "ARISTA_EOS",
            "ease": "A compromised account can receive broader CLI access than the identity service intended.",
            "evidence": [
                "centralized login authentication without all-command authorization"
            ],
            "exploitability": "A compromised account can receive broader CLI access than the identity service intended.",
            "impact": "Authenticated users may execute commands outside the intended central or local RBAC policy.",
            "observation": "Remote login authentication is configured without an effective default all-command authorization method list.",
            "recommendation": "Configure 'aaa authorization commands all default' using the approved service and controlled fallback.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-user-security"
            ],
            "rule_id": "arista.eos.authorization.commands",
            "severity": "High",
            "title": "Centralized login lacks command authorization"
        },
        "11.0.2. Centralized administrative access lacks complete accounting": {
            "device": "ARISTA_EOS",
            "ease": "A compromised administrator can act with reduced centralized evidence.",
            "evidence": [
                "default EXEC/all-command accounting incomplete"
            ],
            "exploitability": "A compromised administrator can act with reduced centralized evidence.",
            "impact": "Login sessions or executed commands may lack an independent audit trail.",
            "observation": "Default AAA accounting is missing for: commands-all, exec.",
            "recommendation": "Configure default EXEC and all-command accounting to TACACS+, RADIUS, or protected syslog.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-user-security"
            ],
            "rule_id": "arista.eos.authentication.accounting",
            "severity": "Medium",
            "title": "Centralized administrative access lacks complete accounting"
        },
        "11.0.3. eAPI HTTPS lacks an explicit SSL profile": {
            "device": "ARISTA_EOS",
            "ease": "Administrators may receive an unexpected certificate or negotiate an unintended legacy protocol.",
            "evidence": [
                "management api http-commands",
                "vrf MGMT",
                "no shutdown"
            ],
            "exploitability": "Administrators may receive an unexpected certificate or negotiate an unintended legacy protocol.",
            "impact": "Certificate identity and TLS-version policy remain dependent on an implicit service default.",
            "observation": "The active HTTPS eAPI endpoint in VRF 'MGMT' does not attach an SSL profile.",
            "recommendation": "Attach a named SSL profile with an approved certificate and TLS 1.2 or 1.3 policy.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-control-plane-security",
                "https://www.arista.com/en/um-eos/eos-session-management-commands"
            ],
            "rule_id": "arista.eos.eapi.tls_profile",
            "severity": "Medium",
            "title": "eAPI HTTPS lacks an explicit SSL profile"
        },
        "11.0.4. Explicit SSH service policy lacks access groups": {
            "device": "ARISTA_EOS",
            "ease": "A reachable attacker can probe the daemon, guess credentials, or target SSH implementation flaws.",
            "evidence": [
                "management ssh",
                "vrf MGMT",
                "no shutdown"
            ],
            "exploitability": "A reachable attacker can probe the daemon, guess credentials, or target SSH implementation flaws.",
            "impact": "Every routed source that can reach the switch can attempt SSH authentication.",
            "observation": "A management SSH block is configured without an IPv4 or IPv6 service ACL.",
            "recommendation": "Apply IPv4 and, where applicable, IPv6 access groups in management SSH configuration for each management VRF.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-acls-and-route-maps",
                "https://www.arista.com/en/um-eos/eos-session-management-commands"
            ],
            "rule_id": "arista.eos.ssh.source_restriction",
            "severity": "Medium",
            "title": "Explicit SSH service policy lacks access groups"
        },
        "11.0.5. Centralized login lacks exec authorization": {
            "device": "ARISTA_EOS",
            "ease": "A compromised or overprivileged account can exercise commands not constrained by centralized authorization.",
            "evidence": [
                "centralized login authentication without aaa authorization exec"
            ],
            "exploitability": "A compromised or overprivileged account can exercise commands not constrained by centralized authorization.",
            "impact": "Authenticated users may receive locally determined command access that is broader than central policy intends.",
            "observation": "RADIUS or TACACS+ login authentication is configured without an active centralized exec authorization method.",
            "recommendation": "Configure AAA exec authorization through the approved central service with a controlled local fallback.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-security"
            ],
            "rule_id": "arista.eos.authorization.exec",
            "severity": "Medium",
            "title": "Centralized login lacks exec authorization"
        },
        "11.0.6. No remote syslog destination is configured": {
            "device": "ARISTA_EOS",
            "ease": "An attacker with device access benefits from reduced external evidence.",
            "evidence": [
                "remote logging destination absent"
            ],
            "exploitability": "An attacker with device access benefits from reduced external evidence.",
            "impact": "Security events may be lost through local rollover or device compromise.",
            "observation": "No active 'logging host' destination was found.",
            "recommendation": "Configure protected, redundant remote syslog destinations.",
            "references": [
                "https://www.arista.com/en/um-eos/eos-security"
            ],
            "rule_id": "arista.eos.logging.remote_destination",
            "severity": "Medium",
            "title": "No remote syslog destination is configured"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: none of the three explicit NTP/key/token concerns.
- Detected but degraded: no definite related finding.
- Missed entirely: unauthenticated NTP, reversible RADIUS key storage and plaintext TerminAttr ingestion token, corroborating RW-005/RW-009 within the same lab.
- False positives: no definite one; management-source/AAA assertions still depend on MGMT topology.
- Crashes/failures: none.

<a id="RW-029"></a>
### JUNOS — Published SRX uplink-monitoring example with global permit-all

**Provenance:** [SRX IP-monitoring example](https://gist.github.com/Jamesits/f8d0f88e2ab02ccf5dd8c1f7030e13ad), raw gist revision `5c357af0af920c81e558840d22cbd827ef2449b7`; SHA-256 `4B684D69BDA27989789FBC66015B0F09753ABABC6EAD361A2F922BA885323A84`. This is a configuration *example* centered on uplink failover, not a confirmed full running export.

**Ground truth (established before running the tool):** `security policies default-policy permit-all` explicitly changes the global inter-zone fallback to allow traffic unmatched by explicit policies. In this example no explicit inter-zone policy rules are shown; if committed, the broad default could permit unintended zone crossings. Zone host-inbound settings still govern traffic to the device itself, so this is not asserted as unrestricted administrative access. Applied group definitions for zone services/screens need resolution; absence elsewhere in the excerpt is unknown.

**Tool output (actual, unedited):**

**RW029-JUNOS CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Juniper JunOS)
[2/4] Fetching JunOS API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW029-JUNOS.json
```

**RW029-JUNOS generated JSON report (SHA-256 `4CB881E7B7807C14E8EEDE3303178FF4DC85A2CE5D48F838C86DEC59B820D04B`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "JUNOS",
        "diagnostics": [
            "apply-groups is preserved but group inheritance is not expanded"
        ],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "No active system host-name statement",
                "knowledge-state": "unknown",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Model metadata is not present",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "Version metadata is not present",
                "knowledge-state": "unknown",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 3,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "JunOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 18:35:55.769730",
        "device-type": "JUNOS",
        "hostname": "junos-device"
    },
    "remediation-summary": {
        "finding-count": 0,
        "priority-actions": [],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {}
    },
    "security-audit": {},
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: none; the JSON has zero security-audit findings.
- Detected but degraded: none.
- Missed entirely: the explicit global default-policy permit-all. [Juniper's command reference](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-default-policy.html) says it permits traffic unmatched by user-defined policy; this is a concrete fail-open transit-policy setting.
- False positives: none reported. Coverage nevertheless says security-policies known with item-count zero despite the explicit default-policy command; the only diagnostic concerns group inheritance, not a parse error.
- Crashes/failures: none; successful exit makes the silent miss especially easy to misread as a clean policy.

<a id="RW-030"></a>
### PAN_OS — Palo Alto Networks Azure multi-IP bootstrap sample

**Provenance:** [Vendor multi-IP bootstrap XML](https://github.com/PaloAltoNetworks/multi-ip/blob/master/bootstrap.xml), raw SHA-256 `BB0163D10A71F9282E039CC029B0E82EC29217C5C0D938A9AF7065814C99C77E`. This is a publishable reference deployment sample for PAN-OS 8.0, not proof of a live firewall's running state.

**Ground truth (established before running the tool):** The `Allow web-browsing In` security rule permits application `web-browsing` from Untrust to Trust with source `any` and destination `any`, whereas the sample's inbound NAT destinations are specific. If deployed with broader Trust routes, the security rule grants broader HTTP reachability than those named NAT targets; this is a conditional scoping concern, not proof that all Trust hosts are reachable. The `Allow All Out` rule permits any application/service from Trust to Untrust with any endpoints; this is a broad egress choice, whose severity depends on the site's policy. The XML enables password complexity, disables Telnet/HTTP management, and enables update installation, so absence or insecure-service findings on those controls would be wrong. Its two local admin password hashes are not exposed plaintext and their actual strength is unknown. No finding is claimed solely from missing NTP/syslog in this bootstrap sample.

**Tool output (actual, unedited):**

**RW030-PAN CLI stdout (exit 0):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Palo Alto PAN-OS)
[2/4] Fetching PAN-OS API information
[3/4] Checking misconfiguration vulnerabilities
[4/4] Generating report
Generated new JSON report file in C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\RW030-PAN.json
```

**RW030-PAN generated JSON report (SHA-256 `5E77BDFB6344493C543B4BC629DD19CEF48D8BC5706A8B1D072DD2A612B6E3FE`):**

```json
{
    "configuration-inventory": {},
    "coverage": {
        "device-type": "PAN_OS",
        "diagnostics": [],
        "fields": [
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "hostname"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "detail": "PAN-OS model metadata was not present",
                "knowledge-state": "unknown",
                "name": "device-model"
            },
            {
                "audit-selection": "included",
                "category": "inventory",
                "knowledge-state": "known",
                "name": "software-version"
            },
            {
                "audit-selection": "included",
                "category": "services",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "management-services"
            },
            {
                "audit-selection": "included",
                "category": "credentials",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "local-users"
            },
            {
                "audit-selection": "included",
                "category": "interfaces",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "interfaces"
            },
            {
                "audit-selection": "included",
                "category": "filtering",
                "item-count": 2,
                "knowledge-state": "known",
                "name": "security-policies"
            },
            {
                "audit-selection": "included",
                "category": "logging",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "logging-destinations"
            },
            {
                "audit-selection": "included",
                "category": "crypto",
                "item-count": 0,
                "knowledge-state": "known",
                "name": "crypto-settings"
            }
        ],
        "input-artifact-count": null,
        "input-kind": "file",
        "parser": "PaloAltoPANOSParser",
        "schema-version": 1,
        "scope-note": "Known means the supplied export was parsed for this normalized field; it is not a passed security check. Unknown, unsupported, parse-error, and excluded scope is not implied secure."
    },
    "data": {
        "assessment-policy": {
            "assessment-time": null,
            "configuration-backup-scope": "unspecified",
            "credential-blocklist-sha256-count": 0,
            "device-role": "unknown",
            "excluded-categories": [],
            "interface-roles": {},
            "management-certificate-identities": {},
            "minimum-plaintext-credential-length": null,
            "policy-version": "pynipper-v2/default-v1",
            "protected-aaa-profiles": [],
            "provenance": "built-in default",
            "report-inventory": [],
            "scope-note": "Excluded categories were not assessed and are not implied secure.",
            "trusted-certificate-sha256": []
        },
        "date": "2026-09-21 22:06:54.205557",
        "device-type": "PAN_OS",
        "hostname": "VM-FW1"
    },
    "remediation-summary": {
        "finding-count": 12,
        "priority-actions": [
            {
                "recommendation": "Attach the organization's approved Security Profile Group or explicit profiles to the allow rule.",
                "rule-id": "paloalto.panos.policy.security_profiles",
                "severity": "High",
                "title": "Allow rule has no security profile attachment"
            },
            {
                "recommendation": "Attach the organization's approved Security Profile Group or explicit profiles to the allow rule.",
                "rule-id": "paloalto.panos.policy.security_profiles",
                "severity": "High",
                "title": "Allow rule has no security profile attachment"
            },
            {
                "recommendation": "Enable password complexity and require at least 12 characters with uppercase, lowercase, numeric, and special-character minima, or apply the approved organizational benchmark.",
                "rule-id": "paloalto.panos.credentials.password_complexity",
                "severity": "High",
                "title": "Management password complexity is insufficient"
            },
            {
                "recommendation": "Attach a same-vsys Log Forwarding profile with an active syslog destination and enable session-end logging.",
                "rule-id": "paloalto.panos.policy.log_forwarding",
                "severity": "Medium",
                "title": "Allow rule lacks effective centralized log forwarding"
            },
            {
                "recommendation": "Enable log-at-session-end on the rule unless a documented exception applies.",
                "rule-id": "paloalto.panos.policy.session_logging",
                "severity": "Medium",
                "title": "Allow rule does not log at session end"
            }
        ],
        "scope-note": "This is a concise prioritization of emitted findings, not a compliance score. Review the coverage ledger for unknown, unsupported, parse-error, or excluded scope.",
        "severity-counts": {
            "High": 3,
            "Low": 1,
            "Medium": 8
        }
    },
    "security-audit": {
        "7.0.0. Allow rule lacks effective centralized log forwarding": {
            "device": "PAN_OS",
            "ease": "Reduced centralized telemetry can delay detection and investigation of malicious traffic.",
            "evidence": [
                "localhost.localdomain/vsys1/rulebase: security rule 1 Allow web-browsing In"
            ],
            "exploitability": "Reduced centralized telemetry can delay detection and investigation of malicious traffic.",
            "impact": "Traffic and threat events may remain only in limited local storage and be unavailable to central monitoring.",
            "observation": "Enabled allow rule 'Allow web-browsing In' in 'vsys1' references 'no log-forwarding profile', which does not resolve to a same-scope profile with a syslog destination.",
            "recommendation": "Attach a same-vsys Log Forwarding profile with an active syslog destination and enable session-end logging.",
            "references": [
                "https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/log-forwarding"
            ],
            "rule_id": "paloalto.panos.policy.log_forwarding",
            "severity": "Medium",
            "title": "Allow rule lacks effective centralized log forwarding"
        },
        "7.0.1. Allow rule does not log at session end": {
            "device": "PAN_OS",
            "ease": "Incomplete traffic records reduce visibility into successful or long-lived malicious sessions.",
            "evidence": [
                "localhost.localdomain/vsys1/rulebase: security rule 1 Allow web-browsing In"
            ],
            "exploitability": "Incomplete traffic records reduce visibility into successful or long-lived malicious sessions.",
            "impact": "Completed-session byte counts, duration, and final application information may not be recorded.",
            "observation": "Enabled allow rule 'Allow web-browsing In' in 'vsys1' does not enable log-at-session-end.",
            "recommendation": "Enable log-at-session-end on the rule unless a documented exception applies.",
            "references": [
                "https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/security-policy-best-practices/deploy-security-policy-best-practices/security-policy-rule-best-practices"
            ],
            "rule_id": "paloalto.panos.policy.session_logging",
            "severity": "Medium",
            "title": "Allow rule does not log at session end"
        },
        "7.0.10. No NTP servers are configured": {
            "device": "PAN_OS",
            "ease": "Inconsistent time reduces the reliability of monitoring and forensic timelines.",
            "evidence": [
                "deviceconfig system ntp-servers absent"
            ],
            "exploitability": "Inconsistent time reduces the reliability of monitoring and forensic timelines.",
            "impact": "Incorrect timestamps hinder log correlation, authentication, and certificate validation.",
            "observation": "Neither a primary nor secondary NTP server address was found in local device configuration.",
            "recommendation": "Configure redundant trusted primary and secondary NTP servers.",
            "references": [
                "https://docs.paloaltonetworks.com/ngfw/getting-started/initial-setup-configuration-ngfws"
            ],
            "rule_id": "paloalto.panos.ntp.servers",
            "severity": "Low",
            "title": "No NTP servers are configured"
        },
        "7.0.11. System events lack a syslog forwarding destination": {
            "device": "PAN_OS",
            "ease": "An attacker who compromises the firewall benefits from reduced off-device audit evidence.",
            "evidence": [
                "deviceconfig system log-settings system syslog destination absent"
            ],
            "exploitability": "An attacker who compromises the firewall benefits from reduced off-device audit evidence.",
            "impact": "Administrative, update, high-availability, and system events may remain only on the appliance.",
            "observation": "No device-level system log match entry sends events to a syslog server profile.",
            "recommendation": "Configure Device Log Settings for system events and send relevant severities to protected centralized syslog destinations.",
            "references": [
                "https://docs.paloaltonetworks.com/ngfw/administration/monitoring/configure-log-forwarding"
            ],
            "rule_id": "paloalto.panos.logging.system_forwarding",
            "severity": "Medium",
            "title": "System events lack a syslog forwarding destination"
        },
        "7.0.2. Allow rule has no security profile attachment": {
            "device": "PAN_OS",
            "ease": "An attacker can deliver malicious content through traffic permitted by the uninspected rule.",
            "evidence": [
                "localhost.localdomain/vsys1/rulebase: security rule 1 Allow web-browsing In"
            ],
            "exploitability": "An attacker can deliver malicious content through traffic permitted by the uninspected rule.",
            "impact": "Permitted traffic may bypass threat, malware, URL, file, and data inspection controls.",
            "observation": "Enabled allow rule 'Allow web-browsing In' in 'vsys1' has no profile group or individual security profiles.",
            "recommendation": "Attach the organization's approved Security Profile Group or explicit profiles to the allow rule.",
            "references": [
                "https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/security-policy-best-practices/deploy-security-policy-best-practices/security-policy-rule-best-practices"
            ],
            "rule_id": "paloalto.panos.policy.security_profiles",
            "severity": "High",
            "title": "Allow rule has no security profile attachment"
        },
        "7.0.3. Allow rule permits every application and service": {
            "device": "PAN_OS",
            "ease": "A reachable source can use unnecessary or unexpected protocols through the rule.",
            "evidence": [
                "localhost.localdomain/vsys1/rulebase: security rule 2 Allow All Out"
            ],
            "exploitability": "A reachable source can use unnecessary or unexpected protocols through the rule.",
            "impact": "The rule permits all identifiable applications on all ports within its remaining network and identity scope.",
            "observation": "Enabled allow rule 'Allow All Out' in 'vsys1' uses Any for both application and service.",
            "recommendation": "Constrain the rule to approved applications and use application-default or reviewed explicit services as appropriate.",
            "references": [
                "https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/security-policy-best-practices/deploy-security-policy-best-practices/security-policy-rule-best-practices"
            ],
            "rule_id": "paloalto.panos.policy.broad_service",
            "severity": "Medium",
            "title": "Allow rule permits every application and service"
        },
        "7.0.4. Allow rule lacks effective centralized log forwarding": {
            "device": "PAN_OS",
            "ease": "Reduced centralized telemetry can delay detection and investigation of malicious traffic.",
            "evidence": [
                "localhost.localdomain/vsys1/rulebase: security rule 2 Allow All Out"
            ],
            "exploitability": "Reduced centralized telemetry can delay detection and investigation of malicious traffic.",
            "impact": "Traffic and threat events may remain only in limited local storage and be unavailable to central monitoring.",
            "observation": "Enabled allow rule 'Allow All Out' in 'vsys1' references 'no log-forwarding profile', which does not resolve to a same-scope profile with a syslog destination.",
            "recommendation": "Attach a same-vsys Log Forwarding profile with an active syslog destination and enable session-end logging.",
            "references": [
                "https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/log-forwarding"
            ],
            "rule_id": "paloalto.panos.policy.log_forwarding",
            "severity": "Medium",
            "title": "Allow rule lacks effective centralized log forwarding"
        },
        "7.0.5. Allow rule does not log at session end": {
            "device": "PAN_OS",
            "ease": "Incomplete traffic records reduce visibility into successful or long-lived malicious sessions.",
            "evidence": [
                "localhost.localdomain/vsys1/rulebase: security rule 2 Allow All Out"
            ],
            "exploitability": "Incomplete traffic records reduce visibility into successful or long-lived malicious sessions.",
            "impact": "Completed-session byte counts, duration, and final application information may not be recorded.",
            "observation": "Enabled allow rule 'Allow All Out' in 'vsys1' does not enable log-at-session-end.",
            "recommendation": "Enable log-at-session-end on the rule unless a documented exception applies.",
            "references": [
                "https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/security-policy-best-practices/deploy-security-policy-best-practices/security-policy-rule-best-practices"
            ],
            "rule_id": "paloalto.panos.policy.session_logging",
            "severity": "Medium",
            "title": "Allow rule does not log at session end"
        },
        "7.0.6. Allow rule has no security profile attachment": {
            "device": "PAN_OS",
            "ease": "An attacker can deliver malicious content through traffic permitted by the uninspected rule.",
            "evidence": [
                "localhost.localdomain/vsys1/rulebase: security rule 2 Allow All Out"
            ],
            "exploitability": "An attacker can deliver malicious content through traffic permitted by the uninspected rule.",
            "impact": "Permitted traffic may bypass threat, malware, URL, file, and data inspection controls.",
            "observation": "Enabled allow rule 'Allow All Out' in 'vsys1' has no profile group or individual security profiles.",
            "recommendation": "Attach the organization's approved Security Profile Group or explicit profiles to the allow rule.",
            "references": [
                "https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/security-policy-best-practices/deploy-security-policy-best-practices/security-policy-rule-best-practices"
            ],
            "rule_id": "paloalto.panos.policy.security_profiles",
            "severity": "High",
            "title": "Allow rule has no security profile attachment"
        },
        "7.0.7. Management password complexity is insufficient": {
            "device": "PAN_OS",
            "ease": "An attacker with management reachability can target accounts protected by the weak local policy.",
            "evidence": [
                "password-complexity absent"
            ],
            "exploitability": "An attacker with management reachability can target accounts protected by the weak local policy.",
            "impact": "Weak local administrator passwords are more susceptible to guessing and credential attacks.",
            "observation": "The local administrator password policy is unsafe: complexity is absent or disabled; minimum length is below 12 or unparseable; uppercase character minimum is below 1 or unparseable; lowercase character minimum is below 1 or unparseable; numeric character minimum is below 1 or unparseable; special character minimum is below 1 or unparseable.",
            "recommendation": "Enable password complexity and require at least 12 characters with uppercase, lowercase, numeric, and special-character minima, or apply the approved organizational benchmark.",
            "references": [
                "https://origin-docs.paloaltonetworks.com/ngfw/help/12-1/device/device-setup-management"
            ],
            "rule_id": "paloalto.panos.credentials.password_complexity",
            "severity": "High",
            "title": "Management password complexity is insufficient"
        },
        "7.0.8. Administrators use local-only authentication": {
            "device": "PAN_OS",
            "ease": "Compromise of a local credential can provide firewall access independently of central identity controls.",
            "evidence": [
                "mgt-config user admin",
                "mgt-config user paloalto"
            ],
            "exploitability": "Compromise of a local credential can provide firewall access independently of central identity controls.",
            "impact": "Local-only accounts reduce centralized revocation, policy enforcement, and authentication auditability.",
            "observation": "Every parsed administrator account uses the local authentication database.",
            "recommendation": "Use RADIUS, SAML, TACACS+, or another approved external authentication profile, with a controlled emergency local account.",
            "references": [
                "https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/manage-firewall-administrators/administrative-authentication"
            ],
            "rule_id": "paloalto.panos.admin.centralized_authentication",
            "severity": "Medium",
            "title": "Administrators use local-only authentication"
        },
        "7.0.9. Administrative login banner is missing": {
            "device": "PAN_OS",
            "ease": "Missing legal or acceptable-use notice can weaken deterrence and incident-response support.",
            "evidence": [
                "localhost.localdomain: administrative management settings"
            ],
            "exploitability": "Missing legal or acceptable-use notice can weaken deterrence and incident-response support.",
            "impact": "Administrators are not shown an approved access warning before authentication.",
            "observation": "No login banner is configured for device scope 'localhost.localdomain'.",
            "recommendation": "Configure an organization-approved login banner on the management interface.",
            "references": [
                "https://origin-docs.paloaltonetworks.com/ngfw/help/12-1/device/device-setup-management"
            ],
            "rule_id": "paloalto.panos.admin.login_banner",
            "severity": "Medium",
            "title": "Administrative login banner is missing"
        }
    },
    "vulnerabilities": []
}
```

**Classification:**
- Detected correctly: none of the two broad-rule concerns; the strong management settings are correctly not reported as absent.
- Detected but degraded: none.
- Missed entirely: both broad rules receive no review signal even though filtering coverage says two policies are known. Their risk is conditional on routing and intended egress, so this is **not scored as a definite vulnerability false negative** from the bootstrap sample alone.
- False positives: none; the scan returns zero findings.
- Crashes/failures: none.

<a id="RW-031"></a>
### FORTIOS — AWS landing-zone FortiGate reference configuration

**Provenance:** [AWS public-sector landing-zone FortiGate artifact](https://github.com/aws-samples/landing-zone-accelerator-on-aws-for-cccs-medium/blob/main/reference-artifacts/third-party/fortinet/assets/fortinet/lza-fortigate.conf), raw SHA-256 `464A1C4E679848EBD7F307FD3D1B9C507D0B6E2672A8B3A3070D04894AF02EB2`. This is an unresolved `${ACCEL_LOOKUP::...}` deployment template, not a finished running configuration.

**Ground truth (established before running the tool):** In the global section, a syslog server name is configured but `set status disable` explicitly disables that remote sink; the server string alone is not evidence of forwarding. Root VDOM disk logging is configured, so the text does not prove that all logging is absent. Policy 1 (`outbound-all`) actively allows all services from port2 to port1, with all source and destination addresses and no UTM profile; this is a broad egress permission whose risk depends on the landing-zone policy and other layers. Policies 2, 3 and 5 also name `ALL`, but explicitly set `status disable`; they are negative controls and must not be reported as active broad permits. The global `admintimeout` is first set to 60 and then 15, so its effective value in this text is 15. Telnet administration is disabled, admin TLS is restricted to 1.2/1.3, and port2 management access is ping-only. Template placeholders leave actual addressing and deployment scope unknown.

**Tool output (actual, unedited):**

**RW031-FORTI CLI stdout (exit 1):**

```text
pynipper-v2 - network configuration security analyzer
[1/4] Initializing pynipper-ng (Fortinet FortiOS)
```

**RW031-FORTI CLI stderr (exit 1; no report created):**

```text
Traceback (most recent call last):
  File "<frozen runpy>", line 198, in _run_module_as_main
  File "<frozen runpy>", line 88, in _run_code
  File "C:\Users\Bogdan\Documents\Projects\pynipper-v2\.venv\Scripts\pynipper-ng.exe\__main__.py", line 7, in <module>
    sys.exit(main())
             ~~~~^^
  File "C:\Users\Bogdan\Documents\Projects\pynipper-v2\src\main.py", line 63, in main
    analyze_device(args_dict["device_type"], args_dict["input_file"], args_dict["output_file"],
    ~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                   args_dict["output_type"], args_dict["conf_file"], not args_dict["offline"],
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                   assessment_context
                   ^^^^^^^^^^^^^^^^^^
                   )
                   ^
  File "C:\Users\Bogdan\Documents\Projects\pynipper-v2\src\analyze\analyze_device.py", line 16, in analyze_device
    analyzer(device, input_filename, output_filename, output_type, configuration, online, assessment_context)
    ~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\Bogdan\Documents\Projects\pynipper-v2\src\analyze\fortinet\analyze_fortinet_device.py", line 14, in analyze_fortinet_device
    parser = get_parser(device, input_filename)
  File "C:\Users\Bogdan\Documents\Projects\pynipper-v2\src\devices\__init__.py", line 16, in get_parser
    parser = definition.load_parser_class()(config_filepath)
  File "C:\Users\Bogdan\Documents\Projects\pynipper-v2\src\devices\fortinet\fortios.py", line 313, in __init__
    self.config = self._parse_config(config_filepath)
                  ~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^
  File "C:\Users\Bogdan\Documents\Projects\pynipper-v2\src\devices\fortinet\fortios.py", line 458, in _parse_config
    self._require_frame(frames, "config", line_number, command)
    ~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\Bogdan\Documents\Projects\pynipper-v2\src\devices\fortinet\fortios.py", line 382, in _require_frame
    raise FortiOSParseError(
    ...<3 lines>...
    )
src.devices.fortinet.fortios.FortiOSParseError: C:\Users\Bogdan\AppData\Local\Temp\pynipper-realworld-2026-09-21\forti-aws-lza.conf:153: 'end' has no open config block
```

**Classification:**
- Detected correctly: unassessed because the scan failed before generating a report.
- Detected but degraded: unassessed.
- Missed entirely: unassessed; a crash is not treated as a clean scan or as a per-check false negative.
- False positives: unassessed.
- Crashes/failures: **exit 1**, `FortiOSParseError` at line 153; no JSON report was generated. The source uses `end` while inside the `edit root` VDOM entry. [Fortinet's CLI syntax guide](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/508024/command-syntax) explicitly allows `end` to save the current table entry and table, so this is a supported command form even though this artifact is an unresolved template.
