"""SonicOS 7 E-CLI management, policy, VPN, and operations checks."""

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.sonicwall.sonicos import SonicOSParser


SONICOS_CLI_GUIDE = (
    "https://www.sonicwall.com/techdocs/pdf/"
    "sonicosx-7-command-line-interface-reference-guide.pdf"
)
SONICOS_MANAGEMENT_GUIDE = (
    "https://www.sonicwall.com/support/technical-documentation/docs/"
    "sonicos-7-0-0-0-device_settings/Content/Topics/Management/management-ssh.htm"
)
SONICOS_SYSTEM_GUIDE = (
    "https://www.sonicwall.com/techdocs/pdf/sonicos-7-0-0-0-system.pdf"
)
SONICOS_POLICY_GUIDE = (
    "https://www.sonicwall.com/techdocs/pdf/sonicos-7-0-0-0-rules_and_policies.pdf"
)
SONICOS_VPN_GUIDE = (
    "https://www.sonicwall.com/support/knowledge-base/"
    "configuring-site-to-site-vpn-policies-using-enterprise-command-line-interface-e-cli/kA1VN0000000JUH0A2"
)
SONICOS_CAPTURE_ATP_GUIDE = (
    "https://www.sonicwall.com/support/technical-documentation/docs/"
    "sonicos-7-1-capture_atp/Content/capture-atp-disabling-gav.htm"
)


class PluginSonicOSChecks(BasePlugin):
    _EXTERNAL_ZONES = {"wan", "dmz", "wlan", "ssl-vpn"}
    _WEAK_ENCRYPTION = {"des", "3des", "triple-des"}
    _WEAK_AUTHENTICATION = {"md5", "sha", "sha1", "sha-1"}
    _WEAK_DH = {"1", "2", "5", "group1", "group2", "group5"}

    @staticmethod
    def _sonic(parser: BaseDeviceParser) -> SonicOSParser:
        if not isinstance(parser, SonicOSParser):
            raise TypeError("PluginSonicOSChecks requires a SonicOSParser")
        return parser

    def check_management(self, parser: BaseDeviceParser) -> None:
        for interface in self._sonic(parser).get_interfaces():
            if not interface.enabled:
                continue
            evidence = tuple(item.text for item in interface.evidence)
            if "http" in interface.management:
                self.add_issue(
                    Finding(
                        rule_id="sonicwall.sonicos.management.http",
                        device=parser.device_type,
                        title="Clear-text HTTP management is enabled",
                        observation=f"Interface '{interface.name}' in zone '{interface.zone or 'unspecified'}' permits HTTP management.",
                        impact="Administrative credentials and sessions can be exposed or modified in transit.",
                        exploitability="An attacker with management-path reachability can intercept clear-text traffic.",
                        recommendation="Remove HTTP management from the interface and use HTTPS with an approved certificate.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(SONICOS_MANAGEMENT_GUIDE, SONICOS_SYSTEM_GUIDE),
                    )
                )
            exposed = sorted(set(interface.management) & {"https", "ssh", "snmp"})
            if exposed and interface.zone.casefold() in self._EXTERNAL_ZONES:
                self.add_issue(
                    Finding(
                        rule_id="sonicwall.sonicos.management.external_interface",
                        device=parser.device_type,
                        title="Management is enabled on an external-zone interface",
                        observation=f"Interface '{interface.name}' in {interface.zone} permits {', '.join(exposed)} management.",
                        impact="Internet- or partner-facing paths may expose the firewall management plane.",
                        exploitability="Any source allowed to reach the interface can probe the enabled services; inter-zone rules may add restrictions not reconstructed here.",
                        recommendation="Remove management from external interfaces or constrain it with explicit source-specific access rules and upstream controls.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(SONICOS_SYSTEM_GUIDE, SONICOS_POLICY_GUIDE),
                    )
                )

    @staticmethod
    def _is_any(value: str) -> bool:
        return value.casefold() in {"any", "all"}

    def check_access_rules(self, parser: BaseDeviceParser) -> None:
        for rule in self._sonic(parser).get_access_rules():
            if not rule.enabled or rule.action != "allow":
                continue
            evidence = tuple(item.text for item in rule.evidence)
            if all(
                self._is_any(value)
                for value in (
                    rule.from_zone,
                    rule.to_zone,
                    rule.source,
                    rule.destination,
                    rule.service,
                )
            ) and rule.schedule.casefold() in {"", "any", "always-on"}:
                self.add_issue(
                    Finding(
                        rule_id="sonicwall.sonicos.policy.broad_allow",
                        device=parser.device_type,
                        title="Unrestricted access rule is enabled",
                        observation=f"Rule '{rule.name}' at position {rule.position} allows any zone, source, destination, and service.",
                        impact="The rule can bypass intended network segmentation and least-privilege controls.",
                        exploitability="Any matching source can reach any routable destination and service permitted by surrounding infrastructure.",
                        recommendation="Replace wildcard fields with explicit zones, address objects, services, users, and schedules.",
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                        references=(SONICOS_POLICY_GUIDE, SONICOS_CLI_GUIDE),
                    )
                )
            if not rule.logging:
                self.add_issue(
                    Finding(
                        rule_id="sonicwall.sonicos.policy.logging",
                        device=parser.device_type,
                        title="Allow rule does not enable logging",
                        observation=f"Enabled allow rule '{rule.name}' at position {rule.position} has logging disabled or absent.",
                        impact="Permitted connections may lack the telemetry needed for detection and investigation.",
                        exploitability="Malicious traffic matching the rule can be harder to identify or reconstruct.",
                        recommendation="Enable logging on security-relevant allow rules and forward events to centralized storage.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(SONICOS_POLICY_GUIDE, SONICOS_CLI_GUIDE),
                    )
                )

    def check_vpn(self, parser: BaseDeviceParser) -> None:
        for policy in self._sonic(parser).get_vpn_policies():
            if not policy.enabled:
                continue
            weak = []
            for label, value, denied in (
                ("IKE encryption", policy.ike_encryption, self._WEAK_ENCRYPTION),
                ("IPsec encryption", policy.ipsec_encryption, self._WEAK_ENCRYPTION),
                ("IKE authentication", policy.ike_authentication, self._WEAK_AUTHENTICATION),
                ("IPsec authentication", policy.ipsec_authentication, self._WEAK_AUTHENTICATION),
                ("DH group", policy.dh_group, self._WEAK_DH),
            ):
                if value in denied:
                    weak.append(f"{label} {value}")
            if not weak:
                continue
            self.add_issue(
                Finding(
                    rule_id="sonicwall.sonicos.vpn.weak_proposal",
                    device=parser.device_type,
                    title="Active VPN policy uses a weak proposal",
                    observation=f"VPN policy '{policy.name}' uses " + ", ".join(weak) + ".",
                    impact="Legacy encryption, hashes, or DH groups weaken tunnel confidentiality and integrity.",
                    exploitability="A capable network attacker may exploit cryptographic weaknesses or downgrade-compatible peers.",
                    recommendation="Use AES-GCM or AES-256, SHA-256 or stronger authentication, and a current approved DH group.",
                    severity=Severity.HIGH,
                    evidence=tuple(item.text for item in policy.evidence),
                    references=(SONICOS_VPN_GUIDE, SONICOS_CLI_GUIDE),
                )
            )

    def check_operations(self, parser: BaseDeviceParser) -> None:
        sonic = self._sonic(parser)
        if sonic.get_services()["snmp"] and not sonic.has_secure_snmpv3_user():
            self.add_issue(
                Finding(
                    rule_id="sonicwall.sonicos.snmp.secure_user_missing",
                    device=parser.device_type,
                    title="SNMP management lacks an authenticated private user",
                    observation="SNMP is enabled on an interface without a parsed SNMPv3 SHA/AES user.",
                    impact="Monitoring may rely on community credentials without authentication and confidentiality.",
                    exploitability="A reachable attacker can capture, guess, or misuse legacy SNMP credentials.",
                    recommendation="Configure SNMPv3 with authentication and privacy, then restrict SNMP to approved managers.",
                    severity=Severity.MEDIUM,
                    evidence=("SNMP interface management enabled without secure SNMPv3 user",),
                    references=(SONICOS_SYSTEM_GUIDE, SONICOS_CLI_GUIDE),
                )
            )
        if not sonic.get_syslog_destinations():
            self.add_issue(
                Finding(
                    rule_id="sonicwall.sonicos.logging.remote_destination",
                    device=parser.device_type,
                    title="No enabled syslog destination is configured",
                    observation="No enabled SonicOS syslog server was found.",
                    impact="Security events may be lost through local rollover or appliance compromise.",
                    exploitability="An attacker with appliance access benefits from reduced external evidence.",
                    recommendation="Configure and enable redundant protected syslog destinations.",
                    severity=Severity.MEDIUM,
                    evidence=("enabled syslog destination absent",),
                    references=(SONICOS_CLI_GUIDE,),
                )
            )
        ntp_servers = sonic.get_ntp_server_records()
        if not ntp_servers:
            self.add_issue(
                Finding(
                    rule_id="sonicwall.sonicos.ntp.servers",
                    device=parser.device_type,
                    title="No custom NTP server is configured",
                    observation="No active SonicOS 'ntp-server' entry was found.",
                    impact="Incorrect timestamps hinder event correlation and authentication troubleshooting.",
                    exploitability="Inconsistent time reduces the reliability of security monitoring and forensic timelines.",
                    recommendation="Configure redundant trusted NTP servers and authenticate them where supported.",
                    severity=Severity.LOW,
                    evidence=("custom NTP server absent",),
                    references=(SONICOS_CLI_GUIDE,),
                )
            )
        elif not any(server.authenticated for server in ntp_servers):
            self.add_issue(
                Finding(
                    rule_id="sonicwall.sonicos.ntp.authentication",
                    device=parser.device_type,
                    title="NTP servers lack authentication",
                    observation="Active NTP server entries do not include a parsed authentication algorithm and trusted key reference.",
                    impact="Unauthenticated time responses can corrupt log chronology and time-dependent authentication behavior.",
                    exploitability="A network-positioned attacker may spoof NTP responses if routing and filtering permit it.",
                    recommendation="Configure trusted NTP servers with supported authentication keys and restrict management-plane reachability.",
                    severity=Severity.MEDIUM,
                    evidence=tuple(item.text for server in ntp_servers for item in server.evidence),
                    references=(SONICOS_CLI_GUIDE,),
                )
            )
        services = sonic.get_security_services()
        disabled = [name for name, state in services.items() if state is False]
        if disabled:
            self.add_issue(
                Finding(
                    rule_id="sonicwall.sonicos.security_services.disabled",
                    device=parser.device_type,
                    title="Threat-prevention services are explicitly disabled",
                    observation="Explicitly disabled services: " + ", ".join(disabled) + ".",
                    impact="Traffic may bypass malware, intrusion, or spyware inspection.",
                    exploitability="Attackers can deliver threats that the disabled inspection service would otherwise detect.",
                    recommendation="Enable the applicable licensed security services and attach them to relevant policies.",
                    severity=Severity.HIGH,
                    evidence=tuple(f"no {name} enable" for name in disabled),
                    references=(SONICOS_SYSTEM_GUIDE,),
                )
            )
        if services["capture-atp"] is True and (
            services["gateway-anti-virus"] is False
            or services["cloud-gateway-anti-virus"] is False
        ):
            unavailable = [
                name for name in ("gateway-anti-virus", "cloud-gateway-anti-virus")
                if services[name] is False
            ]
            self.add_issue(
                Finding(
                    rule_id="sonicwall.sonicos.capture_atp.dependencies",
                    device=parser.device_type,
                    title="Capture ATP has an explicitly disabled antivirus dependency",
                    observation="Capture ATP is enabled while these required services are explicitly disabled: " + ", ".join(unavailable) + ".",
                    impact="Capture ATP cannot provide its intended file analysis while its Gateway Anti-Virus dependencies are disabled.",
                    exploitability="Malicious files can traverse paths that operators may incorrectly believe receive Capture ATP analysis.",
                    recommendation="Enable both Gateway Anti-Virus and Cloud Gateway Anti-Virus, verify licensing, and confirm applicable protocol inspection.",
                    severity=Severity.HIGH,
                    evidence=tuple(["capture-atp enable", *(f"no {name} enable" for name in unavailable)]),
                    references=(SONICOS_CAPTURE_ATP_GUIDE,),
                )
            )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_management(parser)
        self.check_access_rules(parser)
        self.check_vpn(parser)
        self.check_operations(parser)
