"""Effective-state Arista EOS management and operational baseline checks."""

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.arista.eos import AristaEOSParser
from src.devices.common.base_parser import BaseDeviceParser


ARISTA_SESSION_GUIDE = "https://www.arista.com/en/um-eos/eos-session-management-commands"
ARISTA_ACL_GUIDE = "https://www.arista.com/en/um-eos/eos-acls-and-route-maps"
ARISTA_SNMP_GUIDE = "https://www.arista.com/en/um-eos/eos-snmp"
ARISTA_TIME_GUIDE = "https://www.arista.com/en/um-eos/eos-system-clock-and-time-protocols"
ARISTA_SECURITY_GUIDE = "https://www.arista.com/en/um-eos/eos-security"


class PluginAristaChecks(BasePlugin):
    # NEEDS_HUMAN_REVIEW: this project policy classifies explicit CBC/3DES/RC4,
    # SHA-1, and MD5 choices as weak; align it with the organization's approved
    # interoperability and cryptographic standard before deployment.
    _WEAK_SSH = {
        "cipher": {"3des-cbc", "arcfour", "aes128-cbc", "aes192-cbc", "aes256-cbc"},
        "key exchange": {
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group14-sha",
        },
        "MAC": {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96"},
    }
    @staticmethod
    def _eos(parser: BaseDeviceParser) -> AristaEOSParser:
        if not isinstance(parser, AristaEOSParser):
            raise TypeError("PluginAristaChecks requires an AristaEOSParser")
        return parser

    def check_management_api(self, parser: BaseDeviceParser) -> None:
        for endpoint in self._eos(parser).get_eapi_endpoints():
            if not endpoint.active:
                continue
            evidence = tuple(item.text for item in endpoint.evidence)
            if endpoint.http:
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.eapi.insecure_http",
                        device=parser.device_type,
                        title="eAPI permits clear-text HTTP",
                        observation=f"The active eAPI endpoint in VRF '{endpoint.scope}' enables HTTP.",
                        impact="API credentials, commands, and responses can be exposed or modified in transit.",
                        exploitability="An attacker with path access to the endpoint can intercept a clear-text management session.",
                        recommendation="Remove 'protocol http', retain HTTPS, and use a trusted TLS certificate.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(ARISTA_SESSION_GUIDE,),
                    )
                )
            if not endpoint.https:
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.eapi.https_disabled",
                        device=parser.device_type,
                        title="Active eAPI endpoint has HTTPS disabled",
                        observation=f"The active eAPI endpoint in VRF '{endpoint.scope}' explicitly disables HTTPS.",
                        impact="The API lacks its protected HTTPS transport.",
                        exploitability="Management may fall back to clear-text HTTP or become dependent on other unverified controls.",
                        recommendation="Enable 'protocol https' and configure an approved certificate and TLS profile.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(ARISTA_SESSION_GUIDE,),
                    )
                )
            if not endpoint.ipv4_acl and not endpoint.ipv6_acl:
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.eapi.source_restriction",
                        device=parser.device_type,
                        title="eAPI endpoint lacks a service ACL",
                        observation=f"The active eAPI endpoint in VRF '{endpoint.scope}' has no IPv4 or IPv6 access-group.",
                        impact="All routed clients in the endpoint VRF can attempt API access.",
                        exploitability="Any host with VRF reachability can probe the service or attempt authentication.",
                        recommendation="Apply explicit IPv4 and, where applicable, IPv6 service ACLs to each enabled eAPI VRF.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(ARISTA_ACL_GUIDE,),
                    )
                )

    def check_authentication(self, parser: BaseDeviceParser) -> None:
        eos = self._eos(parser)
        if not any(endpoint.active for endpoint in eos.get_eapi_endpoints()):
            return
        if eos.get_remote_authentication():
            return
        self.add_issue(
            Finding(
                rule_id="arista.eos.authentication.centralized",
                device=parser.device_type,
                title="eAPI authentication is not backed by centralized AAA",
                observation="eAPI is active but no RADIUS or TACACS+ login method was parsed.",
                impact="Local-only accounts reduce centralized revocation, policy enforcement, and auditability.",
                exploitability="Compromise of a local credential can provide management access independently of the central identity system.",
                recommendation="Configure centralized AAA for the login method with a controlled emergency local fallback.",
                severity=Severity.MEDIUM,
                evidence=("active eAPI without parsed centralized AAA",),
                references=(ARISTA_SECURITY_GUIDE,),
            )
        )

    def check_ssh_and_authorization(self, parser: BaseDeviceParser) -> None:
        eos = self._eos(parser)
        ssh = eos.get_ssh_settings()
        if ssh.configured:
            evidence = tuple(item.text for item in ssh.evidence)
            if ssh.empty_passwords == "permit":
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.ssh.empty_passwords",
                        device=parser.device_type,
                        title="SSH explicitly permits empty passwords",
                        observation="The management SSH policy sets 'authentication empty-passwords permit'.",
                        impact="A local account without a password can be used remotely over SSH.",
                        exploitability="A reachable attacker can attempt authentication to empty-password accounts without possessing a credential.",
                        recommendation="Set 'authentication empty-passwords deny' and ensure every local account has an approved credential.",
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                        references=(ARISTA_SESSION_GUIDE,),
                    )
                )
            weak = {
                "cipher": sorted(set(ssh.ciphers) & self._WEAK_SSH["cipher"]),
                "key exchange": sorted(set(ssh.key_exchanges) & self._WEAK_SSH["key exchange"]),
                "MAC": sorted(set(ssh.macs) & self._WEAK_SSH["MAC"]),
            }
            weak = {name: values for name, values in weak.items() if values}
            if weak:
                summary = "; ".join(f"{name}: {', '.join(values)}" for name, values in weak.items())
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.ssh.weak_algorithms",
                        device=parser.device_type,
                        title="SSH explicitly permits legacy algorithms",
                        observation=f"The explicit management SSH suite contains {summary}.",
                        impact="Legacy CBC/3DES/RC4, SHA-1, or MD5 algorithms weaken management transport protection.",
                        exploitability="A network-positioned attacker may exploit downgrade compatibility or weaknesses in a negotiated legacy algorithm.",
                        recommendation="Remove the listed algorithms and retain modern AES-GCM/CTR, SHA-2, Curve25519, ECDH, or strong finite-field DH choices.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(ARISTA_SESSION_GUIDE,),
                    )
                )
            if not ssh.ipv4_acls and not ssh.ipv6_acls:
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.ssh.source_restriction",
                        device=parser.device_type,
                        title="Explicit SSH service policy lacks access groups",
                        observation="A management SSH block is configured without an IPv4 or IPv6 service ACL.",
                        impact="Every routed source that can reach the switch can attempt SSH authentication.",
                        exploitability="A reachable attacker can probe the daemon, guess credentials, or target SSH implementation flaws.",
                        recommendation="Apply IPv4 and, where applicable, IPv6 access groups in management SSH configuration for each management VRF.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(ARISTA_ACL_GUIDE, ARISTA_SESSION_GUIDE),
                    )
                )

        if eos.get_remote_authentication() and not eos.has_exec_authorization():
            self.add_issue(
                Finding(
                    rule_id="arista.eos.authorization.exec",
                    device=parser.device_type,
                    title="Centralized login lacks exec authorization",
                    observation="RADIUS or TACACS+ login authentication is configured without an active centralized exec authorization method.",
                    impact="Authenticated users may receive locally determined command access that is broader than central policy intends.",
                    exploitability="A compromised or overprivileged account can exercise commands not constrained by centralized authorization.",
                    recommendation="Configure AAA exec authorization through the approved central service with a controlled local fallback.",
                    severity=Severity.MEDIUM,
                    evidence=("centralized login authentication without aaa authorization exec",),
                    references=(ARISTA_SECURITY_GUIDE,),
                )
            )

    def check_snmp(self, parser: BaseDeviceParser) -> None:
        eos = self._eos(parser)
        communities = eos.get_snmp_communities()
        for name, evidence in communities:
            if name in {"public", "private"}:
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.snmp.default_community",
                        device=parser.device_type,
                        title="Default SNMP community is configured",
                        observation=f"The exact default community '{name}' is active.",
                        impact="A widely known community string can enable unauthorized SNMP queries or changes.",
                        exploitability="An attacker needs SNMP reachability and can try the known value directly.",
                        recommendation="Remove the default community and use authenticated, encrypted SNMPv3.",
                        severity=Severity.HIGH,
                        evidence=(evidence.text,),
                        references=(ARISTA_SNMP_GUIDE,),
                    )
                )
        if communities and not eos.has_secure_snmpv3_user():
            self.add_issue(
                Finding(
                    rule_id="arista.eos.snmp.secure_user_missing",
                    device=parser.device_type,
                    title="Community SNMP lacks a secure SNMPv3 replacement",
                    observation="SNMP community access is configured without a parsed SNMPv3 user using SHA authentication and AES privacy.",
                    impact="Management traffic may depend on reusable community credentials without confidentiality.",
                    exploitability="A network-positioned attacker can capture or guess a community value.",
                    recommendation="Configure an SNMPv3 authPriv user and remove community-based access.",
                    severity=Severity.MEDIUM,
                    evidence=tuple(item.text for _, item in communities),
                    references=(ARISTA_SNMP_GUIDE,),
                )
            )

    def check_operations(self, parser: BaseDeviceParser) -> None:
        eos = self._eos(parser)
        if not eos.get_logging_destinations():
            self.add_issue(
                Finding(
                    rule_id="arista.eos.logging.remote_destination",
                    device=parser.device_type,
                    title="No remote syslog destination is configured",
                    observation="No active 'logging host' destination was found.",
                    impact="Security events may be lost through local rollover or device compromise.",
                    exploitability="An attacker with device access benefits from reduced external evidence.",
                    recommendation="Configure protected, redundant remote syslog destinations.",
                    severity=Severity.MEDIUM,
                    evidence=("remote logging destination absent",),
                    references=(ARISTA_SECURITY_GUIDE,),
                )
            )
        if not eos.get_ntp_servers():
            self.add_issue(
                Finding(
                    rule_id="arista.eos.ntp.servers",
                    device=parser.device_type,
                    title="No NTP server is configured",
                    observation="No active 'ntp server' association was found.",
                    impact="Incorrect timestamps hinder event correlation and authentication troubleshooting.",
                    exploitability="Inconsistent time reduces the reliability of security monitoring and forensic timelines.",
                    recommendation="Configure redundant trusted NTP or NTS servers.",
                    severity=Severity.LOW,
                    evidence=("NTP server absent",),
                    references=(ARISTA_TIME_GUIDE,),
                )
            )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_management_api(parser)
        self.check_authentication(parser)
        self.check_ssh_and_authorization(parser)
        self.check_snmp(parser)
        self.check_operations(parser)
