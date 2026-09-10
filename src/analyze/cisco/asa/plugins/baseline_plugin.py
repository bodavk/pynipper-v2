import re

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.cisco.asa import CiscoASAParser


class PluginASABaseline(BasePlugin):
    """Additional version-aware ASA management and platform baseline."""

    @staticmethod
    def _asa(parser: BaseDeviceParser) -> CiscoASAParser:
        if not isinstance(parser, CiscoASAParser):
            raise TypeError("PluginASABaseline requires an ASA parser")
        return parser

    def _lines(self, parser: BaseDeviceParser) -> list[str]:
        return [line.strip() for line in self._asa(parser).parser.ioscfg if line.strip()]

    @staticmethod
    def _finding(parser, rule_id, title, observation, impact, recommendation, severity, evidence):
        return Finding(
            rule_id=rule_id,
            device=parser.device_type,
            title=title,
            observation=observation,
            impact=impact,
            exploitability="An attacker with management or data-plane reachability may exploit this condition.",
            recommendation=recommendation,
            severity=severity,
            evidence=evidence,
        )

    def check_aaa(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        lines = self._lines(parser)
        management = bool(
            asa.get_management_grants("ssh")
            or asa.get_management_grants("telnet")
            or asa.get_management_grants("http")
        )
        if not management:
            return
        authentication = [
            line for line in lines
            if re.fullmatch(r"aaa authentication (?:ssh|telnet|http) console\s+.+", line)
        ]
        if not authentication:
            self.add_issue(self._finding(
                parser, "cisco.asa.aaa.management_authentication",
                "Centralized management authentication is missing",
                "Remote management grants exist without an AAA authentication binding for SSH, Telnet, or HTTP.",
                "Management access may rely solely on local or unintended authentication behavior.",
                "Bind each enabled management protocol to a resilient AAA server group with LOCAL fallback.",
                Severity.HIGH, ("Remote management grants configured",),
            ))
        accounting = [
            line for line in lines
            if re.fullmatch(r"aaa accounting (?:ssh|telnet|http) console\s+.+", line)
        ]
        if not accounting:
            self.add_issue(self._finding(
                parser, "cisco.asa.aaa.management_accounting",
                "Management AAA accounting is missing",
                "Remote management is configured without AAA accounting for administrative sessions.",
                "Administrative activity may not be attributable in a central audit trail.",
                "Configure AAA accounting for every enabled management protocol.",
                Severity.MEDIUM, tuple(authentication) or ("No management AAA accounting",),
            ))

    def check_local_users(self, parser: BaseDeviceParser) -> None:
        for line in self._lines(parser):
            match = re.fullmatch(r"username\s+(\S+)\s+password(?:\s+(\S+))?(?:\s+(encrypted|pbkdf2))?(?:\s+privilege\s+\d+)?", line)
            if not match:
                continue
            username, value, marker = match.group(1), match.group(2) or "", match.group(3) or "plaintext"
            if marker != "plaintext" and value.casefold() not in {"cisco", "admin", "password"}:
                continue
            self.add_issue(self._finding(
                parser, "cisco.asa.credentials.local_user_storage",
                "Local administrator credential storage is unsafe",
                f"Local user '{username}' uses {marker} or a known default value; the credential is redacted.",
                "Configuration disclosure can expose or accelerate compromise of a local administrative credential.",
                "Use supported PBKDF2/encrypted storage with unique credentials and prefer centralized AAA.",
                Severity.HIGH, (f"username {username} password <redacted> {marker}",),
            ))

    def check_http_management(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        lines = self._lines(parser)
        enabled = False
        for line in lines:
            if re.fullmatch(r"http server enable(?:\s+\d+)?", line):
                enabled = True
            elif line == "no http server enable":
                enabled = False
        if not enabled:
            return
        grants = asa.get_management_grants("http")
        if not grants:
            self.add_issue(self._finding(
                parser, "cisco.asa.management.http_sources",
                "ASDM/HTTPS management has no explicit source grant",
                "The HTTP server is enabled but no effective HTTP management source grant was parsed.",
                "Management reachability is uncertain and may rely on unintended configuration.",
                "Add narrow 'http <network> <mask> <interface>' grants or disable the HTTP server.",
                Severity.MEDIUM, ("http server enable",),
            ))
        for grant in grants:
            if grant.is_any_source:
                self.add_issue(self._finding(
                    parser, "cisco.asa.management.unrestricted_http",
                    "ASDM/HTTPS management source is unrestricted",
                    f"Every {grant.address_family} source is permitted to reach HTTP/ASDM on interface '{grant.interface}'.",
                    "The administrative web service is exposed to broad authentication and exploitation attempts.",
                    "Restrict HTTP management to dedicated administration networks.",
                    Severity.HIGH, (grant.raw_line,),
                ))
        if not any(re.fullmatch(r"ssl trust-point\s+\S+(?:\s+\S+)?", line) for line in lines):
            self.add_issue(self._finding(
                parser, "cisco.asa.management.certificate",
                "ASDM/HTTPS trustpoint is not explicitly assigned",
                "The management web server is enabled without an explicit SSL trustpoint assignment.",
                "Administrators may receive an untrusted or unintended device certificate.",
                "Enroll a managed certificate and assign it with 'ssl trust-point'.",
                Severity.MEDIUM, ("http server enable",),
            ))

    def check_ntp(self, parser: BaseDeviceParser) -> None:
        lines = self._lines(parser)
        servers = [line for line in lines if re.fullmatch(r"ntp server\s+.+", line)]
        if not servers:
            self.add_issue(self._finding(
                parser, "cisco.asa.ntp.servers", "NTP synchronization is not configured",
                "No NTP server is configured.",
                "Incorrect time weakens event correlation, certificate validation, and forensic timelines.",
                "Configure multiple trusted NTP servers.", Severity.MEDIUM,
                ("No ntp server command",),
            ))
        elif any(" key " not in f" {line} " for line in servers):
            self.add_issue(self._finding(
                parser, "cisco.asa.ntp.authentication", "NTP authentication is incomplete",
                "At least one NTP server is not bound to an authentication key.",
                "A spoofed time source can disrupt logging and time-dependent controls.",
                "Configure NTP authentication keys and reference a key on every server.",
                Severity.MEDIUM, tuple(servers),
            ))

    def check_threat_detection(self, parser: BaseDeviceParser) -> None:
        lines = self._lines(parser)
        enabled = "threat-detection basic-threat" in lines
        if "no threat-detection basic-threat" in lines or not enabled:
            self.add_issue(self._finding(
                parser, "cisco.asa.threat_detection.basic", "Basic threat detection is disabled",
                "The effective ASA configuration does not enable basic threat detection.",
                "Scanning, rate anomalies, and attack indicators may receive reduced local visibility.",
                "Enable and tune basic threat detection for the platform and traffic profile.",
                Severity.MEDIUM, ("threat-detection basic-threat absent or negated",),
            ))

    def check_reverse_path(self, parser: BaseDeviceParser) -> None:
        lines = self._lines(parser)
        protected = {
            match.group(1)
            for line in lines
            if (match := re.fullmatch(r"ip verify reverse-path interface\s+(\S+)", line))
        }
        for interface in self._asa(parser).get_interfaces():
            name = interface["nameif"]
            if interface["security_level"] <= 10 and name not in protected:
                self.add_issue(self._finding(
                    parser, "cisco.asa.interface.reverse_path", "Reverse-path verification is missing",
                    f"Low-trust interface '{name}' does not have uRPF reverse-path verification enabled.",
                    "Spoofed source addresses may cross the firewall boundary without an interface-level routing check.",
                    "Configure 'ip verify reverse-path interface <nameif>' after validating asymmetric routing requirements.",
                    Severity.MEDIUM, (f"interface {name}",),
                ))

    def check_vpn_crypto(self, parser: BaseDeviceParser) -> None:
        native = parser.get_native_config()
        blocks = native.find_objects(r"^crypto (?:ikev1|isakmp) policy\s+")
        blocks += native.find_objects(r"^crypto ikev2 policy\s+")
        for block in blocks:
            children = [child.text.strip().lower() for child in block.children]
            weak = [
                line for line in children
                if any(token in line.split() for token in ("des", "3des", "md5"))
                or re.fullmatch(r"group (?:1|2|5|14)", line)
                or line == "integrity sha"
            ]
            if weak:
                self.add_issue(self._finding(
                    parser, "cisco.asa.crypto.legacy_vpn", "VPN policy uses legacy cryptography",
                    f"{block.text.strip()} contains legacy encryption, integrity, or Diffie-Hellman selections.",
                    "Weak VPN algorithms reduce confidentiality, integrity, or key-exchange strength.",
                    "Use AES-GCM/AES-256, SHA-256 or stronger, and approved modern DH groups.",
                    Severity.HIGH, (block.text.strip(), *weak),
                ))
        for transform in native.find_objects(r"^crypto ipsec (?:ikev1 )?transform-set\s+"):
            if any(token in transform.text.lower().split() for token in ("esp-des", "esp-3des", "esp-md5-hmac", "esp-sha-hmac")):
                self.add_issue(self._finding(
                    parser, "cisco.asa.crypto.legacy_transform", "IPsec transform-set uses legacy cryptography",
                    "An IPsec transform-set includes a legacy encryption or integrity algorithm.",
                    "Legacy transforms weaken protected VPN traffic.",
                    "Replace legacy transforms with AES and SHA-256 or authenticated encryption.",
                    Severity.HIGH, (transform.text.strip(),),
                ))

    def check_failover(self, parser: BaseDeviceParser) -> None:
        lines = self._lines(parser)
        failover = "failover" in lines and "no failover" not in lines
        if not failover:
            return
        if not any(re.fullmatch(r"failover key\s+.+", line) for line in lines):
            self.add_issue(self._finding(
                parser, "cisco.asa.failover.authentication", "Failover link authentication is missing",
                "ASA failover is enabled without an explicit failover key.",
                "Unauthenticated failover communication can weaken the integrity of high-availability state exchange.",
                "Configure a strong failover key and protect the failover network.",
                Severity.HIGH, ("failover",),
            ))

    def analyze(self, parser: BaseDeviceParser) -> None:
        if self._asa(parser).get_version() == "?":
            return
        self.check_aaa(parser)
        self.check_local_users(parser)
        self.check_http_management(parser)
        self.check_ntp(parser)
        self.check_threat_detection(parser)
        self.check_reverse_path(parser)
        self.check_vpn_crypto(parser)
        self.check_failover(parser)
