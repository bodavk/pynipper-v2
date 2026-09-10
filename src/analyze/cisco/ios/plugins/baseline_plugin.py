import re

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.cisco.ios import CiscoIOSParser


CISCO_IOS_HARDENING_GUIDE = (
    "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
)


class PluginIOSBaseline(BasePlugin):
    """Version-gated IOS hardening baseline beyond HTTP and SSH."""

    @staticmethod
    def _ios(parser: BaseDeviceParser) -> CiscoIOSParser:
        if not isinstance(parser, CiscoIOSParser):
            raise TypeError("PluginIOSBaseline requires an IOS-family parser")
        return parser

    @staticmethod
    def _children(parent) -> list[str]:
        return [child.text.strip() for child in parent.children]

    @staticmethod
    def _finding(
        parser: BaseDeviceParser,
        rule_id: str,
        title: str,
        observation: str,
        impact: str,
        recommendation: str,
        severity: Severity,
        evidence: tuple[str, ...],
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            device=parser.device_type,
            title=title,
            observation=observation,
            impact=impact,
            exploitability="An attacker with management-plane or configuration access may exploit this weakness.",
            recommendation=recommendation,
            severity=severity,
            evidence=evidence,
            references=(CISCO_IOS_HARDENING_GUIDE,),
        )

    def _global_lines(self, parser: BaseDeviceParser) -> list[str]:
        return self._ios(parser)._global_lines()

    @staticmethod
    def _effective_toggle(lines: list[str], positive: str, negative: str) -> bool:
        state = False
        for line in lines:
            if re.fullmatch(positive, line):
                state = True
            elif re.fullmatch(negative, line):
                state = False
        return state

    def _applicable(self, parser: BaseDeviceParser) -> bool:
        # Defaults and syntax vary by train. Unknown software is explicitly not
        # treated as proof that a baseline control is absent.
        return self._ios(parser).get_version() != "?"

    def check_aaa(self, parser: BaseDeviceParser) -> None:
        lines = self._global_lines(parser)
        aaa_enabled = self._effective_toggle(lines, r"aaa new-model", r"no aaa new-model")
        if not aaa_enabled:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.aaa.new_model",
                    "Centralized AAA is not enabled",
                    "The effective configuration does not enable 'aaa new-model'.",
                    "Authentication, authorization, and accounting policy may be inconsistent and locally controlled.",
                    "Enable AAA new-model and define a tested local fallback before applying it to management lines.",
                    Severity.HIGH,
                    ("aaa new-model not present or negated",),
                )
            )
            return
        if not any(re.fullmatch(r"aaa authentication login\s+\S+\s+.+", line) for line in lines):
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.aaa.login_authentication",
                    "AAA login authentication method list is missing",
                    "AAA is enabled but no login authentication method list is configured.",
                    "Management lines may fall back to an unintended authentication behavior.",
                    "Configure an 'aaa authentication login' method list with an appropriate local fallback.",
                    Severity.HIGH,
                    ("aaa new-model",),
                )
            )
        if not any(re.fullmatch(r"aaa accounting (?:exec|commands)\s+.+", line) for line in lines):
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.aaa.accounting",
                    "Administrative AAA accounting is missing",
                    "AAA is enabled but no EXEC or command accounting method is configured.",
                    "Administrative activity may not be attributable or centrally auditable.",
                    "Configure start-stop EXEC and command accounting to a resilient AAA service.",
                    Severity.MEDIUM,
                    ("aaa new-model",),
                )
            )

    def check_management_lines(self, parser: BaseDeviceParser) -> None:
        native = parser.get_native_config()
        for line_block in native.find_objects(r"^line vty(?:\s|$)"):
            children = self._children(line_block)
            transport = next(
                (line for line in reversed(children) if line.startswith("transport input")),
                "",
            )
            if not transport or any(token in transport.split()[2:] for token in ("telnet", "all")):
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.vty.telnet",
                        "VTY permits clear-text Telnet",
                        f"{line_block.text.strip()} does not restrict inbound transport to SSH.",
                        "Remote administrative credentials and commands may traverse the network without encryption.",
                        "Configure 'transport input ssh' on every VTY range.",
                        Severity.HIGH,
                        (line_block.text.strip(), transport or "transport input default"),
                    )
                )
            timeout = next(
                (line for line in reversed(children) if line.startswith("exec-timeout")),
                "",
            )
            match = re.fullmatch(r"exec-timeout\s+(\d+)(?:\s+(\d+))?", timeout)
            if match and int(match.group(1)) == 0 and int(match.group(2) or 0) == 0:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.vty.session_timeout",
                        "VTY session timeout is disabled",
                        f"{line_block.text.strip()} uses an unlimited exec-timeout.",
                        "Abandoned authenticated sessions can remain usable indefinitely.",
                        "Configure a finite 'exec-timeout', normally ten minutes or less.",
                        Severity.MEDIUM,
                        (line_block.text.strip(), timeout),
                    )
                )
            if not any(
                re.fullmatch(r"login (?:local|authentication\s+\S+)", line)
                for line in children
            ):
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.vty.authentication",
                        "VTY authentication is not explicitly bound",
                        f"{line_block.text.strip()} lacks 'login local' or an AAA login method list.",
                        "The line may use an unintended password-only or default authentication path.",
                        "Bind each VTY range to a named AAA login method or explicit local authentication.",
                        Severity.HIGH,
                        (line_block.text.strip(),),
                    )
                )

        for console in native.find_objects(r"^line con(?:sole)?(?:\s|$)"):
            children = self._children(console)
            timeout = next(
                (line for line in reversed(children) if line.startswith("exec-timeout")),
                "",
            )
            if timeout == "exec-timeout 0 0":
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.console.session_timeout",
                        "Console session timeout is disabled",
                        "The console line has an unlimited EXEC session timeout.",
                        "Unattended console sessions can remain authenticated indefinitely.",
                        "Configure a finite console exec-timeout.",
                        Severity.MEDIUM,
                        (console.text.strip(), timeout),
                    )
                )

    def check_credentials(self, parser: BaseDeviceParser) -> None:
        lines = self._global_lines(parser)
        for line in lines:
            username = re.match(r"username\s+(\S+)\s+(.+)", line)
            if not username:
                continue
            options = username.group(2)
            password = re.search(r"(?:^|\s)password(?:\s+(\d+))?\s+", options)
            secret = re.search(r"(?:^|\s)secret(?:\s+(\d+))?\s+", options)
            weak = password is not None or (
                secret is not None
                and "algorithm-type " not in options
                and (secret.group(1) or "0") in {"0", "5", "7"}
            )
            if weak:
                storage_kind = "password" if password else "secret"
                storage_type = (
                    (password.group(1) or "0")
                    if password
                    else (secret.group(1) or "0")
                )
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.credentials.local_storage",
                        "Local credential uses weak storage",
                        f"User '{username.group(1)}' uses {storage_kind} storage type '{storage_type}'. The credential is redacted.",
                        "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
                        "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
                        Severity.HIGH,
                        (f"username {username.group(1)} <credential redacted>",),
                    )
                )
        for line in lines:
            match = re.fullmatch(r"enable\s+(password|secret)(?:\s+(\d+))?\s+.+", line)
            if match and (match.group(1) == "password" or (match.group(2) or "0") in {"0", "5", "7"}):
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.credentials.enable_storage",
                        "Enable credential uses weak storage",
                        "The enable credential uses plaintext, reversible, or legacy hash storage; its value is redacted.",
                        "Configuration disclosure can expose or accelerate recovery of the privileged credential.",
                        "Replace it with a strong 'enable secret' algorithm and remove the enable password.",
                        Severity.HIGH,
                        ("enable <credential redacted>",),
                    )
                )
                break

    def check_snmp(self, parser: BaseDeviceParser) -> None:
        for line in self._global_lines(parser):
            match = re.fullmatch(r"snmp-server community\s+(\S+)(?:\s+view\s+\S+)?(?:\s+(ro|rw))?(?:\s+\S+)?", line, re.IGNORECASE)
            if not match:
                continue
            community, access = match.group(1), (match.group(2) or "ro").lower()
            problems = ["community-based SNMP"]
            if community.casefold() in {"public", "private"}:
                problems.append("an exact default community")
            if access == "rw":
                problems.append("read-write access")
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.snmp.legacy_community",
                    "Legacy SNMP community configured",
                    f"An SNMPv1/v2c community uses {', '.join(problems)}. The value is redacted.",
                    "Community-based SNMP lacks modern per-user authentication and privacy protections.",
                    "Migrate to SNMPv3 authPriv, restrict managers, and remove v1/v2c communities.",
                    Severity.HIGH if access == "rw" else Severity.MEDIUM,
                    (f"snmp-server community <redacted> {access}",),
                )
            )

    def check_logging(self, parser: BaseDeviceParser) -> None:
        lines = self._global_lines(parser)
        hosts = [
            line
            for line in lines
            if re.fullmatch(r"logging host\s+\S+\s+\S+(?:\s+.*)?", line)
            or re.fullmatch(r"logging host\s+\S+", line)
            or re.fullmatch(r"logging\s+\d+(?:\.\d+){3}", line)
        ]
        if not hosts:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.logging.remote_destination",
                    "Remote logging destination is missing",
                    "No active remote syslog destination is configured.",
                    "Events may be lost during compromise or device failure and unavailable to central monitoring.",
                    "Configure one or more protected remote logging hosts.",
                    Severity.MEDIUM,
                    ("No logging host command",),
                )
            )
            return
        trap = next((line for line in reversed(lines) if line.startswith("logging trap ")), "")
        levels = {
            "emergencies": 0, "alerts": 1, "critical": 2, "errors": 3,
            "warnings": 4, "notifications": 5, "informational": 6, "debugging": 7,
        }
        value = trap.split()[-1].lower() if trap else ""
        numeric = int(value) if value.isdigit() else levels.get(value)
        if numeric is None or numeric < 6:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.logging.severity",
                    "Remote logging severity is insufficient",
                    f"The remote logging threshold is '{value or 'not configured'}'.",
                    "Administrative and security-relevant informational events may not be centralized.",
                    "Configure 'logging trap informational' unless policy explicitly requires a different threshold.",
                    Severity.LOW,
                    tuple(hosts) + ((trap,) if trap else ()),
                )
            )

    def check_ntp(self, parser: BaseDeviceParser) -> None:
        lines = self._global_lines(parser)
        servers = [line for line in lines if re.fullmatch(r"ntp (?:server|peer)\s+.+", line)]
        if not servers:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.ntp.servers",
                    "NTP synchronization is not configured",
                    "No NTP server or peer is configured.",
                    "Inaccurate time undermines event correlation, certificates, and forensic timelines.",
                    "Configure multiple trusted NTP servers.",
                    Severity.MEDIUM,
                    ("No ntp server or peer command",),
                )
            )
            return
        authentication = self._effective_toggle(lines, r"ntp authenticate", r"no ntp authenticate")
        if not authentication or any(" key " not in f" {line} " for line in servers):
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.ntp.authentication",
                    "NTP authentication is incomplete",
                    "At least one configured NTP association lacks an authenticated key or global NTP authentication is disabled.",
                    "A spoofed time source can disrupt logs and time-dependent security controls.",
                    "Enable NTP authentication and bind every server or peer to a trusted key.",
                    Severity.MEDIUM,
                    tuple(servers),
                )
            )

    def check_banner(self, parser: BaseDeviceParser) -> None:
        lines = self._global_lines(parser)
        if not any(re.match(r"banner (?:login|motd)\s+", line) for line in lines):
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.banner.login",
                    "Login warning banner is missing",
                    "No login or message-of-the-day warning banner is configured.",
                    "Users may not receive the organization's required authorized-use and monitoring notice.",
                    "Configure an approved legal warning with 'banner login'.",
                    Severity.LOW,
                    ("No banner login or banner motd command",),
                )
            )

    def check_unnecessary_services(self, parser: BaseDeviceParser) -> None:
        lines = self._global_lines(parser)
        unsafe = [
            line
            for line in lines
            if line in {
                "service finger",
                "service tcp-small-servers",
                "service udp-small-servers",
                "ip bootp server",
            }
        ]
        if unsafe:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.services.unnecessary",
                    "Unnecessary legacy services are enabled",
                    f"Explicit legacy service commands are active: {', '.join(unsafe)}.",
                    "Unneeded listeners increase management-plane attack surface.",
                    "Disable every service that is not operationally required using its 'no' form.",
                    Severity.MEDIUM,
                    tuple(unsafe),
                )
            )

    def check_interface_protections(self, parser: BaseDeviceParser) -> None:
        lines = self._global_lines(parser)
        if "no ip source-route" not in lines:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.ip.source_route",
                    "IP source routing is not explicitly disabled",
                    "The configuration does not contain the IOS 'no ip source-route' hardening command.",
                    "Source-routed packets can bypass expected routing paths and trust boundaries on applicable releases.",
                    "Configure 'no ip source-route'.",
                    Severity.MEDIUM,
                    ("no ip source-route absent",),
                )
            )
        for interface in parser.get_native_config().find_objects(r"^interface\s+"):
            children = self._children(interface)
            if "shutdown" in children or not any(line.startswith("ip address ") for line in children):
                continue
            missing = []
            if "no ip redirects" not in children:
                missing.append("no ip redirects")
            if "no ip proxy-arp" not in children:
                missing.append("no ip proxy-arp")
            if missing:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.interface.ip_hardening",
                        "Layer-3 interface hardening is incomplete",
                        f"{interface.text.strip()} lacks {', '.join(missing)}.",
                        "Redirects or proxy ARP can enable traffic redirection and weaken local network trust assumptions.",
                        "Disable redirects and proxy ARP on routed interfaces unless explicitly required.",
                        Severity.MEDIUM,
                        (interface.text.strip(), *missing),
                    )
                )

    def check_control_plane(self, parser: BaseDeviceParser) -> None:
        policies = parser.get_native_config().find_objects(r"^control-plane(?:\s|$)")
        protected = any(
            any(re.fullmatch(r"service-policy input\s+\S+", line) for line in self._children(block))
            for block in policies
        )
        if not protected:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.control_plane.copp",
                    "Control-plane policing is not attached",
                    "No input service policy is attached under control-plane configuration.",
                    "Unrestricted control-plane traffic can contribute to CPU exhaustion and management outages.",
                    "Deploy a validated Control Plane Policing policy appropriate for the platform role.",
                    Severity.MEDIUM,
                    ("No control-plane service-policy input",),
                )
            )

    def check_crypto(self, parser: BaseDeviceParser) -> None:
        native = parser.get_native_config()
        for policy in native.find_objects(r"^crypto (?:isakmp|ikev1) policy\s+"):
            children = self._children(policy)
            weak = [
                line for line in children
                if re.fullmatch(r"encryption (?:des|3des)", line)
                or re.fullmatch(r"hash (?:md5|sha)", line)
                or re.fullmatch(r"group (?:1|2|5|14)", line)
            ]
            if weak:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.crypto.legacy_ike",
                        "IKE policy uses legacy algorithms",
                        f"{policy.text.strip()} contains legacy cryptographic selections.",
                        "Weak encryption, hashing, or Diffie-Hellman groups reduce VPN security.",
                        "Use AES-256 or AES-GCM, SHA-256 or stronger, and an approved modern DH group.",
                        Severity.HIGH,
                        (policy.text.strip(), *weak),
                    )
                )
        for transform in native.find_objects(r"^crypto ipsec transform-set\s+"):
            weak = [token for token in transform.text.lower().split() if token in {"esp-des", "esp-3des", "esp-md5-hmac", "esp-sha-hmac"}]
            if weak:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.crypto.legacy_ipsec",
                        "IPsec transform-set uses legacy algorithms",
                        f"Transform-set '{transform.text.split()[3]}' contains legacy algorithms.",
                        "Legacy transforms weaken VPN confidentiality or integrity.",
                        "Replace the transform-set with AES and SHA-256 or an authenticated-encryption suite.",
                        Severity.HIGH,
                        (transform.text.strip(),),
                    )
                )

    def analyze(self, parser: BaseDeviceParser) -> None:
        if not self._applicable(parser):
            return
        self.check_aaa(parser)
        self.check_management_lines(parser)
        self.check_credentials(parser)
        self.check_snmp(parser)
        self.check_logging(parser)
        self.check_ntp(parser)
        self.check_banner(parser)
        self.check_unnecessary_services(parser)
        self.check_interface_protections(parser)
        self.check_control_plane(parser)
        self.check_crypto(parser)
