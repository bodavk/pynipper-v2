import re

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import CredentialStorageAssessment
from src.devices.cisco.ios import CiscoIOSParser


CISCO_IOS_HARDENING_GUIDE = (
    "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"
)
CISCO_IOS_SSH_ALGORITHM_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/security-vpn/"
    "security-vpn/m_sec-secure-shell-algorithm-ccc.html"
)
CISCO_IOS_SNMPV3_GUIDE = (
    "https://www.cisco.com/c/en/us/support/docs/ip/"
    "simple-network-management-protocol-snmp/20370-snmpsecurity-20370.html"
)
CISCO_IOS_ROUTING_HARDENING_GUIDE = (
    "https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening"
)
CISCO_IOS_OSPF_AUTH_GUIDE = (
    "https://www.cisco.com/c/en/us/support/docs/ip/"
    "open-shortest-path-first-ospf/13697-25.html"
)
CISCO_IOS_DISCOVERY_GUIDE = CISCO_IOS_HARDENING_GUIDE


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
        references: tuple[str, ...] = (CISCO_IOS_HARDENING_GUIDE,),
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
            references=references,
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
        ios = self._ios(parser)
        method_lists = ios.get_aaa_method_lists()
        aaa_enabled = self._effective_toggle(
            self._global_lines(parser), r"aaa new-model", r"no aaa new-model"
        )
        has_local_users = any(
            item.context == "local_user" for item in ios.get_credential_metadata()
        )
        aaa_server_groups = ios.get_aaa_server_groups()

        def backend_resolves(method_list, *, authentication: bool = False) -> bool:
            methods = method_list.methods
            for index, method in enumerate(methods):
                if method.casefold() != "group":
                    continue
                if index + 1 >= len(methods):
                    return False
                group = methods[index + 1]
                if group.casefold() not in {"radius", "tacacs+"} and group not in aaa_server_groups:
                    return False
            if authentication:
                if any(method.casefold() == "none" for method in methods):
                    return False
                if any(method.casefold() == "local" for method in methods) and not has_local_users:
                    return False
            return bool(methods)

        login_lists = {
            item.name
            for item in method_lists
            if item.service == "login_authentication"
            and backend_resolves(item, authentication=True)
        }
        exec_lists = {
            item.name
            for item in method_lists
            if item.service == "exec_authorization" and backend_resolves(item)
        }
        command_lists = {
            item.name
            for item in method_lists
            if item.service == "command_authorization"
            and item.privilege_level == 15
            and backend_resolves(item)
        }

        def authentication_resolves(line) -> bool:
            if line.login_kind == "local":
                return has_local_users
            if aaa_enabled and line.login_kind == "aaa" and line.login_list:
                return line.login_list in login_lists
            return False

        for line in ios.get_management_lines("vty"):
            evidence = tuple(item.text for item in line.evidence)
            if line.transports is None or any(
                token in line.transports for token in ("telnet", "all")
            ):
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.vty.telnet",
                        "VTY permits clear-text Telnet",
                        f"{line.line} does not explicitly restrict inbound transport to SSH.",
                        "Remote administrative credentials and commands may traverse the network without encryption.",
                        "Configure 'transport input ssh' on every VTY range.",
                        Severity.HIGH,
                        evidence or (line.line,),
                    )
                )
            active = line.accepts_inbound_connections is not False
            if active and (
                line.timeout_configured
                and not line.timeout_parse_error
                and line.timeout_minutes == 0
                and line.timeout_seconds == 0
            ):
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.vty.session_timeout",
                        "VTY session timeout is disabled",
                        f"{line.line} uses an unlimited exec-timeout.",
                        "Abandoned authenticated sessions can remain usable indefinitely.",
                        "Configure a finite 'exec-timeout', normally ten minutes or less.",
                        Severity.MEDIUM,
                        evidence or (line.line,),
                    )
                )
            if active and not authentication_resolves(line):
                reason = (
                    f"references undefined AAA login list '{line.login_list}'"
                    if line.login_kind == "aaa" and line.login_list
                    else "lacks a resolvable local or AAA login binding"
                )
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.vty.authentication",
                        "VTY authentication is not explicitly bound",
                        f"{line.line} {reason}.",
                        "The line may use an unintended password-only or default authentication path.",
                        "Bind each VTY range to a named AAA login method or explicit local authentication.",
                        Severity.HIGH,
                        evidence or (line.line,),
                    )
                )
            if aaa_enabled and active:
                effective_exec = line.exec_authorization_list or (
                    "default" if "default" in exec_lists else None
                )
                command_map = dict(line.command_authorization)
                effective_commands = command_map.get(15) or (
                    "default" if "default" in command_lists else None
                )
                missing = []
                if not effective_exec or effective_exec not in exec_lists:
                    missing.append("EXEC authorization")
                if not effective_commands or effective_commands not in command_lists:
                    missing.append("privilege-15 command authorization")
                if missing:
                    self.add_issue(
                        self._finding(
                            parser,
                            "cisco.ios.vty.authorization",
                            "VTY administrative authorization is incomplete",
                            f"{line.line} lacks resolved {', '.join(missing)}.",
                            "Authenticated administrators may receive unintended EXEC access or execute commands without centralized authorization.",
                            "Define and bind resolved AAA EXEC and privilege-15 command authorization method lists.",
                            Severity.HIGH,
                            evidence or (line.line,),
                        )
                    )
            if line.output_transports and any(
                item in {"telnet", "rlogin", "all"} for item in line.output_transports
            ):
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.vty.insecure_output_transport",
                        "VTY permits insecure outbound terminal transport",
                        f"{line.line} explicitly permits an insecure outbound transport.",
                        "An administrator can initiate clear-text reverse terminal sessions through the device.",
                        "Set 'transport output ssh' or 'transport output none'.",
                        Severity.MEDIUM,
                        evidence or (line.line,),
                    )
                )

        for console in ios.get_management_lines("console"):
            evidence = tuple(item.text for item in console.evidence)
            if console.timeout_minutes == 0 and console.timeout_seconds == 0:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.console.session_timeout",
                        "Console session timeout is disabled",
                        "The console line has an unlimited EXEC session timeout.",
                        "Unattended console sessions can remain authenticated indefinitely.",
                        "Configure a finite console exec-timeout.",
                        Severity.MEDIUM,
                        evidence or (console.line,),
                    )
                )
            if not authentication_resolves(console):
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.console.authentication",
                        "Console authentication is not explicitly secured",
                        f"{console.line} lacks a resolvable local or AAA login binding.",
                        "Physical or terminal-server access may reach an unintended authentication path.",
                        "Bind the console to a tested AAA login method with an appropriate local recovery path.",
                        Severity.HIGH,
                        evidence or (console.line,),
                    )
                )

        for auxiliary in ios.get_management_lines("aux"):
            evidence = tuple(item.text for item in auxiliary.evidence)
            fully_disabled = (
                auxiliary.exec_enabled is False
                and auxiliary.transports == ("none",)
                and auxiliary.output_transports == ("none",)
            )
            if fully_disabled:
                continue
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.auxiliary.enabled",
                    "Auxiliary management line is not fully disabled",
                    f"{auxiliary.line} does not combine 'no exec', 'transport input none', and 'transport output none'.",
                    "An unused AUX port can provide an additional local, modem, or reverse-terminal management path.",
                    "Disable the AUX line using the complete Cisco hardening sequence unless it has an approved operational use.",
                    Severity.HIGH,
                    evidence or (auxiliary.line,),
                )
            )
            if auxiliary.exec_enabled is not False and not authentication_resolves(auxiliary):
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.auxiliary.authentication",
                        "Active auxiliary line lacks resolved authentication",
                        f"{auxiliary.line} is not disabled and lacks a resolvable local or AAA login binding.",
                        "A reachable AUX session may use an unintended or line-password authentication path.",
                        "Disable the line or bind it to a tested AAA login method.",
                        Severity.HIGH,
                        evidence or (auxiliary.line,),
                    )
                )

    def check_ssh_policy(self, parser: BaseDeviceParser) -> None:
        ios = self._ios(parser)
        if ios.get_ssh_state().value != "enabled":
            return
        weak_algorithms = {
            "encryption": {"des", "3des", "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"},
            "mac": {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96"},
            "kex": {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"},
            "hostkey": {"ssh-dss", "ssh-rsa"},
        }
        weak = []
        evidence = []
        for policy in ios.get_ssh_server_algorithms():
            if policy.algorithms is None:
                continue
            selected = sorted(set(policy.algorithms) & weak_algorithms[policy.category])
            if selected:
                weak.append(f"{policy.category}: {', '.join(selected)}")
                evidence.extend(item.text for item in policy.evidence)
        if weak:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.ssh.weak_algorithms",
                    "SSH server explicitly permits weak algorithms",
                    "The explicit SSH server policy includes " + "; ".join(weak) + ".",
                    "Legacy SSH algorithms weaken confidentiality, integrity, key exchange, or host authentication.",
                    "Restrict the SSH server to release-supported AES-CTR/GCM, SHA-2/EtM, modern KEX, and SHA-2/EdDSA host-key algorithms.",
                    Severity.HIGH,
                    tuple(evidence),
                    (CISCO_IOS_SSH_ALGORITHM_GUIDE,),
                )
            )
        key = ios.get_ssh_rsa_key_modulus()
        if key.configured and key.value is not None and key.value < 2048:
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.ssh.weak_host_key",
                    "Explicit SSH RSA host key is undersized",
                    f"The recorded RSA key-generation command specifies a {key.value}-bit modulus.",
                    "An undersized host key provides inadequate resistance to key recovery.",
                    "Generate a release-supported RSA key of at least 2048 bits or a stronger supported host-key type.",
                    Severity.HIGH,
                    (key.raw_line,),
                    (CISCO_IOS_SSH_ALGORITHM_GUIDE,),
                )
            )

    def check_credentials(self, parser: BaseDeviceParser) -> None:
        unsafe = {
            CredentialStorageAssessment.EMPTY,
            CredentialStorageAssessment.PLAINTEXT,
            CredentialStorageAssessment.WEAK_HASH,
            CredentialStorageAssessment.WEAK_REVERSIBLE,
        }
        for credential in parser.get_credential_metadata():
            if credential.storage_assessment not in unsafe:
                continue
            if credential.context == "local_user":
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.credentials.local_storage",
                        "Local credential uses weak storage",
                        (
                            f"User '{credential.account}' uses '{credential.method}' storage type "
                            f"'{credential.storage_type}', classified as "
                            f"'{credential.storage_assessment.value}'. The credential is redacted."
                        ),
                        "Plaintext, reversible, or legacy hashes are more readily recovered from a configuration disclosure.",
                        "Use a supported strong secret algorithm and migrate administrative authentication to AAA.",
                        Severity.HIGH,
                        tuple(item.text for item in credential.evidence),
                    )
                )
            elif credential.context == "enable":
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.credentials.enable_storage",
                        "Enable credential uses weak storage",
                        (
                            f"The enable credential uses storage type '{credential.storage_type}', "
                            f"classified as '{credential.storage_assessment.value}'; its value is redacted."
                        ),
                        "Configuration disclosure can expose or accelerate recovery of the privileged credential.",
                        "Replace it with a strong 'enable secret' algorithm and remove the enable password.",
                        Severity.HIGH,
                        tuple(item.text for item in credential.evidence),
                    )
                )

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

        views, groups, users = self._ios(parser).get_snmpv3_relationships()
        view_map = {view.name.casefold(): view for view in views}
        group_map = {group.name.casefold(): group for group in groups}
        for user in users:
            evidence = tuple(item.text for item in user.evidence)
            if not user.group_resolved or (user.read_view and not user.read_view_resolved):
                unresolved = (
                    f"group '{user.group}'"
                    if not user.group_resolved
                    else f"read view '{user.read_view}'"
                )
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.snmp.v3_reference",
                        "SNMPv3 user references an unresolved access object",
                        f"SNMPv3 user '{user.name}' references unresolved {unresolved}.",
                        "An unresolved group or view prevents the configuration from proving the intended SNMP access policy.",
                        "Create the referenced SNMPv3 group/view or bind the user to an existing least-privileged object.",
                        Severity.MEDIUM,
                        evidence,
                        (CISCO_IOS_SNMPV3_GUIDE,),
                    )
                )
                continue

            protection_gaps = []
            if user.group_security_level != "priv":
                protection_gaps.append(
                    f"group security level is '{user.group_security_level or 'unknown'}'"
                )
            if not user.authentication:
                protection_gaps.append("authentication is not configured")
            if not user.privacy:
                protection_gaps.append("privacy is not configured")
            if protection_gaps:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.snmp.v3_protection",
                        "SNMPv3 user lacks authPriv protection",
                        f"SNMPv3 user '{user.name}' has " + "; ".join(protection_gaps) + ".",
                        "SNMP management data may lack strong origin authentication or confidentiality.",
                        "Use a v3 priv group and configure the user with supported authentication and AES privacy.",
                        Severity.HIGH,
                        evidence,
                        (CISCO_IOS_SNMPV3_GUIDE,),
                    )
                )

            weak = []
            if user.authentication == "md5":
                weak.append("MD5 authentication")
            if user.privacy in {"des", "des56", "3des"}:
                weak.append(f"{user.privacy.upper()} privacy")
            if weak:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.snmp.v3_weak_algorithm",
                        "SNMPv3 user uses a weak algorithm",
                        f"SNMPv3 user '{user.name}' uses {', '.join(weak)}.",
                        "Legacy SNMP authentication or privacy algorithms provide inadequate cryptographic strength.",
                        "Use a supported SHA-family authentication algorithm and AES privacy; validate SHA-2 availability for the exact IOS XE platform and release.",
                        Severity.MEDIUM,
                        evidence,
                        (CISCO_IOS_SNMPV3_GUIDE,),
                    )
                )

            view = view_map.get(user.read_view.casefold()) if user.read_view else None
            broad_view = not user.read_view or bool(
                view
                and set(view.included_subtrees) & {"iso", "internet", "1", "1.3.6.1"}
                and not view.excluded_subtrees
            )
            group = group_map.get(user.group.casefold())
            access_gaps = []
            if not user.source_restricted:
                access_gaps.append("no user or group source ACL")
            if broad_view:
                access_gaps.append("the default or an unrestricted read view")
            if group and group.write_view:
                access_gaps.append(f"write view '{group.write_view}'")
            if access_gaps:
                self.add_issue(
                    self._finding(
                        parser,
                        "cisco.ios.snmp.v3_access_scope",
                        "SNMPv3 user has broad access scope",
                        f"SNMPv3 user '{user.name}' has " + "; ".join(access_gaps) + ".",
                        "A compromised monitoring identity may query excessive MIB data, reach the agent from unintended networks, or modify managed objects.",
                        "Apply a restrictive read view and source ACL; remove write access unless explicitly required.",
                        Severity.HIGH if group and group.write_view else Severity.MEDIUM,
                        evidence,
                        (CISCO_IOS_SNMPV3_GUIDE,),
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
        associations = self._ios(parser).get_ntp_associations()
        if not associations:
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
        for association in associations:
            if association.authentication_state == "authenticated":
                continue
            detail = (
                "has no effective authenticated key binding"
                if association.authentication_state == "unauthenticated"
                else f"references missing or untrusted key '{association.key_id}'"
            )
            self.add_issue(
                self._finding(
                    parser,
                    "cisco.ios.ntp.authentication",
                    "NTP authentication is incomplete",
                    f"NTP {association.role} '{association.address}' in VRF '{association.vrf}' {detail}.",
                    "A spoofed time source can disrupt logs and time-dependent security controls.",
                    "Enable NTP authentication and configure, trust, and bind a key for this association.",
                    Severity.MEDIUM,
                    tuple(item.text for item in association.evidence),
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

    def check_routing(self, parser: BaseDeviceParser) -> None:
        ios = self._ios(parser)
        for peer in ios.get_bgp_neighbors():
            if not peer.active or peer.inheritance_unknown:
                continue
            scope = f"neighbor {peer.address} in {peer.address_family}, VRF {peer.vrf}"
            evidence = tuple(item.text for item in peer.evidence)
            if peer.authentication_state in {"unauthenticated", "unresolved"}:
                detail = "has no authentication" if peer.authentication_state == "unauthenticated" else "has an unresolved authentication reference"
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.routing.bgp.authentication",
                    "BGP neighbor authentication is incomplete",
                    f"BGP {scope} {detail}.",
                    "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
                    "Configure peer authentication using a mechanism supported by the exact IOS/IOS XE release and the remote peer.",
                    Severity.HIGH,
                    evidence,
                    (CISCO_IOS_ROUTING_HARDENING_GUIDE,),
                ))
            if peer.peer_role != "external":
                continue
            for direction, present in (("inbound", peer.inbound_policy), ("outbound", peer.outbound_policy)):
                if present:
                    continue
                self.add_issue(self._finding(
                    parser,
                    f"cisco.ios.routing.bgp.{direction}_policy",
                    f"External BGP neighbor lacks an {direction} route policy",
                    f"External BGP {scope} has no explicit {direction} route-map, prefix-list, filter-list, or distribute-list.",
                    "Unrestricted route exchange can admit or advertise unintended prefixes across a routing trust boundary.",
                    f"Apply an explicit least-privilege {direction} route policy appropriate to this peer.",
                    Severity.HIGH,
                    evidence,
                    (CISCO_IOS_ROUTING_HARDENING_GUIDE,),
                ))
            if not peer.prefix_limit:
                self.add_issue(self._finding(
                    parser,
                    "cisco.ios.routing.bgp.prefix_limit",
                    "External BGP neighbor has no maximum-prefix safeguard",
                    f"External BGP {scope} has no explicit maximum-prefix control; no numeric threshold is inferred.",
                    "An unexpectedly large route advertisement can consume routing resources or disrupt forwarding.",
                    "Configure a peer-specific maximum-prefix value based on the documented expected route volume.",
                    Severity.MEDIUM,
                    evidence,
                    (CISCO_IOS_ROUTING_HARDENING_GUIDE,),
                ))

        for interface in ios.get_ospf_interfaces():
            if interface.shutdown or interface.passive or interface.authentication_state in {"authenticated", "unknown"}:
                continue
            evidence = tuple(item.text for item in interface.evidence)
            if interface.authentication_state == "weak":
                title = "OSPF interface uses simple-password authentication"
                observation = f"OSPF process {interface.process_id}, interface {interface.interface}, area {interface.area} uses clear-text simple authentication."
                recommendation = "Use message-digest or a supported key-chain algorithm consistently across the adjacency."
                rule_id = "cisco.ios.routing.ospf.weak_authentication"
            else:
                title = "OSPF interface authentication is incomplete"
                observation = f"OSPF process {interface.process_id}, interface {interface.interface}, area {interface.area} is {interface.authentication_state}."
                recommendation = "Configure and validate OSPF authentication consistently across the adjacency."
                rule_id = "cisco.ios.routing.ospf.authentication"
            self.add_issue(self._finding(
                parser, rule_id, title, observation,
                "An unprotected routing adjacency can accept forged protocol packets from a reachable attacker.",
                recommendation, Severity.HIGH if interface.authentication_state != "weak" else Severity.MEDIUM,
                evidence, (CISCO_IOS_OSPF_AUTH_GUIDE,),
            ))

    def check_discovery(self, parser: BaseDeviceParser) -> None:
        ios = self._ios(parser)
        if ios.get_version() == "?":
            return
        for interface in ios.get_discovery_interfaces():
            if not interface.active or interface.role != "external":
                continue
            directions = [
                direction for direction, enabled in (
                    ("transmit", interface.transmit), ("receive", interface.receive)
                ) if enabled
            ]
            if not directions:
                continue
            evidence = tuple(item.text for item in interface.evidence) + (
                f"assessment policy: {interface.interface} role external",
            )
            self.add_issue(self._finding(
                parser,
                f"cisco.ios.discovery.{interface.protocol}.external",
                f"{interface.protocol.upper()} is enabled on an external interface",
                f"Interface {interface.interface} is explicitly classified external and has {interface.protocol.upper()} {', '.join(directions)} enabled.",
                "Discovery advertisements or learned topology can expose device identity and network structure across an untrusted boundary.",
                f"Disable {interface.protocol.upper()} {', '.join(directions)} on this interface unless the assessment policy documents a required trusted use.",
                Severity.MEDIUM,
                evidence,
                (CISCO_IOS_DISCOVERY_GUIDE,),
            ))

    def check_switch_edge(self, parser: BaseDeviceParser) -> None:
        ios = self._ios(parser)
        if ios.get_version() == "?":
            return
        for interface in ios.get_switch_edge_interfaces():
            if not interface.active or interface.role != "access-edge" or interface.mode == "routed":
                continue
            evidence = tuple(item.text for item in interface.evidence) + (
                f"assessment policy: {interface.interface} role access-edge",
            )
            if interface.mode == "trunk":
                self.add_issue(self._finding(
                    parser, "cisco.ios.layer2.access_edge_trunk",
                    "Access-edge interface is configured as a trunk",
                    f"Interface {interface.interface} is explicitly classified access-edge but its effective switchport mode is trunk.",
                    "An unintended trunk can expose multiple VLANs to an endpoint and enable VLAN-hopping or segmentation bypass.",
                    "Configure a static access VLAN, or reclassify the interface as an approved uplink with documented trunk scope.",
                    Severity.HIGH, evidence, (CISCO_IOS_ROUTING_HARDENING_GUIDE,),
                ))
                continue
            if interface.mode not in {"access", "switchport"}:
                continue
            if interface.dhcp_trusted or interface.arp_trusted:
                trusted = ", ".join(
                    name for name, enabled in (
                        ("DHCP snooping", interface.dhcp_trusted),
                        ("ARP inspection", interface.arp_trusted),
                    ) if enabled
                )
                self.add_issue(self._finding(
                    parser, "cisco.ios.layer2.access_edge_trust",
                    "Access-edge interface is trusted by spoofing protections",
                    f"Interface {interface.interface} is explicitly classified access-edge but is trusted for {trusted}.",
                    "Trust bypasses validation intended to block rogue DHCP or forged ARP messages from endpoint-facing ports.",
                    "Remove trust from this access edge; reserve trust for explicitly classified DHCP-server or uplink ports.",
                    Severity.HIGH, evidence, (CISCO_IOS_ROUTING_HARDENING_GUIDE,),
                ))
            mechanisms = (
                ("dhcp_snooping", interface.dhcp_snooping, "DHCP snooping for its access VLAN", interface.access_vlan is not None),
                ("arp_inspection", interface.arp_inspection, "Dynamic ARP Inspection for its access VLAN", interface.access_vlan is not None),
                ("source_guard", interface.source_guard, "IP Source Guard", True),
                ("port_security", interface.port_security, "port security", True),
            )
            for suffix, present, label, applicable in mechanisms:
                if present or not applicable:
                    continue
                self.add_issue(self._finding(
                    parser, f"cisco.ios.layer2.access_edge.{suffix}",
                    f"Access-edge interface lacks {label}",
                    f"Interface {interface.interface} is explicitly classified access-edge but lacks {label}."
                    + (f" Its effective access VLAN is {interface.access_vlan}." if interface.access_vlan else " Its access VLAN is unresolved."),
                    "A connected endpoint may spoof addressing or identities, introduce a rogue service, or exceed the intended endpoint count.",
                    f"Enable and validate {label} for this access edge where supported by the exact switch model and attachment design.",
                    Severity.MEDIUM, evidence, (CISCO_IOS_ROUTING_HARDENING_GUIDE,),
                ))
    def analyze(self, parser: BaseDeviceParser) -> None:
        if not self._applicable(parser):
            return
        self.check_aaa(parser)
        self.check_management_lines(parser)
        self.check_ssh_policy(parser)
        self.check_credentials(parser)
        self.check_snmp(parser)
        self.check_logging(parser)
        self.check_ntp(parser)
        self.check_banner(parser)
        self.check_unnecessary_services(parser)
        self.check_interface_protections(parser)
        self.check_control_plane(parser)
        self.check_crypto(parser)
        self.check_routing(parser)
        self.check_discovery(parser)
        self.check_switch_edge(parser)
