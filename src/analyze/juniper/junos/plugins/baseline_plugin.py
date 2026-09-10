"""Version-aware Junos management and control-plane hardening checks."""

from collections import defaultdict

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.juniper.junos import JunOSParser, JunosStatement


JUNIPER_ACCESS_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "user-access/topics/topic-map/junos-software-remote-access-overview.html"
)
JUNIPER_AUTH_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "user-access/topics/topic-map/junos-os-authentication-order.html"
)
JUNIPER_LOGIN_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "user-access/topics/topic-map/junos-os-login-settings.html"
)
JUNIPER_SSH_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/"
    "topics/ref/statement/ssh-edit-system.html"
)
JUNIPER_SNMP_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "network-mgmt/topics/topic-map/configure-snmpv3.html"
)
JUNIPER_SYSLOG_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "network-mgmt/topics/topic-map/syslog-over-tls.html"
)
JUNIPER_NTP_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "time-mgmt/topics/concept/ntp-authentication-keys.html"
)
JUNIPER_FILTER_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "routing-policy/topics/concept/firewall-filter-stateless-basic-uses-for.html"
)
JUNIPER_REDIRECT_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/"
    "topics/ref/statement/no-redirects-edit-system.html"
)


class PluginJunOSBaseline(BasePlugin):
    """Evaluate explicit Junos security state without inventing release defaults."""

    _WEAK_SSH = {
        "ciphers": {
            "3des-cbc",
            "aes128-cbc",
            "aes192-cbc",
            "aes256-cbc",
            "blowfish-cbc",
            "cast128-cbc",
            "arcfour",
            "arcfour128",
            "arcfour256",
        },
        "macs": {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96"},
        "key-exchange": {
            "dh-group1-sha1",
            "dh-group14-sha1",
            "group-exchange-sha1",
        },
        "hostkey-algorithm": {"ssh-dss", "ssh-rsa"},
    }

    @staticmethod
    def _junos(parser: BaseDeviceParser) -> JunOSParser:
        if not isinstance(parser, JunOSParser):
            raise TypeError("PluginJunOSBaseline requires a Junos parser")
        return parser

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
        references: tuple[str, ...],
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            device=parser.device_type,
            title=title,
            observation=observation,
            impact=impact,
            exploitability=(
                "An attacker with management-plane reachability may exploit the "
                "effective weakness."
            ),
            recommendation=recommendation,
            severity=severity,
            evidence=evidence,
            references=references,
        )

    @staticmethod
    def _texts(statements: list[JunosStatement]) -> tuple[str, ...]:
        return tuple(statement.evidence.text for statement in statements)

    def _statements(
        self, parser: BaseDeviceParser, prefix: tuple[str, ...]
    ) -> list[JunosStatement]:
        return self._junos(parser).get_active_statements(prefix)

    def _applicable(self, parser: BaseDeviceParser) -> bool:
        junos = self._junos(parser)
        return not junos.parse_error and junos.get_version() != "?"

    def check_authentication(self, parser: BaseDeviceParser) -> None:
        authentication_order = self._statements(parser, ("system", "authentication-order"))
        order_tokens = {
            token
            for statement in authentication_order
            for token in statement.path[2:]
        }
        if not order_tokens.intersection({"radius", "tacplus"}):
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.junos.authentication.centralized",
                    "Centralized administrator authentication is not configured",
                    "The effective authentication order uses only local passwords or the local-password default.",
                    "Local-only authentication reduces centralized access control and accountability.",
                    "Configure RADIUS or TACACS+ first in authentication-order and retain a tested local fallback according to policy.",
                    Severity.MEDIUM,
                    self._texts(authentication_order) or ("system authentication-order absent",),
                    (JUNIPER_AUTH_GUIDE,),
                )
            )

        retries = self._statements(
            parser, ("system", "login", "retry-options", "tries-before-disconnect")
        )
        if retries:
            value = retries[-1].path[-1]
            if value.isdigit() and int(value) > 3:
                self.add_issue(
                    self._finding(
                        parser,
                        "juniper.junos.authentication.login_attempts",
                        "Excessive login attempts are permitted",
                        f"The effective tries-before-disconnect value is {value}; the Junos default and hardened target is three attempts.",
                        "Additional guesses increase exposure to online password attacks.",
                        "Set system login retry-options tries-before-disconnect to 3 or fewer.",
                        Severity.MEDIUM,
                        self._texts(retries[-1:]),
                        (JUNIPER_LOGIN_GUIDE,),
                    )
                )

        lockout = self._statements(
            parser, ("system", "login", "retry-options", "lockout-period")
        )
        if not lockout:
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.junos.authentication.lockout",
                    "Administrative account lockout is not configured",
                    "No effective login retry-options lockout-period is configured.",
                    "Repeated password guessing is not interrupted by a timed account lockout.",
                    "Configure a policy-approved lockout-period and test the recovery procedure.",
                    Severity.MEDIUM,
                    ("system login retry-options lockout-period absent",),
                    (JUNIPER_LOGIN_GUIDE,),
                )
            )

        for user in self._junos(parser).get_users():
            if user["class"] != "super-user":
                continue
            if not user["authentication"]:
                self.add_issue(
                    self._finding(
                        parser,
                        "juniper.junos.authentication.super_user",
                        "Super-user account lacks explicit authentication",
                        f"Administrative user '{user['username']}' has class super-user but no effective authentication method.",
                        "An unusable or unexpectedly inherited account can undermine intended administrative access controls.",
                        "Configure an approved SSH key or strong encrypted password, or remove the account.",
                        Severity.HIGH,
                        tuple(item.text for item in user["evidence"]),
                        (JUNIPER_AUTH_GUIDE,),
                    )
                )

        for statement in self._statements(parser, ("system", "login", "user")):
            path = statement.path
            if "authentication" not in path:
                continue
            auth_index = path.index("authentication")
            suffix = path[auth_index + 1 :]
            if not suffix:
                continue
            method = suffix[0]
            value = suffix[1] if len(suffix) > 1 else ""
            weak = method == "plain-text-password" or (
                method == "encrypted-password"
                and value.startswith(("$1$", "$9$", "$md5$"))
            )
            if weak:
                username = path[3] if len(path) > 3 else "unknown"
                self.add_issue(
                    self._finding(
                        parser,
                        "juniper.junos.authentication.weak_storage",
                        "Administrative credential uses weak storage",
                        f"User '{username}' uses '{method}' with a plaintext, reversible, or legacy representation; the value is redacted.",
                        "Configuration disclosure can expose or accelerate recovery of the credential.",
                        "Replace the credential with a supported strong hash or SSH public key.",
                        Severity.HIGH,
                        (statement.evidence.text,),
                        (JUNIPER_AUTH_GUIDE,),
                    )
                )

    def check_ssh_algorithms(self, parser: BaseDeviceParser) -> None:
        if not self._junos(parser).get_services()["ssh"]:
            return
        for field, weak_values in self._WEAK_SSH.items():
            statements = self._statements(
                parser, ("system", "services", "ssh", field)
            )
            configured = {
                token.casefold()
                for statement in statements
                for token in statement.path[4:]
            }
            weak = sorted(configured.intersection(weak_values))
            if not weak:
                continue
            self.add_issue(
                self._finding(
                    parser,
                    f"juniper.junos.ssh.weak_{field.replace('-', '_')}",
                    f"Weak SSH {field.replace('-', ' ')} explicitly enabled",
                    f"The effective SSH {field} list includes: {', '.join(weak)}.",
                    "Legacy SSH algorithms weaken confidentiality, integrity, or server authentication.",
                    f"Remove the weak {field} values and retain only algorithms approved by organizational policy.",
                    Severity.HIGH,
                    self._texts(statements),
                    (JUNIPER_SSH_REFERENCE,),
                )
            )

    def check_additional_services(self, parser: BaseDeviceParser) -> None:
        insecure = {
            "ftp",
            "finger",
            "rlogin",
            "rsh",
            "xnm-clear-text",
        }
        for service in sorted(insecure):
            statements = self._statements(parser, ("system", "services", service))
            if not statements:
                continue
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.junos.services.legacy",
                    "Legacy management service is enabled",
                    f"The effective configuration explicitly enables {service}.",
                    "Clear-text or obsolete services unnecessarily expand the Routing Engine attack surface.",
                    "Delete the service and use SSH/SCP or another authenticated encrypted alternative.",
                    Severity.HIGH,
                    self._texts(statements),
                    (JUNIPER_ACCESS_GUIDE,),
                )
            )

    def check_snmp(self, parser: BaseDeviceParser) -> None:
        communities: dict[str, list[JunosStatement]] = defaultdict(list)
        for statement in self._statements(parser, ("snmp", "community")):
            if len(statement.path) > 2:
                communities[statement.path[2]].append(statement)
        for community, statements in communities.items():
            tokens = {token.casefold() for item in statements for token in item.path[3:]}
            severe = community.casefold() in {"public", "private"} or "read-write" in tokens
            qualifiers = []
            if community.casefold() in {"public", "private"}:
                qualifiers.append("an exact default community")
            if "read-write" in tokens:
                qualifiers.append("read-write authorization")
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.junos.snmp.legacy_community",
                    "Legacy SNMP community is configured",
                    "A community-based SNMP configuration is active"
                    + (f" with {', '.join(qualifiers)}" if qualifiers else "")
                    + "; the community value is redacted.",
                    "SNMPv1/v2c communities do not provide modern per-user authentication and privacy.",
                    "Migrate to SNMPv3 USM with authentication and privacy, then remove the community.",
                    Severity.HIGH if severe else Severity.MEDIUM,
                    tuple(
                        item.evidence.text.replace(community, "<redacted>")
                        for item in statements
                    ),
                    (JUNIPER_SNMP_GUIDE,),
                )
            )

        users: dict[str, list[JunosStatement]] = defaultdict(list)
        prefix = ("snmp", "v3", "usm", "local-engine", "user")
        for statement in self._statements(parser, prefix):
            if len(statement.path) > 5:
                users[statement.path[5]].append(statement)
        for username, statements in users.items():
            values = {
                token.casefold()
                for statement in statements
                for token in statement.path[6:]
            }
            has_auth = any(
                token.startswith("authentication-")
                and token not in {"authentication-password", "authentication-key"}
                for token in values
            )
            has_privacy = any(
                token.startswith("privacy-")
                and token not in {"privacy-password", "privacy-key", "privacy-none"}
                for token in values
            )
            weak = sorted(
                token
                for token in values
                if token in {"authentication-md5", "privacy-des", "privacy-none"}
            )
            if has_auth and has_privacy and not weak:
                continue
            detail = "missing authentication or privacy" if not (has_auth and has_privacy) else f"weak settings: {', '.join(weak)}"
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.junos.snmp.v3_security",
                    "SNMPv3 user security is incomplete",
                    f"SNMPv3 user '{username}' has {detail}; key material is redacted.",
                    "Unauthenticated, unencrypted, or legacy SNMP protection exposes management data and control operations.",
                    "Configure a supported SHA authentication method and AES privacy for the USM user.",
                    Severity.HIGH,
                    tuple(item.evidence.text for item in statements),
                    (JUNIPER_SNMP_GUIDE,),
                )
            )

    def check_logging(self, parser: BaseDeviceParser) -> None:
        destinations = self._junos(parser).get_logging_destinations()
        if destinations:
            return
        self.add_issue(
            self._finding(
                parser,
                "juniper.junos.logging.remote_destination",
                "Remote system logging is not configured",
                "No effective system syslog host destination is present.",
                "Locally stored events can be lost during compromise or device failure.",
                "Configure protected remote syslog destinations; use TLS on supported releases.",
                Severity.MEDIUM,
                ("system syslog host absent",),
                (JUNIPER_SYSLOG_GUIDE,),
            )
        )

    def check_ntp(self, parser: BaseDeviceParser) -> None:
        associations = self._statements(parser, ("system", "ntp", "server"))
        associations += self._statements(parser, ("system", "ntp", "peer"))
        if not associations:
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.junos.ntp.associations",
                    "NTP synchronization is not configured",
                    "No effective NTP server or peer is configured.",
                    "Incorrect time undermines event correlation and time-dependent security controls.",
                    "Configure multiple trusted NTP servers or peers.",
                    Severity.MEDIUM,
                    ("system ntp server/peer absent",),
                    (JUNIPER_NTP_GUIDE,),
                )
            )
            return
        trusted = self._statements(parser, ("system", "ntp", "trusted-key"))
        auth_keys = self._statements(parser, ("system", "ntp", "authentication-key"))
        trusted_ids = {item.path[3] for item in trusted if len(item.path) > 3}
        configured_ids = {item.path[3] for item in auth_keys if len(item.path) > 3}
        association_ids = []
        for item in associations:
            if "key" not in item.path[4:]:
                association_ids.append("")
                continue
            key_index = item.path.index("key", 4)
            association_ids.append(
                item.path[key_index + 1] if key_index + 1 < len(item.path) else ""
            )
        incomplete = any(
            not key_id
            or key_id not in trusted_ids
            or key_id not in configured_ids
            for key_id in association_ids
        )
        if incomplete:
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.junos.ntp.authentication",
                    "NTP authentication is incomplete",
                    "At least one NTP association lacks a key, or no matching authentication/trusted key state is configured.",
                    "A spoofed time source can disrupt logs and time-sensitive security behavior.",
                    "Configure authentication-key and trusted-key, then bind each association to a trusted key ID.",
                    Severity.MEDIUM,
                    self._texts(associations + trusted + auth_keys),
                    (JUNIPER_NTP_GUIDE,),
                )
            )

    def check_routing_engine_filter(self, parser: BaseDeviceParser) -> None:
        attachments = [
            statement
            for statement in self._statements(parser, ("interfaces", "lo0"))
            if "filter" in statement.path
            and "input" in statement.path
            and "family" in statement.path
        ]
        if attachments:
            return
        self.add_issue(
            self._finding(
                parser,
                "juniper.junos.control_plane.lo0_filter",
                "Routing Engine input filter is not attached",
                "No effective family inet or inet6 input firewall filter is attached to lo0.",
                "Unfiltered host-bound traffic increases exposure to scanning and denial-of-service attacks.",
                "Apply a tested, source-restricted control-plane filter to the appropriate lo0 families.",
                Severity.HIGH,
                ("interfaces lo0 family filter input absent",),
                (JUNIPER_FILTER_GUIDE,),
            )
        )

    def check_redirects(self, parser: BaseDeviceParser) -> None:
        if self._statements(parser, ("system", "no-redirects")):
            return
        self.add_issue(
            self._finding(
                parser,
                "juniper.junos.interfaces.redirects",
                "IPv4 redirects are not explicitly disabled",
                "The effective configuration lacks system no-redirects.",
                "Protocol redirects can alter host forwarding decisions on applicable platforms.",
                "Configure system no-redirects, or document the platform-specific condition that makes it inapplicable.",
                Severity.LOW,
                ("system no-redirects absent",),
                (JUNIPER_REDIRECT_REFERENCE,),
            )
        )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_ssh_algorithms(parser)
        self.check_additional_services(parser)
        self.check_snmp(parser)
        if not self._applicable(parser):
            return
        self.check_authentication(parser)
        self.check_logging(parser)
        self.check_ntp(parser)
        self.check_routing_engine_filter(parser)
        self.check_redirects(parser)
