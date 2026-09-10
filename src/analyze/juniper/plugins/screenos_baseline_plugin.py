"""Effective-state hardening checks for legacy Juniper ScreenOS exports."""

from collections import defaultdict

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.juniper.screenos import JuniperScreenOSParser, ScreenOSCommand


SCREENOS_DOCUMENTATION = (
    "https://www.juniper.net/documentation/product/us/en/screenos/6.3.0/"
)
JUNIPER_IPSEC_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/vpn-ipsec/"
    "topics/topic-map/security-ipsec-vpn-configuration-overview.html"
)
ORIGINAL_ADMIN_REFERENCE = (
    "reference/nipper-ng-original/libnipper-0.12.6/"
    "Juniper-ScreenOS/administration.cpp"
)
ORIGINAL_SNMP_REFERENCE = (
    "reference/nipper-ng-original/libnipper-0.12.6/Juniper-ScreenOS/snmp.cpp"
)


class PluginScreenOSBaseline(BasePlugin):
    """Restore high-value ScreenOS checks while respecting set/unset state."""

    _KNOWN_DEFAULT_PASSWORD_HASHES = {
        value.casefold()
        for value in {
            "nBh1JgrWI8BMcxVE1sfD3ZHtPvNqOn",
            "nIEXLGrQKPGFclpK2srC+GItLBIaYn",
            "nEgTC0rULyNDcfOHZsFDJSAtfiPqWn",
            "nJBnMRrmG7cFc3ALdsWMLIKtWHC4ln",
            "nL1kB1ryFpdIcuHBksgKNQLttDFjCn",
            "nA0XKervNIgBctzLBsjNKyEtOcM5an",
            "nFR1M7r3PBEHcA0FWs1JJ8LtBTOHIn",
            "nDQFBzrfECTDcLFD7sRA2kMtP4FNwn",
            "nH/vDirbE5GBcjdGoslAEBBtHFA6En",
            "nMjFM0rdC9iOc+xIFsGEm3LtAeGZhn",
            "nO8gOKrtJ/YMclhNlsoJCrCtllAL7n",
            "nDC0GjreNnlGcIPHTsGOUAFt6BJZdn",
            "nKv3LvrdAVtOcE5EcsGIpYBtniNbUn",
            "nKVUM2rwMUzPcrkG5sWIHdCtqkAibn",
        }
    }

    @staticmethod
    def _screenos(parser: BaseDeviceParser) -> JuniperScreenOSParser:
        if not isinstance(parser, JuniperScreenOSParser):
            raise TypeError("PluginScreenOSBaseline requires a ScreenOS parser")
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
                "An attacker with network reachability or configuration access may "
                "exploit this legacy-platform weakness."
            ),
            recommendation=recommendation,
            severity=severity,
            evidence=evidence,
            references=references,
        )

    def _commands(
        self, parser: BaseDeviceParser, prefix: tuple[str, ...]
    ) -> list[ScreenOSCommand]:
        return self._screenos(parser).get_effective_commands(prefix)

    @staticmethod
    def _evidence(commands: list[ScreenOSCommand]) -> tuple[str, ...]:
        return tuple(command.evidence.text for command in commands)

    def _applicable(self, parser: BaseDeviceParser) -> bool:
        return self._screenos(parser).get_version() != "?"

    def check_lifecycle(self, parser: BaseDeviceParser) -> None:
        screenos = self._screenos(parser)
        self.add_issue(
            self._finding(
                parser,
                "juniper.screenos.lifecycle.end_of_life",
                "ScreenOS is an end-of-life platform",
                f"The configuration identifies ScreenOS version {screenos.get_version()}; Juniper classifies ScreenOS as EOL.",
                "Unsupported software does not receive normal security fixes and may retain publicly known vulnerabilities.",
                "Migrate the configuration and policy to a supported security platform; use compensating controls only as an interim measure.",
                Severity.CRITICAL,
                (f"ScreenOS version {screenos.get_version()}",),
                (SCREENOS_DOCUMENTATION,),
            )
        )

    def check_administration(self, parser: BaseDeviceParser) -> None:
        screenos = self._screenos(parser)
        management_enabled = any(
            service.protocol in {"ssh", "https", "http", "telnet"}
            for service in screenos.get_normalized_config().management_services.items
        )
        if management_enabled and not screenos.manager_ips and not any(
            interface.manager_ips for interface in screenos.interfaces.values()
        ):
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.screenos.administration.manager_sources",
                    "Administrative source restrictions are missing",
                    "Management is enabled but no effective global or per-interface manager-IP restriction is configured.",
                    "Any host with network reachability can attempt administrative authentication.",
                    "Restrict management to explicit manager IP addresses and dedicated trusted interfaces.",
                    Severity.HIGH,
                    ("admin/interface manager-IP restrictions absent",),
                    (SCREENOS_DOCUMENTATION, ORIGINAL_ADMIN_REFERENCE),
                )
            )

        timeout_commands = self._commands(parser, ("console", "timeout"))
        if timeout_commands:
            value = timeout_commands[-1].tokens[-1]
            if value.isdigit() and (int(value) == 0 or int(value) > 10):
                self.add_issue(
                    self._finding(
                        parser,
                        "juniper.screenos.administration.session_timeout",
                        "Administrative session timeout is excessive",
                        f"The effective console/SSH/Telnet timeout is {value} minutes; the target maximum is 10 minutes.",
                        "Abandoned authenticated sessions can remain usable for an excessive period.",
                        "Set console timeout to a policy-approved value of 10 minutes or less.",
                        Severity.MEDIUM,
                        self._evidence(timeout_commands[-1:]),
                        (SCREENOS_DOCUMENTATION, ORIGINAL_ADMIN_REFERENCE),
                    )
                )

        attempts = self._commands(parser, ("admin", "access", "attempts"))
        if attempts:
            value = attempts[-1].tokens[-1]
            if value.isdigit() and int(value) > 3:
                self.add_issue(
                    self._finding(
                        parser,
                        "juniper.screenos.administration.login_attempts",
                        "Excessive administrator login attempts are allowed",
                        f"The effective administrator access-attempt limit is {value}.",
                        "Additional guesses increase exposure to online password attacks.",
                        "Set admin access attempts to three or fewer and monitor authentication failures.",
                        Severity.MEDIUM,
                        self._evidence(attempts[-1:]),
                        (SCREENOS_DOCUMENTATION,),
                    )
                )

        if screenos.get_services()["ssh"]:
            versions = self._commands(parser, ("ssh", "version"))
            effective = versions[-1].tokens[-1] if versions else "v1-and-v2 default"
            if effective != "v2":
                self.add_issue(
                    self._finding(
                        parser,
                        "juniper.screenos.ssh.protocol_version",
                        "SSH protocol version 1 remains available",
                        f"SSH management is active with effective version state '{effective}'.",
                        "SSHv1 has obsolete protocol design and cryptographic weaknesses.",
                        "Configure set ssh version v2 and remove SSHv1 dependencies.",
                        Severity.HIGH,
                        self._evidence(versions) or ("set ssh version v2 absent",),
                        (SCREENOS_DOCUMENTATION, ORIGINAL_ADMIN_REFERENCE),
                    )
                )

        ssl_interfaces = [
            interface.name
            for interface in screenos.interfaces.values()
            if not interface.disabled and "https" in interface.management_methods
        ]
        if ssl_interfaces and not self._commands(parser, ("ssl", "enable")):
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.screenos.https.global_activation",
                    "HTTPS interface configuration is not globally active",
                    f"Interfaces {', '.join(ssl_interfaces)} permit SSL management, but global 'set ssl enable' is absent.",
                    "Operators may believe encrypted management is available when the global service is disabled.",
                    "Enable SSL globally and verify HTTPS, or remove the unused per-interface SSL settings.",
                    Severity.MEDIUM,
                    tuple(f"interface {name} manage ssl" for name in ssl_interfaces),
                    (SCREENOS_DOCUMENTATION, ORIGINAL_ADMIN_REFERENCE),
                )
            )

        weak_ciphers = self._commands(parser, ("ssl", "encrypt"))
        for command in weak_ciphers:
            algorithms = set(command.tokens[2:])
            weak = sorted(
                algorithms.intersection(
                    {"des", "3des", "rc4", "rc4-40", "md5", "sha-1"}
                )
            )
            if weak:
                self.add_issue(
                    self._finding(
                        parser,
                        "juniper.screenos.https.legacy_cipher",
                        "Legacy HTTPS cipher is configured",
                        f"The effective SSL cipher definition includes {', '.join(weak)}.",
                        "Legacy encryption or hashes do not meet current transport-security policy.",
                        "Remove web management from ScreenOS and prioritize platform migration; restrict HTTPS sources in the interim.",
                        Severity.HIGH,
                        (command.evidence.text,),
                        (SCREENOS_DOCUMENTATION, ORIGINAL_ADMIN_REFERENCE),
                    )
                )

    def check_credentials_and_banner(self, parser: BaseDeviceParser) -> None:
        credential_commands = self._commands(parser, ("admin", "password"))
        credential_commands += self._commands(parser, ("admin", "user"))
        for command in credential_commands:
            tokens = command.tokens
            if "password" not in tokens:
                continue
            index = tokens.index("password")
            value = tokens[index + 1] if index + 1 < len(tokens) else ""
            if (
                not value
                or value.casefold() in {"password", "netscreen", "admin", "administrator"}
                or value.casefold() in self._KNOWN_DEFAULT_PASSWORD_HASHES
            ):
                username = tokens[2] if tokens[:2] == ("admin", "user") and len(tokens) > 2 else "primary admin"
                self.add_issue(
                    self._finding(
                        parser,
                        "juniper.screenos.credentials.default_or_empty",
                        "Administrator credential is empty or a known default",
                        f"The {username} credential matches an empty or known default value; the value is redacted.",
                        "Default administrative credentials can provide immediate privileged access.",
                        "Set a unique high-entropy credential, restrict manager sources, and plan platform migration.",
                        Severity.CRITICAL,
                        (command.evidence.text,),
                        (SCREENOS_DOCUMENTATION,),
                    )
                )

        banners = self._commands(parser, ("admin", "auth", "banner"))
        if not banners:
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.screenos.administration.login_banner",
                    "Administrative login banner is missing",
                    "No effective administrator authentication banner is configured.",
                    "Users may not receive the required authorized-use and monitoring notice.",
                    "Configure approved pre-login banners for the enabled administrative channels.",
                    Severity.LOW,
                    ("admin auth banner absent",),
                    (SCREENOS_DOCUMENTATION, ORIGINAL_ADMIN_REFERENCE),
                )
            )

    def check_logging(self, parser: BaseDeviceParser) -> None:
        destinations = self._screenos(parser).get_logging_destinations()
        active = [item for item in destinations if item.state.value == "enabled"]
        if active:
            return
        evidence = tuple(
            item.evidence[0].text for item in destinations if item.evidence
        ) or ("enabled syslog destination absent",)
        self.add_issue(
            self._finding(
                parser,
                "juniper.screenos.logging.remote_destination",
                "Remote syslog is not effectively configured",
                "No enabled ScreenOS syslog destination is present.",
                "Locally retained events can be lost during compromise or device failure.",
                "Configure a protected syslog destination and enable syslog transmission.",
                Severity.MEDIUM,
                evidence,
                (SCREENOS_DOCUMENTATION,),
            )
        )

    def check_snmp(self, parser: BaseDeviceParser) -> None:
        screenos = self._screenos(parser)
        snmp_interfaces = [
            interface
            for interface in screenos.interfaces.values()
            if not interface.disabled and "snmp" in interface.management_methods
        ]
        if not snmp_interfaces:
            return
        communities = self._commands(parser, ("snmp", "community"))
        hosts = self._commands(parser, ("snmp", "host"))
        for community in communities:
            name = community.tokens[2] if len(community.tokens) > 2 else ""
            access = (
                "read-write"
                if "read-write" in community.tokens
                else "read-only"
            )
            restricted = any(
                len(host.tokens) > 2 and host.tokens[2] == name for host in hosts
            )
            severity = (
                Severity.HIGH
                if access == "read-write"
                or name in {"public", "private"}
                or not restricted
                else Severity.MEDIUM
            )
            qualifiers = [access]
            if name in {"public", "private"}:
                qualifiers.append("exact default community")
            if not restricted:
                qualifiers.append("no matching manager host restriction")
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.screenos.snmp.legacy_community",
                    "Legacy ScreenOS SNMP community is active",
                    f"SNMP is enabled on {', '.join(item.name for item in snmp_interfaces)} with {', '.join(qualifiers)}; the community is redacted.",
                    "ScreenOS supports community-based SNMP only, without SNMPv3 authentication and privacy.",
                    "Disable SNMP or constrain it to read-only access from explicit manager hosts until the platform is replaced.",
                    severity,
                    (community.evidence.text,),
                    (SCREENOS_DOCUMENTATION, ORIGINAL_SNMP_REFERENCE),
                )
            )

    def check_ntp(self, parser: BaseDeviceParser) -> None:
        servers = self._commands(parser, ("ntp", "server"))
        if servers:
            return
        self.add_issue(
            self._finding(
                parser,
                "juniper.screenos.ntp.servers",
                "NTP synchronization is not configured",
                "No effective ScreenOS NTP server command is present.",
                "Inaccurate time undermines event correlation and forensic timelines.",
                "Configure trusted NTP servers and restrict their reachability.",
                Severity.MEDIUM,
                ("ntp server absent",),
                (SCREENOS_DOCUMENTATION,),
            )
        )

    def check_policy_logging(self, parser: BaseDeviceParser) -> None:
        for policy in self._screenos(parser).policies.values():
            if policy.disabled or policy.action.casefold() not in {"permit", "accept"}:
                continue
            if policy.tracking:
                continue
            untrusted = policy.from_zone.casefold() in {"untrust", "dmz", "public"}
            broad = all(
                values and all(value.casefold() == "any" for value in values)
                for values in (policy.sources, policy.destinations, policy.services)
            )
            if not (untrusted or broad):
                continue
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.screenos.policy.unlogged_permit",
                    "High-risk permit policy is not logged",
                    f"Enabled policy ID {policy.policy_id} permits traffic from '{policy.from_zone}' to '{policy.to_zone}' without session logging.",
                    "Security-relevant permitted traffic may be unavailable for monitoring and incident investigation.",
                    "Enable appropriate session logging and send the resulting events to a protected remote destination.",
                    Severity.MEDIUM,
                    tuple(item.text for item in policy.evidence),
                    (SCREENOS_DOCUMENTATION,),
                )
            )

    def check_vpn_crypto(self, parser: BaseDeviceParser) -> None:
        commands = self._screenos(parser).effective_commands
        references: set[str] = set()
        for command in commands:
            if not (
                command.tokens[:2] == ("ike", "gateway")
                or command.tokens[:1] == ("vpn",)
            ):
                continue
            if "proposal" in command.tokens:
                index = command.tokens.index("proposal")
                if index + 1 < len(command.tokens):
                    references.add(command.tokens[index + 1])

        weak_values = {
            "des",
            "3des",
            "md5",
            "sha-1",
            "pre-g1",
            "pre-g2",
            "nopfs-esp-des-md5",
            "nopfs-esp-3des-md5",
        }
        proposals = self._commands(parser, ("ike", "p1-proposal"))
        proposals += self._commands(parser, ("ike", "p2-proposal"))
        for proposal in proposals:
            if len(proposal.tokens) < 3 or proposal.tokens[2] not in references:
                continue
            weak = sorted(
                token
                for token in set(proposal.tokens[3:])
                if token in weak_values
                or any(
                    f"-{algorithm}-" in f"-{token}-"
                    for algorithm in ("des", "3des", "md5")
                )
            )
            if not weak:
                continue
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.screenos.vpn.weak_proposal",
                    "Active VPN references a weak proposal",
                    f"Referenced proposal '{proposal.tokens[2]}' contains weak algorithms or groups: {', '.join(weak)}.",
                    "Weak IKE or IPsec cryptography can reduce VPN confidentiality and resistance to key recovery.",
                    "Replace the proposal with the strongest ScreenOS-supported "
                    "suite as an interim control, then migrate the VPN to a "
                    "supported platform.",
                    Severity.HIGH,
                    (proposal.evidence.text,),
                    (SCREENOS_DOCUMENTATION, JUNIPER_IPSEC_GUIDE),
                )
            )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_administration(parser)
        self.check_snmp(parser)
        self.check_policy_logging(parser)
        self.check_vpn_crypto(parser)
        if not self._applicable(parser):
            return
        self.check_lifecycle(parser)
        self.check_credentials_and_banner(parser)
        self.check_logging(parser)
        self.check_ntp(parser)
