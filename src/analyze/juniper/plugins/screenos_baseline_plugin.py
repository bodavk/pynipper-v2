"""Effective-state hardening checks for legacy Juniper ScreenOS exports."""

from collections import defaultdict

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.credentials import (
    CredentialPropertyState,
    credential_policy_from_context,
    evaluate_credential,
)
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import CredentialStorageAssessment
from src.devices.juniper.screenos import JuniperScreenOSParser, ScreenOSCommand


SCREENOS_DOCUMENTATION = (
    "https://www.juniper.net/documentation/product/us/en/screenos/6.3.0/"
)
SCREENOS_IPV4_CLI = (
    "https://www.juniper.net/documentation/software/screenos/"
    "screenos6.3.0/630_ipv4_cli.pdf"
)
SCREENOS_R27_RELEASE_NOTES = (
    "https://www.juniper.net/documentation/software/screenos/"
    "screenos6.3.0/rn-630r27-rev01.pdf"
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
        basis=None,
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
            basis=basis,
        )

    def _commands(
        self, parser: BaseDeviceParser, prefix: tuple[str, ...]
    ) -> list[ScreenOSCommand]:
        return self._screenos(parser).get_effective_commands(prefix)

    @staticmethod
    def _evidence(commands: list[ScreenOSCommand]) -> tuple[str, ...]:
        return tuple(command.evidence for command in commands)

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

        session_controls = screenos.get_session_controls()
        for control in session_controls:
            if (
                not control.active
                or control.resolution_state != "known"
                or control.timeout_minutes is None
                or (0 < control.timeout_minutes <= 10)
            ):
                continue
            evidence = tuple(item for item in control.evidence)
            if control.scope == "console-telnet":
                self.add_issue(
                    self._finding(
                        parser,
                        "juniper.screenos.administration.session_timeout",
                        "Administrative session timeout is excessive",
                        f"The effective console/Telnet timeout is {control.timeout_minutes} minutes; zero disables the timeout and the target maximum is 10 minutes.",
                        "Abandoned authenticated sessions can remain usable for an excessive period.",
                        "Set console timeout to a policy-approved value of 10 minutes or less.",
                        Severity.MEDIUM,
                        evidence or ("ScreenOS 6.3 console timeout state",),
                        (SCREENOS_DOCUMENTATION, SCREENOS_IPV4_CLI),
                    )
                )
            elif control.scope == "web-management":
                self.add_issue(
                    self._finding(
                        parser,
                        "juniper.screenos.administration.web_session_timeout",
                        "Web administrative session timeout is excessive",
                        f"The effective Web administrative timeout is {control.timeout_minutes} minutes; zero disables the timeout and the target maximum is 10 minutes.",
                        "An abandoned authenticated WebUI session can remain usable for an excessive period.",
                        "Set admin auth web timeout to a policy-approved value of 10 minutes or less.",
                        Severity.MEDIUM,
                        evidence or ("ScreenOS 6.3 Web administration timeout state",),
                        (
                            SCREENOS_DOCUMENTATION,
                            SCREENOS_IPV4_CLI,
                            SCREENOS_R27_RELEASE_NOTES,
                        ),
                    )
                )
            elif control.scope == "authentication-server":
                uses = ", ".join(control.uses)
                rule_id = (
                    "juniper.screenos.administration.remote_session_timeout"
                    if "administrator" in control.uses
                    else "juniper.screenos.authentication.session_timeout"
                )
                title = (
                    "Remote administrator session timeout is excessive"
                    if "administrator" in control.uses
                    else "Authentication-user timeout is excessive"
                )
                self.add_issue(
                    self._finding(
                        parser,
                        rule_id,
                        title,
                        f"Bound authentication server '{control.name}' is used by {uses} with an effective timeout of {control.timeout_minutes} minutes; zero disables reauthentication timeout.",
                        "A stolen authenticated session or cached authentication state can remain useful for an excessive period.",
                        "Set the bound auth-server timeout to a policy-approved value of 10 minutes or less.",
                        Severity.MEDIUM,
                        evidence or (f"bound auth-server {control.name}",),
                        (SCREENOS_DOCUMENTATION, SCREENOS_IPV4_CLI),
                    )
                )

        for control in session_controls:
            if (
                control.scope == "authentication-server"
                and control.active
                and control.resolution_state == "unresolved"
            ):
                self.add_issue(
                    self._finding(
                        parser,
                        "juniper.screenos.authentication.server_reference",
                        "Active authentication-server reference is unresolved",
                        f"Authentication server '{control.name}' is referenced by {', '.join(control.uses)}, but no matching server object is present in the export.",
                        "The static export cannot establish the authentication source or its effective session policy.",
                        "Export the complete auth-server configuration and correct or remove the unresolved binding.",
                        Severity.HIGH,
                        tuple(item for item in control.evidence)
                        or (f"unresolved auth-server {control.name}",),
                        (SCREENOS_DOCUMENTATION, SCREENOS_IPV4_CLI),
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
                        (command.evidence,),
                        (SCREENOS_DOCUMENTATION, ORIGINAL_ADMIN_REFERENCE),
                    )
                )

    def check_credentials_and_banner(self, parser: BaseDeviceParser) -> None:
        policy = credential_policy_from_context(parser.assessment_context)
        for credential in self._screenos(parser).get_credential_metadata():
            result = evaluate_credential(credential, policy)
            if (
                result.storage_assessment == CredentialStorageAssessment.EMPTY
                or result.default_state == CredentialPropertyState.FAIL
                or result.blocklist_state == CredentialPropertyState.FAIL
            ):
                self.add_issue(
                    self._finding(
                        parser,
                        "juniper.screenos.credentials.default_or_empty",
                        "Administrator credential is empty or a known default",
                        (
                            f"The {credential.context} credential for '{credential.account}' has storage "
                            f"classification '{result.storage_assessment.value}' under credential policy "
                            f"'{result.policy_version}' and exact-default comparison "
                            f"'{result.default_assessment.value}'; the blocklist comparison "
                            f"{result.blocklist_summary}. The value is redacted."
                        ),
                        "Default administrative credentials can provide immediate privileged access.",
                        "Set a unique high-entropy credential, restrict manager sources, and plan platform migration.",
                        Severity.CRITICAL,
                        tuple(item for item in credential.evidence),
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
            item.evidence[0] for item in destinations if item.evidence
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
                    (community.evidence,),
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
                    tuple(item for item in policy.evidence),
                    (SCREENOS_DOCUMENTATION,),
                )
            )

    def check_policy_default(self, parser: BaseDeviceParser) -> None:
        state = self._screenos(parser).get_firewall_policy_state()
        if state.resolution_state != "explicit" or state.default_action != "permit-all":
            return
        self.add_issue(
            self._finding(
                parser,
                "juniper.screenos.policy.default_permit",
                "Unmatched interzone traffic is permitted by default",
                f"ScreenOS 6.3 default-permit-all is explicitly enabled; {state.configured_policy_count} enabled explicit policies are present, but unmatched interzone traffic bypasses them and is permitted.",
                "Traffic that fails to match an interzone or global policy can cross the firewall without an explicit allow rule.",
                "Unset policy default-permit-all and create narrowly scoped explicit permit policies.",
                Severity.CRITICAL,
                tuple(item for item in state.evidence),
                (SCREENOS_DOCUMENTATION, SCREENOS_IPV4_CLI),
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
                    (proposal.evidence,),
                    (SCREENOS_DOCUMENTATION, JUNIPER_IPSEC_GUIDE),
                )
            )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_administration(parser)
        self.check_snmp(parser)
        self.check_policy_logging(parser)
        self.check_policy_default(parser)
        self.check_vpn_crypto(parser)
        if not self._applicable(parser):
            return
        self.check_lifecycle(parser)
        self.check_credentials_and_banner(parser)
        self.check_logging(parser)
        self.check_ntp(parser)
