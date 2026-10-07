"""Effective-state hardening checks for legacy Juniper ScreenOS exports."""

from collections import defaultdict

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.controls import ControlOutcome, record_control
from src.analyze.common.credentials import (
    CredentialPropertyState,
    credential_policy_from_context,
    evaluate_credential,
)
from src.analyze.common.issue import Finding, FindingBasis, Severity
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


_TIMEOUT_CONTROLS = {
    "console-telnet": "juniper.screenos.console-timeout",
    "web-management": "juniper.screenos.web-timeout",
    "authentication-server": "juniper.screenos.auth-server-timeout",
}
_VERSION_GATED_CONTROLS = (
    "juniper.screenos.admin-credentials",
    "juniper.screenos.login-banner",
    "juniper.screenos.remote-logging",
    "juniper.screenos.ntp-servers",
)


def record_unused_management(
    parser: BaseDeviceParser,
    screenos: JuniperScreenOSParser,
    control_id: str,
    feature: str,
    instance: str = "device",
) -> None:
    """Not applicable only when no enabled interface relies on an unverified default."""

    unstated = screenos.get_unstated_management_interfaces()
    if unstated:
        record_control(
            parser,
            control_id,
            ControlOutcome.UNKNOWN,
            f"{feature} is not explicitly enabled, but interface(s) {', '.join(unstated[:5])} have no exported "
            "manage statement and the ScreenOS default management services are not verified for this release.",
            instance=instance,
        )
    else:
        record_control(
            parser,
            control_id,
            ControlOutcome.NOT_APPLICABLE,
            f"{feature} is not enabled globally or on any enabled interface.",
            instance=instance,
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

    @staticmethod
    def _record_timeout(parser, screenos, control, excessive: bool) -> None:
        control_id = _TIMEOUT_CONTROLS.get(control.scope)
        if control_id is None:
            return
        server = control.scope == "authentication-server"
        instance = f"auth-server {control.name}" if server else "device"
        source = (
            "documented ScreenOS 6.3 default"
            if control.value_source == "documented-default"
            else "explicit value"
        )
        if excessive:
            record_control(parser, control_id, ControlOutcome.FINDING,
                           f"Effective timeout {control.timeout_minutes} minutes ({source}) is zero or above ten.",
                           instance=instance)
        elif not control.active:
            if server:
                record_control(parser, control_id, ControlOutcome.NOT_APPLICABLE,
                               "The authentication server is not bound to any active use.", instance=instance)
            else:
                record_unused_management(
                    parser, screenos, control_id,
                    "Console/Telnet administration" if control.scope == "console-telnet"
                    else "Web (HTTP/HTTPS) administration",
                )
        elif control.resolution_state == "unresolved":
            record_control(parser, control_id, ControlOutcome.UNKNOWN,
                           "The bound authentication server is not in the export; its timeout is not known.",
                           instance=instance)
        elif control.resolution_state != "known" or control.timeout_minutes is None:
            record_control(parser, control_id, ControlOutcome.UNKNOWN,
                           "The timeout value is malformed.", instance=instance)
        else:
            record_control(parser, control_id, ControlOutcome.NO_FINDING,
                           f"Effective timeout {control.timeout_minutes} minutes ({source}).", instance=instance)

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
                basis=FindingBasis.EXPLICIT_VALUE,
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
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )
            record_control(parser, "juniper.screenos.manager-sources", ControlOutcome.FINDING,
                           "Management is enabled without a global or per-interface manager-IP restriction.")
        elif not management_enabled:
            record_unused_management(parser, screenos, "juniper.screenos.manager-sources",
                                     "SSH, HTTPS, HTTP or Telnet management")
        elif screenos.manager_ips:
            record_control(parser, "juniper.screenos.manager-sources", ControlOutcome.NO_FINDING,
                           f"Global admin manager-ip restricts management to {len(screenos.manager_ips)} source entr"
                           f"{'y' if len(screenos.manager_ips) == 1 else 'ies'}.")
        else:
            record_control(parser, "juniper.screenos.manager-sources", ControlOutcome.UNKNOWN,
                           "Only interface manage-ip values are present; manage-ip sets the interface management "
                           "address, not permitted manager sources, so a source restriction is not established.")

        session_controls = screenos.get_session_controls()
        if screenos.is_screenos_63() and not any(
            control.scope == "authentication-server" for control in session_controls
        ):
            record_control(parser, "juniper.screenos.auth-server-timeout", ControlOutcome.NOT_APPLICABLE,
                           "No authentication server is defined or bound.")
        if not screenos.is_screenos_63():
            for control_id in (*_TIMEOUT_CONTROLS.values(), "juniper.screenos.auth-server-references"):
                record_control(parser, control_id, ControlOutcome.UNKNOWN,
                               f"ScreenOS release '{screenos.get_version()}' is not the verified 6.3 family; timeout "
                               "defaults and authentication-server bindings are not resolved.")
        for control in session_controls:
            excessive = (
                control.active
                and control.resolution_state == "known"
                and control.timeout_minutes is not None
                and not (0 < control.timeout_minutes <= 10)
            )
            self._record_timeout(parser, screenos, control, excessive)
            if not excessive:
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
                        basis=FindingBasis.DOCUMENTED_DEFAULT if control.value_source == "documented-default" else FindingBasis.EXPLICIT_VALUE,
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
                        basis=FindingBasis.DOCUMENTED_DEFAULT if control.value_source == "documented-default" else FindingBasis.EXPLICIT_VALUE,
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
                        basis=FindingBasis.DOCUMENTED_DEFAULT if control.value_source == "documented-default" else FindingBasis.EXPLICIT_VALUE,
                    )
                )

        active_servers = [
            control for control in session_controls
            if control.scope == "authentication-server" and control.active
        ]
        if screenos.is_screenos_63() and not active_servers:
            record_control(parser, "juniper.screenos.auth-server-references", ControlOutcome.NOT_APPLICABLE,
                           "No authentication server is bound to administrators, users, policies or 802.1X.")
        for control in session_controls:
            if (
                control.scope == "authentication-server"
                and control.active
                and control.resolution_state != "unresolved"
            ):
                record_control(parser, "juniper.screenos.auth-server-references", ControlOutcome.NO_FINDING,
                               "The bound authentication server is defined in the export"
                               + (" (built-in local database)." if control.name == "local" else "."),
                               instance=f"auth-server {control.name}")
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
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )
                record_control(parser, "juniper.screenos.auth-server-references", ControlOutcome.FINDING,
                               "The bound authentication server is not defined in the export.",
                               instance=f"auth-server {control.name}")

        attempts = self._commands(parser, ("admin", "access", "attempts"))
        if not attempts:
            record_control(parser, "juniper.screenos.login-attempts", ControlOutcome.UNKNOWN,
                           "admin access attempts is omitted and the ScreenOS default attempt limit is not cited "
                           "for this release.")
        if attempts:
            value = attempts[-1].tokens[-1]
            if not value.isdigit():
                record_control(parser, "juniper.screenos.login-attempts", ControlOutcome.UNKNOWN,
                               "The admin access attempts value is malformed.")
            elif int(value) <= 3:
                record_control(parser, "juniper.screenos.login-attempts", ControlOutcome.NO_FINDING,
                               f"Administrator access attempts are limited to {value}.")
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
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
                record_control(parser, "juniper.screenos.login-attempts", ControlOutcome.FINDING,
                               f"Administrator access attempts are set to {value}, above three.")

        if not screenos.get_services()["ssh"]:
            record_unused_management(parser, screenos, "juniper.screenos.ssh-protocol", "SSH management")
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
                        basis=FindingBasis.EXPLICIT_VALUE if versions else FindingBasis.DOCUMENTED_DEFAULT,
                    )
                )
                record_control(parser, "juniper.screenos.ssh-protocol", ControlOutcome.FINDING,
                               f"SSH management is active with effective version state '{effective}'.")
            else:
                record_control(parser, "juniper.screenos.ssh-protocol", ControlOutcome.NO_FINDING,
                               "SSH management is restricted to protocol version 2.")

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
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )
            record_control(parser, "juniper.screenos.https-activation", ControlOutcome.FINDING,
                           "Interfaces permit SSL management but global 'set ssl enable' is absent.")
        elif ssl_interfaces:
            record_control(parser, "juniper.screenos.https-activation", ControlOutcome.NO_FINDING,
                           "Interfaces permitting SSL management have SSL enabled globally.")
        else:
            record_unused_management(parser, screenos, "juniper.screenos.https-activation",
                                     "Per-interface SSL management")

        weak_ciphers = self._commands(parser, ("ssl", "encrypt"))
        if not weak_ciphers:
            if screenos.get_services()["https"]:
                record_control(parser, "juniper.screenos.https-ciphers", ControlOutcome.UNKNOWN,
                               "HTTPS management is active, 'set ssl encrypt' is omitted and the ScreenOS default "
                               "cipher set is not cited for this release.")
            else:
                record_unused_management(parser, screenos, "juniper.screenos.https-ciphers", "HTTPS management")
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
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
                record_control(parser, "juniper.screenos.https-ciphers", ControlOutcome.FINDING,
                               f"The effective SSL cipher definition includes {', '.join(weak)}.")
            else:
                record_control(parser, "juniper.screenos.https-ciphers", ControlOutcome.NO_FINDING,
                               "The effective SSL cipher definition names no legacy cipher or hash.")

    def check_credentials_and_banner(self, parser: BaseDeviceParser) -> None:
        policy = credential_policy_from_context(parser.assessment_context)
        credentials = self._screenos(parser).get_credential_metadata()
        if not credentials:
            record_control(parser, "juniper.screenos.admin-credentials", ControlOutcome.UNKNOWN,
                           "No administrator password statement is exported.")
        for credential in credentials:
            result = evaluate_credential(credential, policy)
            instance = f"{credential.context} {credential.account}"
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
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
                record_control(parser, "juniper.screenos.admin-credentials", ControlOutcome.FINDING,
                               "The credential is empty or matches a known default or the blocklist.",
                               instance=instance)
            elif result.default_state == CredentialPropertyState.PASS:
                record_control(parser, "juniper.screenos.admin-credentials", ControlOutcome.NO_FINDING,
                               "The credential is not empty and does not equal a known default representation.",
                               instance=instance)
            else:
                record_control(parser, "juniper.screenos.admin-credentials", ControlOutcome.UNKNOWN,
                               "The known-default comparison was not evaluated for this credential.",
                               instance=instance)

        banners = self._commands(parser, ("admin", "auth", "banner"))
        if banners:
            record_control(parser, "juniper.screenos.login-banner", ControlOutcome.NO_FINDING,
                           "An administrator authentication banner is configured.")
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
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )
            record_control(parser, "juniper.screenos.login-banner", ControlOutcome.FINDING,
                           "No administrator authentication banner is configured.")

    def check_logging(self, parser: BaseDeviceParser) -> None:
        destinations = self._screenos(parser).get_logging_destinations()
        active = [item for item in destinations if item.state.value == "enabled"]
        if active:
            record_control(parser, "juniper.screenos.remote-logging", ControlOutcome.NO_FINDING,
                           f"{len(active)} syslog destination(s) are configured with syslog enabled.")
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
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            )
        )
        record_control(parser, "juniper.screenos.remote-logging", ControlOutcome.FINDING,
                       "No enabled syslog destination is configured.")

    def check_snmp(self, parser: BaseDeviceParser) -> None:
        screenos = self._screenos(parser)
        snmp_interfaces = [
            interface
            for interface in screenos.interfaces.values()
            if not interface.disabled and "snmp" in interface.management_methods
        ]
        communities = self._commands(parser, ("snmp", "community"))
        if not snmp_interfaces:
            if communities:
                record_unused_management(parser, screenos, "juniper.screenos.snmp-community", "SNMP management")
            else:
                record_control(parser, "juniper.screenos.snmp-community", ControlOutcome.NOT_APPLICABLE,
                               "No SNMP community is configured and no interface enables SNMP management.")
            return
        if not communities:
            record_control(parser, "juniper.screenos.snmp-community", ControlOutcome.NO_FINDING,
                           "SNMP management is enabled on interfaces but no SNMP community is configured.")
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
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )
            record_control(parser, "juniper.screenos.snmp-community", ControlOutcome.FINDING,
                           f"A {access} SNMP community is active on SNMP-managed interfaces (value redacted).",
                           instance=f"community line {community.evidence.line_number or '?'}")

    def check_ntp(self, parser: BaseDeviceParser) -> None:
        servers = self._commands(parser, ("ntp", "server"))
        if servers:
            record_control(parser, "juniper.screenos.ntp-servers", ControlOutcome.NO_FINDING,
                           f"{len(servers)} NTP server command(s) are configured.")
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
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            )
        )
        record_control(parser, "juniper.screenos.ntp-servers", ControlOutcome.FINDING,
                       "No NTP server is configured.")

    def check_policy_logging(self, parser: BaseDeviceParser) -> None:
        evaluated = False
        for policy in self._screenos(parser).policies.values():
            if policy.disabled or policy.action.casefold() not in {"permit", "accept"}:
                continue
            evaluated = True
            instance = f"policy {policy.policy_id}"
            untrusted = policy.from_zone.casefold() in {"untrust", "dmz", "public"}
            broad = all(
                values and all(value.casefold() == "any" for value in values)
                for values in (policy.sources, policy.destinations, policy.services)
            )
            if policy.tracking:
                record_control(
                    parser, "juniper.screenos.policy-logging",
                    ControlOutcome.NO_FINDING if (untrusted or broad) else ControlOutcome.NOT_APPLICABLE,
                    "The permit policy logs sessions." if (untrusted or broad)
                    else "The permit policy is neither from an untrusted zone nor Any/Any/Any.",
                    instance=instance,
                )
                continue
            if not (untrusted or broad):
                record_control(parser, "juniper.screenos.policy-logging", ControlOutcome.NOT_APPLICABLE,
                               "The permit policy is neither from an untrusted zone nor Any/Any/Any.",
                               instance=instance)
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
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )
            record_control(parser, "juniper.screenos.policy-logging", ControlOutcome.FINDING,
                           "The high-risk permit policy has no session logging configured.", instance=instance)
        if not evaluated:
            record_control(parser, "juniper.screenos.policy-logging", ControlOutcome.NOT_APPLICABLE,
                           "No enabled permit policy is configured.")

    def check_policy_default(self, parser: BaseDeviceParser) -> None:
        state = self._screenos(parser).get_firewall_policy_state()
        if state.resolution_state == "unsupported-release":
            record_control(parser, "juniper.screenos.default-deny", ControlOutcome.UNKNOWN,
                           "The unmatched-policy default is verified only for the ScreenOS 6.3 family.")
        elif state.default_action == "deny-all":
            record_control(parser, "juniper.screenos.default-deny", ControlOutcome.NO_FINDING,
                           "policy default-permit-all is not set; the documented ScreenOS 6.3 default denies "
                           "unmatched interzone traffic.")
        elif not (state.resolution_state == "explicit" and state.default_action == "permit-all"):
            record_control(parser, "juniper.screenos.default-deny", ControlOutcome.UNKNOWN,
                           "The unmatched-policy behavior is not resolved.")
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
                basis=FindingBasis.EXPLICIT_VALUE,
            )
        )
        record_control(parser, "juniper.screenos.default-deny", ControlOutcome.FINDING,
                       "policy default-permit-all is explicitly enabled.")

    def check_vpn_crypto(self, parser: BaseDeviceParser) -> None:
        commands = self._screenos(parser).effective_commands
        references: set[str] = set()
        stated: dict[str, bool] = {}
        for command in commands:
            if not (
                command.tokens[:2] == ("ike", "gateway")
                or command.tokens[:1] == ("vpn",)
            ):
                continue
            group = " ".join(command.tokens[:3] if command.tokens[:1] == ("ike",) else command.tokens[:2])
            stated.setdefault(group, False)
            if "sec-level" in command.tokens:
                stated[group] = True
                record_control(parser, "juniper.screenos.vpn-proposals", ControlOutcome.UNKNOWN,
                               "A predefined sec-level proposal set is used; its algorithms are not evaluated.",
                               instance=group)
            if "proposal" in command.tokens:
                stated[group] = True
                index = command.tokens.index("proposal")
                if index + 2 < len(command.tokens):
                    record_control(parser, "juniper.screenos.vpn-proposals", ControlOutcome.UNKNOWN,
                                   "Only the first proposal name on the statement is evaluated; later tokens "
                                   "are not assessed.", instance=group)
                if index + 1 < len(command.tokens):
                    references.add(command.tokens[index + 1])
        if not stated:
            record_control(parser, "juniper.screenos.vpn-proposals", ControlOutcome.NOT_APPLICABLE,
                           "No IKE gateway or VPN is configured.")
        for group, has_proposal in stated.items():
            if not has_proposal:
                record_control(parser, "juniper.screenos.vpn-proposals", ControlOutcome.UNKNOWN,
                               "No proposal or sec-level is stated and the release default proposal set is not "
                               "cited.", instance=group)

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
        defined = {proposal.tokens[2] for proposal in proposals if len(proposal.tokens) >= 3}
        for name in sorted(references - defined):
            record_control(parser, "juniper.screenos.vpn-proposals", ControlOutcome.UNKNOWN,
                           "The referenced proposal is not defined in the export (predefined suite or unexported "
                           "object); its algorithms are not evaluated.", instance=f"proposal {name}")
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
                record_control(parser, "juniper.screenos.vpn-proposals", ControlOutcome.NO_FINDING,
                               "The referenced proposal names no weak algorithm or group.",
                               instance=f"proposal {proposal.tokens[2]}")
                continue
            record_control(parser, "juniper.screenos.vpn-proposals", ControlOutcome.FINDING,
                           f"The referenced proposal contains {', '.join(weak)}.",
                           instance=f"proposal {proposal.tokens[2]}")
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
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_administration(parser)
        self.check_snmp(parser)
        self.check_policy_logging(parser)
        self.check_policy_default(parser)
        self.check_vpn_crypto(parser)
        if not self._applicable(parser):
            for control_id in _VERSION_GATED_CONTROLS:
                record_control(parser, control_id, ControlOutcome.UNKNOWN,
                               "The export has no ScreenOS version header; these checks run only on identified "
                               "ScreenOS exports.")
            return
        self.check_lifecycle(parser)
        self.check_credentials_and_banner(parser)
        self.check_logging(parser)
        self.check_ntp(parser)
