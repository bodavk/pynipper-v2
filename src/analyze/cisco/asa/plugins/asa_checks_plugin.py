import re

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.controls import ControlOutcome, record_control
from src.analyze.common.credentials import credential_policy_from_context, evaluate_credential
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.common.models import DefaultCredentialAssessment
from src.analyze.common.risky_services import CISCO_PORT_NAMES, risky_labels
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.policy_semantics import ProofState, network_covers, service_covers
from src.devices.cisco.asa import CiscoASAParser
from src.analyze.common.attack_paths import (
    FactState, PathFact, PathResult, evidence_locations, mark_evaluated, record_deny_defeated, record_path,
    record_path_not_assessed,
)
from src.devices.common.models import ConfigurationState


CISCO_ASA_MANAGEMENT_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/asdm720/"
    "general/asdm-720-general-config/admin-management.html"
)
CISCO_ASA_PASSWORD_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/"
    "A-H/asa-command-ref-A-H/e-commands.html"
)
CISCO_ASA_SNMP_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa917/configuration/"
    "general/asa-917-general-config/monitor-snmp.html"
)
CISCO_ASA_LOGGING_HOST_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/m_log-lz.html"
)
CISCO_ASA_LOGGING_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/"
    "general/asa-916-general-config/monitor-syslog.html"
)
CISCO_ASA_TLS_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/"
    "S/asa-command-ref-S/so-st-commands.html"
)
CISCO_ASA_PASSWD_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/pa-pn-commands.html"
)
CISCO_ASA_912_RN = "https://www.cisco.com/c/en/us/td/docs/security/asa/asa912/release/notes/asarn912.html"
# SC-044 PIX 6.3 command references (Cisco archive copies).
CISCO_PIX63_GL_REFERENCE = (
    "https://web.archive.org/web/20111208224049/http://www.cisco.com/en/US/docs/security/pix/"
    "pix63/command/reference/gl.html"
)
CISCO_PIX63_S_REFERENCE = (
    "https://web.archive.org/web/20110728200323/http://www.cisco.com/en/US/docs/security/pix/"
    "pix63/command/reference/s.html"
)
CISCO_ASA_ACCESS_RULES_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/"
    "firewall/asa-firewall-cli/access-rules.html"
)


class PluginASAChecks(BasePlugin):
    """Scope-aware checks for ASA management, logging, TLS, SNMP, and ACLs."""

    @staticmethod
    def _asa(parser: BaseDeviceParser) -> CiscoASAParser:
        if not isinstance(parser, CiscoASAParser):
            raise TypeError("PluginASAChecks requires a Cisco ASA parser")
        return parser

    def check_telnet(self, parser: BaseDeviceParser) -> None:
        grants = self._asa(parser).get_management_grants("telnet")
        if not grants:
            record_control(parser, "cisco.asa.management-telnet", ControlOutcome.NO_FINDING,
                           "No Telnet management grant is configured.")
        for grant in grants:
            record_control(parser, "cisco.asa.management-telnet", ControlOutcome.FINDING,
                           f"A Telnet management grant is active on interface '{grant.interface}'.",
                           instance=grant.raw_line)
            self.add_issue(
                Finding(
                    rule_id="cisco.asa.management.telnet",
                    device=parser.device_type,
                    title="Telnet Service Enabled",
                    observation=f"A Telnet management grant is active on interface '{grant.interface}' for source {grant.source}{' ' + grant.mask if grant.mask else ''}.",
                    impact="Telnet sends administrative credentials and sessions without encryption.",
                    severity=Severity.HIGH,
                    exploitability="An attacker on the traffic path can capture credentials and commands.",
                    recommendation="Remove the Telnet grant and use restricted SSH management access.",
                    evidence=(grant.raw_line,),
                    references=(CISCO_ASA_MANAGEMENT_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )

    def check_enable_credential(self, parser: BaseDeviceParser) -> None:
        credential = self._asa(parser).get_enable_credential()
        if credential is None:
            return
        result = evaluate_credential(
            credential, credential_policy_from_context(parser.assessment_context)
        )
        if not result.unsafe_storage:
            record_control(parser, "cisco.asa.device-passwords", ControlOutcome.NO_FINDING,
                           "The enable credential uses a safe storage format.", instance="enable")
            return
        record_control(parser, "cisco.asa.device-passwords", ControlOutcome.FINDING,
                       "The enable credential uses an unsafe storage format.", instance="enable")
        self.add_issue(
            Finding(
                rule_id="cisco.asa.credentials.weak_enable_password",
                device=parser.device_type,
                title="Unsafe enable credential storage",
                observation=(
                    f"The enable credential uses format '{credential.storage_type}', classified as "
                    f"'{result.storage_assessment.value}' under credential policy '{result.policy_version}'; "
                    f"the separate exact-default comparison is '{result.default_assessment.value}' and "
                    f"the blocklist comparison {result.blocklist_summary}. "
                    "The secret value has been redacted."
                ),
                impact="A recoverable or default credential can enable administrative privilege escalation.",
                severity=Severity.HIGH,
                exploitability="Default values are easily guessed; plaintext values are exposed if the configuration is obtained.",
                recommendation="Replace the credential with a unique secret stored using a supported strong hash format.",
                evidence=(credential.raw_line_redacted,),
                references=(CISCO_ASA_PASSWORD_REFERENCE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            )
        )

    def check_default_passwords(self, parser: BaseDeviceParser) -> None:
        """SC-044 ASA-10/11: stored enable/login passwords equal to the documented defaults.

        The unsalted 'encrypted' (PIX-MD5) form of a blank or 'cisco' password is
        recognised by recomputing it; no other value is compared.
        """
        asa = self._asa(parser)
        platform, release = asa.get_release()
        lines = [raw.strip() for raw in asa.parser.ioscfg]
        aaa = {protocol for protocol in ("enable", "ssh", "telnet")
               if any(re.fullmatch(rf"aaa authentication {protocol} console \S+.*", line) for line in lines)}
        enable = asa.get_enable_credential()
        if enable is None:
            record_control(parser, "cisco.asa.device-passwords",
                           ControlOutcome.NOT_APPLICABLE if "enable" in aaa else ControlOutcome.UNKNOWN,
                           "Privileged mode uses 'aaa authentication enable console'." if "enable" in aaa else
                           "No enable password is exported; the release default enable state is not modelled.",
                           instance="enable")
        if enable is not None and enable.default_assessment == DefaultCredentialAssessment.MATCH and "enable" not in aaa:
            record_control(parser, "cisco.asa.device-passwords", ControlOutcome.FINDING,
                           "The stored enable password is the documented factory default.", instance="enable")
            self.add_issue(Finding(
                rule_id="cisco.asa.credentials.known_default_value",
                device=parser.device_type,
                title="Enable password is still the factory default",
                observation=("The stored enable password is the documented default (blank, or 'cisco'); the value is "
                             "recognised from its unsalted hash and is not shown."),
                impact="Anyone who reaches an administrative login can enter privileged mode without knowing a secret.",
                severity=Severity.HIGH,
                exploitability="Default and blank enable passwords are the first values attackers try.",
                recommendation="Set a unique enable password ('enable password <strong> pbkdf2' on 9.7+), or use 'aaa authentication enable console'.",
                evidence=tuple(enable.evidence),
                references=(CISCO_ASA_PASSWORD_REFERENCE, CISCO_ASA_912_RN),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        login = asa.get_login_password()
        telnet = bool(asa.get_management_grants("telnet")) and "telnet" not in aaa
        ssh = (bool(asa.get_management_grants("ssh")) and "ssh" not in aaa
               and (platform == "PIX" or (release is not None and release < (8, 4, 2))))
        ssh_unqualified = (bool(asa.get_management_grants("ssh")) and "ssh" not in aaa
                           and platform != "PIX" and release is None)
        if not (telnet or ssh):
            record_control(parser, "cisco.asa.device-passwords",
                           ControlOutcome.UNKNOWN if ssh_unqualified else ControlOutcome.NOT_APPLICABLE,
                           "SSH without AAA is granted, but the release that decides 'passwd' use is not identified."
                           if ssh_unqualified else "No Telnet or pre-8.4(2) SSH login relies on the 'passwd' password.",
                           instance="login")
        elif login is None:
            record_control(parser, "cisco.asa.device-passwords", ControlOutcome.UNKNOWN,
                           "Logins rely on the 'passwd' password, which is not exported.", instance="login")
        elif not login.default_value:
            record_control(parser, "cisco.asa.device-passwords", ControlOutcome.NO_FINDING,
                           "The 'passwd' login password is not a documented default.", instance="login")
        if login is not None and login.default_value and (telnet or ssh):
            record_control(parser, "cisco.asa.device-passwords", ControlOutcome.FINDING,
                           "The 'passwd' login password is the documented default and protects logins.", instance="login")
            self.add_issue(Finding(
                rule_id="cisco.asa.credentials.known_default_value",
                device=parser.device_type,
                title="Login password is still the factory default",
                observation=(f"The 'passwd' login password is the documented default ('{login.default_value}'), and it "
                             "protects " + " and ".join(name for name, used in (("Telnet", telnet), ("SSH", ssh)) if used)
                             + " logins without AAA."),
                impact="Anyone who can reach the management service can log in with the well-known password.",
                severity=Severity.HIGH,
                exploitability="The default login password is published and tried by automated tools.",
                recommendation="Configure 'aaa authentication ssh console LOCAL' with named users, set a unique 'passwd', and remove Telnet access.",
                evidence=(login.evidence,),
                references=(CISCO_ASA_PASSWD_REFERENCE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    # Kept as a compatibility entry point for external callers.
    def check_weak_enable_password(self, parser: BaseDeviceParser) -> None:
        self.check_enable_credential(parser)

    def check_snmp(self, parser: BaseDeviceParser) -> None:
        communities, hosts, users = self._asa(parser).get_snmp_configuration()
        if any(community.is_default or community.access == "rw" for community in communities):
            record_control(parser, "cisco.asa.snmp-community", ControlOutcome.FINDING,
                           "A default or writable SNMP community is configured.")
        else:
            record_control(parser, "cisco.asa.snmp-community", ControlOutcome.NO_FINDING,
                           "No default or writable SNMP community is configured.")
        for community in communities:
            if community.is_default:
                self.add_issue(
                    Finding(
                        rule_id="cisco.asa.snmp.default_community",
                        device=parser.device_type,
                        title="Default SNMP community configured",
                        observation="An exact default SNMP community is configured. Its value has been redacted.",
                        impact="Default communities are routinely tried by automated discovery and attack tools.",
                        severity=Severity.HIGH,
                        exploitability="The default value is publicly known.",
                        recommendation="Remove SNMPv1/v2c defaults and prefer SNMPv3 with authentication and privacy.",
                        evidence=(community.raw_line_redacted,),
                        references=(CISCO_ASA_SNMP_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            if community.access == "rw":
                self.add_issue(
                    Finding(
                        rule_id="cisco.asa.snmp.write_community",
                        device=parser.device_type,
                        title="Writable SNMP community configured",
                        observation="An SNMP community grants read-write access. Its value has been redacted.",
                        impact="Compromise of the community may permit remote state or configuration changes.",
                        severity=Severity.HIGH,
                        exploitability="An attacker needs SNMP reachability and the community value.",
                        recommendation="Remove write communities and use a least-privileged SNMPv3 user.",
                        evidence=(community.raw_line_redacted,),
                        references=(CISCO_ASA_SNMP_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )

        legacy_hosts = [host for host in hosts if host.version in {"1", "2", "2c", "unknown"}]
        for host in hosts:
            legacy = host in legacy_hosts
            record_control(parser, "cisco.asa.snmp-v3", ControlOutcome.FINDING if legacy else ControlOutcome.NO_FINDING,
                           "SNMP destination uses v1/v2c or states no version." if legacy else
                           "SNMP destination uses SNMPv3.", instance=f"host {host.interface}:{host.address}")
        if not hosts and not any(user.active for user in users):
            record_control(parser, "cisco.asa.snmp-v3", ControlOutcome.NOT_APPLICABLE,
                           "No SNMP destination or active SNMPv3 user is configured.")
        if legacy_hosts:
            self.add_issue(
                Finding(
                    rule_id="cisco.asa.snmp.legacy_version",
                    device=parser.device_type,
                    title="Legacy SNMP management configured",
                    observation="At least one SNMP destination uses v1/v2c or does not state a version.",
                    impact="Community-based SNMP does not provide modern authentication and privacy protections.",
                    severity=Severity.MEDIUM,
                    exploitability="An attacker on the path may observe community-based SNMP traffic.",
                    recommendation="Use SNMPv3 with both authentication and privacy.",
                    evidence=tuple(host.raw_line_redacted for host in legacy_hosts),
                    references=(CISCO_ASA_SNMP_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )

        release = self._asa(parser)._release_tuple(parser.get_version())
        for user in users:
            if not user.active:
                record_control(parser, "cisco.asa.snmp-v3", ControlOutcome.NOT_APPLICABLE,
                               "SNMPv3 user is not referenced by an SNMPv3 host.", instance=f"user {user.name}")
                continue
            evidence = tuple(item for item in user.evidence)
            if not user.group_resolved:
                record_control(parser, "cisco.asa.snmp-v3", ControlOutcome.FINDING,
                               "SNMPv3 user references a group that is not configured.", instance=f"user {user.name}")
                self.add_issue(
                    Finding(
                        rule_id="cisco.asa.snmp.v3_reference",
                        device=parser.device_type,
                        title="SNMPv3 user references an unknown group",
                        observation=f"SNMPv3 user '{user.name}' references group '{user.group}', which is not active in the supplied configuration.",
                        impact="The effective security level for this identity cannot be established.",
                        severity=Severity.MEDIUM,
                        exploitability="A configuration error may leave monitoring unavailable or operating outside the intended policy.",
                        recommendation="Create the intended v3 group or bind the user to an existing v3 priv group.",
                        evidence=evidence,
                        references=(CISCO_ASA_SNMP_GUIDE,),
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )
                continue

            gaps = []
            if user.group_security_level != "priv":
                gaps.append(f"group security level '{user.group_security_level}'")
            if not user.authentication:
                gaps.append("missing authentication")
            if not user.privacy:
                gaps.append("missing privacy")
            if gaps:
                record_control(parser, "cisco.asa.snmp-v3", ControlOutcome.FINDING,
                               "SNMPv3 user lacks authentication or privacy.", instance=f"user {user.name}")
                self.add_issue(
                    Finding(
                        rule_id="cisco.asa.snmp.v3_protection",
                        device=parser.device_type,
                        title="SNMPv3 user lacks authentication or privacy",
                        observation=f"SNMPv3 user '{user.name}' has " + ", ".join(gaps) + ".",
                        impact="SNMP data or credentials may lack confidentiality or strong origin authentication.",
                        severity=Severity.MEDIUM,
                        exploitability="An attacker requires SNMP reachability or traffic-path access.",
                        recommendation="Use a v3 priv group and configure both authentication and AES privacy.",
                        evidence=evidence,
                        references=(CISCO_ASA_SNMP_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )

            weak = []
            if user.authentication == "md5":
                weak.append("MD5 authentication")
            elif release is not None and release >= (9, 14) and user.authentication in {"sha", "sha-1"}:
                weak.append("SHA-1 authentication despite SHA-256 support")
            if user.privacy in {"des", "3des"}:
                weak.append(f"{user.privacy.upper()} privacy")
            if not gaps and not weak:
                unqualified = release is None and user.authentication in {"sha", "sha-1"}
                record_control(parser, "cisco.asa.snmp-v3",
                               ControlOutcome.UNKNOWN if unqualified else ControlOutcome.NO_FINDING,
                               "SHA-1 authentication cannot be judged without an identified release." if unqualified else
                               "SNMPv3 user uses a priv group with authentication and privacy and no legacy algorithm.",
                               instance=f"user {user.name}")
            if weak:
                record_control(parser, "cisco.asa.snmp-v3", ControlOutcome.FINDING,
                               "SNMPv3 user uses a weak algorithm.", instance=f"user {user.name}")
                self.add_issue(
                    Finding(
                        rule_id="cisco.asa.snmp.v3_weak_algorithm",
                        device=parser.device_type,
                        title="SNMPv3 user uses a weak algorithm",
                        observation=f"SNMPv3 user '{user.name}' uses {', '.join(weak)}.",
                        impact="Legacy authentication or privacy algorithms provide inadequate cryptographic strength.",
                        severity=Severity.MEDIUM,
                        exploitability="A traffic observer can target weaknesses in legacy SNMPv3 cryptography.",
                        recommendation="Use SHA-256 or a stronger release-supported authentication algorithm and AES privacy.",
                        evidence=evidence,
                        references=(CISCO_ASA_SNMP_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )

    def check_snmp_communities(self, parser: BaseDeviceParser) -> None:
        self.check_snmp(parser)

    def check_unrestricted_ssh(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        levels = {item["nameif"]: item["security_level"] for item in asa.get_interfaces()}
        grants = asa.get_management_grants("ssh")
        if not grants:
            record_control(parser, "cisco.asa.ssh-source-restriction", ControlOutcome.NOT_APPLICABLE,
                           "No SSH management grant is configured.")
        for grant in grants:
            name = grant.interface.casefold()
            is_management_only = "mgmt" in name or "management" in name or "oob" in name
            is_untrusted = levels.get(grant.interface, -1) <= 10 and not is_management_only
            if not grant.is_any_source or not is_untrusted:
                record_control(parser, "cisco.asa.ssh-source-restriction", ControlOutcome.NO_FINDING,
                               "The SSH grant is source restricted or on a trusted/management interface.",
                               instance=grant.raw_line)
                continue
            record_control(parser, "cisco.asa.ssh-source-restriction", ControlOutcome.FINDING,
                           f"SSH permits every source on untrusted interface '{grant.interface}'.",
                           instance=grant.raw_line)
            self.add_issue(
                Finding(
                    rule_id="cisco.asa.management.unrestricted_ssh",
                    device=parser.device_type,
                    title="Unrestricted SSH access on an untrusted interface",
                    observation=f"SSH permits every {grant.address_family} source on untrusted interface '{grant.interface}'.",
                    impact="The management plane is exposed to password guessing and service exploitation from an untrusted scope.",
                    severity=Severity.MEDIUM,
                    exploitability="Any host reachable through the named interface can attempt SSH access.",
                    recommendation="Restrict the grant to dedicated administration networks or move it to an isolated management interface.",
                    evidence=(grant.raw_line,),
                    references=(CISCO_ASA_MANAGEMENT_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )

    def check_logging(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        hosts = asa.get_logging_hosts()
        if not asa.get_logging_enabled() or not hosts:
            reason = "logging is disabled" if not asa.get_logging_enabled() else "no active remote logging host is configured"
            record_control(parser, "cisco.asa.remote-logging", ControlOutcome.FINDING,
                           f"Remote logging is not operational: {reason}.")
            self.add_issue(
                Finding(
                    rule_id="cisco.asa.logging.missing",
                    device=parser.device_type,
                    title="Remote security logging is not operational",
                    observation=f"Centralized logging is unavailable because {reason}.",
                    impact="Security events may not be retained for monitoring, investigation, or audit.",
                    severity=Severity.LOW,
                    exploitability="An attacker may operate with reduced likelihood of centralized detection.",
                    recommendation="Enable logging and configure at least one reachable remote 'logging host'.",
                    evidence=tuple(hosts) or ("No active logging host",),
                    references=(CISCO_ASA_LOGGING_GUIDE,),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )
            for control in ("cisco.asa.syslog-tls", "cisco.asa.logging-trap-level"):
                record_control(parser, control, ControlOutcome.NOT_APPLICABLE,
                               f"Remote logging is not operational: {reason}.")
            return
        record_control(parser, "cisco.asa.remote-logging", ControlOutcome.NO_FINDING,
                       f"Logging is enabled with {len(hosts)} remote host(s).")

        cleartext = [host for host in hosts if not re.search(r"\bsecure\b", host, re.IGNORECASE)]
        for host in hosts:
            record_control(parser, "cisco.asa.syslog-tls",
                           ControlOutcome.FINDING if host in cleartext else ControlOutcome.NO_FINDING,
                           "Remote syslog destination does not use TLS ('secure')." if host in cleartext else
                           "Remote syslog destination uses TLS ('secure').", instance=host)
        if cleartext:
            self.add_issue(Finding(
                rule_id="cisco.asa.logging.remote_cleartext",
                device=parser.device_type,
                title="Remote syslog is sent without TLS",
                observation="One or more 'logging host' destinations do not use the 'secure' keyword (TLS over TCP); the default is clear-text UDP 514.",
                impact="Log messages, including usernames and addresses, can be read or forged in transit.",
                severity=Severity.LOW,
                exploitability="An attacker on the path to the log server can read events or inject misleading ones.",
                recommendation="Use 'logging host <if> <ip> tcp/<port> secure' with a TLS-capable syslog server, or carry syslog over a protected management network.",
                evidence=tuple(cleartext),
                references=(CISCO_ASA_LOGGING_HOST_REFERENCE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

        level = asa.get_logging_trap_level()
        severity_values = {
            "emergencies": 0,
            "alerts": 1,
            "critical": 2,
            "errors": 3,
            "warnings": 4,
            "notifications": 5,
            "informational": 6,
            "debugging": 7,
        }
        numeric_level = int(level) if level and level.isdigit() else severity_values.get(level or "")
        record_control(parser, "cisco.asa.logging-trap-level",
                       ControlOutcome.FINDING if numeric_level is None or numeric_level < 6 else ControlOutcome.NO_FINDING,
                       f"Effective trap level is {level or 'not configured'}.")
        if numeric_level is None or numeric_level < 6:
            self.add_issue(
                Finding(
                    rule_id="cisco.asa.logging.severity",
                    device=parser.device_type,
                    title="Remote logging severity is insufficient",
                    observation=f"The effective trap level is {level or 'not configured'}; informational events are not assured.",
                    impact="Important security and administrative events may be omitted from centralized logs.",
                    severity=Severity.LOW,
                    exploitability="Missing telemetry reduces the likelihood that suspicious activity is detected.",
                    recommendation="Set 'logging trap informational' unless a documented local policy requires otherwise.",
                    evidence=(f"logging trap {level}",) if level else tuple(hosts),
                    references=(CISCO_ASA_LOGGING_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE if level else FindingBasis.MISSING_EXPLICIT_SETTING,
                )
            )

    def _check_ssl_defaults(self, parser: BaseDeviceParser, policy) -> None:
        """SC-044 ASA-02/ASA-04: 'ssl server-version' and 'ssl cipher' defaults.

        Command reference (so-st): before 9.3(2) the server version default was 'any'
        (SSLv3 accepted); from 9.3(2) 'The default is medium for all protocol versions.'
        Both apply to ASDM (HTTP server) and WebVPN.
        """
        platform, release = self._asa(parser).get_release()
        if platform != "ASA" or release is None:
            return
        services = [f"WebVPN on {', '.join(policy.active_interfaces)}"] if policy.active_interfaces else []
        if policy.http_server_enabled:
            services.append("ASDM (http server enable)")
        if not services:
            return
        evidence = tuple(services)
        if policy.server_minimum is None and release < (9, 3, 2):
            self.add_issue(Finding(
                rule_id="cisco.asa.tls.minimum_version",
                device=parser.device_type,
                title="ASA accepts SSLv3 by default on this release",
                observation=(f"'ssl server-version' is not configured on ASA {release[0]}.{release[1]}({release[2]}); "
                             "before 9.3(2) the default was 'any', which accepts SSLv3 and TLS 1.0 for "
                             + " and ".join(services) + "."),
                impact="SSLv3 and TLS 1.0 have known protocol weaknesses (for example POODLE).",
                severity=Severity.HIGH,
                exploitability="An on-path attacker can force or exploit a legacy protocol version.",
                recommendation="Upgrade to a supported release and set 'ssl server-version tlsv1.2'.",
                evidence=evidence + ("ssl server-version absent: default any before 9.3(2)",),
                references=(CISCO_ASA_TLS_REFERENCE,),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))
        if policy.server_minimum is None and release >= (9, 3, 2):
            # Command reference: '9.3(2) ... The default is now tlsv1 instead of any'
            # ('sh run all ssl' shows 'ssl server-version tlsv1 dtlsv1').
            self.add_issue(Finding(
                rule_id="cisco.asa.tls.minimum_version",
                device=parser.device_type,
                title="ASA accepts TLS 1.0 and 1.1 by default",
                observation=("'ssl server-version' is not configured; the documented default is 'tlsv1', so "
                             + " and ".join(services) + " accept TLS 1.0 and TLS 1.1 clients."),
                impact="TLS 1.0 and 1.1 are deprecated (RFC 8996) and lack modern cipher suites.",
                severity=Severity.MEDIUM,
                exploitability="An on-path attacker may force or exploit a legacy protocol version.",
                recommendation="Set 'ssl server-version tlsv1.2' (or tlsv1.3 where supported).",
                evidence=evidence + ("ssl server-version absent: default tlsv1",),
                references=(CISCO_ASA_TLS_REFERENCE,),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))
        if (release >= (9, 3, 2) and "tlsv1.2" not in policy.cipher_protocols
                and not policy.weak_cipher_commands):
            self.add_issue(Finding(
                rule_id="cisco.asa.tls.weak_cipher",
                device=parser.device_type,
                title="ASA TLS cipher level is left at the default 'medium'",
                observation=("No 'ssl cipher tlsv1.2 ...' line is configured, so the documented default cipher level "
                             "'medium' applies to " + " and ".join(services) + ". This project treats 'medium' as weak, "
                             "as it does for an explicit 'ssl cipher ... medium'."),
                impact="The medium level keeps legacy CBC and SHA-1 based suites (3DES on older releases) that clients can negotiate.",
                severity=Severity.MEDIUM,
                exploitability="An attacker able to influence negotiation may target an offered legacy suite.",
                recommendation="Set 'ssl cipher tlsv1.2 high' (or 'fips' or a reviewed custom list) and the same for TLS 1.3 where supported.",
                evidence=evidence + ("ssl cipher tlsv1.2 absent: default medium",),
                references=(CISCO_ASA_TLS_REFERENCE,),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))

    def _record_tls_control(self, parser: BaseDeviceParser, policy) -> None:
        """SC-049 outcome for the TLS minimum/cipher decisions of _check_ssl_defaults and check_ssl_version."""
        control = "cisco.asa.tls-settings"
        asa = self._asa(parser)
        if not policy.active_interfaces and not policy.http_server_enabled:
            record_control(parser, control, ControlOutcome.NOT_APPLICABLE, "Neither WebVPN nor the HTTP server is enabled.")
            return
        platform, release = asa.get_release()
        defaults_known = platform == "ASA" and release is not None
        webvpn = bool(policy.active_interfaces) and asa.get_version() != "?"
        minimum = policy.server_minimum
        if minimum is None:
            outcome, reason = ((ControlOutcome.FINDING, "'ssl server-version' is omitted; the documented release default accepts legacy versions.")
                               if defaults_known else
                               (ControlOutcome.UNKNOWN, "'ssl server-version' is omitted and the release default is not qualified."))
        elif not policy.server_minimum_valid:
            outcome, reason = ControlOutcome.UNKNOWN, "'ssl server-version' uses an unsupported value."
        elif minimum in {"any", "sslv3", "sslv3-only", "tlsv1", "tlsv1-only", "tlsv1.1"}:
            outcome, reason = ((ControlOutcome.FINDING, "Explicit server minimum permits an obsolete version on active WebVPN.")
                               if webvpn else
                               (ControlOutcome.UNKNOWN, "An explicit legacy minimum is assessed only for active WebVPN on an identified release."))
        else:
            outcome, reason = ControlOutcome.NO_FINDING, f"Explicit server minimum is '{minimum}'."
        record_control(parser, control, outcome, reason, instance="server-version")
        if policy.weak_cipher_commands:
            outcome, reason = ((ControlOutcome.FINDING, "Explicit cipher policy includes weak suites on active WebVPN.")
                               if webvpn else
                               (ControlOutcome.UNKNOWN, "Explicit weak cipher commands are assessed only for active WebVPN on an identified release."))
        elif "tlsv1.2" not in policy.cipher_protocols:
            outcome, reason = ((ControlOutcome.FINDING, "No 'ssl cipher tlsv1.2' line; the documented default level 'medium' applies.")
                               if defaults_known and release >= (9, 3, 2) else
                               (ControlOutcome.UNKNOWN, "No 'ssl cipher tlsv1.2' line and the default cipher level is not qualified for this release."))
        elif policy.unknown_cipher_commands:
            outcome, reason = ControlOutcome.UNKNOWN, "A cipher command uses an unsupported setting."
        else:
            outcome, reason = ControlOutcome.NO_FINDING, "Explicit TLS 1.2 cipher policy uses a high, FIPS or reviewed custom level."
        record_control(parser, control, outcome, reason, instance="cipher")

    def check_pix_defaults(self, parser: BaseDeviceParser) -> None:
        """SC-044 PIX-01/02/03: PIX 6.x defaults from the PIX 6.3 command reference."""
        asa = self._asa(parser)
        platform, release = asa.get_release()
        if platform != "PIX" or release is None or release[0] >= 7:
            return
        version = f"PIX Version {release[0]}.{release[1]}({release[2]})"
        lines = [raw.strip() for raw in asa.parser.ioscfg]
        if any(re.match(r"isakmp enable\s+\S+", line) for line in lines):
            policies: dict[str, dict[str, str]] = {}
            for line in lines:
                match = re.fullmatch(r"isakmp policy (\d+) (\S+)(?:\s+(\S+))?.*", line)
                if match:
                    policies.setdefault(match.group(1), {})[match.group(2)] = match.group(3) or ""
            weak = []
            for number, settings in sorted(policies.items()):
                if settings.get("encryption", "des") in {"des", "3des"}:
                    weak.append(f"isakmp policy {number} encryption {settings.get('encryption', 'des (default)')}")
                if settings.get("group", "1") in {"1", "2", "5"}:
                    weak.append(f"isakmp policy {number} group {settings.get('group', '1 (default)')}")
            if not policies:
                weak.append("no isakmp policy: default suite DES, SHA-1, DH group 1")
            record_control(parser, "cisco.asa.ike-policy", ControlOutcome.FINDING if weak else ControlOutcome.NO_FINDING,
                           "PIX ISAKMP policies resolve to weak values." if weak else
                           "PIX ISAKMP policies set strong explicit values.", instance="pix-isakmp")
            if weak:
                self.add_issue(Finding(
                    rule_id="cisco.asa.vpn.ike_weak_policy",
                    device=parser.device_type,
                    title="PIX IKE policy uses DES or a weak Diffie-Hellman group",
                    observation=f"{version} has ISAKMP enabled and its policies resolve to weak values: " + "; ".join(weak) + ".",
                    impact="DES and DH groups 1/2 can be broken or brute-forced with modest resources, exposing tunnel keys.",
                    severity=Severity.HIGH,
                    exploitability="An attacker who records IKE and IPsec traffic can attack the weak key exchange offline.",
                    recommendation="Replace the PIX with a supported platform; meanwhile set 'isakmp policy <n> encryption aes-256' and 'group 5' or better.",
                    evidence=(version, *weak),
                    references=(CISCO_PIX63_GL_REFERENCE,),
                    basis=(FindingBasis.DOCUMENTED_DEFAULT if any("default" in item for item in weak)
                           else FindingBasis.EXPLICIT_VALUE),
                ))
        ssh = [line for line in lines if re.fullmatch(r"ssh \d+(?:\.\d+){3} \d+(?:\.\d+){3} \S+", line)]
        if ssh:
            record_control(parser, "cisco.asa.ssh-settings", ControlOutcome.FINDING,
                           "PIX 6.x implements SSH version 1 only.", instance="version")
            self.add_issue(Finding(
                rule_id="cisco.asa.ssh.protocol_version",
                device=parser.device_type,
                title="PIX 6.x SSH supports only SSH version 1",
                observation=f"{version} permits SSH management; PIX 6.x implements SSH version 1 only.",
                impact="SSH version 1 has obsolete protocol and cryptographic design weaknesses.",
                severity=Severity.HIGH,
                exploitability="An on-path attacker can exploit SSHv1 weaknesses to recover or hijack sessions.",
                recommendation="Replace the PIX with a supported platform that offers SSH version 2.",
                evidence=(version, *ssh[:5]),
                references=(CISCO_PIX63_S_REFERENCE,),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))
        sysopt = [line for line in lines if line == "sysopt connection permit-ipsec"]
        if sysopt:
            record_control(parser, "cisco.asa.vpn-acl-bypass", ControlOutcome.FINDING,
                           "'sysopt connection permit-ipsec' exempts tunnel traffic from interface ACLs.")
            self.add_issue(Finding(
                rule_id="cisco.asa.vpn.sysopt_permit_vpn",
                device=parser.device_type,
                title="Decrypted IPsec traffic bypasses interface access lists",
                observation=f"{version} has 'sysopt connection permit-ipsec', so traffic from IPsec tunnels is not checked by interface access lists.",
                impact="A compromised or misconfigured VPN peer can reach any internal address the tunnel covers.",
                severity=Severity.MEDIUM,
                exploitability="An attacker who controls a VPN peer or client gains unfiltered access behind the firewall.",
                recommendation="Remove 'sysopt connection permit-ipsec' and permit tunnel traffic explicitly in the interface access lists.",
                evidence=(version, *sysopt),
                references=(CISCO_PIX63_S_REFERENCE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_ssl_version(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        policy = asa.get_ssl_service_policy()
        self._check_ssl_defaults(parser, policy)
        self._record_tls_control(parser, policy)
        if not policy.active_interfaces or asa.get_version() == "?":
            return
        minimum = policy.server_minimum
        active = ", ".join(policy.active_interfaces)
        if policy.server_minimum_valid and minimum in {
            "any", "sslv3", "sslv3-only", "tlsv1", "tlsv1-only", "tlsv1.1",
        }:
            self.add_issue(
                Finding(
                    rule_id="cisco.asa.tls.minimum_version",
                    device=parser.device_type,
                    title="Active ASA WebVPN permits an obsolete TLS version",
                    observation=f"WebVPN is enabled on {active}; its explicit server-side minimum protocol is '{minimum}'.",
                    impact="Legacy SSL/TLS protocols contain known cryptographic weaknesses.",
                    severity=Severity.MEDIUM,
                    exploitability="An on-path attacker may target weaknesses in a permitted legacy protocol version.",
                    recommendation="Set 'ssl server-version tlsv1.2' or a newer version supported by the platform.",
                    evidence=tuple(item for item in policy.evidence if item.text.startswith(("ssl server-version", "enable "))),
                    references=(CISCO_ASA_TLS_REFERENCE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )
        if policy.weak_cipher_commands:
            self.add_issue(Finding(
                rule_id="cisco.asa.tls.weak_cipher",
                device=parser.device_type,
                title="Active ASA WebVPN offers weak TLS cipher suites",
                observation=f"WebVPN is enabled on {active} and its explicit inbound cipher policy includes DES, 3DES, RC4, NULL, MD5, or a cipher level that includes such suites.",
                impact="A client can negotiate cryptography that does not meet current confidentiality or integrity expectations.",
                severity=Severity.HIGH,
                exploitability="An attacker able to influence or intercept negotiation may target an offered legacy suite.",
                recommendation="Remove weak suites and use a supported FIPS/high level or an explicitly modern custom per-protocol cipher policy after compatibility testing.",
                evidence=policy.weak_cipher_commands + tuple(
                    f"webvpn enable {interface}" for interface in policy.active_interfaces
                ),
                references=(CISCO_ASA_TLS_REFERENCE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_wide_open_acls(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        levels = {item["nameif"]: item["security_level"] for item in asa.get_interfaces()}
        for binding in asa.get_acl_bindings():
            if binding["direction"] != "in" or levels.get(binding["interface"], -1) > 10:
                continue
            for position, entry in enumerate(asa.get_acl_entries(binding["acl_name"]), start=1):
                if not entry.is_broad_permit:
                    continue
                record_control(parser, "cisco.asa.acl-permit-scope", ControlOutcome.FINDING,
                               "Broad any-to-any permit is bound inbound on a low-trust interface.",
                               instance=f"system/acl:{entry.acl_name}/entry:{position}/{binding['direction']}:{binding['interface']}")
                self.add_issue(
                    Finding(
                        rule_id="cisco.asa.acl.broad_inbound_permit",
                        device=parser.device_type,
                        title="Broad inbound permit on a low-trust interface",
                        observation=f"ACL '{entry.acl_name}' permits {entry.protocol} from any source to any destination on '{binding['interface']}'.",
                        impact="The rule can defeat the firewall boundary for the permitted protocol.",
                        severity=Severity.CRITICAL,
                        exploitability="Reachable attackers can target any destination allowed by routing and the broad ACE.",
                        recommendation="Replace the ACE with explicit source, destination, and service constraints.",
                        evidence=(entry.raw_line, f"access-group {entry.acl_name} in interface {binding['interface']}"),
                        references=(CISCO_ASA_ACCESS_RULES_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )

    @staticmethod
    def _risky_entry_services(entry) -> list[str]:
        """SC-043: catalogued destination ports on an active permit from any source."""
        if entry.inactive or entry.action != "permit" or entry.source not in {"any", "any4", "any6"}:
            return []
        protocol = entry.protocol.casefold()
        if protocol not in {"tcp", "udp", "tcp-udp"}:
            return []
        qualifiers = list(entry.service_qualifiers)

        def port(value: str) -> int | None:
            return int(value) if value.isdigit() else CISCO_PORT_NAMES.get(value)

        labels: set[str] = set()
        if len(qualifiers) >= 2 and qualifiers[0] == "eq" and port(qualifiers[1]) is not None:
            value = port(qualifiers[1])
            labels = risky_labels(protocol, value, value)
        elif len(qualifiers) >= 3 and qualifiers[0] == "range" and port(qualifiers[1]) is not None and port(qualifiers[2]) is not None:
            labels = risky_labels(protocol, port(qualifiers[1]), port(qualifiers[2]))
        return sorted(labels)

    @staticmethod
    def _acl_scope_unassessed(asa: CiscoASAParser, entry) -> str | None:
        """Why the literal-selector permit-scope rules cannot judge this entry, or None."""
        if entry.action != "permit":
            return None
        any_values = {"any", "any4", "any6"}

        def may_be_any(value: str) -> bool:
            if value in any_values:
                return False
            semantics = asa.resolve_acl_network(value)
            return not semantics.complete or semantics.any
        if not entry.inactive and entry.protocol.casefold().startswith(("object ", "object-group ")):
            service = asa.resolve_acl_service(entry)
            if not service.complete or service.any:
                return "The permit's protocol object is unresolved or may permit every IP protocol; the rules match literal protocols."
        if may_be_any(entry.source):
            return "The permit's source is an object that is unresolved or resolves to any; the rules match literal selectors."
        if entry.source not in any_values or entry.inactive:
            return None
        if may_be_any(entry.destination):
            return "The permit's destination is an object that is unresolved or resolves to any; the rules match literal selectors."
        protocol = entry.protocol.casefold()
        if protocol in {"tcp", "udp", "tcp-udp"}:
            qualifiers = list(entry.service_qualifiers)

            def port(value: str) -> int | None:
                return int(value) if value.isdigit() else CISCO_PORT_NAMES.get(value)
            literal = ((len(qualifiers) >= 2 and qualifiers[0] == "eq" and port(qualifiers[1]) is not None)
                       or (len(qualifiers) >= 3 and qualifiers[0] == "range"
                           and port(qualifiers[1]) is not None and port(qualifiers[2]) is not None))
            if not literal:
                return "Any-source permit has a destination port scope other than a literal eq/range; the risky-service catalogue was not applied."
        elif protocol.startswith(("object ", "object-group ")):
            return "Any-source permit uses a protocol/service object; the risky-service catalogue was not applied."
        return None

    def check_acl_hygiene_and_effectiveness(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        self._deny_shadows = []
        scope_recorded = False
        for binding in asa.get_acl_bindings():
            entries = asa.get_acl_entries(binding["acl_name"])
            if not entries:
                scope_recorded = True
                for control in ("cisco.asa.acl-permit-scope", "cisco.asa.policy-order"):
                    record_control(parser, control, ControlOutcome.UNKNOWN,
                                   "Bound ACL has no parsed extended entries (absent, non-extended or unsupported syntax).",
                                   instance=f"system/acl:{binding['acl_name']}/{binding['direction']}:{binding['interface']}")
            order_unknown = any("duplicate-ace-order" in e.unsupported_predicates for e in entries)
            if order_unknown:
                record_path_not_assessed(parser, "protective-deny-defeated", "Repeated identical ACE commands make bound ACL order unqualified.")
            previous = []
            for position, entry in enumerate(entries, start=1):
                instance = f"system/acl:{entry.acl_name}/entry:{position}/{binding['direction']}:{binding['interface']}"
                def complete(item):
                    return (not item.time_range and not item.unsupported_predicates and all((
                        asa.resolve_acl_network(item.source).complete, asa.resolve_acl_network(item.destination).complete,
                        asa.resolve_acl_service(item).complete)))
                known = not order_unknown and complete(entry) and len(previous) <= 64 and all(complete(p) for _, p in previous)
                record_control(parser, "cisco.asa.policy-order",
                               ControlOutcome.NOT_APPLICABLE if entry.inactive else ControlOutcome.NO_FINDING if known else ControlOutcome.UNKNOWN,
                               "Inactive ACE." if entry.inactive else "Bounded static bound-ACL comparison qualified." if known else
                               "Objects, source-port/time predicates or earlier-rule proof budget are unqualified.", instance=instance)
                evidence = (
                    entry.raw_line,
                    f"access-group {entry.acl_name} {binding['direction']} interface {binding['interface']}",
                )
                scope_recorded = True
                unassessed = self._acl_scope_unassessed(asa, entry)
                record_control(parser, "cisco.asa.acl-permit-scope",
                               ControlOutcome.UNKNOWN if unassessed else ControlOutcome.NO_FINDING,
                               unassessed or "Entry is not a broad, protocol-wide, unlogged or risky-service permit.",
                               instance=instance)
                if entry.inactive:
                    if (
                        entry.action == "permit"
                        and entry.source in {"any", "any4", "any6"}
                        and entry.destination in {"any", "any4", "any6"}
                    ):
                        record_control(parser, "cisco.asa.acl-permit-scope", ControlOutcome.FINDING,
                                       "Inactive broad permit remains configured.", instance=instance)
                        self.add_issue(Finding(
                            rule_id="cisco.asa.acl.inactive_permissive_rule",
                            device=parser.device_type,
                            title="Inactive permissive ACL entry remains configured",
                            observation=f"Inactive entry {position} in ACL '{entry.acl_name}' retains a broad permit on '{binding['interface']}'.",
                            impact="Stale permissive entries obscure policy intent and can create exposure if reactivated.",
                            exploitability="The entry is inactive in the supplied configuration; exploitation requires reactivation.",
                            recommendation="Remove the obsolete entry or narrow and document it before reactivation.",
                            severity=Severity.LOW,
                            evidence=evidence,
                            references=(CISCO_ASA_ACCESS_RULES_GUIDE,),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        ))
                    continue
                if entry.action == "permit" and entry.protocol.casefold() in {"ip", "any"} and not entry.is_broad_permit:
                    record_control(parser, "cisco.asa.acl-permit-scope", ControlOutcome.FINDING,
                                   "Permit is unrestricted by IP protocol.", instance=instance)
                    self.add_issue(Finding(
                        rule_id="cisco.asa.acl.broad_service",
                        device=parser.device_type,
                        title="ACL permit is unrestricted by IP protocol",
                        observation=f"Entry {position} in ACL '{entry.acl_name}' permits every IP protocol within its address scope on '{binding['interface']}'.",
                        impact="Unnecessary protocols can cross the firewall within the matched network scope.",
                        exploitability="A reachable source can use any IP protocol supported by the destination and surrounding path.",
                        recommendation="Constrain the ACE to the required protocol and destination service.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(CISCO_ASA_ACCESS_RULES_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    ))
                risky = self._risky_entry_services(entry)
                # ASA ACLs stop at the first match. A preceding static deny that
                # covers this ACE makes it unreachable only when no earlier
                # permit could have accepted a subset of the same traffic.
                if risky and all(earlier.action == "deny" for _, earlier in previous):
                    current_source = asa.resolve_acl_network(entry.source)
                    current_destination = asa.resolve_acl_network(entry.destination)
                    current_service = asa.resolve_acl_service(entry)
                    if any(
                        not earlier.time_range
                        and not earlier.unsupported_predicates
                        and all(state == ProofState.PROVEN for state in (
                            network_covers(asa.resolve_acl_network(earlier.source), current_source),
                            network_covers(asa.resolve_acl_network(earlier.destination), current_destination),
                            service_covers(asa.resolve_acl_service(earlier), current_service),
                        ))
                        for _, earlier in previous
                    ):
                        risky = []
                if risky:
                    record_control(parser, "cisco.asa.acl-permit-scope", ControlOutcome.FINDING,
                                   "Any-source permit includes a catalogued risky service port.", instance=instance)
                    self.add_issue(Finding(
                        rule_id="cisco.asa.acl.risky_service_exposure",
                        device=parser.device_type,
                        title="ACL may expose a risky service to broad sources",
                        observation=f"Entry {position} in ACL '{entry.acl_name}' on '{binding['interface']}' permits the {', '.join(risky)} port from any source; upstream controls and application transport are not established.",
                        impact="Sensitive services on these ports may be reachable by broad source networks; the port alone does not prove cleartext traffic.",
                        exploitability="Sources that can reach the bound interface and are not excluded by earlier ACL entries may probe the service.",
                        recommendation="Verify the application and transport security, and restrict the permitted source to the hosts that need access.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(CISCO_ASA_ACCESS_RULES_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    ))
                if entry.action == "permit" and entry.is_broad_permit and not entry.logging:
                    record_control(parser, "cisco.asa.acl-permit-scope", ControlOutcome.FINDING,
                                   "Broad permit has no explicit log option.", instance=instance)
                    self.add_issue(Finding(
                        rule_id="cisco.asa.acl.broad_permit_unlogged",
                        device=parser.device_type,
                        title="Broad ACL permit lacks explicit logging",
                        observation=f"Broad permit entry {position} in ACL '{entry.acl_name}' has no explicit log option.",
                        impact="Traffic crossing a highly permissive boundary may lack rule-level audit records.",
                        exploitability="Malicious traffic can blend into an unrestricted flow with reduced policy-hit visibility.",
                        recommendation="Narrow the rule and enable an appropriate reviewed logging level and interval.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(CISCO_ASA_ACCESS_RULES_GUIDE,),
                        basis=FindingBasis.MISSING_EXPLICIT_SETTING,
                    ))

                if order_unknown or entry.time_range or entry.unsupported_predicates:
                    previous.append((position, entry))
                    continue
                current_source = asa.resolve_acl_network(entry.source)
                current_destination = asa.resolve_acl_network(entry.destination)
                current_service = asa.resolve_acl_service(entry)
                for earlier_position, earlier in previous:
                    if earlier.time_range or earlier.unsupported_predicates:
                        continue
                    if not all(
                        state == ProofState.PROVEN
                        for state in (
                            network_covers(asa.resolve_acl_network(earlier.source), current_source),
                            network_covers(asa.resolve_acl_network(earlier.destination), current_destination),
                            service_covers(asa.resolve_acl_service(earlier), current_service),
                        )
                    ):
                        continue
                    same_action = (
                        earlier.action == entry.action
                        and earlier.behavior_signature == entry.behavior_signature
                    )
                    finding = Finding(
                        rule_id=(
                            "cisco.asa.acl.redundant_rule"
                            if same_action else "cisco.asa.acl.shadowed_rule"
                        ),
                        device=parser.device_type,
                        title="ACL entry is redundant" if same_action else "ACL entry is shadowed",
                        observation=f"Entry {position} in ACL '{entry.acl_name}' is fully covered by earlier entry {earlier_position} with {'the same' if same_action else 'a different'} action on '{binding['interface']}'.",
                        impact="The later entry cannot alter first-match enforcement for the statically proven traffic scope and obscures policy intent.",
                        exploitability="A conflicting shadowed entry can give reviewers a false impression of enforced access control.",
                        recommendation="Remove or reorder the entry after validating the applied ACL and operational intent.",
                        severity=Severity.LOW if same_action else Severity.HIGH,
                        evidence=evidence + (earlier.raw_line,),
                        references=(CISCO_ASA_ACCESS_RULES_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                    self.add_issue(finding)
                    record_control(parser, "cisco.asa.policy-order", ControlOutcome.FINDING,
                                   "Proven static shadow/redundancy, not observed nonuse or effective permission.", instance=instance)
                    if earlier.action == "permit" and entry.action == "deny":
                        self._deny_shadows.append((binding, position, entry, earlier_position, earlier, finding))
                    break
                previous.append((position, entry))
        if not scope_recorded:
            for control in ("cisco.asa.acl-permit-scope", "cisco.asa.policy-order"):
                record_control(parser, control, ControlOutcome.NOT_APPLICABLE,
                               "No access list is bound to an interface.")

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_telnet(parser)
        self.check_enable_credential(parser)
        self.check_default_passwords(parser)
        self.check_snmp(parser)
        self.check_unrestricted_ssh(parser)
        self.check_logging(parser)
        self.check_ssl_version(parser)
        self.check_pix_defaults(parser)
        self.check_wide_open_acls(parser)
        self.check_acl_hygiene_and_effectiveness(parser)
        self.produce_attack_paths(parser)

    def produce_cleartext_admin_paths(self, parser: BaseDeviceParser) -> None:
        """SC-063: an any-source Telnet grant on an enabled interface with password login.

        The ASA management access guide states that Telnet cannot be used to the
        lowest security interface except inside a VPN tunnel, so such grants form
        no clear-text path; a tie for the lowest level is not assessed.
        """
        pattern = "cleartext-admin-unrestricted"
        mark_evaluated(parser, pattern)
        asa = self._asa(parser)
        grants = [grant for grant in asa.get_management_grants("telnet") if grant.is_any_source]
        if not grants:
            return
        levels = {item["nameif"].casefold(): item["security_level"] for item in asa.get_interfaces()}
        states = {interface.zone.casefold(): interface.state
                  for interface in parser.get_normalized_config().interfaces.items}
        known_levels = [level for level in levels.values() if level >= 0]
        lowest = min(known_levels) if known_levels else None
        aaa = asa.get_telnet_login_authentication()
        login = asa.get_login_password()
        findings = [item for item in self.get_issues() if item.rule_id == "cisco.asa.management.telnet"]
        for grant in grants:
            key = f"system/telnet:{grant.interface}/{grant.address_family}"
            name = grant.interface.casefold()
            if name not in levels or name not in states:
                record_path_not_assessed(parser, pattern, f"{key}: no interface with nameif '{grant.interface}' was found.")
                continue
            if states[name] == ConfigurationState.DISABLED:
                continue
            level = levels[name]
            if level < 0 or lowest is None or any(value < 0 for value in levels.values()):
                record_path_not_assessed(parser, pattern, f"{key}: interface security levels are incomplete; "
                                         "the lowest-security Telnet restriction could not be applied.")
                continue
            if level == lowest:
                if sum(1 for value in levels.values() if value == lowest) > 1:
                    record_path_not_assessed(parser, pattern, f"{key}: several interfaces share the lowest security "
                                             "level; whether Telnet is refused on this one was not established.")
                continue
            if aaa is not None:
                login_text = (f"Telnet logins authenticate through 'aaa authentication telnet console {aaa[0]}' "
                              "with a username and password.")
                login_evidence: tuple = (aaa[1],)
            elif login is not None:
                login_text = "Without Telnet AAA, logins use the 'passwd' login password."
                login_evidence = (login.evidence,)
            else:
                record_path_not_assessed(parser, pattern, f"{key}: neither Telnet AAA nor a 'passwd' login password "
                                         "is exported; the login method was not resolved.")
                continue
            link = tuple((item.rule_id, item.title) for item in findings
                         if grant.raw_line in tuple(getattr(evidence, "text", evidence) for evidence in item.evidence))[:1]
            family = grant.address_family
            source = "every IPv4 source (0.0.0.0 0.0.0.0)" if family == "ipv4" else f"every IPv6 source ({grant.source})"
            steps = (
                PathFact("telnet-listener", key, "system", family, FactState.KNOWN,
                         f"Telnet management is granted on enabled interface '{grant.interface}' "
                         f"(security level {level}, not the lowest).", evidence_locations((grant.raw_line,)), link),
                PathFact("unrestricted-source", key, "system", family, FactState.KNOWN,
                         f"The grant admits {source}.", evidence_locations((grant.raw_line,))),
                PathFact("password-login", key, "system", family, FactState.KNOWN,
                         login_text + " The password crosses the network in clear text over Telnet.",
                         evidence_locations(login_evidence)),
            )
            record_path(parser, PathResult(pattern, key, "system", family, steps))

    def produce_attack_paths(self, parser: BaseDeviceParser) -> None:
        """SC-063: a bound, active ACL deny entry fully covered by an earlier permit in the same ACL."""
        self.produce_cleartext_admin_paths(parser)
        pattern = "protective-deny-defeated"
        mark_evaluated(parser, pattern)
        states = {
            interface.zone.casefold(): interface.state
            for interface in parser.get_normalized_config().interfaces.items
        }
        grouped: dict = {}
        for binding, position, entry, earlier_position, earlier, finding in getattr(self, "_deny_shadows", ()):
            state = states.get(binding["interface"].casefold())
            key = f"system/acl:{entry.acl_name}/entry:{position}"
            if state is None:
                record_path_not_assessed(
                    parser, pattern, f"{key}: access-group names interface '{binding['interface']}', which has no matching nameif.",
                )
                continue
            if state == ConfigurationState.DISABLED:
                continue
            grouped.setdefault(key, []).append((binding, position, entry, earlier_position, earlier, finding))
        for key, items in sorted(grouped.items()):
            binding, position, entry, earlier_position, earlier, finding = items[0]
            bindings = sorted({f"{item[0]['direction']} on {item[0]['interface']}" for item in items})
            permission = parser.get_effective_acl_permission(
                earlier, tuple(parser.get_acl_entries(entry.acl_name)[:earlier_position-1]), entry)
            record_deny_defeated(
                parser, scope="system", family="any", instance_key=key,
                allow_entity=f"system/acl:{entry.acl_name}/entry:{earlier_position}",
                permission=permission,
                allow_text=(f"Earlier active permit entry {earlier_position} in access list '{entry.acl_name}' statically "
                            "covers the deny's sources, destinations and services."),
                allow_evidence=(earlier.raw_line,) + tuple(p.raw_line for p in parser.get_acl_entries(entry.acl_name)[:earlier_position-1]),
                deny_text=(f"Deny entry {position} in access list '{entry.acl_name}', applied {', '.join(bindings)}, "
                           "is never reached under first-match evaluation."),
                deny_evidence=(entry.raw_line,) + tuple(
                    f"access-group {entry.acl_name} {item[0]['direction']} interface {item[0]['interface']}" for item in items
                ),
                finding=finding,
            )
