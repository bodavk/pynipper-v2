from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.credentials import credential_policy_from_context, evaluate_credential
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.policy_semantics import ProofState, network_covers, service_covers
from src.devices.cisco.asa import CiscoASAParser


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
CISCO_ASA_LOGGING_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/"
    "general/asa-916-general-config/monitor-syslog.html"
)
CISCO_ASA_TLS_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/"
    "S/asa-command-ref-S/so-st-commands.html"
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
        for grant in self._asa(parser).get_management_grants("telnet"):
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
            return
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
            )
        )

    # Kept as a compatibility entry point for external callers.
    def check_weak_enable_password(self, parser: BaseDeviceParser) -> None:
        self.check_enable_credential(parser)

    def check_snmp(self, parser: BaseDeviceParser) -> None:
        communities, hosts, users = self._asa(parser).get_snmp_configuration()
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
                    )
                )

        legacy_hosts = [host for host in hosts if host.version in {"1", "2", "2c", "unknown"}]
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
                )
            )

        release = self._asa(parser)._release_tuple(parser.get_version())
        for user in users:
            if not user.active:
                continue
            evidence = tuple(item for item in user.evidence)
            if not user.group_resolved:
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
                    )
                )

            weak = []
            if user.authentication == "md5":
                weak.append("MD5 authentication")
            elif release is not None and release >= (9, 14) and user.authentication in {"sha", "sha-1"}:
                weak.append("SHA-1 authentication despite SHA-256 support")
            if user.privacy in {"des", "3des"}:
                weak.append(f"{user.privacy.upper()} privacy")
            if weak:
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
                    )
                )

    def check_snmp_communities(self, parser: BaseDeviceParser) -> None:
        self.check_snmp(parser)

    def check_unrestricted_ssh(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        levels = {item["nameif"]: item["security_level"] for item in asa.get_interfaces()}
        for grant in asa.get_management_grants("ssh"):
            name = grant.interface.casefold()
            is_management_only = "mgmt" in name or "management" in name or "oob" in name
            is_untrusted = levels.get(grant.interface, -1) <= 10 and not is_management_only
            if not grant.is_any_source or not is_untrusted:
                continue
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
                )
            )

    def check_logging(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        hosts = asa.get_logging_hosts()
        if not asa.get_logging_enabled() or not hosts:
            reason = "logging is disabled" if not asa.get_logging_enabled() else "no active remote logging host is configured"
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
                )
            )
            return

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
                )
            )

    def check_ssl_version(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        policy = asa.get_ssl_service_policy()
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
            ))

    def check_wide_open_acls(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        levels = {item["nameif"]: item["security_level"] for item in asa.get_interfaces()}
        for binding in asa.get_acl_bindings():
            if binding["direction"] != "in" or levels.get(binding["interface"], -1) > 10:
                continue
            for entry in asa.get_acl_entries(binding["acl_name"]):
                if not entry.is_broad_permit:
                    continue
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
                    )
                )

    def check_acl_hygiene_and_effectiveness(self, parser: BaseDeviceParser) -> None:
        asa = self._asa(parser)
        for binding in asa.get_acl_bindings():
            entries = asa.get_acl_entries(binding["acl_name"])
            previous = []
            for position, entry in enumerate(entries, start=1):
                evidence = (
                    entry.raw_line,
                    f"access-group {entry.acl_name} {binding['direction']} interface {binding['interface']}",
                )
                if entry.inactive:
                    if (
                        entry.action == "permit"
                        and entry.source in {"any", "any4", "any6"}
                        and entry.destination in {"any", "any4", "any6"}
                    ):
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
                        ))
                    continue
                if entry.action == "permit" and entry.protocol.casefold() in {"ip", "any"} and not entry.is_broad_permit:
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
                    ))
                if entry.action == "permit" and entry.is_broad_permit and not entry.logging:
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
                    ))

                if entry.time_range or entry.unsupported_predicates:
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
                    self.add_issue(Finding(
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
                    ))
                    break
                previous.append((position, entry))

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_telnet(parser)
        self.check_enable_credential(parser)
        self.check_snmp(parser)
        self.check_unrestricted_ssh(parser)
        self.check_logging(parser)
        self.check_ssl_version(parser)
        self.check_wide_open_acls(parser)
        self.check_acl_hygiene_and_effectiveness(parser)
