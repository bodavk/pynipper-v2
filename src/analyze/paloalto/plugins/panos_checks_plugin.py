"""Attachment- and scope-aware PAN-OS management and policy checks."""

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.paloalto.panos import PaloAltoPANOSParser, PanosSecurityRule


PANOS_MANAGEMENT_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/networking/configure-interfaces/"
    "use-interface-management-profiles-to-restrict-access"
)
PANOS_POLICY_GUIDE = (
    "https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/"
    "security-policy-best-practices/deploy-security-policy-best-practices/"
    "security-policy-rule-best-practices"
)
PANOS_LOG_FORWARDING_GUIDE = (
    "https://docs.paloaltonetworks.com/network-security/security-policy/"
    "administration/objects/log-forwarding"
)
PANOS_PASSWORD_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/getting-started/set-up-your-ngfws/"
    "perform-the-initial-configuration-for-a-ngfw"
)
PANOS_HIERARCHY_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/"
    "cli-command-hierarchy/pan-os-11-2-configure-cli-command-hierarchy"
)
PANOS_ADMIN_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/"
    "manage-firewall-administrators/administrative-authentication"
)
PANOS_CLI_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/"
    "cli-command-hierarchy/pan-os-11-1-configure-cli-command-hierarchy"
)
PANOS_TLS_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/administration/certificate-management/"
    "configure-ssl-tls-service-profile"
)
PANOS_UPDATE_GUIDE = (
    "https://docs.paloaltonetworks.com/advanced-threat-prevention/administration/"
    "configure-threat-prevention/set-up-antivirus-anti-spyware-and-vulnerability-protection"
)
PANOS_SYSTEM_LOG_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/administration/monitoring/"
    "configure-log-forwarding"
)


class PluginPANOSChecks(BasePlugin):
    """Evaluate only attached local-firewall state that the XML proves."""

    _UNTRUSTED_ZONES = {"untrust", "external", "internet", "public", "wan"}

    @staticmethod
    def _panos(parser: BaseDeviceParser) -> PaloAltoPANOSParser:
        if not isinstance(parser, PaloAltoPANOSParser):
            raise TypeError("PluginPANOSChecks requires a PAN-OS parser")
        return parser

    @staticmethod
    def _evidence(items) -> tuple[str, ...]:
        return tuple(item.text for item in items)

    @staticmethod
    def _all_any(values: tuple[str, ...]) -> bool:
        return bool(values) and all(value.casefold() == "any" for value in values)

    def check_management(self, parser: BaseDeviceParser) -> None:
        services = self._panos(parser).get_normalized_config().management_services.items
        for service in services:
            protocol = service.protocol.casefold()
            if protocol in {"http", "telnet"}:
                self.add_issue(
                    Finding(
                        rule_id=f"paloalto.panos.management.{protocol}",
                        device=parser.device_type,
                        title="Clear-text management service is exposed",
                        observation=f"Attached management profile enables {protocol.upper()} on interface '{service.interface}' in scope '{service.scope}' and zone '{service.zone or 'unspecified'}'.",
                        impact="Administrative credentials and sessions can be disclosed or altered in transit.",
                        exploitability="An attacker with management-path reachability can intercept or attempt access to the clear-text service.",
                        recommendation=f"Disable {protocol.upper()} in the attached Interface Management profile and use SSH or HTTPS.",
                        severity=Severity.HIGH,
                        evidence=self._evidence(service.evidence),
                        references=(PANOS_MANAGEMENT_GUIDE,),
                    )
                )

        unrestricted: dict[tuple, list[str]] = {}
        for service in services:
            protocol = service.protocol.casefold()
            if (
                protocol in {"ssh", "https"}
                and not service.permitted_sources
                and (
                    (service.zone or "").casefold() in self._UNTRUSTED_ZONES
                    or service.interface == "MGT"
                )
            ):
                key = (
                    service.interface,
                    service.scope,
                    service.zone,
                    self._evidence(service.evidence),
                )
                unrestricted.setdefault(key, []).append(protocol.upper())
        for (interface, scope, zone, evidence), protocols in unrestricted.items():
            self.add_issue(
                Finding(
                    rule_id="paloalto.panos.management.unrestricted_secure_service",
                    device=parser.device_type,
                    title="Management service lacks permitted-IP restrictions",
                    observation=f"{'/'.join(dict.fromkeys(protocols))} is enabled on '{interface}' in scope '{scope}' and zone '{zone or 'management'}' without permitted IP addresses.",
                    impact="The management plane is reachable from every source allowed to reach the interface.",
                    exploitability="Any reachable host can probe the service or attempt authentication.",
                    recommendation="Add explicit IPv4/IPv6 Permitted IP Addresses or remove management access from the untrusted interface.",
                    severity=Severity.HIGH,
                    evidence=evidence,
                    references=(PANOS_MANAGEMENT_GUIDE,),
                )
            )

    def check_administration(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        users = panos.get_normalized_config().users.items
        if users and all(user.authentication == "local" for user in users):
            self.add_issue(
                Finding(
                    rule_id="paloalto.panos.admin.centralized_authentication",
                    device=parser.device_type,
                    title="Administrators use local-only authentication",
                    observation="Every parsed administrator account uses the local authentication database.",
                    impact="Local-only accounts reduce centralized revocation, policy enforcement, and authentication auditability.",
                    exploitability="Compromise of a local credential can provide firewall access independently of central identity controls.",
                    recommendation="Use RADIUS, SAML, TACACS+, or another approved external authentication profile, with a controlled emergency local account.",
                    severity=Severity.MEDIUM,
                    evidence=tuple(
                        evidence.text for user in users for evidence in user.evidence
                    ),
                    references=(PANOS_ADMIN_GUIDE,),
                )
            )

    def check_platform_services(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        if panos.panorama_inheritance_unknown:
            return
        if not panos.get_ntp_servers():
            self.add_issue(
                Finding(
                    rule_id="paloalto.panos.ntp.servers",
                    device=parser.device_type,
                    title="No NTP servers are configured",
                    observation="Neither a primary nor secondary NTP server address was found in local device configuration.",
                    impact="Incorrect timestamps hinder log correlation, authentication, and certificate validation.",
                    exploitability="Inconsistent time reduces the reliability of monitoring and forensic timelines.",
                    recommendation="Configure redundant trusted primary and secondary NTP servers.",
                    severity=Severity.LOW,
                    evidence=("deviceconfig system ntp-servers absent",),
                    references=(PANOS_CLI_GUIDE,),
                )
            )
        if not panos.get_dns_servers():
            self.add_issue(
                Finding(
                    rule_id="paloalto.panos.dns.servers",
                    device=parser.device_type,
                    title="No DNS servers are configured",
                    observation="Neither a primary nor secondary management-plane DNS server was found.",
                    impact="Name resolution failures can disrupt update, logging, authentication, and security-service connectivity.",
                    exploitability="Loss of dependable resolution can weaken availability and monitoring integrations.",
                    recommendation="Configure approved primary and secondary DNS resolvers for the management plane.",
                    severity=Severity.LOW,
                    evidence=("deviceconfig system dns-setting servers absent",),
                    references=(PANOS_CLI_GUIDE,),
                )
            )
        snmp_enabled = any(
            service.protocol.casefold() == "snmp"
            for service in panos.get_normalized_config().management_services.items
        )
        if snmp_enabled and not panos.has_secure_snmpv3_user():
            self.add_issue(
                Finding(
                    rule_id="paloalto.panos.snmp.secure_user_missing",
                    device=parser.device_type,
                    title="SNMP management lacks a secure SNMPv3 user",
                    observation="SNMP is enabled by an attached management profile but no SHA/AES SNMPv3 user was parsed.",
                    impact="SNMP management may lack strong authentication or confidentiality.",
                    exploitability="A reachable attacker may capture, guess, or misuse legacy SNMP credentials.",
                    recommendation="Configure an SNMPv3 user using SHA authentication and AES privacy, and restrict permitted manager IPs.",
                    severity=Severity.MEDIUM,
                    evidence=("attached SNMP management without secure SNMPv3 user",),
                    references=(PANOS_CLI_GUIDE, PANOS_MANAGEMENT_GUIDE),
                )
            )

    def check_management_tls(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        if panos.panorama_inheritance_unknown:
            return
        profiles = {profile.name: profile for profile in panos.get_ssl_tls_service_profiles()}
        https_scopes = {
            service.scope
            for service in panos.get_dedicated_management_services()
            if service.protocol.casefold() == "https"
        }
        management_profiles = {
            (profile.scope, profile.name): profile
            for profile in panos.get_management_profiles()
        }
        for interface in panos.get_interfaces():
            profile = management_profiles.get((interface.device_scope, interface.management_profile))
            if interface.enabled and profile and "https" in profile.protocols:
                https_scopes.add(interface.device_scope)

        for setting in panos.get_management_tls():
            if setting.device_scope not in https_scopes:
                continue
            evidence = self._evidence(setting.evidence)
            if setting.tls_mode == "tlsv1.3_only":
                if not setting.certificate:
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.management.certificate_missing",
                            device=parser.device_type,
                            title="Management TLS 1.3 has no explicit server certificate",
                            observation=f"Management HTTPS in '{setting.device_scope}' selects TLS 1.3-only mode without an explicit management certificate.",
                            impact="Administrators cannot reliably authenticate the management endpoint with an approved certificate.",
                            exploitability="A network-positioned attacker can more easily impersonate an endpoint when clients accept an untrusted certificate.",
                            recommendation="Select a signed management server certificate appropriate for the firewall hostname.",
                            severity=Severity.MEDIUM,
                            evidence=evidence,
                            references=(PANOS_TLS_GUIDE,),
                        )
                    )
                continue
            if not setting.profile:
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.management.tls_profile_missing",
                        device=parser.device_type,
                        title="Management HTTPS lacks an SSL/TLS service profile",
                        observation=f"HTTPS management is enabled in '{setting.device_scope}' without an attached SSL/TLS service profile.",
                        impact="The management web service can use platform-default certificate and protocol settings rather than an approved policy.",
                        exploitability="A reachable attacker may target legacy protocol support or exploit administrators accepting an untrusted default certificate.",
                        recommendation="Attach an SSL/TLS service profile with a signed certificate and TLS 1.2 or later.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(PANOS_TLS_GUIDE,),
                    )
                )
                continue
            profile = profiles.get(setting.profile)
            if profile is None:
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.management.tls_profile_unresolved",
                        device=parser.device_type,
                        title="Management SSL/TLS service profile reference is unresolved",
                        observation=f"Management HTTPS references '{setting.profile}', but no local shared or vsys profile with that name was parsed.",
                        impact="The audit cannot establish the certificate or minimum TLS version protecting management access.",
                        exploitability="A missing or inherited object can conceal weaker effective management TLS settings.",
                        recommendation="Supply the complete effective configuration and ensure the referenced profile exists locally with approved settings.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(PANOS_TLS_GUIDE,),
                    )
                )
                continue
            profile_evidence = evidence + self._evidence(profile.evidence)
            if not profile.certificate:
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.management.certificate_missing",
                        device=parser.device_type,
                        title="Management SSL/TLS profile has no server certificate",
                        observation=f"Attached profile '{profile.name}' does not select a server certificate.",
                        impact="Administrators cannot reliably authenticate the management endpoint with an approved certificate.",
                        exploitability="A network-positioned attacker can more easily impersonate an endpoint when clients accept an untrusted certificate.",
                        recommendation="Select a signed non-CA server certificate in the attached SSL/TLS service profile.",
                        severity=Severity.MEDIUM,
                        evidence=profile_evidence,
                        references=(PANOS_TLS_GUIDE,),
                    )
                )
            if profile.minimum_version not in {"tls1-2", "tls1-3", "tlsv1.2", "tlsv1.3"}:
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.management.tls_minimum_version",
                        device=parser.device_type,
                        title="Management SSL/TLS profile permits a legacy minimum version",
                        observation=f"Attached profile '{profile.name}' has minimum version '{profile.minimum_version or 'unspecified'}'.",
                        impact="TLS 1.0 or 1.1 support exposes management sessions to obsolete protocol behavior and weak cipher compatibility.",
                        exploitability="A network-positioned attacker may attempt protocol downgrade or exploit legacy TLS weaknesses.",
                        recommendation="Set the management profile minimum to TLS 1.2 or TLS 1.3 where supported.",
                        severity=Severity.HIGH,
                        evidence=profile_evidence,
                        references=(PANOS_TLS_GUIDE,),
                    )
                )

    def check_updates_and_system_logging(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        if panos.panorama_inheritance_unknown:
            return
        threat_schedules = [
            schedule for schedule in panos.get_update_schedules()
            if schedule.content_type == "threats"
        ]
        if not threat_schedules or not any(
            schedule.recurrence not in {"", "none"}
            and schedule.action == "download-and-install"
            for schedule in threat_schedules
        ):
            self.add_issue(
                Finding(
                    rule_id="paloalto.panos.updates.threat_content",
                    device=parser.device_type,
                    title="Threat content is not scheduled for automatic installation",
                    observation="No recurring Applications and Threats schedule with action 'download-and-install' was parsed.",
                    impact="Threat signatures and decoders can remain stale even when update packages are downloaded.",
                    exploitability="Attackers may use techniques covered by signatures that have not yet been installed.",
                    recommendation="Configure a recurring Applications and Threats update schedule using download-and-install with an approved rollout threshold.",
                    severity=Severity.HIGH,
                    evidence=tuple(
                        item.text for schedule in threat_schedules for item in schedule.evidence
                    ) or ("deviceconfig system update-schedule threats absent",),
                    references=(PANOS_UPDATE_GUIDE,),
                )
            )
        if not panos.get_system_log_forwarding_destinations():
            self.add_issue(
                Finding(
                    rule_id="paloalto.panos.logging.system_forwarding",
                    device=parser.device_type,
                    title="System events lack a syslog forwarding destination",
                    observation="No device-level system log match entry sends events to a syslog server profile.",
                    impact="Administrative, update, high-availability, and system events may remain only on the appliance.",
                    exploitability="An attacker who compromises the firewall benefits from reduced off-device audit evidence.",
                    recommendation="Configure Device Log Settings for system events and send relevant severities to protected centralized syslog destinations.",
                    severity=Severity.MEDIUM,
                    evidence=("deviceconfig system log-settings system syslog destination absent",),
                    references=(PANOS_SYSTEM_LOG_GUIDE,),
                )
            )

    def _broad(self, rule: PanosSecurityRule) -> bool:
        return all(
            self._all_any(values)
            for values in (
                rule.from_zones,
                rule.to_zones,
                rule.sources,
                rule.destinations,
                rule.applications,
                rule.services,
                rule.source_users,
                rule.categories,
            )
        ) and rule.schedule.casefold() in {"none", "any"}

    def check_security_rules(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        profiles = {
            (profile.scope, profile.name): profile
            for profile in panos.get_log_forwarding_profiles()
        }
        for rule in panos.get_security_rules():
            if not rule.enabled or rule.action != "allow":
                continue
            evidence = self._evidence(rule.evidence)
            if self._broad(rule):
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.policy.broad_allow",
                        device=parser.device_type,
                        title="Unrestricted security policy rule",
                        observation=f"Enabled rule '{rule.name}' at position {rule.position} in '{rule.scope}' allows any zone, source, user, destination, application, service, and category without a schedule restriction.",
                        impact="The rule can bypass intended network and application segmentation.",
                        exploitability="Any matching source can reach any routable destination and application permitted by surrounding infrastructure.",
                        recommendation="Replace wildcard match dimensions with explicit zones, addresses, users, applications, and application-default service where appropriate.",
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                        references=(PANOS_POLICY_GUIDE,),
                    )
                )

            forwarding = profiles.get((rule.scope, rule.log_setting))
            if not forwarding or not forwarding.syslog_servers:
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.policy.log_forwarding",
                        device=parser.device_type,
                        title="Allow rule lacks effective centralized log forwarding",
                        observation=f"Enabled allow rule '{rule.name}' in '{rule.scope}' references '{rule.log_setting or 'no log-forwarding profile'}', which does not resolve to a same-scope profile with a syslog destination.",
                        impact="Traffic and threat events may remain only in limited local storage and be unavailable to central monitoring.",
                        exploitability="Reduced centralized telemetry can delay detection and investigation of malicious traffic.",
                        recommendation="Attach a same-vsys Log Forwarding profile with an active syslog destination and enable session-end logging.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(PANOS_LOG_FORWARDING_GUIDE,),
                    )
                )

            if not rule.log_end:
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.policy.session_logging",
                        device=parser.device_type,
                        title="Allow rule does not log at session end",
                        observation=f"Enabled allow rule '{rule.name}' in '{rule.scope}' does not enable log-at-session-end.",
                        impact="Completed-session byte counts, duration, and final application information may not be recorded.",
                        exploitability="Incomplete traffic records reduce visibility into successful or long-lived malicious sessions.",
                        recommendation="Enable log-at-session-end on the rule unless a documented exception applies.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(PANOS_POLICY_GUIDE,),
                    )
                )

            if not rule.profile_setting:
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.policy.security_profiles",
                        device=parser.device_type,
                        title="Allow rule has no security profile attachment",
                        observation=f"Enabled allow rule '{rule.name}' in '{rule.scope}' has no profile group or individual security profiles.",
                        impact="Permitted traffic may bypass threat, malware, URL, file, and data inspection controls.",
                        exploitability="An attacker can deliver malicious content through traffic permitted by the uninspected rule.",
                        recommendation="Attach the organization's approved Security Profile Group or explicit profiles to the allow rule.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(PANOS_POLICY_GUIDE,),
                    )
                )

    def check_password_policy(self, parser: BaseDeviceParser) -> None:
        policy = self._panos(parser).get_password_policy()
        weaknesses = []
        if policy.enabled is not True:
            weaknesses.append("complexity is absent or disabled")
        # NEEDS_HUMAN_REVIEW: 12 is the project baseline; PAN-OS documents a
        # product minimum of eight but organizations may require a higher value.
        if policy.minimum_length is None or policy.minimum_length < 12:
            weaknesses.append("minimum length is below 12 or unparseable")
        for label, value in (
            ("uppercase", policy.minimum_uppercase),
            ("lowercase", policy.minimum_lowercase),
            ("numeric", policy.minimum_numeric),
            ("special", policy.minimum_special),
        ):
            if value is None or value < 1:
                weaknesses.append(f"{label} character minimum is below 1 or unparseable")
        if not weaknesses:
            return
        self.add_issue(
            Finding(
                rule_id="paloalto.panos.credentials.password_complexity",
                device=parser.device_type,
                title="Management password complexity is insufficient",
                observation="The local administrator password policy is unsafe: " + "; ".join(weaknesses) + ".",
                impact="Weak local administrator passwords are more susceptible to guessing and credential attacks.",
                exploitability="An attacker with management reachability can target accounts protected by the weak local policy.",
                recommendation="Enable password complexity and require at least 12 characters with uppercase, lowercase, numeric, and special-character minima, or apply the approved organizational benchmark.",
                severity=Severity.HIGH,
                evidence=self._evidence(policy.evidence) or ("password-complexity absent",),
                references=(PANOS_PASSWORD_GUIDE,),
            )
        )

    def check_panorama_scope(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        if not panos.panorama_inheritance_unknown:
            return
        self.add_issue(
            Finding(
                rule_id="paloalto.panos.analysis.panorama_inheritance_unknown",
                device=parser.device_type,
                title="Panorama inheritance is not resolved",
                observation="The XML contains device-group or template configuration whose effective inheritance cannot be reconstructed from this single export.",
                impact="Locally observed settings may be overridden or supplemented by Panorama-managed configuration.",
                exploitability="This is an analysis-confidence limitation rather than a directly exploitable condition.",
                recommendation="Audit a merged effective device configuration or supply all relevant Panorama template, stack, and device-group exports.",
                severity=Severity.INFORMATIONAL,
                evidence=tuple(panos.diagnostics),
                references=(PANOS_HIERARCHY_GUIDE,),
            )
        )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_management(parser)
        self.check_security_rules(parser)
        self.check_password_policy(parser)
        self.check_administration(parser)
        self.check_platform_services(parser)
        self.check_management_tls(parser)
        self.check_updates_and_system_logging(parser)
        self.check_panorama_scope(parser)
