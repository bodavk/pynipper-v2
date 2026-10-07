"""Attachment- and scope-aware PAN-OS management and policy checks."""

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.controls import ControlOutcome, record_control
from src.analyze.common.input_scope import _EXPLICIT_RULES as _TEMPLATE_EXPLICIT_RULES
from src.devices.common.models import KnowledgeState
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.analyze.common.attack_paths import mark_evaluated, record_deny_defeated, record_path_not_assessed
from src.devices.common.policy_semantics import (
    ProofState,
    network_covers,
    service_covers,
    static_values_cover,
)
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.paloalto.panos import PaloAltoPANOSParser, PanosSecurityRule


PANOS_DNS_SINKHOLE_GUIDE = "https://docs.paloaltonetworks.com/advanced-threat-prevention/administration/configure-threat-prevention/use-dns-queries-to-identify-infected-hosts-on-the-network/configure-dns-sinkholing"
PANOS_MANAGEMENT_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/networking/configure-interfaces/"
    "use-interface-management-profiles-to-restrict-access"
)
PANOS_POLICY_GUIDE = (
    "https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/"
    "security-policy-best-practices/deploy-security-policy-best-practices/"
    "security-policy-rule-best-practices"
)
PANOS_DEFAULT_RULE_GUIDE = (
    "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-policy"
)
PANOS_SECURITY_PROFILES_GUIDE = (
    "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/"
    "security-profiles"
)
PANOS_LOG_FORWARDING_GUIDE = (
    "https://docs.paloaltonetworks.com/network-security/security-policy/"
    "administration/objects/log-forwarding"
)
PANOS_PASSWORD_GUIDE = (
    "https://origin-docs.paloaltonetworks.com/ngfw/help/12-1/"
    "device/device-setup-management"
)
PANOS_HIERARCHY_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/"
    "cli-command-hierarchy/pan-os-11-2-configure-cli-command-hierarchy"
)
PANOS_INITIAL_CONFIGURATION = (
    "https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/getting-started/"
    "integrate-the-firewall-into-your-management-network/perform-initial-configuration"
)
PANOS_ADMIN_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/"
    "manage-firewall-administrators/administrative-authentication"
)
PANOS_ADMIN_ROLE_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/help/12-1/device/"
    "device-admin-roles"
)
PANOS_SSH_PROFILE_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/administration/"
    "certificate-management/configure-ssh-service-profile"
)
PANOS_CLI_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/"
    "cli-command-hierarchy/pan-os-11-1-configure-cli-command-hierarchy"
)
PANOS_TLS_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/administration/certificate-management/"
    "configure-ssl-tls-service-profile"
)
NIST_CRYPTO_TRANSITIONS = "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"
PANOS_UPDATE_GUIDE = (
    "https://docs.paloaltonetworks.com/advanced-threat-prevention/administration/"
    "configure-threat-prevention/set-up-antivirus-anti-spyware-and-vulnerability-protection"
)
PANOS_SYSTEM_LOG_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/administration/monitoring/"
    "configure-log-forwarding"
)
PANOS_NTP_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/getting-started/"
    "initial-setup-configuration-ngfws"
)
PANOS_ZONE_PROTECTION_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/administration/"
    "zone-protection-and-dos-protection/zone-defense/zone-protection-profiles"
)
PANOS_RECONNAISSANCE_GUIDE = (
    "https://docs.paloaltonetworks.com/ngfw/administration/zone-protection-and-dos-protection/"
    "zone-defense/zone-protection-profiles/configure-reconnaissance-protection"
)


class PluginPANOSChecks(BasePlugin):
    """Evaluate only attached local-firewall state that the XML proves."""

    _UNTRUSTED_ZONES = {"untrust", "external", "internet", "public", "wan"}
    _EXTERNAL_AUTH_METHODS = frozenset({"radius", "tacacs-plus", "ldap", "kerberos", "saml-idp", "cloud"})
    _TERMINAL_ACTIONS = {
        "allow", "deny", "drop", "reset-both", "reset-client", "reset-server"
    }

    @staticmethod
    def _panos(parser: BaseDeviceParser) -> PaloAltoPANOSParser:
        if not isinstance(parser, PaloAltoPANOSParser):
            raise TypeError("PluginPANOSChecks requires a PAN-OS parser")
        return parser

    @staticmethod
    def _evidence(items) -> tuple[str, ...]:
        return tuple(item for item in items)

    @staticmethod
    def _all_any(values: tuple[str, ...]) -> bool:
        return bool(values) and all(value.casefold() == "any" for value in values)

    @staticmethod
    def _record(parser, control: str, outcome: ControlOutcome, reason: str, *, rule: str = "",
                instance: str = "device") -> None:
        """Record a control outcome; a finding withheld for an unrendered template is unknown."""
        if (outcome == ControlOutcome.FINDING and rule and getattr(parser, "template_unresolved", False)
                and rule not in _TEMPLATE_EXPLICIT_RULES.get(parser.device_type, frozenset())):
            outcome = ControlOutcome.UNKNOWN
            reason = "Unrendered template; this finding is withheld because the template may omit settings."
        record_control(parser, control, outcome, reason, instance=instance)

    @staticmethod
    def _setting_outcome(panos: PaloAltoPANOSParser, fired: bool, *states: str) -> tuple[ControlOutcome, str]:
        """Outcome for an explicit-value check over bounded management settings."""
        if fired:
            return ControlOutcome.FINDING, "An explicit value is outside the baseline."
        if any(state in {"invalid", "unknown-inherited"} for state in states):
            return ControlOutcome.UNKNOWN, "A value is malformed, out of range or inherited."
        if "absent" in states and not panos.management_exported():
            return ControlOutcome.UNKNOWN, "The device management configuration is not exported."
        if "absent" in states:
            # The check grades explicit values only; no cited vendor source fixes the
            # release default, so an omitted value is an unqualified default.
            return ControlOutcome.UNKNOWN, "A setting is omitted and its release default is not verified; only explicit values are graded."
        return ControlOutcome.NO_FINDING, "Explicit values meet the baseline."

    def check_management(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        services = panos.get_normalized_config().management_services.items
        control = "paloalto.panos.cleartext-management"
        cleartext = [service for service in services if service.protocol.casefold() in {"http", "telnet"}]
        if not cleartext:
            profiles = {(item.scope, item.name) for item in panos.get_management_profiles()}
            unresolved_profile = any(
                interface.enabled and interface.management_profile
                and (interface.device_scope, interface.management_profile) not in profiles
                for interface in panos.get_interfaces()
            )
            if panos.panorama_inheritance_unknown:
                record_control(parser, control, ControlOutcome.UNKNOWN,
                               "Panorama template inheritance is unresolved; inherited management services are unknown.")
            elif not panos.management_exported():
                record_control(parser, control, ControlOutcome.UNKNOWN,
                               "Device management configuration is not exported.")
            elif unresolved_profile:
                record_control(parser, control, ControlOutcome.UNKNOWN,
                               "An interface references a management profile that is not exported.")
            else:
                record_control(parser, control, ControlOutcome.NO_FINDING,
                               "No attached Interface Management profile or MGT service enables HTTP or Telnet.")
        for service in services:
            protocol = service.protocol.casefold()
            if protocol in {"http", "telnet"}:
                record_control(parser, control, ControlOutcome.FINDING,
                               f"{protocol.upper()} management is enabled.",
                               instance=f"{service.scope}/{service.interface}/{protocol}")
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
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )

        secure_control = "paloalto.panos.management-source-restriction"
        secure_services = [service for service in services if service.protocol.casefold() in {"ssh", "https"}]
        if not secure_services:
            profiles = {(item.scope, item.name) for item in panos.get_management_profiles()}
            if panos.panorama_inheritance_unknown:
                self._record(parser, secure_control, ControlOutcome.UNKNOWN,
                             "Panorama template inheritance is unresolved; inherited management services are unknown.")
            elif not panos.management_exported():
                self._record(parser, secure_control, ControlOutcome.UNKNOWN,
                             "Device management configuration is not exported.")
            elif any(interface.enabled and interface.management_profile
                     and (interface.device_scope, interface.management_profile) not in profiles
                     for interface in panos.get_interfaces()):
                self._record(parser, secure_control, ControlOutcome.UNKNOWN,
                             "An interface references a management profile that is not exported.")
            else:
                self._record(parser, secure_control, ControlOutcome.NO_FINDING,
                             "No attached Interface Management profile or MGT service explicitly enables SSH or HTTPS.")
        for service in secure_services:
            exposed = not service.permitted_sources and (
                (service.zone or "").casefold() in self._UNTRUSTED_ZONES or service.interface == "MGT")
            self._record(parser, secure_control, ControlOutcome.FINDING if exposed else ControlOutcome.NO_FINDING,
                         "SSH/HTTPS management on MGT or an untrusted zone has no permitted IP addresses." if exposed else
                         "Permitted IP addresses are configured, or the service is not on MGT or an untrusted zone.",
                         rule="paloalto.panos.management.unrestricted_secure_service",
                         instance=f"{service.scope}/{service.interface}/{service.protocol.casefold()}")

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
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )

    def check_administration(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        default_admin = panos.get_default_admin_password()
        if default_admin is not None:
            self.add_issue(Finding(
                rule_id="paloalto.panos.credentials.known_default_value",
                device=parser.device_type,
                title="Built-in admin account still uses its factory password",
                observation="The stored hash of the 'admin' account is the documented factory password (recognised by recomputing it; the value is not shown).",
                impact="Anyone who reaches the web interface, API or SSH can log in with full administrative rights.",
                exploitability="admin/admin is published and is the first credential attackers try.",
                recommendation="Change the admin password now, or disable the built-in admin after creating named administrators.",
                severity=Severity.CRITICAL,
                evidence=(default_admin,),
                references=(PANOS_INITIAL_CONFIGURATION,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        default_control = "paloalto.panos.default-admin-password"
        default_state = panos.get_default_admin_password_state()
        if default_admin is not None:
            self._record(parser, default_control, ControlOutcome.FINDING,
                         "The built-in admin account uses the factory password.",
                         rule="paloalto.panos.credentials.known_default_value", instance="management/admin:admin")
        elif default_state == "changed":
            self._record(parser, default_control, ControlOutcome.NO_FINDING,
                         "The built-in admin password hash is not the factory value.", instance="management/admin:admin")
        elif default_state == "absent" and panos.management_exported() and not panos.panorama_inheritance_unknown:
            self._record(parser, default_control, ControlOutcome.NOT_APPLICABLE,
                         "The exported administrator list has no built-in admin account.")
        else:
            self._record(parser, default_control, ControlOutcome.UNKNOWN,
                         "The built-in admin account or its password hash is not exported, inherited or uses an unsupported hash format.")
        users = panos.get_normalized_config().users.items
        auth_control = "paloalto.panos.centralized-authentication"
        if not users:
            self._record(parser, auth_control, ControlOutcome.UNKNOWN, "No administrator account is exported.")
        elif all(user.authentication == "local" for user in users):
            self._record(parser, auth_control, ControlOutcome.FINDING,
                         "Every administrator uses local authentication.",
                         rule="paloalto.panos.admin.centralized_authentication")
        elif any(policy.authentication_profile and policy.authentication_resolution == "known"
                 and policy.authentication_method in self._EXTERNAL_AUTH_METHODS
                 for policy in panos.get_administrator_policies()):
            self._record(parser, auth_control, ControlOutcome.NO_FINDING,
                         "At least one administrator is bound to a resolved external authentication profile.")
        else:
            self._record(parser, auth_control, ControlOutcome.UNKNOWN,
                         "Administrator authentication profiles are unresolved, inherited or not proven to be external.")
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
                        evidence for user in users for evidence in user.evidence
                    ),
                    references=(PANOS_ADMIN_GUIDE,),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )

    def check_administrative_policy(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        accounts = panos.get_administrator_policies()
        if not accounts:
            record_control(parser, "paloalto.panos.administrator-policy", ControlOutcome.UNKNOWN,
                           "Administrator identity/role scope is unexported; completeness is unqualified.")
        for account in accounts:
            control = "paloalto.panos.administrator-policy"
            instance = "management/admin:" + account.username
            record_control(parser, control,
                           ControlOutcome.NO_FINDING if account.role_resolution == "known" else ControlOutcome.UNKNOWN,
                           "Explicit role resolves in the supplied configuration." if account.role_resolution == "known" else
                           "Administrator role is absent, unexported or inherited; privilege completeness is unqualified.",
                           instance=instance + "/role")
            record_control(parser, control,
                           ControlOutcome.NO_FINDING if account.authentication_resolution == "known" and account.authentication_profile else ControlOutcome.UNKNOWN,
                           "Explicit authentication binding resolves." if account.authentication_resolution == "known" and account.authentication_profile else
                           "Authentication binding is unexported, ambiguous or inherited; it is not a proven missing control.",
                           instance=instance + "/authentication")

        admin_controls = ("paloalto.panos.login-banner-acknowledgement", "paloalto.panos.admin-idle-timeout",
                          "paloalto.panos.admin-lockout", "paloalto.panos.admin-session-limit")
        if panos.panorama_inheritance_unknown:
            record_control(parser, "paloalto.panos.login-banner", ControlOutcome.UNKNOWN,
                           "Administrative settings may be inherited from Panorama.")
            for admin_control in admin_controls:
                record_control(parser, admin_control, ControlOutcome.UNKNOWN,
                               "Administrative settings may be inherited from Panorama.")
        elif not panos.get_administrative_settings():
            record_control(parser, "paloalto.panos.login-banner", ControlOutcome.UNKNOWN,
                           "No device configuration is exported.")
            for admin_control in admin_controls:
                record_control(parser, admin_control, ControlOutcome.UNKNOWN, "No device configuration is exported.")
        if not panos.panorama_inheritance_unknown:
            for settings in panos.get_administrative_settings():
                evidence = self._evidence(settings.evidence)
                record_control(parser, "paloalto.panos.login-banner",
                               ControlOutcome.NO_FINDING if settings.login_banner_configured else ControlOutcome.FINDING,
                               "A login banner is configured." if settings.login_banner_configured
                               else "No login banner is configured.", instance=settings.device_scope)
                if settings.authentication_resolution in {"unresolved", "ambiguous"}:
                    record_control(parser, "paloalto.panos.administrator-policy", ControlOutcome.UNKNOWN,
                                   "Global authentication profile/sequence is unexported or ambiguous.",
                                   instance=settings.device_scope + "/authentication")
                self._record(parser, "paloalto.panos.login-banner-acknowledgement",
                             ControlOutcome.NOT_APPLICABLE if not settings.login_banner_configured else
                             ControlOutcome.NO_FINDING if settings.acknowledge_login_banner is True else ControlOutcome.FINDING,
                             "No login banner is configured." if not settings.login_banner_configured else
                             "Administrators must acknowledge the login banner." if settings.acknowledge_login_banner is True else
                             "Login banner acknowledgement is disabled or not configured.",
                             rule="paloalto.panos.admin.login_banner_acknowledgement", instance=settings.device_scope)
                idle_fired = (settings.idle_timeout_state == "explicit" and settings.idle_timeout_minutes is not None
                              and (settings.idle_timeout_minutes == 0 or settings.idle_timeout_minutes > 10))
                outcome, reason = self._setting_outcome(panos, idle_fired, settings.idle_timeout_state)
                self._record(parser, "paloalto.panos.admin-idle-timeout", outcome, reason,
                             rule="paloalto.panos.admin.idle_timeout", instance=settings.device_scope)
                attempts_fired = (settings.failed_attempts_state == "explicit" and settings.failed_attempts is not None
                                  and (settings.failed_attempts == 0 or settings.failed_attempts > 5))
                lockout_fired = (settings.failed_attempts_state == "explicit" and settings.failed_attempts is not None
                                 and settings.failed_attempts > 0 and settings.lockout_state == "explicit"
                                 and settings.lockout_minutes is not None and 0 < settings.lockout_minutes < 30)
                outcome, reason = self._setting_outcome(panos, attempts_fired or lockout_fired,
                                                        settings.failed_attempts_state, settings.lockout_state)
                self._record(parser, "paloalto.panos.admin-lockout", outcome, reason,
                             rule="paloalto.panos.admin.login_attempts" if attempts_fired else "paloalto.panos.admin.lockout_time",
                             instance=settings.device_scope)
                sessions_fired = settings.max_session_count_state == "explicit" and settings.max_session_count == 0
                outcome, reason = self._setting_outcome(panos, sessions_fired, settings.max_session_count_state)
                self._record(parser, "paloalto.panos.admin-session-limit", outcome, reason,
                             rule="paloalto.panos.admin.concurrent_sessions", instance=settings.device_scope)
                if not settings.login_banner_configured:
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.admin.login_banner",
                            device=parser.device_type,
                            title="Administrative login banner is missing",
                            observation=f"No login banner is configured for device scope '{settings.device_scope}'.",
                            impact="Administrators are not shown an approved access warning before authentication.",
                            exploitability="Missing legal or acceptable-use notice can weaken deterrence and incident-response support.",
                            recommendation="Configure an organization-approved login banner on the management interface.",
                            severity=Severity.MEDIUM,
                            evidence=evidence,
                            references=(PANOS_PASSWORD_GUIDE,),
                            basis=FindingBasis.REQUIRED_SETTING_MISSING,
                        )
                    )
                elif settings.acknowledge_login_banner is not True:
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.admin.login_banner_acknowledgement",
                            device=parser.device_type,
                            title="Login banner acknowledgement is not enforced",
                            observation=f"A login banner exists in device scope '{settings.device_scope}', but administrators are not explicitly required to acknowledge it.",
                            impact="The warning can be bypassed without affirmative acknowledgement.",
                            exploitability="An unauthorized user can proceed directly to authentication without accepting the displayed notice.",
                            recommendation="Enable Force Admins to Acknowledge Login Banner.",
                            severity=Severity.LOW,
                            evidence=evidence,
                            references=(PANOS_PASSWORD_GUIDE,),
                            basis=FindingBasis.EXPLICIT_VALUE if settings.acknowledge_login_banner is False else FindingBasis.MISSING_EXPLICIT_SETTING,
                        )
                    )
                if (
                    settings.idle_timeout_state == "explicit"
                    and settings.idle_timeout_minutes is not None
                    and (settings.idle_timeout_minutes == 0 or settings.idle_timeout_minutes > 10)
                ):
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.admin.idle_timeout",
                            device=parser.device_type,
                            title="Administrative idle timeout is disabled or excessive",
                            observation=f"The explicit management idle timeout is {settings.idle_timeout_minutes} minutes in device scope '{settings.device_scope}'.",
                            impact="An abandoned web or CLI administrative session can remain usable for an excessive period.",
                            exploitability="A person with access to an unattended administrator workstation can reuse the active session.",
                            recommendation="Set the management idle timeout to 10 minutes or the stricter approved organizational value.",
                            severity=Severity.MEDIUM,
                            evidence=evidence,
                            references=(PANOS_PASSWORD_GUIDE,),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        )
                    )
                if (
                    settings.failed_attempts_state == "explicit"
                    and settings.failed_attempts is not None
                    and (settings.failed_attempts == 0 or settings.failed_attempts > 5)
                ):
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.admin.login_attempts",
                            device=parser.device_type,
                            title="Administrative login attempt limit is unsafe",
                            observation=f"The explicit failed-attempt limit is {settings.failed_attempts} in device scope '{settings.device_scope}'.",
                            impact="Unlimited or excessive retries increase exposure to online password guessing.",
                            exploitability="A management-plane attacker can submit more credential guesses before account lockout.",
                            recommendation="Set Failed Attempts to a value from 1 through 5 and test the recovery procedure.",
                            severity=Severity.MEDIUM,
                            evidence=evidence,
                            references=(PANOS_PASSWORD_GUIDE,),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        )
                    )
                if (
                    settings.failed_attempts_state == "explicit"
                    and settings.failed_attempts is not None
                    and settings.failed_attempts > 0
                    and settings.lockout_state == "explicit"
                    and settings.lockout_minutes is not None
                    and 0 < settings.lockout_minutes < 30
                ):
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.admin.lockout_time",
                            device=parser.device_type,
                            title="Administrative lockout period is too short",
                            observation=f"The explicit lockout period is {settings.lockout_minutes} minutes after {settings.failed_attempts} failed attempts in device scope '{settings.device_scope}'.",
                            impact="Short lockouts allow repeated guessing campaigns to resume quickly.",
                            exploitability="An attacker can wait out the short lockout and continue attempting credentials.",
                            recommendation="Set Lockout Time to at least 30 minutes or use the manual-unlock value according to policy.",
                            severity=Severity.MEDIUM,
                            evidence=evidence,
                            references=(PANOS_PASSWORD_GUIDE,),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        )
                    )
                if (
                    settings.max_session_count_state == "explicit"
                    and settings.max_session_count == 0
                ):
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.admin.concurrent_sessions",
                            device=parser.device_type,
                            title="Concurrent administrative sessions are unlimited",
                            observation=f"The explicit maximum session count is 0 (unlimited) in device scope '{settings.device_scope}'.",
                            impact="Unlimited concurrent sessions weaken account-use control and can increase management-plane resource pressure.",
                            exploitability="A compromised administrator credential can be used for multiple simultaneous sessions without this bound.",
                            recommendation="Configure a finite Max Session Count consistent with the number of authorized administrators.",
                            severity=Severity.MEDIUM,
                            evidence=evidence,
                            references=(PANOS_PASSWORD_GUIDE,),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        )
                    )

        weak_ciphers = {"aes128-cbc", "aes192-cbc", "aes256-cbc"}
        weak_kex = {"diffie-hellman-group14-sha1"}
        weak_macs = {"hmac-sha1"}
        ssh_policies = panos.get_ssh_management_policies()
        if not ssh_policies:
            record_control(parser, "paloalto.panos.management-ssh", ControlOutcome.UNKNOWN, "Management SSH scope is unexported.")
        for policy in ssh_policies:
            control = "paloalto.panos.management-ssh"
            if not policy.enabled or not policy.supported:
                record_control(parser, control, ControlOutcome.UNSUPPORTED if not policy.supported else ControlOutcome.UNKNOWN,
                               "Management SSH profile dialect/release is unsupported." if not policy.supported else
                               "No explicit active management SSH attachment is supplied; service completeness is unqualified.",
                               instance=policy.device_scope)
                continue
            evidence = self._evidence(policy.evidence)
            if policy.resolution_state == "missing":
                record_control(parser, control, ControlOutcome.FINDING,
                               "SSH management is enabled and no management SSH server profile is configured.",
                               instance=policy.device_scope)
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.admin.ssh_profile_missing",
                        device=parser.device_type,
                        title="Management SSH service profile is not configured",
                        observation=(f"SSH management is enabled in device scope '{policy.device_scope}', but no management SSH "
                                     "server profile is applied. The setting is omitted from the configuration, not set to a weak value."),
                        impact="The management SSH server offers the platform's full default algorithm set instead of an explicitly restricted policy.",
                        exploitability="A reachable SSH client can negotiate any algorithm that remains available in the default server set.",
                        recommendation="Create, apply, and activate a management SSH service profile containing only approved algorithms.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(PANOS_SSH_PROFILE_GUIDE,),
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )
                continue
            if policy.resolution_state != "known":
                record_control(parser, control, ControlOutcome.UNKNOWN,
                               "Management SSH profile reference is unresolved or inherited; the referenced definition is not in the export.",
                               instance=policy.device_scope)
                continue
            weaknesses = []
            omitted = [f"{label} list is not configured (all default algorithms are offered)" for label in policy.omitted_fields]
            if not all((policy.ciphers, policy.key_exchanges, policy.macs)) and not omitted:
                record_control(parser, control, ControlOutcome.UNKNOWN,
                               policy.knowledge.reason, instance=policy.device_scope + "/incomplete-fields")
            if weak := sorted(set(policy.ciphers).intersection(weak_ciphers)):
                weaknesses.append("CBC ciphers: " + ", ".join(weak))
            if weak := sorted(set(policy.key_exchanges).intersection(weak_kex)):
                weaknesses.append("legacy key exchange: " + ", ".join(weak))
            if weak := sorted(set(policy.macs).intersection(weak_macs)):
                weaknesses.append("legacy MAC: " + ", ".join(weak))
            explicit_weak = bool(weaknesses)
            weaknesses += omitted
            if weaknesses:
                record_control(parser, control, ControlOutcome.FINDING,
                               "Weak or unrestricted applied management SSH algorithms.", instance=policy.device_scope)
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.admin.ssh_profile_algorithms",
                        device=parser.device_type,
                        title="Management SSH profile permits unsafe algorithm behavior",
                        observation=f"Applied profile '{policy.selected_profile}' has the following weaknesses: {'; '.join(weaknesses)}.",
                        impact="Legacy or unrestricted SSH negotiation weakens management-session confidentiality and integrity.",
                        exploitability="A management-path attacker can target or negotiate algorithms left available by the applied profile.",
                        recommendation="Restrict the profile to approved CTR/GCM ciphers, SHA-2 MACs, and SHA-2 elliptic-curve key exchange, then restart the management SSH service.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(PANOS_SSH_PROFILE_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE if explicit_weak else FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )
            elif all((policy.ciphers, policy.key_exchanges, policy.macs)):
                record_control(parser, control, ControlOutcome.NO_FINDING, "Exported algorithm lists contain no supported explicit legacy algorithm; runtime activation unassessed.", instance=policy.device_scope)

    def check_platform_services(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        if panos.panorama_inheritance_unknown:
            record_control(parser, "paloalto.panos.ntp-authentication", ControlOutcome.UNKNOWN,
                           "NTP settings may be inherited from Panorama.")
            for platform_control in ("paloalto.panos.ntp-servers", "paloalto.panos.ntp-key-algorithm",
                                     "paloalto.panos.dns-servers", "paloalto.panos.snmpv3-users"):
                record_control(parser, platform_control, ControlOutcome.UNKNOWN,
                               "Platform settings may be inherited from Panorama.")
            return
        associations = panos.get_ntp_associations()
        self._record(parser, "paloalto.panos.ntp-servers",
                     ControlOutcome.FINDING if not associations else ControlOutcome.NO_FINDING,
                     "No NTP server is configured." if not associations else "At least one NTP server is configured.",
                     rule="paloalto.panos.ntp.servers")
        if not associations:
            record_control(parser, "paloalto.panos.ntp-authentication", ControlOutcome.NOT_APPLICABLE,
                           "No NTP server is configured.")
            record_control(parser, "paloalto.panos.ntp-key-algorithm", ControlOutcome.NOT_APPLICABLE,
                           "No NTP server is configured.")
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
                    references=(PANOS_NTP_GUIDE,),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )
        else:
            modern_algorithms = panos.supports_modern_ntp_algorithms()
            for association in associations:
                incomplete = association.authentication == "none" or (
                    association.authentication == "symmetric-key"
                    and (
                        not association.key_id
                        or not association.algorithm
                        or association.key_material_state == "missing"
                    )
                )
                record_control(parser, "paloalto.panos.ntp-authentication",
                               ControlOutcome.FINDING if incomplete else
                               ControlOutcome.UNKNOWN if association.authentication == "unknown" else ControlOutcome.NO_FINDING,
                               "Association lacks complete authentication." if incomplete else
                               "Association authentication uses unsupported syntax." if association.authentication == "unknown"
                               else "Association has a complete authentication configuration.",
                               instance=f"{association.device_scope}/{association.role}")
                if incomplete:
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.ntp.authentication",
                            device=parser.device_type,
                            title="NTP association is not authenticated",
                            observation=f"The {association.role} NTP server '{association.address}' in scope '{association.device_scope}' lacks a complete authentication configuration.",
                            impact="Unauthenticated time responses can corrupt log chronology and time-dependent security behavior.",
                            exploitability="A network-positioned attacker may spoof NTP responses if routing and filtering permit it.",
                            recommendation="Configure complete per-server symmetric-key authentication using an algorithm supported by the installed PAN-OS release.",
                            severity=Severity.MEDIUM,
                            evidence=self._evidence(association.evidence),
                            references=(PANOS_NTP_GUIDE,),
                            basis=FindingBasis.REQUIRED_SETTING_MISSING,
                        )
                    )
                weak = association.authentication == "autokey" or (
                    modern_algorithms is True
                    and association.authentication == "symmetric-key"
                    and association.algorithm in {"md5", "sha1"}
                )
                legacy = association.authentication == "symmetric-key" and association.algorithm in {"md5", "sha1"}
                self._record(
                    parser, "paloalto.panos.ntp-key-algorithm",
                    ControlOutcome.FINDING if weak else
                    ControlOutcome.UNKNOWN if association.authentication == "unknown" or (legacy and modern_algorithms is None) else
                    ControlOutcome.NOT_APPLICABLE if association.authentication == "none" or not association.algorithm else
                    ControlOutcome.NO_FINDING,
                    "Association uses autokey or MD5/SHA-1 on a release that supports SHA-2." if weak else
                    "Authentication syntax is unsupported." if association.authentication == "unknown" else
                    "The release is unidentified, so SHA-2 NTP support is unqualified." if legacy and modern_algorithms is None else
                    "Association has no complete symmetric-key algorithm (see ntp-authentication)."
                    if association.authentication == "none" or not association.algorithm else
                    "Association uses SHA-2, or MD5/SHA-1 on a release without SHA-2 NTP support.",
                    rule="paloalto.panos.ntp.weak_algorithm", instance=f"{association.device_scope}/{association.role}")
                if weak:
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.ntp.weak_algorithm",
                            device=parser.device_type,
                            title="NTP association uses a legacy authentication method",
                            observation=f"The {association.role} NTP server '{association.address}' uses '{association.authentication if association.authentication == 'autokey' else association.algorithm}'.",
                            impact="A legacy NTP authentication method provides weaker protection against forged time updates.",
                            exploitability="A network-positioned attacker can target weaknesses in the configured authentication method.",
                            recommendation="On PAN-OS 12.1.2 or later, use SHA-256 or SHA-512 symmetric-key authentication; upgrade older releases where the approved policy requires modern algorithms.",
                            severity=Severity.MEDIUM,
                            evidence=self._evidence(association.evidence),
                            references=(PANOS_NTP_GUIDE,),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        )
                    )
        dns_servers = panos.get_dns_servers()
        self._record(parser, "paloalto.panos.dns-servers",
                     ControlOutcome.FINDING if not dns_servers else ControlOutcome.NO_FINDING,
                     "No management-plane DNS server is configured." if not dns_servers else
                     "A management-plane DNS server is configured.", rule="paloalto.panos.dns.servers")
        if not dns_servers:
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
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )
        snmp_enabled = any(
            service.protocol.casefold() == "snmp"
            for service in panos.get_normalized_config().management_services.items
        )
        snmp_control = "paloalto.panos.snmpv3-users"
        if not snmp_enabled:
            self._record(parser, snmp_control,
                         ControlOutcome.NOT_APPLICABLE if panos.management_exported() else ControlOutcome.UNKNOWN,
                         "SNMP is not enabled on any management service." if panos.management_exported() else
                         "Device management configuration is not exported.")
        else:
            secure_user = panos.has_secure_snmpv3_user()
            self._record(parser, snmp_control, ControlOutcome.NO_FINDING if secure_user else ControlOutcome.FINDING,
                         "A SHA/AES SNMPv3 user is configured." if secure_user else
                         "SNMP is enabled without a SHA/AES SNMPv3 user.",
                         rule="paloalto.panos.snmp.secure_user_missing")
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
                    references=(PANOS_HIERARCHY_GUIDE, PANOS_MANAGEMENT_GUIDE),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )
        if snmp_enabled:
            snmp_release = panos._release_tuple(panos.get_version())
            for user in panos.get_snmpv3_users():
                evidence = self._evidence(user.evidence)
                missing = []
                if user.authentication in {"none", "noauth"}:
                    missing.append("authentication")
                if user.privacy in {"none", "nopriv"}:
                    missing.append("privacy")
                if missing:
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.snmp.v3_protection",
                            device=parser.device_type,
                            title="SNMPv3 user lacks complete protection",
                            observation=f"SNMPv3 user '{user.name}' in '{user.device_scope}' lacks {' and '.join(missing)}.",
                            impact="SNMP management data may lack strong authentication or confidentiality.",
                            exploitability="A reachable or on-path attacker can target an under-protected SNMP identity.",
                            recommendation="Configure SHA-family authentication and AES privacy for every active SNMPv3 user.",
                            severity=Severity.HIGH,
                            evidence=evidence,
                            references=(PANOS_HIERARCHY_GUIDE, PANOS_MANAGEMENT_GUIDE),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        )
                    )
                weak = []
                if user.authentication == "md5" or (
                    snmp_release is not None
                    and snmp_release >= (11, 2, 0)
                    and user.authentication in {"sha", "sha1", "sha-1"}
                ):
                    weak.append(f"{user.authentication.upper()} authentication")
                if user.privacy in {"des", "3des"}:
                    weak.append(f"{user.privacy.upper()} privacy")
                user_instance = f"{user.device_scope}/snmpv3-user:{user.name}"
                if missing or weak:
                    self._record(parser, snmp_control, ControlOutcome.FINDING,
                                 "SNMPv3 user lacks protection or uses a weak algorithm.",
                                 rule="paloalto.panos.snmp.v3_protection" if missing else "paloalto.panos.snmp.v3_weak_algorithm",
                                 instance=user_instance)
                elif user.authentication in {"sha", "sha1", "sha-1"} and snmp_release is None:
                    record_control(parser, snmp_control, ControlOutcome.UNKNOWN,
                                   "The release is unidentified, so whether SHA-1 is weak is unqualified.", instance=user_instance)
                elif (user.authentication in {"sha", "sha1", "sha-1", "sha-224", "sha-256", "sha-384", "sha-512"}
                      and user.privacy in {"aes", "aes-128", "aes-192", "aes-256"}):
                    record_control(parser, snmp_control, ControlOutcome.NO_FINDING,
                                   "SNMPv3 user uses supported authentication and AES privacy.", instance=user_instance)
                else:
                    record_control(parser, snmp_control, ControlOutcome.UNKNOWN,
                                   "SNMPv3 protocol is omitted (release default unqualified) or unsupported.", instance=user_instance)
                if weak:
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.snmp.v3_weak_algorithm",
                            device=parser.device_type,
                            title="SNMPv3 user uses weak algorithms",
                            observation=f"SNMPv3 user '{user.name}' in '{user.device_scope}' uses {', '.join(weak)}.",
                            impact="Legacy SNMPv3 algorithms provide inadequate cryptographic protection.",
                            exploitability="A traffic observer can target weaknesses in legacy algorithms.",
                            recommendation="Use a supported SHA-2 authentication option and AES privacy.",
                            severity=Severity.MEDIUM,
                            evidence=evidence,
                            references=(PANOS_HIERARCHY_GUIDE,),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        )
                    )

    def check_management_tls(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        cert_control = "paloalto.panos.management-certificate"
        if panos.panorama_inheritance_unknown:
            record_control(parser, "paloalto.panos.management-tls", ControlOutcome.UNKNOWN,
                           "Panorama management TLS inheritance is unresolved.")
            record_control(parser, cert_control, ControlOutcome.UNKNOWN,
                           "Panorama management TLS inheritance is unresolved.")
            return
        profiles = {
            (profile.scope, profile.name): profile
            for profile in panos.get_ssl_tls_service_profiles()
        }
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

        tls_settings = panos.get_management_tls()
        if not tls_settings:
            record_control(parser, "paloalto.panos.management-tls", ControlOutcome.UNKNOWN, "Management TLS scope is unexported.")
            record_control(parser, cert_control, ControlOutcome.UNKNOWN, "Management TLS scope is unexported.")
        for setting in tls_settings:
            presence = setting.device_scope + "/certificate"
            if setting.device_scope not in https_scopes:
                record_control(parser, "paloalto.panos.management-tls", ControlOutcome.UNKNOWN,
                               "No explicit active management HTTPS attachment is supplied; service completeness is unqualified.", instance=setting.device_scope)
                record_control(parser, cert_control, ControlOutcome.UNKNOWN,
                               "No explicit active management HTTPS attachment is supplied; service completeness is unqualified.", instance=presence)
                continue
            evidence = self._evidence(setting.evidence)
            if setting.tls_mode == "tlsv1.3_only":
                record_control(parser, "paloalto.panos.management-tls", ControlOutcome.NO_FINDING,
                               "Explicit TLS 1.3-only mode; certificate and runtime state are separate.", instance=setting.device_scope)
                self._record(parser, cert_control,
                             ControlOutcome.NO_FINDING if setting.certificate else ControlOutcome.FINDING,
                             "A management server certificate is selected." if setting.certificate else
                             "TLS 1.3-only management has no explicit server certificate.",
                             rule="paloalto.panos.management.certificate_missing", instance=presence)
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
                            basis=FindingBasis.REQUIRED_SETTING_MISSING,
                        )
                    )
                continue
            if not setting.profile:
                record_control(parser, "paloalto.panos.management-tls", ControlOutcome.FINDING,
                               "HTTPS management is enabled and no SSL/TLS service profile is configured.", instance=setting.device_scope)
                record_control(parser, cert_control, ControlOutcome.UNKNOWN,
                               "No SSL/TLS service profile is attached; the platform-default certificate is not in the export.",
                               instance=presence)
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.management.tls_profile_missing",
                        device=parser.device_type,
                        title="Management HTTPS SSL/TLS service profile is not configured",
                        observation=(f"HTTPS management is enabled in '{setting.device_scope}' without an attached SSL/TLS service profile. "
                                     "The setting is omitted from the configuration, not set to a weak value."),
                        impact="The management web service uses platform-default certificate and protocol settings rather than an approved policy.",
                        exploitability="A reachable attacker may target legacy protocol support or exploit administrators accepting an untrusted default certificate.",
                        recommendation="Attach an SSL/TLS service profile with a signed certificate and TLS 1.2 or later.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(PANOS_TLS_GUIDE,),
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )
                continue
            profile = profiles.get((setting.device_scope, setting.profile)) or profiles.get(
                ("shared", setting.profile)
            )
            if profile is None:
                record_control(parser, "paloalto.panos.management-tls", ControlOutcome.UNKNOWN,
                               "Referenced management TLS profile is unexported or unresolved.", instance=setting.device_scope)
                record_control(parser, cert_control, ControlOutcome.UNKNOWN,
                               "Referenced management TLS profile is unexported or unresolved.", instance=presence)
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
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )
                continue
            profile_evidence = evidence + self._evidence(profile.evidence)
            self._record(parser, cert_control, ControlOutcome.NO_FINDING if profile.certificate else ControlOutcome.FINDING,
                         "The attached SSL/TLS profile selects a server certificate." if profile.certificate else
                         "The attached SSL/TLS profile selects no server certificate.",
                         rule="paloalto.panos.management.certificate_missing", instance=presence)
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
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )
            if profile.minimum_version in {"tls1-0", "tls1-1", "tlsv1.0", "tlsv1.1"}:
                record_control(parser, "paloalto.panos.management-tls", ControlOutcome.FINDING,
                               "Explicit legacy TLS minimum on an applied profile.", instance=setting.device_scope)
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
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            elif profile.minimum_version in {"tls1-2", "tls1-3", "tlsv1.2", "tlsv1.3"}:
                record_control(parser, "paloalto.panos.management-tls", ControlOutcome.NO_FINDING,
                               "Applied profile has an explicit modern TLS minimum; certificate and runtime state are separate.", instance=setting.device_scope)
            elif not profile.minimum_version:
                record_control(parser, "paloalto.panos.management-tls", ControlOutcome.FINDING,
                               "Applied profile does not set a TLS minimum version.", instance=setting.device_scope)
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.management.tls_minimum_version",
                        device=parser.device_type,
                        title="Management TLS minimum version is not configured",
                        observation=(f"Applied SSL/TLS service profile '{profile.name}' in '{profile.scope}' does not set a minimum TLS version. "
                                     "The setting is omitted, so the platform default applies; that default was not assessed."),
                        impact="Depending on the release default, the management web service may accept TLS versions older than 1.2.",
                        exploitability="A management-path attacker may negotiate a legacy protocol version if the default allows it.",
                        recommendation="Set the profile's minimum version to TLSv1.2 or later.",
                        severity=Severity.MEDIUM,
                        evidence=self._evidence(profile.evidence),
                        references=(PANOS_TLS_GUIDE,),
                        basis=FindingBasis.MISSING_EXPLICIT_SETTING,
                    )
                )
            else:
                record_control(parser, "paloalto.panos.management-tls", ControlOutcome.UNKNOWN,
                               "TLS minimum is malformed or unsupported; no value is inferred.", instance=setting.device_scope)

        for binding in panos.get_management_certificate_bindings():
            evidence = self._evidence(binding.evidence)
            bound = f"{binding.device_scope}/certificate:{binding.certificate}"
            if binding.resolution == "unresolved":
                self._record(parser, cert_control, ControlOutcome.FINDING, "The certificate object is not in the export.",
                             rule="paloalto.panos.management.certificate_unresolved", instance=bound + "/resolution")
            elif binding.public_material_state == "malformed":
                self._record(parser, cert_control, ControlOutcome.FINDING, "The certificate material is malformed.",
                             rule="paloalto.panos.management.certificate_material_malformed", instance=bound + "/material")
            elif binding.assessment is None:
                record_control(parser, cert_control, ControlOutcome.UNKNOWN,
                               "Certificate public material is not exported or cannot be parsed.", instance=bound + "/material")
            if binding.assessment is not None:
                result = binding.assessment
                trusted_context = result.identity_state == "match" and result.validity_state == "valid-at-assessment-time"
                for aspect, state, bad, good, aspect_rule in (
                    ("validity", result.validity_state, {"expired", "not-yet-valid"}, {"valid-at-assessment-time"},
                     "paloalto.panos.management.certificate_validity"),
                    ("identity", result.identity_state, {"mismatch"}, {"match"},
                     "paloalto.panos.management.certificate_identity"),
                    ("algorithm", result.algorithm_state, {"weak"}, {"acceptable"},
                     "paloalto.panos.management.certificate_algorithm"),
                    ("trust", result.trust_state, {"verification-failed"} if trusted_context else set(), {"trusted"},
                     "paloalto.panos.management.certificate_trust"),
                ):
                    self._record(parser, cert_control,
                                 ControlOutcome.FINDING if state in bad else
                                 ControlOutcome.NO_FINDING if state in good else ControlOutcome.UNKNOWN,
                                 f"Certificate {aspect} state is '{state}'.", rule=aspect_rule, instance=bound + "/" + aspect)
            if binding.resolution == "unresolved":
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.management.certificate_unresolved",
                        device=parser.device_type,
                        title="Management certificate object is unresolved",
                        observation=f"Management HTTPS in '{binding.device_scope}' references certificate '{binding.certificate}' through {binding.source}, but no matching shared or device-scoped certificate object was parsed.",
                        impact="The supplied export does not establish which certificate material authenticates the management endpoint.",
                        exploitability="An incomplete or inherited object can conceal an unintended management identity.",
                        recommendation="Supply the complete effective configuration and ensure the attached certificate object exists in the applicable device or shared scope.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(PANOS_TLS_GUIDE,),
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )
            elif binding.public_material_state == "malformed":
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.management.certificate_material_malformed",
                        device=parser.device_type,
                        title="Management certificate material is malformed",
                        observation=f"Attached certificate object '{binding.certificate}' in '{binding.object_scope}' contains public material that is not a structurally encoded certificate value.",
                        impact="Malformed certificate material cannot establish the intended management endpoint identity.",
                        exploitability="Administrators may encounter failed validation or fall back to accepting an unintended identity.",
                        recommendation="Re-import the public certificate and verify the management SSL/TLS profile references the intended object.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(PANOS_TLS_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            if binding.assessment is None:
                continue
            assessment = binding.assessment
            metadata = assessment.metadata
            if assessment.validity_state in {"expired", "not-yet-valid"}:
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.management.certificate_validity",
                        device=parser.device_type,
                        title="Management certificate is outside its validity period",
                        observation=f"Attached certificate '{binding.certificate}' is {assessment.validity_state} at the explicit assessment time; its validity interval is {metadata.not_before} through {metadata.not_after}.",
                        impact="Administrators cannot validate an endpoint certificate outside its declared validity interval.",
                        exploitability="Certificate warnings can condition administrators to bypass identity validation or can interrupt managed access.",
                        recommendation="Renew or replace the attached management certificate and verify the complete chain before its activation boundary.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(PANOS_TLS_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            if assessment.identity_state == "mismatch":
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.management.certificate_identity",
                        device=parser.device_type,
                        title="Management certificate does not match the intended identity",
                        observation=f"Attached certificate '{binding.certificate}' does not contain the explicitly declared management identity for scope '{binding.device_scope}' in its subjectAltName values.",
                        impact="Clients validating the intended hostname or address will reject the management endpoint identity.",
                        exploitability="Identity-validation failures can encourage unsafe certificate-warning bypasses.",
                        recommendation="Issue and attach a certificate whose subjectAltName contains the declared management DNS name or IP address.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(PANOS_TLS_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            if assessment.algorithm_state == "weak":
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.management.certificate_algorithm",
                        device=parser.device_type,
                        title="Management certificate uses a legacy key or signature",
                        observation=f"Attached certificate '{binding.certificate}' uses {metadata.public_key_algorithm} {metadata.public_key_size or 'intrinsic'} and signature hash {metadata.signature_hash_algorithm}.",
                        impact="Legacy public-key sizes or certificate signatures provide inadequate cryptographic assurance.",
                        exploitability="An attacker may target known weaknesses in undersized keys or deprecated signature hashes.",
                        recommendation="Replace the certificate with an organization-approved key and SHA-2-or-stronger signature consistent with current platform support.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(PANOS_TLS_GUIDE, NIST_CRYPTO_TRANSITIONS),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            if (
                assessment.trust_state == "verification-failed"
                and assessment.identity_state == "match"
                and assessment.validity_state == "valid-at-assessment-time"
            ):
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.management.certificate_trust",
                        device=parser.device_type,
                        title="Management certificate chain does not validate to an approved anchor",
                        observation=f"Attached certificate '{binding.certificate}' matches the intended identity and time boundary but cannot be validated to the explicitly approved exported trust-anchor fingerprint(s).",
                        impact="The supplied certificate chain does not establish trust under the selected assessment policy.",
                        exploitability="Clients using the approved trust policy may reject the endpoint or administrators may bypass warnings.",
                        recommendation="Attach the correct issuing chain and approve only the intended root fingerprint after independent verification.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(PANOS_TLS_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )

    def check_updates_and_system_logging(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        if panos.panorama_inheritance_unknown:
            record_control(parser, "paloalto.panos.threat-updates", ControlOutcome.UNKNOWN, "Panorama threat-update inheritance is unresolved.")
            record_control(parser, "paloalto.panos.update-server-verification", ControlOutcome.UNKNOWN,
                           "Panorama system-setting inheritance is unresolved.")
            record_control(parser, "paloalto.panos.system-log-forwarding", ControlOutcome.UNKNOWN,
                           "Panorama log-setting inheritance is unresolved.")
            return
        threat_schedules = [
            schedule for schedule in panos.get_update_schedules()
            if schedule.content_type == "threats"
        ]
        control = "paloalto.panos.threat-updates"
        if not threat_schedules and panos.management_exported():
            record_control(parser, control, ControlOutcome.FINDING,
                           "No Applications and Threats update schedule is configured in the exported system configuration.")
            self.add_issue(Finding(
                rule_id="paloalto.panos.updates.threat_content",
                device=parser.device_type,
                title="Threat content updates are not scheduled",
                observation=("The exported system configuration has no Applications and Threats update schedule. "
                             "The setting is omitted, not misconfigured: no automatic download or installation is configured."),
                impact="Threat signatures and decoders remain stale unless an administrator installs updates manually.",
                exploitability="Attackers may use techniques covered by signatures that have not yet been installed.",
                recommendation="Configure a recurring Applications and Threats update schedule using download-and-install with an approved rollout threshold.",
                severity=Severity.HIGH,
                evidence=("deviceconfig system update-schedule threats: not configured",),
                references=(PANOS_UPDATE_GUIDE,),
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            ))
        elif not threat_schedules:
            record_control(parser, control, ControlOutcome.UNKNOWN,
                           "The device system configuration is not in the export, so the update schedule cannot be assessed.")
        for schedule in threat_schedules:
            instance = schedule.device_scope + "/threats"
            if schedule.knowledge.state != KnowledgeState.KNOWN:
                record_control(parser, control, ControlOutcome.UNKNOWN,
                               "Threat schedule recurrence/action is absent, malformed or unsupported.", instance=instance)
                continue
            if schedule.action == "download-and-install":
                record_control(parser, control, ControlOutcome.NO_FINDING,
                               "Explicit automatic threat-content installation; delivery and freshness unassessed.", instance=instance)
                continue
            record_control(parser, control, ControlOutcome.FINDING,
                           "Explicit manual/download-only threat schedule does not automatically install content.", instance=instance)
            self.add_issue(Finding(
                rule_id="paloalto.panos.updates.threat_content",
                device=parser.device_type,
                title="Threat content is not scheduled for automatic installation",
                observation=f"Scope '{schedule.device_scope}' explicitly selects {'manual (none)' if schedule.recurrence == 'none' else 'download-only'} for its threat-content schedule.",
                impact="Threat signatures and decoders can remain stale even when update packages are downloaded.",
                exploitability="Attackers may use techniques covered by signatures that have not yet been installed.",
                recommendation="Configure the existing recurring Applications and Threats schedule using download-and-install with an approved rollout threshold.",
                severity=Severity.HIGH,
                evidence=self._evidence(schedule.evidence),
                references=(PANOS_UPDATE_GUIDE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        verification = panos.get_update_server_verification()
        if not verification:
            self._record(parser, "paloalto.panos.update-server-verification",
                         ControlOutcome.UNKNOWN,
                         "server-verification is omitted; no cited vendor default exists, so only an explicit value is graded."
                         if panos.management_exported() else "Device system configuration is not exported.")
        for scope, value, evidence in verification:
            self._record(parser, "paloalto.panos.update-server-verification",
                         ControlOutcome.FINDING if value == "no" else
                         ControlOutcome.NO_FINDING if value == "yes" else ControlOutcome.UNKNOWN,
                         "Update server identity verification is disabled." if value == "no" else
                         "Update server identity verification is enabled." if value == "yes" else
                         "server-verification has an unsupported value.",
                         rule="paloalto.panos.update.server_unverified", instance=scope)
            if value != "no":
                continue
            self.add_issue(Finding(
                rule_id="paloalto.panos.update.server_unverified",
                device=parser.device_type,
                title="Update server identity verification is disabled",
                observation=f"Device scope '{scope}' sets server-verification to 'no' ('Verify Update Server Identity' unchecked).",
                impact="The firewall downloads software and content updates without verifying the update server's certificate.",
                exploitability="An attacker who can redirect DNS or intercept the update session can serve a modified update package.",
                recommendation="Enable 'Verify Update Server Identity' (set deviceconfig system server-verification yes); if an SSL forward proxy intercepts updates, exempt the update servers instead.",
                severity=Severity.HIGH,
                evidence=(evidence,),
                references=(PANOS_UPDATE_GUIDE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        system_destinations = panos.get_system_log_forwarding_destinations()
        self._record(parser, "paloalto.panos.system-log-forwarding",
                     ControlOutcome.FINDING if not system_destinations else ControlOutcome.NO_FINDING,
                     "No system log match entry forwards to a syslog server." if not system_destinations else
                     "System events are forwarded to a syslog server.", rule="paloalto.panos.logging.system_forwarding")
        if not system_destinations:
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
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
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

    def check_default_security_rules(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        defaults = panos.get_default_security_rules()
        control = "paloalto.panos.interzone-default-deny"
        if not defaults:
            if panos.panorama_inheritance_unknown:
                record_control(parser, control, ControlOutcome.UNKNOWN,
                               "The interzone-default rule may be inherited from Panorama.")
            elif not panos.get_security_rules():
                record_control(parser, control, ControlOutcome.UNKNOWN, "The security rulebase is not exported.")
            else:
                record_control(parser, control, ControlOutcome.UNKNOWN,
                               "No interzone-default override is exported; the implicit platform default is not synthesized (SC-007).")
        for rule in defaults:
            self._record(parser, control,
                         ControlOutcome.UNKNOWN if rule.resolution_state != "known" else
                         ControlOutcome.FINDING if rule.action == "allow" else ControlOutcome.NO_FINDING,
                         "The interzone-default override is inherited or malformed." if rule.resolution_state != "known" else
                         f"The interzone-default override action is '{rule.action}'.",
                         rule="paloalto.panos.policy.interzone_default_allow",
                         instance=f"{rule.device_scope}/{rule.scope}/interzone-default")
            if rule.resolution_state != "known" or rule.action != "allow":
                continue
            self.add_issue(Finding(
                rule_id="paloalto.panos.policy.interzone_default_allow",
                device=parser.device_type,
                title="Interzone default security rule permits unmatched traffic",
                observation=(
                    f"Explicit interzone-default override in '{rule.device_scope}/{rule.scope}' "
                    f"allows traffic that matches no earlier security rule."
                ),
                impact="Unmatched traffic between security zones is permitted instead of denied.",
                exploitability="A source able to reach a different zone can use paths not explicitly permitted by named rules.",
                recommendation="Set the interzone-default action to deny and create narrowly scoped allow rules for approved traffic.",
                severity=Severity.HIGH,
                evidence=self._evidence(rule.evidence),
                references=(PANOS_DEFAULT_RULE_GUIDE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def check_security_rules(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        rules = panos.get_security_rules()
        if not rules:
            record_control(parser, "paloalto.panos.policy-inspection", ControlOutcome.UNKNOWN,
                           "Security policy/inspection scope is unexported; completeness is unqualified.")
            record_control(parser, "paloalto.panos.policy-logging", ControlOutcome.UNKNOWN,
                           "Security policy is unexported; completeness is unqualified.")
            record_control(parser, "paloalto.panos.policy-scope", ControlOutcome.UNKNOWN,
                           "Security policy is unexported; completeness is unqualified.")
        elif not any(rule.enabled and rule.action == "allow" for rule in rules):
            record_control(parser, "paloalto.panos.policy-logging", ControlOutcome.NOT_APPLICABLE,
                           "No enabled allow rule is configured.")
        profiles = {
            (profile.scope, profile.name): profile
            for profile in panos.get_log_forwarding_profiles()
        }
        inspections = {
            (inspection.rule_scope, inspection.rule_position, inspection.rule_name): inspection
            for inspection in panos.get_security_inspection()
        }
        for rule in rules:
            evidence = self._evidence(rule.evidence)
            scope_instance = f"{rule.device_scope}/{rule.scope}/{rule.rulebase}/rule:{rule.name}"
            if not rule.enabled:
                disabled_broad = rule.action == "allow" and self._broad(rule)
                self._record(parser, "paloalto.panos.policy-scope",
                             ControlOutcome.FINDING if disabled_broad else ControlOutcome.NOT_APPLICABLE,
                             "Disabled unrestricted allow rule remains in the policy." if disabled_broad else
                             "Security rule is disabled.",
                             rule="paloalto.panos.policy.disabled_permissive_rule", instance=scope_instance)
                if rule.action == "allow" and self._broad(rule):
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.policy.disabled_permissive_rule",
                            device=parser.device_type,
                            title="Disabled permissive rule remains in the policy",
                            observation=f"Disabled rule '{rule.name}' at position {rule.position} in '{rule.scope}' is an unrestricted allow rule.",
                            impact="Stale permissive rules obscure policy intent and can create broad exposure if re-enabled without review.",
                            exploitability="The rule is not active in the supplied configuration; exploitation requires it to be enabled.",
                            recommendation="Remove the obsolete rule or document, narrow, and periodically review it before any reactivation.",
                            severity=Severity.LOW,
                            evidence=evidence,
                            references=(PANOS_POLICY_GUIDE,),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        )
                    )
                continue
            if rule.action != "allow":
                record_control(parser, "paloalto.panos.policy-scope", ControlOutcome.NOT_APPLICABLE,
                               "Security rule does not allow traffic.", instance=scope_instance)
                continue
            broad = self._broad(rule)
            broad_service = not broad and self._all_any(rule.applications) and self._all_any(rule.services)
            self._record(parser, "paloalto.panos.policy-scope",
                         ControlOutcome.FINDING if broad or broad_service else ControlOutcome.NO_FINDING,
                         "Allow rule is unrestricted." if broad else
                         "Allow rule permits every application and service." if broad_service else
                         "Allow rule restricts its match criteria.",
                         rule="paloalto.panos.policy.broad_allow" if broad else "paloalto.panos.policy.broad_service",
                         instance=scope_instance)
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
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            elif self._all_any(rule.applications) and self._all_any(rule.services):
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.policy.broad_service",
                        device=parser.device_type,
                        title="Allow rule permits every application and service",
                        observation=f"Enabled allow rule '{rule.name}' in '{rule.scope}' uses Any for both application and service.",
                        impact="The rule permits all identifiable applications on all ports within its remaining network and identity scope.",
                        exploitability="A reachable source can use unnecessary or unexpected protocols through the rule.",
                        recommendation="Constrain the rule to approved applications and use application-default or reviewed explicit services as appropriate.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(PANOS_POLICY_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
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
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
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
                        basis=FindingBasis.MISSING_EXPLICIT_SETTING,
                    )
                )

            logging_gaps = []
            if not forwarding or not forwarding.syslog_servers:
                logging_gaps.append("no effective syslog log-forwarding profile")
            if not rule.log_end:
                logging_gaps.append("log-at-session-end disabled")
            record_control(parser, "paloalto.panos.policy-logging",
                           ControlOutcome.FINDING if logging_gaps else ControlOutcome.NO_FINDING,
                           ("Allow rule has " + " and ".join(logging_gaps) + ".") if logging_gaps
                           else "Allow rule logs at session end and forwards to syslog.",
                           instance=f"{rule.device_scope}/{rule.scope}/{rule.rulebase}/rule:{rule.name}")

            control = "paloalto.panos.policy-inspection"
            instance = f"{rule.device_scope}/{rule.scope}/{rule.rulebase}/rule:{rule.name}"
            if not rule.profile_setting:
                record_control(parser, control, ControlOutcome.FINDING,
                               "Allow rule has no security profile or profile group configured.", instance=instance)
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.policy.security_profiles",
                        device=parser.device_type,
                        title="Allow rule has no security profiles configured",
                        observation=(f"Enabled allow rule '{rule.name}' in '{rule.scope}' has no profile group or individual security profiles. "
                                     "The rule omits the attachment; no inspection is configured for its traffic."),
                        impact="Permitted traffic may bypass threat, malware, URL, file, and data inspection controls.",
                        exploitability="An attacker can deliver malicious content through traffic permitted by the uninspected rule.",
                        recommendation="Attach the organization's approved Security Profile Group or explicit profiles to the allow rule.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(PANOS_POLICY_GUIDE,),
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )
                continue
            inspection = inspections.get((rule.scope, rule.position, rule.name))
            if inspection is None or inspection.resolution_state != "resolved":
                record_control(parser, control, ControlOutcome.UNKNOWN,
                               "Inspection group or membership is unexported, empty or inherited; absence is not a proven ineffective attachment.",
                               instance=instance)
                continue
            record_control(parser, control, ControlOutcome.UNKNOWN,
                           "Only exported explicit inspection actions are assessed; full threat coverage and runtime enforcement are unassessed.",
                           instance=instance + "/coverage")

            for profile in inspection.profiles:
                profile_evidence = evidence + self._evidence(profile.evidence) + (
                    f"{rule.scope}: {profile.profile_type} profile {profile.name}",
                )
                if profile.resolution_state != "resolved" or profile.content_state in {"empty", "unknown", "vendor-default"}:
                    record_control(parser, control, ControlOutcome.UNKNOWN,
                                   "Referenced profile or its inspection content is unexported/unsupported.",
                                   instance=instance + "/profile:" + profile.profile_type + ":" + profile.name)
                elif profile.content_state == "nonblocking":
                    record_control(parser, control, ControlOutcome.FINDING, "Explicit nonblocking attached inspection actions.", instance=instance)
                    reason = "contains only explicitly non-blocking actions: " + ", ".join(profile.actions)
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.policy.security_profile_ineffective",
                            device=parser.device_type,
                            title="Allow rule uses an ineffective security profile",
                            observation=f"Enabled allow rule '{rule.name}' in '{rule.scope}' uses {profile.profile_type} profile '{profile.name}', which {reason}.",
                            impact="The attached profile does not block the threats its name may imply.",
                            exploitability="Matching malicious content can be permitted or merely logged by the explicitly weak profile.",
                            recommendation=f"Configure '{profile.name}' with reviewed blocking or reset actions appropriate to the protected traffic.",
                            severity=Severity.HIGH,
                            evidence=profile_evidence,
                            references=(PANOS_SECURITY_PROFILES_GUIDE,),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        )
                    )
                elif profile.resolution_state == "resolved" and profile.content_state == "configured":
                    weak_severities: list[str] = []
                    selector_evidence: list[str] = []
                    # Signature rules are top-down. A broad earlier selector
                    # determines the class action; a later weak selector must
                    # not be mistaken for effective policy.
                    for target in ("critical", "high"):
                        first = next((
                            selector for selector in profile.threat_selectors
                            if selector.broad_match
                            and (not selector.severities or target in selector.severities
                                 or "any" in selector.severities)
                        ), None)
                        if first is not None and first.severities and first.action in {"allow", "alert"}:
                            weak_severities.append(target)
                            selector_evidence.extend(self._evidence(first.evidence))
                    if weak_severities:
                        record_control(parser, control, ControlOutcome.FINDING, "Explicit selected high-severity nonblocking actions.", instance=instance)
                        self.add_issue(Finding(
                            rule_id="paloalto.panos.policy.threat_selector_nonblocking",
                            device=parser.device_type,
                            title="Attached PAN-OS threat profile does not block selected high-severity threats",
                            observation=(
                                f"Enabled allow rule '{rule.name}' in '{rule.scope}' uses "
                                f"{profile.profile_type} profile '{profile.name}' whose first broad "
                                f"selector for {', '.join(weak_severities)} severity is explicitly "
                                "allow or alert. Other blocking selectors in the profile do not "
                                "protect these selected classes."
                            ),
                            impact="Matching critical or high-severity threats may be permitted instead of blocked.",
                            exploitability="A matching threat can traverse this allowed traffic path without a blocking profile response.",
                            recommendation="Review the selector order and set an approved blocking action for the affected severities.",
                            severity=Severity.HIGH,
                            evidence=profile_evidence + tuple(dict.fromkeys(selector_evidence)),
                            references=(PANOS_SECURITY_PROFILES_GUIDE,),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        ))

    @staticmethod
    def _static_effectiveness_comparable(rule: PanosSecurityRule) -> bool:
        """Limit proof to rules without dynamic or time-dependent predicates."""
        return PaloAltoPANOSParser.is_static_security_rule(rule)

    def _rule_covers(
        self,
        panos: PaloAltoPANOSParser,
        prior: PanosSecurityRule,
        current: PanosSecurityRule,
    ) -> bool:
        if not self._static_effectiveness_comparable(prior) or not self._static_effectiveness_comparable(current):
            return False
        return all(
            state == ProofState.PROVEN
            for state in (
                static_values_cover(prior.from_zones, current.from_zones),
                static_values_cover(prior.to_zones, current.to_zones),
                network_covers(
                    panos.resolve_network_semantics(prior.sources, device_scope=prior.device_scope, scope=prior.scope),
                    panos.resolve_network_semantics(current.sources, device_scope=current.device_scope, scope=current.scope),
                ),
                network_covers(
                    panos.resolve_network_semantics(prior.destinations, device_scope=prior.device_scope, scope=prior.scope),
                    panos.resolve_network_semantics(current.destinations, device_scope=current.device_scope, scope=current.scope),
                ),
                service_covers(
                    panos.resolve_service_semantics(prior.services, device_scope=prior.device_scope, scope=prior.scope),
                    panos.resolve_service_semantics(current.services, device_scope=current.device_scope, scope=current.scope),
                ),
            )
        )

    def check_rule_effectiveness(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        pattern = "protective-deny-defeated"
        mark_evaluated(parser, pattern)
        control = "paloalto.panos.policy-order"
        if panos.panorama_inheritance_unknown:
            record_control(parser, control, ControlOutcome.UNKNOWN, "Unresolved Panorama inheritance.")
            record_path_not_assessed(
                parser, pattern,
                "Panorama inheritance is unresolved; first-match rule proof was withheld.",
            )
            return
        previous_by_scope: dict[tuple[str, str, str], list[PanosSecurityRule]] = {}
        rules = panos.get_security_rules()
        if not rules:
            record_control(parser, control, ControlOutcome.UNKNOWN, "Security-rule scope not supplied or its completeness is unqualified.")
        for rule in rules:
            scope = (rule.device_scope, rule.scope, rule.rulebase)
            previous = previous_by_scope.setdefault(scope, [])
            instance = f"{rule.device_scope}/{rule.scope}/{rule.rulebase}/rule:{rule.name}"
            if not rule.enabled:
                record_control(parser, control, ControlOutcome.NOT_APPLICABLE, "Security rule is explicitly disabled.", instance=instance)
                continue
            if rule.action not in self._TERMINAL_ACTIONS:
                record_control(parser, control, ControlOutcome.UNKNOWN, "Security rule action is unsupported or malformed.", instance=instance)
                record_path_not_assessed(parser, pattern, f"{instance}: terminal action is unqualified.")
                previous.append(rule)
                continue
            static_known = (self._static_effectiveness_comparable(rule) and all((
                panos.resolve_network_semantics(rule.sources, device_scope=rule.device_scope, scope=rule.scope).complete,
                panos.resolve_network_semantics(rule.destinations, device_scope=rule.device_scope, scope=rule.scope).complete,
                panos.resolve_service_semantics(rule.services, device_scope=rule.device_scope, scope=rule.scope).complete)))
            all_prior_known = len(previous) <= 64 and all(self._static_effectiveness_comparable(p) and all((
                panos.resolve_network_semantics(p.sources, device_scope=p.device_scope, scope=p.scope).complete,
                panos.resolve_network_semantics(p.destinations, device_scope=p.device_scope, scope=p.scope).complete,
                panos.resolve_service_semantics(p.services, device_scope=p.device_scope, scope=p.scope).complete)) for p in previous)
            nat = panos.qualify_nat_comparison(rule, rule)
            qualified = static_known and all_prior_known and nat.state == ProofState.PROVEN
            record_control(parser, control, ControlOutcome.NO_FINDING if qualified else ControlOutcome.UNKNOWN,
                           "Bounded static comparisons and NAT relevance qualified." if qualified else
                           nat.reason if nat.state != ProofState.PROVEN else "Current/earlier rule selectors or comparison budget are unqualified.", instance=instance)
            if not self._static_effectiveness_comparable(rule):
                record_control(parser, control, ControlOutcome.UNKNOWN, "Rule has unsupported application/user/category/schedule or negated predicates.", instance=instance)
                record_path_not_assessed(parser, pattern, f"{instance}: rule predicates are unqualified.")
            for earlier in previous:
                if not self._rule_covers(panos, earlier, rule):
                    continue
                nat = panos.qualify_nat_comparison(earlier, rule)
                if nat.state != ProofState.PROVEN:
                    record_control(parser, control, ControlOutcome.UNKNOWN, nat.reason, instance=instance)
                    record_path_not_assessed(parser, pattern, f"{instance}: {nat.reason}")
                    continue
                same_action = earlier.action == rule.action
                finding = Finding(
                        rule_id="paloalto.panos.policy.redundant_rule" if same_action else "paloalto.panos.policy.shadowed_rule",
                        device=parser.device_type,
                        title="Rule is redundant" if same_action else "Rule is shadowed",
                        observation=f"Rule '{rule.name}' at position {rule.position} in '{rule.scope}/{rule.rulebase}' is fully covered by earlier rule '{earlier.name}' at position {earlier.position} with {'the same' if same_action else 'a different'} terminal action.",
                        impact="The later rule cannot alter enforcement for the statically proven traffic scope and obscures policy intent.",
                        exploitability="A conflicting shadowed rule can give reviewers a false impression of enforced access control; an equivalent rule adds operational ambiguity.",
                        recommendation="Remove or reorder the rule after validating the committed policy and any externally managed dynamic state.",
                        severity=Severity.LOW if same_action else Severity.HIGH,
                        evidence=self._evidence(rule.evidence) + self._evidence(earlier.evidence),
                        references=(PANOS_POLICY_GUIDE,),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                self.add_issue(finding)
                record_control(parser, control, ControlOutcome.FINDING, "Static same-scope containment with qualified NAT relevance.", instance=instance)
                if earlier.action == "allow" and rule.action != "allow":
                    where = f"{rule.device_scope}/{rule.scope}/{rule.rulebase}"
                    permission = panos.get_effective_security_permission(earlier, tuple(previous), rule)
                    if permission.state == ProofState.UNKNOWN:
                        record_control(parser, control, ControlOutcome.UNKNOWN, permission.reason, instance=instance + "/effective-permission")
                    record_deny_defeated(
                        parser, scope=where, family="any", instance_key=f"{where}/rule:{rule.name}",
                        allow_entity=f"{where}/rule:{earlier.name}",
                        allow_text=(f"Earlier enabled allow rule '{earlier.name}' at position {earlier.position} statically "
                                    "covers the rule's zones, sources, destinations and services, with any application, user and category."),
                        allow_evidence=earlier.evidence + tuple(ev for p in previous if p.position < earlier.position for ev in p.evidence),
                        deny_text=(f"Enabled {rule.action} rule '{rule.name}' at position {rule.position} in "
                                   f"'{rule.scope}/{rule.rulebase}' is never reached under first-match evaluation."),
                        deny_evidence=rule.evidence, finding=finding, permission=permission,
                    )
                break
            previous.append(rule)

    def check_password_policy(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        policy = panos.get_password_policy()
        control = "paloalto.panos.password-complexity"
        if panos.panorama_inheritance_unknown:
            record_control(parser, control, ControlOutcome.UNKNOWN, "Unresolved Panorama management-policy inheritance.", instance="management")
            return
        if policy.knowledge.state != KnowledgeState.KNOWN:
            record_control(parser, control, ControlOutcome.UNKNOWN, policy.knowledge.reason, instance="management:incomplete-fields")
        weaknesses = []
        omitted = policy.omission is not None
        if policy.omission == "section":
            weaknesses.append("password complexity is not configured (the section is omitted, so complexity is not enforced)")
        elif policy.omission == "enabled":
            weaknesses.append("password complexity is not enabled (the 'enabled' setting is omitted)")
        if policy.enabled is False:
            weaknesses.append("complexity is explicitly disabled")
        # NEEDS_HUMAN_REVIEW: 12 is the project baseline; PAN-OS documents a
        # product minimum of eight but organizations may require a higher value.
        if policy.minimum_length is not None and 0 <= policy.minimum_length < 12:
            weaknesses.append("minimum length is explicitly below 12")
        for label, value in (
            ("uppercase", policy.minimum_uppercase),
            ("lowercase", policy.minimum_lowercase),
            ("numeric", policy.minimum_numeric),
            ("special", policy.minimum_special),
        ):
            if value == 0:
                weaknesses.append(f"{label} character minimum is explicitly below 1")
        if not weaknesses:
            if policy.knowledge.state == KnowledgeState.KNOWN:
                record_control(parser, control, ControlOutcome.NO_FINDING, "Every explicit password-complexity field meets the existing baseline.", instance="management")
            return
        explicit = len(weaknesses) > (1 if omitted else 0)
        record_control(parser, control, ControlOutcome.FINDING,
                       "Weak or unconfigured password-complexity setting.", instance="management")
        self.add_issue(
            Finding(
                rule_id="paloalto.panos.credentials.password_complexity",
                device=parser.device_type,
                title="Management password complexity is insufficient",
                observation="The local administrator password policy is weak or not configured: " + "; ".join(weaknesses) + ".",
                impact="Weak local administrator passwords are more susceptible to guessing and credential attacks.",
                exploitability="An attacker with management reachability can target accounts protected by the weak local policy.",
                recommendation="Enable password complexity and require at least 12 characters with uppercase, lowercase, numeric, and special-character minima, or apply the approved organizational benchmark.",
                severity=Severity.HIGH,
                evidence=self._evidence(policy.evidence) or ("mgt-config password-complexity: not configured",),
                references=(PANOS_PASSWORD_GUIDE,),
                basis=FindingBasis.EXPLICIT_VALUE if explicit else FindingBasis.REQUIRED_SETTING_MISSING,
            )
        )

    def check_password_reuse_and_username(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        control = "paloalto.panos.password-reuse"
        if panos.panorama_inheritance_unknown:
            record_control(parser, control, ControlOutcome.UNKNOWN, "Unresolved Panorama management-policy inheritance.")
            return
        policy = panos.get_password_policy()
        if policy.enabled is not True:
            known_off = policy.enabled is False or policy.omission is not None
            record_control(parser, control, ControlOutcome.NOT_APPLICABLE if known_off else ControlOutcome.UNKNOWN,
                           "Password complexity is not enabled (see password-complexity)." if known_off else
                           "The password-complexity section is not exported or its enabled flag is malformed.")
            return
        for label, fired, state, rule in (
            ("history", policy.history_count == 0, policy.history_state, "paloalto.panos.credentials.password_history_disabled"),
            ("username", policy.blocks_username is False, policy.blocks_username_state,
             "paloalto.panos.credentials.username_inclusion_allowed"),
        ):
            self._record(parser, control,
                         ControlOutcome.FINDING if fired else
                         ControlOutcome.NO_FINDING if state == "explicit" else ControlOutcome.UNKNOWN,
                         f"The explicit {label} setting is insecure." if fired else
                         f"The explicit {label} setting is secure." if state == "explicit" else
                         f"The {label} setting is malformed." if state == "invalid" else
                         f"The {label} setting is omitted and its release default is not verified; only explicit values are graded.",
                         rule=rule, instance="management/" + label)
        evidence = self._evidence(policy.evidence)
        if policy.history_count == 0:
            self.add_issue(
                Finding(
                    rule_id="paloalto.panos.credentials.password_history_disabled",
                    device=parser.device_type,
                    title="Management password reuse prevention is disabled",
                    observation="The explicit local password history count is 0, so previous administrator passwords are not retained for reuse prevention.",
                    impact="Administrators can immediately recycle a previously exposed or guessed password.",
                    exploitability="An attacker may regain access when a known password is reused after a nominal password change.",
                    recommendation="Set a nonzero password history count that meets the approved organizational password policy.",
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                    references=(PANOS_PASSWORD_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )
        if policy.blocks_username is False:
            self.add_issue(
                Finding(
                    rule_id="paloalto.panos.credentials.username_inclusion_allowed",
                    device=parser.device_type,
                    title="Administrator passwords may contain the username",
                    observation="The explicit local password policy disables username-inclusion blocking.",
                    impact="Passwords derived from account names are easier to predict and target with focused guessing.",
                    exploitability="An attacker who knows an administrator username can prioritize closely related password candidates.",
                    recommendation="Enable Block Username Inclusion for the local administrator password policy.",
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                    references=(PANOS_PASSWORD_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
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

    def check_zone_protection(self, parser: BaseDeviceParser) -> None:
        """Only explicit external-interface SYN flood disablement is graded."""
        panos = self._panos(parser)
        control = "paloalto.panos.zone-protection"
        if panos.panorama_inheritance_unknown or panos.template_unresolved:
            record_control(parser, control, ControlOutcome.UNKNOWN,
                           "Zone configuration may be inherited from Panorama or comes from an unrendered template.")
            return
        zones = panos.get_zone_protections()
        if not zones:
            record_control(parser, control, ControlOutcome.UNKNOWN, "No security zone is exported.")
        for zone in zones:
            external = tuple(
                interface for interface in zone.interfaces
                if panos.assessment_context.role_for_interface(interface) == "external"
            )
            zone_instance = f"{zone.device_scope}/{zone.vsys}/zone:{zone.zone}"
            if not external:
                roles_known = all(panos.assessment_context.role_for_interface(interface) != "unknown"
                                  for interface in zone.interfaces)
                record_control(parser, control, ControlOutcome.NOT_APPLICABLE if roles_known else ControlOutcome.UNKNOWN,
                               "The zone has no interface classified external." if roles_known else
                               "Interface roles are not declared, so whether the zone is external is unknown.",
                               instance=zone_instance)
            elif zone.resolution_state != "resolved":
                record_control(parser, control,
                               ControlOutcome.NOT_APPLICABLE if zone.resolution_state == "unbound" else ControlOutcome.UNKNOWN,
                               "No zone-protection profile is attached to the external zone." if zone.resolution_state == "unbound"
                               else "The attached zone-protection profile is not in the export.", instance=zone_instance)
            else:
                record_control(parser, control, ControlOutcome.FINDING if zone.allowed_scans else ControlOutcome.NO_FINDING,
                               "The attached profile allows reconnaissance scans." if zone.allowed_scans else
                               "The attached profile does not allow reconnaissance scans.", instance=zone_instance + "/scan")
                flood_disabled = zone.syn_flood_state == "disabled" or bool(zone.disabled_other_floods)
                record_control(parser, control,
                               ControlOutcome.UNKNOWN if zone.dos_alternative_possible else
                               ControlOutcome.FINDING if flood_disabled else
                               ControlOutcome.NO_FINDING if zone.syn_flood_state == "enabled" else ControlOutcome.UNKNOWN,
                               "A DoS protect rule may provide flood protection; profile flood settings are not graded."
                               if zone.dos_alternative_possible else
                               "The attached profile explicitly disables flood protection." if flood_disabled else
                               "SYN flood protection is explicitly enabled and no other flood type is explicitly disabled."
                               if zone.syn_flood_state == "enabled" else
                               "SYN flood protection is omitted or malformed; its release default is not verified.",
                               instance=zone_instance + "/flood")
            if not external or zone.resolution_state != "resolved":
                continue
            if zone.allowed_scans:
                self.add_issue(Finding(
                    rule_id="paloalto.panos.zone.scan_allow",
                    device=parser.device_type,
                    title="Attached PAN-OS zone profile explicitly allows reconnaissance scans",
                    observation=(
                        f"Zone '{zone.zone}' in '{zone.device_scope}/{zone.vsys}' contains assessed "
                        f"external interface(s) {', '.join(external)} and uses profile '{zone.profile}' "
                        f"whose scan entries {', '.join(zone.allowed_scans)} explicitly set action allow."
                    ),
                    impact="Matching reconnaissance scans are permitted by the attached zone profile.",
                    exploitability="A scanner reaching the assessed ingress zone may continue matching probes.",
                    recommendation=(
                        "Review these scan exceptions and use an approved alert or blocking action "
                        "for the exposed zone."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=self._evidence(zone.evidence),
                    references=(PANOS_RECONNAISSANCE_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            if zone.dos_alternative_possible:
                continue
            if zone.syn_flood_state == "disabled":
                self.add_issue(Finding(
                    rule_id="paloalto.panos.zone.syn_flood_disabled",
                    device=parser.device_type,
                    title="Attached PAN-OS zone profile explicitly disables SYN flood protection",
                    observation=(
                        f"Zone '{zone.zone}' in '{zone.device_scope}/{zone.vsys}' contains assessed "
                        f"external interface(s) {', '.join(external)} and uses profile '{zone.profile}' "
                        "with flood tcp-syn enable no. No configured DoS protect rule was found in "
                        "this local vsys export."
                    ),
                    impact="SYN floods entering this zone are not mitigated by the attached zone profile.",
                    exploitability="An attacker reaching the assessed ingress zone may send a SYN flood.",
                    recommendation=(
                        "Enable a reviewed SYN flood action and thresholds on the attached zone "
                        "profile, or verify an applicable DoS or upstream protection path."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=self._evidence(zone.evidence),
                    references=(PANOS_ZONE_PROTECTION_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            if zone.disabled_other_floods:
                self.add_issue(Finding(
                    rule_id="paloalto.panos.zone.other_flood_disabled",
                    device=parser.device_type,
                    title="Attached PAN-OS zone profile explicitly disables flood protection",
                    observation=(
                        f"Zone '{zone.zone}' in '{zone.device_scope}/{zone.vsys}' contains assessed "
                        f"external interface(s) {', '.join(external)} and uses profile '{zone.profile}' "
                        f"with flood protection explicitly disabled for "
                        f"{', '.join(zone.disabled_other_floods).upper()}. No configured DoS protect "
                        "rule was found in this local vsys export."
                    ),
                    impact="The named floods are not mitigated by this attached zone profile.",
                    exploitability="An attacker reaching the assessed ingress zone may send these floods.",
                    recommendation=(
                        "Enable the relevant flood protections with reviewed thresholds, or verify "
                        "an applicable DoS or upstream protection path."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=self._evidence(zone.evidence),
                    references=(PANOS_ZONE_PROTECTION_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))

    def check_cis_follow_ups(self, parser: BaseDeviceParser) -> None:
        """SC-061: CIS PAN-OS follow-ups (User-ID on external zones, hygiene)."""
        panos = self._panos(parser)
        context = panos.assessment_context
        user_id_zones = panos.get_user_id_zones()
        uid_control = "paloalto.panos.user-id-zones"
        if not user_id_zones:
            if panos.panorama_inheritance_unknown:
                record_control(parser, uid_control, ControlOutcome.UNKNOWN, "Zones may be inherited from Panorama.")
            elif not panos.get_zone_protections():
                record_control(parser, uid_control, ControlOutcome.UNKNOWN, "No security zone is exported.")
            else:
                record_control(parser, uid_control, ControlOutcome.NOT_APPLICABLE, "No exported zone enables User-ID.")
        for vsys, zone, interfaces, evidence in user_id_zones:
            external = [i for i in interfaces if context.role_for_interface(i) == "external"
                        or context.role_for_interface(i.split(".")[0]) == "external"]
            roles_known = all(context.role_for_interface(i) != "unknown"
                              or context.role_for_interface(i.split(".")[0]) != "unknown" for i in interfaces)
            self._record(parser, uid_control,
                         ControlOutcome.FINDING if external else
                         ControlOutcome.NO_FINDING if roles_known else ControlOutcome.UNKNOWN,
                         "User-ID is enabled on a zone with an external interface." if external else
                         "User-ID is enabled only on zones without external interfaces." if roles_known else
                         "Interface roles are not declared, so whether the User-ID zone is external is unknown.",
                         rule="paloalto.panos.user_id.untrusted_zone", instance=f"{vsys}/zone:{zone}")
            if not external:
                continue
            self.add_issue(Finding(
                rule_id="paloalto.panos.user_id.untrusted_zone",
                device=parser.device_type,
                title="User-ID is enabled on an untrusted zone",
                observation=f"Zone '{zone}' ({vsys}) enables User-ID and contains interface(s) classified external: {', '.join(external)}.",
                impact="User-ID probing and mapping on untrusted networks can leak service-account credentials or accept spoofed user mappings.",
                exploitability="Requires presence on the untrusted network attached to the zone.",
                recommendation="Disable User-ID on untrusted zones and use include/exclude networks to limit mapping to internal ranges (CIS PAN-OS 2.3, 2.4).",
                severity=Severity.MEDIUM,
                evidence=(evidence,),
                references=(PANOS_UPDATE_GUIDE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        facts = panos.get_cis_hygiene_facts()
        schedules = {s.content_type for s in panos.get_update_schedules() if s.action == "download-and-install"}
        items = [
            ("1.1.1.2", "SNMPv3 trap profile", not facts["snmp_v3_trap"]),
            ("1.1.3", "log on high dataplane load", not facts["high_dp_load"]),
            ("1.3.10", "administrator password profile", not facts["password_profile"]),
            ("3.2", "HA link/path monitoring", facts["ha_enabled"] and not facts["ha_monitoring"]),
            ("4.1", "antivirus update schedule (download-and-install)", "anti-virus" not in schedules),
            ("5.6", "WildFire update schedule (download-and-install)", "wildfire" not in schedules),
        ]
        missing = [f"CIS {ref}: {label}" for ref, label, gap in items if gap]
        if missing and not getattr(panos, "panorama_inheritance_unknown", False):
            self.add_issue(Finding(
                rule_id="paloalto.panos.hardening.cis_hygiene",
                device=parser.device_type,
                title="CIS hardening items not configured",
                observation=f"{len(missing)} lower-priority CIS hardening item(s) are not configured: " + "; ".join(missing) + ".",
                impact="Each item is minor on its own; together they affect monitoring, update freshness and resilience.",
                exploitability="Not directly exploitable; these settings reduce the impact of other weaknesses.",
                recommendation="Review the listed items against the organization's baseline and configure those that apply.",
                severity=Severity.INFORMATIONAL,
                evidence=(f"{len(missing)} CIS hygiene item(s) absent; see observation",),
                references=(PANOS_UPDATE_GUIDE,),
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            ))

    def check_dns_sinkhole(self, parser: BaseDeviceParser) -> None:
        """CIS Palo Alto 6.4: anti-spyware profiles in use should sinkhole malicious DNS queries."""
        panos = self._panos(parser)
        reported: set[tuple[str, str]] = set()
        control = "paloalto.panos.dns-sinkhole"
        inspections = panos.get_security_inspection()
        for inspection in inspections:
            if inspection.resolution_state in {"unresolved", "unknown-inherited"}:
                record_control(parser, control, ControlOutcome.UNKNOWN,
                               "The rule's profile group is not exported, so its anti-spyware profile is unknown.",
                               instance=f"{inspection.rule_scope}/rule:{inspection.rule_name}")
            for profile in inspection.profiles:
                if profile.profile_type != "spyware":
                    continue
                self._record(parser, control,
                             ControlOutcome.UNKNOWN if profile.resolution_state != "resolved" else
                             ControlOutcome.FINDING if profile.dns_sinkhole in {"absent", "not-sinkhole"} else
                             ControlOutcome.NO_FINDING if profile.dns_sinkhole == "sinkhole" else ControlOutcome.UNKNOWN,
                             "The anti-spyware profile is built-in, unresolved or inherited." if profile.resolution_state != "resolved" else
                             "DNS signature lists do not sinkhole or have no action configured."
                             if profile.dns_sinkhole in {"absent", "not-sinkhole"} else
                             "Every DNS signature list sinkholes." if profile.dns_sinkhole == "sinkhole" else
                             "DNS signature lists use the vendor default or a malformed action.",
                             rule="paloalto.panos.profile.dns_sinkhole",
                             instance=f"{profile.definition_scope or 'unresolved'}/spyware:{profile.name}")
        if not any(profile.profile_type == "spyware" for inspection in inspections for profile in inspection.profiles) \
                and not any(inspection.resolution_state in {"unresolved", "unknown-inherited"} for inspection in inspections):
            record_control(parser, control,
                           ControlOutcome.NOT_APPLICABLE if panos.get_security_rules() else ControlOutcome.UNKNOWN,
                           "No enabled allow rule uses an anti-spyware profile." if panos.get_security_rules() else
                           "Security policy is unexported; completeness is unqualified.")
        for inspection in inspections:
            for profile in inspection.profiles:
                key = (profile.definition_scope, profile.name)
                if (profile.profile_type != "spyware" or profile.resolution_state != "resolved"
                        or profile.dns_sinkhole not in {"absent", "not-sinkhole"} or key in reported):
                    continue
                reported.add(key)
                explicit = profile.dns_sinkhole == "not-sinkhole"
                self.add_issue(Finding(
                    rule_id="paloalto.panos.profile.dns_sinkhole",
                    device=parser.device_type,
                    title="Anti-spyware profile does not sinkhole malicious DNS queries",
                    observation=(f"Anti-spyware profile '{profile.name}' in '{profile.definition_scope}' is used by allow rule "
                                 f"'{inspection.rule_name}' and "
                                 + ("sets an action other than sinkhole for its DNS signature list."
                                    if explicit else
                                    "has no DNS signature list action configured (setting omitted; the default action was not assessed).")),
                    impact="Infected hosts that resolve command-and-control domains are not redirected to a sinkhole, so they are harder to identify.",
                    exploitability="Malware on an internal host can keep resolving its command-and-control infrastructure.",
                    recommendation="Set the DNS signature list (for example default-paloalto-dns) action to sinkhole and configure a sinkhole address.",
                    severity=Severity.MEDIUM,
                    evidence=self._evidence(profile.evidence),
                    references=(PANOS_DNS_SINKHOLE_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE if explicit else FindingBasis.MISSING_EXPLICIT_SETTING,
                ))

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_management(parser)
        self.check_zone_protection(parser)
        self.check_default_security_rules(parser)
        self.check_security_rules(parser)
        self.check_rule_effectiveness(parser)
        self.check_password_policy(parser)
        self.check_password_reuse_and_username(parser)
        self.check_administration(parser)
        self.check_administrative_policy(parser)
        self.check_platform_services(parser)
        self.check_management_tls(parser)
        self.check_updates_and_system_logging(parser)
        self.check_cis_follow_ups(parser)
        self.check_dns_sinkhole(parser)
        self.check_panorama_scope(parser)
