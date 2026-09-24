"""Attachment- and scope-aware PAN-OS management and policy checks."""

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.policy_semantics import (
    ProofState,
    network_covers,
    service_covers,
    static_values_cover,
)
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
                        evidence for user in users for evidence in user.evidence
                    ),
                    references=(PANOS_ADMIN_GUIDE,),
                )
            )

    def check_administrative_policy(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        for account in panos.get_administrator_policies():
            evidence = self._evidence(account.evidence)
            if account.role_resolution in {"missing", "unresolved"}:
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.admin.role_assignment",
                        device=parser.device_type,
                        title="Administrator role is missing or unresolved",
                        observation=(
                            f"Administrator '{account.username}' has no resolved role assignment."
                            if account.role_resolution == "missing"
                            else f"Administrator '{account.username}' references custom role '{account.role or 'unnamed'}', but that role is not defined in the supplied configuration."
                        ),
                        impact="The export does not establish the privileges granted to the administrative identity.",
                        exploitability="An incorrectly resolved role can grant unintended management capabilities or prevent intended separation of duties.",
                        recommendation="Assign a defined dynamic or custom Admin Role profile that matches the administrator's approved duties.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(PANOS_ADMIN_ROLE_GUIDE,),
                    )
                )
            if account.authentication_resolution in {"unresolved", "ambiguous"}:
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.admin.authentication_profile_unresolved",
                        device=parser.device_type,
                        title="Administrator authentication profile is unresolved",
                        observation=f"Administrator '{account.username}' references authentication profile '{account.authentication_profile}', but the profile cannot be resolved uniquely in the supplied configuration.",
                        impact="The static export cannot establish the authentication method protecting this administrator.",
                        exploitability="A missing or incorrectly scoped profile can cause unexpected authentication behavior or reliance on an unintended method.",
                        recommendation="Define the referenced authentication profile in the correct scope or provide the merged effective Panorama configuration.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(PANOS_ADMIN_GUIDE,),
                    )
                )

        if not panos.panorama_inheritance_unknown:
            for settings in panos.get_administrative_settings():
                evidence = self._evidence(settings.evidence)
                if settings.authentication_resolution in {"unresolved", "ambiguous"}:
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.admin.authentication_profile_unresolved",
                            device=parser.device_type,
                            title="Global administrator authentication profile is unresolved",
                            observation=f"Device scope '{settings.device_scope}' references global authentication profile or sequence '{settings.authentication_profile}', but it cannot be resolved uniquely in the supplied configuration.",
                            impact="The static export cannot establish authentication for externally defined administrators.",
                            exploitability="A missing or incorrectly scoped global profile can cause unexpected authentication behavior or prevent the intended external control from applying.",
                            recommendation="Define the referenced profile or sequence in the correct scope, or provide the merged effective Panorama configuration.",
                            severity=Severity.HIGH,
                            evidence=evidence,
                            references=(PANOS_ADMIN_GUIDE,),
                        )
                    )
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
                        )
                    )

        weak_ciphers = {"aes128-cbc", "aes192-cbc", "aes256-cbc"}
        weak_kex = {"diffie-hellman-group14-sha1"}
        weak_macs = {"hmac-sha1"}
        for policy in panos.get_ssh_management_policies():
            if not policy.enabled or not policy.supported:
                continue
            evidence = self._evidence(policy.evidence)
            if policy.resolution_state == "missing":
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.admin.ssh_profile_missing",
                        device=parser.device_type,
                        title="Management SSH service profile is not applied",
                        observation=f"SSH management is enabled in device scope '{policy.device_scope}' without an applied management SSH service profile.",
                        impact="The management SSH server can advertise the full default algorithm set instead of an explicitly restricted policy.",
                        exploitability="A reachable SSH client can negotiate any algorithm that remains available in the default server set.",
                        recommendation="Create, apply, and activate a management SSH service profile containing only approved algorithms.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(PANOS_SSH_PROFILE_GUIDE,),
                    )
                )
                continue
            if policy.resolution_state == "unresolved":
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.admin.ssh_profile_unresolved",
                        device=parser.device_type,
                        title="Management SSH service profile is unresolved",
                        observation=f"SSH management in device scope '{policy.device_scope}' references profile '{policy.selected_profile}', but its definition is absent.",
                        impact="The exported configuration does not establish the algorithms offered by the management SSH server.",
                        exploitability="A broken or incorrectly scoped reference can leave the intended SSH hardening unapplied.",
                        recommendation="Define and apply the referenced management SSH service profile in the correct device or template scope.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(PANOS_SSH_PROFILE_GUIDE,),
                    )
                )
                continue
            if policy.resolution_state != "known":
                continue
            weaknesses = []
            if not policy.ciphers:
                weaknesses.append("cipher list is not restricted")
            elif weak := sorted(set(policy.ciphers).intersection(weak_ciphers)):
                weaknesses.append("CBC ciphers: " + ", ".join(weak))
            if not policy.key_exchanges:
                weaknesses.append("key-exchange list is not restricted")
            elif weak := sorted(set(policy.key_exchanges).intersection(weak_kex)):
                weaknesses.append("legacy key exchange: " + ", ".join(weak))
            if not policy.macs:
                weaknesses.append("MAC list is not restricted")
            elif weak := sorted(set(policy.macs).intersection(weak_macs)):
                weaknesses.append("legacy MAC: " + ", ".join(weak))
            if weaknesses:
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
                    )
                )

    def check_platform_services(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        if panos.panorama_inheritance_unknown:
            return
        associations = panos.get_ntp_associations()
        if not associations:
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
                        )
                    )
                weak = association.authentication == "autokey" or (
                    modern_algorithms is True
                    and association.authentication == "symmetric-key"
                    and association.algorithm in {"md5", "sha1"}
                )
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
                    references=(PANOS_HIERARCHY_GUIDE, PANOS_MANAGEMENT_GUIDE),
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
                        )
                    )

    def check_management_tls(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        if panos.panorama_inheritance_unknown:
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
            profile = profiles.get((setting.device_scope, setting.profile)) or profiles.get(
                ("shared", setting.profile)
            )
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

        for binding in panos.get_management_certificate_bindings():
            evidence = self._evidence(binding.evidence)
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
                        item for schedule in threat_schedules for item in schedule.evidence
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

    def check_default_security_rules(self, parser: BaseDeviceParser) -> None:
        for rule in self._panos(parser).get_default_security_rules():
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
            ))

    def check_security_rules(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        profiles = {
            (profile.scope, profile.name): profile
            for profile in panos.get_log_forwarding_profiles()
        }
        inspections = {
            (inspection.rule_scope, inspection.rule_position, inspection.rule_name): inspection
            for inspection in panos.get_security_inspection()
        }
        for rule in panos.get_security_rules():
            evidence = self._evidence(rule.evidence)
            if not rule.enabled:
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
                        )
                    )
                continue
            if rule.action != "allow":
                continue
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
                continue

            inspection = inspections.get((rule.scope, rule.position, rule.name))
            if inspection is None:
                continue
            attachment_evidence = evidence + (
                f"{rule.scope}: {inspection.attachment_mode} {inspection.attachment_name}",
            )
            if inspection.resolution_state == "unresolved":
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.policy.security_profile_unresolved",
                        device=parser.device_type,
                        title="Allow rule references an unresolved security profile group",
                        observation=f"Enabled allow rule '{rule.name}' in '{rule.scope}' references security profile group '{inspection.attachment_name}', but no same-vsys or shared definition is present.",
                        impact="The static export does not prove that threat inspection is attached to the permitted traffic.",
                        exploitability="Traffic matching the rule may avoid the intended threat-prevention controls if the reference is invalid.",
                        recommendation="Attach an existing same-vsys or shared Security Profile Group and verify its member profiles.",
                        severity=Severity.HIGH,
                        evidence=attachment_evidence,
                        references=(PANOS_POLICY_GUIDE, PANOS_SECURITY_PROFILES_GUIDE),
                    )
                )
                continue
            if inspection.resolution_state == "empty":
                self.add_issue(
                    Finding(
                        rule_id="paloalto.panos.policy.security_profile_ineffective",
                        device=parser.device_type,
                        title="Allow rule uses an empty security profile group",
                        observation=f"Enabled allow rule '{rule.name}' in '{rule.scope}' references group '{inspection.attachment_name}', but the resolved group has no profile members.",
                        impact="An empty group does not provide the threat, malware, URL, file, or data inspection implied by its attachment.",
                        exploitability="Malicious content can traverse traffic matched by the rule without the intended profile controls.",
                        recommendation="Populate the group with the approved inspection profiles or attach suitable individual profiles.",
                        severity=Severity.HIGH,
                        evidence=attachment_evidence,
                        references=(PANOS_SECURITY_PROFILES_GUIDE,),
                    )
                )

            for profile in inspection.profiles:
                profile_evidence = evidence + self._evidence(profile.evidence) + (
                    f"{rule.scope}: {profile.profile_type} profile {profile.name}",
                )
                if profile.resolution_state == "unresolved":
                    self.add_issue(
                        Finding(
                            rule_id="paloalto.panos.policy.security_profile_unresolved",
                            device=parser.device_type,
                            title="Allow rule references an unresolved security profile",
                            observation=f"Enabled allow rule '{rule.name}' in '{rule.scope}' references {profile.profile_type} profile '{profile.name}', but no same-vsys, shared, or known built-in definition is present.",
                            impact="The static export does not prove that the referenced inspection function can be applied.",
                            exploitability="Traffic matching the rule may avoid this inspection control if the reference is invalid.",
                            recommendation=f"Attach an existing {profile.profile_type} profile in the rule's vsys or shared scope.",
                            severity=Severity.HIGH,
                            evidence=profile_evidence,
                            references=(PANOS_POLICY_GUIDE, PANOS_SECURITY_PROFILES_GUIDE),
                        )
                    )
                elif profile.content_state in {"empty", "nonblocking"}:
                    reason = (
                        "has no exported inspection settings"
                        if profile.content_state == "empty"
                        else "contains only explicitly non-blocking actions: "
                        + ", ".join(profile.actions)
                    )
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
                        ))

    @staticmethod
    def _static_effectiveness_comparable(rule: PanosSecurityRule) -> bool:
        """Limit proof to rules without dynamic or time-dependent predicates."""
        return (
            not rule.source_negated
            and not rule.destination_negated
            and rule.schedule.casefold() in {"none", "any"}
            and bool(rule.applications)
            and all(value.casefold() == "any" for value in rule.applications)
            and bool(rule.source_users)
            and all(value.casefold() == "any" for value in rule.source_users)
            and bool(rule.categories)
            and all(value.casefold() == "any" for value in rule.categories)
        )

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
        if panos.panorama_inheritance_unknown or panos.has_nat_policy():
            return
        previous_by_scope: dict[tuple[str, str, str], list[PanosSecurityRule]] = {}
        for rule in panos.get_security_rules():
            scope = (rule.device_scope, rule.scope, rule.rulebase)
            previous = previous_by_scope.setdefault(scope, [])
            if not rule.enabled or rule.action not in self._TERMINAL_ACTIONS:
                continue
            for earlier in previous:
                if not self._rule_covers(panos, earlier, rule):
                    continue
                same_action = earlier.action == rule.action
                self.add_issue(
                    Finding(
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
                    )
                )
                break
            previous.append(rule)

    def check_password_policy(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        if panos.panorama_inheritance_unknown:
            return
        policy = panos.get_password_policy()
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

    def check_password_reuse_and_username(self, parser: BaseDeviceParser) -> None:
        panos = self._panos(parser)
        if panos.panorama_inheritance_unknown:
            return
        policy = panos.get_password_policy()
        if policy.enabled is not True:
            return
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
        if panos.panorama_inheritance_unknown or panos.template_unresolved:
            return
        for zone in panos.get_zone_protections():
            external = tuple(
                interface for interface in zone.interfaces
                if panos.assessment_context.role_for_interface(interface) == "external"
            )
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
        self.check_panorama_scope(parser)
