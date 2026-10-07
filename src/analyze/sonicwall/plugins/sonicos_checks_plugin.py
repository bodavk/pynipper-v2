"""SonicOS 7 E-CLI management, policy, VPN, and operations checks."""

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.controls import ControlOutcome as CO, record_control
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.policy_semantics import (
    ProofState,
    network_covers,
    service_covers,
    static_values_cover,
)
from src.devices.sonicwall.sonicos import SonicOSParser


SONICOS_CLI_GUIDE = (
    "https://www.sonicwall.com/techdocs/pdf/"
    "sonicosx-7-command-line-interface-reference-guide.pdf"
)
SONICOS_MANAGEMENT_GUIDE = (
    "https://www.sonicwall.com/support/technical-documentation/docs/"
    "sonicos-7-0-0-0-device_settings/Content/Topics/Management/management-ssh.htm"
)
SONICOS_SYSTEM_GUIDE = (
    "https://www.sonicwall.com/techdocs/pdf/sonicos-7-0-0-0-system.pdf"
)
SONICOS_POLICY_GUIDE = (
    "https://www.sonicwall.com/techdocs/pdf/sonicos-7-0-0-0-rules_and_policies.pdf"
)
SONICOS_VPN_GUIDE = (
    "https://www.sonicwall.com/support/knowledge-base/"
    "configuring-site-to-site-vpn-policies-using-enterprise-command-line-interface-e-cli/kA1VN0000000JUH0A2"
)
SONICOS_CAPTURE_ATP_GUIDE = (
    "https://www.sonicwall.com/support/technical-documentation/docs/"
    "sonicos-7-1-capture_atp/Content/capture-atp-disabling-gav.htm"
)
SONICOS_PASSWORD_GUIDE = (
    "https://www.sonicwall.com/support/technical-documentation/docs/"
    "sonicos-7-1-device_settings/Content/System_Administration/Multiple_Administrator/"
    "password-compliance-configuration.htm"
)
SONICOS_LOGIN_CONSTRAINTS_GUIDE = (
    "https://www.sonicwall.com/support/technical-documentation/docs/"
    "sonicos-7-1-device_settings/Content/System_Administration/Multiple_Administrator/"
    "login-constraints-configuring.htm"
)
SONICOS_ADMIN_ROLES_GUIDE = (
    "https://www.sonicwall.com/support/knowledge-base/"
    "access-rights-for-administrators/kA1VN0000000Frz0AE"
)
SONICOS_CERTIFICATE_GUIDE = (
    "https://www.sonicwall.com/support/technical-documentation/docs/"
    "sonicos-7-1-device_settings/Content/Management/security-certificate-selecting.htm"
)
SONICOS_TLS_GUIDE = (
    "https://www.sonicwall.com/support/technical-documentation/docs/"
    "sonicos-7-1-device_settings/Content/Management/TLS-version-enforcing.htm"
)
SONICOS_LOGIN_BANNER_GUIDE = (
    "https://www.sonicwall.com/support/knowledge-base/"
    "modifying-the-sonicwall-login-banner-page-display/kA1VN0000000Ogg0AE"
)


class PluginSonicOSChecks(BasePlugin):
    _EXTERNAL_ZONES = {"wan", "dmz", "wlan", "ssl-vpn"}
    _WEAK_ENCRYPTION = {"des", "3des", "triple-des"}
    _WEAK_AUTHENTICATION = {"md5", "sha", "sha1", "sha-1"}
    _WEAK_DH = {"1", "2", "5", "group1", "group2", "group5"}
    _INTERNAL_ZONES = {"lan", "mgmt", "vpn", "multicast"}
    _NO_INTERFACES = "No interface record is exported; management-service exposure is not established."

    @staticmethod
    def _sonic(parser: BaseDeviceParser) -> SonicOSParser:
        if not isinstance(parser, SonicOSParser):
            raise TypeError("PluginSonicOSChecks requires a SonicOSParser")
        return parser

    @staticmethod
    def _evidence_has(evidence, phrase: str) -> bool:
        """Whether any evidence line contains ``phrase`` (finds an explicit setting for PT-009 basis)."""
        return any(phrase in getattr(item, "text", str(item)).casefold() for item in evidence)

    def check_management(self, parser: BaseDeviceParser) -> None:
        if not self._sonic(parser).get_interfaces():
            for control in ("sonicwall.sonicos.management-http", "sonicwall.sonicos.management-external-exposure"):
                record_control(parser, control, CO.UNKNOWN, self._NO_INTERFACES)
        for interface in self._sonic(parser).get_interfaces():
            instance = f"interface {interface.name}"
            if not interface.enabled:
                for control in ("sonicwall.sonicos.management-http", "sonicwall.sonicos.management-external-exposure"):
                    record_control(parser, control, CO.NOT_APPLICABLE, "The interface is shut down.", instance=instance)
                continue
            evidence = tuple(item for item in interface.evidence)
            # Only one 'management' statement per interface is a qualified grammar (SC-018).
            ambiguous = sum(
                1 for item in interface.evidence
                if getattr(item, "text", str(item)).strip().casefold().startswith("management")
            ) > 1
            record_control(
                parser, "sonicwall.sonicos.management-http",
                CO.FINDING if "http" in interface.management else CO.UNKNOWN if ambiguous else CO.NO_FINDING,
                "HTTP management is enabled." if "http" in interface.management
                else "Several management statements; only the first is a qualified grammar." if ambiguous
                else "HTTP management is not enabled.",
                instance=instance,
            )
            exposed_services = sorted(set(interface.management) & {"https", "ssh", "snmp"})
            zone = interface.zone.casefold()
            if exposed_services and zone in self._EXTERNAL_ZONES:
                outcome, reason = CO.FINDING, f"Management is enabled in external zone {interface.zone}."
            elif ambiguous:
                outcome, reason = CO.UNKNOWN, "Several management statements; only the first is a qualified grammar."
            elif not exposed_services:
                outcome, reason = CO.NO_FINDING, "No HTTPS, SSH or SNMP management is enabled."
            elif zone in self._INTERNAL_ZONES:
                outcome, reason = CO.NO_FINDING, f"Management is limited to built-in internal zone {interface.zone}."
            else:
                outcome, reason = CO.UNKNOWN, f"Zone '{interface.zone or 'unspecified'}' trust type is not resolved."
            record_control(parser, "sonicwall.sonicos.management-external-exposure", outcome, reason, instance=instance)
            if "http" in interface.management:
                self.add_issue(
                    Finding(
                        rule_id="sonicwall.sonicos.management.http",
                        device=parser.device_type,
                        title="Clear-text HTTP management is enabled",
                        observation=f"Interface '{interface.name}' in zone '{interface.zone or 'unspecified'}' permits HTTP management.",
                        impact="Administrative credentials and sessions can be exposed or modified in transit.",
                        exploitability="An attacker with management-path reachability can intercept clear-text traffic.",
                        recommendation="Remove HTTP management from the interface and use HTTPS with an approved certificate.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(SONICOS_MANAGEMENT_GUIDE, SONICOS_SYSTEM_GUIDE),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            exposed = sorted(set(interface.management) & {"https", "ssh", "snmp"})
            if exposed and interface.zone.casefold() in self._EXTERNAL_ZONES:
                self.add_issue(
                    Finding(
                        rule_id="sonicwall.sonicos.management.external_interface",
                        device=parser.device_type,
                        title="Management is enabled on an external-zone interface",
                        observation=f"Interface '{interface.name}' in {interface.zone} permits {', '.join(exposed)} management.",
                        impact="Internet- or partner-facing paths may expose the firewall management plane.",
                        exploitability="Any source allowed to reach the interface can probe the enabled services; inter-zone rules may add restrictions not reconstructed here.",
                        recommendation="Remove management from external interfaces or constrain it with explicit source-specific access rules and upstream controls.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(SONICOS_SYSTEM_GUIDE, SONICOS_POLICY_GUIDE),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )

    def check_administration(self, parser: BaseDeviceParser) -> None:
        sonic = self._sonic(parser)
        services = sonic.get_services()

        for administrator in sonic.get_administrators():
            instance = f"administrator {administrator.name}"
            record_control(
                parser, "sonicwall.sonicos.admin-role-separation",
                CO.FINDING if len(administrator.roles) > 1 else CO.NO_FINDING,
                f"Administrative roles: {', '.join(administrator.roles)}.", instance=instance,
            )
            if administrator.effective_role in {"full-admin", "limited-admin"}:
                record_control(
                    parser, "sonicwall.sonicos.admin-mfa",
                    CO.FINDING if administrator.otp_enabled is False
                    else CO.NO_FINDING if administrator.otp_enabled else CO.UNKNOWN,
                    "TOTP is disabled (explicit or documented 7.0-7.2 default)." if administrator.otp_enabled is False
                    else "TOTP is required." if administrator.otp_enabled
                    else "TOTP is not exported and the release default is not qualified.",
                    instance=instance,
                )
            else:
                record_control(parser, "sonicwall.sonicos.admin-mfa", CO.NOT_APPLICABLE,
                               "The account is not a full or limited administrator.", instance=instance)
            if len(administrator.roles) > 1:
                self.add_issue(Finding(
                    rule_id="sonicwall.sonicos.admin.conflicting_roles",
                    device=parser.device_type,
                    title="Administrator belongs to conflicting privilege groups",
                    observation=(
                        f"Local administrator '{administrator.name}' belongs to {', '.join(administrator.roles)}; "
                        f"SonicOS resolves the effective role to {administrator.effective_role}."
                    ),
                    impact="A higher-precedence group can silently override the intended lower-privilege administrative role.",
                    exploitability="Compromise or misuse of the account receives the effective higher privilege.",
                    recommendation="Place each administrator in one deliberate administrative group and use read-only or limited access wherever sufficient.",
                    severity=Severity.HIGH if administrator.effective_role == "full-admin" else Severity.MEDIUM,
                    evidence=tuple(item for item in administrator.evidence),
                    references=(SONICOS_ADMIN_ROLES_GUIDE, SONICOS_CLI_GUIDE),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            if administrator.otp_enabled is False and administrator.effective_role in {"full-admin", "limited-admin"}:
                self.add_issue(Finding(
                    rule_id="sonicwall.sonicos.admin.mfa_missing",
                    device=parser.device_type,
                    title="Privileged local administrator does not require TOTP",
                    observation=f"Local {administrator.effective_role} account '{administrator.name}' has TOTP explicitly or unambiguously disabled.",
                    impact="A stolen or guessed password alone can authorize privileged firewall administration.",
                    exploitability="An attacker who obtains the local password does not need an independent authentication factor.",
                    recommendation="Require TOTP for privileged local administrators and maintain a separately controlled recovery procedure.",
                    severity=Severity.HIGH,
                    evidence=tuple(item for item in administrator.evidence) or (
                        "SonicOS 7.0-7.2 documented default: built-in administrator TOTP disabled",
                    ),
                    references=(SONICOS_CLI_GUIDE,),
                    basis=(
                        FindingBasis.EXPLICIT_VALUE if self._evidence_has(administrator.evidence, "one-time-p")
                        else FindingBasis.DOCUMENTED_DEFAULT
                    ),
                ))

        password = sonic.get_password_policy()
        password_evidence = tuple(item for item in password.evidence)
        for key, value, fires in (
            ("minimum-length", password.minimum_length,
             password.minimum_length is not None and password.minimum_length < 12),
            ("complexity", password.complexity,
             password.complexity is not None
             and password.complexity not in {"alpha-and-numeric-and-symbols", "alphanumeric-and-symbols"}),
            ("constraint-scope", password.scopes,
             password.scopes is not None
             and not {"admin", "full-admin", "limited-admin"}.issubset(password.scopes)),
        ):
            record_control(
                parser, "sonicwall.sonicos.password-policy",
                CO.FINDING if fires else CO.UNKNOWN if value is None else CO.NO_FINDING,
                f"{key}: {value} ({password.resolution_state})." if value is not None
                else f"{key} is not exported or malformed and the release default is not qualified.",
                instance=key,
            )
        if password.minimum_length is not None and password.minimum_length < 12:
            self.add_issue(Finding(
                rule_id="sonicwall.sonicos.password.minimum_length",
                device=parser.device_type,
                title="Administrative password minimum length is weak",
                observation=f"The effective minimum password length is {password.minimum_length}, below the 12-character project baseline.",
                impact="Short passwords reduce resistance to online guessing and offline cracking after credential disclosure.",
                exploitability="An attacker can search a materially smaller password space.",
                recommendation="Set the SonicOS minimum password length to at least 12 characters and prefer longer passphrases.",
                severity=Severity.MEDIUM,
                evidence=password_evidence or ("SonicOS 7.0-7.2 documented minimum-length default: 8",),
                references=(SONICOS_PASSWORD_GUIDE, SONICOS_CLI_GUIDE),
                basis=(
                    FindingBasis.EXPLICIT_VALUE if self._evidence_has(password_evidence, "password minimum-length")
                    else FindingBasis.DOCUMENTED_DEFAULT
                ),
            ))
        if password.complexity is not None and password.complexity not in {
            "alpha-and-numeric-and-symbols", "alphanumeric-and-symbols"
        }:
            self.add_issue(Finding(
                rule_id="sonicwall.sonicos.password.complexity",
                device=parser.device_type,
                title="Administrative password complexity is not fully enabled",
                observation=f"The effective password complexity mode is '{password.complexity}'.",
                impact="Locally managed passwords may be easier to guess or reuse across systems.",
                exploitability="Password-spraying and credential-cracking attacks benefit from a less diverse password policy.",
                recommendation="Require alphabetic, numeric, and symbolic characters for applicable administrator accounts.",
                severity=Severity.MEDIUM,
                evidence=password_evidence or ("SonicOS 7.0-7.2 documented password-complexity default: none",),
                references=(SONICOS_PASSWORD_GUIDE, SONICOS_CLI_GUIDE),
                basis=(
                    FindingBasis.EXPLICIT_VALUE if self._evidence_has(password_evidence, "password complexity")
                    else FindingBasis.DOCUMENTED_DEFAULT
                ),
            ))
        required_scopes = {"admin", "full-admin", "limited-admin"}
        if password.scopes is not None and not required_scopes.issubset(password.scopes):
            missing_scopes = sorted(required_scopes - set(password.scopes))
            self.add_issue(Finding(
                rule_id="sonicwall.sonicos.password.admin_scope",
                device=parser.device_type,
                title="Password constraints omit an administrator class",
                observation="Password constraints do not apply to: " + ", ".join(missing_scopes) + ".",
                impact="Privileged local accounts in the omitted classes can be assigned passwords outside the configured policy.",
                exploitability="An attacker can target weaker credentials belonging to an excluded administrator class.",
                recommendation="Apply password constraints to the built-in, full, and limited administrator classes.",
                severity=Severity.HIGH,
                evidence=password_evidence,
                references=(SONICOS_PASSWORD_GUIDE, SONICOS_CLI_GUIDE),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

        session = sonic.get_admin_session_policy()
        session_evidence = tuple(item for item in session.evidence)
        management_active = any(services.values())
        interfaces_exported = bool(sonic.get_interfaces())
        if not management_active:
            for control in ("sonicwall.sonicos.admin-lockout", "sonicwall.sonicos.admin-idle-timeout"):
                record_control(parser, control, CO.NOT_APPLICABLE if interfaces_exported else CO.UNKNOWN,
                               "No enabled interface permits management." if interfaces_exported else self._NO_INTERFACES)
        else:
            weak_lockout = (
                (session.failures_per_minute is not None and session.failures_per_minute > 5)
                or (session.lockout_duration_minutes is not None and session.lockout_duration_minutes < 5)
            )
            if session.lockout_enabled is False:
                outcome, reason = CO.FINDING, "User lockout is disabled."
            elif session.lockout_enabled is None:
                outcome, reason = CO.UNKNOWN, "User lockout is not exported and the release default is not qualified."
            elif weak_lockout:
                outcome, reason = CO.FINDING, "Lockout thresholds are weak."
            elif session.failures_per_minute is None or session.lockout_duration_minutes is None:
                outcome, reason = CO.UNKNOWN, "Lockout thresholds are not exported or malformed."
            else:
                outcome, reason = CO.NO_FINDING, (
                    f"Lockout after {session.failures_per_minute} failures for {session.lockout_duration_minutes} minutes.")
            record_control(parser, "sonicwall.sonicos.admin-lockout", outcome, reason, instance="lockout")
            record_control(
                parser, "sonicwall.sonicos.admin-lockout",
                CO.FINDING if session.log_without_lockout is True
                else CO.NO_FINDING if session.log_without_lockout is False else CO.UNKNOWN,
                "log-without-lockout is enabled." if session.log_without_lockout is True
                else "log-without-lockout is disabled." if session.log_without_lockout is False
                else "log-without-lockout is not exported and the release default is not qualified.",
                instance="log-without-lockout",
            )
            idle = session.idle_logout_minutes
            record_control(
                parser, "sonicwall.sonicos.admin-idle-timeout",
                CO.UNKNOWN if idle is None or idle < 1 else CO.FINDING if idle > 5 else CO.NO_FINDING,
                "Idle timeout is not exported, malformed or outside the qualified range." if idle is None or idle < 1
                else f"Idle timeout is {idle} minutes ({session.resolution_state}).",
            )
        if not services["ssh"]:
            for control in ("sonicwall.sonicos.cli-login-attempts", "sonicwall.sonicos.connection-banner"):
                record_control(parser, control, CO.NOT_APPLICABLE if interfaces_exported else CO.UNKNOWN,
                               "SSH management is not enabled." if interfaces_exported else self._NO_INTERFACES)
        else:
            attempts = session.max_cli_attempts
            record_control(
                parser, "sonicwall.sonicos.cli-login-attempts",
                CO.UNKNOWN if attempts is None else CO.FINDING if attempts > 5 else CO.NO_FINDING,
                "CLI attempt limit is not exported and the release default is not qualified." if attempts is None
                else f"CLI attempt limit is {attempts}.",
            )
        if management_active and session.lockout_enabled is False:
            self.add_issue(Finding(
                rule_id="sonicwall.sonicos.admin.lockout_disabled",
                device=parser.device_type,
                title="Administrator login lockout is disabled",
                observation="The effective administrator/user lockout control is disabled while a management service is active.",
                impact="Repeated password guesses are not stopped by the appliance lockout control.",
                exploitability="A reachable attacker can sustain online password-guessing attempts.",
                recommendation="Enable user lockout with a conservative failed-attempt threshold and a controlled recovery process.",
                severity=Severity.HIGH,
                evidence=session_evidence or ("SonicOS 7.0-7.2 documented user-lockout default: disabled",),
                references=(SONICOS_LOGIN_CONSTRAINTS_GUIDE, SONICOS_CLI_GUIDE),
                basis=(
                    FindingBasis.EXPLICIT_VALUE if self._evidence_has(session_evidence, "user-lockout")
                    else FindingBasis.DOCUMENTED_DEFAULT
                ),
            ))
        if management_active and session.lockout_enabled is True:
            weaknesses = []
            if session.failures_per_minute is not None and session.failures_per_minute > 5:
                weaknesses.append(f"{session.failures_per_minute} allowed failures")
            if session.lockout_duration_minutes is not None and session.lockout_duration_minutes < 5:
                weaknesses.append(f"{session.lockout_duration_minutes}-minute lockout")
            if weaknesses:
                self.add_issue(Finding(
                    rule_id="sonicwall.sonicos.admin.lockout_policy",
                    device=parser.device_type,
                    title="Administrator lockout thresholds are weak",
                    observation="The effective lockout policy uses " + " and ".join(weaknesses) + ".",
                    impact="The appliance permits rapid retry or restores guessing access too quickly.",
                    exploitability="A reachable attacker receives more opportunities to guess an administrator password.",
                    recommendation="Allow no more than five failed attempts and lock the account for at least five minutes.",
                    severity=Severity.MEDIUM,
                    evidence=session_evidence,
                    references=(SONICOS_LOGIN_CONSTRAINTS_GUIDE, SONICOS_CLI_GUIDE),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
        if management_active and session.idle_logout_minutes is not None and session.idle_logout_minutes > 5:
            self.add_issue(Finding(
                rule_id="sonicwall.sonicos.admin.idle_timeout",
                device=parser.device_type,
                title="Administrator idle timeout is excessive",
                observation=f"The effective administrator inactivity timeout is {session.idle_logout_minutes} minutes.",
                impact="An unattended authenticated management session remains usable longer than the vendor default.",
                exploitability="A person or process with access to an abandoned session can inherit its privileges.",
                recommendation="Set the administrator inactivity timeout to five minutes or less.",
                severity=Severity.MEDIUM,
                evidence=session_evidence,
                references=(SONICOS_LOGIN_CONSTRAINTS_GUIDE, SONICOS_CLI_GUIDE),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        if services["ssh"] and session.max_cli_attempts is not None and session.max_cli_attempts > 5:
            self.add_issue(Finding(
                rule_id="sonicwall.sonicos.admin.cli_login_attempts",
                device=parser.device_type,
                title="CLI login attempt limit is excessive",
                observation=f"The CLI permits {session.max_cli_attempts} attempts before disconnecting the session.",
                impact="Each SSH connection receives more opportunities to guess a privileged password.",
                exploitability="A reachable attacker can make more guesses per connection.",
                recommendation="Set max-login-attempts-cli to five or fewer.",
                severity=Severity.MEDIUM,
                evidence=session_evidence,
                references=(SONICOS_LOGIN_CONSTRAINTS_GUIDE, SONICOS_CLI_GUIDE),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        if management_active and session.log_without_lockout is True:
            self.add_issue(Finding(
                rule_id="sonicwall.sonicos.admin.log_without_lockout",
                device=parser.device_type,
                title="Failed logins are logged without enforcing lockout",
                observation="The log-without-lockout option is enabled.",
                impact="Monitoring records failed attempts but does not stop sustained password guessing.",
                exploitability="A reachable attacker can continue attempts despite generating audit events.",
                recommendation="Disable log-without-lockout and enforce the configured administrator lockout policy.",
                severity=Severity.HIGH,
                evidence=session_evidence,
                references=(SONICOS_LOGIN_CONSTRAINTS_GUIDE, SONICOS_CLI_GUIDE),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

        banner = sonic.get_banner_policy()
        if services["ssh"]:
            record_control(
                parser, "sonicwall.sonicos.connection-banner",
                CO.FINDING if banner.connection_enabled is False
                else CO.NO_FINDING if banner.connection_enabled else CO.UNKNOWN,
                "No CLI connection banner is configured." if banner.connection_enabled is False
                else "A CLI connection banner is configured." if banner.connection_enabled
                else "The connection banner is not exported and the release default is not qualified.",
            )
        if services["ssh"] and banner.connection_enabled is False:
            self.add_issue(Finding(
                rule_id="sonicwall.sonicos.admin.connection_banner",
                device=parser.device_type,
                title="SSH connection notice is not configured",
                observation="SSH management is active without an effective pre-authentication CLI connection banner.",
                impact="Administrative users are not shown the organization's authorization and monitoring notice before login.",
                exploitability="This is primarily a governance and legal-notice control rather than a direct technical exploit.",
                recommendation="Configure an approved 'cli banner connection' notice and validate it before the credential prompt.",
                severity=Severity.LOW,
                evidence=tuple(item for item in banner.evidence) or (
                    "SonicOS 7.0-7.2 documented CLI connection banner default: absent",
                ),
                references=(SONICOS_LOGIN_BANNER_GUIDE, SONICOS_CLI_GUIDE),
                basis=FindingBasis.REQUIRED_SETTING_MISSING,
            ))

        tls = sonic.get_management_tls_policy()
        tls_evidence = tuple(item for item in tls.evidence)
        if not tls.applicable:
            for control in ("sonicwall.sonicos.management-tls-version", "sonicwall.sonicos.management-certificate"):
                record_control(parser, control, CO.NOT_APPLICABLE if interfaces_exported else CO.UNKNOWN,
                               "HTTPS management is not enabled." if interfaces_exported else self._NO_INTERFACES)
        else:
            record_control(
                parser, "sonicwall.sonicos.management-tls-version",
                CO.FINDING if tls.minimum_version == "tls1.0"
                else CO.NO_FINDING if tls.minimum_version == "tls1.1" else CO.UNKNOWN,
                "'no tls-and-above' permits TLS 1.0." if tls.minimum_version == "tls1.0"
                else "'tls-and-above' is enabled." if tls.minimum_version == "tls1.1"
                else "tls-and-above is not exported and the release default is not qualified.",
            )
            record_control(
                parser, "sonicwall.sonicos.management-certificate",
                CO.FINDING if tls.certificate_type == "self-signed"
                else CO.NO_FINDING if tls.certificate_type == "imported" else CO.UNKNOWN,
                "The self-signed certificate is selected." if tls.certificate_type == "self-signed"
                else "An imported certificate is selected (selection only; validity is not assessed)."
                if tls.certificate_type == "imported"
                else "Certificate selection is not exported and the release default is not qualified.",
            )
        if tls.applicable and tls.minimum_version == "tls1.0":
            self.add_issue(Finding(
                rule_id="sonicwall.sonicos.management.legacy_tls",
                device=parser.device_type,
                title="Legacy TLS 1.0 is permitted for web management",
                observation="HTTPS management is active and 'no tls-and-above' permits TLS 1.0.",
                impact="Administrative sessions can negotiate an obsolete protocol with known design weaknesses.",
                exploitability="A network-positioned attacker can target clients that negotiate the legacy protocol.",
                recommendation="Enable tls-and-above and, where the release permits, enforce a stronger TLS floor through the supported management settings.",
                severity=Severity.HIGH,
                evidence=tls_evidence,
                references=(SONICOS_TLS_GUIDE, SONICOS_CLI_GUIDE),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        if tls.applicable and tls.certificate_type == "self-signed":
            self.add_issue(Finding(
                rule_id="sonicwall.sonicos.management.self_signed_certificate",
                device=parser.device_type,
                title="Web management uses the default self-signed certificate type",
                observation="HTTPS management is active and the effective certificate selection is self-signed.",
                impact="Administrators cannot rely on an organization-trusted identity chain to authenticate the firewall.",
                exploitability="Users who bypass certificate warnings are more susceptible to management-plane impersonation.",
                recommendation="Install and select an organization-approved identity certificate with the correct DNS name and trust chain.",
                severity=Severity.MEDIUM,
                evidence=tls_evidence or ("SonicOS 7.0-7.2 documented certificate-selection default: self-signed",),
                references=(SONICOS_CERTIFICATE_GUIDE, SONICOS_CLI_GUIDE),
                basis=(
                    FindingBasis.EXPLICIT_VALUE if self._evidence_has(tls_evidence, "web-management certificate")
                    else FindingBasis.DOCUMENTED_DEFAULT
                ),
            ))
    @staticmethod
    def _is_any(value: str) -> bool:
        return value.casefold() in {"any", "all"}

    def check_access_rules(self, parser: BaseDeviceParser) -> None:
        self._broad_allow_instances: set[str] = set()
        if not self._sonic(parser).get_access_rules():
            for control in ("sonicwall.sonicos.policy-scope", "sonicwall.sonicos.policy-logging",
                            "sonicwall.sonicos.policy-order", "sonicwall.sonicos.policy-disabled-permissive"):
                record_control(parser, control, CO.UNKNOWN,
                               "No access-rule record is exported; the effective rule base is not established.")
        for rule in self._sonic(parser).get_access_rules():
            instance = f"rule {rule.position} {rule.name}"
            if not rule.enabled or rule.action != "allow":
                for control in ("sonicwall.sonicos.policy-scope", "sonicwall.sonicos.policy-logging"):
                    record_control(parser, control, CO.NOT_APPLICABLE, "Disabled or non-allow rule.", instance=instance)
                continue
            evidence = tuple(item for item in rule.evidence)
            record_control(
                parser, "sonicwall.sonicos.policy-logging", CO.NO_FINDING if rule.logging else CO.FINDING,
                "Logging is enabled." if rule.logging else "Logging is disabled or not configured.", instance=instance,
            )
            if all(
                self._is_any(value)
                for value in (
                    rule.from_zone,
                    rule.to_zone,
                    rule.source,
                    rule.destination,
                    rule.service,
                )
            ) and rule.schedule.casefold() in {"", "any", "always-on"}:
                self._broad_allow_instances.add(instance)
                record_control(parser, "sonicwall.sonicos.policy-scope", CO.FINDING,
                               "The rule allows any zone, source, destination and service.", instance=instance)
                self.add_issue(
                    Finding(
                        rule_id="sonicwall.sonicos.policy.broad_allow",
                        device=parser.device_type,
                        title="Unrestricted access rule is enabled",
                        observation=f"Rule '{rule.name}' at position {rule.position} allows any zone, source, destination, and service.",
                        impact="The rule can bypass intended network segmentation and least-privilege controls.",
                        exploitability="Any matching source can reach any routable destination and service permitted by surrounding infrastructure.",
                        recommendation="Replace wildcard fields with explicit zones, address objects, services, users, and schedules.",
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                        references=(SONICOS_POLICY_GUIDE, SONICOS_CLI_GUIDE),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    )
                )
            if not rule.logging:
                self.add_issue(
                    Finding(
                        rule_id="sonicwall.sonicos.policy.logging",
                        device=parser.device_type,
                        title="Allow rule does not enable logging",
                        observation=f"Enabled allow rule '{rule.name}' at position {rule.position} has logging disabled or absent.",
                        impact="Permitted connections may lack the telemetry needed for detection and investigation.",
                        exploitability="Malicious traffic matching the rule can be harder to identify or reconstruct.",
                        recommendation="Enable logging on security-relevant allow rules and forward events to centralized storage.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(SONICOS_POLICY_GUIDE, SONICOS_CLI_GUIDE),
                        basis=(
                            FindingBasis.EXPLICIT_VALUE if self._evidence_has(evidence, "no logging")
                            else FindingBasis.MISSING_EXPLICIT_SETTING
                        ),
                    )
                )

    def check_policy_effectiveness(self, parser: BaseDeviceParser) -> None:
        """Report only statically proven first-match policy relationships."""
        earlier_rules = []
        unqualified_earlier = False
        disabled_rules = 0
        broad_allow_instances = getattr(self, "_broad_allow_instances", set())
        for rule in self._sonic(parser).get_access_rules():
            instance = f"rule {rule.position} {rule.name}"
            evidence = tuple(item for item in rule.evidence) or (
                f"access rule {rule.name}",
            )
            unrestricted = (
                rule.source_networks.any
                and rule.destination_networks.any
                and rule.services.any
                and self._is_any(rule.from_zone)
                and self._is_any(rule.to_zone)
                and rule.schedule.casefold() in {"", "any", "always-on"}
                and not rule.unsupported_predicates
            )
            if not rule.enabled:
                disabled_rules += 1
                record_control(parser, "sonicwall.sonicos.policy-order", CO.NOT_APPLICABLE, "Disabled rule.",
                               instance=instance)
                record_control(
                    parser, "sonicwall.sonicos.policy-disabled-permissive",
                    CO.NOT_APPLICABLE if rule.action != "allow"
                    else CO.FINDING if unrestricted
                    else CO.UNKNOWN if rule.unsupported_predicates or not (
                        rule.source_networks.complete and rule.destination_networks.complete and rule.services.complete)
                    else CO.NO_FINDING,
                    "Disabled non-allow rule." if rule.action != "allow"
                    else "Disabled rule retains an unrestricted allow." if unrestricted
                    else "Disabled allow rule selectors are not fully resolved." if rule.unsupported_predicates or not (
                        rule.source_networks.complete and rule.destination_networks.complete and rule.services.complete)
                    else "Disabled allow rule is restricted.",
                    instance=instance,
                )
                if rule.action == "allow" and unrestricted:
                    self.add_issue(Finding(
                        rule_id="sonicwall.sonicos.policy.disabled_permissive_rule",
                        device=parser.device_type,
                        title="Disabled permissive SonicOS access rule remains configured",
                        observation=f"Disabled access rule '{rule.name}' at position {rule.position} retains an unrestricted allow action.",
                        impact="Stale permissive policy obscures intent and can create broad exposure if re-enabled.",
                        exploitability="The rule is disabled in the supplied configuration; exploitation requires reactivation.",
                        recommendation="Remove the obsolete rule or narrow and document it before reactivation.",
                        severity=Severity.LOW,
                        evidence=evidence,
                        references=(SONICOS_POLICY_GUIDE, SONICOS_CLI_GUIDE),
                        basis=FindingBasis.EXPLICIT_VALUE,
                    ))
                continue

            if rule.action == "allow" and instance not in broad_allow_instances:
                record_control(
                    parser, "sonicwall.sonicos.policy-scope",
                    CO.FINDING if rule.services.any and not unrestricted
                    else CO.UNKNOWN if not rule.services.complete or unrestricted
                    else CO.NO_FINDING,
                    "The rule permits Any service." if rule.services.any and not unrestricted
                    else "Service selector is not fully resolved." if not rule.services.complete
                    else "Selectors resolve to unrestricted scope through objects; not reported by the wildcard check."
                    if unrestricted
                    else "Service selector is restricted and the rule is not fully wildcarded.",
                    instance=instance,
                )
            elif rule.action == "allow" and rule.services.any and not unrestricted:
                record_control(parser, "sonicwall.sonicos.policy-scope", CO.FINDING,
                               "The rule permits Any service.", instance=instance)
            if rule.action == "allow" and rule.services.any and not unrestricted:
                self.add_issue(Finding(
                    rule_id="sonicwall.sonicos.policy.broad_service",
                    device=parser.device_type,
                    title="SonicOS access rule is unrestricted by service",
                    observation=f"Enabled access rule '{rule.name}' at position {rule.position} permits Any service within its zone and address scope.",
                    impact="Unnecessary protocols and destination ports can cross the policy boundary.",
                    exploitability="A matching source can attempt any service reachable in the destination scope.",
                    recommendation="Replace Any with the smallest required services or reviewed service group.",
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                    references=(SONICOS_POLICY_GUIDE, SONICOS_CLI_GUIDE),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))

            if not rule.proof_eligible:
                record_control(parser, "sonicwall.sonicos.policy-order", CO.UNKNOWN,
                               "Rule selectors, schedule or predicates are not fully resolved.", instance=instance)
                unqualified_earlier = True
                continue
            undetermined = False
            for earlier in earlier_rules:
                if earlier.family != rule.family:
                    continue
                states = (
                    static_values_cover((earlier.from_zone,), (rule.from_zone,)),
                    static_values_cover((earlier.to_zone,), (rule.to_zone,)),
                    network_covers(earlier.source_networks, rule.source_networks),
                    network_covers(
                        earlier.destination_networks, rule.destination_networks
                    ),
                    service_covers(earlier.services, rule.services),
                )
                if not all(state == ProofState.PROVEN for state in states):
                    if ProofState.DISPROVEN not in states:
                        undetermined = True
                    continue
                same_action = earlier.action == rule.action
                if same_action and earlier.behavior_signature != rule.behavior_signature:
                    continue
                self.add_issue(Finding(
                    rule_id=(
                        "sonicwall.sonicos.policy.redundant_rule"
                        if same_action
                        else "sonicwall.sonicos.policy.shadowed_rule"
                    ),
                    device=parser.device_type,
                    title=(
                        "SonicOS access rule is redundant"
                        if same_action
                        else "SonicOS access rule is shadowed"
                    ),
                    observation=f"Access rule '{rule.name}' at position {rule.position} is fully covered by earlier rule '{earlier.name}' at position {earlier.position} with {'equivalent behavior' if same_action else 'a different terminal action'}.",
                    impact="The later rule cannot alter first-match enforcement for the statically proven traffic scope and obscures policy intent.",
                    exploitability="A conflicting shadowed rule can give reviewers a false impression of enforced access control.",
                    recommendation="Remove or reorder the rule after validating address/service objects, logging, and operational intent.",
                    severity=Severity.LOW if same_action else Severity.HIGH,
                    evidence=evidence + tuple(item for item in earlier.evidence),
                    references=(SONICOS_POLICY_GUIDE, SONICOS_CLI_GUIDE),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
                record_control(parser, "sonicwall.sonicos.policy-order", CO.FINDING,
                               "Proven static shadow/redundancy, not observed nonuse.", instance=instance)
                break
            else:
                record_control(
                    parser, "sonicwall.sonicos.policy-order",
                    CO.UNKNOWN if undetermined or unqualified_earlier else CO.NO_FINDING,
                    "An earlier rule is unresolved or coverage is undetermined." if undetermined or unqualified_earlier
                    else "Bounded static comparison with every earlier rule qualified.",
                    instance=instance,
                )
            earlier_rules.append(rule)
        if not disabled_rules and self._sonic(parser).get_access_rules():
            record_control(parser, "sonicwall.sonicos.policy-disabled-permissive", CO.NOT_APPLICABLE,
                           "No disabled access rule is exported.")

    def check_vpn(self, parser: BaseDeviceParser) -> None:
        if not self._sonic(parser).get_vpn_policies():
            record_control(parser, "sonicwall.sonicos.vpn-crypto", CO.NOT_APPLICABLE, "No VPN policy is configured.")
        for policy in self._sonic(parser).get_vpn_policies():
            instance = f"vpn policy {policy.name}"
            if not policy.enabled:
                record_control(parser, "sonicwall.sonicos.vpn-crypto", CO.NOT_APPLICABLE, "Disabled VPN policy.",
                               instance=instance)
                continue
            proposal = (policy.ike_encryption, policy.ike_authentication, policy.dh_group,
                        policy.ipsec_encryption, policy.ipsec_authentication)
            weak_proposal = any(
                value in denied for value, denied in zip(proposal, (
                    self._WEAK_ENCRYPTION, self._WEAK_AUTHENTICATION, self._WEAK_DH,
                    self._WEAK_ENCRYPTION, self._WEAK_AUTHENTICATION))
            )
            record_control(
                parser, "sonicwall.sonicos.vpn-crypto",
                CO.FINDING if weak_proposal else CO.UNKNOWN if not all(proposal) else CO.NO_FINDING,
                "The proposal includes a weak algorithm or DH group." if weak_proposal
                else "A proposal field is not exported; the release default is not qualified." if not all(proposal)
                else "All exported proposal fields avoid the listed weak algorithms.",
                instance=instance,
            )
            weak = []
            for label, value, denied in (
                ("IKE encryption", policy.ike_encryption, self._WEAK_ENCRYPTION),
                ("IPsec encryption", policy.ipsec_encryption, self._WEAK_ENCRYPTION),
                ("IKE authentication", policy.ike_authentication, self._WEAK_AUTHENTICATION),
                ("IPsec authentication", policy.ipsec_authentication, self._WEAK_AUTHENTICATION),
                ("DH group", policy.dh_group, self._WEAK_DH),
            ):
                if value in denied:
                    weak.append(f"{label} {value}")
            if not weak:
                continue
            self.add_issue(
                Finding(
                    rule_id="sonicwall.sonicos.vpn.weak_proposal",
                    device=parser.device_type,
                    title="Active VPN policy uses a weak proposal",
                    observation=f"VPN policy '{policy.name}' uses " + ", ".join(weak) + ".",
                    impact="Legacy encryption, hashes, or DH groups weaken tunnel confidentiality and integrity.",
                    exploitability="A capable network attacker may exploit cryptographic weaknesses or downgrade-compatible peers.",
                    recommendation="Use AES-GCM or AES-256, SHA-256 or stronger authentication, and a current approved DH group.",
                    severity=Severity.HIGH,
                    evidence=tuple(item for item in policy.evidence),
                    references=(SONICOS_VPN_GUIDE, SONICOS_CLI_GUIDE),
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )

    def check_operations(self, parser: BaseDeviceParser) -> None:
        sonic = self._sonic(parser)
        snmp_enabled = sonic.get_services()["snmp"]
        if not snmp_enabled:
            record_control(parser, "sonicwall.sonicos.snmpv3-security",
                           CO.NOT_APPLICABLE if sonic.get_interfaces() else CO.UNKNOWN,
                           "SNMP management is not enabled on an interface." if sonic.get_interfaces()
                           else self._NO_INTERFACES)
        else:
            secure = sonic.has_secure_snmpv3_user()
            record_control(parser, "sonicwall.sonicos.snmpv3-security", CO.NO_FINDING if secure else CO.FINDING,
                           "An SNMPv3 SHA/AES user is configured." if secure
                           else "SNMP is enabled without an SNMPv3 SHA/AES user.", instance="secure-user")
            for user in sonic.get_snmpv3_users():
                fires = (user.authentication in {"none", "md5"} or user.privacy in {"none", "des", "3des"})
                strong = (user.authentication in {"sha", "sha256", "sha384", "sha512"}
                          and user.privacy in {"aes", "aes128", "aes192", "aes256", "aes_cfb128"})
                record_control(
                    parser, "sonicwall.sonicos.snmpv3-security",
                    CO.FINDING if fires else CO.NO_FINDING if strong else CO.UNKNOWN,
                    f"Authentication '{user.authentication}', privacy '{user.privacy}'"
                    + ("." if fires or strong else " (not a qualified algorithm)."),
                    instance=f"snmpv3 user {user.name}",
                )
        if snmp_enabled and not sonic.has_secure_snmpv3_user():
            self.add_issue(
                Finding(
                    rule_id="sonicwall.sonicos.snmp.secure_user_missing",
                    device=parser.device_type,
                    title="SNMP management lacks an authenticated private user",
                    observation="SNMP is enabled on an interface without a parsed SNMPv3 SHA/AES user.",
                    impact="Monitoring may rely on community credentials without authentication and confidentiality.",
                    exploitability="A reachable attacker can capture, guess, or misuse legacy SNMP credentials.",
                    recommendation="Configure SNMPv3 with authentication and privacy, then restrict SNMP to approved managers.",
                    severity=Severity.MEDIUM,
                    evidence=("SNMP interface management enabled without secure SNMPv3 user",),
                    references=(SONICOS_SYSTEM_GUIDE, SONICOS_CLI_GUIDE),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )
        if snmp_enabled:
            for user in sonic.get_snmpv3_users():
                evidence = tuple(item for item in user.evidence)
                missing = []
                if user.authentication == "none":
                    missing.append("authentication")
                if user.privacy == "none":
                    missing.append("privacy")
                if missing:
                    self.add_issue(
                        Finding(
                            rule_id="sonicwall.sonicos.snmp.v3_protection",
                            device=parser.device_type,
                            title="SNMPv3 user lacks complete protection",
                            observation=f"SNMPv3 user '{user.name}' lacks {' and '.join(missing)}.",
                            impact="SNMP management traffic may lack origin authentication or confidentiality.",
                            exploitability="A reachable or on-path attacker can target an under-protected identity.",
                            recommendation="Configure SHA authentication and AES privacy for every SNMPv3 user.",
                            severity=Severity.HIGH,
                            evidence=evidence,
                            references=(SONICOS_SYSTEM_GUIDE, SONICOS_CLI_GUIDE),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        )
                    )
                weak = []
                if user.authentication == "md5":
                    weak.append("MD5 authentication")
                if user.privacy in {"des", "3des"}:
                    weak.append(f"{user.privacy.upper()} privacy")
                if weak:
                    self.add_issue(
                        Finding(
                            rule_id="sonicwall.sonicos.snmp.v3_weak_algorithm",
                            device=parser.device_type,
                            title="SNMPv3 user uses weak algorithms",
                            observation=f"SNMPv3 user '{user.name}' uses {', '.join(weak)}.",
                            impact="Legacy SNMPv3 algorithms provide inadequate cryptographic protection.",
                            exploitability="A traffic observer can target weaknesses in legacy algorithms.",
                            recommendation="Use SHA authentication and AES privacy.",
                            severity=Severity.MEDIUM,
                            evidence=evidence,
                            references=(SONICOS_SYSTEM_GUIDE, SONICOS_CLI_GUIDE),
                            basis=FindingBasis.EXPLICIT_VALUE,
                        )
                    )
        record_control(
            parser, "sonicwall.sonicos.remote-logging",
            CO.NO_FINDING if sonic.get_syslog_destinations() else CO.FINDING,
            "An enabled syslog destination is configured." if sonic.get_syslog_destinations()
            else "No enabled syslog destination is configured.",
        )
        if not sonic.get_syslog_destinations():
            self.add_issue(
                Finding(
                    rule_id="sonicwall.sonicos.logging.remote_destination",
                    device=parser.device_type,
                    title="No enabled syslog destination is configured",
                    observation="No enabled SonicOS syslog server was found.",
                    impact="Security events may be lost through local rollover or appliance compromise.",
                    exploitability="An attacker with appliance access benefits from reduced external evidence.",
                    recommendation="Configure and enable redundant protected syslog destinations.",
                    severity=Severity.MEDIUM,
                    evidence=("enabled syslog destination absent",),
                    references=(SONICOS_CLI_GUIDE,),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )
        ntp_servers = sonic.get_ntp_server_records()
        record_control(parser, "sonicwall.sonicos.ntp-servers", CO.NO_FINDING if ntp_servers else CO.FINDING,
                       "A custom NTP server is configured." if ntp_servers else "No custom NTP server is configured.")
        if not ntp_servers:
            record_control(parser, "sonicwall.sonicos.ntp-authentication", CO.NOT_APPLICABLE,
                           "No custom NTP server is configured.")
        for server in ntp_servers:
            record_control(
                parser, "sonicwall.sonicos.ntp-authentication", CO.NO_FINDING if server.authenticated else CO.FINDING,
                "Matching trust/key numbers, algorithm and key material are configured." if server.authenticated
                else "Authentication fields are incomplete or absent.",
                instance=f"ntp server {server.address}",
            )
        if not ntp_servers:
            self.add_issue(
                Finding(
                    rule_id="sonicwall.sonicos.ntp.servers",
                    device=parser.device_type,
                    title="No custom NTP server is configured",
                    observation="No active SonicOS 'ntp-server' entry was found.",
                    impact="Incorrect timestamps hinder event correlation and authentication troubleshooting.",
                    exploitability="Inconsistent time reduces the reliability of security monitoring and forensic timelines.",
                    recommendation="Configure redundant trusted NTP servers and authenticate them where supported.",
                    severity=Severity.LOW,
                    evidence=("custom NTP server absent",),
                    references=(SONICOS_CLI_GUIDE,),
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
                )
            )
        else:
            for server in ntp_servers:
                if server.authenticated:
                    continue
                self.add_issue(
                    Finding(
                        rule_id="sonicwall.sonicos.ntp.authentication",
                        device=parser.device_type,
                        title="NTP server lacks complete authentication",
                        observation=f"Active NTP server '{server.address}' lacks matching trust/key numbers, MD5 selection, or configured key material.",
                        impact="Unauthenticated time responses can corrupt log chronology and time-dependent authentication behavior.",
                        exploitability="A network-positioned attacker may spoof NTP responses if routing and filtering permit it.",
                        recommendation="Configure the platform-supported authenticated NTP fields for every custom server and restrict management-plane reachability.",
                        severity=Severity.MEDIUM,
                        evidence=tuple(item for item in server.evidence),
                        references=(SONICOS_CLI_GUIDE,),
                        basis=FindingBasis.REQUIRED_SETTING_MISSING,
                    )
                )
        services = sonic.get_security_services()
        disabled = [name for name, state in services.items() if state is False]
        for name, state in services.items():
            record_control(
                parser, "sonicwall.sonicos.security-services",
                CO.FINDING if state is False else CO.NO_FINDING if state else CO.UNKNOWN,
                "Explicitly disabled." if state is False else "Explicitly enabled (licensing and runtime not assessed)."
                if state else "Not exported; default and licensing are not qualified.",
                instance=name,
            )
        if disabled:
            self.add_issue(
                Finding(
                    rule_id="sonicwall.sonicos.security_services.disabled",
                    device=parser.device_type,
                    title="Threat-prevention services are explicitly disabled",
                    observation="Explicitly disabled services: " + ", ".join(disabled) + ".",
                    impact="Traffic may bypass malware, intrusion, or spyware inspection.",
                    exploitability="Attackers can deliver threats that the disabled inspection service would otherwise detect.",
                    recommendation="Enable the applicable licensed security services and attach them to relevant policies.",
                    severity=Severity.HIGH,
                    evidence=tuple(f"no {name} enable" for name in disabled),
                    references=(SONICOS_SYSTEM_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )
        labels = {"intrusion-prevention": "intrusion prevention", "gateway-anti-virus": "gateway anti-virus",
                  "anti-spyware": "anti-spyware"}
        if not sonic.get_zone_security_services():
            record_control(parser, "sonicwall.sonicos.zone-security-services", CO.UNKNOWN,
                           "No zone record is exported; zone security-service state is not established.")
        for zone in sonic.get_zone_security_services():
            off = [name for name, enabled in zone.services.items()
                   if enabled is False and services.get(name) is not False]
            relevant = [name for name in labels if services.get(name) is not False]
            if not zone.active_interfaces:
                outcome, reason = CO.NOT_APPLICABLE, "The zone has no enabled interface."
            elif off:
                outcome, reason = CO.FINDING, "The zone explicitly disables " + ", ".join(off) + "."
            elif not relevant:
                outcome, reason = CO.NOT_APPLICABLE, "All zone services are disabled globally (reported globally)."
            elif all(zone.services.get(name) is True for name in relevant):
                outcome, reason = CO.NO_FINDING, "The zone explicitly enables the globally available services."
            else:
                outcome, reason = CO.UNKNOWN, "A zone service switch is omitted; the zone default is not qualified."
            record_control(parser, "sonicwall.sonicos.zone-security-services", outcome, reason,
                           instance=f"zone {zone.name}")
            if not off or not zone.active_interfaces:
                continue
            self.add_issue(Finding(
                rule_id="sonicwall.sonicos.zone.security_service_disabled",
                device=parser.device_type,
                title="Security services are disabled for a zone in use",
                observation=(
                    f"Zone '{zone.name}' (active interfaces: {', '.join(zone.active_interfaces)}) explicitly disables "
                    + ", ".join(labels[name] for name in off) + "."
                ),
                impact="Traffic in this zone is not inspected by the disabled services, even where they are enabled globally.",
                exploitability="Threats that the disabled service would detect can pass through interfaces in this zone.",
                recommendation="Enable the services in the zone ('intrusion-prevention', 'gateway-anti-virus', 'anti-spyware') unless an approved exception applies.",
                severity=Severity.HIGH,
                evidence=zone.evidence,
                references=(SONICOS_CLI_GUIDE,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        dependencies = (services["gateway-anti-virus"], services["cloud-gateway-anti-virus"])
        if services["capture-atp"] is True:
            record_control(
                parser, "sonicwall.sonicos.capture-atp-dependencies",
                CO.FINDING if False in dependencies else CO.NO_FINDING if all(dependencies) else CO.UNKNOWN,
                "A Gateway Anti-Virus dependency is explicitly disabled." if False in dependencies
                else "Both Gateway Anti-Virus dependencies are enabled." if all(dependencies)
                else "A Gateway Anti-Virus dependency is not exported.",
            )
        else:
            record_control(
                parser, "sonicwall.sonicos.capture-atp-dependencies",
                CO.NOT_APPLICABLE if services["capture-atp"] is False else CO.UNKNOWN,
                "Capture ATP is disabled." if services["capture-atp"] is False
                else "Capture ATP state is not exported.",
            )
        if services["capture-atp"] is True and (
            services["gateway-anti-virus"] is False
            or services["cloud-gateway-anti-virus"] is False
        ):
            unavailable = [
                name for name in ("gateway-anti-virus", "cloud-gateway-anti-virus")
                if services[name] is False
            ]
            self.add_issue(
                Finding(
                    rule_id="sonicwall.sonicos.capture_atp.dependencies",
                    device=parser.device_type,
                    title="Capture ATP has an explicitly disabled antivirus dependency",
                    observation="Capture ATP is enabled while these required services are explicitly disabled: " + ", ".join(unavailable) + ".",
                    impact="Capture ATP cannot provide its intended file analysis while its Gateway Anti-Virus dependencies are disabled.",
                    exploitability="Malicious files can traverse paths that operators may incorrectly believe receive Capture ATP analysis.",
                    recommendation="Enable both Gateway Anti-Virus and Cloud Gateway Anti-Virus, verify licensing, and confirm applicable protocol inspection.",
                    severity=Severity.HIGH,
                    evidence=tuple(["capture-atp enable", *(f"no {name} enable" for name in unavailable)]),
                    references=(SONICOS_CAPTURE_ATP_GUIDE,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                )
            )

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_management(parser)
        self.check_administration(parser)
        self.check_access_rules(parser)
        self.check_policy_effectiveness(parser)
        self.check_vpn(parser)
        self.check_operations(parser)
