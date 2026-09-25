"""Effective-state Arista EOS management and operational baseline checks."""

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.credentials import credential_policy_from_context, evaluate_credential
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.arista.eos import AristaEOSParser
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.common.models import CredentialStorageAssessment


ARISTA_SESSION_GUIDE = "https://www.arista.com/en/um-eos/eos-session-management-commands"
ARISTA_ACL_GUIDE = "https://www.arista.com/en/um-eos/eos-acls-and-route-maps"
ARISTA_SNMP_GUIDE = "https://www.arista.com/en/um-eos/eos-snmp"
ARISTA_TIME_GUIDE = "https://www.arista.com/en/um-eos/eos-system-clock-and-time-protocols"
ARISTA_SECURITY_GUIDE = "https://www.arista.com/en/um-eos/eos-security"
ARISTA_USER_SECURITY_GUIDE = "https://www.arista.com/en/um-eos/eos-user-security"
ARISTA_DISPLAY_GUIDE = "https://www.arista.com/en/um-eos/eos-managing-display-attributes"
ARISTA_TLS_GUIDE = "https://www.arista.com/en/um-eos/eos-control-plane-security"
ARISTA_CONTROL_PLANE_GUIDE = "https://www.arista.com/en/um-eos/eos-traffic-management"
ARISTA_CONTROL_PLANE_ACL_GUIDE = "https://www.arista.com/en/um-eos/eos-data-transfer"
ARISTA_STP_GUIDE = "https://www.arista.com/en/um-eos/eos-spanning-tree-protocol"
ARISTA_LOGGING_GUIDE = "https://www.arista.com/en/um-eos/eos-switch-administration-commands"


class PluginAristaChecks(BasePlugin):
    # NEEDS_HUMAN_REVIEW: this project policy classifies explicit CBC/3DES/RC4,
    # SHA-1, and MD5 choices as weak; align it with the organization's approved
    # interoperability and cryptographic standard before deployment.
    _WEAK_SSH = {
        "cipher": {"3des-cbc", "arcfour", "aes128-cbc", "aes192-cbc", "aes256-cbc"},
        "key exchange": {
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group14-sha",
        },
        "MAC": {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96"},
    }
    @staticmethod
    def _eos(parser: BaseDeviceParser) -> AristaEOSParser:
        if not isinstance(parser, AristaEOSParser):
            raise TypeError("PluginAristaChecks requires an AristaEOSParser")
        return parser

    def check_management_api(self, parser: BaseDeviceParser) -> None:
        for endpoint in self._eos(parser).get_eapi_endpoints():
            if not endpoint.active:
                continue
            evidence = tuple(item for item in endpoint.evidence)
            if endpoint.http:
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.eapi.insecure_http",
                        device=parser.device_type,
                        title="eAPI permits clear-text HTTP",
                        observation=f"The active eAPI endpoint in VRF '{endpoint.scope}' enables HTTP.",
                        impact="API credentials, commands, and responses can be exposed or modified in transit.",
                        exploitability="An attacker with path access to the endpoint can intercept a clear-text management session.",
                        recommendation="Remove 'protocol http', retain HTTPS, and use a trusted TLS certificate.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(ARISTA_SESSION_GUIDE,),
                    )
                )
            if not endpoint.https:
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.eapi.https_disabled",
                        device=parser.device_type,
                        title="Active eAPI endpoint has HTTPS disabled",
                        observation=f"The active eAPI endpoint in VRF '{endpoint.scope}' explicitly disables HTTPS.",
                        impact="The API lacks its protected HTTPS transport.",
                        exploitability="Management may fall back to clear-text HTTP or become dependent on other unverified controls.",
                        recommendation="Enable 'protocol https' and configure an approved certificate and TLS profile.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(ARISTA_SESSION_GUIDE,),
                    )
                )
            if not endpoint.ipv4_acl and not endpoint.ipv6_acl:
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.eapi.source_restriction",
                        device=parser.device_type,
                        title="eAPI endpoint lacks a service ACL",
                        observation=f"The active eAPI endpoint in VRF '{endpoint.scope}' has no IPv4 or IPv6 access-group.",
                        impact="All routed clients in the endpoint VRF can attempt API access.",
                        exploitability="Any host with VRF reachability can probe the service or attempt authentication.",
                        recommendation="Apply explicit IPv4 and, where applicable, IPv6 service ACLs to each enabled eAPI VRF.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(ARISTA_ACL_GUIDE,),
                    )
                )

    def check_authentication(self, parser: BaseDeviceParser) -> None:
        eos = self._eos(parser)
        remote_cli = any(
            session.applicable is True and session.channel in {"ssh", "telnet"}
            for session in eos.get_management_sessions()
        )
        if not any(endpoint.active for endpoint in eos.get_eapi_endpoints()) and not remote_cli:
            return
        if eos.get_remote_authentication():
            return
        self.add_issue(
            Finding(
                rule_id="arista.eos.authentication.centralized",
                device=parser.device_type,
                title="eAPI authentication is not backed by centralized AAA",
                observation="eAPI is active but no RADIUS or TACACS+ login method was parsed.",
                impact="Local-only accounts reduce centralized revocation, policy enforcement, and auditability.",
                exploitability="Compromise of a local credential can provide management access independently of the central identity system.",
                recommendation="Configure centralized AAA for the login method with a controlled emergency local fallback.",
                severity=Severity.MEDIUM,
                evidence=("active eAPI without parsed centralized AAA",),
                references=(ARISTA_SECURITY_GUIDE,),
            )
        )

    def check_administrative_policy(self, parser: BaseDeviceParser) -> None:
        eos = self._eos(parser)
        endpoints = eos.get_eapi_endpoints()
        sessions = eos.get_management_sessions()
        interactive = [item for item in sessions if item.applicable is True]
        remote_active = any(endpoint.active for endpoint in endpoints) or any(
            item.channel in {"ssh", "telnet"} for item in interactive
        )

        for administrator in eos.get_administrators():
            if administrator.role_resolved:
                continue
            self.add_issue(Finding(
                rule_id="arista.eos.admin.role_reference",
                device=parser.device_type,
                title="Local administrator references an undefined role",
                observation=f"Local user '{administrator.name}' resolves to role '{administrator.role}', which is not defined in the export.",
                impact="The intended command authorization boundary cannot be established from the configuration.",
                exploitability="A fallback/default role may grant different access than operators intended.",
                recommendation="Define the referenced role or assign a verified built-in/custom role explicitly.",
                severity=Severity.HIGH,
                evidence=tuple(item for item in administrator.evidence),
                references=(ARISTA_USER_SECURITY_GUIDE,),
            ))

        for policy in eos.get_aaa_policies():
            if policy.unauthenticated is not True:
                continue
            applicable = (
                policy.connection == "console" and any(item.channel == "console" for item in interactive)
            ) or (
                policy.connection == "default" and remote_active
            )
            if not applicable:
                continue
            self.add_issue(Finding(
                rule_id="arista.eos.authentication.unauthenticated_method",
                device=parser.device_type,
                title="Applicable AAA policy includes a bypass method",
                observation=(
                    f"The effective {policy.policy_type} {policy.service} {policy.connection} method list includes 'none', "
                    f"which EOS documents as permitting the {policy.policy_type} action without validation."
                ),
                impact="The fallback can admit a session or command without the intended AAA decision.",
                exploitability="A reachable user can be accepted if earlier methods are unavailable and EOS reaches the none method.",
                recommendation="Remove 'none' and use an approved centralized method with a controlled local emergency fallback.",
                severity=Severity.CRITICAL,
                evidence=tuple(item for item in policy.evidence),
                references=(ARISTA_USER_SECURITY_GUIDE,),
            ))

        remote_auth = eos.get_remote_authentication()
        if remote_active and remote_auth:
            aaa = eos.get_aaa_policies()
            commands_authorized = any(
                item.policy_type == "authorization"
                and
                item.service == "commands-all"
                and item.connection == "default"
                and item.methods is not None
                and (item.centralized or "local" in item.methods)
                and not item.unauthenticated
                for item in aaa
            )
            if not commands_authorized:
                self.add_issue(Finding(
                    rule_id="arista.eos.authorization.commands",
                    device=parser.device_type,
                    title="Centralized login lacks command authorization",
                    observation="Remote login authentication is configured without an effective default all-command authorization method list.",
                    impact="Authenticated users may execute commands outside the intended central or local RBAC policy.",
                    exploitability="A compromised account can receive broader CLI access than the identity service intended.",
                    recommendation="Configure 'aaa authorization commands all default' using the approved service and controlled fallback.",
                    severity=Severity.HIGH,
                    evidence=("centralized login authentication without all-command authorization",),
                    references=(ARISTA_USER_SECURITY_GUIDE,),
                ))

            accounting = eos.get_accounting_policies()
            covered = {
                item.service
                for item in accounting
                if item.connection == "default"
                and item.mode in {"start-stop", "stop-only", "stop"}
                and item.destinations
                and "none" not in item.destinations
            }
            missing = sorted({"exec", "commands-all"} - covered)
            if missing:
                self.add_issue(Finding(
                    rule_id="arista.eos.authentication.accounting",
                    device=parser.device_type,
                    title="Centralized administrative access lacks complete accounting",
                    observation="Default AAA accounting is missing for: " + ", ".join(missing) + ".",
                    impact="Login sessions or executed commands may lack an independent audit trail.",
                    exploitability="A compromised administrator can act with reduced centralized evidence.",
                    recommendation="Configure default EXEC and all-command accounting to TACACS+, RADIUS, or protected syslog.",
                    severity=Severity.MEDIUM,
                    evidence=tuple(
                        evidence for item in accounting for evidence in item.evidence
                    ) or ("default EXEC/all-command accounting incomplete",),
                    references=(ARISTA_USER_SECURITY_GUIDE,),
                ))

        lockout = eos.get_lockout_policy()
        if remote_active and lockout.enabled is False:
            self.add_issue(Finding(
                rule_id="arista.eos.authentication.lockout_disabled",
                device=parser.device_type,
                title="Remote login lockout is disabled",
                observation="An explicit management service is active while the EOS AAA time-based lockout policy is disabled by default or reset.",
                impact="The switch does not locally suspend accounts after repeated failed remote logins.",
                exploitability="A reachable attacker can sustain password-guessing attempts.",
                recommendation="Configure AAA lockout with no more than five failures and a duration of at least 300 seconds.",
                severity=Severity.HIGH,
                evidence=tuple(item for item in lockout.evidence) or (
                    "identified EOS release default: AAA time-based lockout disabled",
                ),
                references=(ARISTA_USER_SECURITY_GUIDE,),
                basis=(
                    FindingBasis.EXPLICIT_VALUE if lockout.evidence
                    else FindingBasis.DOCUMENTED_DEFAULT
                ),
            ))
        elif remote_active and lockout.enabled is True:
            weak = []
            if lockout.failure_count is not None and lockout.failure_count > 5:
                weak.append(f"{lockout.failure_count} failures")
            if lockout.duration_seconds is not None and lockout.duration_seconds < 300:
                weak.append(f"{lockout.duration_seconds}-second duration")
            if weak:
                self.add_issue(Finding(
                    rule_id="arista.eos.authentication.lockout_policy",
                    device=parser.device_type,
                    title="Remote login lockout thresholds are weak",
                    observation="The explicit lockout policy uses " + " and ".join(weak) + ".",
                    impact="The switch permits excessive guesses or restores access too quickly.",
                    exploitability="A reachable attacker receives more opportunities to guess a password.",
                    recommendation="Allow no more than five failures and lock the account for at least 300 seconds.",
                    severity=Severity.MEDIUM,
                    evidence=tuple(item for item in lockout.evidence),
                    references=(ARISTA_USER_SECURITY_GUIDE,),
                ))

        local_admin_path = bool(eos.get_administrators()) and remote_active and any(
            policy.policy_type == "authentication"
            and policy.service == "login"
            and policy.connection == "default"
            and policy.methods is not None
            and "local" in policy.methods
            for policy in eos.get_aaa_policies()
        )
        password_minimum = eos.get_password_minimum_policy()
        if local_admin_path and password_minimum.resolution_state in {
            "explicit-disabled", "explicit"
        } and (
            password_minimum.resolution_state == "explicit-disabled"
            or password_minimum.minimum_length == 1
        ):
            self.add_issue(Finding(
                rule_id="arista.eos.admin.local_password_minimum_ineffective",
                device=parser.device_type,
                title="EOS local administrative password minimum is ineffective",
                observation=(
                    "The global local-password policy is explicitly disabled."
                    if password_minimum.resolution_state == "explicit-disabled" else
                    "The explicit global minimum permits a one-character local password."
                ),
                impact="New or changed local administrator passwords may be trivially weak; existing secret strength is not inferred.",
                exploitability="An attacker with a reachable local-login path has more opportunity to guess a short password.",
                recommendation="Enable a local password minimum aligned with the approved administrative-password policy.",
                severity=Severity.MEDIUM,
                evidence=tuple(item for item in password_minimum.evidence),
                references=(ARISTA_SESSION_GUIDE,),
            ))

        for session in interactive:
            if session.resolution_state == "invalid" or session.idle_timeout_minutes is None:
                continue
            if 0 < session.idle_timeout_minutes <= 10:
                continue
            self.add_issue(Finding(
                rule_id="arista.eos.admin.idle_timeout",
                device=parser.device_type,
                title=f"{session.channel.upper()} administrative idle timeout is " + (
                    "disabled" if session.idle_timeout_minutes == 0 else "excessive"
                ),
                observation=(
                    f"The {session.channel} idle timeout is disabled."
                    if session.idle_timeout_minutes == 0
                    else f"The {session.channel} idle timeout is {session.idle_timeout_minutes} minutes, above the 10-minute project target."
                ),
                impact="An unattended authenticated management session can remain usable longer than intended.",
                exploitability="A person or process with access to an abandoned session can inherit its privileges.",
                recommendation=f"Set the {session.channel} idle-timeout to ten minutes or less.",
                severity=Severity.MEDIUM,
                evidence=tuple(item for item in session.evidence),
                references=(ARISTA_SESSION_GUIDE,),
            ))

        banner = eos.get_banner_policy()
        if interactive and banner.login_enabled is False:
            self.add_issue(Finding(
                rule_id="arista.eos.admin.login_banner",
                device=parser.device_type,
                title="Pre-login administrative notice is not configured",
                observation="An interactive management channel is explicitly configured without an effective login banner.",
                impact="Users are not shown the organization's authorization and monitoring notice before login.",
                exploitability="This is primarily a governance and legal-notice control rather than a direct technical exploit.",
                recommendation="Configure an approved 'banner login' notice and validate it before the credential prompt.",
                severity=Severity.LOW,
                evidence=tuple(item for item in banner.evidence) or (
                    "banner login absent from identified EOS configuration",
                ),
                references=(ARISTA_DISPLAY_GUIDE,),
            ))

        profiles = eos.get_ssl_profiles()
        for endpoint in endpoints:
            if not endpoint.active or not endpoint.https:
                continue
            evidence = tuple(item for item in endpoint.evidence)
            if not endpoint.ssl_profile:
                self.add_issue(Finding(
                    rule_id="arista.eos.eapi.tls_profile",
                    device=parser.device_type,
                    title="eAPI HTTPS lacks an explicit SSL profile",
                    observation=f"The active HTTPS eAPI endpoint in VRF '{endpoint.scope}' does not attach an SSL profile.",
                    impact="Certificate identity and TLS-version policy remain dependent on an implicit service default.",
                    exploitability="Administrators may receive an unexpected certificate or negotiate an unintended legacy protocol.",
                    recommendation="Attach a named SSL profile with an approved certificate and TLS 1.2 or 1.3 policy.",
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                    references=(ARISTA_TLS_GUIDE, ARISTA_SESSION_GUIDE),
                ))
                continue
            profile = profiles.get(endpoint.ssl_profile.casefold())
            if profile is None:
                self.add_issue(Finding(
                    rule_id="arista.eos.eapi.tls_profile_reference",
                    device=parser.device_type,
                    title="eAPI HTTPS references an undefined SSL profile",
                    observation=f"The active HTTPS eAPI endpoint in VRF '{endpoint.scope}' references '{endpoint.ssl_profile}', which is absent.",
                    impact="The intended HTTPS identity and protocol policy cannot be established.",
                    exploitability="The service can fail or use behavior different from the intended profile.",
                    recommendation="Define the referenced SSL profile and attach its certificate and TLS-version policy.",
                    severity=Severity.HIGH,
                    evidence=evidence,
                    references=(ARISTA_TLS_GUIDE, ARISTA_SESSION_GUIDE),
                ))
                continue
            profile_evidence = evidence + tuple(item for item in profile.evidence)
            if not profile.certificate:
                self.add_issue(Finding(
                    rule_id="arista.eos.eapi.tls_certificate",
                    device=parser.device_type,
                    title="Attached eAPI SSL profile lacks a certificate",
                    observation=f"SSL profile '{profile.name}' is attached to active eAPI HTTPS but has no certificate declaration.",
                    impact="The switch cannot present the intended managed identity from this profile.",
                    exploitability="Clients may reject the service or accept an unintended fallback identity.",
                    recommendation="Configure an approved certificate and matching private key in the attached SSL profile.",
                    severity=Severity.HIGH,
                    evidence=profile_evidence,
                    references=(ARISTA_TLS_GUIDE,),
                ))
            if profile.tls_versions is not None and set(profile.tls_versions) & {"1.0", "1.1"}:
                self.add_issue(Finding(
                    rule_id="arista.eos.eapi.legacy_tls",
                    device=parser.device_type,
                    title="Attached eAPI SSL profile permits legacy TLS",
                    observation=f"SSL profile '{profile.name}' explicitly permits: {', '.join(profile.tls_versions)}.",
                    impact="Administrative API sessions can negotiate obsolete TLS versions.",
                    exploitability="A network-positioned attacker can target clients that negotiate the legacy protocol.",
                    recommendation="Restrict the attached SSL profile to TLS 1.2 and 1.3.",
                    severity=Severity.HIGH,
                    evidence=profile_evidence,
                    references=(ARISTA_TLS_GUIDE,),
                ))

    def check_ssh_and_authorization(self, parser: BaseDeviceParser) -> None:
        eos = self._eos(parser)
        ssh = eos.get_ssh_settings()
        if ssh.configured:
            evidence = tuple(item for item in ssh.evidence)
            if ssh.empty_passwords == "permit":
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.ssh.empty_passwords",
                        device=parser.device_type,
                        title="SSH explicitly permits empty passwords",
                        observation="The management SSH policy sets 'authentication empty-passwords permit'.",
                        impact="A local account without a password can be used remotely over SSH.",
                        exploitability="A reachable attacker can attempt authentication to empty-password accounts without possessing a credential.",
                        recommendation="Set 'authentication empty-passwords deny' and ensure every local account has an approved credential.",
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                        references=(ARISTA_SESSION_GUIDE,),
                    )
                )
            weak = {
                "cipher": sorted(set(ssh.ciphers) & self._WEAK_SSH["cipher"]),
                "key exchange": sorted(set(ssh.key_exchanges) & self._WEAK_SSH["key exchange"]),
                "MAC": sorted(set(ssh.macs) & self._WEAK_SSH["MAC"]),
            }
            weak = {name: values for name, values in weak.items() if values}
            if weak:
                summary = "; ".join(f"{name}: {', '.join(values)}" for name, values in weak.items())
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.ssh.weak_algorithms",
                        device=parser.device_type,
                        title="SSH explicitly permits legacy algorithms",
                        observation=f"The explicit management SSH suite contains {summary}.",
                        impact="Legacy CBC/3DES/RC4, SHA-1, or MD5 algorithms weaken management transport protection.",
                        exploitability="A network-positioned attacker may exploit downgrade compatibility or weaknesses in a negotiated legacy algorithm.",
                        recommendation="Remove the listed algorithms and retain modern AES-GCM/CTR, SHA-2, Curve25519, ECDH, or strong finite-field DH choices.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(ARISTA_SESSION_GUIDE,),
                    )
                )
            if not ssh.ipv4_acls and not ssh.ipv6_acls:
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.ssh.source_restriction",
                        device=parser.device_type,
                        title="Explicit SSH service policy lacks access groups",
                        observation="A management SSH block is configured without an IPv4 or IPv6 service ACL.",
                        impact="Every routed source that can reach the switch can attempt SSH authentication.",
                        exploitability="A reachable attacker can probe the daemon, guess credentials, or target SSH implementation flaws.",
                        recommendation="Apply IPv4 and, where applicable, IPv6 access groups in management SSH configuration for each management VRF.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(ARISTA_ACL_GUIDE, ARISTA_SESSION_GUIDE),
                    )
                )

        if eos.get_remote_authentication() and not eos.has_exec_authorization():
            self.add_issue(
                Finding(
                    rule_id="arista.eos.authorization.exec",
                    device=parser.device_type,
                    title="Centralized login lacks exec authorization",
                    observation="RADIUS or TACACS+ login authentication is configured without an active centralized exec authorization method.",
                    impact="Authenticated users may receive locally determined command access that is broader than central policy intends.",
                    exploitability="A compromised or overprivileged account can exercise commands not constrained by centralized authorization.",
                    recommendation="Configure AAA exec authorization through the approved central service with a controlled local fallback.",
                    severity=Severity.MEDIUM,
                    evidence=("centralized login authentication without aaa authorization exec",),
                    references=(ARISTA_SECURITY_GUIDE,),
                )
            )

    def check_snmp(self, parser: BaseDeviceParser) -> None:
        eos = self._eos(parser)
        if not eos.get_snmp_default_vrf_enabled():
            return
        communities = eos.get_snmp_communities()
        for name, evidence in communities:
            if name in {"public", "private"}:
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.snmp.default_community",
                        device=parser.device_type,
                        title="Default SNMP community is configured",
                        observation=f"The exact default community '{name}' is active.",
                        impact="A widely known community string can enable unauthorized SNMP queries or changes.",
                        exploitability="An attacker needs SNMP reachability and can try the known value directly.",
                        recommendation="Remove the default community and use authenticated, encrypted SNMPv3.",
                        severity=Severity.HIGH,
                        evidence=(evidence,),
                        references=(ARISTA_SNMP_GUIDE,),
                    )
                )
        if communities and not eos.has_secure_snmpv3_user():
            self.add_issue(
                Finding(
                    rule_id="arista.eos.snmp.secure_user_missing",
                    device=parser.device_type,
                    title="Community SNMP lacks a secure SNMPv3 replacement",
                    observation="SNMP community access is configured without a parsed SNMPv3 user using SHA authentication and AES privacy.",
                    impact="Management traffic may depend on reusable community credentials without confidentiality.",
                    exploitability="A network-positioned attacker can capture or guess a community value.",
                    recommendation="Configure an SNMPv3 authPriv user and remove community-based access.",
                    severity=Severity.MEDIUM,
                    evidence=tuple(item for _, item in communities),
                    references=(ARISTA_SNMP_GUIDE,),
                )
            )

        views, groups, users = eos.get_snmpv3_relationships()
        view_map = {view.name.casefold(): view for view in views}
        group_map = {group.name.casefold(): group for group in groups}
        for user in users:
            evidence = tuple(item for item in user.evidence)
            if not user.group_resolved or (user.read_view and not user.read_view_resolved):
                unresolved = f"group '{user.group}'" if not user.group_resolved else f"view '{user.read_view}'"
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.snmp.v3_reference",
                        device=parser.device_type,
                        title="SNMPv3 user references an unresolved access object",
                        observation=f"SNMPv3 user '{user.name}' references unresolved {unresolved}.",
                        impact="The intended user security and view scope cannot be established.",
                        exploitability="A configuration error may leave monitoring unavailable or outside the intended policy.",
                        recommendation="Bind the user to an active v3 priv group and a defined read view.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(ARISTA_SNMP_GUIDE,),
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
                        rule_id="arista.eos.snmp.v3_protection",
                        device=parser.device_type,
                        title="SNMPv3 user lacks authPriv protection",
                        observation=f"SNMPv3 user '{user.name}' has " + ", ".join(gaps) + ".",
                        impact="SNMP management data may lack strong authentication or confidentiality.",
                        exploitability="A reachable or on-path attacker can target an under-protected identity.",
                        recommendation="Use a v3 priv group with SHA authentication and AES privacy.",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        references=(ARISTA_SNMP_GUIDE,),
                    )
                )
            weak = []
            if user.authentication == "md5":
                weak.append("MD5 authentication")
            if user.privacy == "des":
                weak.append("DES privacy")
            if weak:
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.snmp.v3_weak_algorithm",
                        device=parser.device_type,
                        title="SNMPv3 user uses weak algorithms",
                        observation=f"SNMPv3 user '{user.name}' uses {', '.join(weak)}.",
                        impact="Legacy SNMPv3 algorithms provide inadequate cryptographic strength.",
                        exploitability="A traffic observer can target weaknesses in legacy algorithms.",
                        recommendation="Use SHA authentication and AES privacy supported by the deployed EOS release.",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        references=(ARISTA_SNMP_GUIDE,),
                    )
                )
            group = group_map.get(user.group.casefold())
            view = view_map.get(user.read_view.casefold()) if user.read_view else None
            broad_view = not user.read_view or bool(
                view
                and set(view.included_subtrees) & {"iso", "internet", "1", "1.3.6.1"}
                and not view.excluded_subtrees
            )
            access_gaps = []
            if not user.source_restricted:
                access_gaps.append("no SNMP source ACL in the default VRF")
            if broad_view:
                access_gaps.append("the default or an unrestricted read view")
            if group and group.write_view:
                access_gaps.append(f"write view '{group.write_view}'")
            if access_gaps:
                self.add_issue(
                    Finding(
                        rule_id="arista.eos.snmp.v3_access_scope",
                        device=parser.device_type,
                        title="SNMPv3 user has broad access scope",
                        observation=f"SNMPv3 user '{user.name}' has " + "; ".join(access_gaps) + ".",
                        impact="A compromised user may reach the agent from unintended networks or access excessive MIB objects.",
                        exploitability="The user credential is useful from any reachable source allowed by external controls.",
                        recommendation="Apply an SNMP IPv4/IPv6 ACL and a least-privileged read view; avoid write views unless required.",
                        severity=Severity.HIGH if group and group.write_view else Severity.MEDIUM,
                        evidence=evidence,
                        references=(ARISTA_SNMP_GUIDE,),
                    )
                )

    def check_credentials(self, parser: BaseDeviceParser) -> None:
        policy = credential_policy_from_context(parser.assessment_context)
        for credential in self._eos(parser).get_credential_metadata():
            result = evaluate_credential(credential, policy)
            if not result.unsafe_storage:
                continue
            self.add_issue(
                Finding(
                    rule_id="arista.eos.credentials.local_storage",
                    device=parser.device_type,
                    title="Local credential uses unsafe storage",
                    observation=(
                        f"User '{credential.account}' has storage classified as "
                        f"'{result.storage_assessment.value}' from format "
                        f"'{credential.storage_type}' under credential policy '{result.policy_version}'; "
                        f"the separate default comparison {result.default_summary}, and the blocklist "
                        f"comparison {result.blocklist_summary}."
                    ),
                    impact="An empty, plaintext, reversible, or legacy-hashed local credential can enable account compromise.",
                    exploitability="An attacker may use an empty/default credential directly or recover exposed weakly stored material.",
                    recommendation="Set a unique credential and allow EOS to store it with the supported SHA-512 representation; prefer centralized AAA.",
                    severity=(
                        Severity.CRITICAL
                        if credential.storage_assessment == CredentialStorageAssessment.EMPTY
                        else Severity.HIGH
                    ),
                    evidence=tuple(item for item in credential.evidence),
                    references=(ARISTA_SECURITY_GUIDE,),
                )
            )

        for credential in self._eos(parser).get_additional_credential_metadata():
            result = evaluate_credential(credential, policy)
            if not result.unsafe_storage:
                continue
            token = credential.context == "terminattr_ingestauth"
            self.add_issue(Finding(
                rule_id=("arista.eos.credentials.terminattr_literal" if token
                         else "arista.eos.credentials.radius_storage"),
                device=parser.device_type,
                title="Literal TerminAttr ingestion token in configuration" if token else "RADIUS key uses unsafe storage",
                observation=(
                    f"The {'TerminAttr ingestion token' if token else 'RADIUS shared key'} at "
                    f"'{credential.account}' is stored as '{result.storage_assessment.value}' "
                    f"under credential policy '{result.policy_version}'. Its value is redacted."
                ),
                impact="Configuration disclosure can expose or permit recovery of this authentication material.",
                exploitability="An attacker who obtains the configuration may acquire the authentication material; runtime reachability and reuse are not inferred.",
                recommendation="Rotate the value and use an appropriately protected authentication method where supported.",
                severity=Severity.HIGH,
                evidence=tuple(item for item in credential.evidence),
                references=(ARISTA_USER_SECURITY_GUIDE,),
            ))

    def check_operations(self, parser: BaseDeviceParser) -> None:
        eos = self._eos(parser)
        destinations = eos.get_logging_destinations()
        logging = eos.get_logging_severity_policy()
        if not destinations:
            self.add_issue(
                Finding(
                    rule_id="arista.eos.logging.remote_destination",
                    device=parser.device_type,
                    title="No remote syslog destination is configured",
                    observation="No active remote syslog destination is effective; no host is configured or system logging is explicitly disabled.",
                    impact="Security events may be lost through local rollover or device compromise.",
                    exploitability="An attacker with device access benefits from reduced external evidence.",
                    recommendation="Configure protected, redundant remote syslog destinations.",
                    severity=Severity.MEDIUM,
                    evidence=("remote logging destination absent",),
                    references=(ARISTA_SECURITY_GUIDE,),
                )
            )
        if (destinations and logging.logging_on is not False
                and logging.trap_state == "explicit"
                and logging.trap_level is not None and logging.trap_level < 3):
            self.add_issue(Finding(
                rule_id="arista.eos.logging.remote_severity_excludes_errors",
                device=parser.device_type,
                title="EOS remote logging excludes error-severity events",
                observation=(
                    f"An explicit remote trap threshold of {logging.trap_level} forwards "
                    "only more urgent events; error-severity (level 3) events are excluded "
                    f"from {len(destinations)} configured remote destination(s)."
                ),
                impact="Error-severity security and operational events can be absent from central monitoring.",
                exploitability="A device fault or hostile action logged at error severity may not reach the remote collector.",
                recommendation="Set the remote trap threshold to errors (3) or a more inclusive approved level.",
                severity=Severity.MEDIUM,
                evidence=tuple(item for item in logging.trap_evidence)
                + tuple(item for destination in destinations for item in destination.evidence),
                references=(ARISTA_LOGGING_GUIDE,),
            ))
        if (logging.logging_on is not False
                and logging.buffer_state == "explicit" and logging.buffer_level is not None
                and logging.buffer_level < 3):
            self.add_issue(Finding(
                rule_id="arista.eos.logging.buffer_severity_excludes_errors",
                device=parser.device_type,
                title="EOS local log buffer excludes error-severity events",
                observation=(
                    f"An explicit buffer threshold of {logging.buffer_level} excludes "
                    "error-severity (level 3) events from the local log buffer."
                ),
                impact="Local troubleshooting and incident review may lack error-severity events.",
                exploitability="An attacker with device access may benefit from reduced local evidence; remote logging is assessed separately.",
                recommendation="Set the buffer threshold to errors (3) or a more inclusive approved level.",
                severity=Severity.LOW,
                evidence=tuple(item for item in logging.buffer_evidence),
                references=(ARISTA_LOGGING_GUIDE,),
            ))
        associations = eos.get_ntp_associations()
        if not associations:
            self.add_issue(
                Finding(
                    rule_id="arista.eos.ntp.servers",
                    device=parser.device_type,
                    title="No NTP server is configured",
                    observation="No active 'ntp server' association was found.",
                    impact="Incorrect timestamps hinder event correlation and authentication troubleshooting.",
                    exploitability="Inconsistent time reduces the reliability of security monitoring and forensic timelines.",
                    recommendation="Configure redundant trusted NTP or NTS servers.",
                    severity=Severity.LOW,
                    evidence=("NTP server absent",),
                    references=(ARISTA_TIME_GUIDE,),
                )
            )
        else:
            for association in associations:
                if association.authentication_state == "unauthenticated":
                    self.add_issue(
                        Finding(
                            rule_id="arista.eos.ntp.authentication",
                            device=parser.device_type,
                            title="NTP association is unauthenticated",
                            observation=f"NTP server '{association.address}' in VRF '{association.vrf}' has neither an effective symmetric-key binding nor NTS.",
                            impact="Unauthenticated time responses can corrupt log chronology and time-dependent security behavior.",
                            exploitability="A network-positioned attacker may spoof NTP responses if routing and filtering permit it.",
                            recommendation="Enable NTP authentication and bind a configured trusted key, or use a resolved NTS SSL profile on EOS 4.35.0F or later.",
                            severity=Severity.MEDIUM,
                            evidence=tuple(item for item in association.evidence),
                            references=(ARISTA_TIME_GUIDE,),
                        )
                    )
                elif association.authentication_state == "unresolved":
                    reference = association.nts_profile or association.key_id or "missing"
                    self.add_issue(
                        Finding(
                            rule_id="arista.eos.ntp.authentication_reference",
                            device=parser.device_type,
                            title="NTP authentication reference is unresolved",
                            observation=f"NTP server '{association.address}' in VRF '{association.vrf}' references '{reference}', but the required trusted key or NTS trust profile is incomplete or unsupported by the release.",
                            impact="The intended authenticated time association cannot be established from the exported configuration.",
                            exploitability="Authentication failure can cause loss of synchronization or use of an unintended source.",
                            recommendation="Resolve the trusted key binding, or on EOS 4.35.0F or later attach an SSL profile containing a trusted certificate.",
                            severity=Severity.MEDIUM,
                            evidence=tuple(item for item in association.evidence),
                            references=(ARISTA_TIME_GUIDE,),
                        )
                    )
                if (
                    eos.supports_nts() is True
                    and association.authentication_state == "authenticated"
                    and association.algorithm in {"md5", "sha1"}
                ):
                    self.add_issue(
                        Finding(
                            rule_id="arista.eos.ntp.weak_algorithm",
                            device=parser.device_type,
                            title="NTP association uses a legacy symmetric algorithm",
                            observation=f"NTP server '{association.address}' in VRF '{association.vrf}' uses '{association.algorithm}' although this release supports NTS.",
                            impact="Legacy symmetric NTP authentication provides weaker protection than TLS-based NTS.",
                            exploitability="A network-positioned attacker can target weaknesses in the legacy authentication scheme.",
                            recommendation="Migrate the association to NTS using a valid SSL trust profile.",
                            severity=Severity.MEDIUM,
                            evidence=tuple(item for item in association.evidence),
                            references=(ARISTA_TIME_GUIDE,),
                        )
                    )

    def check_control_plane(self, parser: BaseDeviceParser) -> None:
        eos = self._eos(parser)
        for acl in eos.get_control_plane_acls():
            evidence = tuple(item for item in acl.evidence)
            if acl.resolution_state == "undefined":
                self.add_issue(Finding(
                    rule_id="arista.eos.control_plane.acl_reference",
                    device=parser.device_type,
                    title="Control-plane ACL reference is unresolved",
                    observation=f"The {acl.family} control-plane attachment references undefined ACL '{acl.name}'.",
                    impact="The intended control-plane traffic restriction cannot be established from the configuration.",
                    exploitability="Unexpected sources may reach switch control-plane services if the attachment is rejected or ineffective.",
                    recommendation="Define the referenced ACL in the matching address family and verify its active control-plane attachment.",
                    severity=Severity.HIGH,
                    evidence=evidence,
                    references=(ARISTA_CONTROL_PLANE_ACL_GUIDE,),
                ))
            elif acl.protection_state == "empty":
                self.add_issue(Finding(
                    rule_id="arista.eos.control_plane.acl_empty",
                    device=parser.device_type,
                    title="Attached control-plane ACL is empty",
                    observation=f"The attached {acl.family} ACL '{acl.name}' contains no active permit or deny entries.",
                    impact="An empty attachment does not demonstrate an intentional, reviewable control-plane access boundary.",
                    exploitability="Platform handling or later edits may expose control-plane traffic beyond the intended sources.",
                    recommendation="Populate the ACL with explicit required traffic and a reviewed default disposition.",
                    severity=Severity.HIGH,
                    evidence=evidence,
                    references=(ARISTA_CONTROL_PLANE_ACL_GUIDE,),
                ))
            elif acl.protection_state == "no-enforcement":
                self.add_issue(Finding(
                    rule_id="arista.eos.control_plane.acl_no_enforcement",
                    device=parser.device_type,
                    title="Control-plane ACL permits all traffic",
                    observation=f"The attached {acl.family} ACL '{acl.name}' reaches an unconditional permit without a preceding restrictive rule.",
                    impact="The custom ACL does not narrow traffic delivered to the switch control plane.",
                    exploitability="Any routed source can continue to send traffic toward protected control-plane services.",
                    recommendation="Restrict the ACL to documented protocols and trusted source ranges, retaining required operational traffic.",
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                    references=(ARISTA_CONTROL_PLANE_ACL_GUIDE,),
                ))

        policy = eos.get_copp_policy()
        for policy_class in policy.classes:
            evidence = tuple(item for item in policy_class.evidence)
            if policy_class.selector_state == "undefined-class":
                self.add_issue(Finding(
                    rule_id="arista.eos.control_plane.copp_class_reference",
                    device=parser.device_type,
                    title="CoPP policy references an undefined class",
                    observation=f"The always-attached '{policy.name}' policy references custom class '{policy_class.name}', which is not defined.",
                    impact="Traffic intended for the class cannot be proven to receive its control-plane rate policy.",
                    exploitability="Unclassified traffic may reach the CPU outside the intended custom protection path.",
                    recommendation="Define the control-plane class and its ACL selector, or remove the stale policy entry.",
                    severity=Severity.HIGH,
                    evidence=evidence,
                    references=(ARISTA_CONTROL_PLANE_GUIDE,),
                ))
            elif policy_class.selector_state in {"empty-class", "empty-selector", "undefined-selector"}:
                self.add_issue(Finding(
                    rule_id="arista.eos.control_plane.copp_class_reference",
                    device=parser.device_type,
                    title="CoPP class traffic selector is unresolved",
                    observation=f"Custom class '{policy_class.name}' in '{policy.name}' has selector state '{policy_class.selector_state}' for ACL '{policy_class.selector_reference or 'none'}'.",
                    impact="The class cannot identify the traffic intended for its control-plane treatment.",
                    exploitability="Relevant CPU-bound traffic may bypass the intended custom rate control.",
                    recommendation="Attach a populated IPv4 or IPv6 ACL selector to the class.",
                    severity=Severity.HIGH,
                    evidence=evidence,
                    references=(ARISTA_CONTROL_PLANE_GUIDE,),
                ))
            elif policy_class.selector_state == "resolved" and policy_class.enforcement_state == "no-enforcement":
                self.add_issue(Finding(
                    rule_id="arista.eos.control_plane.copp_class_no_enforcement",
                    device=parser.device_type,
                    title="Custom CoPP class has no rate action",
                    observation=f"Custom class '{policy_class.name}' resolves its selector but has no explicit numeric shape or bandwidth action in '{policy.name}'.",
                    impact="The exported override does not demonstrate rate enforcement for the selected traffic.",
                    exploitability="Selected traffic may consume control-plane resources without the intended custom limit.",
                    recommendation="Configure and operationally validate shape/bandwidth values appropriate to the platform and workload.",
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                    references=(ARISTA_CONTROL_PLANE_GUIDE,),
                ))
    def check_bpdu_guard(self, parser: BaseDeviceParser) -> None:
        """Explicitly ineffective BPDU guard on assessed EOS access-edge ports."""

        for port in self._eos(parser).get_bpdu_guard_policies():
            if (not port.active or port.role != "access-edge" or port.lag_member
                    or port.mode != "access"):
                continue
            evidence = tuple(port.evidence) + (f"assessment policy: {port.interface} role access-edge",)
            if port.guard_enabled is False:
                cause = {
                    "local-disabled": "'spanning-tree bpduguard disable' overrides any edge-port default",
                    "global-disabled": "the global edge-port BPDU-guard default is explicitly disabled",
                    "portfast-disabled": "the port is explicitly not a portfast port, so the portfast-only guard default does not apply",
                }.get(port.guard_state, "BPDU guard is explicitly ineffective")
                self.add_issue(Finding(
                    rule_id="arista.eos.layer2.access_edge.bpdu_guard_ineffective",
                    device=parser.device_type,
                    title="Access-edge port has ineffective BPDU guard",
                    observation=f"Interface {port.interface} is an assessed access edge, but {cause}.",
                    impact="A connected device can send BPDUs without the port being disabled, potentially affecting spanning-tree topology.",
                    exploitability="A user or attacker on the access port can connect a bridge or send crafted BPDUs.",
                    recommendation="Enable BPDU guard on this access port ('spanning-tree bpduguard enable'), or make it a portfast port covered by 'spanning-tree edge-port bpduguard default'.",
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                    references=(ARISTA_STP_GUIDE,),
                ))
            elif port.guard_enabled is True and port.filter_enabled is True:
                self.add_issue(Finding(
                    rule_id="arista.eos.layer2.access_edge.bpdu_filter_bypass",
                    device=parser.device_type,
                    title="Access-edge BPDU filtering can bypass guard",
                    observation=f"Interface {port.interface} has BPDU guard but also 'spanning-tree bpdufilter enable'.",
                    impact="BPDU filtering stops the port from receiving BPDUs, so the guard may never see the BPDU that should disable the port.",
                    exploitability="A bridge connected to the access port may go undetected.",
                    recommendation="Remove BPDU filtering from the assessed access edge and keep BPDU guard.",
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                    references=(ARISTA_STP_GUIDE,),
                ))

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_management_api(parser)
        self.check_authentication(parser)
        self.check_administrative_policy(parser)
        self.check_ssh_and_authorization(parser)
        self.check_credentials(parser)
        self.check_snmp(parser)
        self.check_operations(parser)
        self.check_control_plane(parser)
        self.check_bpdu_guard(parser)
