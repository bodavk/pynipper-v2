"""Version-aware Junos management and control-plane hardening checks."""

from collections import defaultdict
from dataclasses import replace

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.credentials import credential_policy_from_context, evaluate_credential
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.juniper.junos import JunOSParser, JunosStatement


JUNIPER_ACCESS_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "user-access/topics/topic-map/junos-software-remote-access-overview.html"
)
JUNIPER_AUTH_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "user-access/topics/topic-map/junos-os-authentication-order.html"
)
JUNIPER_LOGIN_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "user-access/topics/topic-map/junos-os-login-settings.html"
)
JUNIPER_LOGIN_CLASS_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/"
    "topics/ref/statement/class-edit-system-login.html"
)
JUNIPER_TACACS_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "user-access/topics/topic-map/user-access-tacacs-authentication.html"
)
JUNIPER_RADIUS_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "user-access/topics/topic-map/user-access-radius-authentication.html"
)
JUNIPER_JWEB_SESSION_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/"
    "topics/ref/statement/session-edit-system.html"
)
JUNIPER_SSH_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/"
    "topics/ref/statement/ssh-edit-system.html"
)
JUNIPER_SNMP_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "network-mgmt/topics/topic-map/configure-snmpv3.html"
)
JUNIPER_SYSLOG_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "network-mgmt/topics/topic-map/system-logging.html"
)
JUNIPER_SYSLOG_HOST_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/"
    "topics/ref/statement/host-edit-system.html"
)
JUNIPER_NTP_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "time-mgmt/topics/concept/ntp-authentication-keys.html"
)
JUNIPER_FILTER_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "routing-policy/topics/concept/firewall-filter-overview.html"
)
JUNIPER_POLICER_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "routing-policy/topics/concept/policer-summary-configuration-two-color.html"
)
JUNIPER_CONFIGURATION_ARCHIVE_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/cli/topics/task/"
    "junos-software-system-management-router-configuration-archiving.html"
)
JUNIPER_ACCOUNTING_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/"
    "topics/ref/statement/accounting-edit-system.html"
)
JUNIPER_REDIRECT_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/"
    "topics/ref/statement/no-redirects-edit-system.html"
)
JUNIPER_BGP_SECURITY_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "bgp/topics/topic-map/bgp_security.html"
)
JUNIPER_OSPF_AUTH_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "ospf/topics/topic-map/configuring-ospf-authentication.html"
)
JUNIPER_LLDP_GUIDE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "multicast-l2/topics/task/layer-2-services-lldp-configuring.html"
)
JUNIPER_DEFAULT_POLICY_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/"
    "topics/ref/statement/security-edit-default-policy.html"
)
JUNIPER_IDP_ACTION_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/"
    "topics/ref/statement/security-edit-action.html"
)
JUNIPER_IDP_RULEBASE_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/idp-policy/"
    "topics/topic-map/security-idp-policy-rules-and-rulebases.html"
)
# IPS rulebase actions that never stop an attack (vendor action reference).
IDP_NON_BLOCKING_ACTIONS = frozenset({"no-action", "ignore-connection", "mark-diffserv", "class-of-service"})
JUNIPER_SCREEN_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "cli-reference/topics/ref/statement/security-edit-syn-flood.html"
)
JUNIPER_UDP_SCREEN_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "cli-reference/topics/ref/statement/security-edit-flood-udp.html"
)
JUNIPER_ICMP_SCREEN_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "cli-reference/topics/ref/statement/security-edit-flood-icmp.html"
)
JUNIPER_SCREEN_OPTION_REFERENCE = (
    "https://www.juniper.net/documentation/us/en/software/junos/"
    "cli-reference/topics/ref/statement/security-edit-ids-option.html"
)


class PluginJunOSBaseline(BasePlugin):
    """Evaluate explicit Junos security state without inventing release defaults."""

    _WEAK_SSH = {
        "ciphers": {
            "3des-cbc",
            "aes128-cbc",
            "aes192-cbc",
            "aes256-cbc",
            "blowfish-cbc",
            "cast128-cbc",
            "arcfour",
            "arcfour128",
            "arcfour256",
        },
        "macs": {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96"},
        "key-exchange": {
            "dh-group1-sha1",
            "dh-group14-sha1",
            "group-exchange-sha1",
        },
        "hostkey-algorithm": {"ssh-dss", "ssh-rsa"},
    }

    @staticmethod
    def _junos(parser: BaseDeviceParser) -> JunOSParser:
        if not isinstance(parser, JunOSParser):
            raise TypeError("PluginJunOSBaseline requires a Junos parser")
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
                "An attacker with management-plane reachability may exploit the "
                "effective weakness."
            ),
            recommendation=recommendation,
            severity=severity,
            evidence=evidence,
            references=references,
            basis=basis,
        )

    @staticmethod
    def _texts(statements: list[JunosStatement]) -> tuple[str, ...]:
        return tuple(statement.evidence for statement in statements)

    def _statements(
        self, parser: BaseDeviceParser, prefix: tuple[str, ...]
    ) -> list[JunosStatement]:
        return self._junos(parser).get_active_statements(prefix)

    def _applicable(self, parser: BaseDeviceParser) -> bool:
        junos = self._junos(parser)
        return not junos.parse_error and junos.get_version() != "?"

    def check_default_security_policy(self, parser: BaseDeviceParser) -> None:
        state = self._junos(parser).get_default_security_policy()
        if state.resolution_state not in {"explicit", "inherited"} or state.action != "permit-all":
            return
        self.add_issue(self._finding(
            parser,
            "juniper.junos.policy.default_permit_all",
            "Unmatched SRX transit traffic is permitted",
            "The effective global security default-policy permits traffic that matches no zone or global security policy; it does not govern host-inbound management traffic or stateless firewall filters.",
            "Inter-zone and intra-zone traffic without an explicit matching security rule can traverse the firewall.",
            "Set security policies default-policy deny-all and create narrowly scoped explicit permit policies.",
            Severity.HIGH,
            tuple(item for item in state.evidence),
            (JUNIPER_DEFAULT_POLICY_REFERENCE,),
        ))

    def check_authentication(self, parser: BaseDeviceParser) -> None:
        authentication_order = self._statements(parser, ("system", "authentication-order"))
        order_tokens = {
            token for statement in authentication_order for token in statement.path[2:]
        }
        if not order_tokens.intersection({"radius", "tacplus"}):
            self.add_issue(self._finding(
                parser, "juniper.junos.authentication.centralized",
                "Centralized administrator authentication is not configured",
                "The effective authentication order uses only local passwords or the local-password default.",
                "Local-only authentication reduces centralized access control and accountability.",
                "Configure RADIUS or TACACS+ first in authentication-order and retain a tested local fallback according to policy.",
                Severity.MEDIUM,
                self._texts(authentication_order) or ("system authentication-order absent",),
                (JUNIPER_AUTH_GUIDE,),
            ))

        retries = self._statements(
            parser, ("system", "login", "retry-options", "tries-before-disconnect")
        )
        if retries:
            value = retries[-1].path[-1]
            if value.isdigit() and int(value) > 3:
                self.add_issue(self._finding(
                    parser, "juniper.junos.authentication.login_attempts",
                    "Excessive login attempts are permitted",
                    f"The effective tries-before-disconnect value is {value}; the Junos default and hardened target is three attempts.",
                    "Additional guesses increase exposure to online password attacks.",
                    "Set system login retry-options tries-before-disconnect to 3 or fewer.",
                    Severity.MEDIUM, self._texts(retries[-1:]), (JUNIPER_LOGIN_GUIDE,),
                ))

        lockout = self._statements(
            parser, ("system", "login", "retry-options", "lockout-period")
        )
        if not lockout:
            self.add_issue(self._finding(
                parser, "juniper.junos.authentication.lockout",
                "Administrative account lockout is not configured",
                "No effective login retry-options lockout-period is configured.",
                "Repeated password guessing is not interrupted by a timed account lockout.",
                "Configure a policy-approved lockout-period and test the recovery procedure.",
                Severity.MEDIUM, ("system login retry-options lockout-period absent",),
                (JUNIPER_LOGIN_GUIDE,),
            ))

        for user in self._junos(parser).get_users():
            if user["class"] == "super-user" and not user["authentication"]:
                self.add_issue(self._finding(
                    parser, "juniper.junos.authentication.super_user",
                    "Super-user account lacks explicit authentication",
                    f"Administrative user '{user['username']}' has class super-user but no effective authentication method.",
                    "An unusable or unexpectedly inherited account can undermine intended administrative access controls.",
                    "Configure an approved SSH key or strong encrypted password, or remove the account.",
                    Severity.HIGH, tuple(item for item in user["evidence"]),
                    (JUNIPER_AUTH_GUIDE,),
                ))

        credential_policy = credential_policy_from_context(parser.assessment_context)
        for credential in self._junos(parser).get_credential_metadata():
            result = evaluate_credential(credential, credential_policy)
            if result.unsafe_storage:
                self.add_issue(self._finding(
                    parser, "juniper.junos.authentication.weak_storage",
                    "Administrative credential uses weak storage",
                    f"The {credential.context} credential for '{credential.account}' uses '{credential.method}' format '{credential.storage_type}', classified as '{result.storage_assessment.value}' under credential policy '{result.policy_version}'; the separate exact-default comparison is '{result.default_assessment.value}' and the blocklist comparison {result.blocklist_summary}. The value is redacted.",
                    "Configuration disclosure can expose or accelerate recovery of the credential.",
                    "Replace the credential with a supported strong hash or SSH public key.",
                    Severity.HIGH, tuple(item for item in credential.evidence),
                    (JUNIPER_AUTH_GUIDE,),
                ))

    def check_administrative_policy(self, parser: BaseDeviceParser) -> None:
        junos = self._junos(parser)
        notice = junos.get_login_notice_policy()
        if not notice.message_configured and not notice.inheritance_unknown:
            self.add_issue(self._finding(
                parser, "juniper.junos.authentication.login_banner",
                "Pre-authentication login message is missing",
                "No effective system login message is configured; a post-login announcement does not replace the pre-authentication notice.",
                "Users are not shown an approved access warning before supplying administrative credentials.",
                "Configure an organization-approved system login message and retain announcements only for post-login information.",
                Severity.MEDIUM, tuple(item for item in notice.evidence) or ("system login message absent",),
                (JUNIPER_LOGIN_GUIDE,),
            ))

        inheritance_unknown = junos.has_unexpanded_inheritance()
        for user in junos.get_users():
            if not user["class"] and not inheritance_unknown:
                self.add_issue(self._finding(
                    parser, "juniper.junos.authentication.login_class_binding",
                    "Administrative user has no resolved login class",
                    f"User '{user['username']}' has no effective login-class binding in the supplied configuration.",
                    "The export does not establish the authorization privileges applied to this identity.",
                    "Assign the user to a defined least-privilege login class or provide the complete inherited configuration.",
                    Severity.HIGH, tuple(item for item in user["evidence"]),
                    (JUNIPER_LOGIN_CLASS_REFERENCE,),
                ))

        for policy in junos.get_login_class_policies():
            if not policy.users:
                continue
            evidence = tuple(item for item in policy.evidence)
            if not policy.defined and not policy.inheritance_unknown:
                self.add_issue(self._finding(
                    parser, "juniper.junos.authentication.login_class_binding",
                    "Administrative user references an unresolved login class",
                    f"Users {', '.join(policy.users)} reference login class '{policy.name}', but no predefined or locally defined class is resolved.",
                    "The export does not establish the authorization privileges applied to these identities.",
                    "Define and review the referenced least-privilege class or correct the user bindings.",
                    Severity.HIGH, evidence, (JUNIPER_LOGIN_CLASS_REFERENCE,),
                ))
                continue
            if (
                policy.name.casefold() == "unauthorized"
                or policy.resolution_state != "known"
                or policy.idle_timeout_minutes not in {None, 0}
            ):
                continue
            state = (
                "is not configured, so the documented default does not force idle logout"
                if policy.idle_timeout_minutes is None
                else "is explicitly zero, which disables idle logout"
            )
            self.add_issue(self._finding(
                parser, "juniper.junos.authentication.idle_timeout",
                "Administrative login class has no effective idle timeout",
                f"Login class '{policy.name}', used by {', '.join(policy.users)}, {state}.",
                "An abandoned authenticated CLI session can remain available indefinitely.",
                "Apply a policy-approved nonzero idle-timeout through the user-defined class or supported global login setting.",
                Severity.MEDIUM, evidence or (f"login class {policy.name} timeout absent",),
                (JUNIPER_LOGIN_GUIDE, JUNIPER_LOGIN_CLASS_REFERENCE),
            ))

        authentication_order = self._statements(parser, ("system", "authentication-order"))
        remote_methods = {
            token for statement in authentication_order for token in statement.path[2:]
            if token in {"radius", "tacplus"}
        }
        if remote_methods:
            accounting = junos.get_accounting_policy()
            missing_events = sorted(
                {"login", "change-log", "interactive-commands"} - set(accounting.events)
            )
            evidence = tuple(item for item in accounting.evidence)
            if missing_events and not accounting.inheritance_unknown:
                self.add_issue(self._finding(
                    parser, "juniper.junos.authentication.accounting_events",
                    "Administrative accounting event coverage is incomplete",
                    f"Remote authentication uses {', '.join(sorted(remote_methods))}, but accounting omits: {', '.join(missing_events)}.",
                    "Logins, configuration changes, or interactive commands can lack centralized attribution.",
                    "Configure system accounting events for login, change-log, and interactive-commands.",
                    Severity.MEDIUM, evidence or ("system accounting events absent",),
                    (JUNIPER_TACACS_GUIDE, JUNIPER_RADIUS_GUIDE),
                ))

            unresolved = sorted(
                set(accounting.destination_methods) - set(accounting.resolved_methods)
            )
            if not accounting.inheritance_unknown and (
                not accounting.destination_methods or unresolved
            ):
                observation = (
                    "No effective RADIUS or TACACS+ accounting destination is configured."
                    if not accounting.destination_methods
                    else f"Accounting destination methods have no resolved server: {', '.join(unresolved)}."
                )
                self.add_issue(self._finding(
                    parser, "juniper.junos.authentication.accounting_destination",
                    "Administrative accounting destination is missing or unresolved",
                    observation,
                    "Centralized authentication activity might not reach an independent audit destination.",
                    "Configure and verify a RADIUS or TACACS+ accounting destination with a resolved server.",
                    Severity.HIGH, evidence or ("system accounting destination absent",),
                    (JUNIPER_TACACS_GUIDE, JUNIPER_RADIUS_GUIDE),
                ))

        web = junos.get_web_management_policy()
        if not web.enabled:
            return
        evidence = tuple(item for item in web.evidence)
        if (
            web.idle_timeout_resolution == "known"
            and web.idle_timeout_minutes is not None
            and web.idle_timeout_minutes > 30
        ):
            self.add_issue(self._finding(
                parser, "juniper.junos.administration.web_session_timeout",
                "J-Web idle timeout exceeds the hardened reference value",
                f"J-Web is enabled for {', '.join(web.protocols)} with an explicit idle timeout of {web.idle_timeout_minutes} minutes.",
                "An abandoned authenticated browser session remains usable for an excessive period.",
                "Set the J-Web session idle-timeout to 30 minutes or less, or the stricter approved organizational value.",
                Severity.MEDIUM, evidence, (JUNIPER_JWEB_SESSION_REFERENCE,),
            ))
        if web.session_limit_resolution == "known" and web.session_limit is None:
            self.add_issue(self._finding(
                parser, "juniper.junos.administration.web_session_limit",
                "J-Web concurrent sessions are not bounded",
                "J-Web is enabled without an explicit session-limit; the documented default permits an unlimited number of concurrent sessions.",
                "Unbounded authenticated sessions can increase management-plane resource pressure and account-sharing exposure.",
                "Configure a finite J-Web session-limit based on the number of authorized administrators.",
                Severity.MEDIUM, evidence, (JUNIPER_JWEB_SESSION_REFERENCE,),
            ))

    def check_aaa_transport(self, parser: BaseDeviceParser) -> None:
        junos = self._junos(parser)
        inheritance_unknown = junos.has_unexpanded_inheritance()
        for profile in junos.get_aaa_transport_profiles():
            evidence = tuple(item for item in profile.evidence) or (
                f"system RADIUS server {profile.address}",
            )
            use = " and ".join(profile.roles)
            if profile.transport == "tls":
                if not profile.trusted_ca_group and not inheritance_unknown:
                    self.add_issue(self._finding(
                        parser,
                        "juniper.junos.aaa.radsec_trust",
                        "Administrative RadSec server has no trusted CA group",
                        f"RADIUS server '{profile.address}' uses TLS for administrative {use} but has no effective trusted-ca-group binding.",
                        "The exported configuration does not establish certificate validation for the RADIUS server identity.",
                        "Bind the RadSec server to the approved trusted-ca-group and verify the CA files and server certificate operationally.",
                        Severity.HIGH,
                        evidence,
                        (JUNIPER_RADIUS_GUIDE,),
                    ))
                if (
                    profile.mutual_authentication
                    and not profile.client_certificate_id
                    and not inheritance_unknown
                ):
                    self.add_issue(self._finding(
                        parser,
                        "juniper.junos.aaa.radsec_client_certificate",
                        "Administrative RadSec mutual authentication is incomplete",
                        f"RADIUS server '{profile.address}' enables mutual authentication for administrative {use} without an effective certificate-id binding.",
                        "The Junos client identity required for mutual TLS is not established by the supplied configuration.",
                        "Bind the intended certificate-id and verify that client.crt and client.key are present and protected on the device.",
                        Severity.HIGH,
                        evidence,
                        (JUNIPER_RADIUS_GUIDE,),
                    ))
                continue

            if profile.message_authenticator == "disabled":
                path = (
                    "a separately declared protected path"
                    if profile.protected_path else "a network path whose protection is unknown"
                )
                self.add_issue(self._finding(
                    parser,
                    "juniper.junos.aaa.radius_message_authenticator",
                    "Administrative RADIUS Message-Authenticator validation is disabled",
                    f"RADIUS server '{profile.address}' uses UDP over {path} for administrative {use} and explicitly configures no-message-authenticator.",
                    "Forged or modified RADIUS replies may be accepted without the additional protocol message-validation control.",
                    "Configure message-authenticator where the server supports it, or migrate to RadSec with an approved trusted CA group.",
                    Severity.HIGH,
                    evidence,
                    (JUNIPER_RADIUS_GUIDE,),
                ))

    def check_ssh_algorithms(self, parser: BaseDeviceParser) -> None:
        if not self._junos(parser).get_services()["ssh"]:
            return
        for field, weak_values in self._WEAK_SSH.items():
            statements = self._statements(
                parser, ("system", "services", "ssh", field)
            )
            configured = {
                token.casefold()
                for statement in statements
                for token in statement.path[4:]
            }
            weak = sorted(configured.intersection(weak_values))
            if not weak:
                continue
            self.add_issue(
                self._finding(
                    parser,
                    f"juniper.junos.ssh.weak_{field.replace('-', '_')}",
                    f"Weak SSH {field.replace('-', ' ')} explicitly enabled",
                    f"The effective SSH {field} list includes: {', '.join(weak)}.",
                    "Legacy SSH algorithms weaken confidentiality, integrity, or server authentication.",
                    f"Remove the weak {field} values and retain only algorithms approved by organizational policy.",
                    Severity.HIGH,
                    self._texts(statements),
                    (JUNIPER_SSH_REFERENCE,),
                )
            )

    def check_additional_services(self, parser: BaseDeviceParser) -> None:
        insecure = {
            "ftp",
            "finger",
            "rlogin",
            "rsh",
            "xnm-clear-text",
        }
        for service in sorted(insecure):
            statements = self._statements(parser, ("system", "services", service))
            if not statements:
                continue
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.junos.services.legacy",
                    "Legacy management service is enabled",
                    f"The effective configuration explicitly enables {service}.",
                    "Clear-text or obsolete services unnecessarily expand the Routing Engine attack surface.",
                    "Delete the service and use SSH/SCP or another authenticated encrypted alternative.",
                    Severity.HIGH,
                    self._texts(statements),
                    (JUNIPER_ACCESS_GUIDE,),
                )
            )

    def check_snmp(self, parser: BaseDeviceParser) -> None:
        communities: dict[str, list[JunosStatement]] = defaultdict(list)
        for statement in self._statements(parser, ("snmp", "community")):
            if len(statement.path) > 2:
                communities[statement.path[2]].append(statement)
        for community, statements in communities.items():
            tokens = {token.casefold() for item in statements for token in item.path[3:]}
            severe = community.casefold() in {"public", "private"} or "read-write" in tokens
            qualifiers = []
            if community.casefold() in {"public", "private"}:
                qualifiers.append("an exact default community")
            if "read-write" in tokens:
                qualifiers.append("read-write authorization")
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.junos.snmp.legacy_community",
                    "Legacy SNMP community is configured",
                    "A community-based SNMP configuration is active"
                    + (f" with {', '.join(qualifiers)}" if qualifiers else "")
                    + "; the community value is redacted.",
                    "SNMPv1/v2c communities do not provide modern per-user authentication and privacy.",
                    "Migrate to SNMPv3 USM with authentication and privacy, then remove the community.",
                    Severity.HIGH if severe else Severity.MEDIUM,
                    tuple(
                        replace(item.evidence, text=item.evidence.text.replace(community, "<redacted>"))
                        for item in statements
                    ),
                    (JUNIPER_SNMP_GUIDE,),
                )
            )

        users: dict[str, list[JunosStatement]] = defaultdict(list)
        prefix = ("snmp", "v3", "usm", "local-engine", "user")
        for statement in self._statements(parser, prefix):
            if len(statement.path) > 5:
                users[statement.path[5]].append(statement)
        for username, statements in users.items():
            values = {
                token.casefold()
                for statement in statements
                for token in statement.path[6:]
            }
            has_auth = any(
                token.startswith("authentication-")
                and token not in {"authentication-password", "authentication-key"}
                for token in values
            )
            has_privacy = any(
                token.startswith("privacy-")
                and token not in {"privacy-password", "privacy-key", "privacy-none"}
                for token in values
            )
            weak = sorted(
                token
                for token in values
                if token in {"authentication-md5", "privacy-des", "privacy-none"}
            )
            if has_auth and has_privacy and not weak:
                continue
            detail = "missing authentication or privacy" if not (has_auth and has_privacy) else f"weak settings: {', '.join(weak)}"
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.junos.snmp.v3_security",
                    "SNMPv3 user security is incomplete",
                    f"SNMPv3 user '{username}' has {detail}; key material is redacted.",
                    "Unauthenticated, unencrypted, or legacy SNMP protection exposes management data and control operations.",
                    "Configure a supported SHA authentication method and AES privacy for the USM user.",
                    Severity.HIGH,
                    tuple(item.evidence for item in statements),
                    (JUNIPER_SNMP_GUIDE,),
                )
            )

    def check_configuration_management(self, parser: BaseDeviceParser) -> None:
        junos = self._junos(parser)
        state = junos.get_configuration_management()
        evidence = tuple(item for item in state.evidence)
        authentication_order = self._statements(parser, ("system", "authentication-order"))
        remote_authentication = any(
            token in {"radius", "tacplus"}
            for statement in authentication_order
            for token in statement.path[2:]
        )
        # Remote-authentication accounting gaps are already reported by the
        # administrative-policy check with precise event/destination causes.
        if state.change_audit_state == "missing" and not remote_authentication:
            self.add_issue(self._finding(
                parser,
                "juniper.junos.configuration.change_audit",
                "Configuration changes lack an audit destination",
                "Neither a resolved system-accounting change-log destination nor an active syslog change-log selector is configured.",
                "Configuration changes can lack an independent attributable audit trail.",
                "Send change-log events to a protected syslog destination or configure resolved RADIUS/TACACS+ system accounting.",
                Severity.MEDIUM,
                evidence or ("configuration change audit destination absent",),
                (JUNIPER_ACCOUNTING_REFERENCE, JUNIPER_SYSLOG_GUIDE),
            ))

        archive_configured = bool(state.sites) or state.schedule_state != "missing" or bool(
            state.routing_instance
        )
        archive_complete = bool(state.sites) and state.schedule_state == "effective"
        if archive_configured and not archive_complete:
            gaps = []
            if not state.sites:
                gaps.append("no archive site")
            if state.schedule_state != "effective":
                gaps.append(f"schedule state '{state.schedule_state}'")
            self.add_issue(self._finding(
                parser,
                "juniper.junos.configuration.archive_incomplete",
                "Configuration archival is incomplete",
                "The system archival configuration has " + " and ".join(gaps) + ".",
                "The device cannot automatically transfer complete configuration checkpoints as intended.",
                "Configure at least one archive site plus transfer-on-commit or a valid transfer-interval.",
                Severity.MEDIUM,
                evidence,
                (JUNIPER_CONFIGURATION_ARCHIVE_GUIDE,),
            ))
        elif (
            parser.assessment_context.configuration_backup_scope == "on-device-required"
            and not archive_complete
            and not state.inheritance_unknown
        ):
            self.add_issue(self._finding(
                parser,
                "juniper.junos.configuration.archive_required",
                "Required on-device configuration archival is absent",
                "The assessment policy requires on-device archival, but no complete archive site and schedule are configured.",
                "The device lacks the policy-required configuration checkpoints for recovery.",
                "Configure secure archive-sites with transfer-on-commit or a valid transfer-interval.",
                Severity.MEDIUM,
                evidence or ("assessment policy: on-device configuration backup required",),
                (JUNIPER_CONFIGURATION_ARCHIVE_GUIDE,),
            ))
        for site in state.sites:
            if site.transport_security != "insecure":
                continue
            self.add_issue(self._finding(
                parser,
                "juniper.junos.configuration.archive_transport",
                "Configuration archive site uses an insecure transport",
                f"Archive site '{site.destination}' uses '{site.protocol}' transport.",
                "Configuration backups can expose credentials, addressing, and security policy in transit.",
                "Use SCP or SFTP and verify the archive host key through a trusted channel.",
                Severity.HIGH,
                tuple(item for item in site.evidence),
                (JUNIPER_CONFIGURATION_ARCHIVE_GUIDE,),
            ))

    def check_logging(self, parser: BaseDeviceParser) -> None:
        destinations = self._junos(parser).get_syslog_destinations()
        if not destinations:
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.junos.logging.remote_destination",
                    "Remote system logging is not configured",
                    "No effective system syslog host destination is present.",
                    "Locally stored events can be lost during compromise or device failure.",
                    "Configure protected remote syslog destinations; use an approved transport on supported releases.",
                    Severity.MEDIUM,
                    ("system syslog host absent",),
                    (JUNIPER_SYSLOG_GUIDE,),
                )
            )
            return

        accepted_severities = {"any", "info", "informational"}
        for destination in destinations:
            covered = {
                facility
                for facility in ("authorization", "interactive-commands")
                if any(
                    selector.severity in accepted_severities
                    and selector.facility in {"any", facility}
                    for selector in destination.selectors
                )
            }
            if len(covered) == 2 or destination.has_unknown_selector:
                continue
            missing = sorted({"authorization", "interactive-commands"} - covered)
            scope = destination.routing_instance or "default"
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.junos.logging.event_coverage",
                    "Remote syslog destination omits security-relevant events",
                    f"Syslog host '{destination.address}' in routing-instance scope '{scope}' lacks verified informational-or-broader coverage for: {', '.join(missing)}. Its transport is {'explicitly ' + destination.transport if destination.transport else 'not established by the export'}.",
                    "Authentication and administrative-command activity may be absent from this destination, creating a monitoring blind spot even when another host is complete.",
                    "Configure authorization and interactive-commands selectors at an approved severity, or an equivalently broad any selector, for each required destination.",
                    Severity.MEDIUM,
                    tuple(item for item in destination.evidence),
                    (JUNIPER_SYSLOG_GUIDE, JUNIPER_SYSLOG_HOST_REFERENCE),
                )
            )

    def check_ntp(self, parser: BaseDeviceParser) -> None:
        junos = self._junos(parser)
        associations = junos.get_ntp_associations()
        if not associations:
            self.add_issue(
                self._finding(
                    parser,
                    "juniper.junos.ntp.associations",
                    "NTP synchronization is not configured",
                    "No effective NTP server or peer is configured.",
                    "Incorrect time undermines event correlation and time-dependent security controls.",
                    "Configure multiple trusted NTP servers or peers.",
                    Severity.MEDIUM,
                    ("system ntp server/peer absent",),
                    (JUNIPER_NTP_GUIDE,),
                )
            )
            return
        model = self._junos(parser).get_model().casefold()
        legacy_only = model.startswith(
            ("ex4300", "ex4600", "qfx5100")
        )
        for association in associations:
            evidence = tuple(item for item in association.evidence)
            if association.authentication_state != "authenticated":
                detail = (
                    "has no key binding"
                    if association.authentication_state == "unauthenticated"
                    else f"references unresolved or untrusted key '{association.key_id}'"
                )
                self.add_issue(
                    self._finding(
                        parser,
                        "juniper.junos.ntp.authentication",
                        "NTP authentication is incomplete",
                        f"NTP {association.role} '{association.address}' {detail}.",
                        "A spoofed time source can disrupt logs and time-sensitive security behavior.",
                        "Configure authentication-key and trusted-key, then bind this association to the trusted key ID.",
                        Severity.MEDIUM,
                        evidence,
                        (JUNIPER_NTP_GUIDE,),
                    )
                )
            elif model != "?" and not legacy_only and association.algorithm in {"md5", "sha1"}:
                self.add_issue(
                    self._finding(
                        parser,
                        "juniper.junos.ntp.weak_algorithm",
                        "NTP association uses a legacy authentication algorithm",
                        f"NTP {association.role} '{association.address}' uses '{association.algorithm}'.",
                        "A legacy digest provides weaker protection against forged time updates.",
                        "Use SHA-256 where supported by the exact Junos platform and release.",
                        Severity.MEDIUM,
                        evidence,
                        (JUNIPER_NTP_GUIDE,),
                    )
                )

    def check_routing_engine_filter(self, parser: BaseDeviceParser) -> None:
        junos = self._junos(parser)
        protections = junos.get_routing_engine_protections()
        inheritance_unknown = any(
            statement.active
            and statement.path[:2] == ("interfaces", "lo0")
            and "apply-groups" in statement.path
            for statement in junos.statements
        )
        if not protections and inheritance_unknown:
            return
        if not protections:
            self.add_issue(self._finding(
                parser,
                "juniper.junos.control_plane.lo0_filter",
                "Routing Engine input filter is not attached",
                "No effective family inet or inet6 input firewall filter is attached to lo0.",
                "Unfiltered host-bound traffic increases exposure to scanning and denial-of-service attacks.",
                "Apply a tested, source-restricted control-plane filter to the appropriate lo0 families.",
                Severity.HIGH,
                ("interfaces lo0 family filter input absent",),
                (JUNIPER_FILTER_GUIDE,),
            ))
            return

        for protection in protections:
            evidence = tuple(item for item in protection.evidence)
            scope = f"{protection.interface}.{protection.unit} family {protection.family}"
            if not protection.filter_resolved:
                if protection.protection_state == "unknown-inheritance":
                    continue
                self.add_issue(self._finding(
                    parser,
                    "juniper.junos.control_plane.filter_reference",
                    "Routing Engine filter attachment is unresolved",
                    f"{scope} references undefined filter '{protection.filter_name}' in the same address family.",
                    "A missing or wrong-family definition cannot filter host-bound traffic as intended.",
                    "Define the attached filter under the matching family and verify its active terms.",
                    Severity.HIGH,
                    evidence,
                    (JUNIPER_FILTER_GUIDE,),
                ))
                continue
            if protection.protection_state == "empty-filter":
                self.add_issue(self._finding(
                    parser,
                    "juniper.junos.control_plane.filter_empty",
                    "Attached Routing Engine filter is empty",
                    f"Filter '{protection.filter_name}' is attached to {scope} but has no active terms.",
                    "The attachment provides no explicit classification or enforcement policy.",
                    "Add reviewed, ordered terms that permit required control traffic and discard or police unwanted traffic.",
                    Severity.HIGH,
                    evidence,
                    (JUNIPER_FILTER_GUIDE,),
                ))
                continue

            for term in protection.terms:
                if term.policer_resolution not in {"undefined", "incomplete"}:
                    continue
                self.add_issue(self._finding(
                    parser,
                    "juniper.junos.control_plane.policer_reference",
                    "Routing Engine term has an unresolved policer",
                    f"Term '{term.name}' in filter '{protection.filter_name}' references policer '{term.policer}' with state '{term.policer_resolution}'.",
                    "A missing rate, burst limit, discard action, or policer definition cannot provide the intended rate enforcement.",
                    "Define the referenced policer with an operationally approved rate, burst limit, and discard action.",
                    Severity.HIGH,
                    tuple(item for item in term.evidence) or evidence,
                    (JUNIPER_POLICER_GUIDE,),
                ))

            if protection.protection_state == "no-enforcement":
                self.add_issue(self._finding(
                    parser,
                    "juniper.junos.control_plane.filter_no_enforcement",
                    "Attached Routing Engine filter permits all traffic",
                    f"Filter '{protection.filter_name}' on {scope} has no discard, reject, complete discard policer, or restrictive implicit-discard term set.",
                    "An unconditional permit-only filter does not reduce traffic reaching the Routing Engine.",
                    "Use ordered source/protocol restrictions and explicit discard/reject or a complete discard policer; set rates from platform and traffic evidence.",
                    Severity.HIGH,
                    evidence,
                    (JUNIPER_FILTER_GUIDE, JUNIPER_POLICER_GUIDE),
                ))

    def check_redirects(self, parser: BaseDeviceParser) -> None:
        if self._statements(parser, ("system", "no-redirects")):
            return
        self.add_issue(
            self._finding(
                parser,
                "juniper.junos.interfaces.redirects",
                "IPv4 redirects are not explicitly disabled",
                "The effective configuration lacks system no-redirects.",
                "Protocol redirects can alter host forwarding decisions on applicable platforms.",
                "Configure system no-redirects, or document the platform-specific condition that makes it inapplicable.",
                Severity.LOW,
                ("system no-redirects absent",),
                (JUNIPER_REDIRECT_REFERENCE,),
            )
        )

    def check_routing(self, parser: BaseDeviceParser) -> None:
        junos = self._junos(parser)
        for peer in junos.get_bgp_neighbors():
            if not peer.active or peer.inheritance_unknown:
                continue
            scope = (
                f"neighbor {peer.address} in group {peer.group}, "
                f"family {peer.address_family}, routing-instance {peer.routing_instance}"
            )
            evidence = tuple(item for item in peer.evidence)
            if peer.authentication_state in {"unauthenticated", "unresolved"}:
                detail = "has no authentication" if peer.authentication_state == "unauthenticated" else "has an unresolved authentication key-chain or algorithm"
                self.add_issue(self._finding(
                    parser,
                    "juniper.junos.routing.bgp.authentication",
                    "BGP neighbor authentication is incomplete",
                    f"BGP {scope} {detail}.",
                    "An unauthenticated routing adjacency can permit spoofed session establishment or route injection from a reachable attacker.",
                    "Configure an authentication-key or a fully defined authentication key-chain and supported algorithm on the peer group.",
                    Severity.HIGH,
                    evidence,
                    (JUNIPER_BGP_SECURITY_GUIDE,),
                ))
            if peer.peer_role != "external":
                continue
            for direction, present in (("inbound", peer.inbound_policy), ("outbound", peer.outbound_policy)):
                if present:
                    continue
                self.add_issue(self._finding(
                    parser,
                    f"juniper.junos.routing.bgp.{direction}_policy",
                    f"External BGP neighbor lacks an {direction} policy",
                    f"External BGP {scope} has no explicit {direction} policy at neighbor or group scope.",
                    "Unrestricted route exchange can admit or advertise unintended prefixes across a routing trust boundary.",
                    f"Apply a least-privilege {direction} routing policy appropriate to this peer.",
                    Severity.HIGH,
                    evidence,
                    (JUNIPER_BGP_SECURITY_GUIDE,),
                ))
            if not peer.prefix_limit:
                self.add_issue(self._finding(
                    parser,
                    "juniper.junos.routing.bgp.prefix_limit",
                    "External BGP neighbor has no prefix limit",
                    f"External BGP {scope} has no explicit prefix-limit; no numeric threshold is inferred.",
                    "An unexpectedly large route advertisement can consume routing resources or disrupt forwarding.",
                    "Configure an accepted-prefix-limit or prefix-limit based on the documented expected route volume.",
                    Severity.MEDIUM,
                    evidence,
                    (JUNIPER_BGP_SECURITY_GUIDE,),
                ))

        for interface in junos.get_ospf_interfaces():
            if not interface.active or interface.passive or interface.authentication_state in {"authenticated", "unknown"}:
                continue
            evidence = tuple(item for item in interface.evidence)
            if interface.authentication_state == "weak":
                rule_id = "juniper.junos.routing.ospf.weak_authentication"
                title = "OSPF interface uses simple-password authentication"
                observation = f"OSPF interface {interface.interface}, area {interface.area}, routing-instance {interface.routing_instance} uses simple-password authentication."
                recommendation = "Use MD5 or a release-supported key-chain algorithm consistently across the OSPFv2 adjacency."
                severity = Severity.MEDIUM
            else:
                rule_id = "juniper.junos.routing.ospf.authentication"
                title = "OSPF interface authentication is incomplete"
                observation = f"OSPF interface {interface.interface}, area {interface.area}, routing-instance {interface.routing_instance} is {interface.authentication_state}."
                recommendation = "Configure and validate OSPFv2 authentication consistently across the adjacency."
                severity = Severity.HIGH
            self.add_issue(self._finding(
                parser, rule_id, title, observation,
                "An unprotected routing adjacency can accept forged protocol packets from a reachable attacker.",
                recommendation, severity, evidence, (JUNIPER_OSPF_AUTH_GUIDE,),
            ))

    def check_discovery(self, parser: BaseDeviceParser) -> None:
        junos = self._junos(parser)
        if junos.parse_error or junos.get_version() == "?":
            return
        for interface in junos.get_discovery_interfaces():
            if (
                not interface.active
                or interface.role != "external"
                or not (interface.transmit or interface.receive)
            ):
                continue
            evidence = tuple(item for item in interface.evidence) + (
                f"assessment policy: {interface.interface} role external",
            )
            self.add_issue(self._finding(
                parser,
                "juniper.junos.discovery.lldp.external",
                "LLDP is enabled on an external interface",
                f"Interface {interface.interface} is explicitly classified external and has LLDP transmit and receive enabled.",
                "LLDP can expose device identity and topology information across an untrusted boundary.",
                "Disable LLDP on this interface unless the assessment policy documents a required trusted use.",
                Severity.MEDIUM,
                evidence,
                (JUNIPER_LLDP_GUIDE,),
            ))

    def check_zone_screens(self, parser: BaseDeviceParser) -> None:
        junos = self._junos(parser)
        if (
            junos.parse_error
            or not junos.get_model().upper().startswith("SRX")
            or junos.has_unexpanded_inheritance()
        ):
            return
        for binding in junos.get_zone_screens():
            external = tuple(
                interface for interface in binding.interfaces
                if junos.assessment_context.role_for_interface(interface) == "external"
                or junos.assessment_context.role_for_interface(interface.split(".", 1)[0]) == "external"
            )
            if not external:
                continue
            evidence = tuple(item for item in binding.evidence) + tuple(
                f"assessment policy: {interface} role external" for interface in external
            )
            for option, state, reference in (
                ("syn_flood", binding.syn_flood_state, JUNIPER_SCREEN_REFERENCE),
                ("udp_flood", binding.udp_flood_state, JUNIPER_UDP_SCREEN_REFERENCE),
                ("icmp_flood", binding.icmp_flood_state, JUNIPER_ICMP_SCREEN_REFERENCE),
            ):
                if state != "explicitly-inactive":
                    continue
                label = {
                    "syn_flood": "TCP SYN-flood",
                    "udp_flood": "UDP-flood",
                    "icmp_flood": "ICMP-flood",
                }[option]
                self.add_issue(self._finding(
                    parser,
                    f"juniper.junos.screen.{option}_inactive",
                    f"Attached SRX screen has {label} protection deactivated",
                    f"SRX zone {binding.zone} attaches screen {binding.screen} on assessed external interface(s) {', '.join(external)}, but its configured {label} option is explicitly inactive.",
                    f"The attached screen does not provide its configured {label} defense on this ingress zone.",
                    f"Activate and tune {label} protection in the attached screen after validating legitimate traffic levels.",
                    Severity.HIGH,
                    evidence,
                    (reference,),
                ))
            if binding.alarm_without_drop:
                for option, state, reference in (
                    ("udp_flood", binding.udp_flood_state, JUNIPER_UDP_SCREEN_REFERENCE),
                    ("icmp_flood", binding.icmp_flood_state, JUNIPER_ICMP_SCREEN_REFERENCE),
                ):
                    if state != "active":
                        continue
                    label = "UDP-flood" if option == "udp_flood" else "ICMP-flood"
                    self.add_issue(self._finding(
                        parser,
                        f"juniper.junos.screen.{option}_alarm_only",
                        f"Attached SRX {label} screen alarms without dropping",
                        f"SRX zone {binding.zone} attaches screen {binding.screen} on assessed external interface(s) {', '.join(external)}; {label} detection is active but the screen explicitly uses alarm-without-drop.",
                        f"The configured screen alarms on detected {label} traffic without blocking it.",
                        "Remove alarm-without-drop where blocking is required, then validate thresholds against legitimate traffic.",
                        Severity.HIGH,
                        evidence,
                        (JUNIPER_SCREEN_OPTION_REFERENCE, reference),
                    ))

    def check_idp_actions(self, parser: BaseDeviceParser) -> None:
        """Report an IDP policy applied by a permit rule whose every IPS rule is non-blocking."""

        junos = self._junos(parser)
        if (
            junos.parse_error
            or not junos.get_model().upper().startswith("SRX")
            or junos.has_unexpanded_inheritance()
        ):
            return
        for binding in junos.get_idp_bindings():
            if binding.resolution_state != "resolved" or not binding.rules:
                continue
            actions = {rule.action for rule in binding.rules}
            if None in actions or not actions <= IDP_NON_BLOCKING_ACTIONS:
                continue
            evidence = tuple(binding.evidence) + tuple(
                item for rule in binding.rules for item in rule.evidence
            )
            self.add_issue(self._finding(
                parser,
                "juniper.junos.policy.idp_nonblocking",
                "Applied IDP policy has no blocking rule",
                (
                    f"Security policy {binding.from_zone}->{binding.to_zone} '{binding.security_policy}' "
                    f"permits traffic with IDP policy '{binding.idp_policy}', but every active IPS rule "
                    f"in that policy uses a non-blocking action ({', '.join(sorted(actions))})."
                ),
                "Detected attacks in this permitted traffic are at most logged; the IDP policy cannot stop them.",
                "Use a blocking action (for example drop-connection or recommended) for rules that match high-risk attacks, after validating false positives.",
                Severity.MEDIUM,
                evidence,
                (JUNIPER_IDP_ACTION_REFERENCE, JUNIPER_IDP_RULEBASE_REFERENCE),
            ))

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_ssh_algorithms(parser)
        self.check_additional_services(parser)
        self.check_snmp(parser)
        self.check_default_security_policy(parser)
        if not self._applicable(parser):
            return
        self.check_authentication(parser)
        self.check_administrative_policy(parser)
        self.check_aaa_transport(parser)
        self.check_logging(parser)
        self.check_configuration_management(parser)
        self.check_ntp(parser)
        self.check_routing_engine_filter(parser)
        self.check_redirects(parser)
        self.check_routing(parser)
        self.check_discovery(parser)
        self.check_zone_screens(parser)
        self.check_idp_actions(parser)
