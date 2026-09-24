"""Explicit BIG-IP TMOS management and audit controls."""

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.f5.bigip import (
    F5BIGIPParser, F5Setting, resolve_ssl_protocols, weak_literal_cipher_suites,
)


SSHD = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_sshd.html"
HTTPD = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/sys/sys_httpd.html"
CONSOLE = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_global-settings.html"
CLI = "https://clouddocs.f5.com/cli/tmsh-reference/v15/modules/cli/cli_global-settings.html"
PASSWORD = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/auth/auth_password-policy.html"
USER = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/auth/auth_user.html"
AUTH_SOURCE = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/auth/auth_source.html"
AUTH_LDAP = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/auth/auth_ldap.html"
AUTH_CERT_LDAP = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/auth/auth_cert-ldap.html"
SYSLOG = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_syslog.html"
CLIENT_SSL = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/ltm/ltm_profile_client-ssl.html"
VIRTUAL = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/ltm/ltm_virtual.html"
HTTPD_TLS_DEFAULT = "https://cdn.f5.com/product/bugtracker/ID668624.html"
RFC_8996 = "https://www.rfc-editor.org/rfc/rfc8996"
NIST_TLS = "https://csrc.nist.gov/pubs/sp/800/52/r2/final"
SNMP = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/sys/sys_snmp.html"
RFC_3414 = "https://www.rfc-editor.org/rfc/rfc3414"


class PluginF5BIGIPChecks(BasePlugin):
    def _emit(self, parser: F5BIGIPParser, setting: F5Setting, *, rule_id: str,
              title: str, observation: str, impact: str, recommendation: str,
              severity: Severity, reference: str) -> None:
        self.add_issue(Finding(
            rule_id=rule_id, device=parser.device_type, title=title,
            observation=observation, impact=impact,
            exploitability="An attacker who can reach the management service or obtain administrative access may exploit this setting.",
            recommendation=recommendation, severity=severity,
            evidence=(setting.evidence,), references=(reference,),
        ))

    def analyze(self, parser: BaseDeviceParser) -> None:
        if not isinstance(parser, F5BIGIPParser):
            raise TypeError("PluginF5BIGIPChecks requires an F5BIGIPParser")
        setting = parser.get_setting
        ssh_login = setting("sys sshd", "login")
        ssh_active = ssh_login is not None and ssh_login.value == "enabled"
        ssh_allow = setting("sys sshd", "allow")
        if ssh_active and ssh_allow and ssh_allow.value == "unrestricted":
            self._emit(parser, ssh_allow, rule_id="f5.bigip.ssh.unrestricted_sources",
                       title="SSH permits unrestricted management sources",
                       observation="The explicitly enabled SSH service has an unrestricted source allow setting.",
                       impact="More hosts can attempt administrative SSH authentication.",
                       recommendation="Restrict SSH to authorized management addresses.",
                       severity=Severity.HIGH, reference=SSHD)
        ssh_timeout = setting("sys sshd", "inactivity-timeout")
        if ssh_active and ssh_timeout and ssh_timeout.value == 0:
            self._emit(parser, ssh_timeout, rule_id="f5.bigip.ssh.idle_timeout_disabled",
                       title="SSH idle timeout is disabled",
                       observation="The enabled SSH service has an explicit inactivity timeout of zero seconds.",
                       impact="An unattended administrative session can remain open.",
                       recommendation="Set a finite SSH inactivity timeout appropriate for the management policy.",
                       severity=Severity.MEDIUM, reference=SSHD)
        http_allow = setting("sys httpd", "allow")
        if http_allow and http_allow.value == "unrestricted":
            self._emit(parser, http_allow, rule_id="f5.bigip.http.unrestricted_sources",
                       title="Configuration utility permits unrestricted source addresses",
                       observation="The HTTP configuration utility allow setting explicitly permits all source addresses.",
                       impact="More hosts can attempt access to the management interface when it is running.",
                       recommendation="Restrict the configuration utility to authorized management addresses.",
                       severity=Severity.HIGH, reference=HTTPD)
        redirect = setting("sys httpd", "redirect-http-to-https")
        if redirect and redirect.value == "disabled" and not (http_allow and http_allow.value == "none"):
            self._emit(parser, redirect, rule_id="f5.bigip.http.redirect_disabled",
                       title="HTTP-to-HTTPS management redirect is disabled",
                       observation="The configuration utility explicitly does not redirect HTTP requests to HTTPS.",
                       impact="HTTP requests to the configuration utility are not automatically upgraded to HTTPS where its HTTP path is reachable.",
                       recommendation="Enable HTTP-to-HTTPS redirection and restrict management access.",
                       severity=Severity.MEDIUM, reference=HTTPD)
        if not (http_allow and http_allow.value == "none"):
            self._check_management_tls(parser)
        self._check_snmp(parser)
        console = setting("sys global-settings", "console-inactivity-timeout")
        if console and console.value == 0:
            self._emit(parser, console, rule_id="f5.bigip.console.idle_timeout_disabled",
                       title="Console idle timeout is disabled",
                       observation="The explicit console inactivity timeout is zero seconds.",
                       impact="An unattended console session can remain open.",
                       recommendation="Set a finite console inactivity timeout.",
                       severity=Severity.MEDIUM, reference=CONSOLE)
        cli_timeout = setting("cli global-settings", "idle-timeout")
        if cli_timeout and cli_timeout.value == "disabled":
            self._emit(parser, cli_timeout, rule_id="f5.bigip.cli.idle_timeout_disabled",
                       title="tmsh idle timeout is disabled",
                       observation="The tmsh interactive session has an explicitly disabled idle timeout.",
                       impact="An unattended administrative shell can remain available.",
                       recommendation="Set a finite tmsh idle timeout.",
                       severity=Severity.MEDIUM, reference=CLI)
        audit = setting("cli global-settings", "audit")
        if audit and audit.value == "disabled":
            self._emit(parser, audit, rule_id="f5.bigip.cli.audit_disabled",
                       title="tmsh command auditing is disabled",
                       observation="The CLI audit setting is explicitly disabled.",
                       impact="Administrative command activity may be missing from the audit log.",
                       recommendation="Enable tmsh command auditing and forward relevant logs.",
                       severity=Severity.HIGH, reference=CLI)
        password = setting("auth password-policy", "policy-enforcement")
        if password and password.value == "disabled":
            self._emit(parser, password, rule_id="f5.bigip.password_policy.enforcement_disabled",
                       title="Local password policy enforcement is disabled",
                       observation="The exported password policy explicitly disables enforcement.",
                       impact="Locally managed passwords need not satisfy the configured policy constraints.",
                       recommendation="Enable password policy enforcement and set organization-approved constraints.",
                       severity=Severity.HIGH, reference=PASSWORD)
        failures = setting("auth password-policy", "max-login-failures")
        if failures and failures.value == 0:
            self._emit(parser, failures, rule_id="f5.bigip.password_policy.login_lockout_disabled",
                       title="Local login lockout is disabled",
                       observation="The explicit maximum-login-failures value is zero, disabling local user lockout.",
                       impact="Repeated local password guesses are not stopped by this account-lockout setting.",
                       recommendation="Set a finite maximum-login-failures value under the approved administrative policy.",
                       severity=Severity.MEDIUM, reference=PASSWORD)
        minimum = setting("auth password-policy", "minimum-length")
        if password and password.value == "enabled" and minimum and minimum.value == 0:
            self._emit(parser, minimum, rule_id="f5.bigip.password_policy.minimum_length_disabled",
                       title="Enforced local password policy has no minimum length",
                       observation="Password-policy enforcement is enabled but its explicit minimum-length value is zero.",
                       impact="The configured local password policy does not require any minimum password length.",
                       recommendation="Set a positive minimum length appropriate to the approved password policy.",
                       severity=Severity.MEDIUM, reference=PASSWORD)
        for credential in parser.get_local_user_credentials():
            if credential.storage != "plaintext":
                continue
            self.add_issue(Finding(
                rule_id="f5.bigip.credentials.local_plaintext",
                device=parser.device_type,
                title="Local user password is present in plaintext",
                observation=f"Saved auth user object '{credential.name}' uses an explicit plaintext password field.",
                impact="Anyone who obtains the exported configuration may recover that local user's password.",
                exploitability="An attacker needs access to the saved configuration or report source.",
                recommendation="Replace the exposed password and use an export that stores only protected credential material.",
                severity=Severity.HIGH,
                evidence=(credential.evidence,),
                references=(USER,),
            ))
        active_auth = setting("auth source", "type")
        if active_auth and active_auth.value in {"radius", "ldap", "tacacs", "cert-ldap"}:
            profiles = parser.get_remote_auth_profiles(str(active_auth.value))
            if profiles and all(profile.servers_state == "none" for profile in profiles):
                self.add_issue(Finding(
                    rule_id="f5.bigip.auth.active_remote_servers_none",
                    device=parser.device_type,
                    title="Active remote authentication has no configured servers",
                    observation=(
                        f"The explicit auth source selects {active_auth.value}, while every "
                        "exported provider object of that type explicitly sets servers none."
                    ),
                    impact="Remote administrators may be unable to authenticate through the selected source.",
                    exploitability="This is an availability and administrative-access risk, not proof of a live login failure.",
                    recommendation=(
                        "Configure valid servers for the selected authentication provider and "
                        "verify the intended emergency local-access policy."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=(active_auth.evidence,) + tuple(
                        profile.evidence for profile in profiles
                    ),
                    references=(AUTH_SOURCE,),
                ))
            if (active_auth.value in {"ldap", "cert-ldap"} and profiles
                    and all(profile.servers_state == "configured"
                            and profile.ssl_state == "disabled" for profile in profiles)):
                self.add_issue(Finding(
                    rule_id="f5.bigip.auth.ldap_ssl_disabled",
                    device=parser.device_type,
                    title="Active LDAP authentication explicitly disables protected transport",
                    observation=(
                        f"The selected {active_auth.value} authentication source has configured "
                        "server references, but every exported provider object explicitly sets ssl disabled."
                    ),
                    impact="LDAP authentication traffic is not protected by the provider's SSL/TLS setting.",
                    exploitability="An observer on an unprotected path to an LDAP server may inspect or alter traffic.",
                    recommendation=(
                        "Enable verified TLS or StartTLS for the selected LDAP provider, or document "
                        "a separately protected path and its trust boundary."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=(active_auth.evidence,) + tuple(
                        profile.evidence for profile in profiles
                    ),
                    references=(AUTH_SOURCE, AUTH_CERT_LDAP if active_auth.value == "cert-ldap" else AUTH_LDAP),
                ))
            if (active_auth.value in {"ldap", "cert-ldap"} and profiles
                    and all(profile.servers_state == "configured"
                            and profile.ssl_state in {"enabled", "start-tls"}
                            and profile.peer_check_state == "disabled"
                            for profile in profiles)):
                self.add_issue(Finding(
                    rule_id="f5.bigip.auth.ldap_peer_check_disabled",
                    device=parser.device_type,
                    title="Active LDAP authentication does not verify the TLS peer",
                    observation=(
                        f"The selected {active_auth.value} authentication source uses protected "
                        "transport, but every exported provider object explicitly sets "
                        "ssl-check-peer disabled."
                    ),
                    impact="The device may accept an untrusted LDAP server certificate.",
                    exploitability="A network attacker able to impersonate the LDAP endpoint may intercept or alter authentication traffic.",
                    recommendation=(
                        "Enable LDAP TLS peer verification and configure the appropriate trusted CA "
                        "for each selected provider."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=(active_auth.evidence,) + tuple(
                        profile.evidence for profile in profiles
                    ),
                    references=(AUTH_SOURCE, AUTH_CERT_LDAP if active_auth.value == "cert-ldap" else AUTH_LDAP),
                ))
        remote = setting("sys syslog", "remote-servers")
        if remote and remote.value == "none":
            self._emit(parser, remote, rule_id="f5.bigip.logging.syslog_remote_none",
                       title="Standard remote syslog has no server",
                       observation="The system syslog remote-servers setting is explicitly none; other logging paths are not assessed by this check.",
                       impact="Standard system logs may lack an external copy if no other forwarding path is configured.",
                       recommendation="Configure an appropriate remote syslog destination and verify delivery.",
                       severity=Severity.MEDIUM, reference=SYSLOG)
        for virtual, profile in parser.get_bound_cleartext_client_ssl():
            self.add_issue(Finding(
                rule_id="f5.bigip.ltm.clientssl_cleartext_enabled",
                device=parser.device_type,
                title="Active virtual server permits non-SSL client traffic",
                observation=(f"Enabled virtual server '{virtual.name}' attaches enabled Client SSL profile "
                             f"'{profile.name}' with allow-non-ssl enabled."),
                impact="Client traffic can pass without the expected TLS protection on this virtual server.",
                exploitability="A client reaching this virtual server may send plaintext traffic when the profile permits it.",
                recommendation="Disable allow-non-ssl on the attached Client SSL profile after validating application requirements.",
                severity=Severity.HIGH,
                evidence=(virtual.evidence, profile.evidence),
                references=(VIRTUAL, CLIENT_SSL),
            ))

    def _check_management_tls(self, parser: F5BIGIPParser) -> None:
        protocol = parser.get_setting("sys httpd", "ssl-protocol")
        enabled = resolve_ssl_protocols(str(protocol.value)) if protocol and protocol.value else None
        legacy = [item for item in (enabled or ()) if item in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}]
        if legacy:
            self.add_issue(Finding(
                rule_id="f5.bigip.http.legacy_tls_protocol",
                device=parser.device_type,
                title="Configuration utility accepts legacy SSL/TLS versions",
                observation=(
                    f"The explicit sys httpd ssl-protocol value enables {', '.join(legacy)} for the "
                    "configuration utility (mod_ssl SSLProtocol semantics)."
                ),
                impact="Administrative HTTPS sessions can be negotiated with deprecated protocol versions.",
                exploitability="A network attacker on the management path may attempt protocol downgrade or known attacks on legacy TLS.",
                recommendation="Set ssl-protocol so only TLS 1.2 and TLS 1.3 are accepted, for example 'all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1'.",
                severity=Severity.HIGH,
                evidence=(protocol.evidence,),
                references=(HTTPD, HTTPD_TLS_DEFAULT, RFC_8996),
            ))
        suites = parser.get_setting("sys httpd", "ssl-ciphersuite")
        weak = weak_literal_cipher_suites(str(suites.value)) if suites and suites.value else None
        if weak:
            self.add_issue(Finding(
                rule_id="f5.bigip.http.weak_cipher_suite",
                device=parser.device_type,
                title="Configuration utility offers weak cipher suites",
                observation=(
                    "The explicit sys httpd ssl-ciphersuite list includes "
                    f"{', '.join(weak)}."
                ),
                impact="Administrative HTTPS sessions may use obsolete ciphers such as 3DES, RC4, NULL or export suites.",
                exploitability="An attacker who can observe or influence the management connection may exploit weak cipher properties.",
                recommendation="Remove legacy suites and offer only AEAD suites with forward secrecy (for example ECDHE with AES-GCM).",
                severity=Severity.MEDIUM,
                evidence=(suites.evidence,),
                references=(HTTPD, NIST_TLS),
            ))

    def _check_snmp(self, parser: F5BIGIPParser) -> None:
        agent = parser.get_snmp_agent()
        # Only an explicitly exported non-loopback client scope makes SNMP access reachable.
        if agent is None or agent.client_scope not in {"unrestricted", "restricted"}:
            return
        communities = parser.get_snmp_communities()
        if agent.client_scope == "unrestricted" and communities:
            self.add_issue(Finding(
                rule_id="f5.bigip.snmp.community_access",
                device=parser.device_type,
                title="SNMP community access is allowed from any address",
                observation="sys snmp allowed-addresses explicitly admits every client address while community-based access is configured.",
                impact="Any host that can reach the management address may attempt SNMP queries with a guessed or captured community.",
                exploitability="An attacker with network reach can query SNMP data using a known or observed community string.",
                recommendation="Limit allowed-addresses to the monitoring systems and replace communities with SNMPv3 users.",
                severity=Severity.HIGH,
                evidence=(agent.evidence,) + tuple(item.evidence for item in communities),
                references=(SNMP,),
            ))
        for community in communities:
            if community.default_name:
                self.add_issue(Finding(
                    rule_id="f5.bigip.snmp.default_community",
                    device=parser.device_type,
                    title="Default SNMP community is configured",
                    observation=f"SNMP community object '{community.name}' uses a well-known default community name.",
                    impact="Default community strings are the first values tried by scanners and grant the object's SNMP access.",
                    exploitability="An attacker permitted by allowed-addresses can query the device without learning a secret.",
                    recommendation="Remove the default community; use SNMPv3 users or a unique community restricted to monitoring hosts.",
                    severity=Severity.HIGH,
                    evidence=(agent.evidence, community.evidence),
                    references=(SNMP,),
                ))
            if community.access == "rw":
                self.add_issue(Finding(
                    rule_id="f5.bigip.snmp.write_community",
                    device=parser.device_type,
                    title="SNMP community grants write access",
                    observation=f"SNMP community object '{community.name}' has access rw.",
                    impact="A holder of the community string can change SNMP-writable settings over an unauthenticated, unencrypted protocol.",
                    exploitability="An attacker permitted by allowed-addresses who learns the community can modify writable objects.",
                    recommendation="Set community access to ro, or remove the community and use an authenticated SNMPv3 user.",
                    severity=Severity.HIGH,
                    evidence=(agent.evidence, community.evidence),
                    references=(SNMP,),
                ))
        for user in parser.get_snmp_users():
            if user.security_level in {"no-auth-no-privacy", "auth-no-privacy"}:
                self.add_issue(Finding(
                    rule_id="f5.bigip.snmp.v3_security",
                    device=parser.device_type,
                    title="SNMPv3 user does not require authentication and privacy",
                    observation=f"SNMPv3 user '{user.name}' has security-level {user.security_level}.",
                    impact="SNMP messages for this user are not both authenticated and encrypted.",
                    exploitability="An attacker on the monitoring path may read or forge this user's SNMP traffic.",
                    recommendation="Set security-level auth-privacy with SHA authentication and AES privacy.",
                    severity=Severity.MEDIUM,
                    evidence=(agent.evidence, user.evidence),
                    references=(SNMP, RFC_3414),
                ))
            elif user.auth_protocol == "md5" or user.privacy_protocol == "des":
                self.add_issue(Finding(
                    rule_id="f5.bigip.snmp.v3_weak_algorithm",
                    device=parser.device_type,
                    title="SNMPv3 user uses a legacy algorithm",
                    observation=(
                        f"SNMPv3 user '{user.name}' uses auth-protocol {user.auth_protocol} "
                        f"and privacy-protocol {user.privacy_protocol}."
                    ),
                    impact="MD5 authentication and DES privacy provide weak protection for SNMP messages.",
                    exploitability="An attacker who captures SNMP traffic has a better chance to recover or forge protected messages.",
                    recommendation="Use SHA authentication and AES privacy for SNMPv3 users.",
                    severity=Severity.MEDIUM,
                    evidence=(agent.evidence, user.evidence),
                    references=(SNMP, RFC_3414),
                ))
