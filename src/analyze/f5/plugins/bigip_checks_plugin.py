"""Explicit BIG-IP TMOS management and audit controls."""

import re

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.controls import ControlOutcome as CO, record_control
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.analyze.common.risky_services import CISCO_PORT_NAMES, risky_labels
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
VIRTUAL_SOURCE_DEFAULT = {
    13: "https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/ltm-basics-13-0-0/2.html",
    14: "https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/big-ip-local-traffic-management-basics-14-0-0/02.html",
}
HTTPD_TLS_DEFAULT = "https://cdn.f5.com/product/bugtracker/ID668624.html"
RFC_8996 = "https://www.rfc-editor.org/rfc/rfc8996"
NIST_TLS = "https://csrc.nist.gov/pubs/sp/800/52/r2/final"
SNMP = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/sys/sys_snmp.html"
RFC_3414 = "https://www.rfc-editor.org/rfc/rfc3414"
NTP = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/sys/sys_ntp.html"
NTP_AUTH = "https://my.f5.com/manage/s/article/K14120"
AFM_DEFAULT_PROCESSING = (
    "https://techdocs.f5.com/en-us/bigip-15-1-0/big-ip-network-firewall-policies-and-implementations/"
    "afm-firewall-default-traffic-processing.html"
)
AFM_DEFAULT_ACTION_DB = "https://cdn.f5.com/product/bugtracker/ID813165.html"
ASM_POLICY = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/asm/asm_policy.html"
LTM_POLICY = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/ltm/ltm_policy.html"
NET_SELF = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/net/net_self.html"
PORT_LOCKDOWN = "https://my.f5.com/manage/s/article/K17333"
ICONTROL_CVE_2022_1388 = "https://my.f5.com/manage/s/article/K23605346"
IKE_PEER = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/net/net_ipsec_ike-peer.html"
RFC_2409 = "https://www.rfc-editor.org/rfc/rfc2409"
_MANAGEMENT_SERVICES = {"tcp:22", "tcp:ssh", "tcp:443", "tcp:https", "tcp:any", "tcp:0"}
REMOTE_USER = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/auth/auth_remote-user.html"
PASSWORD_POLICY_LATEST = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/auth/auth_password-policy.html"
USER_LATEST = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/auth/auth_user.html"
LOCKDOWN_SETTINGS = "https://community.f5.com/kb/technicalarticles/10-settings-to-lock-down-your-big-ip/274601"
COOKIE_PERSISTENCE = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/ltm/ltm_persistence_cookie.html"
COOKIE_ENCODING = "https://my.f5.com/manage/s/article/K6917"
MONITOR_HTTP = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/ltm/ltm_monitor_http.html"
SNMP_LATEST = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_snmp.html"
# SC-044 release-default sources (docs/agent_notes/INSECURE_DEFAULTS_BY_RELEASE.md).
SERVER_SSL = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/ltm/ltm_profile_server-ssl.html"
DEFAULT_PASSWORDS_K13121 = "https://my.f5.com/manage/s/article/K13121"
ROOT_LOGIN_K15632 = "https://my.f5.com/manage/s/article/K15632"
PASSWORD_POLICY_14 = "https://cdn.f5.com/product/bugtracker/ID661909.html"
COOKIE_ENCRYPTION_DEFAULT = "https://my.f5.com/manage/s/article/K23254150"
PORT_LOCKDOWN_11 = "https://my.f5.com/manage/s/article/K13250"
HTTPD_SSLV3 = "https://my.f5.com/manage/s/article/K15702"
HTTPD_LATEST = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_httpd.html"
CLIENTSSL_DEFAULT_SSLV3 = "https://my.f5.com/manage/s/article/K15022"
CLIENTSSL_DEFAULT_CIPHERS = "https://my.f5.com/manage/s/article/K13156"
CLIENTSSL_DEFAULT_17 = "https://my.f5.com/manage/s/article/K000134647"
CLIENTSSL_DEFAULT_16 = "https://my.f5.com/manage/s/article/K72605755"
_ANY_SOURCE = re.compile(r"^(0\.0\.0\.0(%\d+)?/0|::(%\d+)?/0|any)$")


class PluginF5BIGIPChecks(BasePlugin):
    def _emit(self, parser: F5BIGIPParser, setting: F5Setting, *, rule_id: str,
              title: str, observation: str, impact: str, recommendation: str,
              severity: Severity, reference: str, basis: FindingBasis | None = None) -> None:
        self.add_issue(Finding(
            rule_id=rule_id, device=parser.device_type, title=title,
            observation=observation, impact=impact,
            exploitability="An attacker who can reach the management service or obtain administrative access may exploit this setting.",
            recommendation=recommendation, severity=severity,
            evidence=(setting.evidence,), references=(reference,), basis=basis,
        ))

    def analyze(self, parser: BaseDeviceParser) -> None:
        if not isinstance(parser, F5BIGIPParser):
            raise TypeError("PluginF5BIGIPChecks requires an F5BIGIPParser")
        self._lockdown_names: set[str] = set()  # self IPs that received a port-lockdown finding
        self._fired_at: dict[str, set[str]] = {}  # rule ID -> instance keys that fired (SC-049)
        setting = parser.get_setting
        ssh_login = setting("sys sshd", "login")
        ssh_active = ssh_login is not None and ssh_login.value == "enabled"
        ssh_allow = setting("sys sshd", "allow")
        # An omitted 'login' inside an exported sys sshd block is the documented default
        # 'enabled' (tmsh sys sshd reference, v13-v17); outside that range it stays ungraded.
        release = parser.get_release()
        ssh_default_on = (ssh_login is None and parser.has_object("sys sshd")
                          and release is not None and (13, 0, 0) <= release < (18, 0, 0))
        if (ssh_active or ssh_default_on) and ssh_allow and ssh_allow.value == "unrestricted":
            self._emit(parser, ssh_allow, rule_id="f5.bigip.ssh.unrestricted_sources",
                       title="SSH permits unrestricted management sources",
                       observation=("The explicitly enabled SSH service has an unrestricted source allow setting."
                                    if ssh_active else
                                    "SSH 'login' is not configured, so the documented default 'enabled' applies, and the "
                                    "source allow setting is explicitly unrestricted."),
                       impact="More hosts can attempt administrative SSH authentication.",
                       recommendation="Restrict SSH to authorized management addresses.",
                       severity=Severity.HIGH, reference=SSHD,
                       basis=FindingBasis.EXPLICIT_VALUE if ssh_active else FindingBasis.DOCUMENTED_DEFAULT)
        ssh_timeout = setting("sys sshd", "inactivity-timeout")
        if ssh_active and ssh_timeout and ssh_timeout.value == 0:
            self._emit(parser, ssh_timeout, rule_id="f5.bigip.ssh.idle_timeout_disabled",
                       title="SSH idle timeout is disabled",
                       observation="The enabled SSH service has an explicit inactivity timeout of zero seconds.",
                       impact="An unattended administrative session can remain open.",
                       recommendation="Set a finite SSH inactivity timeout appropriate for the management policy.",
                       severity=Severity.MEDIUM, reference=SSHD,
                       basis=FindingBasis.EXPLICIT_VALUE)
        http_allow = setting("sys httpd", "allow")
        if http_allow and http_allow.value == "unrestricted":
            self._emit(parser, http_allow, rule_id="f5.bigip.http.unrestricted_sources",
                       title="Configuration utility permits unrestricted source addresses",
                       observation="The HTTP configuration utility allow setting explicitly permits all source addresses.",
                       impact="More hosts can attempt access to the management interface when it is running.",
                       recommendation="Restrict the configuration utility to authorized management addresses.",
                       severity=Severity.HIGH, reference=HTTPD,
                       basis=FindingBasis.EXPLICIT_VALUE)
        redirect = setting("sys httpd", "redirect-http-to-https")
        if redirect and redirect.value == "disabled" and not (http_allow and http_allow.value == "none"):
            self._emit(parser, redirect, rule_id="f5.bigip.http.redirect_disabled",
                       title="HTTP-to-HTTPS management redirect is disabled",
                       observation="The configuration utility explicitly does not redirect HTTP requests to HTTPS.",
                       impact="HTTP requests to the configuration utility are not automatically upgraded to HTTPS where its HTTP path is reachable.",
                       recommendation="Enable HTTP-to-HTTPS redirection and restrict management access.",
                       severity=Severity.MEDIUM, reference=HTTPD,
                       basis=FindingBasis.EXPLICIT_VALUE)
        if not (http_allow and http_allow.value == "none"):
            self._check_management_tls(parser)
        self._check_snmp(parser)
        self._check_ntp(parser)
        self._check_modules(parser)
        self._check_self_ips(parser)
        self._check_ike_peers(parser)
        self._check_admin_access(parser)
        self._check_data_plane(parser)
        self._check_cleartext_extras(parser)
        self._check_release_defaults(parser)
        console = setting("sys global-settings", "console-inactivity-timeout")
        if console and console.value == 0:
            self._emit(parser, console, rule_id="f5.bigip.console.idle_timeout_disabled",
                       title="Console idle timeout is disabled",
                       observation="The explicit console inactivity timeout is zero seconds.",
                       impact="An unattended console session can remain open.",
                       recommendation="Set a finite console inactivity timeout.",
                       severity=Severity.MEDIUM, reference=CONSOLE,
                       basis=FindingBasis.EXPLICIT_VALUE)
        cli_timeout = setting("cli global-settings", "idle-timeout")
        if cli_timeout and cli_timeout.value == "disabled":
            self._emit(parser, cli_timeout, rule_id="f5.bigip.cli.idle_timeout_disabled",
                       title="tmsh idle timeout is disabled",
                       observation="The tmsh interactive session has an explicitly disabled idle timeout.",
                       impact="An unattended administrative shell can remain available.",
                       recommendation="Set a finite tmsh idle timeout.",
                       severity=Severity.MEDIUM, reference=CLI,
                       basis=FindingBasis.EXPLICIT_VALUE)
        audit = setting("cli global-settings", "audit")
        if audit and audit.value == "disabled":
            self._emit(parser, audit, rule_id="f5.bigip.cli.audit_disabled",
                       title="tmsh command auditing is disabled",
                       observation="The CLI audit setting is explicitly disabled.",
                       impact="Administrative command activity may be missing from the audit log.",
                       recommendation="Enable tmsh command auditing and forward relevant logs.",
                       severity=Severity.HIGH, reference=CLI,
                       basis=FindingBasis.EXPLICIT_VALUE)
        password = setting("auth password-policy", "policy-enforcement")
        if password and password.value == "disabled":
            self._emit(parser, password, rule_id="f5.bigip.password_policy.enforcement_disabled",
                       title="Local password policy enforcement is disabled",
                       observation="The exported password policy explicitly disables enforcement.",
                       impact="Locally managed passwords need not satisfy the configured policy constraints.",
                       recommendation="Enable password policy enforcement and set organization-approved constraints.",
                       severity=Severity.HIGH, reference=PASSWORD,
                       basis=FindingBasis.EXPLICIT_VALUE)
        failures = setting("auth password-policy", "max-login-failures")
        if failures and failures.value == 0:
            self._emit(parser, failures, rule_id="f5.bigip.password_policy.login_lockout_disabled",
                       title="Local login lockout is disabled",
                       observation="The explicit maximum-login-failures value is zero, disabling local user lockout.",
                       impact="Repeated local password guesses are not stopped by this account-lockout setting.",
                       recommendation="Set a finite maximum-login-failures value under the approved administrative policy.",
                       severity=Severity.MEDIUM, reference=PASSWORD,
                       basis=FindingBasis.EXPLICIT_VALUE)
        minimum = setting("auth password-policy", "minimum-length")
        if password and password.value == "enabled" and minimum and minimum.value == 0:
            self._emit(parser, minimum, rule_id="f5.bigip.password_policy.minimum_length_disabled",
                       title="Enforced local password policy has no minimum length",
                       observation="Password-policy enforcement is enabled but its explicit minimum-length value is zero.",
                       impact="The configured local password policy does not require any minimum password length.",
                       recommendation="Set a positive minimum length appropriate to the approved password policy.",
                       severity=Severity.MEDIUM, reference=PASSWORD,
                       basis=FindingBasis.EXPLICIT_VALUE)
        for credential in parser.get_local_user_credentials():
            if credential.known_default:
                self._mark("f5.bigip.credentials.known_default_value", credential.name)
                self.add_issue(Finding(
                    rule_id="f5.bigip.credentials.known_default_value",
                    device=parser.device_type,
                    title="Built-in account still uses its factory password",
                    observation=(f"The stored password of '{credential.name}' is the documented factory default "
                                 "(recognised by recomputing its hash; the value is not shown)."),
                    impact="Anyone who reaches the Configuration utility, iControl REST or SSH can log in as this administrator.",
                    exploitability="Factory credentials (admin/admin, root/default) are published and tried first by attackers.",
                    recommendation="Change the password now ('modify auth user admin prompt-for-password'), and disable or rename unused built-in accounts (K15632).",
                    severity=Severity.CRITICAL,
                    evidence=(credential.evidence,),
                    references=(DEFAULT_PASSWORDS_K13121, ROOT_LOGIN_K15632),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            if credential.storage != "plaintext":
                continue
            self._mark("f5.bigip.credentials.local_plaintext", credential.name)
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
                basis=FindingBasis.EXPLICIT_VALUE,
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
                    basis=FindingBasis.REQUIRED_SETTING_MISSING,
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
                    basis=FindingBasis.EXPLICIT_VALUE,
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
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
        remote = setting("sys syslog", "remote-servers")
        if remote and remote.value == "none":
            self._emit(parser, remote, rule_id="f5.bigip.logging.syslog_remote_none",
                       title="Standard remote syslog has no server",
                       observation="The system syslog remote-servers setting is explicitly none; other logging paths are not assessed by this check.",
                       impact="Standard system logs may lack an external copy if no other forwarding path is configured.",
                       recommendation="Configure an appropriate remote syslog destination and verify delivery.",
                       severity=Severity.MEDIUM, reference=SYSLOG,
                       basis=FindingBasis.REQUIRED_SETTING_MISSING)
        for virtual, profile in parser.get_bound_cleartext_client_ssl():
            self._mark("f5.bigip.ltm.clientssl_cleartext_enabled", f"{virtual.name}|{profile.name}")
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
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        self._record_controls(parser)
        self._record_completion(parser)

    def _record_controls(self, parser: F5BIGIPParser) -> None:
        """SC-049 fifth batch: one outcome per control (per self IP) after the checks ran."""
        fired = {issue.rule_id for issue in self.issues}
        setting = parser.get_setting
        release = parser.get_release()

        control = "f5.bigip.self-ip-port-lockdown"
        self_ips = parser.get_self_ips()
        if not self_ips:
            record_control(parser, control, CO.NOT_APPLICABLE, "No self IP is configured.")
        lockdown = getattr(self, "_lockdown_names", set())
        for self_ip in self_ips:
            if self_ip.name in lockdown:
                record_control(parser, control, CO.FINDING, "Port lockdown allows SSH or HTTPS management.",
                               instance=self_ip.name)
            elif self_ip.allow_service:
                record_control(parser, control, CO.NO_FINDING,
                               "Port lockdown does not allow SSH or HTTPS management.", instance=self_ip.name)
            elif release is not None and release >= (11, 5, 3):
                record_control(parser, control, CO.NO_FINDING,
                               "allow-service is omitted; the documented default for this release is none.",
                               instance=self_ip.name)
            else:
                record_control(parser, control, CO.UNKNOWN,
                               "allow-service is omitted and the default is not verified for this release.",
                               instance=self_ip.name)

        control = "f5.bigip.root-login"
        root = parser.get_db("systemauth.disablerootlogin")
        login = setting("sys sshd", "login")
        if "f5.bigip.auth.root_login_enabled" in fired:
            record_control(parser, control, CO.FINDING, "Direct root login is allowed.")
        elif root is not None:
            record_control(parser, control,
                           CO.NO_FINDING if root[0].strip('"').casefold() == "true" else CO.UNKNOWN,
                           "systemauth.disablerootlogin is true." if root[0].strip('"').casefold() == "true"
                           else "systemauth.disablerootlogin has an unrecognized value.")
        elif not parser.has_db_entries():
            record_control(parser, control, CO.UNKNOWN, "No sys db settings are exported; the root login state is not evaluated.")
        elif release is None or release < (11, 6, 0) or not parser.has_object("sys sshd") or (
                login is not None and login.value is None):
            record_control(parser, control, CO.UNKNOWN,
                           "The root login default is not verified for this release or the SSH service block is missing or malformed.")
        else:
            record_control(parser, control, CO.NOT_APPLICABLE,
                           "systemauth.disablerootlogin is at its default and SSH login is disabled.")

        control = "f5.bigip.ssh-source-restriction"
        allow = setting("sys sshd", "allow")
        if "f5.bigip.ssh.unrestricted_sources" in fired:
            record_control(parser, control, CO.FINDING, "SSH accepts any source address.")
        elif not parser.has_object("sys sshd") or (login is not None and login.value is None):
            record_control(parser, control, CO.UNKNOWN, "The sys sshd block is not exported or its login value is malformed.")
        elif login is not None and login.value == "disabled":
            record_control(parser, control, CO.NOT_APPLICABLE, "SSH login is disabled.")
        elif allow is not None and allow.value == "restricted":
            record_control(parser, control, CO.NO_FINDING, "SSH is limited to listed source addresses.")
        elif allow is not None and allow.value == "unrestricted":
            record_control(parser, control, CO.UNKNOWN,
                           "SSH allow is unrestricted and login is omitted; the login default is documented only for 13.x-17.x.")
        else:
            record_control(parser, control, CO.UNKNOWN,
                           "The SSH allow value is malformed or its default is not verified for this release.")

        control = "f5.bigip.httpd-source-restriction"
        http_allow = setting("sys httpd", "allow")
        if "f5.bigip.http.unrestricted_sources" in fired:
            record_control(parser, control, CO.FINDING, "The configuration utility accepts any source address.")
        elif http_allow is not None and http_allow.value == "none":
            record_control(parser, control, CO.NOT_APPLICABLE, "The configuration utility allows no source (allow none).")
        elif http_allow is not None and http_allow.value == "restricted":
            record_control(parser, control, CO.NO_FINDING, "The configuration utility is limited to listed source addresses.")
        elif not parser.has_object("sys httpd"):
            record_control(parser, control, CO.UNKNOWN, "No sys httpd block is exported.")
        else:
            record_control(parser, control, CO.UNKNOWN,
                           "The httpd allow value is malformed or its default is not verified for this release.")

        control = "f5.bigip.password-policy-enforcement"
        enforcement = setting("auth password-policy", "policy-enforcement")
        if "f5.bigip.password_policy.enforcement_disabled" in fired:
            record_control(parser, control, CO.FINDING, "Password policy enforcement is disabled.")
        elif enforcement is not None:
            record_control(parser, control, CO.NO_FINDING if enforcement.value == "enabled" else CO.UNKNOWN,
                           "Password policy enforcement is enabled." if enforcement.value == "enabled"
                           else "The policy-enforcement value is malformed.")
        elif not parser.has_object("auth password-policy"):
            record_control(parser, control, CO.UNKNOWN, "No auth password-policy block is exported.")
        elif release is not None and release >= (14, 0, 0):
            record_control(parser, control, CO.NO_FINDING,
                           "policy-enforcement is omitted; from 14.0.0 the documented default is enabled.")
        else:
            record_control(parser, control, CO.UNKNOWN, "The policy-enforcement default is not verified for this release.")

        control = "f5.bigip.snmp-community"
        agent = parser.get_snmp_agent()
        communities = parser.get_snmp_communities()
        if fired & {"f5.bigip.snmp.community_access", "f5.bigip.snmp.default_community", "f5.bigip.snmp.write_community"}:
            record_control(parser, control, CO.FINDING, "A default, writable or unrestricted SNMP community is reachable.")
        elif not parser.has_object("sys snmp"):
            record_control(parser, control, CO.UNKNOWN, "No sys snmp block is exported.")
        elif agent is None or agent.client_scope in {"none", "loopback-only"}:
            record_control(parser, control, CO.NOT_APPLICABLE,
                           "SNMP clients are limited to the local host (allowed-addresses omitted, none or loopback).")
        elif agent.client_scope == "unknown":
            record_control(parser, control, CO.UNKNOWN, "The SNMP allowed-addresses value is malformed.")
        elif any(item.default_name is None for item in communities):
            record_control(parser, control, CO.UNKNOWN, "A community name is not in the export, so a default name cannot be excluded.")
        else:
            record_control(parser, control, CO.NO_FINDING,
                           "No reachable SNMP community is default, writable or open to any source."
                           if communities else "No SNMP community is configured.")

        control = "f5.bigip.remote-user-defaults"
        role = setting("auth remote-user", "default-role")
        console = setting("auth remote-user", "remote-console-access")
        source = setting("auth source", "type")
        if fired & {"f5.bigip.auth.remote_default_admin", "f5.bigip.auth.remote_console_access"}:
            record_control(parser, control, CO.FINDING, "Remote users get the admin role or terminal access by default.")
        elif any(item is not None and item.value is None for item in (role, console)):
            record_control(parser, control, CO.UNKNOWN, "The auth remote-user values are malformed.")
        elif parser.has_object("auth remote-user"):
            record_control(parser, control, CO.NO_FINDING,
                           "Remote-user defaults give no admin role and no terminal access (omitted values: no-access, disabled).")
        elif source is not None and source.value == "local":
            record_control(parser, control, CO.NOT_APPLICABLE, "Authentication source is local.")
        else:
            record_control(parser, control, CO.UNKNOWN, "No auth remote-user block is exported.")

    def _mark(self, rule_id: str, instance: str) -> None:
        """Remember which instance a per-object rule fired for (SC-049 control outcomes)."""
        self._fired_at.setdefault(rule_id, set()).add(instance)

    def _record_fired(self, parser: F5BIGIPParser, control: str, rule_ids: tuple[str, ...], reason: str) -> set[str]:
        keys = set().union(*(self._fired_at.get(rule_id, set()) for rule_id in rule_ids))
        for key in sorted(keys):
            record_control(parser, control, CO.FINDING, reason, instance=key)
        return keys

    def _record_completion(self, parser: F5BIGIPParser) -> None:
        """SC-049 completion: outcomes for the remaining F5 controls on every decision path."""
        fired = {issue.rule_id for issue in self.issues}
        setting = parser.get_setting
        release = parser.get_release()
        documented = release is not None and (13, 0, 0) <= release < (18, 0, 0)  # tmsh reference v13-v17

        def malformed(item: F5Setting | None) -> bool:
            return item is not None and item.value is None

        self._record_management_controls(parser, fired, setting, release, documented, malformed)
        self._record_account_controls(parser, fired, setting, release, documented, malformed)
        self._record_service_controls(parser, fired)
        self._record_traffic_controls(parser, fired, release)

    def _record_management_controls(self, parser, fired, setting, release, documented, malformed) -> None:
        login = setting("sys sshd", "login")
        sshd = parser.has_object("sys sshd")

        control = "f5.bigip.ssh-idle-timeout"
        timeout = setting("sys sshd", "inactivity-timeout")
        if "f5.bigip.ssh.idle_timeout_disabled" in fired:
            record_control(parser, control, CO.FINDING, "The SSH inactivity timeout is zero or omitted (documented default 0).")
        elif not sshd:
            record_control(parser, control, CO.UNKNOWN, "No sys sshd block is exported.")
        elif malformed(login) or malformed(timeout):
            record_control(parser, control, CO.UNKNOWN, "The sys sshd login or inactivity-timeout value is malformed.")
        elif login is not None and login.value == "disabled":
            record_control(parser, control, CO.NOT_APPLICABLE, "SSH login is disabled.")
        elif timeout is not None and timeout.value > 0:
            record_control(parser, control, CO.NO_FINDING, "The SSH inactivity timeout is finite.")
        elif timeout is not None:
            record_control(parser, control, CO.UNKNOWN,
                           "inactivity-timeout is explicitly 0 while login is omitted; the check grades an explicit "
                           "zero only with an explicit 'login enabled'.")
        else:
            record_control(parser, control, CO.UNKNOWN,
                           "inactivity-timeout is omitted and its default is documented only for 13.x-17.x.")

        control = "f5.bigip.console-idle-timeout"
        console = setting("sys global-settings", "console-inactivity-timeout")
        if "f5.bigip.console.idle_timeout_disabled" in fired:
            record_control(parser, control, CO.FINDING, "The console inactivity timeout is zero or omitted (documented default 0).")
        elif malformed(console):
            record_control(parser, control, CO.UNKNOWN, "The console-inactivity-timeout value is malformed.")
        elif console is not None:
            record_control(parser, control, CO.NO_FINDING, "The console inactivity timeout is finite.")
        elif not parser.has_object("sys global-settings"):
            record_control(parser, control, CO.UNKNOWN, "No sys global-settings block is exported.")
        else:
            record_control(parser, control, CO.UNKNOWN,
                           "console-inactivity-timeout is omitted and its default is documented only for 13.x-17.x.")

        control = "f5.bigip.cli-audit"
        audit = setting("cli global-settings", "audit")
        if "f5.bigip.cli.audit_disabled" in fired:
            record_control(parser, control, CO.FINDING, "tmsh command auditing is disabled.")
        elif malformed(audit):
            record_control(parser, control, CO.UNKNOWN, "The cli global-settings audit value is malformed.")
        elif audit is not None:
            record_control(parser, control, CO.NO_FINDING, "tmsh command auditing is enabled.")
        elif not parser.has_object("cli global-settings"):
            record_control(parser, control, CO.UNKNOWN, "No cli global-settings block is exported.")
        elif documented:
            record_control(parser, control, CO.NO_FINDING,
                           "audit is omitted; the tmsh cli global-settings reference documents the default enabled.")
        else:
            record_control(parser, control, CO.UNKNOWN, "audit is omitted and its default is not verified for this release.")

        httpd_off = (lambda allow: allow is not None and allow.value == "none")(setting("sys httpd", "allow"))
        control = "f5.bigip.httpd-tls-protocol"
        protocol = setting("sys httpd", "ssl-protocol")
        if "f5.bigip.http.legacy_tls_protocol" in fired:
            record_control(parser, control, CO.FINDING, "The configuration utility accepts SSLv3, TLS 1.0 or TLS 1.1.")
        elif httpd_off:
            record_control(parser, control, CO.NOT_APPLICABLE, "The configuration utility allows no source (allow none).")
        elif malformed(protocol):
            record_control(parser, control, CO.UNKNOWN, "The ssl-protocol value is malformed or unsupported.")
        elif protocol is not None:
            record_control(parser, control, CO.NO_FINDING, "ssl-protocol enables no protocol older than TLS 1.2.")
        elif not parser.has_object("sys httpd"):
            record_control(parser, control, CO.UNKNOWN, "No sys httpd block is exported.")
        else:
            record_control(parser, control, CO.UNKNOWN, "ssl-protocol is omitted and its default is not verified for this release.")

        control = "f5.bigip.httpd-cipher-suite"
        suites = setting("sys httpd", "ssl-ciphersuite")
        if "f5.bigip.http.weak_cipher_suite" in fired:
            record_control(parser, control, CO.FINDING, "The configuration utility offers 3DES or other weak suites.")
        elif httpd_off:
            record_control(parser, control, CO.NOT_APPLICABLE, "The configuration utility allows no source (allow none).")
        elif malformed(suites):
            record_control(parser, control, CO.UNKNOWN, "The ssl-ciphersuite value is malformed.")
        elif suites is not None:
            if weak_literal_cipher_suites(str(suites.value)) is None:
                record_control(parser, control, CO.UNKNOWN,
                               "ssl-ciphersuite uses keywords or operators whose effective list is not evaluated.")
            else:
                record_control(parser, control, CO.NO_FINDING, "ssl-ciphersuite lists no weak suite.")
        elif not parser.has_object("sys httpd"):
            record_control(parser, control, CO.UNKNOWN, "No sys httpd block is exported.")
        else:
            record_control(parser, control, CO.UNKNOWN,
                           "ssl-ciphersuite is omitted and its default is documented only for 13.x-17.x.")

        control = "f5.bigip.ssh-algorithms"
        include = setting("sys sshd", "include")
        if "f5.bigip.ssh.weak_algorithms" in fired:
            record_control(parser, control, CO.FINDING, "sys sshd include allows weak SSH algorithms.")
        elif not sshd:
            record_control(parser, control, CO.UNKNOWN, "No sys sshd block is exported.")
        elif malformed(login) or malformed(include):
            record_control(parser, control, CO.UNKNOWN, "The sys sshd login or include value is malformed.")
        elif login is not None and login.value == "disabled":
            record_control(parser, control, CO.NOT_APPLICABLE, "SSH login is disabled.")
        elif include is not None and all(re.search(directive + r"\s+\S+", str(include.value), re.IGNORECASE)
                                         for directive in ("ciphers", "macs", "kexalgorithms")):
            record_control(parser, control, CO.NO_FINDING, "Ciphers, MACs and KexAlgorithms are restricted to strong algorithms.")
        else:
            record_control(parser, control, CO.UNKNOWN,
                           "Ciphers, MACs or KexAlgorithms are not all set in sys sshd include; the release's default "
                           "algorithm sets are not verified.")

    def _record_account_controls(self, parser, fired, setting, release, documented, malformed) -> None:
        policy = "auth password-policy"
        enforcement = setting(policy, "policy-enforcement")
        if enforcement is not None:
            enforced = None if enforcement.value is None else enforcement.value == "enabled"
        else:
            # PASSWORD_POLICY_14: enabled by default from 14.0.0, disabled before.
            enforced = None if release is None else release >= (14, 0, 0)
        for control, rule_id, field, finding, default_ok, gap in (
            ("f5.bigip.password-minimum-length", "f5.bigip.password_policy.minimum_length_disabled", "minimum-length",
             "The enforced password policy sets minimum-length 0.",
             "minimum-length is omitted; the tmsh auth password-policy reference documents the default 6.",
             "minimum-length is 0 while policy-enforcement is at its 14.0+ default; the check grades it only with "
             "explicit enforcement."),
            ("f5.bigip.password-history", "f5.bigip.password_policy.history_disabled", "password-memory",
             "The enforced password policy remembers no previous password.", None,
             "password-memory is 0 or omitted (default 0) while policy-enforcement is at its 14.0+ default; the check "
             "grades it only with explicit enforcement."),
        ):
            value = setting(policy, field)
            if rule_id in fired:
                record_control(parser, control, CO.FINDING, finding)
            elif not parser.has_object(policy):
                record_control(parser, control, CO.UNKNOWN, "No auth password-policy block is exported.")
            elif malformed(enforcement) or malformed(value):
                record_control(parser, control, CO.UNKNOWN, f"The policy-enforcement or {field} value is malformed.")
            elif enforced is None:
                record_control(parser, control, CO.UNKNOWN, "policy-enforcement is omitted and the release is not identified.")
            elif not enforced:
                record_control(parser, control, CO.NOT_APPLICABLE,
                               "Password policy enforcement is disabled (explicitly or by the pre-14.0 default).")
            elif value is not None and value.value > 0:
                record_control(parser, control, CO.NO_FINDING, f"{field} is {value.value}.")
            elif value is None and default_ok and documented:
                record_control(parser, control, CO.NO_FINDING, default_ok)
            elif value is None and default_ok:
                record_control(parser, control, CO.UNKNOWN, f"{field} is omitted and its default is not verified for this release.")
            else:
                record_control(parser, control, CO.UNKNOWN, gap)

        source = setting("auth source", "type")
        remote = source is not None and source.value not in {None, "local"}
        for control, rule_id, finding in (
            ("f5.bigip.remote-auth-fallback", "f5.bigip.auth.remote_fallback_local",
             "Remote authentication falls back to local accounts."),
            ("f5.bigip.remote-auth-servers", "f5.bigip.auth.active_remote_servers_none",
             "Every provider of the active remote authentication source sets servers none."),
        ):
            if rule_id in fired:
                record_control(parser, control, CO.FINDING, finding)
            elif not parser.has_object("auth source"):
                record_control(parser, control, CO.UNKNOWN, "No auth source block is exported.")
            elif malformed(source):
                record_control(parser, control, CO.UNKNOWN, "The auth source type value is malformed.")
            elif not remote:
                record_control(parser, control, CO.NOT_APPLICABLE,
                               "The authentication source is local (explicit or the documented default).")
            elif control == "f5.bigip.remote-auth-fallback":
                fallback = setting("auth source", "fallback")
                if malformed(fallback):
                    record_control(parser, control, CO.UNKNOWN, "The auth source fallback value is malformed.")
                else:
                    record_control(parser, control, CO.NO_FINDING,
                                   "fallback is false" + (" (omitted: documented default false)." if fallback is None else "."))
            elif source.value not in {"radius", "ldap", "tacacs", "cert-ldap"}:
                record_control(parser, control, CO.UNKNOWN, f"Provider servers are not evaluated for auth source type {source.value}.")
            else:
                profiles = parser.get_remote_auth_profiles(str(source.value))
                if not profiles:
                    record_control(parser, control, CO.UNKNOWN, f"No auth {source.value} provider object is exported.")
                elif any(profile.servers_state == "configured" for profile in profiles):
                    record_control(parser, control, CO.NO_FINDING, "A provider of the active source lists servers.")
                else:
                    record_control(parser, control, CO.UNKNOWN,
                                   "The provider servers value is missing or malformed (tmsh requires servers).")

        control = "f5.bigip.local-credentials"
        keys = self._record_fired(parser, control, ("f5.bigip.credentials.known_default_value",
                                                    "f5.bigip.credentials.local_plaintext"),
                                  "The local password is a factory default or stored in plaintext.")
        credentials = parser.get_local_user_credentials()
        if not credentials:
            record_control(parser, control, CO.UNKNOWN, "No local user password is exported.")
        for credential in credentials:
            if credential.name in keys:
                continue
            if credential.storage == "encrypted":
                record_control(parser, control, CO.NO_FINDING, "The password is stored as a hash that is not a factory default.",
                               instance=credential.name)
            else:
                record_control(parser, control, CO.UNKNOWN, "The password value is masked in the export.",
                               instance=credential.name)

    def _record_service_controls(self, parser, fired) -> None:
        control = "f5.bigip.monitor-credentials"
        if "f5.bigip.credentials.monitor_storage" in fired:
            record_control(parser, control, CO.FINDING, "A health monitor send string carries Basic credentials.")
        elif parser.get_http_monitor_count():
            record_control(parser, control, CO.NO_FINDING, "No HTTP/HTTPS monitor send string carries Basic credentials.")
        else:
            record_control(parser, control, CO.NOT_APPLICABLE, "No HTTP/HTTPS monitor is configured.")

        snmp = parser.has_object("sys snmp")
        agent = parser.get_snmp_agent()
        reachable = agent is not None and agent.client_scope in {"unrestricted", "restricted"}
        communities = parser.get_snmp_communities()
        traps = parser.get_snmp_traps()
        control = "f5.bigip.snmp-legacy-version"
        if "f5.bigip.snmp.legacy_version" in fired:
            record_control(parser, control, CO.FINDING, "SNMPv1/v2c communities are reachable or traps use v1/v2c.")
        elif not snmp:
            record_control(parser, control, CO.UNKNOWN, "No sys snmp block is exported.")
        elif agent is not None and agent.client_scope == "unknown":
            record_control(parser, control, CO.UNKNOWN, "The SNMP allowed-addresses value is malformed.")
        elif reachable and communities and any(
                state == "enable" for state, _ in parser.get_snmp_legacy_versions().values()):
            record_control(parser, control, CO.UNKNOWN,
                           "snmpv1/snmpv2c are omitted and their default is documented only for 13.x-17.x.")
        elif any(version != "3" for _, version, _ in traps):
            record_control(parser, control, CO.UNKNOWN, "A trap target omits its version or uses an unrecognized one.")
        elif (reachable and communities) or traps:
            record_control(parser, control, CO.NO_FINDING, "SNMPv1/v2c are disabled for reachable communities and traps use v3.")
        else:
            record_control(parser, control, CO.NOT_APPLICABLE,
                           "No community is reachable from non-local clients and no trap target is configured.")

        control = "f5.bigip.snmpv3-users"
        keys = self._record_fired(parser, control, ("f5.bigip.snmp.v3_security", "f5.bigip.snmp.v3_weak_algorithm"),
                                  "The SNMPv3 user lacks auth-privacy or uses MD5/DES.")
        users = parser.get_snmp_users()
        if not snmp:
            record_control(parser, control, CO.UNKNOWN, "No sys snmp block is exported.")
        elif agent is not None and agent.client_scope == "unknown":
            record_control(parser, control, CO.UNKNOWN, "The SNMP allowed-addresses value is malformed.")
        elif not reachable:
            record_control(parser, control, CO.NOT_APPLICABLE, "SNMP clients are limited to the local host.")
        elif not users:
            record_control(parser, control, CO.NOT_APPLICABLE, "No SNMPv3 user is configured.")
        else:
            for user in users:
                if user.name in keys:
                    continue
                if (user.security_level == "auth-privacy" and user.auth_protocol.startswith("sha")
                        and user.privacy_protocol.startswith("aes")):
                    record_control(parser, control, CO.NO_FINDING, "auth-privacy with SHA and AES.", instance=user.name)
                else:
                    record_control(parser, control, CO.UNKNOWN,
                                   "security-level, auth-protocol or privacy-protocol is omitted or unrecognized.",
                                   instance=user.name)

        control = "f5.bigip.ntp-authentication"
        keys = self._record_fired(parser, control, ("f5.bigip.ntp.unauthenticated_server",),
                                  "The NTP server is used without authentication.")
        servers = parser.get_ntp_servers()
        if not parser.has_ntp_section():
            record_control(parser, control, CO.UNKNOWN, "No sys ntp block is exported.")
        elif not servers:
            record_control(parser, control, CO.NOT_APPLICABLE, "No NTP server is configured.")
        for server in servers:
            key = f"{server.source}:{server.address}"
            if key not in keys:
                record_control(parser, control, CO.UNKNOWN,
                               "The server references a trusted key whose material is outside the export.", instance=key)

        modules = parser.get_provisioned_modules()
        control = "f5.bigip.afm-default-action"
        if "f5.bigip.afm.default_accept" in fired:
            record_control(parser, control, CO.FINDING, "AFM accepts traffic that no rule matches.")
        elif not modules:
            record_control(parser, control, CO.UNKNOWN, "No sys provision object is exported.")
        elif modules.get("afm", "none") == "none":
            record_control(parser, control, CO.NOT_APPLICABLE, "AFM is not provisioned.")
        elif parser.get_firewall_default_action()[0] in {"drop", "reject"}:
            record_control(parser, control, CO.NO_FINDING, "The AFM default action drops or rejects unmatched traffic.")
        else:
            record_control(parser, control, CO.UNKNOWN, "The tm.fw.defaultaction value is not recognized.")

        control = "f5.bigip.asm-enforcement"
        keys = self._record_fired(parser, control, ("f5.bigip.asm.inactive_policy", "f5.bigip.asm.transparent_policy"),
                                  "The bound ASM policy is inactive or transparent.")
        bindings = parser.get_asm_bindings() if modules.get("asm", "none") != "none" else ()
        if not modules:
            record_control(parser, control, CO.UNKNOWN, "No sys provision object is exported.")
        elif not bindings:
            record_control(parser, control, CO.NOT_APPLICABLE,
                           "ASM is not provisioned or no enabled virtual server enables an exported ASM policy.")
        for virtual, _, asm in bindings:
            key = f"{virtual.name}|{asm.name}"
            if key in keys:
                continue
            if asm.active and asm.blocking_mode == "enabled":
                record_control(parser, control, CO.NO_FINDING, "The ASM policy is active and blocking.", instance=key)
            else:
                record_control(parser, control, CO.UNKNOWN, "blocking-mode is omitted or unrecognized.", instance=key)

        peers = parser.get_ike_peers()
        for control, rule_id, finding in (
            ("f5.bigip.ike-version", "f5.bigip.vpn.ikev1", "The IKE peer negotiates only IKEv1."),
            ("f5.bigip.ike-aggressive-mode", "f5.bigip.vpn.ike_aggressive_mode",
             "The IKE peer uses IKEv1 aggressive mode with a pre-shared key."),
        ):
            keys = self._record_fired(parser, control, (rule_id,), finding)
            if not peers:
                record_control(parser, control, CO.NOT_APPLICABLE, "No IPsec IKE peer is configured.")
            for peer in peers:
                if peer.name in keys:
                    continue
                if not peer.enabled:
                    record_control(parser, control, CO.NOT_APPLICABLE, "The IKE peer is disabled.", instance=peer.name)
                elif control == "f5.bigip.ike-version":
                    if "v2" in peer.versions:
                        record_control(parser, control, CO.NO_FINDING, "The IKE peer offers IKEv2.", instance=peer.name)
                    else:
                        record_control(parser, control, CO.UNKNOWN,
                                       "The IKE version is not graded (unrecognized value or unidentified release).",
                                       instance=peer.name)
                elif ("v1" not in peer.versions or peer.mode == "main"
                      or (peer.mode == "aggressive" and peer.auth_method not in {"pre-shared-key", "unknown"})):
                    record_control(parser, control, CO.NO_FINDING,
                                   "The IKE peer does not use IKEv1 aggressive mode with a pre-shared key.", instance=peer.name)
                else:
                    record_control(parser, control, CO.UNKNOWN,
                                   "mode or phase1-auth-method is omitted or unrecognized; no default is documented.",
                                   instance=peer.name)

    def _record_traffic_controls(self, parser, fired, release) -> None:
        client = parser.get_client_ssl_bindings()
        control = "f5.bigip.clientssl-cleartext"
        keys = self._record_fired(parser, control, ("f5.bigip.ltm.clientssl_cleartext_enabled",),
                                  "The client SSL profile permits non-SSL traffic.")
        if not client:
            record_control(parser, control, CO.NOT_APPLICABLE, "No enabled virtual server attaches a client SSL profile.")
        for virtual, name, profile in client:
            key = f"{virtual.name}|{name}"
            if key in keys:
                continue
            if profile is None:
                record_control(parser, control, CO.NO_FINDING,
                               "Built-in clientssl profile: documented default allow-non-ssl disabled.", instance=key)
            elif profile.allow_non_ssl is False:
                record_control(parser, control, CO.NO_FINDING, "allow-non-ssl is disabled.", instance=key)
            elif profile.mode_enabled is False:
                record_control(parser, control, CO.NOT_APPLICABLE, "SSL processing is disabled on this profile.", instance=key)
            elif profile.allow_non_ssl is None and (
                    not profile.parent or (profile.parent.rsplit("/", 1)[-1] == "clientssl"
                                           and parser.get_client_ssl_profile(profile.parent) is None)):
                record_control(parser, control, CO.NO_FINDING,
                               "allow-non-ssl is omitted and inherited from the built-in default disabled.", instance=key)
            else:
                record_control(parser, control, CO.UNKNOWN,
                               "allow-non-ssl or mode is inherited from an exported parent or omitted; not evaluated.",
                               instance=key)

        control = "f5.bigip.clientssl-tls"
        keys = self._record_fired(parser, control, ("f5.bigip.ltm.clientssl_weak_cipher", "f5.bigip.ltm.clientssl_legacy_tls"),
                                  "The client SSL profile offers weak ciphers or TLS 1.0/1.1.")
        defaults = {f"{virtual.name}|{name}" for virtual, name, _, _ in parser.get_bound_default_cipher_profiles()}
        if not client:
            record_control(parser, control, CO.NOT_APPLICABLE, "No enabled virtual server attaches a client SSL profile.")
        for virtual, name, _ in client:
            key = f"{virtual.name}|{name}"
            if key in keys:
                continue
            if key in defaults and release is not None:
                record_control(parser, control, CO.NO_FINDING,
                               "The built-in DEFAULT cipher string has no weak suite on this release and the profile "
                               "disables TLS 1.0 and 1.1.", instance=key)
            elif key in defaults:
                record_control(parser, control, CO.UNKNOWN, "The DEFAULT cipher string is release dependent; release unknown.",
                               instance=key)
            else:
                record_control(parser, control, CO.UNKNOWN,
                               "A custom cipher string or group is evaluated only for explicit weak tokens.", instance=key)

        control = "f5.bigip.cookie-encryption"
        keys = self._record_fired(parser, control, ("f5.bigip.ltm.cookie_unencrypted",),
                                  "The persistence cookie is not encrypted.")
        cookies = parser.get_cookie_persistence_bindings()
        if not cookies:
            record_control(parser, control, CO.NOT_APPLICABLE, "No enabled virtual server uses cookie persistence.")
        for virtual, name, encryption, method in cookies:
            key = f"{virtual.name}|{name}"
            if key in keys:
                continue
            if encryption in {"required", "preferred"}:
                record_control(parser, control, CO.NO_FINDING, f"cookie-encryption is {encryption}.", instance=key)
            elif (method or "insert") not in {"insert", "rewrite", "passive"}:
                record_control(parser, control, CO.NOT_APPLICABLE,
                               f"Cookie method {method} does not encode the pool member address.", instance=key)
            else:
                record_control(parser, control, CO.UNKNOWN,
                               "cookie-encryption is inherited or unrecognized; not evaluated.", instance=key)

        control = "f5.bigip.serverssl-validation"
        keys = self._record_fired(parser, control, ("f5.bigip.ltm.serverssl_no_cert_validation",),
                                  "The server SSL profile does not verify the pool member certificate.")
        servers = parser.get_server_ssl_bindings()
        if not servers:
            record_control(parser, control, CO.NOT_APPLICABLE, "No enabled virtual server re-encrypts with a server SSL profile.")
        for virtual, name, mode in servers:
            key = f"{virtual.name}|{name}"
            if key in keys:
                continue
            if mode == "require":
                record_control(parser, control, CO.NO_FINDING, "peer-cert-mode is require.", instance=key)
            else:
                record_control(parser, control, CO.UNKNOWN, f"peer-cert-mode {mode} is not graded.", instance=key)

        control = "f5.bigip.virtual-risky-services"
        keys = self._record_fired(parser, control, ("f5.bigip.ltm.risky_service_exposure",),
                                  "The virtual server publishes a catalogued risky service to any source.")
        endpoints = parser.get_virtual_endpoints()
        if not endpoints:
            record_control(parser, control, CO.NOT_APPLICABLE, "No enabled virtual server publishes a destination.")
        for endpoint in endpoints:
            key = endpoint.virtual.name
            if key in keys:
                continue
            number = (int(endpoint.port) if endpoint.port.isdigit()
                      else CISCO_PORT_NAMES.get(endpoint.port.casefold()))
            if endpoint.protocol == "unknown" or endpoint.source == "unknown":
                record_control(parser, control, CO.UNKNOWN,
                               "The IP protocol or source is omitted and its default is not verified for this release.",
                               instance=key)
            elif not _ANY_SOURCE.match(endpoint.source.casefold()):
                record_control(parser, control, CO.NO_FINDING, "The source address is restricted.", instance=key)
            elif number is None:
                record_control(parser, control, CO.UNKNOWN, f"Port {endpoint.port} is not resolved.", instance=key)
            else:
                record_control(parser, control, CO.NO_FINDING, "The published port is not a catalogued risky service.",
                               instance=key)

    def _default(self, parser: F5BIGIPParser, rule_id: str, title: str, observation: str, impact: str,
                 recommendation: str, severity: Severity, evidence: tuple, references: tuple) -> None:
        self.add_issue(Finding(
            rule_id=rule_id, device=parser.device_type, title=title, observation=observation, impact=impact,
            exploitability="An attacker who can reach the service can use the weakness left by the documented default.",
            recommendation=recommendation, severity=severity, evidence=evidence, references=references,
            basis=FindingBasis.DOCUMENTED_DEFAULT,
        ))

    def _check_release_defaults(self, parser: F5BIGIPParser) -> None:
        """SC-044 F5-01..08, F5-10..13, F5-22: settings left at a documented insecure default."""
        release = parser.get_release()
        if release is None:
            return
        label = ".".join(map(str, release))
        setting = parser.get_setting
        tmsh_documented = (13, 0, 0) <= release < (18, 0, 0)  # tmsh reference v13-v17 default cells

        # F5-01: K13250, port lockdown default was Allow Default on 11.0.0-11.5.2.
        if (11, 0, 0) <= release < (11, 5, 3):
            for self_ip in parser.get_self_ips():
                if self_ip.allow_service:
                    continue
                self._lockdown_names.add(self_ip.name)
                self._default(parser, "f5.bigip.management.self_ip_port_lockdown", "Self IP allows management services",
                              f"Self IP {self_ip.name} (VLAN {self_ip.vlan or 'unknown'}) sets no allow-service; on BIG-IP {label} "
                              "the default port lockdown is Allow Default, which includes SSH (TCP 22) and HTTPS (TCP 443).",
                              "SSH, the Configuration utility and iControl REST can be reached on this traffic VLAN.",
                              "Set 'allow-service none' (or a custom list without TCP 22 and 443) and upgrade to a supported release.",
                              Severity.MEDIUM, (self_ip.evidence, f"BIG-IP {label}: default allow-service default before 11.5.3"),
                              (PORT_LOCKDOWN_11, PORT_LOCKDOWN, ICONTROL_CVE_2022_1388))

        # Properties are only read as defaults when their object is in the export, so a
        # partial snippet without 'sys httpd { }' is not treated as all-default.
        http_allow = setting("sys httpd", "allow")
        httpd_on = not (http_allow and http_allow.value == "none")
        if httpd_on and parser.has_object("sys httpd"):
            # F5-02/03: K15702 (SSLv3 until 12.0.0) and ID668624 (TLS 1.0 off from 14.0.0);
            # TLS 1.1 stays enabled by default through 17.x.
            if setting("sys httpd", "ssl-protocol") is None and release < (18, 0, 0):
                if release < (12, 0, 0):
                    legacy, severity = "SSLv3, TLS 1.0 and TLS 1.1", Severity.HIGH
                elif release < (14, 0, 0):
                    legacy, severity = "TLS 1.0 and TLS 1.1", Severity.MEDIUM
                else:
                    legacy, severity = "TLS 1.1", Severity.LOW
                self._default(parser, "f5.bigip.http.legacy_tls_protocol",
                              "Configuration utility accepts legacy SSL/TLS versions by default",
                              f"sys httpd ssl-protocol is not set, so the BIG-IP {label} default applies and the configuration utility accepts {legacy}.",
                              "Administrative HTTPS sessions can be negotiated with deprecated protocol versions.",
                              "Set ssl-protocol to 'all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1'.",
                              severity, (f"sys httpd ssl-protocol absent (BIG-IP {label})",),
                              (HTTPD_SSLV3, HTTPD_TLS_DEFAULT, HTTPD_LATEST, RFC_8996))
            # F5-04: tmsh sys httpd, the default suite list ends with three DES-CBC3 suites.
            if setting("sys httpd", "ssl-ciphersuite") is None and tmsh_documented:
                self._default(parser, "f5.bigip.http.weak_cipher_suite",
                              "Configuration utility offers 3DES suites by default",
                              "sys httpd ssl-ciphersuite is not set; the documented default list ends with "
                              "ECDHE-RSA-DES-CBC3-SHA, ECDHE-ECDSA-DES-CBC3-SHA and DES-CBC3-SHA.",
                              "3DES has a 64-bit block size and is vulnerable to birthday attacks (SWEET32) on long sessions.",
                              "Set an explicit ssl-ciphersuite with only ECDHE AES-GCM suites.",
                              Severity.LOW, ("sys httpd ssl-ciphersuite absent",), (HTTPD_LATEST, NIST_TLS))
            # F5-05: 'The default value is All.'
            if http_allow is None and tmsh_documented:
                self._default(parser, "f5.bigip.http.unrestricted_sources",
                              "Configuration utility accepts any source address by default",
                              "sys httpd allow is not set; the documented default is All, so any address that reaches the "
                              "management interface (or a self IP that allows HTTPS) can open the configuration utility.",
                              "More hosts can attempt to log in to or exploit the configuration utility and iControl REST.",
                              "Set 'sys httpd allow' to the management networks only.",
                              Severity.MEDIUM, ("sys httpd allow absent: default All",), (HTTPD_LATEST, LOCKDOWN_SETTINGS))

        login = setting("sys sshd", "login")
        ssh_on = login is None or login.value == "enabled"  # 'The default value is enabled.'
        if ssh_on and tmsh_documented and parser.has_object("sys sshd"):
            if setting("sys sshd", "allow") is None:
                self._default(parser, "f5.bigip.ssh.unrestricted_sources", "SSH accepts any source address by default",
                              "sys sshd allow is not set; the documented default is all, so any address that reaches the "
                              "management interface can attempt SSH logins.",
                              "More hosts can attempt administrative SSH authentication.",
                              "Set 'sys sshd allow' to the management networks only.",
                              Severity.MEDIUM, ("sys sshd allow absent: default all",), (SSHD, LOCKDOWN_SETTINGS))
            if setting("sys sshd", "inactivity-timeout") is None:
                self._default(parser, "f5.bigip.ssh.idle_timeout_disabled", "SSH idle timeout is disabled by default",
                              "sys sshd inactivity-timeout is not set; the documented default is 0, which disables the timeout.",
                              "An unattended administrative session can remain open.",
                              "Set a finite SSH inactivity timeout (for example 900 seconds or less).",
                              Severity.LOW, ("sys sshd inactivity-timeout absent: default 0",), (SSHD,))
        if (tmsh_documented and parser.has_object("sys global-settings")
                and setting("sys global-settings", "console-inactivity-timeout") is None):
            self._default(parser, "f5.bigip.console.idle_timeout_disabled", "Console idle timeout is disabled by default",
                          "sys global-settings console-inactivity-timeout is not set; the documented default is 0 (no timeout).",
                          "An unattended console session can remain open.",
                          "Set a finite console inactivity timeout.",
                          Severity.LOW, ("console-inactivity-timeout absent: default 0",), (CONSOLE,))

        # F5-10/11/12/13: the built-in DEFAULT cipher string (K15022, K13156, K000134647).
        for virtual, profile, options, evidence in parser.get_bound_default_cipher_profiles():
            weak = []
            if release < (11, 5, 0):
                weak.append("SSLv3 (DEFAULT before 11.5.0)")
            if (11, 2, 0) <= release < (11, 6, 0):
                weak.append("RC4-SHA (DEFAULT 11.2.0-11.5.x)")
            if release < (13, 1, 0):
                weak.append("3DES (DEFAULT before 13.1.0)")
            if weak:
                self._mark("f5.bigip.ltm.clientssl_weak_cipher", f"{virtual.name}|{profile}")
                self._default(parser, "f5.bigip.ltm.clientssl_weak_cipher",
                              "Client SSL profile uses a DEFAULT cipher string that includes weak suites",
                              f"Enabled virtual server '{virtual.name}' uses Client SSL profile '{profile}', which resolves to the "
                              f"built-in DEFAULT cipher string; on BIG-IP {label} that includes " + ", ".join(weak) + ".",
                              "Clients can negotiate obsolete protocols or ciphers for application traffic.",
                              "Set an explicit cipher string or cipher group (for example 'ECDHE+AES-GCM:!SSLv3:!RC4:!3DES') and upgrade.",
                              Severity.HIGH if release < (11, 6, 0) else Severity.MEDIUM,
                              (virtual.evidence, evidence), (CLIENTSSL_DEFAULT_SSLV3, CLIENTSSL_DEFAULT_CIPHERS))
            lowered = {item.casefold() for item in options}
            if not {"no-tlsv1", "no-tlsv1.1"} <= lowered:
                missing = [item for item in ("no-tlsv1", "no-tlsv1.1") if item not in lowered]
                self._mark("f5.bigip.ltm.clientssl_legacy_tls", f"{virtual.name}|{profile}")
                self._default(parser, "f5.bigip.ltm.clientssl_legacy_tls",
                              "Client SSL profile accepts TLS 1.0/1.1",
                              f"Enabled virtual server '{virtual.name}' uses Client SSL profile '{profile}' with the DEFAULT cipher "
                              f"string and without the {' and '.join(missing)} option(s), so TLS 1.0/1.1 clients are accepted.",
                              "TLS 1.0 and 1.1 are deprecated (RFC 8996) and lack modern cipher suites.",
                              "Add 'options { no-tlsv1 no-tlsv1.1 }' (keep other needed options) or use a cipher rule/group that excludes them.",
                              Severity.MEDIUM, (virtual.evidence, evidence),
                              (CLIENTSSL_DEFAULT_17, CLIENTSSL_DEFAULT_16, RFC_8996))

        # F5-21: tmsh auth password-policy, policy-enforcement defaults to disabled; from
        # 14.0.0 (ID661909) the policy is enabled by default, so only earlier releases.
        if (release < (14, 0, 0) and parser.has_object("auth password-policy")
                and setting("auth password-policy", "policy-enforcement") is None):
            self._default(parser, "f5.bigip.password_policy.enforcement_disabled",
                          "Local password policy enforcement is disabled by default",
                          f"auth password-policy does not set policy-enforcement; before 14.0.0 the default is disabled (BIG-IP {label}).",
                          "Locally managed passwords need not satisfy the configured policy constraints.",
                          "Set 'policy-enforcement enabled' with organization-approved constraints, and upgrade.",
                          Severity.MEDIUM, ("auth password-policy policy-enforcement absent: default disabled before 14.0.0",),
                          (PASSWORD, PASSWORD_POLICY_14))

        # F5-22: net ipsec ike-peer version defaults to v1.
        for peer in parser.get_ike_peers():
            if peer.enabled and peer.versions == ("v1",):
                self._mark("f5.bigip.vpn.ikev1", peer.name)
                self.add_issue(Finding(
                    rule_id="f5.bigip.vpn.ikev1", device=parser.device_type,
                    title="IPsec peer uses IKEv1",
                    observation=f"IKE peer {peer.name} negotiates only IKEv1"
                                + ("." if peer.version_explicit else " (version not set; the documented default is v1)."),
                    impact="IKEv1 lacks the protections of IKEv2 (for example against reflection and some downgrade attacks) and is being retired by vendors.",
                    exploitability="Mainly a hardening gap; weak IKEv1 settings are reported separately.",
                    recommendation="Use 'version { v2 }' when the peer supports IKEv2.",
                    severity=Severity.LOW, evidence=(peer.evidence,), references=(IKE_PEER,),
                    basis=FindingBasis.EXPLICIT_VALUE if peer.version_explicit else FindingBasis.DOCUMENTED_DEFAULT,
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
                basis=FindingBasis.EXPLICIT_VALUE,
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
                basis=FindingBasis.EXPLICIT_VALUE,
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
                basis=FindingBasis.EXPLICIT_VALUE,
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
                    basis=FindingBasis.EXPLICIT_VALUE,
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
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
        versions = {name: state for name, state in parser.get_snmp_legacy_versions().items() if state[0] == "enable"}
        release = parser.get_release()
        documented = release is not None and (13, 0, 0) <= release < (18, 0, 0)  # tmsh reference v13-v17
        if communities and versions and (documented or any(evidence for _, evidence in versions.values())):
            explicit = [evidence for _, evidence in versions.values() if evidence]
            self.add_issue(Finding(
                rule_id="f5.bigip.snmp.legacy_version",
                device=parser.device_type,
                title="SNMPv1/v2c community access is enabled",
                observation=(f"Communities are configured and {' and '.join(sorted(versions))} "
                             + ("is enabled." if explicit else "are not disabled (the documented default is enable).")),
                impact="Community strings travel in clear text and give no per-user authentication.",
                exploitability="An attacker who captures or guesses a community can query the device from an allowed address.",
                recommendation="Set 'snmpv1 disable' and 'snmpv2c disable' under sys snmp and use SNMPv3 users with auth-privacy.",
                severity=Severity.LOW,
                evidence=(agent.evidence, *explicit) if explicit else (agent.evidence, "sys snmp snmpv1/snmpv2c absent: default enable"),
                references=(SNMP_LATEST,),
                basis=FindingBasis.EXPLICIT_VALUE if explicit else FindingBasis.DOCUMENTED_DEFAULT,
            ))
        for user in parser.get_snmp_users():
            if user.security_level in {"no-auth-no-privacy", "auth-no-privacy"}:
                self._mark("f5.bigip.snmp.v3_security", user.name)
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
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
            elif user.auth_protocol == "md5" or user.privacy_protocol == "des":
                self._mark("f5.bigip.snmp.v3_weak_algorithm", user.name)
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
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))

    def _check_ntp(self, parser: F5BIGIPParser) -> None:
        """SC-016 time stage (F5 K14120: tmsh servers are unauthenticated NTP)."""

        # A missing NTP configuration is not graded: whether an SCF export always
        # carries sys ntp is not qualified. Only documented unauthenticated
        # associations are reported.
        servers = parser.get_ntp_servers()
        for server in servers:
            if server.source == "include" and server.key_trusted:
                continue  # key material is outside the export; its presence stays unknown
            if server.source == "tmsh":
                detail = "is configured through tmsh/GUI, which F5 documents as unauthenticated NTP"
            elif server.key_id:
                detail = f"references key {server.key_id}, which no trustedkey statement trusts"
            else:
                detail = "has no key in the include statement"
            self._mark("f5.bigip.ntp.unauthenticated_server", f"{server.source}:{server.address}")
            self.add_issue(Finding(
                rule_id="f5.bigip.ntp.unauthenticated_server",
                device=parser.device_type,
                title="NTP server is used without authentication",
                observation=f"NTP server {server.address} {detail}.",
                impact="A spoofed or manipulated time source can shift the clock, disrupting logs, certificates and time-based controls.",
                exploitability="An on-path attacker can forge NTP responses for an unauthenticated association.",
                recommendation=(
                    "Remove the server from sys ntp servers and configure it in sys ntp include as "
                    "'server <address> key <n>' with 'trustedkey <n>' and a key in /etc/ntp/keys (F5 K14120)."
                ),
                severity=Severity.MEDIUM,
                evidence=(server.evidence,),
                references=(NTP_AUTH, NTP),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def _check_modules(self, parser: F5BIGIPParser) -> None:
        """SC-024 bounded stages: AFM default action and ASM enforcement on bound policies."""

        modules = parser.get_provisioned_modules()
        if modules.get("afm", "none") != "none":
            action, evidence = parser.get_firewall_default_action()
            if action in {"accept", "allow"}:
                self.add_issue(Finding(
                    rule_id="f5.bigip.afm.default_accept",
                    device=parser.device_type,
                    title="AFM network firewall allows unmatched traffic by default",
                    observation=(
                        "AFM is provisioned and the virtual server/self IP default action is accept "
                        + ("(sys db tm.fw.defaultaction)." if evidence else "(ADC mode, the documented default).")
                    ),
                    impact="Traffic to virtual servers and self IPs that no firewall rule matches is allowed.",
                    exploitability="Services reachable on the BIG-IP are exposed unless another rule blocks them.",
                    recommendation="Switch AFM to firewall mode (default action drop or reject) and allow required traffic explicitly, or document the ADC-mode design.",
                    severity=Severity.MEDIUM,
                    evidence=((evidence,) if evidence else ()) + (
                        f"sys provision afm level {modules['afm']}",
                    ),
                    references=(AFM_DEFAULT_PROCESSING, AFM_DEFAULT_ACTION_DB),
                    basis=FindingBasis.EXPLICIT_VALUE if evidence else FindingBasis.DOCUMENTED_DEFAULT,
                ))
        if modules.get("asm", "none") == "none":
            return
        for virtual, ltm, asm in parser.get_asm_bindings():
            evidence = (virtual.evidence, ltm.evidence, asm.evidence)
            if not asm.active:
                self._mark("f5.bigip.asm.inactive_policy", f"{virtual.name}|{asm.name}")
                self.add_issue(Finding(
                    rule_id="f5.bigip.asm.inactive_policy",
                    device=parser.device_type,
                    title="Web application firewall policy is not active",
                    observation=f"Virtual server {virtual.name} enables ASM policy {asm.name} through LTM policy {ltm.name}, but the ASM policy is inactive (the documented default).",
                    impact="Requests to this application are not inspected by the intended security policy.",
                    exploitability="Web attacks that the policy would detect reach the application.",
                    recommendation=f"Activate ASM policy {asm.name} ('modify asm policy {asm.name} active') and apply the changes.",
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                    references=(ASM_POLICY, LTM_POLICY),
                    basis=FindingBasis.DOCUMENTED_DEFAULT,
                ))
            elif asm.blocking_mode == "disabled":
                self._mark("f5.bigip.asm.transparent_policy", f"{virtual.name}|{asm.name}")
                self.add_issue(Finding(
                    rule_id="f5.bigip.asm.transparent_policy",
                    device=parser.device_type,
                    title="Web application firewall policy only logs violations",
                    observation=f"Virtual server {virtual.name} uses ASM policy {asm.name} with blocking-mode disabled (transparent): violations are logged but not blocked.",
                    impact="Detected web attacks still reach the application.",
                    exploitability="An attacker's requests pass even when the policy recognizes them as violations.",
                    recommendation=f"After tuning, enable blocking ('modify asm policy {asm.name} blocking-mode enabled').",
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                    references=(ASM_POLICY, LTM_POLICY),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))

    def _check_self_ips(self, parser: F5BIGIPParser) -> None:
        """SC-041: port lockdown on self IPs exposing SSH or the configuration utility/iControl REST."""
        for self_ip in parser.get_self_ips():
            services = {item.casefold() for item in self_ip.allow_service}
            if "all" in services:
                exposed, severity = "all services", Severity.HIGH
            elif "default" in services:
                exposed, severity = "the default service set, which includes SSH (TCP 22) and HTTPS (TCP 443)", Severity.MEDIUM
            elif services & _MANAGEMENT_SERVICES:
                exposed = "SSH or HTTPS (" + ", ".join(sorted(services & _MANAGEMENT_SERVICES)) + ")"
                severity = Severity.MEDIUM
            else:
                continue
            self._lockdown_names.add(self_ip.name)
            self.add_issue(Finding(
                rule_id="f5.bigip.management.self_ip_port_lockdown",
                device=parser.device_type,
                title="Self IP allows management services",
                observation=f"Self IP {self_ip.name} (VLAN {self_ip.vlan or 'unknown'}) has port lockdown set to allow {exposed}.",
                impact="SSH, the Configuration utility and iControl REST can be reached on this traffic VLAN, not only on the management port.",
                exploitability=(
                    "Critical BIG-IP management vulnerabilities such as CVE-2022-1388 are exploitable through "
                    "self IPs that allow these services; no credentials are needed for some of them."
                ),
                recommendation=(
                    "Set port lockdown to Allow None ('modify net self <name> allow-service none'), or to a "
                    "custom list without TCP 22 and 443; keep only services needed for HA or routing."
                ),
                severity=severity,
                evidence=(self_ip.evidence,),
                references=(PORT_LOCKDOWN, NET_SELF, ICONTROL_CVE_2022_1388),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def _check_ike_peers(self, parser: F5BIGIPParser) -> None:
        """SC-034: IKEv1 aggressive mode with pre-shared-key authentication."""
        for peer in parser.get_ike_peers():
            if (not peer.enabled or peer.mode != "aggressive" or peer.auth_method != "pre-shared-key"
                    or "v1" not in peer.versions):
                continue
            self._mark("f5.bigip.vpn.ike_aggressive_mode", peer.name)
            self.add_issue(Finding(
                rule_id="f5.bigip.vpn.ike_aggressive_mode",
                device=parser.device_type,
                title="IKEv1 aggressive mode with a pre-shared key",
                observation=f"IKE peer {peer.name} uses IKEv1 aggressive mode with pre-shared-key authentication.",
                impact="Aggressive mode sends a hash derived from the pre-shared key before the peer is authenticated, so it can be captured and cracked offline.",
                exploitability="An attacker who can reach the IKE service can request an aggressive-mode exchange and brute-force a weak key offline.",
                recommendation="Use main mode or IKEv2, or certificate authentication; if aggressive mode is required, use a long random pre-shared key.",
                severity=Severity.MEDIUM,
                evidence=(peer.evidence,),
                references=(IKE_PEER, RFC_2409),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

    def _check_admin_access(self, parser: F5BIGIPParser) -> None:
        """SC-030: root login, bash shells, remote-user default admin role and password history."""
        root = parser.get_db("systemauth.disablerootlogin")
        if root and root[0].strip('"').casefold() == "false":
            self.add_issue(Finding(
                rule_id="f5.bigip.auth.root_login_enabled",
                device=parser.device_type,
                title="Direct root login is allowed",
                observation="'sys db systemauth.disablerootlogin' is false, so the root account can log in directly.",
                impact="A single shared, all-powerful account can log in without being tied to a person, and its compromise gives full system access.",
                exploitability="Attackers target the well-known root account with password guessing or reused credentials.",
                recommendation="Run 'modify sys db systemauth.disablerootlogin value true' and use named administrator accounts.",
                severity=Severity.MEDIUM,
                evidence=(root[1],),
                references=(LOCKDOWN_SETTINGS,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        release = parser.get_release()
        login = parser.get_setting("sys sshd", "login")
        if (root is None and release and release >= (11, 6, 0) and parser.has_db_entries()
                and parser.has_object("sys sshd") and (login is None or login.value == "enabled")):
            # SC-044 F5-17: K15632, root shell login can be disabled from 11.6.0 and stays
            # enabled until 'systemauth.disablerootlogin' is set; sys db entries are only
            # saved when changed, so a system export without the key means the default.
            self.add_issue(Finding(
                rule_id="f5.bigip.auth.root_login_enabled",
                device=parser.device_type,
                title="Direct root login is allowed",
                observation=("'sys db systemauth.disablerootlogin' is not in the exported database settings, so the "
                             "default applies and the root account can log in directly over SSH."),
                impact="A single shared, all-powerful account can log in without being tied to a person, and its compromise gives full system access.",
                exploitability="Attackers target the well-known root account with password guessing or reused credentials.",
                recommendation="Run 'modify sys db systemauth.disablerootlogin value true' and use named administrator accounts.",
                severity=Severity.MEDIUM,
                evidence=("sys db systemauth.disablerootlogin absent: default false",),
                references=(ROOT_LOGIN_K15632, LOCKDOWN_SETTINGS),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))
        for name, evidence in parser.get_user_shells().items():
            if not evidence.text.endswith(" shell bash") or name.rsplit("/", 1)[-1] == "root":
                continue
            self.add_issue(Finding(
                rule_id="f5.bigip.auth.user_bash_shell",
                device=parser.device_type,
                title="Local user has an unrestricted bash shell",
                observation=f"Local user {name} has 'shell bash', an unrestricted system prompt.",
                impact="Anyone who obtains this account's password gets a full Linux shell instead of the restricted tmsh.",
                exploitability="A compromised administrator password leads directly to operating-system level control.",
                recommendation=f"Set 'modify auth user {name} shell tmsh' (or none) unless bash is operationally required.",
                severity=Severity.LOW,
                evidence=(evidence,),
                references=(USER_LATEST, LOCKDOWN_SETTINGS),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        include = parser.get_setting("sys sshd", "include")
        if include and isinstance(include.value, str):
            weak = []
            for directive, bad in (("ciphers", ("cbc", "3des", "arcfour", "blowfish")),
                                   ("macs", ("md5", "hmac-sha1", "umac-64")),
                                   ("kexalgorithms", ("group1-sha1", "group14-sha1", "group-exchange-sha1"))):
                match = re.search(directive + r"\s+(\S+)", include.value, re.IGNORECASE)
                if match:
                    weak += [alg for alg in match.group(1).split(",") if any(b in alg.lower() for b in bad)]
            if weak:
                self.add_issue(Finding(
                    rule_id="f5.bigip.ssh.weak_algorithms",
                    device=parser.device_type,
                    title="SSH allows weak algorithms",
                    observation=f"The 'sys sshd include' directives allow: {', '.join(weak)}.",
                    impact="Legacy SSH algorithms weaken confidentiality, integrity or key exchange of administrative sessions.",
                    exploitability="Requires a position on the path to the management interface.",
                    recommendation="Restrict Ciphers, MACs and KexAlgorithms to modern algorithms (CIS F5 4.5–4.7).",
                    severity=Severity.MEDIUM,
                    evidence=(include.evidence,),
                    references=(LOCKDOWN_SETTINGS,),
                    basis=FindingBasis.EXPLICIT_VALUE,
                ))
        source = parser.get_setting("auth source", "type")
        fallback = parser.get_setting("auth source", "fallback")
        if source and source.value not in {None, "local"} and fallback and fallback.value == "true":
            self.add_issue(Finding(
                rule_id="f5.bigip.auth.remote_fallback_local",
                device=parser.device_type,
                title="Remote authentication falls back to local accounts",
                observation=f"The auth source is '{source.value}' with 'fallback true', so local accounts are accepted when the remote servers are unreachable.",
                impact="Local accounts sit outside the central password, MFA and offboarding controls; an attacker who can make the AAA servers unreachable can force local logins.",
                exploitability="Requires a valid local credential and the ability to disrupt reachability of the remote authentication servers.",
                recommendation="Set 'fallback false' unless a documented break-glass procedure requires it (CIS F5 2.3); protect remaining local accounts strongly.",
                severity=Severity.LOW,
                evidence=(source.evidence, fallback.evidence),
                references=(REMOTE_USER,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        console = parser.get_setting("auth remote-user", "remote-console-access")
        if console and console.value not in {None, "disabled"}:
            self.add_issue(Finding(
                rule_id="f5.bigip.auth.remote_console_access",
                device=parser.device_type,
                title="Remote users get terminal access",
                observation=f"'auth remote-user remote-console-access {console.value}' gives remotely authenticated users without a specific mapping command-line access.",
                impact="Any account accepted by the remote directory can open a CLI session on the BIG-IP.",
                exploitability="Requires a valid directory account.",
                recommendation="Set 'remote-console-access disabled' and grant terminal access through 'auth remote-role' mappings only (CIS F5 2.6).",
                severity=Severity.MEDIUM,
                evidence=(console.evidence,),
                references=(REMOTE_USER,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        role = parser.get_setting("auth remote-user", "default-role")
        if role and role.value == "admin":
            self.add_issue(Finding(
                rule_id="f5.bigip.auth.remote_default_admin",
                device=parser.device_type,
                title="Remote users get the administrator role by default",
                observation="'auth remote-user default-role admin' gives every remotely authenticated user without a specific role mapping the admin role (default: no-access).",
                impact="Any account the remote directory accepts, not only intended administrators, gets full control of the BIG-IP.",
                exploitability="An attacker with any valid directory account can log in as an administrator.",
                recommendation="Set 'default-role no-access' and grant roles through 'auth remote-role' mappings for administrator groups.",
                severity=Severity.HIGH,
                evidence=(role.evidence,),
                references=(REMOTE_USER,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        enforcement = parser.get_setting("auth password-policy", "policy-enforcement")
        memory = parser.get_setting("auth password-policy", "password-memory")
        if enforcement and enforcement.value == "enabled" and (memory is None or memory.value == 0):
            self.add_issue(Finding(
                rule_id="f5.bigip.password_policy.history_disabled",
                device=parser.device_type,
                title="Password history is not enforced",
                observation=("Password-policy enforcement is enabled but password-memory is "
                             + ("0." if memory else "not set (default 0).")),
                impact="Users can set a previous password again, including one that was exposed.",
                exploitability="A leaked old password remains usable after a forced change.",
                recommendation="Set 'modify auth password-policy password-memory <n>' to remember recent passwords.",
                severity=Severity.LOW,
                evidence=((memory.evidence,) if memory else (enforcement.evidence,)),
                references=(PASSWORD_POLICY_LATEST,),
                basis=FindingBasis.EXPLICIT_VALUE if memory else FindingBasis.DOCUMENTED_DEFAULT,
            ))

    def _check_data_plane(self, parser: F5BIGIPParser) -> None:
        """SC-042: weak client-side ciphers and unencrypted persistence cookies on enabled virtuals."""
        for virtual, profile, weak in parser.get_bound_weak_client_ciphers():
            self._mark("f5.bigip.ltm.clientssl_weak_cipher", f"{virtual.name}|{profile.name}")
            self.add_issue(Finding(
                rule_id="f5.bigip.ltm.clientssl_weak_cipher",
                device=parser.device_type,
                title="Virtual server offers weak TLS cipher suites",
                observation=f"Virtual server {virtual.name} uses client SSL profile {profile.name}, whose cipher string adds {', '.join(weak)}.",
                impact="Application traffic, including user credentials, may be protected only by weak or broken ciphers.",
                exploitability="An attacker on the path benefits when a client negotiates one of these suites.",
                recommendation="Remove weak tokens from the cipher string or use a current F5 cipher group, and test client compatibility.",
                severity=Severity.MEDIUM,
                evidence=(virtual.evidence, profile.ciphers_evidence or profile.evidence),
                references=(CLIENT_SSL, NIST_TLS),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        for virtual, name, evidence in parser.get_unencrypted_cookie_persistence():
            self._mark("f5.bigip.ltm.cookie_unencrypted", f"{virtual.name}|{name}")
            self.add_issue(Finding(
                rule_id="f5.bigip.ltm.cookie_unencrypted",
                device=parser.device_type,
                title="Persistence cookie reveals internal server addresses",
                observation=f"Virtual server {virtual.name} uses cookie persistence profile {name} with cookie-encryption disabled.",
                impact="The persistence cookie encodes the pool member's internal IP address and port, which any client can decode.",
                exploitability="An attacker learns internal addressing and server layout from a single response, which helps later targeting.",
                recommendation=f"Set 'cookie-encryption required' with a passphrase on {name}.",
                severity=Severity.LOW,
                evidence=(virtual.evidence, evidence),
                references=(COOKIE_ENCODING, COOKIE_PERSISTENCE),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))

        for virtual, name, method in parser.get_default_unencrypted_cookie_persistence():
            self._mark("f5.bigip.ltm.cookie_unencrypted", f"{virtual.name}|{name}")
            self.add_issue(Finding(
                rule_id="f5.bigip.ltm.cookie_unencrypted",
                device=parser.device_type,
                title="Persistence cookie reveals internal server addresses",
                observation=(f"Virtual server {virtual.name} uses cookie persistence profile {name} (method {method}) "
                             "without 'cookie-encryption'; the documented default is disabled."),
                impact="The persistence cookie encodes the pool member's internal IP address and port, which any client can decode.",
                exploitability="An attacker learns internal addressing and server layout from a single response, which helps later targeting.",
                recommendation=f"Create a cookie profile with 'cookie-encryption required' and a passphrase and attach it instead of {name}.",
                severity=Severity.LOW,
                evidence=(virtual.evidence, f"ltm persistence cookie {name} cookie-encryption <absent: default disabled>"),
                references=(COOKIE_ENCRYPTION_DEFAULT, COOKIE_ENCODING, COOKIE_PERSISTENCE),
                basis=FindingBasis.DOCUMENTED_DEFAULT,
            ))

        for virtual, name, mode, evidence in parser.get_unverified_server_ssl():
            explicit = "<absent" not in evidence.text
            self._mark("f5.bigip.ltm.serverssl_no_cert_validation", f"{virtual.name}|{name}")
            self.add_issue(Finding(
                rule_id="f5.bigip.ltm.serverssl_no_cert_validation",
                device=parser.device_type,
                title="Server SSL profile does not verify the pool member certificate",
                observation=(f"Virtual server {virtual.name} re-encrypts to the pool with Server SSL profile {name}, whose "
                             f"peer-cert-mode is {mode}" + ("." if explicit else " (the documented default).")),
                impact="The BIG-IP accepts any certificate from the back end, so a host that can intercept that path can read and change the traffic.",
                exploitability="An attacker on the server-side network can impersonate a pool member with a self-signed certificate.",
                recommendation=f"Set 'peer-cert-mode require' with a trusted ca-file (and authenticate-name) on {name}, or document why the server-side path is trusted.",
                severity=Severity.LOW,
                evidence=(virtual.evidence, evidence),
                references=(SERVER_SSL,),
                basis=FindingBasis.EXPLICIT_VALUE if explicit else FindingBasis.DOCUMENTED_DEFAULT,
            ))

    def _check_cleartext_extras(self, parser: F5BIGIPParser) -> None:
        """SC-036/037/043: basic-auth monitors, SNMPv1/v2c traps, risky services on any-source virtuals."""
        for evidence in parser.get_monitor_basic_auth():
            self.add_issue(Finding(
                rule_id="f5.bigip.credentials.monitor_storage",
                device=parser.device_type,
                title="Health monitor sends a Basic authentication header",
                observation="An HTTP/HTTPS monitor send string contains an 'Authorization: Basic' header; the value is redacted.",
                impact="Basic credentials are only Base64-encoded: anyone with the configuration can decode them, and HTTP monitors send them in clear text.",
                exploitability="An attacker who obtains a configuration backup, or captures monitor traffic, can reuse the monitoring account on the application.",
                recommendation="Use a dedicated low-privilege monitoring account, prefer an HTTPS monitor, and rotate the exposed credential.",
                severity=Severity.MEDIUM,
                evidence=(evidence,),
                references=(MONITOR_HTTP,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        legacy = [evidence for _, version, evidence in parser.get_snmp_traps() if version in {"1", "2c"}]
        if legacy:
            self.add_issue(Finding(
                rule_id="f5.bigip.snmp.legacy_version",
                device=parser.device_type,
                title="SNMP traps use SNMPv1/v2c",
                observation="One or more 'sys snmp traps' targets explicitly use version 1 or 2c.",
                impact="Each trap carries the community string in clear text and has no integrity protection.",
                exploitability="An attacker on the path can read the community and reuse it if it also grants SNMP access.",
                recommendation="Send traps with version 3 and security-level auth-privacy.",
                severity=Severity.MEDIUM,
                evidence=tuple(legacy),
                references=(SNMP_LATEST,),
                basis=FindingBasis.EXPLICIT_VALUE,
            ))
        for endpoint in parser.get_virtual_endpoints():
            if not _ANY_SOURCE.match(endpoint.source.casefold()) or endpoint.protocol == "unknown":
                continue
            number = (int(endpoint.port) if endpoint.port.isdigit()
                      else CISCO_PORT_NAMES.get(endpoint.port.casefold()))
            if number is None:
                continue
            labels = sorted(risky_labels(endpoint.protocol, number, number))
            if not labels:
                continue
            release = parser.get_release()
            references = [VIRTUAL]
            if not endpoint.protocol_explicit and release:
                references.append(
                    f"https://clouddocs.f5.com/cli/tmsh-reference/v{release[0]}/modules/ltm/ltm_virtual.html"
                )
            if not endpoint.source_explicit and release:
                references.append(VIRTUAL_SOURCE_DEFAULT[release[0]])
            self._mark("f5.bigip.ltm.risky_service_exposure", endpoint.virtual.name)
            self.add_issue(Finding(
                rule_id="f5.bigip.ltm.risky_service_exposure",
                device=parser.device_type,
                title="Virtual server publishes a potentially risky service to any source",
                observation=(f"Enabled virtual server {endpoint.virtual.name} listens on "
                             f"{endpoint.protocol.upper()}/{endpoint.port} "
                             f"({', '.join(labels)}) for source {endpoint.source}. "
                             "Port identity does not establish the application protocol or encryption."),
                impact="A sensitive service may be reachable from broad client networks if the destination uses the catalogued protocol.",
                exploitability="A client that can reach the virtual address may be able to probe the published service; application behavior and upstream controls are not established by this export.",
                recommendation="Verify the application on this port and its transport security, and restrict the virtual server's source addresses where appropriate.",
                severity=Severity.MEDIUM,
                evidence=(endpoint.evidence,),
                references=tuple(dict.fromkeys(references)),
                basis=(FindingBasis.EXPLICIT_VALUE if endpoint.protocol_explicit and endpoint.source_explicit
                       else FindingBasis.DOCUMENTED_DEFAULT),
            ))
