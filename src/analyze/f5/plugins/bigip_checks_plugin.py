"""Explicit BIG-IP TMOS management and audit controls."""

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser
from src.devices.f5.bigip import F5BIGIPParser, F5Setting


SSHD = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_sshd.html"
HTTPD = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/sys/sys_httpd.html"
CONSOLE = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_global-settings.html"
CLI = "https://clouddocs.f5.com/cli/tmsh-reference/v15/modules/cli/cli_global-settings.html"
PASSWORD = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/auth/auth_password-policy.html"
USER = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/auth/auth_user.html"
SYSLOG = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_syslog.html"
CLIENT_SSL = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/ltm/ltm_profile_client-ssl.html"
VIRTUAL = "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/ltm/ltm_virtual.html"


class PluginF5BIGIPChecks(BasePlugin):
    def _emit(self, parser: F5BIGIPParser, setting: F5Setting, *, rule_id: str,
              title: str, observation: str, impact: str, recommendation: str,
              severity: Severity, reference: str) -> None:
        self.add_issue(Finding(
            rule_id=rule_id, device=parser.device_type, title=title,
            observation=observation, impact=impact,
            exploitability="An attacker who can reach the management service or obtain administrative access may exploit this setting.",
            recommendation=recommendation, severity=severity,
            evidence=(setting.evidence.text,), references=(reference,),
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
                evidence=(credential.evidence.text,),
                references=(USER,),
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
                evidence=(virtual.evidence.text, profile.evidence.text),
                references=(VIRTUAL, CLIENT_SSL),
            ))
