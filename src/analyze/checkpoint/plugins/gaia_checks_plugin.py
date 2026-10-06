"""Check Point Gaia OS management checks (SC-023) from the Gaia Administration Guide."""

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.controls import ControlOutcome as CO, record_control
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.checkpoint.gaia import CheckPointGaiaParser
from src.devices.common.base_parser import BaseDeviceParser

_GUIDE = "https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_Gaia_AdminGuide/Topics-GAG/"
NETWORK_ACCESS = _GUIDE + "Network-Access.htm"
SNMP = _GUIDE + "SNMP-Gaia-Clish.htm"
PASSWORD_POLICY = _GUIDE + "Password-Policy-Gaia-Clish.htm"
SESSION = _GUIDE + "Session.htm"
MESSAGES = _GUIDE + "Messages.htm"
USERS = _GUIDE + "Users-Gaia-Clish.htm"
NIST_PASSWORDS = "https://pages.nist.gov/800-63-4/sp800-63b.html"
# SC-044 release-default sources (docs/agent_notes/INSECURE_DEFAULTS_BY_RELEASE.md).
PASSWORD_POLICY_R8030 = (
    "https://sc1.checkpoint.com/documents/R80.30/WebAdminGuides/EN/CP_R80.30_Gaia_AdminGuide/94483.htm"
)
SSH_SERVER_R8120 = (
    "https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_Gaia_AdminGuide/Content/"
    "Topics-GAG/Advanced-Gaia-Configuration-SSH-MAC-KEX.htm"
)
CLUSTERXL_R8030 = (
    "https://sc1.checkpoint.com/documents/R80.30/WebAdminGuides/EN/CP_R80.30_ClusterXL_AdminGuide/213846.htm"
)
SYSLOG_R8120 = (
    "https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_Gaia_AdminGuide/Content/"
    "Topics-GAG/System-Logging-Gaia-Clish.htm"
)
ALLOWED_CLIENTS = _GUIDE + "Allowed-Clients-Gaia-Clish.htm"
PASSWORD_POLICY_R8120 = (
    "https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_Gaia_AdminGuide/Content/"
    "Topics-GAG/Password-Policy-Gaia-Portal.htm"
)
WEB_SERVER_R82 = (
    "https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_Gaia_AdminGuide/Content/"
    "Topics-GAG/Advanced-Gaia-Configuration-Gaia-Portal-Web-Server.htm"
)
DEFAULT_COMMUNITIES = {"public", "private"}


class PluginCheckPointGaiaChecks(BasePlugin):
    def _emit(self, parser, rule, title, observation, impact, recommendation, severity, evidence,
              references, basis, exploitability="An attacker who can reach the management plane may exploit this setting."):
        self.add_issue(Finding(
            rule_id=f"checkpoint.gaia.{rule}", device=parser.device_type, title=title,
            observation=observation, impact=impact, exploitability=exploitability,
            recommendation=recommendation, severity=severity, evidence=evidence,
            references=references, basis=basis,
        ))

    def analyze(self, parser: BaseDeviceParser) -> None:
        if not isinstance(parser, CheckPointGaiaParser):
            raise TypeError("PluginCheckPointGaiaChecks requires a CheckPointGaiaParser")
        self._check_management(parser)
        self._check_snmp(parser)
        self._check_password_policy(parser)
        self._check_session(parser)
        self._check_user_shells(parser)
        self._check_release_defaults(parser)
        self._record_controls(parser)

    def _record_controls(self, parser: CheckPointGaiaParser) -> None:
        """SC-049 fifth batch. A Clish export is one flat configuration, so an omitted
        command is evaluated against the documented default the check already applies."""
        fired = {issue.rule_id for issue in self.issues}

        def digits(item):
            return item is None or item.value.isdigit()

        control = "checkpoint.gaia.login-lockout"
        lockout = parser.get_password_control("deny-on-fail enable")
        if fired & {"checkpoint.gaia.password_policy.lockout_disabled", "checkpoint.gaia.password_policy.lockout_threshold"}:
            record_control(parser, control, CO.FINDING, "Failed-login lockout is disabled or allows many attempts.")
        elif lockout.value != "on" or not (digits(parser.get_password_control("deny-on-fail failures-allowed"))
                                           and digits(parser.get_password_control("deny-on-fail allow-after"))):
            record_control(parser, control, CO.UNKNOWN, "A failed-login lockout value is malformed.")
        else:
            record_control(parser, control, CO.NO_FINDING,
                           "Lockout is on with at most five failures and at least 300 seconds.")

        control = "checkpoint.gaia.password-length"
        length = parser.get_password_control("min-password-length")
        if "checkpoint.gaia.password_policy.minimum_length" in fired:
            record_control(parser, control, CO.FINDING, "Minimum password length is below eight or at the default of six.")
        elif not digits(length):
            record_control(parser, control, CO.UNKNOWN, "min-password-length is malformed.")
        else:
            record_control(parser, control, CO.NO_FINDING, f"min-password-length is {length.value}.")

        control = "checkpoint.gaia.web-session-timeout"
        web = parser.get_web_session_timeout()
        if "checkpoint.gaia.web.session_timeout_excessive" in fired:
            record_control(parser, control, CO.FINDING, "Gaia Portal session timeout exceeds ten minutes.")
        elif not digits(web):
            record_control(parser, control, CO.UNKNOWN, "web session-timeout is malformed.")
        else:
            record_control(parser, control, CO.NO_FINDING, f"web session-timeout is {web.value} minutes.")

        control = "checkpoint.gaia.cli-idle-timeout"
        timeout = parser.get_inactivity_timeout()
        if "checkpoint.gaia.cli.idle_timeout_excessive" in fired:
            record_control(parser, control, CO.FINDING, "Clish idle timeout exceeds ten minutes.")
        elif not digits(timeout):
            record_control(parser, control, CO.UNKNOWN, "inactivity-timeout is malformed.")
        else:
            record_control(parser, control, CO.NO_FINDING,
                           f"inactivity-timeout is {timeout.value} minutes." if timeout
                           else "inactivity-timeout is omitted; the documented default is 10 minutes.")

        control = "checkpoint.gaia.login-banner"
        banner = parser.get_banner()
        if "checkpoint.gaia.banner.login_disabled" in fired:
            record_control(parser, control, CO.FINDING, "The pre-login banner is disabled.")
        elif banner is not None and banner.value != "on":
            record_control(parser, control, CO.UNKNOWN, "The message banner value is malformed.")
        else:
            record_control(parser, control, CO.NO_FINDING,
                           "The message banner is on." if banner
                           else "The message banner is omitted; it is enabled by default.")

        control = "checkpoint.gaia.management-telnet"
        telnet = parser.get_telnet()
        if "checkpoint.gaia.management.telnet" in fired:
            record_control(parser, control, CO.FINDING, "Telnet management is enabled.")
        elif telnet is not None and telnet.value != "off":
            record_control(parser, control, CO.UNKNOWN, "The net-access telnet value is malformed.")
        else:
            record_control(parser, control, CO.NO_FINDING,
                           "Telnet management is off." if telnet else "Telnet is omitted; it is disabled by default.")

        control = "checkpoint.gaia.snmp-community"
        agent = parser.get_snmp_agent()
        communities = parser.get_snmp_communities()
        if fired & {"checkpoint.gaia.snmp.default_community", "checkpoint.gaia.snmp.write_community"}:
            record_control(parser, control, CO.FINDING, "A default or read-write SNMP community is configured.")
        elif agent is None or agent.value == "off":
            record_control(parser, control, CO.NOT_APPLICABLE, "The SNMP agent is not enabled.")
        elif agent.value != "on" or any(item.access == "unknown" for item in communities):
            record_control(parser, control, CO.UNKNOWN, "The SNMP agent or a community access value is malformed.")
        else:
            record_control(parser, control, CO.NO_FINDING,
                           "No default or read-write community is configured." if communities
                           else "No SNMP community is configured.")

        control = "checkpoint.gaia.ssh-root-login"
        ssh = parser.get_ssh_server_settings()
        root = ssh.get("permit-root-login")
        if "checkpoint.gaia.ssh.root_login_permitted" in fired:
            record_control(parser, control, CO.FINDING, "SSH root login is permitted.")
        elif root is not None and root.value.lower() == "no":
            record_control(parser, control, CO.NO_FINDING, "permit-root-login is no.")
        elif root is not None:
            record_control(parser, control, CO.UNKNOWN, "permit-root-login has an unrecognized value.")
        else:
            record_control(parser, control, CO.UNKNOWN,
                           "No 'set ssh server' settings are exported (pre-R81.20 syntax); the root login default is not verified.")

    def _check_release_defaults(self, parser: CheckPointGaiaParser) -> None:
        """SC-044 CP-03/05/06/07/08/11."""
        nonuse = parser.get_password_control("deny-on-nonuse enable")
        if nonuse is None or nonuse.value == "off":
            self._emit(parser, "password_policy.nonuse_lockout_disabled", "Unused accounts are not locked",
                       "'deny-on-nonuse' is off, so accounts that have not logged in for a long time stay usable"
                       + ("." if nonuse else " (the documented default)."),
                       "Forgotten accounts of former administrators remain valid targets for password guessing.",
                       "Run 'set password-controls deny-on-nonuse enable on' with an allowed-no-use period.",
                       Severity.LOW, ((nonuse.evidence,) if nonuse else ("no set password-controls deny-on-nonuse enable",)),
                       (PASSWORD_POLICY, PASSWORD_POLICY_R8030),
                       FindingBasis.EXPLICIT_VALUE if nonuse else FindingBasis.DOCUMENTED_DEFAULT)
        if parser.get_password_control("min-password-length") is None:
            self._emit(parser, "password_policy.minimum_length", "Minimum password length is short",
                       "'min-password-length' is not in the export; the documented default is 6 characters.",
                       "Short passwords can be guessed or cracked quickly.",
                       "Set 'set password-controls min-password-length' to at least 8, preferably 14 or more.",
                       Severity.MEDIUM, ("min-password-length absent: default 6",),
                       (PASSWORD_POLICY_R8030, NIST_PASSWORDS), FindingBasis.DOCUMENTED_DEFAULT)
        ssh = parser.get_ssh_server_settings()
        root = ssh.get("permit-root-login")
        if (root and root.value.lower() == "yes") or (ssh and root is None):
            self._emit(parser, "ssh.root_login_permitted", "SSH login as root is permitted",
                       ("'set ssh server permit-root-login yes' is configured." if root else
                        "The export uses the R81.20+ 'set ssh server' settings but not permit-root-login; the documented default is 'yes'."),
                       "A root password can be guessed or reused over SSH, giving a full shell without a personal account.",
                       "Run 'set ssh server permit-root-login no' and use named administrators.",
                       Severity.MEDIUM, (root.evidence,) if root else tuple(item.evidence for item in list(ssh.values())[:3]),
                       (SSH_SERVER_R8120,), FindingBasis.EXPLICIT_VALUE if root else FindingBasis.DOCUMENTED_DEFAULT)
        ccp = parser.get_cluster_ccp_encryption()
        if ccp and ccp.value.lower() == "off":
            self._emit(parser, "cluster.ccp_encryption_disabled", "ClusterXL control protocol is not encrypted",
                       "'set cluster member ccpenc off' sends Cluster Control Protocol (CCP) messages without encryption.",
                       "An attacker on the synchronisation network can read or forge cluster state messages.",
                       "Run 'set cluster member ccpenc on' on every member and keep the sync network isolated.",
                       Severity.MEDIUM, (ccp.evidence,), (CLUSTERXL_R8030,), FindingBasis.EXPLICIT_VALUE)
        for address, protocol, evidence in parser.get_remote_syslog():
            if protocol in {"", "udp"}:
                self._emit(parser, "syslog.remote_udp", "Remote syslog uses UDP",
                           f"Remote syslog server {address} uses UDP" + (" (the documented default)." if not protocol else "."),
                           "UDP syslog can be lost silently or spoofed, and is unencrypted.",
                           "Use 'protocol tcp' (R81.20+) or forward logs through the management server, over a protected path.",
                           Severity.LOW, (evidence,), (SYSLOG_R8120,),
                           FindingBasis.DOCUMENTED_DEFAULT if not protocol else FindingBasis.EXPLICIT_VALUE)
        for target, evidence in parser.get_allowed_clients():
            if target in {"any-host", "any"}:
                self._emit(parser, "management.unrestricted_allowed_client", "Gaia management accepts any client host",
                           "'allowed-client host any-host' lets any address connect to the Gaia Portal, SSH and other management services.",
                           "More hosts can attempt administrative logins or exploit management-plane vulnerabilities.",
                           "Delete 'any-host' and add only the management networks ('add allowed-client network ...').",
                           Severity.MEDIUM, (evidence,), (ALLOWED_CLIENTS,), FindingBasis.EXPLICIT_VALUE)

    def _check_user_shells(self, parser: CheckPointGaiaParser) -> None:
        """SC-030: users whose login shell is bash (Expert mode) instead of Clish."""
        for user in parser.get_local_users():
            if user.shell not in {"/bin/bash", "bash"} or user.name == "root":
                continue
            evidence = tuple(item for item in user.evidence if " shell " in f" {item.text} ") or user.evidence
            self._emit(parser, "auth.user_bash_shell", "User logs in to the Expert (bash) shell",
                       f"User '{user.name}' has shell /bin/bash, so login opens the Linux Expert shell instead of Clish.",
                       "A compromised password for this user gives a full operating-system shell without the Expert-mode password step.",
                       f"Set 'set user {user.name} shell /etc/cli.sh' unless Expert access at login is required.",
                       Severity.LOW, evidence, (USERS,), FindingBasis.EXPLICIT_VALUE)

    def _check_management(self, parser: CheckPointGaiaParser) -> None:
        telnet = parser.get_telnet()
        if telnet and telnet.value == "on":
            self._emit(parser, "management.telnet", "Telnet access to Gaia is enabled",
                       "'set net-access telnet on' enables clear-text Telnet management (disabled by default).",
                       "Administrator credentials and sessions can be captured on the network.",
                       "Run 'set net-access telnet off' and use SSH.",
                       Severity.HIGH, (telnet.evidence,), (NETWORK_ACCESS,), FindingBasis.EXPLICIT_VALUE)

    def _check_snmp(self, parser: CheckPointGaiaParser) -> None:
        agent = parser.get_snmp_agent()
        if not agent or agent.value != "on":
            return
        version = parser.get_snmp_agent_version()
        communities = parser.get_snmp_communities()
        for community in communities:
            if community.name.casefold() in DEFAULT_COMMUNITIES:
                self._emit(parser, "snmp.default_community", "Default SNMP community is configured",
                           "A well-known default community name is configured while the SNMP agent is on; its value is redacted.",
                           "Anyone who can reach SNMP can query the gateway with a known string.",
                           "Delete the community ('delete snmp community <name>') and use SNMPv3 users with authPriv.",
                           Severity.HIGH, (agent.evidence, community.evidence), (SNMP,), FindingBasis.EXPLICIT_VALUE)
            if community.access == "read-write":
                self._emit(parser, "snmp.write_community", "SNMP community grants write access",
                           "An SNMP community is configured read-write while the SNMP agent is on.",
                           "A holder of the community string can change settings over an unauthenticated, unencrypted protocol.",
                           "Set the community to read-only or remove it, and use SNMPv3.",
                           Severity.HIGH, (agent.evidence, community.evidence), (SNMP,), FindingBasis.EXPLICIT_VALUE)
        if communities and version and version.value == "any":
            self._emit(parser, "snmp.legacy_version", "SNMPv1/v2c access is enabled",
                       "The SNMP agent is on with 'agent-version any' and at least one community, so community-based SNMP is accepted.",
                       "Community strings travel in clear text and give no per-user authentication.",
                       "Set 'set snmp agent-version v3-Only' and use SNMPv3 users with authPriv.",
                       Severity.MEDIUM, (agent.evidence, version.evidence), (SNMP,), FindingBasis.EXPLICIT_VALUE)
        for user in parser.get_snmp_users():
            if user.security_level.casefold() != "authpriv":
                self._emit(parser, "snmp.v3_security", "SNMPv3 user without encryption",
                           f"SNMPv3 user '{user.name}' uses security-level {user.security_level}.",
                           "SNMP messages for this user are not encrypted.",
                           "Recreate the user with 'security-level authPriv' and AES privacy.",
                           Severity.MEDIUM, (user.evidence,), (SNMP,), FindingBasis.EXPLICIT_VALUE)

    def _check_password_policy(self, parser: CheckPointGaiaParser) -> None:
        lockout = parser.get_password_control("deny-on-fail enable")
        if lockout is None or lockout.value == "off":
            self._emit(parser, "password_policy.lockout_disabled", "Failed-login lockout is disabled",
                       "'deny-on-fail' is off, so accounts are not locked after repeated failed logins"
                       + ("." if lockout else " (the documented default)."),
                       "Password guessing against administrator accounts is not slowed down.",
                       "Run 'set password-controls deny-on-fail enable on' and set failures-allowed and allow-after.",
                       Severity.MEDIUM, ((lockout.evidence,) if lockout else ("no set password-controls deny-on-fail enable",)),
                       (PASSWORD_POLICY,), FindingBasis.EXPLICIT_VALUE if lockout else FindingBasis.DOCUMENTED_DEFAULT)
        history = parser.get_password_control("history-checking")
        if history and history.value == "off":
            self._emit(parser, "password_policy.history_disabled", "Password history checking is disabled",
                       "'set password-controls history-checking off' allows reusing previous passwords.",
                       "A compromised old password can be set again.",
                       "Run 'set password-controls history-checking on'.",
                       Severity.LOW, (history.evidence,), (PASSWORD_POLICY,), FindingBasis.EXPLICIT_VALUE)
        complexity = parser.get_password_control("complexity")
        if complexity and complexity.value == "1":
            self._emit(parser, "password_policy.complexity", "Password complexity is at the lowest level",
                       "'set password-controls complexity 1' does not require different character types.",
                       "Simple passwords are easier to guess.",
                       "Set complexity 2 or higher, or rely on a long minimum length.",
                       Severity.LOW, (complexity.evidence,), (PASSWORD_POLICY,), FindingBasis.EXPLICIT_VALUE)
        length = parser.get_password_control("min-password-length")
        if length and length.value.isdigit() and int(length.value) < 8:
            self._emit(parser, "password_policy.minimum_length", "Minimum password length is short",
                       f"'set password-controls min-password-length {length.value}' allows passwords shorter than 8 characters.",
                       "Short passwords can be guessed or cracked quickly.",
                       "Set a minimum length of at least 8, preferably 14 or more.",
                       Severity.MEDIUM, (length.evidence,), (PASSWORD_POLICY, NIST_PASSWORDS), FindingBasis.EXPLICIT_VALUE)

    def _check_lockout_limits(self, parser: CheckPointGaiaParser) -> None:
        """CIS Check Point 1.12/1.13: limits that apply once deny-on-fail is enabled.

        Gaia Administration Guide (password policy): failures-allowed default 10
        (range 2-1000); allow-after default 1200 seconds (range 60-604800).
        """
        lockout = parser.get_password_control("deny-on-fail enable")
        if lockout is None or lockout.value != "on":
            return  # lockout disabled is reported by password_policy.lockout_disabled
        failures = parser.get_password_control("deny-on-fail failures-allowed")
        allow_after = parser.get_password_control("deny-on-fail allow-after")
        problems, evidence, explicit = [], [lockout.evidence], False
        if failures is None:
            problems.append("failures-allowed is not set, so the documented default of 10 failed attempts applies")
        elif failures.value.isdigit() and int(failures.value) > 5:
            problems.append(f"failures-allowed is {failures.value}")
            evidence.append(failures.evidence)
            explicit = True
        if allow_after is not None and allow_after.value.isdigit() and int(allow_after.value) < 300:
            problems.append(f"allow-after is {allow_after.value} seconds")
            evidence.append(allow_after.evidence)
            explicit = True
        if problems:
            self._emit(parser, "password_policy.lockout_threshold", "Failed-login lockout allows many attempts",
                       "Failed-login lockout is enabled, but " + "; ".join(problems) + ".",
                       "More password guesses are possible before an account is locked, or the lock ends sooner.",
                       "Set 'deny-on-fail failures-allowed' to 5 or fewer and 'allow-after' to at least 300 seconds.",
                       Severity.LOW, tuple(evidence), (PASSWORD_POLICY_R8120,),
                       FindingBasis.EXPLICIT_VALUE if explicit else FindingBasis.DOCUMENTED_DEFAULT)

    def _check_session(self, parser: CheckPointGaiaParser) -> None:
        self._check_lockout_limits(parser)
        web = parser.get_web_session_timeout()
        if web is None or (web.value.isdigit() and int(web.value) > 10):
            minutes = web.value if web is not None else "15"
            self._emit(parser, "web.session_timeout_excessive", "Gaia Portal session timeout is longer than ten minutes",
                       (f"'set web session-timeout {web.value}' keeps Gaia Portal sessions open for {web.value} minutes."
                        if web is not None else
                        "'web session-timeout' is not set, so the documented default of 15 minutes applies."),
                       "An unattended web administration session stays usable longer.",
                       "Run 'set web session-timeout 10' or less.",
                       Severity.LOW, (web.evidence,) if web is not None else ("set web session-timeout: not configured (default 15)",),
                       (WEB_SERVER_R82,),
                       FindingBasis.EXPLICIT_VALUE if web is not None else FindingBasis.DOCUMENTED_DEFAULT)
        timeout = parser.get_inactivity_timeout()
        if timeout and timeout.value.isdigit() and int(timeout.value) > 10:
            self._emit(parser, "cli.idle_timeout_excessive", "Clish idle timeout is longer than ten minutes",
                       f"'set inactivity-timeout {timeout.value}' keeps idle Clish sessions open for {timeout.value} minutes (default 10).",
                       "An unattended administrator session stays usable longer.",
                       "Set 'set inactivity-timeout 10' or less.",
                       Severity.LOW, (timeout.evidence,), (SESSION,), FindingBasis.EXPLICIT_VALUE)
        banner = parser.get_banner()
        if banner and banner.value == "off":
            self._emit(parser, "banner.login_disabled", "Login banner is disabled",
                       "'set message banner off' removes the pre-login notice (enabled by default).",
                       "Users are not warned about authorized use, which can weaken legal action after misuse.",
                       "Run 'set message banner on msgvalue \"<approved notice>\"'.",
                       Severity.LOW, (banner.evidence,), (MESSAGES,), FindingBasis.EXPLICIT_VALUE)
