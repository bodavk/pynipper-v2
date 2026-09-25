"""Check Point Gaia OS management checks (SC-023) from the Gaia Administration Guide."""

from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.checkpoint.gaia import CheckPointGaiaParser
from src.devices.common.base_parser import BaseDeviceParser

_GUIDE = "https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_Gaia_AdminGuide/Topics-GAG/"
NETWORK_ACCESS = _GUIDE + "Network-Access.htm"
SNMP = _GUIDE + "SNMP-Gaia-Clish.htm"
PASSWORD_POLICY = _GUIDE + "Password-Policy-Gaia-Clish.htm"
SESSION = _GUIDE + "Session.htm"
MESSAGES = _GUIDE + "Messages.htm"
NIST_PASSWORDS = "https://pages.nist.gov/800-63-4/sp800-63b.html"
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

    def _check_session(self, parser: CheckPointGaiaParser) -> None:
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
