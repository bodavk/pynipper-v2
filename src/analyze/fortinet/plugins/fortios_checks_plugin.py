from src.analyze.common.base_plugin import BasePlugin
from src.analyze.cisco.ios.issue.cisco_ios_issue import CiscoIOSIssue
from src.devices.common.base_parser import BaseDeviceParser


class PluginFortiOSChecks(BasePlugin):

    def __init__(self):
        super().__init__()

    # FT-01: Weak Administrative Access
    def check_admin_access(self, parser: BaseDeviceParser) -> None:
        services = parser.get_services()
        if services.get("http", False) or services.get("telnet", False):
            issue = CiscoIOSIssue(
                "Weak Administrative Access",
                "HTTP or Telnet management is enabled.",
                "Insecure protocols.",
                "High",
                "Disable HTTP/Telnet; use HTTPS/SSH."
            )
            self.add_issue(issue)

    # FT-02: Broad Firewall Policies
    def check_broad_policies(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        policies = config.get("firewall policy", {})
        for name, policy in policies.items():
            if policy.get("srcintf") == "any" and \
               policy.get("dstintf") == "any" and \
               policy.get("action") == "accept":
                issue = CiscoIOSIssue(
                    "Broad Firewall Policy",
                    f"Policy '{name}' is overly permissive (any-any-any allow).",
                    "Security bypass.",
                    "Critical",
                    "Restrict the policy."
                )
                self.add_issue(issue)

    # FT-03: Insecure TLS Settings
    def check_tls_settings(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        system = config.get("system global", {})
        if system.get("ssl-min-proto-version") in ["TLSv1.0", "TLSv1.1"]:
            issue = CiscoIOSIssue(
                "Insecure TLS Version",
                "Minimum SSL/TLS protocol version is set to an insecure version.",
                "Traffic can be decrypted.",
                "High",
                "Set ssl-min-proto-version to TLSv1.2 or higher."
            )
            self.add_issue(issue)

    # FT-04: Lack of System Logging
    def check_syslog(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        if "log syslogd setting" not in config:
            issue = CiscoIOSIssue(
                "Lack of System Logging",
                "Syslog is not configured.",
                "No audit trail.",
                "Medium",
                "Configure log syslogd settings."
            )
            self.add_issue(issue)

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_admin_access(parser)
        self.check_broad_policies(parser)
        self.check_tls_settings(parser)
        self.check_syslog(parser)
