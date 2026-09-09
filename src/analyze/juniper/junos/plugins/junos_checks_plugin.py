from src.analyze.common.base_plugin import BasePlugin
from src.analyze.cisco.ios.issue.cisco_ios_issue import CiscoIOSIssue
from src.devices.common.base_parser import BaseDeviceParser


class PluginJunOSChecks(BasePlugin):

    def __init__(self):
        super().__init__()

    # JUN-01: Insecure Web / CLI management
    def check_management(self, parser: BaseDeviceParser) -> None:
        services = parser.get_services()
        if services.get("telnet", False) or services.get("http", False):
            issue = CiscoIOSIssue(
                "Insecure Management Service Enabled",
                "Telnet or Web-management is enabled.",
                "Insecure protocols.",
                "High",
                "Disable Telnet/Web-management."
            )
            self.add_issue(issue)

    # JUN-02: Broad Firewall Filters
    def check_broad_filters(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        for line in config:
            if "term" in line and "then accept" in line and "filter" in line:
                # Simplistic check for overly permissive filter
                if "source-address 0.0.0.0/0" in line or "destination-address 0.0.0.0/0" in line:
                    issue = CiscoIOSIssue(
                        "Broad Firewall Filter",
                        "Filter allows any traffic without logging.",
                        "Security bypass.",
                        "Critical",
                        "Restrict filter and enable logging."
                    )
                    self.add_issue(issue)

    # JUN-03: SSH Root Login
    def check_ssh_root(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        for line in config:
            if "set system services ssh root-login allow" in line:
                issue = CiscoIOSIssue(
                    "SSH Root Login Permitted",
                    "Root login via SSH is allowed.",
                    "Higher risk of credential compromise.",
                    "High",
                    "Disable root login via SSH."
                )
                self.add_issue(issue)

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_management(parser)
        self.check_broad_filters(parser)
        self.check_ssh_root(parser)
