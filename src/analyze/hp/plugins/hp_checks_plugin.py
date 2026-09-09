from src.analyze.common.base_plugin import BasePlugin
from src.analyze.cisco.ios.issue.cisco_ios_issue import CiscoIOSIssue
from src.devices.common.base_parser import BaseDeviceParser


class PluginHPChecks(BasePlugin):

    def __init__(self):
        super().__init__()

    # HP-01: Telnet Enabled
    def check_telnet(self, parser: BaseDeviceParser) -> None:
        services = parser.get_services()
        if services.get("telnet", True):
            issue = CiscoIOSIssue(
                "Telnet Enabled",
                "Telnet is enabled, which is insecure.",
                "Credentials can be sniffed.",
                "High",
                "Disable Telnet: 'no telnet-server'"
            )
            self.add_issue(issue)

    # HP-02: SNMP Default Communities
    def check_snmp_communities(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        for line in config:
            if "snmp-server community public" in line or "snmp-server community private" in line:
                issue = CiscoIOSIssue(
                    "Default SNMP Community",
                    f"Default SNMP community string detected: {line}",
                    "Information disclosure.",
                    "Medium",
                    "Change the community string."
                )
                self.add_issue(issue)

    # HP-03: Insecure Web Management
    def check_web_management(self, parser: BaseDeviceParser) -> None:
        services = parser.get_services()
        if services.get("http", False):
            issue = CiscoIOSIssue(
                "Insecure Web Management",
                "Clear-text web management is enabled.",
                "Credentials can be sniffed.",
                "High",
                "Disable http: 'no web-management'"
            )
            self.add_issue(issue)

    # HP-04: Lack of SSH Key Exchange Hardening
    def check_ssh_hardening(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        # Simplistic check
        if not any("ip ssh key-exchange" in line for line in config):
            issue = CiscoIOSIssue(
                "SSH Key Exchange Not Hardened",
                "SSH key exchange settings are not explicitly hardened.",
                "Weak SSH configuration.",
                "Medium",
                "Configure hardened SSH key exchange settings."
            )
            self.add_issue(issue)

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_telnet(parser)
        self.check_snmp_communities(parser)
        self.check_web_management(parser)
        self.check_ssh_hardening(parser)
