from src.analyze.common.base_plugin import BasePlugin
from src.analyze.cisco.ios.issue.cisco_ios_issue import CiscoIOSIssue
from src.devices.common.base_parser import BaseDeviceParser


class PluginScreenOSChecks(BasePlugin):

    def __init__(self):
        super().__init__()

    # NS-01: Insecure Admin Services
    def check_insecure_services(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        # Look for enabled telnet or web (HTTP)
        for line in config:
            if "set admin telnet enable" in line:
                issue = CiscoIOSIssue(
                    "Telnet Service Enabled",
                    "The Telnet service is enabled on the device.",
                    "Telnet transmits management credentials in clear-text, exposing them to interception.",
                    "High",
                    "Disable Telnet and use SSH. Command: unset admin telnet"
                )
                self.add_issue(issue)
            elif "set admin web enable" in line:
                issue = CiscoIOSIssue(
                    "Web Management (HTTP) Enabled",
                    "Web management (HTTP) is enabled.",
                    "Web management via HTTP transmits traffic in clear-text.",
                    "High",
                    "Disable HTTP and use HTTPS. Command: unset admin web"
                )
                self.add_issue(issue)

    # NS-03: Broad Policy Rules
    def check_broad_policy_rules(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        # Simplistic check for policy rules allowing 'any'
        for line in config:
            if "set policy" in line and "any" in line and "any" in line and "permit" in line:
                issue = CiscoIOSIssue(
                    "Broad Policy Rule Detected",
                    f"Policy rule detected allowing 'any' to 'any': {line.strip()}",
                    "Allows unrestricted traffic between zones/networks.",
                    "Critical",
                    "Restrict policy rules to specific source/destination objects."
                )
                self.add_issue(issue)

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_insecure_services(parser)
        self.check_broad_policy_rules(parser)
