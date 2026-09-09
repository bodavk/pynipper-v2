from src.analyze.common.base_plugin import BasePlugin
from src.analyze.cisco.ios.issue.cisco_ios_issue import CiscoIOSIssue
from src.devices.common.base_parser import BaseDeviceParser


class PluginAristaChecks(BasePlugin):

    def __init__(self):
        super().__init__()

    # AR-01: Unsecured Management API
    def check_management_api(self, parser: BaseDeviceParser) -> None:
        conf_parse = parser.get_raw_config()
        # Look for management api http commands
        if conf_parse.has_line_with("management api http-commands"):
            if not conf_parse.has_line_with("protocol https"):
                issue = CiscoIOSIssue(
                    "Unsecured Management API",
                    "HTTP management API is enabled without HTTPS.",
                    "API credentials can be sniffed.",
                    "High",
                    "Configure 'protocol https' for management api."
                )
                self.add_issue(issue)

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_management_api(parser)
