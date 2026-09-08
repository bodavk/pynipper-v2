from src.analyze.common.base_plugin import BasePlugin
from src.analyze.cisco.ios.issue.cisco_ios_issue import CiscoIOSIssue
from src.devices.common.base_parser import BaseDeviceParser


class PluginCheckPointChecks(BasePlugin):

    def __init__(self):
        super().__init__()

    def _find_in_dict(self, data, target_value):
        """Recursively find if a target_value exists in the nested dict."""
        if isinstance(data, dict):
            for value in data.values():
                if self._find_in_dict(value, target_value):
                    return True
        elif data == target_value:
            return True
        return False

    # CP-01: Insecure Object Definitions
    def check_insecure_objects(self, parser: BaseDeviceParser) -> None:
        data = parser.get_raw_config()
        # Look for 'any' in network objects
        if self._find_in_dict(data.get('objects', {}), 'any'):
            issue = CiscoIOSIssue(
                "Insecure Object Definition",
                "Found an object definition using 'any', which is overly permissive.",
                "Allows traffic from any source/to any destination, violating the principle of least privilege.",
                "High — Increases attack surface.",
                "Restrict object definitions to specific IP ranges or subnets."
            )
            self.add_issue(issue)

    # CP-02: Broad Filter Rules
    def check_broad_filter_rules(self, parser: BaseDeviceParser) -> None:
        data = parser.get_raw_config()
        # Look for 'accept' rules combined with 'any'
        # This is a rudimentary check given the parser structure
        if self._find_in_dict(data.get('rules', {}), 'accept') and \
           self._find_in_dict(data.get('rules', {}), 'any'):
            issue = CiscoIOSIssue(
                "Broad Filter Rule Detected",
                "Found a filter rule with 'accept' action and 'any' object.",
                "Allows unrestricted traffic through the firewall.",
                "Critical — Allows immediate access/attack vector.",
                "Restrict the filter rule to specific source/destination objects."
            )
            self.add_issue(issue)

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_insecure_objects(parser)
        self.check_broad_filter_rules(parser)
