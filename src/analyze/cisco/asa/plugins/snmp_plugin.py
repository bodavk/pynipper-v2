from ..core.base_plugin import ASAPlugin
from src.analyze.common.issue import Issue
from src.devices.common.base_parser import BaseDeviceParser


class SNMPPlugin(ASAPlugin):

    def get_insecure_community_issue(self, parser: BaseDeviceParser):
        # We need to cast or use specific methods if they are not in base interface
        # For now, let's assume we can access them if we know it's a CiscoASAParser
        # Or just use get_raw_config()
        cisco_parser = parser.get_raw_config()
        snmp_lines = cisco_parser.find_objects("^snmp-server community")
        for line in snmp_lines:
            if "public" in line.text or "private" in line.text:
                return Issue(
                    "Insecure SNMP Communities",
                    "The SNMP service is configured with common or default community strings (e.g., 'public', 'private').",
                    "Attackers can easily guess these strings to gain information or modify configuration via SNMP.",
                    "Common community strings are widely known and frequently targeted by automated scanners.",
                    "Change SNMP community strings to complex, unique values. Command: snmp-server community <new-string>"
                )
        return None

    def analyze(self, parser: BaseDeviceParser) -> None:
        issue = self.get_insecure_community_issue(parser)
        if issue:
            self.add_issue(issue)
