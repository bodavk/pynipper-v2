from ..core.base_plugin import ASAPlugin
from src.analyze.common.issue import Issue
from src.devices.common.base_parser import BaseDeviceParser


class ManagementPlugin(ASAPlugin):

    def get_telnet_issue(self, parser: BaseDeviceParser):
        services = parser.get_services()
        if services.get("telnet", False):
            return Issue(
                "Telnet Enabled",
                "The Telnet service is enabled on the device. Telnet is a clear-text protocol and is vulnerable to packet-capture techniques.",
                "An attacker could capture authentication credentials monitoring network traffic.",
                "It is trivial to use captured credentials to log in.",
                "Disable Telnet and use SSH instead. Command: no telnet <network> <mask> <interface>"
            )
        return None

    def get_ssh_access_issue(self, parser: BaseDeviceParser):
        cisco_parser = parser.get_raw_config()
        ssh_lines = cisco_parser.find_objects("^ssh")
        for line in ssh_lines:
            if "0.0.0.0 0.0.0.0" in line.text:
                return Issue(
                    "Unrestricted SSH Access",
                    "SSH access is allowed from any IP address (0.0.0.0).",
                    "Increases the risk of brute-force attacks from unauthorized hosts.",
                    "Attackers can attempt to guess passwords from any network location.",
                    "Restrict SSH access to specific management networks. Command: ssh <management-network> <mask> <interface>"
                )
        return None

    def analyze(self, parser: BaseDeviceParser) -> None:
        telnet_issue = self.get_telnet_issue(parser)
        if telnet_issue:
            self.add_issue(telnet_issue)
            
        ssh_issue = self.get_ssh_access_issue(parser)
        if ssh_issue:
            self.add_issue(ssh_issue)
