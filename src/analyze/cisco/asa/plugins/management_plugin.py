from ..core.base_plugin import ASAPlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser


class ManagementPlugin(ASAPlugin):

    def get_telnet_issue(self, parser: BaseDeviceParser):
        services = parser.get_services()
        if services.get("telnet", False):
            return Finding(
                rule_id="cisco.asa.management.telnet",
                device="ASA",
                title="Telnet Enabled",
                observation="The Telnet service is enabled on the device. Telnet is a clear-text protocol and is vulnerable to packet-capture techniques.",
                impact="An attacker could capture authentication credentials monitoring network traffic.",
                exploitability="It is trivial to use captured credentials to log in.",
                recommendation="Disable Telnet and use SSH instead. Command: no telnet <network> <mask> <interface>",
                severity=Severity.HIGH,
            )
        return None

    def get_ssh_access_issue(self, parser: BaseDeviceParser):
        cisco_parser = parser.get_raw_config()
        ssh_lines = cisco_parser.find_objects("^ssh")
        for line in ssh_lines:
            if "0.0.0.0 0.0.0.0" in line.text:
                return Finding(
                    rule_id="cisco.asa.management.unrestricted_ssh",
                    device="ASA",
                    title="Unrestricted SSH Access",
                    observation="SSH access is allowed from any IP address (0.0.0.0).",
                    impact="Increases the risk of brute-force attacks from unauthorized hosts.",
                    exploitability="Attackers can attempt to guess passwords from any network location.",
                    recommendation="Restrict SSH access to specific management networks. Command: ssh <management-network> <mask> <interface>",
                    severity=Severity.MEDIUM,
                )
        return None

    def analyze(self, parser: BaseDeviceParser) -> None:
        telnet_issue = self.get_telnet_issue(parser)
        if telnet_issue:
            self.add_issue(telnet_issue)
            
        ssh_issue = self.get_ssh_access_issue(parser)
        if ssh_issue:
            self.add_issue(ssh_issue)
