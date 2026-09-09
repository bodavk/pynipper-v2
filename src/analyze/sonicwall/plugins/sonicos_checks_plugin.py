from src.analyze.common.base_plugin import BasePlugin
from src.analyze.cisco.ios.issue.cisco_ios_issue import CiscoIOSIssue
from src.devices.common.base_parser import BaseDeviceParser


class PluginSonicOSChecks(BasePlugin):

    def __init__(self):
        super().__init__()

    # SW-01: HTTP Management Enabled
    def check_http_management(self, parser: BaseDeviceParser) -> None:
        services = parser.get_services()
        if services.get("http", False):
            issue = CiscoIOSIssue(
                "HTTP Management Enabled",
                "The HTTP management service is enabled on the device. This protocol is insecure and transmits credentials in cleartext.",
                "An attacker on the network can intercept administrative credentials.",
                "High — Trivial to sniff.",
                "Disable HTTP management: 'no set service http enable'"
            )
            self.add_issue(issue)

    # SW-02: Default Admin Credentials
    def check_default_admin(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        for line in config:
            if "set admin password" in line and "password" in line:
                issue = CiscoIOSIssue(
                    "Potential Default Admin Password",
                    "Detected configuration line that may use default password.",
                    "Device is highly vulnerable to brute-force.",
                    "Critical — Immediate exploit path.",
                    "Change the administrator password to a secure value."
                )
                self.add_issue(issue)
                break

    # SW-03: Weak Encryption for VPNs
    def check_weak_vpn_encryption(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        for line in config:
            if "set vpn encryption" in line and ("des" in line or "3des" in line):
                issue = CiscoIOSIssue(
                    "Weak VPN Encryption",
                    f"Detected insecure VPN encryption: {line}",
                    "VPN traffic can be decrypted by attackers.",
                    "Medium — Requires traffic interception.",
                    "Use strong encryption like AES-256."
                )
                self.add_issue(issue)

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_http_management(parser)
        self.check_default_admin(parser)
        self.check_weak_vpn_encryption(parser)
