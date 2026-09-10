from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser


class PluginSonicOSChecks(BasePlugin):

    def __init__(self):
        super().__init__()

    # SW-01: HTTP Management Enabled
    def check_http_management(self, parser: BaseDeviceParser) -> None:
        services = parser.get_services()
        if services.get("http", False):
            issue = Finding(
                rule_id="sonicwall.sonicos.management.http",
                device="SONICOS",
                title="HTTP Management Enabled",
                observation="The HTTP management service is enabled on the device. This protocol is insecure and transmits credentials in cleartext.",
                impact="An attacker on the network can intercept administrative credentials.",
                severity=Severity.HIGH,
                exploitability="Trivial to sniff.",
                recommendation="Disable HTTP management: 'no set service http enable'",
            )
            self.add_issue(issue)

    # SW-02: Default Admin Credentials
    def check_default_admin(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        for line in config:
            if "set admin password" in line and "password" in line:
                issue = Finding(
                    rule_id="sonicwall.sonicos.credentials.default_admin",
                    device="SONICOS",
                    title="Potential Default Admin Password",
                    observation="Detected configuration line that may use default password.",
                    impact="Device is highly vulnerable to brute-force.",
                    severity=Severity.CRITICAL,
                    exploitability="Immediate exploit path.",
                    recommendation="Change the administrator password to a secure value.",
                )
                self.add_issue(issue)
                break

    # SW-03: Weak Encryption for VPNs
    def check_weak_vpn_encryption(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        for line in config:
            if "set vpn encryption" in line and ("des" in line or "3des" in line):
                issue = Finding(
                    rule_id="sonicwall.sonicos.vpn.weak_encryption",
                    device="SONICOS",
                    title="Weak VPN Encryption",
                    observation=f"Detected insecure VPN encryption: {line}",
                    impact="VPN traffic can be decrypted by attackers.",
                    severity=Severity.MEDIUM,
                    exploitability="Requires traffic interception.",
                    recommendation="Use strong encryption like AES-256.",
                )
                self.add_issue(issue)

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_http_management(parser)
        self.check_default_admin(parser)
        self.check_weak_vpn_encryption(parser)
