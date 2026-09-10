from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser


class PluginHPChecks(BasePlugin):

    def __init__(self):
        super().__init__()

    # HP-01: Telnet Enabled
    def check_telnet(self, parser: BaseDeviceParser) -> None:
        services = parser.get_services()
        if services.get("telnet", True):
            issue = Finding(
                rule_id="hp.procurve.management.telnet",
                device="HP_PROCURVE",
                title="Telnet Enabled",
                observation="Telnet is enabled, which is insecure.",
                impact="Credentials can be sniffed.",
                severity=Severity.HIGH,
                recommendation="Disable Telnet: 'no telnet-server'",
            )
            self.add_issue(issue)

    # HP-02: SNMP Default Communities
    def check_snmp_communities(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        for line in config:
            if "snmp-server community public" in line or "snmp-server community private" in line:
                issue = Finding(
                    rule_id="hp.procurve.snmp.default_community",
                    device="HP_PROCURVE",
                    title="Default SNMP Community",
                    observation=f"Default SNMP community string detected: {line}",
                    impact="Information disclosure.",
                    severity=Severity.MEDIUM,
                    recommendation="Change the community string.",
                )
                self.add_issue(issue)

    # HP-03: Insecure Web Management
    def check_web_management(self, parser: BaseDeviceParser) -> None:
        services = parser.get_services()
        if services.get("http", False):
            issue = Finding(
                rule_id="hp.procurve.management.http",
                device="HP_PROCURVE",
                title="Insecure Web Management",
                observation="Clear-text web management is enabled.",
                impact="Credentials can be sniffed.",
                severity=Severity.HIGH,
                recommendation="Disable http: 'no web-management'",
            )
            self.add_issue(issue)

    # HP-04: Lack of SSH Key Exchange Hardening
    def check_ssh_hardening(self, parser: BaseDeviceParser) -> None:
        config = parser.get_raw_config()
        # Simplistic check
        if not any("ip ssh key-exchange" in line for line in config):
            issue = Finding(
                rule_id="hp.procurve.ssh.key_exchange",
                device="HP_PROCURVE",
                title="SSH Key Exchange Not Hardened",
                observation="SSH key exchange settings are not explicitly hardened.",
                impact="Weak SSH configuration.",
                severity=Severity.MEDIUM,
                recommendation="Configure hardened SSH key exchange settings.",
            )
            self.add_issue(issue)

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_telnet(parser)
        self.check_snmp_communities(parser)
        self.check_web_management(parser)
        self.check_ssh_hardening(parser)
