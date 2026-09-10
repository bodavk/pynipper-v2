from src.analyze.common.base_plugin import BasePlugin
from src.analyze.common.issue import Finding, Severity
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
                issue = Finding(
                    rule_id="arista.eos.eapi.insecure_http",
                    device="ARISTA_EOS",
                    title="Unsecured Management API",
                    observation="HTTP management API is enabled without HTTPS.",
                    impact="API credentials can be sniffed.",
                    severity=Severity.HIGH,
                    recommendation="Configure 'protocol https' for management api.",
                )
                self.add_issue(issue)

    def analyze(self, parser: BaseDeviceParser) -> None:
        self.check_management_api(parser)
