from ..core.base_plugin import ASAPlugin
from src.analyze.common.issue import Finding, Severity
from src.devices.common.base_parser import BaseDeviceParser


class LoggingPlugin(ASAPlugin):

    def get_missing_logging_issue(self, parser: BaseDeviceParser):
        cisco_parser = parser.get_raw_config()
        logging_enable = cisco_parser.find_objects("^logging enable")
        if len(logging_enable) == 0:
            return Finding(
                rule_id="cisco.asa.logging.missing",
                device="ASA",
                title="Missing Logging Configuration",
                observation="System logging is not enabled on the device.",
                impact="Lack of logs makes it difficult to investigate security incidents or troubleshoot issues.",
                exploitability="Without logs, unauthorized access or configuration changes may go undetected.",
                recommendation="Enable system logging. Command: logging enable",
                severity=Severity.LOW,
            )
        return None

    def analyze(self, parser: BaseDeviceParser) -> None:
        issue = self.get_missing_logging_issue(parser)
        if issue:
            self.add_issue(issue)
