from ..core.base_plugin import ASAPlugin
from src.analyze.common.issue import Issue
from src.devices.common.base_parser import BaseDeviceParser


class LoggingPlugin(ASAPlugin):

    def get_missing_logging_issue(self, parser: BaseDeviceParser):
        cisco_parser = parser.get_raw_config()
        logging_enable = cisco_parser.find_objects("^logging enable")
        if len(logging_enable) == 0:
            return Issue(
                "Missing Logging Configuration",
                "System logging is not enabled on the device.",
                "Lack of logs makes it difficult to investigate security incidents or troubleshoot issues.",
                "Without logs, unauthorized access or configuration changes may go undetected.",
                "Enable system logging. Command: logging enable"
            )
        return None

    def analyze(self, parser: BaseDeviceParser) -> None:
        issue = self.get_missing_logging_issue(parser)
        if issue:
            self.add_issue(issue)
