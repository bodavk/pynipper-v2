from abc import abstractmethod
from ciscoconfparse import CiscoConfParse

from src.analyze.common.base_plugin import BasePlugin
from src.devices.common.base_parser import BaseDeviceParser
from ..issue.cisco_ios_issue import CiscoIOSIssue


class GenericPlugin(BasePlugin):

    def __init__(self):
        super().__init__()

    def parse_cisco_ios_config_file(self, filename: str) -> CiscoConfParse:
        # Provided for backwards compatibility, but preferred way is parser.get_raw_config()
        return CiscoConfParse(filename, syntax='ios')

    # GenericPlugin inherits get_issues, add_issue, and issues list from BasePlugin.

    @abstractmethod
    def analyze(self, parser: BaseDeviceParser) -> None:
        pass
