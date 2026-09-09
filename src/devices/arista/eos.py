from typing import Any
from src.devices.cisco.ios import CiscoIOSParser

class AristaEOSParser(CiscoIOSParser):

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        # Inherits parsing capabilities from CiscoIOSParser

    def get_raw_config(self) -> Any:
        return super().get_raw_config()
