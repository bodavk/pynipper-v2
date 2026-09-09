from typing import Any
from src.devices.cisco.ios import CiscoIOSParser

class CiscoIOSXEParser(CiscoIOSParser):

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        # Inherits parsing capabilities from CiscoIOSParser
        
    def get_version(self) -> str:
        # IOS-XE might report version differently, but for now reuse
        return super().get_version()

    def get_raw_config(self) -> Any:
        return super().get_raw_config()
