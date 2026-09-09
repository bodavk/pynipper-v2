import xml.etree.ElementTree as ET
from typing import Any
from src.devices.common.base_parser import BaseDeviceParser

class PaloAltoPANOSParser(BaseDeviceParser):

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        self.tree = ET.parse(config_filepath)
        self.root = self.tree.getroot()

    def get_hostname(self) -> str:
        # /config/devices/entry/system/hostname
        node = self.root.find(".//system/hostname")
        if node is not None:
            return node.text
        return "panos-device"

    def get_version(self) -> str:
        # Extract version if needed
        return "?"

    def get_users(self) -> list[dict]:
        # Placeholder
        return []

    def get_services(self) -> dict:
        # Check management profile for services
        return {"telnet": False, "ssh": False, "http": False}

    def get_raw_config(self) -> Any:
        return self.root
