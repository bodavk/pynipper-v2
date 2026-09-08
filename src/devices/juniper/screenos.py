from typing import Any
from src.devices.common.base_parser import BaseDeviceParser


class JuniperScreenOSParser(BaseDeviceParser):

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        with open(config_filepath, 'r') as f:
            self.config = f.readlines()

    def get_hostname(self) -> str:
        # TODO: Implement ScreenOS hostname extraction
        return "juniper-device"

    def get_version(self) -> str:
        # TODO: Implement ScreenOS version extraction
        return "?"

    def get_users(self) -> list[dict]:
        # TODO: Implement ScreenOS user extraction
        return []

    def get_services(self) -> dict:
        # TODO: Implement ScreenOS service extraction
        return {"telnet": False, "ssh": False, "http": False}

    def get_raw_config(self) -> Any:
        return self.config
