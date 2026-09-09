from typing import Any
from src.devices.common.base_parser import BaseDeviceParser

class SonicOSParser(BaseDeviceParser):

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        with open(config_filepath, 'r') as f:
            self.config = [line.strip() for line in f.readlines()]

    def get_hostname(self) -> str:
        for line in self.config:
            if line.startswith("set hostname"):
                return line.split(" ", 2)[2]
        return "sonicwall-device"

    def get_version(self) -> str:
        return "?"

    def get_users(self) -> list[dict]:
        return []

    def get_services(self) -> dict:
        services = {"telnet": False, "ssh": False, "http": False}
        for line in self.config:
            if "set service telnet" in line and "enable" in line:
                services["telnet"] = True
            if "set service ssh" in line and "enable" in line:
                services["ssh"] = True
            if "set service http" in line and "enable" in line:
                services["http"] = True
        return services

    def get_raw_config(self) -> Any:
        return self.config
