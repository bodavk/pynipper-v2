from typing import Any
from src.devices.common.base_parser import BaseDeviceParser

class JunOSParser(BaseDeviceParser):

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        with open(config_filepath, 'r') as f:
            # Assuming 'display set' syntax for simplicity
            self.config = [line.strip() for line in f.readlines()]

    def get_hostname(self) -> str:
        for line in self.config:
            if "set system host-name" in line:
                return line.split(" ", 3)[3]
        return "junos-device"

    def get_version(self) -> str:
        return "?"

    def get_users(self) -> list[dict]:
        return []

    def get_services(self) -> dict:
        services = {"telnet": False, "ssh": False, "http": False}
        for line in self.config:
            if "set system services telnet" in line:
                services["telnet"] = True
            if "set system services ssh" in line:
                services["ssh"] = True
            if "set system services web-management" in line:
                services["http"] = True
        return services

    def get_raw_config(self) -> Any:
        return self.config
