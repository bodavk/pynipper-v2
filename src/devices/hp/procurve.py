from typing import Any
from src.devices.common.base_parser import BaseDeviceParser

class HPProCurveParser(BaseDeviceParser):

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        with open(config_filepath, 'r') as f:
            self.config = [line.strip() for line in f.readlines()]

    def get_hostname(self) -> str:
        for line in self.config:
            if line.startswith("hostname"):
                return line.split(" ", 1)[1].replace('"', '')
        return "hp-procurve-device"

    def get_version(self) -> str:
        return "?"

    def get_users(self) -> list[dict]:
        users = []
        for line in self.config:
            if line.startswith("password manager"):
                users.append({"raw_line": line})
        return users

    def get_services(self) -> dict:
        services = {"telnet": True, "ssh": False, "http": False}
        for line in self.config:
            if "no telnet-server" in line:
                services["telnet"] = False
            if "ip ssh" in line:
                services["ssh"] = True
            if "web-management" in line and "enable" in line:
                services["http"] = True
        return services

    def get_raw_config(self) -> Any:
        return self.config
