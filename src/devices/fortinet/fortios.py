from typing import Any
from src.devices.common.base_parser import BaseDeviceParser

class FortiOSParser(BaseDeviceParser):

    def __init__(self, config_filepath: str):
        super().__init__(config_filepath)
        self.config = self._parse_config(config_filepath)

    def _parse_config(self, filepath: str) -> dict:
        config = {}
        path = []
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith("config"):
                    path.append(line.split(" ", 1)[1])
                elif line.startswith("edit"):
                    path.append(line.split(" ", 1)[1])
                elif line == "next":
                    path.pop()
                elif line == "end":
                    path.pop()
                elif line.startswith("set"):
                    parts = line.split(" ", 2)
                    key = parts[1]
                    value = parts[2] if len(parts) > 2 else ""
                    
                    d = config
                    for b in path:
                        d = d.setdefault(b, {})
                    d[key] = value
        return config

    def get_hostname(self) -> str:
        return self.config.get("system global", {}).get("hostname", "fortigate-device")

    def get_version(self) -> str:
        return "?"

    def get_users(self) -> list[dict]:
        return []

    def get_services(self) -> dict:
        admin = self.config.get("system admin", {})
        return {
            "http": admin.get("http-access", "disable") == "enable",
            "telnet": admin.get("telnet-access", "disable") == "enable"
        }

    def get_raw_config(self) -> Any:
        return self.config
