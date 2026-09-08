import os
from typing import Any
from src.devices.common.base_parser import BaseDeviceParser
from .parser import CheckPointFileParser


class CheckPointFW1Parser(BaseDeviceParser):

    def __init__(self, config_directory: str):
        super().__init__(config_directory)
        if not os.path.isdir(config_directory):
            raise ValueError(f"CheckPoint configuration source must be a directory: {config_directory}")
        
        self.config_directory = config_directory
        self.files = self._locate_files()
        self.parsed_data = self._parse_files()

    def _locate_files(self) -> dict:
        """Locates CheckPoint database files in the provided directory."""
        files = {
            "objects": None,
            "rules": None,
            "rulebases": None
        }
        
        # Look for object files
        for obj_file in ["objects_5_0.C", "objects.C_41", "objects.C"]:
            path = os.path.join(self.config_directory, obj_file)
            if os.path.exists(path):
                files["objects"] = path
                break
        
        # Look for rule files
        for rule_file in ["rules.C"]:
            path = os.path.join(self.config_directory, rule_file)
            if os.path.exists(path):
                files["rules"] = path
                break

        # Look for rulebases
        for rb_file in ["rulebases_5_0.fws", "rulebases.fws"]:
            path = os.path.join(self.config_directory, rb_file)
            if os.path.exists(path):
                files["rulebases"] = path
                break
                
        return files

    def _parse_files(self) -> dict:
        """Parses all located CheckPoint files."""
        data = {}
        for key, path in self.files.items():
            if path:
                parser = CheckPointFileParser(path)
                data[key] = parser.parse()
        return data

    def get_hostname(self) -> str:
        # Simplistic extraction
        return "checkpoint-device"

    def get_version(self) -> str:
        # Simplistic extraction
        return "unknown"

    def get_users(self) -> list[dict]:
        # Simplistic extraction - CheckPoint stores users differently
        return []

    def get_services(self) -> dict:
        # Simplistic extraction
        return {"telnet": False, "ssh": False, "http": False}

    def get_raw_config(self) -> Any:
        return self.parsed_data
