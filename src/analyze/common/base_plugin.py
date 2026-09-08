from abc import ABC, abstractmethod
from src.devices.common.base_parser import BaseDeviceParser


class BasePlugin(ABC):

    def __init__(self):
        self.issues = []  # A list of issues reported by the plugin

    def get_issues(self) -> list:
        return self.issues

    def add_issue(self, issue):
        self.issues.append(issue)

    @abstractmethod
    def analyze(self, parser: BaseDeviceParser) -> None:
        """Analyze the device configuration using the provided parser."""
        pass
