from abc import ABC, abstractmethod
from typing import Any


class BaseDeviceParser(ABC):

    def __init__(self, config_filepath: str):
        self.config_filepath = config_filepath

    @abstractmethod
    def get_hostname(self) -> str:
        """Extract and return the hostname of the device."""
        pass

    @abstractmethod
    def get_version(self) -> str:
        """Extract and return the OS/firmware version of the device."""
        pass

    @abstractmethod
    def get_users(self) -> list[dict]:
        """Extract and return the list of local users on the device."""
        pass

    @abstractmethod
    def get_services(self) -> dict:
        """Extract and return configured management services (e.g. ssh, telnet, http)."""
        pass

    @abstractmethod
    def get_raw_config(self) -> Any:
        """Return the raw config or native parsing object (e.g. CiscoConfParse, XML Tree, dict)."""
        pass
