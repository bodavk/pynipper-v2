from abc import ABC, abstractmethod

from .models import NormalizedConfig


class BaseDeviceParser(ABC):

    device_type = "UNKNOWN"

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
    def get_native_config(self) -> object:
        """Return the vendor-native parsing object for vendor-specific plugins."""
        pass

    def get_raw_config(self) -> object:
        """Compatibility alias for :meth:`get_native_config`.

        New common logic must consume :meth:`get_normalized_config`. Vendor-
        specific rules may use ``get_native_config`` when the normalized model
        does not yet expose a required construct.
        """

        return self.get_native_config()

    def get_normalized_config(self) -> NormalizedConfig:
        """Return a complete normalized snapshot with explicit unknown state.

        Vendor parsers override this method as their normalized implementations
        are completed. Returning an explicit unknown snapshot is safer than
        converting legacy empty collections or ``False`` placeholders into
        assertions about effective configuration.
        """

        return NormalizedConfig.unknown(self.device_type)
