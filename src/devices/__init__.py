from typing import Any
from .common.types import DeviceType
from .common.base_parser import BaseDeviceParser
from .cisco.ios import CiscoIOSParser
from .cisco.asa import CiscoASAParser
from .checkpoint.fw1 import CheckPointFW1Parser
from .juniper.screenos import JuniperScreenOSParser


def get_parser(device_type: Any, config_filepath: str) -> BaseDeviceParser:
    """Factory function to get the appropriate parser based on device type."""
    dt_str = str(device_type).upper()

    if "ASA" in dt_str:
        return CiscoASAParser(config_filepath)
    elif "CHECKPOINT" in dt_str:
        return CheckPointFW1Parser(config_filepath)
    elif "SCREENOS" in dt_str:
        return JuniperScreenOSParser(config_filepath)
    elif "IOS_SWITCH" in dt_str or "IOS_ROUTER" in dt_str or "IOS_CATALYST" in dt_str:
        return CiscoIOSParser(config_filepath)

    # In the future, other platforms (FortiOS, etc.) will be registered here.
    raise ValueError(f"Unsupported device type: {device_type}")
