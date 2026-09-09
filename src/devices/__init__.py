from typing import Any
from .common.types import DeviceType
from .common.base_parser import BaseDeviceParser
from .cisco.ios import CiscoIOSParser
from .cisco.asa import CiscoASAParser
from .checkpoint.fw1 import CheckPointFW1Parser
from .juniper.screenos import JuniperScreenOSParser
from .sonicwall.sonicos import SonicOSParser
from .hp.procurve import HPProCurveParser
from .paloalto.panos import PaloAltoPANOSParser
from .fortinet.fortios import FortiOSParser
from .cisco.iosxe import CiscoIOSXEParser
from .juniper.junos import JunOSParser
from .arista.eos import AristaEOSParser


def get_parser(device_type: Any, config_filepath: str) -> BaseDeviceParser:
    """Factory function to get the appropriate parser based on device type."""
    dt_str = str(device_type).upper()

    if "ASA" in dt_str:
        return CiscoASAParser(config_filepath)
    elif "CHECKPOINT" in dt_str:
        return CheckPointFW1Parser(config_filepath)
    elif "SCREENOS" in dt_str:
        return JuniperScreenOSParser(config_filepath)
    elif "SONICOS" in dt_str:
        return SonicOSParser(config_filepath)
    elif "HP_PROCURVE" in dt_str:
        return HPProCurveParser(config_filepath)
    elif "PAN_OS" in dt_str:
        return PaloAltoPANOSParser(config_filepath)
    elif "FORTIOS" in dt_str:
        return FortiOSParser(config_filepath)
    elif "IOS_XE" in dt_str:
        return CiscoIOSXEParser(config_filepath)
    elif "JUNOS" in dt_str:
        return JunOSParser(config_filepath)
    elif "ARISTA_EOS" in dt_str:
        return AristaEOSParser(config_filepath)
    elif "IOS_SWITCH" in dt_str or "IOS_ROUTER" in dt_str or "IOS_CATALYST" in dt_str:
        return CiscoIOSParser(config_filepath)

    # In the future, other platforms (FortiOS, etc.) will be registered here.
    raise ValueError(f"Unsupported device type: {device_type}")
