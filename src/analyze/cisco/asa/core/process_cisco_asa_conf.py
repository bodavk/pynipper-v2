from src.devices.common.base_parser import BaseDeviceParser
from .process_asa_conf import process_asa_conf


def process_cisco_asa_conf(parser: BaseDeviceParser) -> dict:
    """Compatibility wrapper for the former second ASA processing path."""

    return process_asa_conf(parser)
