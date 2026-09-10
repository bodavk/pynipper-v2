from typing import Any

from .common.base_parser import BaseDeviceParser
from .registry import (
    DEVICE_REGISTRY,
    DeviceDefinition,
    DeviceType,
    get_device_choices,
    get_device_definition,
)


def get_parser(device_type: Any, config_filepath: str) -> BaseDeviceParser:
    """Factory function to get the appropriate parser based on device type."""
    definition = get_device_definition(device_type)
    parser = definition.load_parser_class()(config_filepath)
    parser.device_type = definition.canonical_id
    return parser


__all__ = [
    "BaseDeviceParser",
    "DEVICE_REGISTRY",
    "DeviceDefinition",
    "DeviceType",
    "get_device_choices",
    "get_device_definition",
    "get_parser",
]
