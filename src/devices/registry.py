"""Authoritative registry for supported device families.

The registry deliberately stores import paths instead of importing parsers and
analyzers eagerly.  Analyzer modules call back into :mod:`src.devices` to obtain
their parser, so lazy loading keeps that public API without creating an import
cycle.
"""

from dataclasses import dataclass
from enum import Enum
from importlib import import_module
from typing import Callable, Dict, Iterable, Tuple, Type

from .common.base_parser import BaseDeviceParser


@dataclass(frozen=True)
class DeviceDefinition:
    canonical_id: str
    legacy_value: int
    aliases: Tuple[str, ...]
    parser_path: str
    analyzer_path: str
    display_name: str

    def load_parser_class(self) -> Type[BaseDeviceParser]:
        parser_class = _load_symbol(self.parser_path)
        if not isinstance(parser_class, type) or not issubclass(parser_class, BaseDeviceParser):
            raise TypeError(
                f"Registered parser for {self.canonical_id} is not a BaseDeviceParser subclass"
            )
        return parser_class

    def load_analyzer(self) -> Callable[..., None]:
        analyzer = _load_symbol(self.analyzer_path)
        if not callable(analyzer):
            raise TypeError(f"Registered analyzer for {self.canonical_id} is not callable")
        return analyzer


def _load_symbol(path: str):
    module_name, symbol_name = path.split(":", 1)
    return getattr(import_module(module_name), symbol_name)


_DEVICE_DEFINITIONS: Tuple[DeviceDefinition, ...] = (
    DeviceDefinition(
        "IOS_SWITCH", 1, ("CISCO_IOS_SWITCH",),
        "src.devices.cisco.ios:CiscoIOSParser",
        "src.analyze.cisco.ios.analyze_cisco_device:analyze_cisco_device",
        "Cisco IOS switch",
    ),
    DeviceDefinition(
        "IOS_ROUTER", 2, ("IOS", "CISCO_IOS", "CISCO_IOS_ROUTER"),
        "src.devices.cisco.ios:CiscoIOSParser",
        "src.analyze.cisco.ios.analyze_cisco_device:analyze_cisco_device",
        "Cisco IOS router",
    ),
    DeviceDefinition(
        "IOS_CATALYST", 3, ("CISCO_IOS_CATALYST",),
        "src.devices.cisco.ios:CiscoIOSParser",
        "src.analyze.cisco.ios.analyze_cisco_device:analyze_cisco_device",
        "Cisco IOS Catalyst",
    ),
    DeviceDefinition(
        "PIX", 4, ("CISCO_PIX",),
        "src.devices.cisco.asa:CiscoASAParser",
        "src.analyze.cisco.asa.analyze_asa_device:analyze_asa_device",
        "Cisco PIX firewall",
    ),
    DeviceDefinition(
        "ASA", 5, ("CISCO_ASA",),
        "src.devices.cisco.asa:CiscoASAParser",
        "src.analyze.cisco.asa.analyze_asa_device:analyze_asa_device",
        "Cisco ASA firewall",
    ),
    DeviceDefinition(
        "SCREENOS", 10, ("JUNIPER_SCREENOS", "NETSCREEN"),
        "src.devices.juniper.screenos:JuniperScreenOSParser",
        "src.analyze.juniper.analyze_juniper_device:analyze_juniper_device",
        "Juniper ScreenOS",
    ),
    DeviceDefinition(
        "SONICOS", 12, ("SONICWALL", "SONICWALL_SONICOS"),
        "src.devices.sonicwall.sonicos:SonicOSParser",
        "src.analyze.sonicwall.analyze_sonicwall_device:analyze_sonicwall_device",
        "SonicWall SonicOS",
    ),
    DeviceDefinition(
        "CHECKPOINT_FW1", 13, ("CHECKPOINT", "FW1", "CHECK_POINT_FW1"),
        "src.devices.checkpoint.fw1:CheckPointFW1Parser",
        "src.analyze.checkpoint.analyze_checkpoint_fw1_device:analyze_checkpoint_fw1_device",
        "Check Point Firewall-1",
    ),
    DeviceDefinition(
        "HP_PROCURVE", 14, ("PROCURVE", "ARUBAOS_SWITCH"),
        "src.devices.hp.procurve:HPProCurveParser",
        "src.analyze.hp.analyze_hp_device:analyze_hp_device",
        "HP ProCurve / ArubaOS-Switch",
    ),
    DeviceDefinition(
        "PAN_OS", 15, ("PANOS", "PALO_ALTO", "PALOALTO_PANOS"),
        "src.devices.paloalto.panos:PaloAltoPANOSParser",
        "src.analyze.paloalto.analyze_panos_device:analyze_panos_device",
        "Palo Alto PAN-OS",
    ),
    DeviceDefinition(
        "FORTIOS", 16, ("FORTIGATE", "FORTINET_FORTIOS"),
        "src.devices.fortinet.fortios:FortiOSParser",
        "src.analyze.fortinet.analyze_fortinet_device:analyze_fortinet_device",
        "Fortinet FortiOS",
    ),
    DeviceDefinition(
        "IOS_XE", 17, ("IOSXE", "CISCO_IOS_XE"),
        "src.devices.cisco.iosxe:CiscoIOSXEParser",
        "src.analyze.cisco.iosxe.analyze_iosxe_device:analyze_iosxe_device",
        "Cisco IOS-XE",
    ),
    DeviceDefinition(
        "JUNOS", 18, ("JUNIPER_JUNOS",),
        "src.devices.juniper.junos:JunOSParser",
        "src.analyze.juniper.junos.analyze_junos_device:analyze_junos_device",
        "Juniper Junos",
    ),
    DeviceDefinition(
        "ARISTA_EOS", 19, ("ARISTA", "EOS"),
        "src.devices.arista.eos:AristaEOSParser",
        "src.analyze.arista.analyze_arista_device:analyze_arista_device",
        "Arista EOS",
    ),
)


DeviceType = Enum(
    "DeviceType",
    {definition.canonical_id: definition.legacy_value for definition in _DEVICE_DEFINITIONS},
)

DEVICE_REGISTRY: Dict[str, DeviceDefinition] = {
    definition.canonical_id: definition for definition in _DEVICE_DEFINITIONS
}


def _normalize_device_id(device: object) -> str:
    if isinstance(device, DeviceType):
        return device.name

    value = str(device).strip().upper().replace("-", "_").replace(" ", "_")
    if value.startswith("DEVICETYPE."):
        value = value.split(".", 1)[1]
    return value


def _build_alias_index(definitions: Iterable[DeviceDefinition]) -> Dict[str, DeviceDefinition]:
    aliases: Dict[str, DeviceDefinition] = {}
    for definition in definitions:
        for raw_alias in (definition.canonical_id,) + definition.aliases:
            alias = _normalize_device_id(raw_alias)
            existing = aliases.get(alias)
            if existing is not None and existing != definition:
                raise ValueError(
                    f"Duplicate device alias {alias!r}: "
                    f"{existing.canonical_id} and {definition.canonical_id}"
                )
            aliases[alias] = definition
    return aliases


_DEVICE_ALIASES = _build_alias_index(_DEVICE_DEFINITIONS)


def get_device_definition(device: object) -> DeviceDefinition:
    """Resolve a canonical ID, alias, or ``DeviceType`` to its definition."""

    normalized = _normalize_device_id(device)
    try:
        return _DEVICE_ALIASES[normalized]
    except KeyError as exc:
        supported = ", ".join(DEVICE_REGISTRY)
        raise ValueError(
            f"Unsupported device type: {device}. Supported device types: {supported}"
        ) from exc


def get_device_choices(include_aliases: bool = True) -> Tuple[str, ...]:
    """Return device IDs accepted by the CLI in stable registry order."""

    choices = []
    for definition in _DEVICE_DEFINITIONS:
        choices.append(definition.canonical_id)
        if include_aliases:
            choices.extend(definition.aliases)
    return tuple(choices)


def validate_device_registry() -> None:
    """Fail fast when enum and registry entries drift apart."""

    enum_names = {member.name for member in DeviceType}
    registry_names = set(DEVICE_REGISTRY)
    if enum_names != registry_names:
        missing = sorted(enum_names - registry_names)
        extra = sorted(registry_names - enum_names)
        raise ValueError(f"Device registry mismatch: missing={missing}, extra={extra}")


validate_device_registry()
