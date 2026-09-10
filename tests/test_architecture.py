import pytest
import os
from src.devices import DEVICE_REGISTRY, DeviceType, get_device_choices, get_device_definition, get_parser
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.cisco.asa import CiscoASAParser
from src.devices.cisco.iosxe import CiscoIOSXEParser
from src.devices.checkpoint.fw1 import CheckPointFW1Parser
from src.devices.juniper.screenos import JuniperScreenOSParser
from src.devices.juniper.junos import JunOSParser
from src.devices.fortinet.fortios import FortiOSParser
from src.devices.sonicwall.sonicos import SonicOSParser
from src.devices.hp.procurve import HPProCurveParser
from src.devices.paloalto.panos import PaloAltoPANOSParser
from src.devices.arista.eos import AristaEOSParser
from src.devices.common.base_parser import BaseDeviceParser
from src import main as main_module


EXPECTED_PARSERS = {
    "IOS_SWITCH": CiscoIOSParser,
    "IOS_ROUTER": CiscoIOSParser,
    "IOS_CATALYST": CiscoIOSParser,
    "PIX": CiscoASAParser,
    "ASA": CiscoASAParser,
    "CHECKPOINT_FW1": CheckPointFW1Parser,
    "SCREENOS": JuniperScreenOSParser,
    "SONICOS": SonicOSParser,
    "HP_PROCURVE": HPProCurveParser,
    "PAN_OS": PaloAltoPANOSParser,
    "FORTIOS": FortiOSParser,
    "IOS_XE": CiscoIOSXEParser,
    "JUNOS": JunOSParser,
    "ARISTA_EOS": AristaEOSParser,
}


EXPECTED_ANALYZERS = {
    "IOS_SWITCH": "analyze_cisco_device",
    "IOS_ROUTER": "analyze_cisco_device",
    "IOS_CATALYST": "analyze_cisco_device",
    "PIX": "analyze_asa_device",
    "ASA": "analyze_asa_device",
    "CHECKPOINT_FW1": "analyze_checkpoint_fw1_device",
    "SCREENOS": "analyze_juniper_device",
    "SONICOS": "analyze_sonicwall_device",
    "HP_PROCURVE": "analyze_hp_device",
    "PAN_OS": "analyze_panos_device",
    "FORTIOS": "analyze_fortinet_device",
    "IOS_XE": "analyze_iosxe_device",
    "JUNOS": "analyze_junos_device",
    "ARISTA_EOS": "analyze_arista_device",
}


def _minimal_config_source(tmp_path, canonical_id):
    if canonical_id == "CHECKPOINT_FW1":
        source = tmp_path / canonical_id.lower()
        source.mkdir()
        return str(source)

    source = tmp_path / f"{canonical_id.lower()}.conf"
    source.write_text("<config />" if canonical_id == "PAN_OS" else "", encoding="utf-8")
    return str(source)


def test_get_parser():
    # Verify that get_parser returns CiscoIOSParser for IOS_ROUTER
    config_file = os.path.join("tests", "test_data", "cisco_ios_example.conf")
    parser = get_parser("IOS_ROUTER", config_file)
    assert isinstance(parser, BaseDeviceParser)
    assert isinstance(parser, CiscoIOSParser)


def test_device_registry_is_complete_and_has_unique_choices():
    assert set(DEVICE_REGISTRY) == {device.name for device in DeviceType}
    choices = get_device_choices(include_aliases=True)
    assert len(choices) == len(set(choices))


@pytest.mark.parametrize("canonical_id", EXPECTED_PARSERS)
def test_every_registered_device_constructs_expected_parser(tmp_path, canonical_id):
    source = _minimal_config_source(tmp_path, canonical_id)
    parser = get_parser(canonical_id, source)

    assert isinstance(parser, BaseDeviceParser)
    assert type(parser) is EXPECTED_PARSERS[canonical_id]


@pytest.mark.parametrize("canonical_id", EXPECTED_ANALYZERS)
def test_every_registered_device_resolves_expected_analyzer(canonical_id):
    analyzer = get_device_definition(canonical_id).load_analyzer()
    assert analyzer.__name__ == EXPECTED_ANALYZERS[canonical_id]


@pytest.mark.parametrize(
    "alias, canonical_id",
    [
        (alias, definition.canonical_id)
        for definition in DEVICE_REGISTRY.values()
        for alias in definition.aliases
    ],
)
def test_every_alias_resolves_to_its_canonical_device(alias, canonical_id):
    assert get_device_definition(alias).canonical_id == canonical_id


@pytest.mark.parametrize("device_choice", get_device_choices(include_aliases=True))
def test_cli_accepts_every_registered_device_choice(monkeypatch, device_choice):
    calls = []
    monkeypatch.setattr(main_module, "display_banner", lambda: None)
    monkeypatch.setattr(main_module, "analyze_device", lambda *args: calls.append(args))

    assert main_module.main(["--device", device_choice, "--input", "unused.conf"]) == 0
    assert calls[0][0] == device_choice


def test_unknown_device_is_rejected_by_factory(tmp_path):
    source = tmp_path / "empty.conf"
    source.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported device type"):
        get_parser("NOT_A_DEVICE", str(source))


def test_cisco_ios_parser_details():
    config_file = os.path.join("tests", "test_data", "cisco_ios_example.conf")
    parser = get_parser("IOS_ROUTER", config_file)
    
    # Verify hostname extraction
    assert parser.get_hostname() == "retail"
    
    # Verify version extraction
    assert parser.get_version() == "12.3"
    
    # Verify service extraction
    services = parser.get_services()
    assert services["http"] is True  # ip http server is enabled in config
    assert services["telnet"] is True  # transport input all includes telnet


def test_cisco_asa_parser_details():
    config_file = os.path.join("tests", "test_data", "cisco_asa_vulnerable.conf")
    parser = get_parser("ASA", config_file)
    assert isinstance(parser, CiscoASAParser)
    
    # Verify hostname extraction
    assert parser.get_hostname() == "asa-vuln"
    
    # Verify version extraction
    assert parser.get_version() == "9.12(4)"
    
    # Verify services
    services = parser.get_services()
    assert services["telnet"] is True
    assert services["ssh"] is True
    assert services["http"] is False
    
    # Verify ASA-specific fields
    assert parser.get_enable_password() == "cisco123"
    assert "public" in parser.get_snmp_communities()
    assert parser.get_logging_enabled() is False
    assert parser.get_ssl_min_version() == "tlsv1"
    
    interfaces = parser.get_interfaces()
    assert len(interfaces) == 2
    assert interfaces[0]["nameif"] == "outside"
    assert interfaces[0]["security_level"] == 0
    assert interfaces[1]["nameif"] == "inside"
    assert interfaces[1]["security_level"] == 100
