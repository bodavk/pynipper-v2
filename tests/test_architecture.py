import pytest
import os
from src.devices import get_parser
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.cisco.asa import CiscoASAParser
from src.devices.common.base_parser import BaseDeviceParser


def test_get_parser():
    # Verify that get_parser returns CiscoIOSParser for IOS_ROUTER
    config_file = os.path.join("tests", "test_data", "cisco_ios_example.conf")
    parser = get_parser("IOS_ROUTER", config_file)
    assert isinstance(parser, BaseDeviceParser)
    assert isinstance(parser, CiscoIOSParser)


def test_cisco_ios_parser_details():
    config_file = os.path.join("tests", "test_data", "cisco_ios_example.conf")
    parser = get_parser("IOS_ROUTER", config_file)
    
    # Verify hostname extraction
    assert parser.get_hostname() == "retail"
    
    # Verify version extraction
    assert parser.get_version() == "12.3(1)"
    
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
