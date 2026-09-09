import pytest
import os
from src.devices import get_parser
from src.analyze.cisco.iosxe.plugins.iosxe_checks_plugin import PluginIOSXEChecks
from src.devices.cisco.iosxe import CiscoIOSXEParser

def test_plugin_iosxe_checks_full():
    # Create a dummy config file triggering all checks
    # CiscoConfParse requires correct indentation for children
    config_path = os.path.join("tests", "test_data", "iosxe_test_full.conf")
    with open(config_path, "w") as f:
        f.write("interface GigabitEthernet1\n")
        f.write("crypto ikev2 proposal prop1\n")
        f.write(" encryption 3des\n")
    
    parser = get_parser("IOS_XE", config_path)
    assert isinstance(parser, CiscoIOSXEParser)
    
    plugin = PluginIOSXEChecks()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    # XE-01: Lack of MACsec
    # XE-02: Legacy Crypto
    assert len(issues) == 2
    assert any("Lack of MACsec" in issue.title for issue in issues)
    assert any("Legacy Crypto Ciphers" in issue.title for issue in issues)
    
    # Cleanup
    os.remove(config_path)
