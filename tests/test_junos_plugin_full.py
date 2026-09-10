import pytest
import os
from src.devices import get_parser
from src.analyze.juniper.junos.plugins.junos_checks_plugin import PluginJunOSChecks
from src.devices.juniper.junos import JunOSParser

def test_plugin_junos_checks_full():
    # Create a dummy config file triggering all checks
    config_path = os.path.join("tests", "test_data", "junos_test_full.conf")
    with open(config_path, "w") as f:
        f.write("set system host-name juniper\n")
        f.write("set system services telnet\n")
        f.write("set system services ssh root-login allow\n")
        f.write("set firewall filter test term 1 from source-address 0.0.0.0/0\n")
        f.write("set firewall filter test term 1 then accept\n")
        f.write("set interfaces ge-0/0/0 unit 0 family inet filter input test\n")
    
    parser = get_parser("JUNOS", config_path)
    assert isinstance(parser, JunOSParser)
    
    plugin = PluginJunOSChecks()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    # JUN-01: Insecure management
    # JUN-02: Broad filter
    # JUN-03: SSH root login
    assert len(issues) == 3
    assert any("Insecure Management Service Enabled" in issue.title for issue in issues)
    assert any("Broad Firewall Filter" in issue.title for issue in issues)
    assert any("SSH Root Login Permitted" in issue.title for issue in issues)
    
    # Cleanup
    os.remove(config_path)
