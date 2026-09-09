import pytest
import os
from src.devices import get_parser
from src.analyze.juniper.junos.plugins.junos_checks_plugin import PluginJunOSChecks
from src.devices.juniper.junos import JunOSParser

def test_plugin_junos_checks():
    # Create a dummy config file
    config_path = os.path.join("tests", "test_data", "junos_test.conf")
    with open(config_path, "w") as f:
        f.write("set system host-name juniper\n")
        f.write("set system services telnet\n")
    
    parser = get_parser("JUNOS", config_path)
    assert isinstance(parser, JunOSParser)
    
    plugin = PluginJunOSChecks()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    assert len(issues) == 1
    assert any("Insecure Management Service Enabled" in issue.title for issue in issues)
    
    # Cleanup
    os.remove(config_path)
