import pytest
import os
from src.devices import get_parser
from src.analyze.fortinet.plugins.fortios_checks_plugin import PluginFortiOSChecks
from src.devices.fortinet.fortios import FortiOSParser

def test_plugin_fortios_checks():
    # Create a dummy config file
    config_path = os.path.join("tests", "test_data", "fortios_test.conf")
    with open(config_path, "w") as f:
        f.write("config system global\n")
        f.write("set hostname fortigate\n")
        f.write("end\n")
        f.write("config system admin\n")
        f.write("set http-access enable\n")
        f.write("end\n")
    
    parser = get_parser("FORTIOS", config_path)
    assert isinstance(parser, FortiOSParser)
    
    plugin = PluginFortiOSChecks()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    assert len(issues) == 1
    assert any("Weak Administrative Access" in issue.title for issue in issues)
    
    # Cleanup
    os.remove(config_path)
