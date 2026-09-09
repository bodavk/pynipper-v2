import pytest
import os
from src.devices import get_parser
from src.analyze.cisco.asa.plugins.asa_checks_plugin import PluginASAChecks
from src.devices.cisco.asa import CiscoASAParser

def test_plugin_asa_checks():
    config_file = os.path.join("tests", "test_data", "cisco_asa_vulnerable.conf")
    parser = get_parser("ASA", config_file)
    assert isinstance(parser, CiscoASAParser)
    
    plugin = PluginASAChecks()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    assert len(issues) > 0
    # Check for a known issue in vulnerable config
    assert any("Telnet Service Enabled" in issue.title for issue in issues)
