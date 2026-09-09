import pytest
import os
from src.devices import get_parser
from src.analyze.paloalto.plugins.panos_checks_plugin import PluginPANOSChecks
from src.devices.paloalto.panos import PaloAltoPANOSParser

def test_plugin_panos_checks():
    config_path = os.path.join("tests", "test_data", "panos_test.xml")
    
    parser = get_parser("PAN_OS", config_path)
    assert isinstance(parser, PaloAltoPANOSParser)
    
    plugin = PluginPANOSChecks()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    assert len(issues) == 2
    assert any("Insecure Management Interface" in issue.title for issue in issues)
    assert any("Broad Security Rule" in issue.title for issue in issues)
