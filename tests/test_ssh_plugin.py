import pytest
import os
from src.devices import get_parser
from src.analyze.cisco.ios.plugins.ssh_plugin import PluginSSH
from src.devices.cisco.ios import CiscoIOSParser

def test_plugin_ssh_detection():
    config_file = os.path.join("tests", "test_data", "cisco_ios_example.conf")
    parser = get_parser("IOS_ROUTER", config_file)
    assert isinstance(parser, CiscoIOSParser)
    
    plugin = PluginSSH()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    # Based on cisco_ios_example.conf, we expect issues related to SSH
    assert len(issues) > 0
    assert any("SSH Protocol Version" in issue.title for issue in issues)
