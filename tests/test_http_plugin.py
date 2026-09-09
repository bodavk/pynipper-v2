import pytest
import os
from src.devices import get_parser
from src.analyze.cisco.ios.plugins.http_plugin import PluginHTTP
from src.devices.cisco.ios import CiscoIOSParser

def test_plugin_http_detection():
    config_file = os.path.join("tests", "test_data", "cisco_ios_example.conf")
    parser = get_parser("IOS_ROUTER", config_file)
    assert isinstance(parser, CiscoIOSParser)
    
    plugin = PluginHTTP()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    # Based on cisco_ios_example.conf, we expect issues related to HTTP
    assert len(issues) > 0
    # Check if specifically HTTP service issue exists
    assert any("HyperText Transport Protocol Service" in issue.title for issue in issues)
