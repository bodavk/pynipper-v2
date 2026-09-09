import pytest
import os
from src.devices import get_parser
from src.analyze.arista.plugins.arista_checks_plugin import PluginAristaChecks
from src.devices.arista.eos import AristaEOSParser

def test_plugin_arista_checks():
    # Create a dummy config file triggering the check
    config_path = os.path.join("tests", "test_data", "arista_test.conf")
    with open(config_path, "w") as f:
        f.write("hostname \"switch\"\n")
        f.write("management api http-commands\n")
        # Explicitly missing "protocol https"
    
    parser = get_parser("ARISTA_EOS", config_path)
    assert isinstance(parser, AristaEOSParser)
    
    plugin = PluginAristaChecks()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    assert len(issues) == 1
    assert any("Unsecured Management API" in issue.title for issue in issues)
    
    # Cleanup
    os.remove(config_path)
