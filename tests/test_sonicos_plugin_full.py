import pytest
import os
from src.devices import get_parser
from src.analyze.sonicwall.plugins.sonicos_checks_plugin import PluginSonicOSChecks
from src.devices.sonicwall.sonicos import SonicOSParser

def test_plugin_sonicos_checks_full():
    # Create a dummy config file triggering all checks
    config_path = os.path.join("tests", "test_data", "sonicos_test_full.conf")
    with open(config_path, "w") as f:
        f.write("set service http enable\n")
        f.write("set admin password password\n")
        f.write("set vpn encryption des\n")
    
    parser = get_parser("SONICOS", config_path)
    assert isinstance(parser, SonicOSParser)
    
    plugin = PluginSonicOSChecks()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    # SW-01: HTTP enabled
    # SW-02: Default password
    # SW-03: Weak encryption
    assert len(issues) == 3
    assert any("HTTP Management Enabled" in issue.title for issue in issues)
    assert any("Potential Default Admin Password" in issue.title for issue in issues)
    assert any("Weak VPN Encryption" in issue.title for issue in issues)
    
    # Cleanup
    os.remove(config_path)
