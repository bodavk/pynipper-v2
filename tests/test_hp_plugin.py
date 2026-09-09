import pytest
import os
from src.devices import get_parser
from src.analyze.hp.plugins.hp_checks_plugin import PluginHPChecks
from src.devices.hp.procurve import HPProCurveParser

def test_plugin_hp_checks():
    # Create a dummy config file
    config_path = os.path.join("tests", "test_data", "hp_test.conf")
    with open(config_path, "w") as f:
        f.write("hostname \"switch\"\n")
        f.write("password manager\n")

    # By default, telnet is true in my parser if "no telnet-server" is not present
    parser = get_parser("HP_PROCURVE", config_path)
    assert isinstance(parser, HPProCurveParser)

    plugin = PluginHPChecks()
    plugin.analyze(parser)

    issues = plugin.get_issues()
    # Should find at least HP-01 (Telnet)
    assert len(issues) >= 1
    assert any("Telnet Enabled" in issue.title for issue in issues)

    # Cleanup
    os.remove(config_path)

