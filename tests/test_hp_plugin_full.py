import pytest
import os
from src.devices import get_parser
from src.analyze.hp.plugins.hp_checks_plugin import PluginHPChecks
from src.devices.hp.procurve import HPProCurveParser

def test_plugin_hp_checks_full():
    # Create a dummy config file triggering all checks
    config_path = os.path.join("tests", "test_data", "hp_test_full.conf")
    with open(config_path, "w") as f:
        f.write("hostname \"switch\"\n")
        f.write("snmp-server community public\n")
        f.write("web-management enable\n")
        # Explicitly missing "ip ssh key-exchange"
    
    parser = get_parser("HP_PROCURVE", config_path)
    assert isinstance(parser, HPProCurveParser)
    
    plugin = PluginHPChecks()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    # HP-01: Telnet (default true in parser)
    # HP-02: SNMP public
    # HP-03: Web enabled
    # HP-04: SSH hardening missing
    assert len(issues) == 4
    assert any("Telnet Enabled" in issue.title for issue in issues)
    assert any("Default SNMP Community" in issue.title for issue in issues)
    assert any("Insecure Web Management" in issue.title for issue in issues)
    assert any("SSH Key Exchange Not Hardened" in issue.title for issue in issues)
    
    # Cleanup
    os.remove(config_path)
