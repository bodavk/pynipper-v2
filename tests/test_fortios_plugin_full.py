import pytest
import os
from src.devices import get_parser
from src.analyze.fortinet.plugins.fortios_checks_plugin import PluginFortiOSChecks
from src.devices.fortinet.fortios import FortiOSParser

def test_plugin_fortios_checks_full():
    # Create a dummy config file triggering all checks
    config_path = os.path.join("tests", "test_data", "fortios_test_full.conf")
    with open(config_path, "w") as f:
        f.write("config system global\n")
        f.write("set ssl-min-proto-version TLSv1-1\n")
        f.write("end\n")
        f.write("config system interface\n")
        f.write('edit "port1"\n')
        f.write('set allowaccess "http" "ssh"\n')
        f.write("next\n")
        f.write("end\n")
        f.write("config firewall policy\n")
        f.write("edit 1\n")
        f.write('set srcintf "any"\n')
        f.write('set dstintf "any"\n')
        f.write('set srcaddr "all"\n')
        f.write('set dstaddr "all"\n')
        f.write('set service "ALL"\n')
        f.write('set schedule "always"\n')
        f.write("set action accept\n")
        f.write("next\n")
        f.write("end\n")
    
    parser = get_parser("FORTIOS", config_path)
    assert isinstance(parser, FortiOSParser)
    
    plugin = PluginFortiOSChecks()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    # FT-01: Admin Access
    # FT-02: Broad Policy
    # FT-03: Insecure TLS
    # FT-04: Lack of syslog
    assert len(issues) == 4
    assert any("Weak Administrative Access" in issue.title for issue in issues)
    assert any("Broad Firewall Policy" in issue.title for issue in issues)
    assert any("Insecure TLS Version" in issue.title for issue in issues)
    assert any("Lack of System Logging" in issue.title for issue in issues)
    
    # Cleanup
    os.remove(config_path)
