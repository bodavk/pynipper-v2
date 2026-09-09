import pytest
import os
from src.devices import get_parser
from src.analyze.paloalto.plugins.panos_checks_plugin import PluginPANOSChecks
from src.devices.paloalto.panos import PaloAltoPANOSParser

def test_plugin_panos_checks_full():
    # Create a dummy config file missing syslog and password complexity
    config_path = os.path.join("tests", "test_data", "panos_test_full.xml")
    with open(config_path, "w") as f:
        f.write("""<config>
    <mgt-config>
        <profiles>
            <entry name="insecure-profile">
                <http>yes</http>
            </entry>
        </profiles>
    </mgt-config>
    <security>
        <rules>
            <entry name="any-rule">
                <source><member>any</member></source>
                <destination><member>any</member></destination>
                <service><member>any</member></service>
                <action>allow</action>
            </entry>
        </rules>
    </security>
</config>
""")
    
    parser = get_parser("PAN_OS", config_path)
    assert isinstance(parser, PaloAltoPANOSParser)
    
    plugin = PluginPANOSChecks()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    # PAN-01: HTTP management
    # PAN-02: Broad rule
    # PAN-03: Missing syslog
    # PAN-04: Weak password
    assert len(issues) == 4
    assert any("Insecure Management Interface" in issue.title for issue in issues)
    assert any("Broad Security Rule" in issue.title for issue in issues)
    assert any("Missing Syslog Forwarding" in issue.title for issue in issues)
    assert any("Weak Password Policy" in issue.title for issue in issues)
    
    # Cleanup
    os.remove(config_path)
