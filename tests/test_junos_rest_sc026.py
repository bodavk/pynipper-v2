import json
import pytest

from src.devices.juniper.junos import JunOSParser
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.main import main


def scan(tmp_path, body):
    source = tmp_path / "junos.conf"
    source.write_text("set version 22.4R1.10\n" + body, encoding="utf-8")
    parser = JunOSParser(str(source))
    plugin = PluginJunOSBaseline()
    plugin.check_rest_listeners(parser)
    return parser, plugin.get_issues()


HTTP = "set system services rest http addresses 192.0.2.1\n"


def test_explicit_listener_with_source_restriction_still_uses_cleartext(tmp_path):
    parser, findings = scan(tmp_path, HTTP +
        "set system services rest http port 3001\n"
        "set system services rest control allowed-sources 198.51.100.10\n")
    listener, = parser.get_rest_listeners()
    assert listener.port == 3001 and listener.allowed_sources == ("198.51.100.10",)
    assert len(findings) == 1
    assert findings[0].rule_id == "juniper.junos.management.rest_http"
    assert findings[0].evidence_locations


@pytest.mark.parametrize("body", [
    "set system services rest https addresses 192.0.2.1\n",
    "set system services rest http addresses 127.0.0.1 ::1\n",
    "set system services rest http port 3000\n",
    HTTP + "deactivate system services rest http\n",
    HTTP + "delete system services rest http\n",
    HTTP + "set system services rest apply-groups REST\n",
    HTTP + "set system services rest http port invalid\n",
    "set system services rest http addresses invalid\n",
])
def test_local_inactive_unknown_or_encrypted_listener_not_reported(tmp_path, body):
    assert scan(tmp_path, body)[1] == []


def test_hierarchical_and_mixed_network_loopback_listener(tmp_path):
    source = tmp_path / "hierarchical.conf"
    source.write_text("version 22.4R1.10; system { services { rest { http { "
                      "addresses [ 127.0.0.1 2001:db8::1 ]; port 3000; } } } }", encoding="utf-8")
    parser = JunOSParser(str(source))
    assert parser.get_rest_listeners()[0].resolution_state == "network"
    plugin = PluginJunOSBaseline()
    plugin.check_rest_listeners(parser)
    assert len(plugin.get_issues()) == 1


@pytest.mark.parametrize("format", ["JSON", "HTML"])
def test_public_report(tmp_path, format):
    scan(tmp_path, HTTP)
    output = tmp_path / ("report." + format.lower())
    assert main(["-d", "junos", "-i", str(tmp_path / "junos.conf"),
                 "-o", format, "-f", str(output)]) == 0
    text = output.read_text(encoding="utf-8")
    assert "REST management API uses clear-text HTTP" in text
    if format == "JSON":
        assert json.loads(text)["security-audit"]
