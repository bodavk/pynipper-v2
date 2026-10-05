"""SC-058 (CIS Juniper OS 6.10.5.7-6.10.5.8): REST allowed-sources and API Explorer."""

from src.analyze.common.guidance import guidance_for
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.devices.juniper.junos import JunOSParser

HTTPS = "set system services rest https addresses 192.0.2.10\nset system services rest https server-certificate CERT\n"


def _rules(tmp_path, body):
    source = tmp_path / "junos.conf"
    source.write_text("set version 22.4R1.10\n" + body, encoding="utf-8")
    plugin = PluginJunOSBaseline()
    plugin.check_rest_restrictions(JunOSParser(str(source)))
    return {item.rule_id for item in plugin.get_issues()}


def test_unrestricted_sources(tmp_path):
    rules = _rules(tmp_path, HTTPS)
    assert rules == {"juniper.junos.management.unrestricted_rest"}
    assert guidance_for("juniper.junos.management.unrestricted_rest")


def test_allowed_sources_and_explorer(tmp_path):
    body = HTTPS + "set system services rest control allowed-sources 192.0.2.50\nset system services rest enable-explorer\n"
    rules = _rules(tmp_path, body)
    assert rules == {"juniper.junos.management.rest_explorer"}
    assert guidance_for("juniper.junos.management.rest_explorer")
