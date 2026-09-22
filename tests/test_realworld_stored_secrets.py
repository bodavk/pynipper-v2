"""Effective-state and value-redaction checks for RV-006/RV-007."""

import json
import subprocess
import sys

import pytest

from src.analyze.arista.plugins.arista_checks_plugin import PluginAristaChecks
from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.devices.arista.eos import AristaEOSParser
from src.devices.cisco.ios import CiscoIOSParser


def _issues(tmp_path, content, parser_type, plugin_type):
    path = tmp_path / "config.cfg"
    path.write_text(content, encoding="utf-8")
    parser = parser_type(str(path))
    plugin = plugin_type()
    plugin.check_credentials(parser)
    if parser_type is CiscoIOSParser:
        plugin.check_snmp(parser)
    return parser, plugin.get_issues()


def test_ios_stored_secrets_defaults_and_overrides(tmp_path):
    secret = "SensitiveRadiusValue"
    parser, issues = _issues(tmp_path, f"""version 15.7
username admin password 7 02050D480809
enable password cisco
radius-server key {secret}
radius-server host 192.0.2.10 key 7 02050D480809
line vty 0 4
 password 0 cisco
 login
snmp-server community public ro
snmp-server community private rw
no snmp-server community private
""", CiscoIOSParser, PluginIOSBaseline)
    ids = [item.rule_id for item in issues]
    assert ids.count("cisco.ios.credentials.radius_key_storage") == 2
    assert "cisco.ios.credentials.line_password_storage" in ids
    assert ids.count("cisco.ios.credentials.known_default_value") == 2
    assert ids.count("cisco.ios.snmp.default_community") == 1
    assert "cisco.ios.credentials.local_storage" in ids
    assert secret not in str(issues)
    assert secret not in str(parser.get_additional_credential_metadata())


def test_ios_removed_and_protected_values_do_not_report(tmp_path):
    _, issues = _issues(tmp_path, """enable password cisco
no enable password
radius-server key 7 02050D480809
no radius-server key
line vty 0 4
 password cisco
 no password
snmp-server community public ro
no snmp-server community public
""", CiscoIOSParser, PluginIOSBaseline)
    assert not any(item.rule_id.startswith("cisco.ios.credentials.") for item in issues)
    assert not any(item.rule_id.startswith("cisco.ios.snmp.default") for item in issues)


def test_eos_radius_and_active_terminattr_are_redacted(tmp_path):
    secret = "SensitiveEOSValue"
    parser, issues = _issues(tmp_path, f"""!RANCID-CONTENT-TYPE: arista
radius-server key 7 02050D480809
radius-server host 192.0.2.10 key 0 {secret}
daemon TerminAttr
 exec /usr/bin/TerminAttr -ingestauth=key,{secret}
 no shutdown
""", AristaEOSParser, PluginAristaChecks)
    ids = [item.rule_id for item in issues]
    assert ids.count("arista.eos.credentials.radius_storage") == 2
    assert ids.count("arista.eos.credentials.terminattr_literal") == 1
    assert secret not in str(issues)
    assert secret not in str(parser.get_additional_credential_metadata())


def test_eos_disabled_and_removed_material_is_not_reported(tmp_path):
    _, issues = _issues(tmp_path, """radius-server key 7 02050D480809
no radius-server key
daemon TerminAttr
 exec /usr/bin/TerminAttr -ingestauth=key,SensitiveEOSValue
 shutdown
""", AristaEOSParser, PluginAristaChecks)
    assert not any(item.rule_id.startswith("arista.eos.credentials.radius") or
                   item.rule_id == "arista.eos.credentials.terminattr_literal" for item in issues)


def test_malformed_and_masked_radius_material_remains_ungraded(tmp_path):
    ios, ios_issues = _issues(tmp_path, "radius-server key 7 <redacted>\n",
                              CiscoIOSParser, PluginIOSBaseline)
    eos, eos_issues = _issues(tmp_path, "radius-server key 7 <redacted>\n",
                              AristaEOSParser, PluginAristaChecks)
    assert ios.get_additional_credential_metadata()[0].storage_assessment.value == "unknown"
    assert eos.get_additional_credential_metadata()[0].storage_assessment.value == "unknown"
    assert not any(item.rule_id.endswith("radius_key_storage") for item in ios_issues)
    assert not any(item.rule_id.endswith("radius_storage") for item in eos_issues)


@pytest.mark.parametrize("device,config,expected", [
    ("IOS_ROUTER", "version 15.7\nenable password cisco\nsnmp-server community public ro\n",
     "cisco.ios.credentials.known_default_value"),
    ("ARISTA_EOS", "radius-server key 7 02050D480809\n",
     "arista.eos.credentials.radius_storage"),
])
@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_cli_redacts_stored_values(tmp_path, device, config, expected, output_type):
    source = tmp_path / "device.cfg"
    source.write_text(config, encoding="utf-8")
    output = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", device, "-i", str(source),
         "-o", output_type, "-f", str(output), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = output.read_text(encoding="utf-8")
    assert expected in report
    assert "02050D480809" not in report + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(report)
        assert expected in {item["rule_id"] for item in data["security-audit"].values()}
