"""Bounded explicit-cleartext gNMI stage for EOS (SC-026)."""

import pytest

from src.analyze.arista.plugins.arista_checks_plugin import PluginAristaChecks
from src.analyze.common.guidance import guidance_for
from src.devices.arista.eos import AristaEOSParser
from src.main import main


def scan(tmp_path, body):
    source = tmp_path / "eos.conf"
    source.write_text("! device: test (DCS-7050, EOS-4.31.2F)\n" + body, encoding="utf-8")
    parser = AristaEOSParser(str(source))
    plugin = PluginAristaChecks()
    plugin.check_management_api(parser)
    return parser, plugin.get_issues()


UNSAFE = """management api gnmi
   transport grpc audit
      vrf management
      port 6030
      ip access-group MGMT
      no ssl profile
      no shutdown
"""


def test_explicit_cleartext_enabled_transport(tmp_path):
    parser, findings = scan(tmp_path, UNSAFE)
    state = parser.get_gnmi_transports()[0]
    assert (state.name, state.active, state.tls_state, state.vrf, state.port,
            state.ipv4_acl) == ("audit", True, "explicit-cleartext", "management", 6030, "MGMT")
    assert [item.rule_id for item in findings] == ["arista.eos.management.gnmi_cleartext"]
    assert findings[0].evidence_locations
    assert guidance_for(findings[0].rule_id) is not None


def test_named_transports_are_assessed_independently(tmp_path):
    body = UNSAFE + """   transport grpc secure
      ssl profile SECURE
      no shutdown
"""
    parser, findings = scan(tmp_path, body)
    assert {item.name for item in parser.get_gnmi_transports()} == {"audit", "secure"}
    assert len(findings) == 1 and "'audit'" in findings[0].observation


@pytest.mark.parametrize("body", [
    UNSAFE.replace("no shutdown", "shutdown"),
    UNSAFE.replace("no shutdown", ""),
    UNSAFE.replace("no ssl profile", ""),
    UNSAFE.replace("no ssl profile", "ssl profile SECURE"),
    UNSAFE + "no management api gnmi\n",
    UNSAFE + "management api gnmi\n   no transport grpc audit\n",
    UNSAFE + "management api gnmi\n   transport grpc audit\n      ssl profile SECURE\n",
    UNSAFE + "management api gnmi\n   transport grpc audit\n      shutdown\n",
    UNSAFE.replace("port 6030", "listen address 127.0.0.1"),
    "management api gnmi\n   transport grpc-tunnel audit\n      no ssl profile\n      no shutdown\n",
    "management client api gnmi\n   server audit\n      no ssl profile\n      no shutdown\n",
])
def test_inactive_unknown_encrypted_or_removed_not_reported(tmp_path, body):
    assert scan(tmp_path, body)[1] == []


@pytest.mark.parametrize("format", ["JSON", "HTML"])
def test_public_report(tmp_path, format):
    scan(tmp_path, UNSAFE)
    output = tmp_path / ("report." + format.lower())
    assert main(["-d", "arista_eos", "-i", str(tmp_path / "eos.conf"), "-o", format,
                 "-f", str(output)]) == 0
    assert "gNMI transport explicitly disables TLS" in output.read_text(encoding="utf-8")
