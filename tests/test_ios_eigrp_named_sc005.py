"""SC-005 stage: EIGRP named-mode (af-interface) authentication on IOS/IOS-XE.

Grammar and inheritance follow the Cisco EIGRP command reference: ``af-interface
default`` applies to every interface of the address family, a specific
``af-interface`` overrides it, and ``authentication key-chain`` has no effect
until ``authentication mode md5`` is set.
"""

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.devices.cisco.ios import CiscoIOSParser

BASE = "version 17.9\nhostname edge-router\n"
PORT = "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n"
CHAIN = "key chain EDGE\n key 1\n  key-string 7 syntheticprivate\n"
NO_AUTH = "cisco.ios.routing.eigrp.authentication"
UNRESOLVED = "cisco.ios.routing.eigrp.key_resolution"


def named(*af_lines, af="address-family ipv4 unicast autonomous-system 10"):
    body = "".join(f"  {line}\n" for line in af_lines)
    return f"router eigrp CAMPUS\n {af}\n  network 192.0.2.0 0.0.0.255\n{body} exit-address-family\n"


def _scan(tmp_path, commands):
    path = tmp_path / "router.conf"
    path.write_text(BASE + commands, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    findings = [item for item in process_cisco_ios_conf(parser).values()
                if item.rule_id in {NO_AUTH, UNRESOLVED}]
    return parser, findings


def test_named_mode_without_authentication_is_reported(tmp_path):
    parser, findings = _scan(tmp_path, named() + PORT)
    record, = parser.get_eigrp_interfaces()
    assert (record.named_instance, record.autonomous_system, record.authentication_state) == (
        "CAMPUS", "10", "unauthenticated")
    finding, = findings
    assert finding.rule_id == NO_AUTH
    assert "named instance CAMPUS" in finding.observation
    assert "af-interface" in finding.recommendation


@pytest.mark.parametrize("af_lines,state", [
    (("af-interface GigabitEthernet0/0", " authentication mode md5",
      " authentication key-chain EDGE", "exit-af-interface"), "configured-md5"),
    (("af-interface default", " authentication mode md5",
      " authentication key-chain EDGE", "exit-af-interface"), "configured-md5"),
    (("af-interface default", " authentication mode hmac-sha-256 0 syntheticsha",
      "exit-af-interface"), "configured-hmac-sha-256"),
    # Documented example form with a space in the interface name.
    (("af-interface GigabitEthernet 0/0", " authentication key-chain EDGE",
      " authentication mode md5", "exit-af-interface"), "configured-md5"),
])
def test_effective_authentication_is_not_reported(tmp_path, af_lines, state):
    parser, findings = _scan(tmp_path, named(*af_lines) + CHAIN + PORT)
    assert parser.get_eigrp_interfaces()[0].authentication_state == state
    assert findings == []


def test_key_chain_without_mode_and_missing_chain(tmp_path):
    parser, findings = _scan(tmp_path, named(
        "af-interface default", " authentication key-chain EDGE", "exit-af-interface") + CHAIN + PORT)
    assert [item.rule_id for item in findings] == [NO_AUTH]
    parser, findings = _scan(tmp_path, named(
        "af-interface default", " authentication mode md5", "exit-af-interface") + PORT)
    assert parser.get_eigrp_interfaces()[0].authentication_state == "unresolved"
    assert [item.rule_id for item in findings] == [UNRESOLVED]


def test_specific_interface_overrides_default(tmp_path):
    # Default authenticates; the specific af-interface switches to an unbound chain.
    parser, findings = _scan(tmp_path, named(
        "af-interface default", " authentication mode md5", " authentication key-chain EDGE",
        "exit-af-interface", "af-interface GigabitEthernet0/0", " authentication key-chain MISSING",
        "exit-af-interface") + CHAIN + PORT)
    assert [item.rule_id for item in findings] == [UNRESOLVED]


def test_specific_negation_of_inherited_default_stays_unknown(tmp_path):
    parser, findings = _scan(tmp_path, named(
        "af-interface default", " authentication mode md5", " authentication key-chain EDGE",
        "exit-af-interface", "af-interface GigabitEthernet0/0", " no authentication mode md5",
        "exit-af-interface") + CHAIN + PORT)
    assert parser.get_eigrp_interfaces()[0].authentication_state == "unknown"
    assert findings == []


@pytest.mark.parametrize("commands", [
    named("af-interface default", " passive-interface", "exit-af-interface") + PORT,
    named("af-interface GigabitEthernet0/0", " shutdown", "exit-af-interface") + PORT,
    named(af="address-family ipv4 unicast vrf CUST autonomous-system 10") + PORT,
    named(af="address-family ipv6 unicast autonomous-system 10") + PORT,
    named() + "no router eigrp CAMPUS\n" + PORT,
    named() + "interface GigabitEthernet0/0\n ip address 198.51.100.1 255.255.255.0\n",
    named() + PORT + " shutdown\n",
])
def test_passive_shutdown_or_out_of_scope_is_not_assessed(tmp_path, commands):
    parser, findings = _scan(tmp_path, commands)
    assert parser.get_eigrp_interfaces() == []
    assert findings == []


def test_passive_default_with_specific_override(tmp_path):
    parser, findings = _scan(tmp_path, named(
        "af-interface default", " passive-interface", "exit-af-interface",
        "af-interface GigabitEthernet0/0", " no passive-interface", "exit-af-interface") + PORT)
    assert [item.rule_id for item in findings] == [NO_AUTH]


def test_topology_submode_is_not_mistaken_for_interface_settings(tmp_path):
    parser, findings = _scan(tmp_path, named(
        "topology base", " passive-interface", "exit-af-topology") + PORT)
    assert [item.rule_id for item in findings] == [NO_AUTH]


def test_hmac_key_is_redacted_but_available_to_show_secrets(tmp_path):
    parser, _ = _scan(tmp_path, named(
        "af-interface default", " authentication mode hmac-sha-256 0 syntheticsha",
        "exit-af-interface") + PORT)
    record, = parser.get_eigrp_interfaces()
    rendered = " ".join(item.text for item in record.evidence)
    assert "syntheticsha" not in rendered
    assert "authentication mode hmac-sha-256 <redacted>" in rendered
    secrets = parser.get_report_secret_evidence()
    assert [(context, item.line_number) for context, item in secrets] == [("eigrp_key", 7)]
