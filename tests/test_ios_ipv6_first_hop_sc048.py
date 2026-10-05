"""SC-048: explicit IPv6 RA guard / DHCPv6 guard trust on assessed IOS/IOS-XE endpoint ports."""

import pytest

from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.common.assessment import AssessmentContext
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.cisco.iosxe import CiscoIOSXEParser

RA = "cisco.ios.layer2.access_edge.ipv6_ra_trusted"
DHCP = "cisco.ios.layer2.access_edge.ipv6_dhcp_server_trusted"
POLICIES = """ipv6 nd raguard policy ROUTERS
 device-role router
ipv6 nd raguard policy HOSTS
 device-role host
ipv6 nd raguard policy OPEN
 trusted-port
ipv6 nd raguard policy SWITCHES
 device-role switch
ipv6 dhcp guard policy SERVERS
 device-role server
ipv6 dhcp guard policy CLIENTS
 device-role client
ipv6 dhcp guard policy DOPEN
 trusted-port
"""


def _port(*lines, mode="switchport mode access", extra=" switchport access vlan 10\n"):
    return "interface GigabitEthernet1/0/1\n " + mode + "\n" + extra + "".join(f" {line}\n" for line in lines)


def _scan(tmp_path, body, roles=None, parser_class=CiscoIOSXEParser):
    path = tmp_path / "switch.conf"
    path.write_text("version 17.9\n" + POLICIES + body, encoding="utf-8")
    parser = parser_class(str(path))
    parser.set_assessment_context(AssessmentContext.from_mapping(
        {"interface_roles": roles if roles is not None else {"GigabitEthernet1/0/1": "access-edge"}}))
    plugin = PluginIOSBaseline()
    plugin.check_ipv6_first_hop(parser)
    return parser, [item.rule_id for item in plugin.get_issues()], plugin.get_issues()


@pytest.mark.parametrize("line,rule", [
    ("ipv6 nd raguard attach-policy ROUTERS", RA),
    ("ipv6 nd raguard attach-policy OPEN", RA),
    ("ipv6 dhcp guard attach-policy SERVERS", DHCP),
    ("ipv6 dhcp guard attach-policy DOPEN", DHCP),
])
def test_explicit_trust_on_endpoint_port_is_reported(tmp_path, line, rule):
    _, rules, findings = _scan(tmp_path, _port(line))
    assert rules == [rule]
    assert findings[0].severity.value == "High"
    assert findings[0].basis == FindingBasis.EXPLICIT_VALUE
    assert any(location.line_number for location in findings[0].evidence_locations)
    assert guidance_for(rule) is not None


@pytest.mark.parametrize("line", [
    "ipv6 nd raguard",                                  # default policy: host
    "ipv6 nd raguard attach-policy HOSTS",
    "ipv6 nd raguard attach-policy SWITCHES",           # unassessed role
    "ipv6 nd raguard attach-policy MISSING",            # undefined policy
    "ipv6 nd raguard attach-policy ROUTERS vlan 20",    # VLAN-qualified attachment
    "ipv6 dhcp guard",
    "ipv6 dhcp guard attach-policy CLIENTS",
    "",                                                 # nothing attached: not graded
])
def test_protected_unknown_or_absent_policy_is_not_reported(tmp_path, line):
    _, rules, _ = _scan(tmp_path, _port(line) if line else _port())
    assert rules == []


def test_uplink_router_port_and_unclassified_port_are_not_flagged(tmp_path):
    body = _port("ipv6 nd raguard attach-policy ROUTERS", mode="switchport mode trunk", extra="")
    assert _scan(tmp_path, body, roles={"GigabitEthernet1/0/1": "uplink"})[1] == []
    assert _scan(tmp_path, _port("ipv6 nd raguard attach-policy ROUTERS"), roles={})[1] == []


def test_inactive_routed_and_trunk_ports_are_skipped(tmp_path):
    assert _scan(tmp_path, _port("ipv6 nd raguard attach-policy ROUTERS", "shutdown"))[1] == []
    assert _scan(tmp_path, _port("ipv6 nd raguard attach-policy ROUTERS", mode="no switchport", extra=""))[1] == []
    trunk = _port("ipv6 nd raguard attach-policy ROUTERS", mode="switchport mode trunk", extra="")
    assert _scan(tmp_path, trunk)[1] == []


def test_vlan_configuration_attachment_applies_to_access_vlan(tmp_path):
    vlan = "vlan configuration 5,10-12\n ipv6 nd raguard attach-policy ROUTERS\n"
    parser, rules, findings = _scan(tmp_path, vlan + _port())
    assert rules == [RA]
    assert "VLAN 10" in findings[0].observation
    other = "vlan configuration 20\n ipv6 nd raguard attach-policy ROUTERS\n"
    assert _scan(tmp_path, other + _port())[1] == []


def test_conflicting_interface_and_vlan_attachments_stay_unknown(tmp_path):
    vlan = "vlan configuration 10\n ipv6 nd raguard attach-policy HOSTS\n"
    parser, rules, _ = _scan(tmp_path, vlan + _port("ipv6 nd raguard attach-policy ROUTERS"))
    assert rules == []
    assert parser.get_ipv6_first_hop_ports()[0].ra_guard.state == "unknown"
    same = "vlan configuration 10\n ipv6 nd raguard attach-policy OPEN\n"
    assert _scan(tmp_path, same + _port("ipv6 nd raguard attach-policy ROUTERS"))[1] == [RA]  # both trust: precedence irrelevant


def test_local_removal_and_policy_override_are_resolved(tmp_path):
    assert _scan(tmp_path, _port("ipv6 nd raguard attach-policy ROUTERS", "no ipv6 nd raguard"))[1] == []
    policy = "ipv6 nd raguard policy LATER\n device-role router\n no device-role router\n"
    assert _scan(tmp_path, policy + _port("ipv6 nd raguard attach-policy LATER"))[1] == []


def test_ipv4_and_ipv6_trust_are_reported_separately(tmp_path):
    path = tmp_path / "dual.conf"
    body = _port("ipv6 dhcp guard attach-policy SERVERS", "ip dhcp snooping trust")
    path.write_text("version 17.9\nip dhcp snooping\nip dhcp snooping vlan 10\n" + POLICIES + body, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    parser.set_assessment_context(AssessmentContext.from_mapping({"interface_roles": {"GigabitEthernet1/0/1": "access-edge"}}))
    plugin = PluginIOSBaseline()
    plugin.check_switch_edge(parser)
    plugin.check_ipv6_first_hop(parser)
    rules = {item.rule_id for item in plugin.get_issues()}
    assert {"cisco.ios.layer2.access_edge_trust", DHCP} <= rules


def test_classic_ios_parser_uses_the_same_grammar(tmp_path):
    assert _scan(tmp_path, _port("ipv6 nd raguard attach-policy ROUTERS"), parser_class=CiscoIOSParser)[1] == [RA]
