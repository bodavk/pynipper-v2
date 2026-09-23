"""SC-005: bounded effective IPv4 BGP prefix-list boundary checks."""

import pytest

from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.devices.cisco.ios import CiscoIOSParser


BASE = """version 17.9
router bgp 65000
 neighbor 192.0.2.1 remote-as 65100
 neighbor 192.0.2.1 password syntheticprivate
 neighbor 192.0.2.1 maximum-prefix 1000
 neighbor 192.0.2.1 prefix-list INBOUND in
 neighbor 192.0.2.1 prefix-list OUTBOUND out
"""
BOUND = "ip prefix-list OUTBOUND permit 198.51.100.0/24\n"
MISSING = "cisco.ios.routing.bgp.missing_prefix_list"
PERMIT_ALL = "cisco.ios.routing.bgp.permit_all_prefix_list"


def _scan(tmp_path, config):
    path = tmp_path / "router.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    plugin = PluginIOSBaseline()
    plugin.check_routing(parser)
    return parser, [issue for issue in plugin.get_issues() if issue.rule_id in {MISSING, PERMIT_ALL}]


def test_missing_referenced_list_is_reported_without_route_leak_claim(tmp_path):
    parser, findings = _scan(tmp_path, BASE + BOUND)
    peer = parser.get_bgp_neighbors()[0]
    assert ("in", "prefix-list", "INBOUND") in peer.policy_references
    assert peer.inbound_policy and peer.outbound_policy
    assert [item.rule_id for item in findings] == [MISSING]
    assert "no definition is exported" in findings[0].observation
    assert "syntheticprivate" not in " ".join(findings[0].evidence)


def test_sole_permit_all_list_is_reported(tmp_path):
    parser, findings = _scan(
        tmp_path, BASE + "ip prefix-list INBOUND seq 5 permit 0.0.0.0/0 le 32\n" + BOUND,
    )
    assert parser.get_bgp_ipv4_prefix_list_effects()["inbound"][0] == "permit-all"
    assert [item.rule_id for item in findings] == [PERMIT_ALL]
    assert "inbound" in findings[0].observation


@pytest.mark.parametrize("list_definition", [
    "ip prefix-list INBOUND deny 10.0.0.0/8 le 32\n"
    "ip prefix-list INBOUND permit 0.0.0.0/0 le 32\n",
    "ip prefix-list INBOUND permit 0.0.0.0/0 le 24\n",
    "ip prefix-list INBOUND seq 5 permit 0.0.0.0/0 le 32\n"
    "no ip prefix-list INBOUND seq 5\n",
])
def test_restrictive_or_unsupported_list_is_not_called_permit_all(tmp_path, list_definition):
    _, findings = _scan(tmp_path, BASE + list_definition + BOUND)
    assert findings == []


def test_other_bound_policy_prevents_permit_all_conclusion(tmp_path):
    config = BASE.replace(
        " neighbor 192.0.2.1 prefix-list INBOUND in\n",
        " neighbor 192.0.2.1 prefix-list INBOUND in\n"
        " neighbor 192.0.2.1 route-map EXTRA in\n",
    )
    parser, findings = _scan(
        tmp_path, config + "ip prefix-list INBOUND permit 0.0.0.0/0 le 32\n" + BOUND,
    )
    assert parser.get_bgp_neighbors()[0].inbound_policy
    assert findings == []


def test_peer_group_inheritance_and_af_scope(tmp_path):
    config = """version 17.9
router bgp 65000
 no bgp default ipv4-unicast
 neighbor EDGE peer-group
 neighbor EDGE remote-as 65100
 neighbor EDGE password syntheticprivate
 neighbor 192.0.2.1 peer-group EDGE
 address-family ipv4 unicast
  neighbor 192.0.2.1 activate
  neighbor EDGE prefix-list INBOUND in
  neighbor EDGE prefix-list OUTBOUND out
ip prefix-list INBOUND permit 0.0.0.0/0 le 32
""" + BOUND
    parser, findings = _scan(tmp_path, config)
    assert parser.get_bgp_neighbors()[0].policy_references == (
        ("in", "prefix-list", "INBOUND"), ("out", "prefix-list", "OUTBOUND"),
    )
    assert [item.rule_id for item in findings] == [PERMIT_ALL]


def test_inactive_or_ipv6_peer_is_not_assessed_as_ipv4(tmp_path):
    inactive = BASE.replace(" neighbor 192.0.2.1 maximum-prefix 1000\n",
                            " neighbor 192.0.2.1 maximum-prefix 1000\n neighbor 192.0.2.1 shutdown\n")
    _, findings = _scan(tmp_path, inactive + "ip prefix-list INBOUND permit 0.0.0.0/0 le 32\n" + BOUND)
    assert findings == []
    ipv6 = """version 17.9
router bgp 65000
 no bgp default ipv4-unicast
 neighbor 2001:db8::1 remote-as 65100
 address-family ipv6 unicast
  neighbor 2001:db8::1 activate
  neighbor 2001:db8::1 prefix-list INBOUND in
"""
    _, findings = _scan(tmp_path, ipv6)
    assert findings == []


def test_removed_list_is_reported_as_missing(tmp_path):
    _, findings = _scan(
        tmp_path, BASE + "ip prefix-list INBOUND permit 0.0.0.0/0 le 32\n"
        "no ip prefix-list INBOUND\n" + BOUND,
    )
    assert [item.rule_id for item in findings] == [MISSING]


def test_removed_neighbor_binding_does_not_create_reference_finding(tmp_path):
    config = BASE.replace(
        " neighbor 192.0.2.1 prefix-list INBOUND in\n",
        " neighbor 192.0.2.1 prefix-list INBOUND in\n"
        " no neighbor 192.0.2.1 prefix-list INBOUND in\n",
    )
    parser, findings = _scan(tmp_path, config + BOUND)
    assert not parser.get_bgp_neighbors()[0].inbound_policy
    assert findings == []


def test_description_is_not_mistaken_for_missing_list(tmp_path):
    parser, findings = _scan(
        tmp_path, BASE + "ip prefix-list INBOUND description Defined but no assessable rules\n" + BOUND,
    )
    assert parser.get_bgp_ipv4_prefix_list_effects()["inbound"][0] == "unknown"
    assert findings == []
