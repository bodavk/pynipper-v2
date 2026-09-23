"""SC-005: bounded external BGP route-map reference/effect checks."""

import pytest

from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.devices.cisco.ios import CiscoIOSParser


BASE = """version 17.9
router bgp 65000
 neighbor 192.0.2.1 remote-as 65100
 neighbor 192.0.2.1 route-map IMPORT in
 neighbor 192.0.2.1 route-map EXPORT out
route-map EXPORT permit 10
 match ip address prefix-list EXPORTS
ip prefix-list EXPORTS permit 198.51.100.0/24
"""
MISSING = "cisco.ios.routing.bgp.missing_route_map"
PERMIT_ALL = "cisco.ios.routing.bgp.permit_all_route_map"


def _scan(tmp_path, config):
    path = tmp_path / "router.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    plugin = PluginIOSBaseline()
    plugin.check_routing(parser)
    return parser, [item for item in plugin.get_issues() if item.rule_id in {MISSING, PERMIT_ALL}]


def test_missing_route_map_definition_is_unresolved(tmp_path):
    parser, findings = _scan(tmp_path, BASE)
    assert ("in", "route-map", "IMPORT") in parser.get_bgp_neighbors()[0].policy_references
    assert [item.rule_id for item in findings] == [MISSING]
    assert "cannot be validated" in findings[0].impact


def test_sole_empty_permit_clause_is_provably_nonrestrictive(tmp_path):
    parser, findings = _scan(tmp_path, BASE + "route-map IMPORT permit 10\n")
    assert parser.get_bgp_route_map_effects()["import"][0] == "permit-all"
    assert [item.rule_id for item in findings] == [PERMIT_ALL]
    assert "inbound" in findings[0].observation


@pytest.mark.parametrize("definition", [
    "route-map IMPORT deny 10\nroute-map IMPORT permit 20\n",
    "route-map IMPORT permit 10\n match ip address prefix-list ALLOWED\n",
    "route-map IMPORT permit 10\n set local-preference 200\n",
    "route-map IMPORT permit 10\nroute-map IMPORT deny 20\n",
])
def test_complex_route_map_is_ungraded(tmp_path, definition):
    _, findings = _scan(tmp_path, BASE + definition)
    assert findings == []


def test_other_bound_filter_suppresses_nonrestrictive_conclusion(tmp_path):
    config = BASE.replace(
        " neighbor 192.0.2.1 route-map IMPORT in\n",
        " neighbor 192.0.2.1 route-map IMPORT in\n"
        " neighbor 192.0.2.1 prefix-list ALLOWED in\n",
    )
    _, findings = _scan(
        tmp_path, config + "route-map IMPORT permit 10\n"
        "ip prefix-list ALLOWED permit 203.0.113.0/24\n",
    )
    assert findings == []


def test_removed_route_map_definition_becomes_missing(tmp_path):
    _, findings = _scan(
        tmp_path, BASE + "route-map IMPORT permit 10\nno route-map IMPORT\n",
    )
    assert [item.rule_id for item in findings] == [MISSING]
