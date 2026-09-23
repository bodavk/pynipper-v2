"""SC-005: bounded external BGP AS-path filter-list checks."""

import pytest

from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.devices.cisco.ios import CiscoIOSParser


BASE = """version 17.9
router bgp 65000
 neighbor 192.0.2.1 remote-as 65100
 neighbor 192.0.2.1 filter-list 10 in
"""
MISSING = "cisco.ios.routing.bgp.missing_filter_list"
PERMIT_ALL = "cisco.ios.routing.bgp.permit_all_filter_list"


def _scan(tmp_path, config):
    path = tmp_path / "router.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    plugin = PluginIOSBaseline()
    plugin.check_routing(parser)
    return parser, [item for item in plugin.get_issues() if item.rule_id in {MISSING, PERMIT_ALL}]


def test_missing_as_path_list(tmp_path):
    parser, findings = _scan(tmp_path, BASE)
    assert ("in", "filter-list", "10") in parser.get_bgp_neighbors()[0].policy_references
    assert [item.rule_id for item in findings] == [MISSING]


@pytest.mark.parametrize("regex", [".*", "^.*$"])
def test_sole_universal_permit(tmp_path, regex):
    parser, findings = _scan(tmp_path, BASE + f"ip as-path access-list 10 permit {regex}\n")
    assert parser.get_bgp_as_path_filter_effects()["10"][0] == "permit-all"
    assert [item.rule_id for item in findings] == [PERMIT_ALL]


def test_nonuniversal_or_earlier_deny_is_not_called_permit_all(tmp_path):
    _, findings = _scan(tmp_path, BASE + "ip as-path access-list 10 deny ^65100$\n"
                        "ip as-path access-list 10 permit .*\n")
    assert findings == []
    _, findings = _scan(tmp_path, BASE + "ip as-path access-list 10 permit ^65100$\n")
    assert findings == []


def test_other_policy_attachment_suppresses_permit_all(tmp_path):
    config = BASE + " neighbor 192.0.2.1 prefix-list ALLOWED in\n"
    parser, findings = _scan(
        tmp_path, config + "ip as-path access-list 10 permit .*\n"
        "ip prefix-list ALLOWED permit 198.51.100.0/24\n",
    )
    assert parser.get_bgp_neighbors()[0].inbound_policy
    assert findings == []


def test_removed_list_is_unresolved(tmp_path):
    _, findings = _scan(tmp_path, BASE + "ip as-path access-list 10 permit .*\n"
                        "no ip as-path access-list 10\n")
    assert [item.rule_id for item in findings] == [MISSING]
