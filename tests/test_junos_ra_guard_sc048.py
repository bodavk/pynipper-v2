"""SC-048 Junos EX: RA guard 'mark-interface trusted' on an assessed access-edge port."""

import pytest

from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.common.assessment import AssessmentContext
from src.devices.juniper.junos import JunOSParser

RULE = "juniper.junos.layer2.access_edge.ipv6_ra_trusted"
BASE = ("set version 22.4R1.10\nset system host-name ex1\n"
        "set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode access\n"
        "set protocols layer2-control bpdu-block interface ge-0/0/1\n")


def _rules(tmp_path, extra, role="access-edge"):
    path = tmp_path / "ex.conf"
    path.write_text(BASE + extra, encoding="utf-8")
    parser = JunOSParser(str(path))
    parser.set_assessment_context(AssessmentContext.from_mapping({"interface_roles": {"ge-0/0/1": role}}))
    plugin = PluginJunOSBaseline()
    plugin.check_access_edge(parser)
    return [f.rule_id for f in plugin.get_issues()]


@pytest.mark.parametrize("name", ["ge-0/0/1", "ge-0/0/1.0"])
def test_trusted_access_edge_is_reported(tmp_path, name):
    extra = f"set forwarding-options access-security router-advertisement-guard interface {name} mark-interface trusted\n"
    assert _rules(tmp_path, extra) == [RULE]


@pytest.mark.parametrize("extra,role", [
    ("set forwarding-options access-security router-advertisement-guard interface ge-0/0/1 mark-interface block\n", "access-edge"),
    ("set forwarding-options access-security router-advertisement-guard interface ge-0/0/1 policy P stateless\n", "access-edge"),
    ("set forwarding-options access-security router-advertisement-guard interface ge-0/0/1 mark-interface trusted\n", "uplink"),
    ("deactivate forwarding-options access-security\n"
     "set forwarding-options access-security router-advertisement-guard interface ge-0/0/1 mark-interface trusted\n", "access-edge"),
    ("", "access-edge"),
])
def test_untrusted_uplink_or_inactive_not_reported(tmp_path, extra, role):
    assert RULE not in _rules(tmp_path, extra, role)
