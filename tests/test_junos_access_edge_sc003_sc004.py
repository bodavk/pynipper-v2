"""SC-003/SC-004 Junos EX stage: BPDU protection and 802.1X supplicant mode on access edges."""

import pytest

from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.analyze.common.issue import FindingBasis
from src.common.assessment import AssessmentContext
from src.devices.juniper.junos import JunOSParser

BPDU = "juniper.junos.layer2.access_edge.bpdu_protection_missing"
SINGLE = "juniper.junos.layer2.access_edge.dot1x_single_supplicant"
BASE = "set version 22.4R1.10\nset system host-name ex1\n"
ACCESS = "set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode access\n"


def _run(tmp_path, body, roles=(("ge-0/0/1", "access-edge"),)):
    path = tmp_path / "ex.conf"
    path.write_text(BASE + body, encoding="utf-8")
    parser = JunOSParser(str(path))
    parser.set_assessment_context(AssessmentContext(interface_roles=tuple(roles)))
    plugin = PluginJunOSBaseline()
    plugin.check_access_edge(parser)
    return parser, plugin.get_issues()


def test_unprotected_access_edge_is_reported_as_documented_default(tmp_path):
    _, findings = _run(tmp_path, ACCESS)
    finding, = findings
    assert finding.rule_id == BPDU and finding.basis is FindingBasis.DOCUMENTED_DEFAULT


@pytest.mark.parametrize("protection", [
    "set protocols layer2-control bpdu-block interface ge-0/0/1\n",
    "set protocols layer2-control bpdu-block interface all\n",
    "set ethernet-switching-options bpdu-block interface ge-0/0/1\n",
    "set protocols rstp bpdu-block-on-edge\nset protocols rstp interface ge-0/0/1 edge\n",
])
def test_bpdu_protection_forms(tmp_path, protection):
    _, findings = _run(tmp_path, ACCESS + protection)
    assert findings == []


@pytest.mark.parametrize("body", [
    # bpdu-block-on-edge without the port being edge does not protect it
    ACCESS + "set protocols rstp bpdu-block-on-edge\n",
    # a deactivated bpdu-block hierarchy is not effective
    ACCESS + "set protocols layer2-control bpdu-block interface ge-0/0/1\n"
    "deactivate protocols layer2-control bpdu-block\n",
])
def test_ineffective_forms_still_report(tmp_path, body):
    _, findings = _run(tmp_path, body)
    assert [f.rule_id for f in findings] == [BPDU]


@pytest.mark.parametrize("body", [
    "set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode trunk\n",
    "set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24\n",
    ACCESS + "set interfaces ge-0/0/1 disable\n",
    ACCESS + "set interfaces interface-range edge member ge-0/0/1\n",
])
def test_not_assessed(tmp_path, body):
    _, findings = _run(tmp_path, body)
    assert findings == []


def test_unassessed_role(tmp_path):
    _, findings = _run(tmp_path, ACCESS, roles=())
    assert findings == []


@pytest.mark.parametrize("mode,expected", [("single", [SINGLE]), ("single-secure", []), ("multiple", [])])
def test_supplicant_modes(tmp_path, mode, expected):
    body = ACCESS + "set protocols layer2-control bpdu-block interface all\n" + (
        f"set protocols dot1x authenticator interface ge-0/0/1 supplicant {mode}\n")
    parser, findings = _run(tmp_path, body)
    assert [f.rule_id for f in findings] == expected
    assert parser.get_access_edge_ports()[0].supplicant_mode == mode
