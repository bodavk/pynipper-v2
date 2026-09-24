"""SC-004 EOS stage: effective edge-port BPDU guard on assessed access edges."""

import json

import pytest

from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.common.assessment import AssessmentContext
from src.devices.arista.eos import AristaEOSParser
from src.main import main

GUARD = "arista.eos.layer2.access_edge.bpdu_guard_ineffective"
FILTER = "arista.eos.layer2.access_edge.bpdu_filter_bypass"
HEADER = "! device: leaf (DCS-7050SX3-48YC8, EOS-4.30.1F)\nhostname leaf\n"


def _run(tmp_path, body, roles=(("Ethernet1", "access-edge"),)):
    path = tmp_path / "eos.conf"
    path.write_text(HEADER + body, encoding="utf-8")
    parser = AristaEOSParser(str(path))
    parser.set_assessment_context(AssessmentContext(interface_roles=tuple(roles)))
    findings = [item for item in process_arista_conf(parser).values()
                if item.rule_id in {GUARD, FILTER}]
    return parser, findings


@pytest.mark.parametrize(
    "body,state",
    [
        ("interface Ethernet1\n   spanning-tree portfast\n   spanning-tree bpduguard disable\n", "local-disabled"),
        ("spanning-tree edge-port bpduguard default\ninterface Ethernet1\n   spanning-tree portfast\n"
         "   spanning-tree bpduguard disable\n", "local-disabled"),
        ("no spanning-tree edge-port bpduguard default\ninterface Ethernet1\n   spanning-tree portfast\n",
         "global-disabled"),
        ("spanning-tree edge-port bpduguard default\ninterface Ethernet1\n   spanning-tree portfast network\n",
         "portfast-disabled"),
    ],
)
def test_explicitly_ineffective_guard_is_reported(tmp_path, body, state):
    parser, findings = _run(tmp_path, body)
    assert parser.get_bpdu_guard_policies()[0].guard_state == state
    finding, = findings
    assert finding.rule_id == GUARD and "Ethernet1" in finding.observation
    assert all(item.line_number for item in finding.evidence_locations
               if not item.text.startswith("assessment policy"))


@pytest.mark.parametrize(
    "body",
    [
        "interface Ethernet1\n   spanning-tree bpduguard enable\n",
        "spanning-tree edge-port bpduguard default\ninterface Ethernet1\n   spanning-tree portfast\n",
        # Later local reset returns to the (enabled) default for a portfast port.
        "spanning-tree edge-port bpduguard default\ninterface Ethernet1\n   spanning-tree portfast\n"
        "   spanning-tree bpduguard disable\n   no spanning-tree bpduguard\n",
        # Omitted global and local settings: unknown, not a finding.
        "interface Ethernet1\n   spanning-tree portfast\n",
        # Auto-edge is operational state, so the default's applicability is unknown.
        "spanning-tree edge-port bpduguard default\ninterface Ethernet1\n   spanning-tree portfast auto\n",
    ],
)
def test_effective_or_unknown_guard_is_not_reported(tmp_path, body):
    assert _run(tmp_path, body)[1] == []


@pytest.mark.parametrize(
    "extra",
    ["   shutdown\n", "   no switchport\n", "   switchport mode trunk\n", "   channel-group 10 mode active\n"],
)
def test_inactive_routed_trunk_and_lag_ports_are_not_assessed(tmp_path, extra):
    body = "interface Ethernet1\n   spanning-tree bpduguard disable\n" + extra
    assert _run(tmp_path, body)[1] == []


def test_unassessed_role_is_not_reported(tmp_path):
    body = "interface Ethernet1\n   spanning-tree bpduguard disable\n"
    assert _run(tmp_path, body, roles=())[1] == []
    assert _run(tmp_path, body, roles=(("Ethernet1", "uplink"),))[1] == []


def test_filter_with_guard_is_a_separate_bypass(tmp_path):
    _, findings = _run(tmp_path, "interface Ethernet1\n   spanning-tree bpduguard enable\n"
                                 "   spanning-tree bpdufilter enable\n")
    finding, = findings
    assert finding.rule_id == FILTER
    _, none = _run(tmp_path, "interface Ethernet1\n   spanning-tree bpduguard enable\n"
                             "   spanning-tree bpdufilter enable\n   no spanning-tree bpdufilter\n")
    assert none == []


def test_public_cli_reports_the_port(tmp_path):
    source = tmp_path / "eos.conf"
    source.write_text(HEADER + "interface Ethernet1\n   spanning-tree bpduguard disable\n", encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"interface_roles": {"Ethernet1": "access-edge"}}), encoding="utf-8")
    report = tmp_path / "report.json"
    assert main(["-d", "arista-eos", "-i", str(source), "-o", "JSON", "-f", str(report), "-x",
                 "--assessment-policy", str(policy)]) == 0
    rules = {item["rule_id"] for item in json.loads(report.read_text(encoding="utf-8"))["security-audit"].values()}
    assert GUARD in rules
