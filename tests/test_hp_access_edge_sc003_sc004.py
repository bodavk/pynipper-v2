"""SC-003/SC-004 AOS-S stage: 802.1X force-authorized and BPDU protection on access edges."""

import json

import pytest

from src.analyze.hp.plugins.hp_checks_plugin import PluginHPChecks
from src.common.assessment import AssessmentContext
from src.devices.hp.procurve import HPProCurveParser
from src.main import main

HARDENED = """; J9772A Configuration Editor; Created on release #YA.16.11.0001
vlan 10
 untagged 1-2
 tagged 24
dhcp-snooping vlan 10
dhcp-snooping trust 24
arp-protect vlan 10
arp-protect trust 24
ip source-lockdown 1-2
port-security 1-2 learn-mode limited-continuous
"""
FORCED = "hp.procurve.layer2.access_edge.dot1x_force_authorized"
GUARD = "hp.procurve.layer2.access_edge.bpdu_guard_ineffective"
FILTER = "hp.procurve.layer2.access_edge.bpdu_filter_bypass"
NEW = {FORCED, GUARD, FILTER}


def _findings(tmp_path, extra, roles=None, release="YA.16.11.0001"):
    path = tmp_path / "switch.conf"
    path.write_text(HARDENED.replace("YA.16.11.0001", release) + extra, encoding="utf-8")
    parser = HPProCurveParser(str(path))
    parser.set_assessment_context(AssessmentContext.from_mapping(
        {"interface_roles": roles or {"1": "access-edge", "2": "access-edge", "24": "uplink"}}
    ))
    plugin = PluginHPChecks()
    plugin.check_edge_protections(parser)
    return parser, sorted((item.rule_id, item.observation.split()[1]) for item in plugin.get_issues()
                          if item.rule_id in NEW)


def test_force_authorized_access_edge_is_reported_per_port(tmp_path):
    _, findings = _findings(tmp_path, "aaa port-access authenticator 1-2 control authorized\n")
    assert findings == [(FORCED, "1"), (FORCED, "2")]


@pytest.mark.parametrize(
    "extra",
    [
        "aaa port-access authenticator 1-2\naaa port-access authenticator 1-2 control auto\n",
        "aaa port-access authenticator 1-2 control authorized\naaa port-access authenticator 1-2 control auto\n",
        "aaa port-access authenticator 1-2 control authorized\nno aaa port-access authenticator 1-2\n",
        "aaa port-access authenticator 24 control authorized\n",  # uplink, not an access edge
    ],
)
def test_auto_removed_and_non_edge_control_is_not_reported(tmp_path, extra):
    assert _findings(tmp_path, extra)[1] == []


def test_explicit_bpdu_protection_disable_and_filter_bypass(tmp_path):
    parser, findings = _findings(
        tmp_path,
        "spanning-tree 1-2 bpdu-protection\nno spanning-tree 1 bpdu-protection\nspanning-tree 2 bpdu-filter\n",
    )
    assert findings == [(FILTER, "2"), (GUARD, "1")]
    records = {item.port: item for item in parser.get_port_protections()}
    assert (records["2"].bpdu_protection, records["2"].bpdu_filter) == (True, True)


def test_all_keyword_applies_and_later_port_override_wins(tmp_path):
    _, findings = _findings(tmp_path, "spanning-tree all bpdu-filter\nspanning-tree 1-2 bpdu-protection\n"
                                      "no spanning-tree 2 bpdu-filter\n")
    assert findings == [(FILTER, "1")]


@pytest.mark.parametrize(
    "extra",
    [
        "spanning-tree 1-2 bpdu-protection\n",
        "",  # omitted protection is unknown, not a finding
        "spanning-tree 1-2 bpdu-filter\n",  # filter without protection is not this bypass
    ],
)
def test_protected_or_unknown_ports_are_not_reported(tmp_path, extra):
    assert _findings(tmp_path, extra)[1] == []


def test_disabled_port_and_unsupported_release_are_not_assessed(tmp_path):
    extra = "aaa port-access authenticator 1 control authorized\ninterface 1 disable\n"
    assert _findings(tmp_path, extra)[1] == []
    assert _findings(tmp_path, "aaa port-access authenticator 1 control authorized\n",
                     release="WC.16.02.0001")[1] == []


def test_public_cli_json_reports_force_authorized(tmp_path):
    source = tmp_path / "switch.conf"
    source.write_text(HARDENED + "aaa port-access authenticator 1 control authorized\n", encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"interface_roles": {"1": "access-edge"}}), encoding="utf-8")
    report = tmp_path / "report.json"
    assert main(["-d", "hp-procurve", "-i", str(source), "-o", "JSON", "-f", str(report), "-x",
                 "--assessment-policy", str(policy)]) == 0
    audit = json.loads(report.read_text(encoding="utf-8"))["security-audit"].values()
    finding = next(item for item in audit if item["rule_id"] == FORCED)
    assert any(item["line"] for item in finding["evidence_locations"])
