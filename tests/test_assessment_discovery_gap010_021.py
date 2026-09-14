import json

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.common.assessment import AssessmentContext
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.juniper.junos import JunOSParser
from src.report.report import _generate_json_report


def _source(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def _context(**values):
    return AssessmentContext.from_mapping(values)


def test_assessment_context_validates_roles_fields_and_categories():
    with pytest.raises(ValueError, match="unsupported interface role"):
        _context(interface_roles={"Gi0/0": "internet-ish"})
    with pytest.raises(ValueError, match="unknown assessment policy fields"):
        _context(target_cidrs=["192.0.2.0/24"])
    with pytest.raises(ValueError, match="category names"):
        _context(excluded_categories=["not a category"])
    with pytest.raises(ValueError, match="UTC offset"):
        _context(assessment_time="2026-09-14T12:00:00")
    with pytest.raises(ValueError, match="64 hexadecimal"):
        _context(trusted_certificate_sha256=["not-a-fingerprint"])
    with pytest.raises(ValueError, match="non-empty scope"):
        _context(management_certificate_identities={"": "fw.example.test"})


def test_default_policy_is_deterministic_and_unknown_role_is_not_external():
    first = AssessmentContext()
    second = AssessmentContext()
    assert first == second
    assert first.role_for_interface("GigabitEthernet0/0") == "unknown"
    assert first.filter_findings([]) == []
    assert first.to_dict()["scope-note"].endswith("not implied secure.")


def test_category_exclusion_filters_public_processor_without_claiming_compliance(tmp_path):
    parser = CiscoIOSParser(_source(tmp_path, "excluded.conf", '''version 17.9
router bgp 65000
 neighbor 192.0.2.1 remote-as 65100
'''))
    parser.set_assessment_context(_context(excluded_categories=["routing"]))
    issues = process_cisco_ios_conf(parser)
    assert issues
    assert all(".routing." not in item.rule_id for item in issues.values())
    assert parser.get_bgp_neighbors()  # Parsing/coverage is retained despite exclusion.


def test_json_report_declares_policy_and_excluded_scope(tmp_path):
    report = tmp_path / "report.json"
    context = _context(
        policy_version="corp-v2",
        device_role="external",
        interface_roles={"ge-0/0/0": "external"},
        excluded_categories=["discovery"],
    )
    _generate_json_report(
        str(report), {}, [],
        {"device-type": "JUNOS", "hostname": "edge", "assessment-policy": context.to_dict()},
    )
    payload = json.loads(report.read_text(encoding="utf-8"))
    policy = payload["data"]["assessment-policy"]
    assert policy["policy-version"] == "corp-v2"
    assert policy["excluded-categories"] == ["discovery"]
    assert "not implied secure" in policy["scope-note"]


def test_ios_discovery_requires_external_role_and_tracks_directions(tmp_path):
    parser = CiscoIOSParser(_source(tmp_path, "ios-discovery.conf", '''version 17.9
lldp run
interface GigabitEthernet0/0
 no shutdown
 no lldp receive
interface GigabitEthernet0/1
 no shutdown
interface GigabitEthernet0/2
 shutdown
'''))
    parser.set_assessment_context(_context(interface_roles={
        "GigabitEthernet0/0": "external",
        "GigabitEthernet0/1": "voice-fabric",
        "GigabitEthernet0/2": "external",
    }))
    plugin = PluginIOSBaseline()
    plugin.check_discovery(parser)
    findings = plugin.get_issues()
    assert [item.rule_id for item in findings] == [
        "cisco.ios.discovery.cdp.external",
        "cisco.ios.discovery.lldp.external",
    ]
    assert all("GigabitEthernet0/0" in item.observation for item in findings)
    assert "transmit" in findings[1].observation
    assert "receive" not in findings[1].observation


def test_ios_global_and_local_discovery_disablement_is_effective(tmp_path):
    parser = CiscoIOSParser(_source(tmp_path, "ios-discovery-off.conf", '''version 17.9
no cdp run
no lldp run
interface GigabitEthernet0/0
 cdp enable
 lldp transmit
 lldp receive
'''))
    parser.set_assessment_context(_context(interface_roles={"GigabitEthernet0/0": "external"}))
    plugin = PluginIOSBaseline()
    plugin.check_discovery(parser)
    assert plugin.get_issues() == []


def test_junos_lldp_all_with_specific_disable_and_internal_scope(tmp_path):
    parser = JunOSParser(_source(tmp_path, "junos-discovery.conf", '''set version 22.4R1.10
set protocols lldp interface all
set protocols lldp interface ge-0/0/1 disable
set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/31
set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.3/31
set interfaces ge-0/0/2 unit 0 family ethernet-switching
'''))
    parser.set_assessment_context(_context(interface_roles={
        "ge-0/0/0": "external",
        "ge-0/0/1": "external",
        "ge-0/0/2": "internal",
    }))
    plugin = PluginJunOSBaseline()
    plugin.check_discovery(parser)
    findings = plugin.get_issues()
    assert len(findings) == 1
    assert findings[0].rule_id == "juniper.junos.discovery.lldp.external"
    assert "ge-0/0/0" in findings[0].observation


def test_junos_disabled_link_and_unknown_role_are_not_reported(tmp_path):
    parser = JunOSParser(_source(tmp_path, "junos-discovery-edge.conf", '''set version 22.4R1.10
set protocols lldp interface all
set interfaces ge-0/0/0 disable
set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/31
'''))
    parser.set_assessment_context(_context(interface_roles={"ge-0/0/0": "external"}))
    plugin = PluginJunOSBaseline()
    plugin.check_discovery(parser)
    assert plugin.get_issues() == []
