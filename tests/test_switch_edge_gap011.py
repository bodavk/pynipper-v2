from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.analyze.hp.plugins.hp_checks_plugin import PluginHPChecks
from src.common.assessment import AssessmentContext
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.hp.procurve import HPProCurveParser


def _source(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


def _context(roles):
    return AssessmentContext.from_mapping({"interface_roles": roles})


def _ios_findings(parser):
    plugin = PluginIOSBaseline()
    plugin.check_switch_edge(parser)
    return plugin.get_issues()


def _hp_findings(parser):
    plugin = PluginHPChecks()
    plugin.check_edge_protections(parser)
    return [item for item in plugin.get_issues() if ".layer2.access_edge" in item.rule_id]


def test_ios_hardened_access_edge_is_clear(tmp_path):
    parser = CiscoIOSParser(_source(tmp_path, "ios-edge-secure.conf", '''version 17.9
ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
 ip verify source
 switchport port-security
 no shutdown
'''))
    parser.set_assessment_context(_context({"GigabitEthernet1/0/1": "access-edge"}))
    record = parser.get_switch_edge_interfaces()[0]
    assert record.access_vlan == 10
    assert record.dhcp_snooping and record.arp_inspection
    assert record.source_guard and record.port_security
    assert _ios_findings(parser) == []


def test_ios_edge_vlan_override_and_trust_are_independent(tmp_path):
    parser = CiscoIOSParser(_source(tmp_path, "ios-edge-weak.conf", '''version 17.9
ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
 switchport access vlan 20
 ip dhcp snooping trust
 ip arp inspection trust
'''))
    parser.set_assessment_context(_context({"GigabitEthernet1/0/1": "access-edge"}))
    findings = _ios_findings(parser)
    assert {item.rule_id for item in findings} == {
        "cisco.ios.layer2.access_edge_trust",
        "cisco.ios.layer2.access_edge.dhcp_snooping",
        "cisco.ios.layer2.access_edge.arp_inspection",
        "cisco.ios.layer2.access_edge.source_guard",
        "cisco.ios.layer2.access_edge.port_security",
    }
    assert all("GigabitEthernet1/0/1" in item.observation for item in findings)


def test_ios_access_edge_trunk_is_reported_but_uplink_and_routed_port_are_not(tmp_path):
    parser = CiscoIOSParser(_source(tmp_path, "ios-edge-roles.conf", '''version 17.9
interface GigabitEthernet1/0/1
 switchport mode trunk
interface GigabitEthernet1/0/2
 switchport mode trunk
 ip dhcp snooping trust
interface GigabitEthernet1/0/3
 no switchport
'''))
    parser.set_assessment_context(_context({
        "GigabitEthernet1/0/1": "access-edge",
        "GigabitEthernet1/0/2": "uplink",
        "GigabitEthernet1/0/3": "access-edge",
    }))
    findings = _ios_findings(parser)
    assert [item.rule_id for item in findings] == ["cisco.ios.layer2.access_edge_trunk"]
    assert "GigabitEthernet1/0/1" in findings[0].observation


def test_ios_disabled_and_unknown_role_ports_are_unassessed(tmp_path):
    parser = CiscoIOSParser(_source(tmp_path, "ios-edge-unknown.conf", '''version 17.9
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan malformed
 shutdown
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 10
'''))
    parser.set_assessment_context(_context({"GigabitEthernet1/0/1": "access-edge"}))
    assert _ios_findings(parser) == []


def test_hp_hardened_access_edge_and_trusted_uplink_are_clear(tmp_path):
    parser = HPProCurveParser(_source(tmp_path, "hp-edge-secure.conf", '''; J9772A Configuration Editor; Created on release #YA.16.11.0001
vlan 10
 untagged 1
 tagged 24
dhcp-snooping vlan 10
dhcp-snooping trust 24
arp-protect vlan 10
arp-protect trust 24
ip source-lockdown 1
port-security 1 learn-mode limited-continuous
'''))
    parser.set_assessment_context(_context({"1": "access-edge", "24": "uplink"}))
    records = {item.port: item for item in parser.get_port_protections()}
    assert records["1"].vlans == (10,)
    assert not records["1"].tagged
    assert records["24"].tagged and records["24"].dhcp_trusted
    assert _hp_findings(parser) == []


def test_hp_access_edge_trust_and_missing_controls_are_reported(tmp_path):
    parser = HPProCurveParser(_source(tmp_path, "hp-edge-weak.conf", '''; J9772A Configuration Editor; Created on release #YA.16.11.0001
vlan 10
 untagged 1
dhcp-snooping vlan 10
dhcp-snooping trust 1
arp-protect trust 1
'''))
    parser.set_assessment_context(_context({"1": "access-edge"}))
    findings = _hp_findings(parser)
    assert {item.rule_id for item in findings} == {
        "hp.procurve.layer2.access_edge_trust",
        "hp.procurve.layer2.access_edge.arp_protection",
        "hp.procurve.layer2.access_edge.source_lockdown",
        "hp.procurve.layer2.access_edge.port_security",
    }


def test_hp_tagged_access_edge_is_reported_without_mechanism_noise(tmp_path):
    parser = HPProCurveParser(_source(tmp_path, "hp-edge-tagged.conf", '''; J9772A Configuration Editor; Created on release #YA.16.11.0001
vlan 10
 tagged 1
'''))
    parser.set_assessment_context(_context({"1": "access-edge"}))
    findings = _hp_findings(parser)
    assert [item.rule_id for item in findings] == ["hp.procurve.layer2.access_edge_trunk"]


def test_hp_unknown_release_disabled_and_unknown_role_ports_are_unassessed(tmp_path):
    parser = HPProCurveParser(_source(tmp_path, "hp-edge-unknown.conf", '''; J9772A Configuration Editor; Created on release #YA.17.01.0001
vlan 10
 untagged 1-2
interface 1 disable
'''))
    parser.set_assessment_context(_context({"1": "access-edge"}))
    assert _hp_findings(parser) == []
