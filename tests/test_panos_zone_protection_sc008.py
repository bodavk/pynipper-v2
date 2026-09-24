"""SC-008: qualified, explicit PAN-OS ingress-zone SYN flood state."""

from src.analyze.paloalto.plugins.panos_checks_plugin import PluginPANOSChecks
from src.common.assessment import AssessmentContext
from src.devices.paloalto.panos import PaloAltoPANOSParser


RULE_ID = "paloalto.panos.zone.syn_flood_disabled"
OTHER_RULE_ID = "paloalto.panos.zone.other_flood_disabled"
SCAN_RULE_ID = "paloalto.panos.zone.scan_allow"


def _scan(tmp_path, *, syn="no", udp=None, icmp=None, icmpv6=None, other_ip=None, attached=True,
          dos=False, dos_disabled=False,
          role="external", scan_action=None,
          panorama=False, extra_vsys=""):
    other_floods = "".join(
        f"<{name}><enable>{value}</enable></{name}>"
        for name, value in (("udp", udp), ("icmp", icmp), ("icmpv6", icmpv6), ("other-ip", other_ip))
        if value is not None
    )
    scan = (
        f'<scan><entry name="tcp-port-scan"><action><{scan_action}/></action>'
        '</entry></scan>' if scan_action else ''
    )
    profile = (
        '<entry name="ZP"><flood><tcp-syn><enable>' + syn
        + '</enable></tcp-syn>' + other_floods + '</flood>' + scan + '</entry>'
    )
    binding = '<zone-protection-profile>ZP</zone-protection-profile>' if attached else ""
    dos_rule = (
        '<rulebase><dos><rules><entry name="protect">'
        '<action><protect/></action>'
        + ('<disabled>yes</disabled>' if dos_disabled else '')
        + '</entry></rules></dos></rulebase>'
        if dos else ""
    )
    inherited = '<template><entry name="unmerged"/></template>' if panorama else ""
    xml = (
        '<config version="11.1"><devices><entry name="localhost.localdomain">'
        '<network><profiles><zone-protection-profile>' + profile
        + '</zone-protection-profile></profiles></network>'
        '<vsys><entry name="vsys1"><zone><entry name="outside">'
        '<network><layer3><member>ethernet1/1</member></layer3>' + binding
        + '</network></entry></zone>' + dos_rule + '</entry>' + extra_vsys + '</vsys>'
        '</entry></devices>' + inherited + '</config>'
    )
    path = tmp_path / "panos.xml"
    path.write_text(xml, encoding="utf-8")
    parser = PaloAltoPANOSParser(str(path))
    parser.set_assessment_context(AssessmentContext(
        interface_roles=(("ethernet1/1", role),)
    ))
    plugin = PluginPANOSChecks()
    plugin.check_zone_protection(parser)
    return parser, [item for item in plugin.get_issues() if item.rule_id == RULE_ID]


def test_attached_explicit_disabled_syn_flood_on_assessed_external_zone(tmp_path):
    parser, findings = _scan(tmp_path)
    assert len(findings) == 1
    assert parser.get_zone_protections()[0].syn_flood_state == "disabled"
    assert any("flood tcp-syn enable no" in item for item in findings[0].evidence)
    assert "ethernet1/1" in findings[0].observation


def test_unbound_internal_enabled_and_unqualified_states_are_not_findings(tmp_path):
    for options in (
        {"attached": False}, {"role": "internal"}, {"syn": "yes"},
        {"syn": "default"}, {"dos": True}, {"panorama": True},
    ):
        assert _scan(tmp_path, **options)[1] == []


def test_same_profile_in_another_vsys_without_assessed_external_interface(tmp_path):
    extra = (
        '<entry name="vsys2"><zone><entry name="inside">'
        '<network><layer3><member>ethernet1/2</member></layer3>'
        '<zone-protection-profile>ZP</zone-protection-profile>'
        '</network></entry></zone></entry>'
    )
    parser, findings = _scan(tmp_path, extra_vsys=extra)
    assert len(parser.get_zone_protections()) == 2
    assert len(findings) == 1
    assert "vsys1" in findings[0].observation


def test_disabled_dos_rule_is_not_treated_as_an_alternative(tmp_path):
    _, findings = _scan(tmp_path, dos=True, dos_disabled=True)
    assert len(findings) == 1


def test_explicit_udp_and_icmp_flood_disablement_is_independent_of_syn(tmp_path):
    parser, findings = _scan(tmp_path, syn="yes", udp="no", icmp="no")
    assert findings == []
    assert parser.get_zone_protections()[0].disabled_other_floods == ("udp", "icmp")
    plugin = PluginPANOSChecks()
    plugin.check_zone_protection(parser)
    other = [item for item in plugin.get_issues() if item.rule_id == OTHER_RULE_ID]
    assert len(other) == 1
    assert "UDP, ICMP" in other[0].observation
    assert any("flood udp enable no" in value for value in other[0].evidence)


def test_other_flood_disablement_respects_dos_alternative(tmp_path):
    parser, _ = _scan(tmp_path, syn="yes", udp="no", dos=True)
    plugin = PluginPANOSChecks()
    plugin.check_zone_protection(parser)
    assert not [item for item in plugin.get_issues() if item.rule_id == OTHER_RULE_ID]


def test_explicit_scan_allow_on_attached_external_zone(tmp_path):
    parser, _ = _scan(tmp_path, syn="yes", scan_action="allow")
    assert parser.get_zone_protections()[0].allowed_scans == ("tcp-port-scan",)
    plugin = PluginPANOSChecks()
    plugin.check_zone_protection(parser)
    findings = [item for item in plugin.get_issues() if item.rule_id == SCAN_RULE_ID]
    assert len(findings) == 1
    assert any("scan tcp-port-scan action allow" in value for value in findings[0].evidence)


def test_alert_scan_and_unbound_profile_do_not_report(tmp_path):
    for options in ({"scan_action": "alert"},
                    {"scan_action": "block"},
                    {"scan_action": "allow", "attached": False},
                    {"scan_action": "allow", "role": "internal"},
                    {"scan_action": "allow", "panorama": True}):
        parser, _ = _scan(tmp_path, syn="yes", **options)
        plugin = PluginPANOSChecks()
        plugin.check_zone_protection(parser)
        assert not [item for item in plugin.get_issues() if item.rule_id == SCAN_RULE_ID]


def test_dos_flood_alternative_does_not_override_scan_allow(tmp_path):
    parser, _ = _scan(tmp_path, syn="yes", scan_action="allow", dos=True)
    plugin = PluginPANOSChecks()
    plugin.check_zone_protection(parser)
    assert [item.rule_id for item in plugin.get_issues()] == [SCAN_RULE_ID]


def test_icmpv6_and_other_ip_flood_disablement_is_reported(tmp_path):
    parser, _ = _scan(tmp_path, syn="yes", icmp="yes", icmpv6="no", other_ip="no")
    assert parser.get_zone_protections()[0].disabled_other_floods == ("icmpv6", "other-ip")
    plugin = PluginPANOSChecks()
    plugin.check_zone_protection(parser)
    other, = [item for item in plugin.get_issues() if item.rule_id == OTHER_RULE_ID]
    assert "ICMPV6, OTHER-IP" in other.observation


def test_enabled_or_omitted_icmpv6_and_other_ip_are_not_reported(tmp_path):
    parser, _ = _scan(tmp_path, syn="yes", icmpv6="yes")
    assert parser.get_zone_protections()[0].disabled_other_floods == ()
