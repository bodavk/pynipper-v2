"""SC-008: qualified, explicit PAN-OS ingress-zone SYN flood state."""

from src.analyze.paloalto.plugins.panos_checks_plugin import PluginPANOSChecks
from src.common.assessment import AssessmentContext
from src.devices.paloalto.panos import PaloAltoPANOSParser


RULE_ID = "paloalto.panos.zone.syn_flood_disabled"


def _scan(tmp_path, *, syn="no", attached=True, dos=False, dos_disabled=False,
          role="external",
          panorama=False, extra_vsys=""):
    profile = (
        '<entry name="ZP"><flood><tcp-syn><enable>' + syn
        + '</enable></tcp-syn></flood></entry>'
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
