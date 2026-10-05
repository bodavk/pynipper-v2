"""SC-061: CIS PAN-OS follow-ups (User-ID on untrusted zones, hygiene)."""

from src.analyze.common.guidance import guidance_for
from src.analyze.paloalto.plugins.panos_checks_plugin import PluginPANOSChecks
from src.common.assessment import AssessmentContext
from src.devices.paloalto.panos import PaloAltoPANOSParser


def _rules(tmp_path, zone_extra, role="external"):
    xml = ('<config version="11.1"><devices><entry name="localhost.localdomain"><deviceconfig><system>'
           '<hostname>fw</hostname></system></deviceconfig><vsys><entry name="vsys1"><zone><entry name="untrust">'
           '<network><layer3><member>ethernet1/1</member></layer3></network>' + zone_extra +
           '</entry></zone></entry></vsys></entry></devices></config>')
    path = tmp_path / "panos.xml"
    path.write_text(xml, encoding="utf-8")
    parser = PaloAltoPANOSParser(str(path))
    parser.set_assessment_context(AssessmentContext.from_mapping({"interface_roles": {"ethernet1/1": role}}))
    plugin = PluginPANOSChecks()
    plugin.check_cis_follow_ups(parser)
    return {item.rule_id: item for item in plugin.get_issues()}


def test_user_id_on_external_zone(tmp_path):
    rules = _rules(tmp_path, "<enable-user-identification>yes</enable-user-identification>")
    assert "paloalto.panos.user_id.untrusted_zone" in rules and guidance_for("paloalto.panos.user_id.untrusted_zone")
    assert "paloalto.panos.user_id.untrusted_zone" not in _rules(
        tmp_path, "<enable-user-identification>yes</enable-user-identification>", role="internal")
    assert "CIS 4.1" in rules["paloalto.panos.hardening.cis_hygiene"].observation
