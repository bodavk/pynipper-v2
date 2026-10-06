"""CIS Palo Alto 6.4: DNS sinkhole on anti-spyware profiles in use."""

import pytest

from src.analyze.common.issue import FindingBasis
from src.analyze.paloalto.plugins.panos_checks_plugin import PluginPANOSChecks
from src.devices.paloalto.panos import PaloAltoPANOSParser

RULE = ('<entry name="out"><from><member>trust</member></from><to><member>untrust</member></to>'
        '<source><member>any</member></source><destination><member>any</member></destination>'
        '<source-user><member>any</member></source-user><category><member>any</member></category>'
        '<application><member>any</member></application><service><member>application-default</member></service>'
        '<action>allow</action><profile-setting><profiles><spyware><member>AS</member></spyware></profiles></profile-setting></entry>')


def _findings(tmp_path, botnet, rule=RULE):
    xml = ('<config version="11.1.0"><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
           f'<profiles><spyware><entry name="AS">{botnet}<rules><entry name="r"><action><reset-both/></action>'
           '<severity><member>critical</member></severity></entry></rules></entry></spyware></profiles>'
           f'<rulebase><security><rules>{rule}</rules></security></rulebase></entry></vsys></entry></devices></config>')
    path = tmp_path / "pan.xml"
    path.write_text(xml, encoding="utf-8")
    plugin = PluginPANOSChecks()
    plugin.check_dns_sinkhole(PaloAltoPANOSParser(str(path)))
    return plugin.get_issues()


def lists(action):
    return (f'<botnet-domains><lists><entry name="default-paloalto-dns"><action><{action}/></action></entry></lists>'
            '<sinkhole><ipv4-address>sinkhole.paloaltonetworks.com</ipv4-address></sinkhole></botnet-domains>')


@pytest.mark.parametrize("botnet,basis", [
    (lists("alert"), FindingBasis.EXPLICIT_VALUE),
    (lists("allow"), FindingBasis.EXPLICIT_VALUE),
    ("", FindingBasis.MISSING_EXPLICIT_SETTING),
])
def test_missing_or_non_sinkhole_action(tmp_path, botnet, basis):
    [finding] = _findings(tmp_path, botnet)
    assert finding.rule_id == "paloalto.panos.profile.dns_sinkhole" and finding.basis is basis


@pytest.mark.parametrize("botnet", [lists("sinkhole"), lists("default")])
def test_sinkhole_or_vendor_default_action_is_not_reported(tmp_path, botnet):
    assert _findings(tmp_path, botnet) == []


def test_unused_profile_is_not_reported(tmp_path):
    assert _findings(tmp_path, lists("alert"), RULE.replace("<member>AS</member>", "<member>OTHER</member>")) == []
