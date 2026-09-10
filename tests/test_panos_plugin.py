import pytest

from src.analyze.paloalto.core.process_panos_conf import process_panos_conf
from src.analyze.paloalto.plugins.panos_checks_plugin import PluginPANOSChecks
from src.devices.common.models import KnowledgeState
from src.devices.paloalto.panos import PaloAltoPANOSParser


VULNERABLE_XML = """<config version="11.2.3">
  <mgt-config><users><entry name="admin"><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry></users></mgt-config>
  <devices><entry name="localhost.localdomain">
    <deviceconfig><system><hostname>edge-pa</hostname><password-complexity><enabled>no</enabled><minimum-length>0</minimum-length><minimum-uppercase-letters>0</minimum-uppercase-letters><minimum-lowercase-letters>0</minimum-lowercase-letters><minimum-numeric-letters>0</minimum-numeric-letters><minimum-special-characters>0</minimum-special-characters></password-complexity></system></deviceconfig>
    <network>
      <profiles><interface-management-profile><entry name="UNUSED-LEGACY"><http>yes</http></entry><entry name="EXPOSED"><http>yes</http><https>yes</https><ssh>yes</ssh><snmp>yes</snmp></entry></interface-management-profile></profiles>
      <interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="198.51.100.1/24"/></ip><interface-management-profile>EXPOSED</interface-management-profile></layer3></entry><entry name="ethernet1/2"><layer3><ip><entry name="10.0.0.1/24"/></ip></layer3></entry></ethernet></interface>
    </network>
    <vsys>
      <entry name="vsys1">
        <zone><entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone>
        <log-settings><profiles><entry name="FORWARD-SIEM"><match-list><entry name="traffic"><send-syslog><member>CORP-SYSLOG</member></send-syslog></entry></match-list></entry></profiles></log-settings>
        <rulebase><security><rules>
          <entry name="BROAD"><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source><destination><member>any</member></destination><source-user><member>any</member></source-user><category><member>any</member></category><application><member>any</member></application><service><member>any</member></service><action>allow</action></entry>
          <entry name="DISABLED-BROAD"><disabled>yes</disabled><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source><destination><member>any</member></destination><source-user><member>any</member></source-user><category><member>any</member></category><application><member>any</member></application><service><member>any</member></service><action>allow</action></entry>
          <entry name="RESTRICTED"><from><member>trust</member></from><to><member>untrust</member></to><source><member>CorpNet</member></source><destination><member>UpdateServers</member></destination><source-user><member>domain-users</member></source-user><category><member>any</member></category><application><member>ssl</member></application><service><member>application-default</member></service><action>allow</action><log-end>yes</log-end><log-setting>FORWARD-SIEM</log-setting><profile-setting><group><member>STRICT</member></group></profile-setting></entry>
        </rules></security></rulebase>
      </entry>
      <entry name="vsys2"><zone><entry name="trust"><network><layer3><member>ethernet1/2</member></layer3></network></entry></zone></entry>
    </vsys>
  </entry></devices>
</config>"""


SECURE_XML = """<config xmlns="urn:panos" version="11.2.3">
  <devices><entry name="localhost.localdomain">
    <deviceconfig><system><hostname>secure-pa</hostname><ssl-tls-service-profile>MGMT-TLS</ssl-tls-service-profile><dns-setting><servers><primary>192.0.2.53</primary><secondary>192.0.2.54</secondary></servers></dns-setting><ntp-servers><primary-ntp-server><ntp-server-address>192.0.2.123</ntp-server-address></primary-ntp-server><secondary-ntp-server><ntp-server-address>192.0.2.124</ntp-server-address></secondary-ntp-server></ntp-servers><update-schedule><threats><recurring><hourly><at>15</at><action>download-and-install</action></hourly></recurring></threats></update-schedule><log-settings><system><match-list><entry name="important"><send-syslog><member>CORP-SYSLOG</member></send-syslog></entry></match-list></system></log-settings><password-complexity><enabled>yes</enabled><minimum-length>14</minimum-length><minimum-uppercase-letters>1</minimum-uppercase-letters><minimum-lowercase-letters>1</minimum-lowercase-letters><minimum-numeric-letters>1</minimum-numeric-letters><minimum-special-characters>1</minimum-special-characters></password-complexity></system></deviceconfig>
    <network><profiles><interface-management-profile><entry name="MGMT-ONLY"><ssh>yes</ssh><https>yes</https><permitted-ip><entry name="192.0.2.0/24"/><entry name="2001:db8::/48"/></permitted-ip></entry></interface-management-profile></profiles><interface><ethernet><entry name="ethernet1/3"><layer3><ip><entry name="192.0.2.1/24"/></ip><interface-management-profile>MGMT-ONLY</interface-management-profile></layer3></entry></ethernet></interface></network>
    <vsys><entry name="vsys1"><zone><entry name="management"><network><layer3><member>ethernet1/3</member></layer3></network></entry></zone><log-settings><profiles><entry name="SIEM"><match-list><entry name="traffic"><send-syslog><member>CORP-SYSLOG</member></send-syslog></entry></match-list></entry></profiles></log-settings><rulebase><security><rules><entry name="ADMIN-UPDATES"><from><member>management</member></from><to><member>untrust</member></to><source><member>192.0.2.0/24</member></source><destination><member>UpdateServers</member></destination><source-user><member>admins</member></source-user><category><member>any</member></category><application><member>ssl</member></application><service><member>application-default</member></service><action>allow</action><log-end>yes</log-end><log-setting>SIEM</log-setting><profile-setting><group><member>STRICT</member></group></profile-setting></entry></rules></security></rulebase></entry></vsys>
  </entry></devices><shared><ssl-tls-service-profile><entry name="MGMT-TLS"><certificate>mgmt-signed-cert</certificate><protocol-settings><min-version>tls1-2</min-version><max-version>max</max-version></protocol-settings></entry></ssl-tls-service-profile></shared>
</config>"""


def _parse(tmp_path, content, name="panos.xml"):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return PaloAltoPANOSParser(str(path))


def _issues(parser):
    plugin = PluginPANOSChecks()
    plugin.analyze(parser)
    return plugin.get_issues()


def test_parser_resolves_real_profile_attachment_vsys_scope_and_metadata(tmp_path):
    parser = _parse(tmp_path, VULNERABLE_XML)
    assert parser.get_hostname() == "edge-pa"
    assert parser.get_version() == "11.2.3"
    assert parser.get_users()[0]["username"] == "admin"
    assert {profile.name for profile in parser.get_management_profiles()} == {"UNUSED-LEGACY", "EXPOSED"}
    assert parser.get_services() == {"telnet": False, "ssh": True, "http": True, "https": True}
    assert [(item.name, item.scope, item.zone) for item in parser.get_interfaces()] == [
        ("ethernet1/1", "vsys1", "untrust"),
        ("ethernet1/2", "vsys2", "trust"),
    ]
    assert [rule.name for rule in parser.get_security_rules()] == ["BROAD", "DISABLED-BROAD", "RESTRICTED"]
    assert parser.get_normalized_config().policies.state == KnowledgeState.KNOWN


def test_plugin_is_attachment_scope_disablement_and_reference_aware(tmp_path):
    issues = _issues(_parse(tmp_path, VULNERABLE_XML))
    assert [issue.rule_id for issue in issues] == [
        "paloalto.panos.management.http",
        "paloalto.panos.management.unrestricted_secure_service",
        "paloalto.panos.policy.broad_allow",
        "paloalto.panos.policy.log_forwarding",
        "paloalto.panos.policy.session_logging",
        "paloalto.panos.policy.security_profiles",
        "paloalto.panos.credentials.password_complexity",
        "paloalto.panos.admin.centralized_authentication",
        "paloalto.panos.ntp.servers",
        "paloalto.panos.dns.servers",
        "paloalto.panos.snmp.secure_user_missing",
        "paloalto.panos.management.tls_profile_missing",
        "paloalto.panos.updates.threat_content",
        "paloalto.panos.logging.system_forwarding",
    ]
    assert all(issue.references for issue in issues)
    assert all("UNUSED-LEGACY" not in " ".join(issue.evidence) for issue in issues)
    assert all("DISABLED-BROAD" not in issue.observation for issue in issues)


def test_secure_namespace_export_has_no_findings(tmp_path):
    parser = _parse(tmp_path, SECURE_XML)
    assert parser.get_hostname() == "secure-pa"
    assert _issues(parser) == []


def test_panorama_inheritance_is_explicitly_unknown(tmp_path):
    parser = _parse(tmp_path, '<config><devices><entry name="local"><device-group><entry name="DG"/></device-group></entry></devices></config>')
    issues = _issues(parser)
    assert parser.panorama_inheritance_unknown
    assert "not resolved" in parser.diagnostics[0]
    assert "paloalto.panos.analysis.panorama_inheritance_unknown" in {issue.rule_id for issue in issues}


def test_management_profile_resolution_is_device_scoped_and_mgt_is_distinct(tmp_path):
    parser = _parse(
        tmp_path,
        """<config version="11.2"><devices>
        <entry name="device-a"><deviceconfig><system><service><disable-http>no</disable-http><disable-ssh>no</disable-ssh></service></system></deviceconfig><network><profiles><interface-management-profile><entry name="SHARED"><http>yes</http></entry></interface-management-profile></profiles><interface><ethernet><entry name="ethernet1/1"><layer3><interface-management-profile>SHARED</interface-management-profile></layer3></entry></ethernet></interface></network></entry>
        <entry name="device-b"><network><profiles><interface-management-profile><entry name="SHARED"><https>yes</https></entry></interface-management-profile></profiles><interface><ethernet><entry name="ethernet1/2"><layer3><interface-management-profile>SHARED</interface-management-profile></layer3></entry></ethernet></interface></network></entry>
        </devices></config>""",
    )
    services = {
        (service.interface, service.protocol)
        for service in parser.get_normalized_config().management_services.items
    }
    assert services == {
        ("MGT", "http"),
        ("MGT", "ssh"),
        ("ethernet1/1", "http"),
        ("ethernet1/2", "https"),
    }
    management = PluginPANOSChecks()
    management.check_management(parser)
    assert [issue.rule_id for issue in management.get_issues()] == [
        "paloalto.panos.management.http",
        "paloalto.panos.management.http",
        "paloalto.panos.management.unrestricted_secure_service",
    ]


def test_public_processor_has_stable_unique_object_findings(tmp_path):
    identities = [
        (issue.rule_id, issue.evidence)
        for issue in process_panos_conf(_parse(tmp_path, VULNERABLE_XML)).values()
    ]
    assert len(identities) == len(set(identities))


def test_malformed_xml_surfaces_parser_error(tmp_path):
    path = tmp_path / "broken.xml"
    path.write_text("<config><devices>", encoding="utf-8")
    with pytest.raises(Exception):
        PaloAltoPANOSParser(str(path))
