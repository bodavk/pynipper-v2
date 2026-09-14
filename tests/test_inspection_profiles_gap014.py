from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.analyze.fortinet.plugins.fortios_baseline_plugin import PluginFortiOSBaseline
from src.analyze.paloalto.core.process_panos_conf import process_panos_conf
from src.analyze.paloalto.plugins.panos_checks_plugin import PluginPANOSChecks
from src.devices.fortinet.fortios import FortiOSParser
from src.devices.paloalto.panos import PaloAltoPANOSParser


def _panos(tmp_path, xml: str) -> PaloAltoPANOSParser:
    path = tmp_path / "gap014-panos.xml"
    path.write_text(xml, encoding="utf-8")
    return PaloAltoPANOSParser(str(path))


def _fortios(tmp_path, config: str) -> FortiOSParser:
    path = tmp_path / "gap014-fortios.conf"
    path.write_text(config, encoding="utf-8")
    return FortiOSParser(str(path))


def _panos_policy(name: str, profile: str, disabled: bool = False) -> str:
    disabled_xml = "<disabled>yes</disabled>" if disabled else ""
    return (
        f'<entry name="{name}">{disabled_xml}<from><member>trust</member></from>'
        '<to><member>untrust</member></to><source><member>Corp</member></source>'
        '<destination><member>Servers</member></destination><source-user><member>users</member>'
        '</source-user><category><member>any</member></category><application><member>ssl</member></application>'
        '<service><member>application-default</member></service><action>allow</action>'
        '<log-end>yes</log-end><profile-setting><profiles><virus>'
        f'<member>{profile}</member></virus></profiles></profile-setting></entry>'
    )


def test_panos_resolves_shared_profiles_with_vsys_override_and_isolation(tmp_path):
    parser = _panos(
        tmp_path,
        "<config><shared><profiles><virus>"
        '<entry name="SHARED"><decoder><entry name="http"><action>reset-both</action>'
        '</entry></decoder></entry></virus></profiles></shared><devices><entry name="local"><vsys>'
        '<entry name="vsys1"><profiles><virus>'
        '<entry name="SHARED"><decoder><entry name="http"><action>allow</action></entry>'
        '</decoder></entry></virus></profiles><rulebase><security><rules>'
        + _panos_policy("LOCAL-WEAK", "SHARED")
        + _panos_policy("WRONG-VSYS", "RED-ONLY")
        + _panos_policy("DISABLED", "RED-ONLY", disabled=True)
        + '</rules></security></rulebase></entry><entry name="vsys2"><profiles><virus>'
        '<entry name="RED-ONLY"><decoder><entry name="http"><action>reset-both</action>'
        "</entry></decoder></entry></virus></profiles><rulebase><security><rules>"
        + _panos_policy("SHARED-STRONG", "SHARED")
        + "</rules></security></rulebase></entry></vsys></entry></devices></config>",
    )

    inspections = {item.rule_name: item for item in parser.get_security_inspection()}
    assert inspections["LOCAL-WEAK"].profiles[0].definition_scope == "vsys1"
    assert inspections["LOCAL-WEAK"].profiles[0].content_state == "nonblocking"
    assert inspections["SHARED-STRONG"].profiles[0].definition_scope == "shared"
    assert inspections["SHARED-STRONG"].profiles[0].content_state == "configured"
    assert inspections["WRONG-VSYS"].profiles[0].resolution_state == "unresolved"
    assert "DISABLED" not in inspections

    plugin = PluginPANOSChecks()
    plugin.check_security_rules(parser)
    material = [
        item
        for item in plugin.get_issues()
        if item.rule_id.startswith("paloalto.panos.policy.security_profile_")
    ]
    assert [(item.rule_id, "LOCAL-WEAK" in item.observation) for item in material] == [
        ("paloalto.panos.policy.security_profile_ineffective", True),
        ("paloalto.panos.policy.security_profile_unresolved", False),
    ]
    assert "WRONG-VSYS" in material[1].observation


def test_panos_group_empty_and_weak_members_are_attached_findings_only(tmp_path):
    parser = _panos(
        tmp_path,
        """<config><devices><entry name="local"><vsys><entry name="vsys1">
        <profiles><vulnerability><entry name="WEAK"><rules><entry name="all"><action><alert/></action></entry></rules></entry></vulnerability>
        <virus><entry name="UNBOUND"><decoder><entry name="http"><action>allow</action></entry></decoder></entry></virus></profiles>
        <profile-group><entry name="WEAK-GROUP"><vulnerability><member>WEAK</member></vulnerability></entry><entry name="EMPTY-GROUP"/></profile-group>
        <rulebase><security><rules>
        <entry name="WEAK-RULE"><from><member>trust</member></from><to><member>untrust</member></to><source><member>Corp</member></source><destination><member>Servers</member></destination><application><member>ssl</member></application><service><member>application-default</member></service><action>allow</action><log-end>yes</log-end><profile-setting><group><member>WEAK-GROUP</member></group></profile-setting></entry>
        <entry name="EMPTY-RULE"><from><member>trust</member></from><to><member>untrust</member></to><source><member>Corp</member></source><destination><member>Servers</member></destination><application><member>ssl</member></application><service><member>application-default</member></service><action>allow</action><log-end>yes</log-end><profile-setting><group><member>EMPTY-GROUP</member></group></profile-setting></entry>
        </rules></security></rulebase></entry></vsys></entry></devices></config>""",
    )
    plugin = PluginPANOSChecks()
    plugin.check_security_rules(parser)
    findings = [
        item
        for item in plugin.get_issues()
        if item.rule_id == "paloalto.panos.policy.security_profile_ineffective"
    ]
    assert len(findings) == 2
    combined = " ".join(item.observation for item in findings)
    assert "WEAK-RULE" in combined and "EMPTY-RULE" in combined
    assert "UNBOUND" not in combined


def test_panos_panorama_unresolved_profile_remains_unknown(tmp_path):
    parser = _panos(
        tmp_path,
        "<config><devices><entry name=\"local\"><device-group><entry name=\"DG\"/></device-group>"
        '<vsys><entry name="vsys1"><rulebase><security><rules>'
        + _panos_policy("INHERITED", "CENTRAL")
        + "</rules></security></rulebase></entry></vsys></entry></devices></config>",
    )
    assert parser.get_security_inspection()[0].profiles[0].resolution_state == "unknown-inherited"
    plugin = PluginPANOSChecks()
    plugin.check_security_rules(parser)
    assert not any(
        item.rule_id == "paloalto.panos.policy.security_profile_unresolved"
        for item in plugin.get_issues()
    )


def _forti_policy(policy_id: int, sensor: str, disabled: bool = False) -> str:
    status = "set status disable\n" if disabled else ""
    return (
        f"edit {policy_id}\n{status}set srcintf lan\nset dstintf wan1\n"
        "set action accept\nset logtraffic all\nset utm-status enable\n"
        f"set ips-sensor {sensor}\nnext\n"
    )


def test_fortios_resolves_global_profiles_with_vdom_override_and_isolation(tmp_path):
    parser = _fortios(
        tmp_path,
        """config global
config ips sensor
edit SHARED
config entries
edit 1
set action block
next
end
next
end
end
config vdom
edit blue
config system interface
edit wan1
set role wan
next
edit lan
set role lan
next
end
config ips sensor
edit SHARED
config entries
edit 1
set action pass
next
end
next
end
config firewall policy
"""
        + _forti_policy(1, "SHARED")
        + _forti_policy(2, "RED-ONLY")
        + _forti_policy(3, "RED-ONLY", disabled=True)
        + """end
next
edit red
config system interface
edit wan1
set role wan
next
edit lan
set role lan
next
end
config ips sensor
edit RED-ONLY
config entries
edit 1
set action block
next
end
next
end
config firewall policy
"""
        + _forti_policy(4, "SHARED")
        + "end\nnext\nend\n",
    )
    inspections = {(item.scope, item.policy_name): item for item in parser.get_security_inspection()}
    assert inspections[("blue", "1")].profiles[0].definition_scope == "blue"
    assert inspections[("blue", "1")].profiles[0].content_state == "nonblocking"
    assert inspections[("red", "4")].profiles[0].definition_scope == "global"
    assert inspections[("blue", "2")].profiles[0].resolution_state == "unresolved"
    assert ("blue", "3") not in inspections

    plugin = PluginFortiOSBaseline()
    plugin.check_logging_and_policy_profiles(parser)
    findings = [
        item
        for item in plugin.get_issues()
        if item.rule_id.startswith("fortinet.fortios.policy.security_profile_")
    ]
    assert [item.rule_id for item in findings] == [
        "fortinet.fortios.policy.security_profile_ineffective",
        "fortinet.fortios.policy.security_profile_unresolved",
    ]


def test_fortios_profile_group_empty_and_weak_members_are_resolved(tmp_path):
    parser = _fortios(
        tmp_path,
        """config system interface
edit wan1
set role wan
next
edit lan
set role lan
next
end
config ips sensor
edit WEAK
config entries
edit 1
set status enable
set default-action pass
set action default
next
end
next
edit UNBOUND
config entries
edit 1
set action pass
next
end
next
end
config firewall profile-group
edit WEAK-GROUP
set ips-sensor WEAK
next
edit EMPTY-GROUP
next
end
config firewall policy
edit 1
set srcintf lan
set dstintf wan1
set action accept
set logtraffic all
set utm-status enable
set profile-type group
set profile-group WEAK-GROUP
next
edit 2
set srcintf lan
set dstintf wan1
set action accept
set logtraffic all
set utm-status enable
set profile-type group
set profile-group EMPTY-GROUP
next
end
""",
    )
    plugin = PluginFortiOSBaseline()
    plugin.check_logging_and_policy_profiles(parser)
    findings = [
        item
        for item in plugin.get_issues()
        if item.rule_id == "fortinet.fortios.policy.security_profile_ineffective"
    ]
    assert len(findings) == 2
    combined = " ".join(item.observation for item in findings)
    assert "ips-sensor 'WEAK'" in combined and "EMPTY-GROUP" in combined
    assert "UNBOUND" not in combined


def test_controller_unknowns_and_public_processors_preserve_new_findings(tmp_path):
    forti = _fortios(
        tmp_path,
        """config system central-management
set type fortimanager
end
config system interface
edit wan1
set role wan
next
edit lan
next
end
config firewall policy
edit 1
set srcintf lan
set dstintf wan1
set action accept
set logtraffic all
set utm-status enable
set ips-sensor CENTRAL
next
end
""",
    )
    assert forti.get_security_inspection()[0].profiles[0].resolution_state == "unknown-inherited"
    forti_plugin = PluginFortiOSBaseline()
    forti_plugin.check_logging_and_policy_profiles(forti)
    assert not any(
        item.rule_id == "fortinet.fortios.policy.security_profile_unresolved"
        for item in forti_plugin.get_issues()
    )

    weak_forti = _fortios(
        tmp_path,
        """config system interface
edit wan1
set role wan
next
edit lan
next
end
config ips sensor
edit EMPTY
next
end
config firewall policy
"""
        + _forti_policy(7, "EMPTY")
        + "end\n",
    )
    assert "fortinet.fortios.policy.security_profile_ineffective" in {
        item.rule_id for item in process_fortios_conf(weak_forti).values()
    }

    panos = _panos(
        tmp_path,
        "<config><devices><entry><vsys><entry name=\"vsys1\"><profiles><virus>"
        '<entry name="EMPTY"/></virus></profiles><rulebase><security><rules>'
        + _panos_policy("EMPTY", "EMPTY")
        + "</rules></security></rulebase></entry></vsys></entry></devices></config>",
    )
    assert "paloalto.panos.policy.security_profile_ineffective" in {
        item.rule_id for item in process_panos_conf(panos).values()
    }
