from src.analyze.fortinet.plugins.fortios_baseline_plugin import PluginFortiOSBaseline
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.common.assessment import AssessmentContext
from src.devices.fortinet.fortios import FortiOSParser
from src.devices.juniper.junos import JunOSParser


def _parser(tmp_path, config, context=None):
    path = tmp_path / "fortios-aaa.conf"
    path.write_text(config, encoding="utf-8")
    parser = FortiOSParser(str(path))
    if context is not None:
        parser.set_assessment_context(context)
    return parser


def _findings(parser):
    plugin = PluginFortiOSBaseline()
    plugin.check_aaa_transport(parser)
    return plugin.get_issues()


def _junos_parser(tmp_path, config, context=None):
    path = tmp_path / "junos-aaa.conf"
    path.write_text(config, encoding="utf-8")
    parser = JunOSParser(str(path))
    if context is not None:
        parser.set_assessment_context(context)
    return parser


def _junos_findings(parser):
    plugin = PluginJunOSBaseline()
    plugin.check_aaa_transport(parser)
    return plugin.get_issues()


AAA_CONFIG = '''#config-version=FGT100F-7.4.6-FW-build0001-240101:opmode=0:vdom=1:user=admin
config user radius
edit "BROKEN-RADSEC"
set server "radius-a.example.test"
set secondary-server "radius-b.example.test"
set secret "do-not-leak-primary"
set secondary-secret "do-not-leak-secondary"
set transport-protocol tls
set radius-port 2083
set server-identity-check disable
set tls-min-proto-version TLSv1-1
set source-ip-interface "mgmt1"
set interface-select-method specify
set interface "mgmt1"
set vrf-select 12
next
edit "GOOD-RADSEC"
set server "radius-good.example.test"
set secret "do-not-leak-good"
set transport-protocol tls
set ca-cert "CORP-AAA-CA"
set client-cert "FGT-RADSEC-CLIENT"
set server-identity-check enable
set tls-min-proto-version TLSv1-2
set source-ip 192.0.2.10
next
edit "UDP-PROTECTED"
set server "192.0.2.20"
set secret "do-not-leak-udp"
set transport-protocol udp
next
edit "UDP-UNSAFE"
set server "192.0.2.21"
set secret "do-not-leak-unsafe"
set transport-protocol udp
set require-message-authenticator disable
next
edit "UNBOUND-BROKEN"
set server "radius-unused.example.test"
set secret "do-not-leak-unused"
set transport-protocol tls
set server-identity-check disable
set tls-min-proto-version SSLv3
next
end
config user group
edit "AAA-Admins"
set member "BROKEN-RADSEC" "GOOD-RADSEC" "LDAP-NOT-A-RADIUS-PROFILE"
config match
edit 1
set server-name "UDP-PROTECTED"
next
edit 2
set server-name "UDP-UNSAFE"
next
end
next
end
config system admin
edit "alice"
set remote-auth enable
set remote-group "AAA-Admins"
next
edit "bob"
set remote-auth enable
set remote-group "AAA-Admins"
next
edit "disabled-admin"
set status disable
set remote-auth enable
set remote-group "AAA-Admins"
next
end
'''


def test_fortios_typed_aaa_profiles_resolve_bindings_scope_and_source(tmp_path):
    context = AssessmentContext.from_mapping({
        "protected_aaa_profiles": ["root:UDP-PROTECTED"],
    })
    parser = _parser(tmp_path, AAA_CONFIG, context)
    profiles = {profile.name: profile for profile in parser.get_aaa_server_profiles()}

    broken = profiles["BROKEN-RADSEC"]
    assert broken.transport == "tls"
    assert broken.servers == ("radius-a.example.test", "radius-b.example.test")
    assert broken.port == "2083"
    assert broken.source_interface == "mgmt1"
    assert broken.interface_select_method == "specify"
    assert broken.interface == "mgmt1"
    assert broken.vrf == "12"
    assert broken.administrator_groups == ("AAA-Admins",)
    assert broken.administrators == ("alice", "bob")
    assert profiles["GOOD-RADSEC"].source_ip == "192.0.2.10"
    assert profiles["UDP-PROTECTED"].protected_path is True
    assert profiles["UDP-UNSAFE"].protected_path is False
    assert profiles["UNBOUND-BROKEN"].is_bound_for_administration is False

    rendered = repr(tuple(profiles.values())) + repr(
        tuple(item.text for profile in profiles.values() for item in profile.evidence)
    )
    assert "do-not-leak" not in rendered
    assert "<redacted>" not in rendered  # Secret fields are omitted, not merely masked.


def test_fortios_aaa_findings_are_bound_and_mechanism_specific(tmp_path):
    parser = _parser(tmp_path, AAA_CONFIG)
    findings = _findings(parser)
    assert [finding.rule_id for finding in findings] == [
        "fortinet.fortios.aaa.radsec_server_identity",
        "fortinet.fortios.aaa.radsec_tls_version",
        "fortinet.fortios.aaa.radius_message_authenticator",
    ]
    assert all("UNBOUND-BROKEN" not in finding.observation for finding in findings)
    assert all("alice" in finding.observation and "bob" in finding.observation for finding in findings)
    assert all("do-not-leak" not in " ".join(finding.evidence) for finding in findings)


def test_fortios_valid_radsec_and_legacy_radius_unknown_path_are_not_findings(tmp_path):
    parser = _parser(tmp_path, AAA_CONFIG)
    findings = _findings(parser)
    names = " ".join(finding.observation for finding in findings)
    assert "GOOD-RADSEC" not in names
    assert "UDP-PROTECTED" not in names


def test_fortios_pre_74_release_does_not_apply_radsec_semantics(tmp_path):
    parser = _parser(tmp_path, AAA_CONFIG.replace("-7.4.6-", "-7.2.11-"))
    profiles = parser.get_aaa_server_profiles()
    assert profiles and all(profile.radsec_supported is False for profile in profiles)
    assert _findings(parser) == []


def test_fortios_vdom_scope_and_all_usergroup_binding_do_not_cross_scopes(tmp_path):
    parser = _parser(tmp_path, '''#config-version=FGT100F-7.4.6-FW-build0001-240101:opmode=0:vdom=1:user=admin
config vdom
edit blue
config user radius
edit BLUE-RADIUS
set server radius-blue.example.test
set transport-protocol tls
set all-usergroup enable
set ca-cert BLUE-CA
next
end
config user group
edit BLUE-ADMINS
set member LDAP-BLUE
next
end
config system admin
edit blue-admin
set remote-auth enable
set remote-group BLUE-ADMINS
next
end
next
edit green
config user radius
edit UNUSED-GREEN
set server radius-green.example.test
set transport-protocol tls
set server-identity-check disable
next
end
next
end
''')
    profiles = {profile.name: profile for profile in parser.get_aaa_server_profiles()}
    assert profiles["BLUE-RADIUS"].scope == "blue"
    assert profiles["BLUE-RADIUS"].administrators == ("blue-admin",)
    assert profiles["UNUSED-GREEN"].scope == "green"
    assert profiles["UNUSED-GREEN"].administrators == ()
    assert _findings(parser) == []


def test_assessment_policy_validates_exact_protected_aaa_selectors():
    context = AssessmentContext.from_mapping({
        "protected_aaa_profiles": ["root:RADIUS-A"],
    })
    assert context.aaa_profile_has_protected_path("ROOT", "radius-a") is True
    assert context.aaa_profile_has_protected_path("root", "radius") is False

    for value in (["RADIUS-A"], [":RADIUS-A"], ["root:"], ["root:RADIUS-A", "ROOT:radius-a"]):
        try:
            AssessmentContext.from_mapping({"protected_aaa_profiles": value})
        except ValueError:
            pass
        else:
            raise AssertionError("invalid protected AAA profile selectors must fail closed")


def test_junos_resolves_complete_administrative_radsec_without_secrets(tmp_path):
    parser = _junos_parser(
        tmp_path,
        '''set version 24.4R2
set system authentication-order [ radius password ]
set system radius-server 192.0.2.10 port 2083
set system radius-server 192.0.2.10 tls trusted-ca-group CORP-AAA-CA
set system radius-server 192.0.2.10 tls mutual-authentication certificate-id JUNOS-CLIENT
set system radius-server 192.0.2.10 secret "DoNotLeak"
''',
    )
    profiles = parser.get_aaa_transport_profiles()
    assert len(profiles) == 1
    assert profiles[0].roles == ("authentication",)
    assert profiles[0].transport == "tls"
    assert profiles[0].port == "2083"
    assert profiles[0].trusted_ca_group == "CORP-AAA-CA"
    assert profiles[0].client_certificate_id == "JUNOS-CLIENT"
    assert _junos_findings(parser) == []
    assert "DoNotLeak" not in repr(profiles)


def test_junos_radsec_reports_missing_server_and_client_identity_bindings(tmp_path):
    parser = _junos_parser(
        tmp_path,
        '''set version 24.4R2
set system authentication-order [ radius password ]
set system radius-server 192.0.2.10 port 2083
set system radius-server 192.0.2.10 tls mutual-authentication
''',
    )
    assert [item.rule_id for item in _junos_findings(parser)] == [
        "juniper.junos.aaa.radsec_trust",
        "juniper.junos.aaa.radsec_client_certificate",
    ]


def test_junos_plain_radius_grades_only_explicit_message_authenticator_disable(tmp_path):
    context = AssessmentContext.from_mapping({
        "protected_aaa_profiles": ["system:192.0.2.10"],
    })
    parser = _junos_parser(
        tmp_path,
        '''set version 24.4R2
set system authentication-order [ radius password ]
set system radius-server 192.0.2.10 no-message-authenticator
set system radius-server 192.0.2.11 secret "$9$hidden"
''',
        context,
    )
    profiles = {item.address: item for item in parser.get_aaa_transport_profiles()}
    assert profiles["192.0.2.10"].protected_path is True
    assert profiles["192.0.2.11"].message_authenticator == "unknown"
    findings = _junos_findings(parser)
    assert [item.rule_id for item in findings] == [
        "juniper.junos.aaa.radius_message_authenticator"
    ]
    assert "separately declared protected path" in findings[0].observation


def test_junos_unbound_radius_definition_is_not_graded_as_admin_transport(tmp_path):
    parser = _junos_parser(
        tmp_path,
        '''set version 24.4R2
set system authentication-order password
set system radius-server 192.0.2.10 tls mutual-authentication
''',
    )
    assert parser.get_aaa_transport_profiles() == ()
    assert _junos_findings(parser) == []


def test_junos_accounting_specific_radsec_and_inheritance_boundary(tmp_path):
    parser = _junos_parser(
        tmp_path,
        '''set version 24.4R2
set system authentication-order [ radius password ]
set system radius-server 192.0.2.10 no-message-authenticator
set system accounting destination radius server 192.0.2.20 accounting-port 2083
set system accounting destination radius server 192.0.2.20 tls trusted-ca-group CORP-AAA-CA
set system accounting destination radius server 192.0.2.20 secret "DoNotLeak"
''',
    )
    profiles = parser.get_aaa_transport_profiles()
    assert [(item.address, item.roles, item.transport) for item in profiles] == [
        ("192.0.2.10", ("authentication",), "udp"),
        ("192.0.2.20", ("accounting",), "tls"),
    ]
    assert [item.rule_id for item in _junos_findings(parser)] == [
        "juniper.junos.aaa.radius_message_authenticator"
    ]
    assert "DoNotLeak" not in repr(profiles)

    inherited = _junos_parser(
        tmp_path,
        '''set version 24.4R2
set apply-groups AAA-TRANSPORT
set system authentication-order radius
set system radius-server 192.0.2.10 tls
''',
    )
    assert _junos_findings(inherited) == []
