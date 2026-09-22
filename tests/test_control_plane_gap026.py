import pytest

from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.analyze.cisco.asa.plugins.baseline_plugin import PluginASABaseline
from src.analyze.arista.plugins.arista_checks_plugin import PluginAristaChecks
from src.analyze.fortinet.plugins.fortios_baseline_plugin import PluginFortiOSBaseline
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.devices.arista.eos import AristaEOSParser
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.cisco.asa import CiscoASAParser
from src.devices.cisco.iosxe import CiscoIOSXEParser
from src.devices.fortinet.fortios import FortiOSParser
from src.devices.juniper.junos import JunOSParser


def _ios(tmp_path, config):
    path = tmp_path / "copp.conf"
    path.write_text(config, encoding="utf-8")
    return CiscoIOSParser(str(path))


def _asa(tmp_path, config):
    path = tmp_path / "connection-limits-asa.conf"
    path.write_text(config, encoding="utf-8")
    return CiscoASAParser(str(path))


def _junos(tmp_path, config):
    path = tmp_path / "protect-re.conf"
    path.write_text(config, encoding="utf-8")
    return JunOSParser(str(path))


def _eos(tmp_path, config):
    path = tmp_path / "control-plane-eos.conf"
    path.write_text(config, encoding="utf-8")
    return AristaEOSParser(str(path))


def _fortios(tmp_path, config):
    path = tmp_path / "dos-fortios.conf"
    path.write_text(config, encoding="utf-8")
    return FortiOSParser(str(path))


def _ios_findings(parser):
    plugin = PluginIOSBaseline()
    plugin.check_control_plane(parser)
    return plugin.get_issues()


def _asa_findings(parser):
    plugin = PluginASABaseline()
    plugin.check_connection_limits(parser)
    return plugin.get_issues()


def test_asa_attached_connection_limits_resolve_without_grading_finite_rates(tmp_path):
    parser = _asa(
        tmp_path,
        """ASA Version 9.20(3)
policy-map CONNECTION-PROTECTION
 class INTERNET-SERVICES
  set connection conn-max 4000 embryonic-conn-max 500 per-client-max 100
service-policy CONNECTION-PROTECTION interface outside
""",
    )
    policies = parser.get_connection_limit_policies()
    assert len(policies) == 1
    assert policies[0].attachment_scopes == ("interface outside",)
    assert dict(policies[0].limits) == {
        "conn-max": 4000,
        "embryonic-conn-max": 500,
        "per-client-max": 100,
    }
    assert _asa_findings(parser) == []


def test_asa_reports_only_effective_explicit_unlimited_connection_values(tmp_path):
    parser = _asa(
        tmp_path,
        """ASA Version 9.20(3)
policy-map type management first-match MANAGEMENT-PROTECTION
 class MANAGEMENT-TRAFFIC
  set connection conn-max 0 embryonic-conn-max 0
policy-map UNUSED
 class UNUSED-CLASS
  set connection conn-max 0
service-policy MANAGEMENT-PROTECTION interface outside
""",
    )
    policies = parser.get_connection_limit_policies()
    assert [(item.policy_type, item.policy_name) for item in policies] == [
        ("management", "MANAGEMENT-PROTECTION")
    ]
    findings = _asa_findings(parser)
    assert [item.rule_id for item in findings] == [
        "cisco.asa.control_plane.connection_limit_unbounded"
    ]
    assert "embryonic-conn-max" in findings[0].observation


def test_asa_connection_limit_removal_and_invalid_value_fail_closed(tmp_path):
    removed = _asa(
        tmp_path,
        """ASA Version 9.20(3)
policy-map CONNECTION-PROTECTION
 class INTERNET-SERVICES
  set connection conn-max 0
service-policy CONNECTION-PROTECTION interface outside
no service-policy CONNECTION-PROTECTION interface outside
""",
    )
    assert removed.get_connection_limit_policies() == ()

    invalid = _asa(
        tmp_path,
        """ASA Version 9.20(3)
policy-map CONNECTION-PROTECTION
 class INTERNET-SERVICES
  set connection conn-max invalid
service-policy CONNECTION-PROTECTION global
""",
    )
    assert [item.rule_id for item in _asa_findings(invalid)] == [
        "cisco.asa.control_plane.connection_limit_invalid"
    ]


def test_asa_connection_limit_release_boundary_does_not_claim_pix_parity(tmp_path):
    parser = _asa(
        tmp_path,
        """version 8.4
policy-map CONNECTION-PROTECTION
 class INTERNET-SERVICES
  set connection conn-max 0
service-policy CONNECTION-PROTECTION global
""",
    )
    assert _asa_findings(parser) == []


def _junos_findings(parser):
    plugin = PluginJunOSBaseline()
    plugin.check_routing_engine_filter(parser)
    return plugin.get_issues()


def _eos_findings(parser):
    plugin = PluginAristaChecks()
    plugin.check_control_plane(parser)
    return plugin.get_issues()


def _fortios_findings(parser):
    plugin = PluginFortiOSBaseline()
    plugin.check_dos_policies(parser)
    return plugin.get_issues()


def test_ios_copp_resolves_scope_class_acl_and_policing(tmp_path):
    parser = _ios(
        tmp_path,
        """version 17.9
ip access-list extended COPP-SSH
 permit tcp 192.0.2.0 0.0.0.255 any eq 22 log
class-map match-any COPP-SSH
 match access-group name COPP-SSH
policy-map HOST-POLICY
 class COPP-SSH
  police cir 128000 conform-action transmit exceed-action drop
control-plane host
 service-policy input HOST-POLICY
""",
    )
    policy = parser.get_control_plane_policies()[0]
    assert (policy.name, policy.scope, policy.direction) == (
        "HOST-POLICY",
        "host",
        "input",
    )
    assert policy.protection_state == "effective"
    assert policy.classes[0].selectors == ("match access-group name COPP-SSH",)
    assert policy.classes[0].selector_references == ("COPP-SSH",)
    assert policy.classes[0].selector_resolution == "resolved"
    assert policy.classes[0].policing
    assert policy.classes[0].discarding
    assert policy.classes[0].logging
    assert _ios_findings(parser) == []


@pytest.mark.parametrize(
    ("body", "expected_rule"),
    [
        (
            "control-plane\n service-policy input MISSING\n",
            "cisco.ios.control_plane.policy_reference",
        ),
        (
            "policy-map EMPTY\ncontrol-plane\n service-policy input EMPTY\n",
            "cisco.ios.control_plane.policy_empty",
        ),
        (
            "policy-map MARK-ONLY\n class class-default\n  set dscp cs6\n"
            "control-plane\n service-policy input MARK-ONLY\n",
            "cisco.ios.control_plane.policy_no_enforcement",
        ),
        (
            "policy-map INVALID\n class class-default\n  police malformed\n"
            "control-plane\n service-policy input INVALID\n",
            "cisco.ios.control_plane.policy_no_enforcement",
        ),
    ],
)
def test_ios_copp_rejects_dangling_empty_and_noop_policies(
    tmp_path, body, expected_rule
):
    findings = _ios_findings(_ios(tmp_path, "version 17.9\n" + body))
    assert [item.rule_id for item in findings] == [expected_rule]


def test_ios_copp_reports_each_unresolved_classification_boundary(tmp_path):
    parser = _ios(
        tmp_path,
        """version 17.9
class-map match-any EMPTY
class-map match-any DANGLING-ACL
 match access-group name DOES-NOT-EXIST
policy-map COPP
 class UNDEFINED
  police 100000
 class EMPTY
  police 100000
 class DANGLING-ACL
  police 100000
control-plane
 service-policy input COPP
""",
    )
    policy = parser.get_control_plane_policies()[0]
    assert [item.selector_resolution for item in policy.classes] == [
        "undefined-class",
        "empty-class",
        "unresolved-selector",
    ]
    findings = _ios_findings(parser)
    assert [item.rule_id for item in findings] == [
        "cisco.ios.control_plane.class_reference",
        "cisco.ios.control_plane.class_reference",
        "cisco.ios.control_plane.class_reference",
    ]


def test_ios_copp_honors_action_and_attachment_removal(tmp_path):
    parser = _ios(
        tmp_path,
        """version 17.9
policy-map COPP
 class class-default
  police 100000 conform-action transmit exceed-action drop
  no police
control-plane
 service-policy input COPP
 no service-policy input COPP
 service-policy output COPP
""",
    )
    policies = parser.get_control_plane_policies()
    assert [(item.direction, item.protection_state) for item in policies] == [
        ("output", "no-enforcement")
    ]
    assert [item.rule_id for item in _ios_findings(parser)] == [
        "cisco.ios.control_plane.copp"
    ]


def test_iosxe_system_generated_copp_is_preserved_as_unknown_content(tmp_path):
    path = tmp_path / "system-cpp.conf"
    path.write_text(
        "version 17.16\ncontrol-plane\n service-policy input system-cpp-policy\n",
        encoding="utf-8",
    )
    parser = CiscoIOSXEParser(str(path))
    policy = parser.get_control_plane_policies()[0]
    assert policy.protection_state == "platform-managed"
    assert policy.classes == ()
    assert _ios_findings(parser) == []


def test_junos_restricted_permit_list_uses_implicit_final_discard(tmp_path):
    parser = _junos(
        tmp_path,
        """set version 22.4R1.10
set interfaces lo0 unit 0 family inet filter input PROTECT-RE
set firewall family inet filter PROTECT-RE term trusted from source-address 192.0.2.0/24
set firewall family inet filter PROTECT-RE term trusted from protocol tcp
set firewall family inet filter PROTECT-RE term trusted then accept
""",
    )
    protection = parser.get_routing_engine_protections()[0]
    assert protection.protection_state == "effective"
    assert protection.terms[0].enforcement_state == "conditional-permit"
    assert _junos_findings(parser) == []


@pytest.mark.parametrize(
    ("body", "expected_rule"),
    [
        (
            "set interfaces lo0 unit 0 family inet filter input MISSING\n",
            "juniper.junos.control_plane.filter_reference",
        ),
        (
            "set firewall family inet filter EMPTY\n"
            "set interfaces lo0 unit 0 family inet filter input EMPTY\n",
            "juniper.junos.control_plane.filter_empty",
        ),
        (
            "set firewall family inet filter OPEN term all then accept\n"
            "set interfaces lo0 unit 0 family inet filter input OPEN\n",
            "juniper.junos.control_plane.filter_no_enforcement",
        ),
        (
            "set firewall family inet filter V4 term deny then discard\n"
            "set interfaces lo0 unit 0 family inet6 filter input V4\n",
            "juniper.junos.control_plane.filter_reference",
        ),
    ],
)
def test_junos_rejects_undefined_empty_open_and_wrong_family_filters(
    tmp_path, body, expected_rule
):
    findings = _junos_findings(_junos(tmp_path, "set version 22.4R1.10\n" + body))
    assert [item.rule_id for item in findings] == [expected_rule]


def test_junos_resolves_complete_and_incomplete_discard_policers(tmp_path):
    parser = _junos(
        tmp_path,
        """set version 22.4R1.10
set firewall policer COMPLETE if-exceeding bandwidth-limit 1m
set firewall policer COMPLETE if-exceeding burst-size-limit 15k
set firewall policer COMPLETE then discard
set firewall policer MARK-ONLY if-exceeding bandwidth-limit 2m
set firewall policer MARK-ONLY if-exceeding burst-size-limit 20k
set firewall policer MARK-ONLY then loss-priority high
set firewall family inet filter PROTECT-RE term icmp from protocol icmp
set firewall family inet filter PROTECT-RE term icmp then policer COMPLETE
set firewall family inet filter PROTECT-RE term icmp then accept
set firewall family inet filter PROTECT-RE term other from protocol udp
set firewall family inet filter PROTECT-RE term other then policer MARK-ONLY
set firewall family inet filter PROTECT-RE term other then accept
set interfaces lo0 unit 0 family inet filter input PROTECT-RE
""",
    )
    protection = parser.get_routing_engine_protections()[0]
    assert [(item.policer, item.policer_resolution) for item in protection.terms] == [
        ("COMPLETE", "complete"),
        ("MARK-ONLY", "incomplete"),
    ]
    assert protection.protection_state == "effective"
    assert [item.rule_id for item in _junos_findings(parser)] == [
        "juniper.junos.control_plane.policer_reference"
    ]


def test_junos_dangling_policer_does_not_become_implicit_protection(tmp_path):
    parser = _junos(
        tmp_path,
        """set version 22.4R1.10
set firewall family inet filter PROTECT-RE term all then policer MISSING
set firewall family inet filter PROTECT-RE term all then accept
set interfaces lo0 unit 0 family inet filter input PROTECT-RE
""",
    )
    protection = parser.get_routing_engine_protections()[0]
    assert protection.protection_state == "unresolved-policer"
    assert [item.rule_id for item in _junos_findings(parser)] == [
        "juniper.junos.control_plane.policer_reference"
    ]


def test_junos_ignores_transit_or_unreferenced_filter_definitions(tmp_path):
    parser = _junos(
        tmp_path,
        """set version 22.4R1.10
set firewall family inet filter STRONG term deny then discard
set interfaces ge-0/0/0 unit 0 family inet filter input STRONG
""",
    )
    assert parser.get_routing_engine_protections() == []
    assert [item.rule_id for item in _junos_findings(parser)] == [
        "juniper.junos.control_plane.lo0_filter"
    ]


def test_junos_apply_groups_keeps_absent_or_inherited_state_unknown(tmp_path):
    parser = _junos(
        tmp_path,
        """set version 22.4R1.10
set interfaces lo0 apply-groups ROUTING-ENGINE-PROTECTION
""",
    )
    assert _junos_findings(parser) == []


def test_eos_resolves_attached_acl_and_custom_copp_class(tmp_path):
    parser = _eos(
        tmp_path,
        """ip access-list CONTROL-PLANE
   10 permit tcp host 192.0.2.10 any eq ssh
class-map type control-plane match-any CUSTOM-SSH
   match ip access-group CONTROL-PLANE
policy-map type copp copp-system-policy
   class CUSTOM-SSH
      shape pps 2000
      bandwidth pps 1000
system control-plane
   ip access-group CONTROL-PLANE
""",
    )
    acl = parser.get_control_plane_acls()[0]
    assert (acl.family, acl.name, acl.protection_state) == (
        "ip",
        "CONTROL-PLANE",
        "effective",
    )
    policy_class = parser.get_copp_policy().classes[0]
    assert (policy_class.selector_reference, policy_class.selector_state) == (
        "CONTROL-PLANE",
        "resolved",
    )
    assert policy_class.enforcement_state == "effective"
    assert _eos_findings(parser) == []


@pytest.mark.parametrize(
    ("body", "expected_rule"),
    [
        (
            "system control-plane\n   ip access-group MISSING\n",
            "arista.eos.control_plane.acl_reference",
        ),
        (
            "ip access-list EMPTY\nsystem control-plane\n   ip access-group EMPTY\n",
            "arista.eos.control_plane.acl_empty",
        ),
        (
            "ip access-list OPEN\n   permit ip any any\n"
            "system control-plane\n   ip access-group OPEN\n",
            "arista.eos.control_plane.acl_no_enforcement",
        ),
        (
            "ip access-list ORDERED\n   permit ip any any\n   deny ip host 192.0.2.1 any\n"
            "system control-plane\n   ip access-group ORDERED\n",
            "arista.eos.control_plane.acl_no_enforcement",
        ),
    ],
)
def test_eos_rejects_dangling_empty_and_open_control_plane_acls(
    tmp_path, body, expected_rule
):
    assert [item.rule_id for item in _eos_findings(_eos(tmp_path, body))] == [
        expected_rule
    ]


def test_eos_custom_copp_reports_class_selector_and_action_boundaries(tmp_path):
    parser = _eos(
        tmp_path,
        """ip access-list VALID
   permit tcp host 192.0.2.10 any eq ssh
class-map type control-plane match-any EMPTY
class-map type control-plane match-any DANGLING
   match ip access-group MISSING
class-map type control-plane match-any NO-ACTION
   match ip access-group VALID
policy-map type copp copp-system-policy
   class UNDEFINED
      shape pps 1000
   class EMPTY
      shape pps 1000
   class DANGLING
      shape pps 1000
   class NO-ACTION
""",
    )
    classes = parser.get_copp_policy().classes
    assert [item.selector_state for item in classes] == [
        "undefined-class",
        "empty-class",
        "undefined-selector",
        "resolved",
    ]
    assert [item.rule_id for item in _eos_findings(parser)] == [
        "arista.eos.control_plane.copp_class_reference",
        "arista.eos.control_plane.copp_class_reference",
        "arista.eos.control_plane.copp_class_reference",
        "arista.eos.control_plane.copp_class_no_enforcement",
    ]


def test_eos_omitted_or_exported_builtin_copp_remains_platform_managed(tmp_path):
    assert _eos(tmp_path, "hostname leaf\n").get_copp_policy().resolution_state == "platform-managed"
    assert _eos_findings(_eos(tmp_path, "hostname leaf\n")) == []
    exported = _eos(
        tmp_path,
        "policy-map type copp copp-system-policy\n   class copp-system-lacp\n",
    )
    assert exported.get_copp_policy().classes[0].enforcement_state == "platform-managed"
    assert _eos_findings(exported) == []


def test_eos_honors_acl_and_rate_action_removals(tmp_path):
    acl_parser = _eos(
        tmp_path,
        """ip access-list REMOVED
   10 permit tcp host 192.0.2.10 any eq ssh
   no 10
system control-plane
   ip access-group REMOVED
""",
    )
    assert acl_parser.get_control_plane_acls()[0].protection_state == "empty"
    assert [item.rule_id for item in _eos_findings(acl_parser)] == [
        "arista.eos.control_plane.acl_empty"
    ]

    copp_parser = _eos(
        tmp_path,
        """ip access-list VALID
   permit tcp host 192.0.2.10 any eq ssh
class-map type control-plane match-any CUSTOM
   match ip access-group VALID
policy-map type copp copp-system-policy
   class CUSTOM
      shape pps 1000
      no shape
""",
    )
    assert copp_parser.get_copp_policy().classes[0].enforcement_state == "no-enforcement"
    assert [item.rule_id for item in _eos_findings(copp_parser)] == [
        "arista.eos.control_plane.copp_class_no_enforcement"
    ]


def test_eos_copp_deny_only_acl_does_not_resolve_as_a_selector(tmp_path):
    parser = _eos(
        tmp_path,
        """ip access-list DENY-ONLY
   deny ip any any
class-map type control-plane match-any CUSTOM
   match ip access-group DENY-ONLY
policy-map type copp copp-system-policy
   class CUSTOM
      shape pps 1000
""",
    )
    assert parser.get_copp_policy().classes[0].selector_state == "empty-selector"
    assert [item.rule_id for item in _eos_findings(parser)] == [
        "arista.eos.control_plane.copp_class_reference"
    ]


def test_eos_unreferenced_strong_acl_does_not_resolve_attached_name(tmp_path):
    parser = _eos(
        tmp_path,
        """ip access-list STRONG
   deny ip any any
system control-plane
   ip access-group MISSING
""",
    )
    assert [item.rule_id for item in _eos_findings(parser)] == [
        "arista.eos.control_plane.acl_reference"
    ]


def test_fortios_resolves_anomaly_scope_action_logging_and_threshold(tmp_path):
    parser = _fortios(
        tmp_path,
        """config firewall DoS-policy
edit 10
set interface wan1
set srcaddr all
set dstaddr WebVIP
set service HTTPS
config anomaly
edit tcp_syn_flood
set status enable
set action block
set log enable
set threshold 2000
next
end
next
end
""",
    )
    policy = parser.get_dos_policies()[0]
    assert (policy.family, policy.scope, policy.interfaces, policy.destinations) == (
        "ipv4",
        "root",
        ("wan1",),
        ("WebVIP",),
    )
    anomaly = policy.anomalies[0]
    assert (anomaly.enabled, anomaly.action, anomaly.logging) == (True, "block", True)
    assert (anomaly.threshold, anomaly.threshold_state) == ("2000", "explicit")
    assert _fortios_findings(parser) == []


def test_fortios_mixed_blocking_policy_does_not_hide_monitor_only_anomaly(tmp_path):
    parser = _fortios(
        tmp_path,
        """config firewall DoS-policy
edit 1
set interface wan1
config anomaly
edit tcp_syn_flood
set status enable
set action block
set log enable
next
edit udp_flood
set status enable
set action pass
next
end
next
end
""",
    )
    findings = _fortios_findings(parser)
    assert [item.rule_id for item in findings] == [
        "fortinet.fortios.dos.no_blocking_anomaly",
        "fortinet.fortios.dos.logging",
    ]
    assert "udp_flood" in findings[0].observation
    assert "tcp_syn_flood" not in findings[0].observation


def test_fortios_empty_policy_does_not_count_as_active_wan_protection(tmp_path):
    parser = _fortios(
        tmp_path,
        """#config-version=FGT60F-7.2.11-FW-build0001-240101:opmode=0:vdom=0:user=admin
config system interface
edit wan1
set role wan
next
end
config firewall DoS-policy
edit 1
set interface wan1
config anomaly
edit tcp_syn_flood
next
end
next
end
""",
    )
    assert [item.rule_id for item in _fortios_findings(parser)] == [
        "fortinet.fortios.dos.no_blocking_anomaly",
        "fortinet.fortios.dos.wan_policy_missing",
    ]


def test_fortios_invalid_explicit_threshold_is_reported_without_grading_rates(tmp_path):
    parser = _fortios(
        tmp_path,
        """config firewall DoS-policy6
edit 1
set interface wan1
config anomaly
edit icmp6_flood
set status enable
set action block
set log enable
set threshold invalid
next
end
next
end
""",
    )
    policy = parser.get_dos_policies()[0]
    assert policy.anomalies[0].threshold_state == "invalid"
    assert [item.rule_id for item in _fortios_findings(parser)] == [
        "fortinet.fortios.dos.threshold_invalid"
    ]


def test_fortios_uses_platform_default_threshold_without_claiming_adequacy(tmp_path):
    parser = _fortios(
        tmp_path,
        """config firewall DoS-policy
edit 1
set interface wan1
config anomaly
edit udp_flood
set status enable
set action block
set log enable
next
end
next
end
""",
    )
    assert parser.get_dos_policies()[0].anomalies[0].threshold_state == "platform-default"
    assert _fortios_findings(parser) == []


def test_fortios_disabled_blocking_anomaly_cannot_mask_active_monitor_only_one(tmp_path):
    parser = _fortios(
        tmp_path,
        """config firewall DoS-policy
edit 1
set interface wan1
config anomaly
edit tcp_syn_flood
set status disable
set action block
set log enable
next
edit udp_flood
set status enable
set action pass
set log enable
next
end
next
end
""",
    )
    findings = _fortios_findings(parser)
    assert [item.rule_id for item in findings] == [
        "fortinet.fortios.dos.no_blocking_anomaly"
    ]
    assert "udp_flood" in findings[0].observation
    assert "tcp_syn_flood" not in findings[0].observation
