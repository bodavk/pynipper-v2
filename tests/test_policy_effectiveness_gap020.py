import time

import pytest

from src.devices.common.policy_semantics import (
    AddressInterval,
    NetworkSemantics,
    ProofState,
    ServiceInterval,
    ServiceSemantics,
    network_covers,
    service_covers,
    static_values_cover,
)
from src.analyze.paloalto.plugins.panos_checks_plugin import PluginPANOSChecks
from src.devices.paloalto.panos import PaloAltoPANOSParser
from src.devices.cisco.asa import CiscoASAParser
from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.cisco.iosxe import CiscoIOSXEParser
from src.analyze.fortinet.plugins.fortios_baseline_plugin import PluginFortiOSBaseline
from src.devices.fortinet.fortios import FortiOSParser
from src.analyze.juniper.junos.plugins.junos_checks_plugin import PluginJunOSChecks
from src.devices.juniper.junos import JunOSParser
from src.analyze.juniper.plugins.screenos_checks_plugin import PluginScreenOSChecks
from src.devices.juniper.screenos import JuniperScreenOSParser
from src.analyze.sonicwall.plugins.sonicos_checks_plugin import PluginSonicOSChecks
from src.devices.sonicwall.sonicos import SonicOSParser


def _parse(tmp_path, xml: str, name: str = "policy.xml") -> PaloAltoPANOSParser:
    path = tmp_path / name
    path.write_text(xml, encoding="utf-8")
    return PaloAltoPANOSParser(str(path))


def _rule(name, source, destination, service, action="allow", extra="") -> str:
    return f"""<entry name="{name}">{extra}
      <from><member>trust</member></from><to><member>untrust</member></to>
      <source><member>{source}</member></source>
      <destination><member>{destination}</member></destination>
      <source-user><member>any</member></source-user><category><member>any</member></category>
      <application><member>any</member></application><service><member>{service}</member></service>
      <action>{action}</action></entry>"""


def _config(objects: str, rules: str, *, extra_vsys: str = "", nat: str = "") -> str:
    return f"""<config><devices><entry name="fw-a"><vsys><entry name="vsys1">
      {objects}<rulebase>{nat}<security><rules>{rules}</rules></security></rulebase>
      </entry>{extra_vsys}</vsys></entry></devices></config>"""


STATIC_OBJECTS = """
<address><entry name="WIDE"><ip-netmask>10.0.0.0/8</ip-netmask></entry>
<entry name="NARROW"><ip-range>10.20.0.0-10.20.255.255</ip-range></entry>
<entry name="HOST"><ip-netmask>192.0.2.42</ip-netmask></entry>
<entry name="V6-WIDE"><ip-netmask>2001:db8::/32</ip-netmask></entry>
<entry name="V6-NARROW"><ip-netmask>2001:db8:1::/48</ip-netmask></entry></address>
<address-group><entry name="WIDE-GROUP"><static><member>WIDE</member></static></entry></address-group>
<service><entry name="WEB-RANGE"><protocol><tcp><port>8000-8999</port></tcp></protocol></entry>
<entry name="WEB-SUB"><protocol><tcp><port>8440-8450</port></tcp></protocol></entry>
<entry name="WEB-ONE"><protocol><tcp><port>8443</port></tcp></protocol></entry></service>
<service-group><entry name="WEB-GROUP"><members><member>WEB-RANGE</member></members></entry></service-group>
"""


def _effectiveness(parser):
    plugin = PluginPANOSChecks()
    plugin.check_rule_effectiveness(parser)
    return plugin.get_issues()


def test_shared_primitives_distinguish_proof_disproof_and_unknown():
    wide = NetworkSemantics(intervals=(AddressInterval(4, 0, 255),))
    narrow = NetworkSemantics(intervals=(AddressInterval(4, 20, 30),))
    partial = NetworkSemantics(intervals=(AddressInterval(4, 250, 300),))
    unknown = NetworkSemantics(complete=False, unresolved=("dynamic",))
    assert network_covers(wide, narrow) == ProofState.PROVEN
    assert network_covers(wide, partial) == ProofState.DISPROVEN
    assert network_covers(wide, unknown) == ProofState.UNKNOWN
    assert static_values_cover(("any",), ("trust",)) == ProofState.PROVEN
    assert static_values_cover((), ("trust",)) == ProofState.UNKNOWN
    assert service_covers(
        ServiceSemantics(intervals=(ServiceInterval("tcp", 80, 90),)),
        ServiceSemantics(intervals=(ServiceInterval("tcp", 85, 85),)),
    ) == ProofState.PROVEN


@pytest.mark.parametrize(
    "family,wide,narrow",
    [(4, "WIDE-GROUP", "NARROW"), (6, "V6-WIDE", "V6-NARROW")],
)
def test_panos_static_containment_proves_shadow_and_redundancy(tmp_path, family, wide, narrow):
    rules = (
        _rule("PARENT", wide, "HOST", "WEB-GROUP")
        + _rule("SHADOW", narrow, "HOST", "WEB-SUB", "deny")
        + _rule("REDUNDANT", narrow, "HOST", "WEB-ONE")
    )
    findings = _effectiveness(_parse(tmp_path, _config(STATIC_OBJECTS, rules), f"v{family}.xml"))
    assert [item.rule_id for item in findings] == [
        "paloalto.panos.policy.shadowed_rule",
        "paloalto.panos.policy.redundant_rule",
    ]


def test_partial_overlap_and_protocol_mismatch_do_not_prove_coverage(tmp_path):
    objects = STATIC_OBJECTS + """
      <address><entry name="PART-A"><ip-range>198.51.100.0-198.51.100.127</ip-range></entry>
      <entry name="PART-B"><ip-netmask>198.51.100.0/24</ip-netmask></entry></address>
      <service><entry name="UDP-WEB"><protocol><udp><port>8443</port></udp></protocol></entry></service>
    """
    rules = _rule("PARTIAL", "PART-A", "HOST", "WEB-ONE") + _rule("WIDER", "PART-B", "HOST", "WEB-ONE", "deny")
    rules += _rule("UDP", "NARROW", "HOST", "UDP-WEB", "deny")
    assert _effectiveness(_parse(tmp_path, _config(objects, rules))) == []


@pytest.mark.parametrize(
    "objects,rules,nat",
    [
        (
            STATIC_OBJECTS + '<address-group><entry name="DYNAMIC"><dynamic><filter>prod</filter></dynamic></entry></address-group>',
            _rule("DYN-A", "DYNAMIC", "HOST", "WEB-RANGE") + _rule("DYN-B", "NARROW", "HOST", "WEB-SUB", "deny"),
            "",
        ),
        (
            STATIC_OBJECTS + '<address-group><entry name="CYCLE-A"><static><member>CYCLE-B</member></static></entry><entry name="CYCLE-B"><static><member>CYCLE-A</member></static></entry></address-group>',
            _rule("CYCLE-A", "CYCLE-A", "HOST", "WEB-RANGE") + _rule("CYCLE-B", "CYCLE-B", "HOST", "WEB-SUB", "deny"),
            "",
        ),
        (
            STATIC_OBJECTS,
            _rule("APP-A", "WIDE", "HOST", "WEB-RANGE").replace("<member>any</member></application>", "<member>ssl</member></application>")
            + _rule("APP-B", "NARROW", "HOST", "WEB-SUB", "deny").replace("<member>any</member></application>", "<member>ssl</member></application>"),
            "",
        ),
        (
            STATIC_OBJECTS,
            _rule("TIME-A", "WIDE", "HOST", "WEB-RANGE", extra="<schedule>business</schedule>")
            + _rule("TIME-B", "NARROW", "HOST", "WEB-SUB", "deny", "<schedule>business</schedule>"),
            "",
        ),
        (
            STATIC_OBJECTS,
            _rule("NAT-A", "WIDE", "HOST", "WEB-RANGE") + _rule("NAT-B", "NARROW", "HOST", "WEB-SUB", "deny"),
            '<nat><rules><entry name="NAT"><source><member>any</member></source></entry></rules></nat>',
        ),
    ],
)
def test_dynamic_application_time_cycle_and_nat_state_block_proof(tmp_path, objects, rules, nat):
    assert _effectiveness(_parse(tmp_path, _config(objects, rules, nat=nat))) == []


def test_negation_scope_zone_and_rulebase_boundaries_block_cross_comparison(tmp_path):
    rules = _rule("NEGATED", "WIDE", "HOST", "WEB-RANGE", extra="<negate-source>yes</negate-source>")
    rules += _rule("OTHER-ZONE", "NARROW", "HOST", "WEB-SUB", "deny").replace("<member>trust</member>", "<member>dmz</member>", 1)
    extra_vsys = f'<entry name="vsys2">{STATIC_OBJECTS}<rulebase><security><rules>{_rule("OTHER-VSYS", "NARROW", "HOST", "WEB-SUB", "deny")}</rules></security></rulebase></entry>'
    xml = _config(STATIC_OBJECTS, rules, extra_vsys=extra_vsys).replace(
        "</entry></vsys>",
        f'<post-rulebase><security><rules>{_rule("OTHER-RULEBASE", "NARROW", "HOST", "WEB-SUB", "deny")}</rules></security></post-rulebase></entry></vsys>',
        1,
    )
    assert _effectiveness(_parse(tmp_path, xml)) == []


def test_hygiene_flags_disabled_unrestricted_and_active_broad_service(tmp_path):
    disabled = _rule("DISABLED", "any", "any", "any", extra="<disabled>yes</disabled>").replace("<member>trust</member>", "<member>any</member>").replace("<member>untrust</member>", "<member>any</member>")
    broad_service = _rule("BROAD-SERVICE", "NARROW", "HOST", "any")
    parser = _parse(tmp_path, _config(STATIC_OBJECTS, disabled + broad_service))
    plugin = PluginPANOSChecks()
    plugin.check_security_rules(parser)
    assert {
        "paloalto.panos.policy.disabled_permissive_rule",
        "paloalto.panos.policy.broad_service",
    }.issubset(item.rule_id for item in plugin.get_issues())


def test_bounded_resolution_and_medium_policy_runtime(tmp_path):
    groups = "".join(
        f'<entry name="G{i}"><static><member>G{i + 1}</member></static></entry>'
        for i in range(40)
    ) + '<entry name="G40"><static><member>WIDE</member></static></entry>'
    objects = STATIC_OBJECTS + f"<address-group>{groups}</address-group>"
    rules = _rule("PARENT", "G0", "HOST", "WEB-RANGE") + "".join(
        _rule(f"CHILD-{i}", "NARROW", "HOST", "WEB-ONE") for i in range(200)
    )
    parser = _parse(tmp_path, _config(objects, rules))
    start = time.monotonic()
    findings = _effectiveness(parser)
    assert len(findings) == 200
    assert time.monotonic() - start < 5


def _asa(tmp_path, body: str, name: str = "asa-policy.conf") -> CiscoASAParser:
    path = tmp_path / name
    path.write_text("ASA Version 9.22\nhostname edge\n" + body, encoding="utf-8")
    return CiscoASAParser(str(path))


def _asa_effectiveness(parser):
    from src.analyze.cisco.asa.plugins.asa_checks_plugin import PluginASAChecks

    plugin = PluginASAChecks()
    plugin.check_acl_hygiene_and_effectiveness(parser)
    return plugin.get_issues()


def test_asa_bound_acl_literal_containment_proves_shadow_and_redundancy(tmp_path):
    parser = _asa(tmp_path, """
access-list EDGE extended permit ip 10.0.0.0 255.0.0.0 any
access-list EDGE extended deny tcp 10.20.0.0 255.255.0.0 host 192.0.2.10 eq 443
access-list EDGE extended permit udp host 10.20.0.5 host 192.0.2.20 eq 53
access-group EDGE in interface outside
""")
    findings = [item for item in _asa_effectiveness(parser) if item.rule_id.endswith(("shadowed_rule", "redundant_rule"))]
    assert [item.rule_id for item in findings] == [
        "cisco.asa.acl.shadowed_rule",
        "cisco.asa.acl.redundant_rule",
    ]


def test_asa_ipv6_containment_and_explicit_line_order_are_preserved(tmp_path):
    parser = _asa(tmp_path, """
access-list V6 line 20 extended deny tcp host 2001:db8::10 host 2001:db8:1::20 eq 443
access-list V6 line 10 extended permit ip any6 any6 log
access-group V6 in interface outside
""")
    shadows = [item for item in _asa_effectiveness(parser) if item.rule_id == "cisco.asa.acl.shadowed_rule"]
    assert len(shadows) == 1
    assert "Entry 2" in shadows[0].observation


def test_asa_static_object_and_named_port_expand_but_partial_time_unbound_stay_bounded(tmp_path):
    parser = _asa(tmp_path, """
object-group network DYNAMIC-SOURCES
 network-object 10.0.0.0 255.0.0.0
access-list PARTIAL extended permit tcp 10.0.0.0 255.255.255.0 any eq 443
access-list PARTIAL extended deny tcp 10.0.0.0 255.255.0.0 any eq 443
access-list OBJECTS extended permit ip object-group DYNAMIC-SOURCES any
access-list OBJECTS extended deny tcp host 10.0.0.5 any eq 443
access-list TIMED extended permit ip any any time-range BUSINESS
access-list TIMED extended deny tcp host 10.0.0.5 any eq 443
access-list PORTS extended permit tcp any any eq https
access-list PORTS extended deny tcp host 10.0.0.5 any eq 443
access-list UNBOUND extended permit ip any any
access-list UNBOUND extended deny tcp host 10.0.0.5 any eq 443
access-group PARTIAL in interface outside
access-group OBJECTS in interface inside
access-group TIMED out interface dmz
access-group PORTS in interface partner
""")
    effectiveness = [
        item for item in _asa_effectiveness(parser)
        if item.rule_id.endswith(("shadowed_rule", "redundant_rule"))
    ]
    assert [item.rule_id for item in effectiveness] == [
        "cisco.asa.acl.shadowed_rule",
        "cisco.asa.acl.shadowed_rule",
    ]
    assert {"'OBJECTS'", "'PORTS'"} == {
        next(token for token in item.observation.split() if token.startswith("'"))
        for item in effectiveness
    }


def test_asa_nested_network_and_service_objects_prove_containment(tmp_path):
    parser = _asa(tmp_path, """
object network WIDE
 subnet 10.0.0.0 255.0.0.0
object network NARROW
 range 10.20.0.0 10.20.255.255
object network HOST
 host 192.0.2.10
object-group network WIDE-GROUP
 network-object object WIDE
object-group network NESTED-GROUP
 group-object WIDE-GROUP
object service WEB-RANGE
 service tcp destination range 8000 8999
object service WEB-ONE
 service tcp destination eq 8443
object-group service WEB-GROUP
 service-object object WEB-RANGE
access-list EDGE extended permit object-group WEB-GROUP object-group NESTED-GROUP object HOST
access-list EDGE extended deny tcp object NARROW object HOST eq 8443
access-list EDGE extended permit object WEB-ONE object NARROW object HOST
access-group EDGE in interface outside
""")
    assert [
        item.rule_id for item in _asa_effectiveness(parser)
        if item.rule_id.endswith(("shadowed_rule", "redundant_rule"))
    ] == [
        "cisco.asa.acl.shadowed_rule",
        "cisco.asa.acl.redundant_rule",
    ]


def test_asa_ipv6_ranges_and_legacy_port_groups_are_bounded_static_objects(tmp_path):
    parser = _asa(tmp_path, """
object network V6-WIDE
 subnet 2001:db8::/32
object-group network V6-GROUP
 network-object object V6-WIDE
object-group service WEB-PORTS tcp
 port-object range 8000 8999
 port-object eq https
access-list V6 extended permit tcp object-group V6-GROUP any6 object-group WEB-PORTS
access-list V6 extended deny tcp host 2001:db8:1::20 any6 eq 8443
access-group V6 in interface outside
""")
    assert [
        item.rule_id for item in _asa_effectiveness(parser)
        if item.rule_id == "cisco.asa.acl.shadowed_rule"
    ]


@pytest.mark.parametrize(
    "objects,parent_protocol,parent_source",
    [
        ("object network DYNAMIC\n fqdn v4 dynamic.example.test\n", "tcp", "object DYNAMIC"),
        (
            "object service SOURCE-BOUND\n service tcp source range 1024 65535 destination range 8000 8999\n",
            "object SOURCE-BOUND",
            "10.0.0.0 255.0.0.0",
        ),
        (
            "object-group network CYCLE-A\n group-object CYCLE-B\n"
            "object-group network CYCLE-B\n group-object CYCLE-A\n",
            "tcp",
            "object-group CYCLE-A",
        ),
        (
            "object-group service CYCLE-SVC\n group-object CYCLE-SVC\n",
            "object-group CYCLE-SVC",
            "10.0.0.0 255.0.0.0",
        ),
    ],
)
def test_asa_dynamic_source_port_and_object_cycles_block_proof(
    tmp_path, objects, parent_protocol, parent_source
):
    parser = _asa(tmp_path, objects + f"""
access-list EDGE extended permit {parent_protocol} {parent_source} any
access-list EDGE extended deny tcp host 10.20.0.5 any eq 8443
access-group EDGE in interface outside
""")
    assert not any(
        item.rule_id.endswith(("shadowed_rule", "redundant_rule"))
        for item in _asa_effectiveness(parser)
    )


def test_asa_same_action_requires_equivalent_logging_behavior(tmp_path):
    parser = _asa(tmp_path, """
access-list EDGE extended permit tcp 10.0.0.0 255.0.0.0 any eq https log informational
access-list EDGE extended permit tcp host 10.20.0.5 any eq 443
access-group EDGE in interface outside
""")
    effectiveness = [
        item for item in _asa_effectiveness(parser)
        if item.rule_id.endswith(("shadowed_rule", "redundant_rule"))
    ]
    assert [item.rule_id for item in effectiveness] == [
        "cisco.asa.acl.shadowed_rule"
    ]


def test_asa_acl_hygiene_is_independent_of_effectiveness_unknowns(tmp_path):
    parser = _asa(tmp_path, """
access-list EDGE extended permit ip any any inactive
access-list EDGE extended permit ip host 10.0.0.5 any
access-list EDGE extended permit ip any any
access-group EDGE in interface outside
""")
    rule_ids = {item.rule_id for item in _asa_effectiveness(parser)}
    assert {
        "cisco.asa.acl.inactive_permissive_rule",
        "cisco.asa.acl.broad_service",
        "cisco.asa.acl.broad_permit_unlogged",
    }.issubset(rule_ids)


def _ios_acl(tmp_path, body: str, name: str = "ios-acl.conf") -> CiscoIOSParser:
    path = tmp_path / name
    path.write_text("version 17.12\nhostname edge\n" + body, encoding="utf-8")
    return CiscoIOSParser(str(path))


def _ios_acl_effectiveness(parser):
    plugin = PluginIOSBaseline()
    plugin.check_acl_effectiveness(parser)
    return plugin.get_issues()


def test_ios_attached_acl_literal_containment_proves_shadow_and_redundancy(tmp_path):
    parser = _ios_acl(tmp_path, """
interface GigabitEthernet0/0
 ip access-group EDGE in
ip access-list extended EDGE
 10 permit tcp 10.0.0.0 0.255.255.255 host 192.0.2.10 range 8000 8999 log
 20 deny tcp 10.20.0.0 0.0.255.255 host 192.0.2.10 eq 8443
 30 permit tcp host 10.20.0.5 host 192.0.2.10 eq 8443 log
""")
    assert [item.rule_id for item in _ios_acl_effectiveness(parser)] == [
        "cisco.ios.acl.shadowed_rule",
        "cisco.ios.acl.redundant_rule",
    ]


def test_ios_ipv6_acl_containment_and_family_scope_are_preserved(tmp_path):
    parser = _ios_acl(tmp_path, """
interface GigabitEthernet0/0
 ip access-group V4 in
 ipv6 traffic-filter V6 in
ip access-list extended V4
 10 permit tcp any any eq 443
ipv6 access-list V6
 10 permit tcp 2001:db8::/32 any eq https
 20 deny tcp host 2001:db8:1::10 any eq 443
""")
    findings = _ios_acl_effectiveness(parser)
    assert [item.rule_id for item in findings] == ["cisco.ios.acl.shadowed_rule"]
    assert "ipv6" in findings[0].observation


@pytest.mark.parametrize(
    "parent",
    [
        "10 permit tcp any range 1024 65535 any eq 443",
        "10 permit tcp 10.0.0.0 0.255.255.255 any range 8000 8999 time-range BUSINESS",
        "10 permit tcp 10.0.0.0 0.0.255.255 any established",
        "10 permit tcp 10.0.0.0 0.255.0.255 any eq 443",
    ],
)
def test_ios_source_ports_time_flags_and_noncontiguous_wildcards_block_proof(
    tmp_path, parent
):
    parser = _ios_acl(tmp_path, f"""
interface GigabitEthernet0/0
 ip access-group EDGE in
ip access-list extended EDGE
 {parent}
 20 deny tcp host 10.20.0.5 any eq 443
""")
    assert _ios_acl_effectiveness(parser) == []


def test_ios_redundancy_requires_equivalent_logging_and_same_attachment(tmp_path):
    parser = _ios_acl(tmp_path, """
interface GigabitEthernet0/0
 ip access-group EDGE-A in
interface GigabitEthernet0/1
 ip access-group EDGE-B in
ip access-list extended EDGE-A
 10 permit tcp 10.0.0.0 0.255.255.255 any eq 443 log
 20 permit tcp host 10.20.0.5 any eq 443
ip access-list extended EDGE-B
 10 deny tcp host 10.20.0.5 any eq 443
""")
    assert _ios_acl_effectiveness(parser) == []


def test_ios_explicit_sequence_order_and_standard_acl_semantics_are_effective(tmp_path):
    parser = _ios_acl(tmp_path, """
interface GigabitEthernet0/0
 ip access-group EDGE in
interface GigabitEthernet0/1
 ip access-group 10 in
ip access-list extended EDGE
 20 deny tcp host 10.20.0.5 any eq 443
 10 permit tcp 10.0.0.0 0.255.255.255 any eq 443
access-list 10 permit any
access-list 10 deny host 192.0.2.10
""")
    findings = _ios_acl_effectiveness(parser)
    assert [item.rule_id for item in findings] == [
        "cisco.ios.acl.shadowed_rule",
        "cisco.ios.acl.shadowed_rule",
    ]
    assert "EDGE:20" in findings[0].observation


def test_iosxe_inherits_attached_acl_proof_with_iosxe_device_identity(tmp_path):
    path = tmp_path / "iosxe-acl.conf"
    path.write_text("""version 17.12.1
hostname edge-xe
interface GigabitEthernet1
 ip access-group EDGE in
ip access-list extended EDGE
 10 permit tcp any any eq 443
 20 deny tcp host 192.0.2.10 any eq https
""", encoding="utf-8")
    findings = _ios_acl_effectiveness(CiscoIOSXEParser(str(path)))
    assert [item.rule_id for item in findings] == ["cisco.ios.acl.shadowed_rule"]
    assert findings[0].device == "IOS_XE"


def _fortios(tmp_path, body: str, name: str = "fortios-policy.conf") -> FortiOSParser:
    path = tmp_path / name
    path.write_text(
        "#config-version=FGT100F-7.6.4-FW-build0001-260101:opmode=0:vdom=1:user=admin\n"
        + body,
        encoding="utf-8",
    )
    return FortiOSParser(str(path))


def _fortios_effectiveness(parser):
    plugin = PluginFortiOSBaseline()
    plugin.check_policy_effectiveness(parser)
    return plugin.get_issues()


FORTIOS_STATIC_OBJECTS = """
config firewall address
edit WIDE
set subnet 10.0.0.0 255.0.0.0
next
edit NARROW
set type iprange
set start-ip 10.20.0.0
set end-ip 10.20.255.255
next
edit HOST
set subnet 192.0.2.42 255.255.255.255
next
end
config firewall addrgrp
edit WIDE-GROUP
set member WIDE
next
end
config firewall service custom
edit WEB-RANGE
set protocol TCP/UDP/SCTP
set tcp-portrange 8000-8999
next
edit WEB-ONE
set protocol TCP/UDP/SCTP
set tcp-portrange 8443
next
end
config firewall service group
edit WEB-GROUP
set member WEB-RANGE
next
end
"""


def test_fortios_static_containment_proves_shadow_and_redundancy(tmp_path):
    parser = _fortios(tmp_path, FORTIOS_STATIC_OBJECTS + """
config firewall policy
edit PARENT
set srcintf any
set dstintf any
set srcaddr WIDE-GROUP
set dstaddr HOST
set service WEB-GROUP
set schedule always
set action accept
next
edit SHADOW
set srcintf lan
set dstintf wan1
set srcaddr NARROW
set dstaddr HOST
set service WEB-ONE
set schedule always
set action deny
next
edit REDUNDANT
set srcintf lan
set dstintf wan1
set srcaddr NARROW
set dstaddr HOST
set service WEB-ONE
set schedule always
set action accept
next
end
""")
    findings = _fortios_effectiveness(parser)
    assert [item.rule_id for item in findings] == [
        "fortinet.fortios.policy.shadowed_rule",
        "fortinet.fortios.policy.redundant_rule",
    ]


def test_fortios_ipv6_policy_uses_separate_family_and_order(tmp_path):
    parser = _fortios(tmp_path, """
config firewall address6
edit V6-WIDE
set ip6 2001:db8::/32
next
edit V6-HOST
set ip6 2001:db8:1::20/128
next
end
config firewall policy6
edit 10
set srcintf any
set dstintf any
set srcaddr V6-WIDE
set dstaddr all_ipv6
set service HTTPS
set schedule always
set action accept
next
edit 20
set srcintf lan
set dstintf wan1
set srcaddr V6-HOST
set dstaddr all_ipv6
set service HTTPS
set schedule always
set action deny
next
end
""")
    findings = _fortios_effectiveness(parser)
    assert [item.rule_id for item in findings] == [
        "fortinet.fortios.policy.shadowed_rule"
    ]
    assert "IPv6 policy '20'" in findings[0].observation


@pytest.mark.parametrize(
    "objects,parent_extra,parent_source,parent_service",
    [
        (
            "config firewall address\nedit DYNAMIC\nset type fqdn\nset fqdn example.test\nnext\nend\n",
            "",
            "DYNAMIC",
            "HTTPS",
        ),
        (
            FORTIOS_STATIC_OBJECTS
            + "config firewall addrgrp\nedit EXCLUDED\nset member WIDE\nset exclude enable\nset exclude-member NARROW\nnext\nend\n",
            "",
            "EXCLUDED",
            "WEB-RANGE",
        ),
        (
            FORTIOS_STATIC_OBJECTS
            + "config firewall service custom\nedit SOURCE-BOUND\nset protocol TCP/UDP/SCTP\nset tcp-portrange 8000-8999:1024-65535\nnext\nend\n",
            "",
            "WIDE",
            "SOURCE-BOUND",
        ),
        (FORTIOS_STATIC_OBJECTS, "set schedule business-hours\n", "WIDE", "WEB-RANGE"),
        (FORTIOS_STATIC_OBJECTS, "set internet-service enable\n", "WIDE", "WEB-RANGE"),
    ],
)
def test_fortios_dynamic_exclusion_source_port_time_and_special_predicates_block_proof(
    tmp_path, objects, parent_extra, parent_source, parent_service
):
    parser = _fortios(tmp_path, objects + f"""
config firewall policy
edit PARENT
set srcintf any
set dstintf any
set srcaddr {parent_source}
set dstaddr all
set service {parent_service}
set schedule always
set action accept
{parent_extra}next
edit CHILD
set srcintf lan
set dstintf wan1
set srcaddr NARROW
set dstaddr all
set service WEB-ONE
set schedule always
set action deny
next
end
""")
    assert not any(
        item.rule_id.endswith(("shadowed_rule", "redundant_rule"))
        for item in _fortios_effectiveness(parser)
    )


def test_fortios_same_action_requires_equivalent_nat_and_inspection_behavior(tmp_path):
    parser = _fortios(tmp_path, FORTIOS_STATIC_OBJECTS + """
config firewall policy
edit NAT-PARENT
set srcintf any
set dstintf any
set srcaddr WIDE
set dstaddr all
set service WEB-RANGE
set schedule always
set action accept
set nat enable
next
edit NO-NAT-CHILD
set srcintf lan
set dstintf wan1
set srcaddr NARROW
set dstaddr all
set service WEB-ONE
set schedule always
set action accept
next
edit DENY-CHILD
set srcintf lan
set dstintf wan1
set srcaddr NARROW
set dstaddr all
set service WEB-ONE
set schedule always
set action deny
next
end
""")
    rule_ids = [item.rule_id for item in _fortios_effectiveness(parser)]
    assert "fortinet.fortios.policy.redundant_rule" not in rule_ids
    assert rule_ids == ["fortinet.fortios.policy.shadowed_rule"]


def test_fortios_scope_cycles_and_partial_overlap_do_not_prove(tmp_path):
    parser = _fortios(tmp_path, """
config vdom
edit blue
config firewall address
edit PARTIAL
set subnet 10.0.0.0 255.255.255.0
next
end
config firewall addrgrp
edit CYCLE-A
set member CYCLE-B
next
edit CYCLE-B
set member CYCLE-A
next
end
config firewall policy
edit BLUE
set srcintf any
set dstintf any
set srcaddr CYCLE-B
set dstaddr all
set service HTTPS
set action accept
next
end
next
edit green
config firewall address
edit WIDER
set subnet 10.0.0.0 255.255.0.0
next
end
config firewall policy
edit GREEN
set srcintf any
set dstintf any
set srcaddr WIDER
set dstaddr all
set service HTTPS
set action deny
next
end
next
end
""")
    assert not any(
        item.rule_id.endswith(("shadowed_rule", "redundant_rule"))
        for item in _fortios_effectiveness(parser)
    )


def test_fortios_policy_hygiene_is_independent_of_proof(tmp_path):
    parser = _fortios(tmp_path, FORTIOS_STATIC_OBJECTS + """
config firewall policy
edit DISABLED
set srcintf any
set dstintf any
set srcaddr all
set dstaddr all
set service ALL
set schedule always
set action accept
set status disable
next
edit BROAD-SERVICE
set srcintf lan
set dstintf wan1
set srcaddr NARROW
set dstaddr HOST
set service ALL
set schedule always
set action accept
next
end
""")
    rule_ids = {item.rule_id for item in _fortios_effectiveness(parser)}
    assert {
        "fortinet.fortios.policy.disabled_permissive_rule",
        "fortinet.fortios.policy.broad_service",
    }.issubset(rule_ids)


def _junos_policy(tmp_path, body: str, name: str = "junos-policy.conf") -> JunOSParser:
    path = tmp_path / name
    path.write_text("set version 23.4R2\n" + body, encoding="utf-8")
    return JunOSParser(str(path))


def _junos_effectiveness(parser):
    plugin = PluginJunOSChecks()
    plugin.check_stateful_policy_effectiveness(parser)
    return plugin.get_issues()


JUNOS_STATIC_OBJECTS = """
set security address-book TRUST address WIDE 10.0.0.0/8
set security address-book TRUST address NARROW range-address 10.20.0.0 to 10.20.255.255
set security address-book TRUST address-set WIDE-GROUP address WIDE
set security address-book TRUST address-set NESTED-GROUP address-set WIDE-GROUP
set security address-book TRUST attach zone trust
set security address-book UNTRUST address HOST 192.0.2.42/32
set security address-book UNTRUST attach zone untrust
set applications application WEB-RANGE protocol tcp
set applications application WEB-RANGE destination-port 8000-8999
set applications application WEB-ONE protocol tcp
set applications application WEB-ONE destination-port 8443
set applications application-set WEB-GROUP application WEB-RANGE
"""


def test_junos_srx_static_containment_proves_shadow_and_redundancy(tmp_path):
    parser = _junos_policy(tmp_path, JUNOS_STATIC_OBJECTS + """
set security policies from-zone trust to-zone untrust policy PARENT match source-address NESTED-GROUP
set security policies from-zone trust to-zone untrust policy PARENT match destination-address HOST
set security policies from-zone trust to-zone untrust policy PARENT match application WEB-GROUP
set security policies from-zone trust to-zone untrust policy PARENT then permit
set security policies from-zone trust to-zone untrust policy SHADOW match source-address NARROW
set security policies from-zone trust to-zone untrust policy SHADOW match destination-address HOST
set security policies from-zone trust to-zone untrust policy SHADOW match application WEB-ONE
set security policies from-zone trust to-zone untrust policy SHADOW then deny
set security policies from-zone trust to-zone untrust policy REDUNDANT match source-address NARROW
set security policies from-zone trust to-zone untrust policy REDUNDANT match destination-address HOST
set security policies from-zone trust to-zone untrust policy REDUNDANT match application WEB-ONE
set security policies from-zone trust to-zone untrust policy REDUNDANT then permit
""")
    findings = _junos_effectiveness(parser)
    assert [item.rule_id for item in findings] == [
        "juniper.junos.policy.shadowed_rule",
        "juniper.junos.policy.redundant_rule",
    ]


def test_junos_srx_ipv6_and_predefined_transport_any_are_bounded(tmp_path):
    parser = _junos_policy(tmp_path, """
set security address-book TRUST6 address WIDE6 2001:db8::/32
set security address-book TRUST6 address HOST6 2001:db8:1::10/128
set security address-book TRUST6 attach zone trust6
set security policies from-zone trust6 to-zone untrust6 policy PARENT match source-address WIDE6
set security policies from-zone trust6 to-zone untrust6 policy PARENT match destination-address any-ipv6
set security policies from-zone trust6 to-zone untrust6 policy PARENT match application junos-tcp-any
set security policies from-zone trust6 to-zone untrust6 policy PARENT then permit
set security policies from-zone trust6 to-zone untrust6 policy CHILD match source-address HOST6
set security policies from-zone trust6 to-zone untrust6 policy CHILD match destination-address any-ipv6
set security policies from-zone trust6 to-zone untrust6 policy CHILD match application junos-tcp-any
set security policies from-zone trust6 to-zone untrust6 policy CHILD then reject
""")
    findings = _junos_effectiveness(parser)
    assert [item.rule_id for item in findings] == [
        "juniper.junos.policy.shadowed_rule"
    ]


def test_junos_bracketed_multi_value_lists_preserve_every_member(tmp_path):
    parser = _junos_policy(tmp_path, JUNOS_STATIC_OBJECTS + """
set security address-book TRUST address-set MULTI address [ WIDE NARROW ]
set applications application-set MULTI-WEB application [ WEB-RANGE WEB-ONE ]
set security policies from-zone trust to-zone untrust policy MULTI match source-address [ WIDE NARROW ]
set security policies from-zone trust to-zone untrust policy MULTI match destination-address HOST
set security policies from-zone trust to-zone untrust policy MULTI match application [ WEB-RANGE WEB-ONE ]
set security policies from-zone trust to-zone untrust policy MULTI then permit
""")
    policy = parser.get_security_policies()[0]
    assert policy.sources == ("WIDE", "NARROW")
    assert policy.applications == ("WEB-RANGE", "WEB-ONE")
    assert policy.source_networks.complete
    assert policy.services.complete


@pytest.mark.parametrize(
    "extra_objects,parent_source,parent_application,parent_match",
    [
        (
            "set security address-book TRUST address DYNAMIC dns-name dynamic.example.test\n",
            "DYNAMIC",
            "WEB-RANGE",
            "",
        ),
        (
            "set applications application SOURCE-BOUND protocol tcp\nset applications application SOURCE-BOUND source-port 1024-65535\nset applications application SOURCE-BOUND destination-port 8000-8999\n",
            "WIDE",
            "SOURCE-BOUND",
            "",
        ),
        ("", "WIDE", "WEB-RANGE", "set security policies from-zone trust to-zone untrust policy PARENT match source-identity authenticated-user\n"),
        ("set security policies global policy GLOBAL match source-address any\nset security policies global policy GLOBAL then deny\n", "WIDE", "WEB-RANGE", ""),
        ("set groups POLICY-INHERIT security policies from-zone trust to-zone untrust policy GROUP-POLICY then deny\nset security apply-groups POLICY-INHERIT\n", "WIDE", "WEB-RANGE", ""),
    ],
)
def test_junos_dynamic_source_port_identity_global_and_inheritance_block_proof(
    tmp_path, extra_objects, parent_source, parent_application, parent_match
):
    parser = _junos_policy(tmp_path, JUNOS_STATIC_OBJECTS + extra_objects + f"""
set security policies from-zone trust to-zone untrust policy PARENT match source-address {parent_source}
set security policies from-zone trust to-zone untrust policy PARENT match destination-address HOST
set security policies from-zone trust to-zone untrust policy PARENT match application {parent_application}
{parent_match}set security policies from-zone trust to-zone untrust policy PARENT then permit
set security policies from-zone trust to-zone untrust policy CHILD match source-address NARROW
set security policies from-zone trust to-zone untrust policy CHILD match destination-address HOST
set security policies from-zone trust to-zone untrust policy CHILD match application WEB-ONE
set security policies from-zone trust to-zone untrust policy CHILD then deny
""")
    assert not any(
        item.rule_id.endswith(("shadowed_rule", "redundant_rule"))
        for item in _junos_effectiveness(parser)
    )


def test_junos_same_action_requires_equivalent_logging_and_tunnel_behavior(tmp_path):
    parser = _junos_policy(tmp_path, JUNOS_STATIC_OBJECTS + """
set security policies from-zone trust to-zone untrust policy PARENT match source-address WIDE
set security policies from-zone trust to-zone untrust policy PARENT match destination-address HOST
set security policies from-zone trust to-zone untrust policy PARENT match application WEB-RANGE
set security policies from-zone trust to-zone untrust policy PARENT then permit
set security policies from-zone trust to-zone untrust policy PARENT then log session-init
set security policies from-zone trust to-zone untrust policy CHILD match source-address NARROW
set security policies from-zone trust to-zone untrust policy CHILD match destination-address HOST
set security policies from-zone trust to-zone untrust policy CHILD match application WEB-ONE
set security policies from-zone trust to-zone untrust policy CHILD then permit
""")
    assert not any(
        item.rule_id == "juniper.junos.policy.redundant_rule"
        for item in _junos_effectiveness(parser)
    )


def test_junos_broad_application_hygiene_is_independent_of_object_proof(tmp_path):
    parser = _junos_policy(tmp_path, JUNOS_STATIC_OBJECTS + """
set security policies from-zone trust to-zone untrust policy BROAD-APP match source-address NARROW
set security policies from-zone trust to-zone untrust policy BROAD-APP match destination-address HOST
set security policies from-zone trust to-zone untrust policy BROAD-APP match application any
set security policies from-zone trust to-zone untrust policy BROAD-APP then permit
""")
    assert [item.rule_id for item in _junos_effectiveness(parser)] == [
        "juniper.junos.policy.broad_application"
    ]


def _screenos_policy(tmp_path, body: str, name: str = "screenos-policy.conf") -> JuniperScreenOSParser:
    path = tmp_path / name
    path.write_text("set version 6.3.0r27.0\n" + body, encoding="utf-8")
    return JuniperScreenOSParser(str(path))


def _screenos_effectiveness(parser):
    plugin = PluginScreenOSChecks()
    plugin.check_policy_effectiveness(parser)
    return plugin.get_issues()


SCREENOS_STATIC_OBJECTS = """
set address "Trust" "WIDE" 10.0.0.0 255.0.0.0
set address "Trust" "NARROW" 10.20.0.0 255.255.0.0
set address "Untrust" "HOST" 192.0.2.42 255.255.255.255
set group address "Trust" "WIDE-GROUP" add "WIDE"
set group address "Trust" "NESTED-GROUP" add "WIDE-GROUP"
set service "WEB-RANGE" protocol tcp src-port 0-65535 dst-port 8000-8999
set service "WEB-ONE" protocol tcp src-port 0-65535 dst-port 8443-8443
set group service "WEB-GROUP" add "WEB-RANGE"
"""


def test_screenos_static_containment_proves_shadow_and_redundancy(tmp_path):
    parser = _screenos_policy(tmp_path, SCREENOS_STATIC_OBJECTS + """
set policy id 10 from "Trust" to "Untrust" "NESTED-GROUP" "HOST" "WEB-GROUP" permit
set policy id 20 from "Trust" to "Untrust" "NARROW" "HOST" "WEB-ONE" deny
set policy id 30 from "Trust" to "Untrust" "NARROW" "HOST" "WEB-ONE" permit
""")
    findings = _screenos_effectiveness(parser)
    assert [item.rule_id for item in findings] == [
        "juniper.screenos.policy.shadowed_rule",
        "juniper.screenos.policy.redundant_rule",
    ]


def test_screenos_global_address_and_builtin_service_resolve_conservatively(tmp_path):
    parser = _screenos_policy(tmp_path, """
set address "Global" "ALL-V4" 0.0.0.0 0.0.0.0
set address "Untrust" "HOST" 192.0.2.42 255.255.255.255
set policy id 10 from "Trust" to "Untrust" "ALL-V4" "HOST" "HTTPS" permit
set policy id 20 from "Trust" to "Untrust" "10.0.0.10/32" "HOST" "HTTPS" reject
""")
    assert [item.rule_id for item in _screenos_effectiveness(parser)] == [
        "juniper.screenos.policy.shadowed_rule"
    ]


@pytest.mark.parametrize(
    "objects,parent_source,parent_service,tail",
    [
        ('set address "Trust" "DYNAMIC" dynamic.example.test\n', "DYNAMIC", "WEB-RANGE", ""),
        ('set service "SOURCE-BOUND" protocol tcp src-port 1024-65535 dst-port 8000-8999\n', "WIDE", "SOURCE-BOUND", ""),
        ("", "WIDE", "WEB-RANGE", ' auth server "AUTH"'),
        (
            'set group address "Trust" "CYCLE-A" add "CYCLE-B"\nset group address "Trust" "CYCLE-B" add "CYCLE-A"\n',
            "CYCLE-A",
            "WEB-RANGE",
            "",
        ),
        (
            'set policy global id 1 from "Global" to "Global" "Any" "Any" "ANY" deny\n',
            "WIDE",
            "WEB-RANGE",
            "",
        ),
    ],
)
def test_screenos_dynamic_source_port_auth_and_cycles_block_proof(
    tmp_path, objects, parent_source, parent_service, tail
):
    parser = _screenos_policy(tmp_path, SCREENOS_STATIC_OBJECTS + objects + f"""
set policy id 10 from "Trust" to "Untrust" "{parent_source}" "HOST" "{parent_service}" permit{tail}
set policy id 20 from "Trust" to "Untrust" "NARROW" "HOST" "WEB-ONE" deny
""")
    assert not any(
        item.rule_id.endswith(("shadowed_rule", "redundant_rule"))
        for item in _screenos_effectiveness(parser)
    )


def test_screenos_same_action_requires_equivalent_tracking_behavior(tmp_path):
    parser = _screenos_policy(tmp_path, SCREENOS_STATIC_OBJECTS + """
set policy id 10 from "Trust" to "Untrust" "WIDE" "HOST" "WEB-RANGE" permit log
set policy id 20 from "Trust" to "Untrust" "NARROW" "HOST" "WEB-ONE" permit
""")
    assert not any(
        item.rule_id == "juniper.screenos.policy.redundant_rule"
        for item in _screenos_effectiveness(parser)
    )


def test_screenos_policy_hygiene_is_independent_of_proof(tmp_path):
    parser = _screenos_policy(tmp_path, SCREENOS_STATIC_OBJECTS + """
set policy id 10 from "Trust" to "Untrust" "Any" "Any" "ANY" permit
set policy id 10 disable
set policy id 20 from "Trust" to "Untrust" "NARROW" "HOST" "ANY" permit
""")
    assert {
        "juniper.screenos.policy.disabled_permissive_rule",
        "juniper.screenos.policy.broad_service",
    }.issubset(item.rule_id for item in _screenos_effectiveness(parser))


def _sonicos_policy(tmp_path, body: str, name: str = "sonicos-policy.conf") -> SonicOSParser:
    path = tmp_path / name
    path.write_text('firmware-version "SonicOS 7.1.2-7019"\n' + body, encoding="utf-8")
    return SonicOSParser(str(path))


def _sonicos_effectiveness(parser):
    plugin = PluginSonicOSChecks()
    plugin.check_policy_effectiveness(parser)
    return plugin.get_issues()


SONICOS_STATIC_OBJECTS = """
address-object ipv4 WIDE network 10.0.0.0 /8
address-object ipv4 NARROW range 10.20.0.0 10.20.255.255
address-object ipv4 HOST host 192.0.2.42
address-object ipv6 V6-WIDE network 2001:db8:: /32
address-object ipv6 V6-NARROW network 2001:db8:1:: /48
address-object ipv6 V6-HOST host 2001:db8:ffff::42
address-group ipv4 WIDE-GROUP
  address-object ipv4 WIDE
address-group ipv4 NESTED-GROUP
  address-group ipv4 WIDE-GROUP
service-object WEB-RANGE tcp 8000 8999
service-object WEB-SUB tcp 8440 8450
service-object WEB-ONE tcp 8443 8443
service-group WEB-GROUP
  service-object WEB-RANGE
"""


def _sonicos_rule(
    name: str,
    source: str,
    destination: str,
    service: str,
    action: str = "allow",
    *,
    family: str = "ipv4",
    from_zone: str = "LAN",
    to_zone: str = "WAN",
    schedule: str = "always-on",
    children: str = "  enable\n  logging\n",
) -> str:
    return (
        f"access-rule {family} from {from_zone} to {to_zone} action {action} "
        f"source address {source} service {service} destination address {destination} "
        f"schedule {schedule}\n  name \"{name}\"\n{children}"
    )


def test_sonicos_static_nested_containment_proves_shadow_and_redundancy(tmp_path):
    rules = (
        _sonicos_rule("PARENT", "group NESTED-GROUP", "name HOST", "group WEB-GROUP")
        + _sonicos_rule("SHADOW", "name NARROW", "name HOST", "name WEB-SUB", "deny")
        + _sonicos_rule("REDUNDANT", "name NARROW", "name HOST", "name WEB-ONE")
    )
    findings = _sonicos_effectiveness(_sonicos_policy(tmp_path, SONICOS_STATIC_OBJECTS + rules))
    assert [item.rule_id for item in findings] == [
        "sonicwall.sonicos.policy.shadowed_rule",
        "sonicwall.sonicos.policy.redundant_rule",
    ]
    assert "SHADOW" in findings[0].observation


def test_sonicos_ipv6_rules_are_compared_only_within_their_family(tmp_path):
    rules = (
        _sonicos_rule("V4", "name WIDE", "name HOST", "name WEB-RANGE")
        + _sonicos_rule(
            "V6-PARENT", "name V6-WIDE", "name V6-HOST", "name WEB-RANGE",
            family="ipv6",
        )
        + _sonicos_rule(
            "V6-CHILD", "name V6-NARROW", "name V6-HOST", "name WEB-ONE",
            "deny", family="ipv6",
        )
    )
    assert [item.rule_id for item in _sonicos_effectiveness(
        _sonicos_policy(tmp_path, SONICOS_STATIC_OBJECTS + rules)
    )] == ["sonicwall.sonicos.policy.shadowed_rule"]


@pytest.mark.parametrize(
    "extra,parent_source,parent_service,schedule,child_command",
    [
        ("address-object ipv4 DYNAMIC fqdn dynamic.example.test\n", "name DYNAMIC", "name WEB-RANGE", "always-on", ""),
        ("address-group ipv4 CYCLE-A\n  address-group ipv4 CYCLE-B\naddress-group ipv4 CYCLE-B\n  address-group ipv4 CYCLE-A\n", "group CYCLE-A", "name WEB-RANGE", "always-on", ""),
        ("", "name WIDE", "name WEB-RANGE", "business-hours", ""),
        ("", "name WIDE", "name WEB-RANGE", "always-on", "  users included Corp-Users\n"),
    ],
)
def test_sonicos_dynamic_cycle_schedule_and_extra_predicates_block_proof(
    tmp_path, extra, parent_source, parent_service, schedule, child_command
):
    rules = _sonicos_rule(
        "PARENT", parent_source, "name HOST", parent_service,
        schedule=schedule, children="  enable\n  logging\n" + child_command,
    ) + _sonicos_rule("CHILD", "name NARROW", "name HOST", "name WEB-ONE", "deny")
    assert not any(
        item.rule_id.endswith(("shadowed_rule", "redundant_rule"))
        for item in _sonicos_effectiveness(
            _sonicos_policy(tmp_path, SONICOS_STATIC_OBJECTS + extra + rules)
        )
    )


def test_sonicos_same_action_requires_equivalent_logging_behavior(tmp_path):
    rules = _sonicos_rule(
        "PARENT", "name WIDE", "name HOST", "name WEB-RANGE",
        children="  enable\n  logging\n",
    ) + _sonicos_rule(
        "CHILD", "name NARROW", "name HOST", "name WEB-ONE",
        children="  enable\n  no logging\n",
    )
    assert not any(
        item.rule_id == "sonicwall.sonicos.policy.redundant_rule"
        for item in _sonicos_effectiveness(
            _sonicos_policy(tmp_path, SONICOS_STATIC_OBJECTS + rules)
        )
    )


def test_sonicos_policy_hygiene_is_independent_of_static_object_proof(tmp_path):
    rules = _sonicos_rule(
        "DISABLED", "any", "any", "any", from_zone="any", to_zone="any",
        children="  no enable\n",
    ) + _sonicos_rule("BROAD-SERVICE", "name NARROW", "name HOST", "any")
    assert {
        "sonicwall.sonicos.policy.disabled_permissive_rule",
        "sonicwall.sonicos.policy.broad_service",
    }.issubset(item.rule_id for item in _sonicos_effectiveness(
        _sonicos_policy(tmp_path, SONICOS_STATIC_OBJECTS + rules)
    ))
