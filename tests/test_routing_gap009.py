from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.juniper.junos import JunOSParser


def _file(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def _routing_issues(plugin_class, parser):
    plugin = plugin_class()
    plugin.check_routing(parser)
    return plugin.get_issues()


def test_ios_bgp_resolves_peer_group_af_vrf_shutdown_and_policies(tmp_path):
    parser = CiscoIOSParser(_file(tmp_path, "ios-bgp.conf", '''version 17.9
router bgp 65000
 no bgp default ipv4-unicast
 neighbor EDGE peer-group
 neighbor EDGE remote-as 65100
 neighbor EDGE password TOPSECRET
 neighbor 192.0.2.1 peer-group EDGE
 neighbor 192.0.2.2 remote-as 65101
 neighbor 192.0.2.2 shutdown
 address-family ipv4 unicast
  neighbor 192.0.2.1 activate
  neighbor 192.0.2.1 route-map IMPORT in
  neighbor 192.0.2.1 route-map EXPORT out
  neighbor 192.0.2.1 maximum-prefix 1000
 address-family ipv6 vrf BLUE
  neighbor 192.0.2.1 activate
  neighbor 192.0.2.1 route-map V6-IN in
  neighbor 192.0.2.1 route-map V6-OUT out
  neighbor 192.0.2.1 maximum-prefix 999999
  neighbor 192.0.2.2 activate
'''))

    peers = parser.get_bgp_neighbors()
    active = [peer for peer in peers if peer.active]
    assert [(peer.address_family, peer.vrf) for peer in active] == [
        ("ipv4 unicast", "default"),
        ("ipv6", "BLUE"),
    ]
    assert all(peer.authentication_state == "authenticated" for peer in active)
    assert all(peer.authentication_method == "md5" for peer in active)
    assert all(peer.inbound_policy and peer.outbound_policy and peer.prefix_limit for peer in active)
    assert _routing_issues(PluginIOSBaseline, parser) == []
    assert all("TOPSECRET" not in item.text for peer in peers for item in peer.evidence)


def test_ios_bgp_reports_each_missing_external_control_but_not_unknown_role(tmp_path):
    parser = CiscoIOSParser(_file(tmp_path, "ios-bgp-missing.conf", '''version 17.9
router bgp 65000
 neighbor 192.0.2.10 remote-as 65100
 neighbor unresolved.example.invalid description role-not-exported
'''))
    findings = _routing_issues(PluginIOSBaseline, parser)
    assert [item.rule_id for item in findings] == [
        "cisco.ios.routing.bgp.authentication",
        "cisco.ios.routing.bgp.inbound_policy",
        "cisco.ios.routing.bgp.outbound_policy",
        "cisco.ios.routing.bgp.prefix_limit",
    ]
    assert all("192.0.2.10" in item.observation for item in findings)


def test_ios_ospf_honors_override_passive_shutdown_rollover_and_unknown_algorithm(tmp_path):
    parser = CiscoIOSParser(_file(tmp_path, "ios-ospf.conf", '''version 17.9
key chain OSPF_KEYS
 key 1
  key-string FIRSTSECRET
 key 2
  key-string SECONDSECRET
  cryptographic-algorithm hmac-sha-256
key chain FUTURE_KEYS
 key 1
  key-string THIRDSECRET
  cryptographic-algorithm future-digest
router ospf 1 vrf BLUE
 area 0 authentication message-digest
 passive-interface default
 no passive-interface GigabitEthernet0/0
 no passive-interface GigabitEthernet0/3
interface GigabitEthernet0/0
 ip ospf 1 area 0
 ip ospf authentication null
interface GigabitEthernet0/1
 ip ospf 1 area 0
interface GigabitEthernet0/2
 ip ospf 1 area 0
 shutdown
interface GigabitEthernet0/3
 ip ospf 1 area 0
 ip ospf authentication key-chain FUTURE_KEYS
'''))
    records = parser.get_ospf_interfaces()
    assert len(records) == 4
    by_name = {item.interface: item for item in records}
    assert by_name["GigabitEthernet0/0"].authentication_state == "unauthenticated"
    assert by_name["GigabitEthernet0/1"].passive
    assert by_name["GigabitEthernet0/2"].shutdown
    assert by_name["GigabitEthernet0/3"].authentication_state == "unknown"
    findings = _routing_issues(PluginIOSBaseline, parser)
    assert [item.rule_id for item in findings] == ["cisco.ios.routing.ospf.authentication"]
    assert "GigabitEthernet0/0" in findings[0].observation
    assert all(secret not in " ".join(findings[0].evidence) for secret in ("FIRSTSECRET", "SECONDSECRET", "THIRDSECRET"))


def test_junos_bgp_resolves_keychain_rollover_family_scope_and_shutdown(tmp_path):
    parser = JunOSParser(_file(tmp_path, "junos-bgp.conf", '''set version 22.4R1.10
set security authentication-key-chains key-chain BGP-AO key 1 secret "FIRSTSECRET"
set security authentication-key-chains key-chain BGP-AO key 2 secret "SECONDSECRET"
set protocols bgp group TRANSIT type external
set protocols bgp group TRANSIT authentication-key-chain BGP-AO
set protocols bgp group TRANSIT authentication-algorithm ao
set protocols bgp group TRANSIT import IMPORT-TRANSIT
set protocols bgp group TRANSIT export EXPORT-TRANSIT
set protocols bgp group TRANSIT family inet6 unicast prefix-limit maximum 999999
set protocols bgp group TRANSIT neighbor 2001:db8::1
set protocols bgp group TRANSIT neighbor 2001:db8::2 shutdown
'''))
    peers = parser.get_bgp_neighbors()
    assert len(peers) == 2
    active = [peer for peer in peers if peer.active]
    assert len(active) == 1
    assert active[0].address_family == "inet6 unicast"
    assert active[0].authentication_state == "authenticated"
    assert active[0].prefix_limit
    assert _routing_issues(PluginJunOSBaseline, parser) == []
    assert all(secret not in item.text for peer in peers for item in peer.evidence for secret in ("FIRSTSECRET", "SECONDSECRET"))


def test_junos_external_bgp_missing_controls_and_unknown_algorithm_are_conservative(tmp_path):
    parser = JunOSParser(_file(tmp_path, "junos-bgp-edge.conf", '''set version 22.4R1.10
set protocols bgp group MISSING type external
set protocols bgp group MISSING neighbor 192.0.2.1
set security authentication-key-chains key-chain FUTURE key 1 secret "DO-NOT-LEAK"
set protocols bgp group UNKNOWN type external
set protocols bgp group UNKNOWN authentication-key-chain FUTURE
set protocols bgp group UNKNOWN authentication-algorithm future-ao
set protocols bgp group UNKNOWN import IMPORT
set protocols bgp group UNKNOWN export EXPORT
set protocols bgp group UNKNOWN family inet unicast prefix-limit maximum 1
set protocols bgp group UNKNOWN neighbor 192.0.2.2
'''))
    peers = parser.get_bgp_neighbors()
    assert {peer.address: peer.authentication_state for peer in peers} == {
        "192.0.2.1": "unauthenticated",
        "192.0.2.2": "unknown",
    }
    findings = _routing_issues(PluginJunOSBaseline, parser)
    assert [item.rule_id for item in findings] == [
        "juniper.junos.routing.bgp.authentication",
        "juniper.junos.routing.bgp.inbound_policy",
        "juniper.junos.routing.bgp.outbound_policy",
        "juniper.junos.routing.bgp.prefix_limit",
    ]
    assert all("192.0.2.1" in item.observation for item in findings)
    assert all("DO-NOT-LEAK" not in evidence for item in findings for evidence in item.evidence)


def test_junos_ospf_honors_simple_override_passive_disable_and_apply_groups_unknown(tmp_path):
    parser = JunOSParser(_file(tmp_path, "junos-ospf.conf", '''set version 22.4R1.10
set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication simple-password "CLEARTEXT"
set protocols ospf area 0.0.0.0 interface ge-0/0/1.0
set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 passive
set protocols ospf area 0.0.0.0 interface ge-0/0/2.0
set protocols ospf area 0.0.0.0 interface ge-0/0/2.0 disable
set protocols ospf area 0.0.0.0 interface ge-0/0/3.0 apply-groups OSPF-AUTH
'''))
    records = parser.get_ospf_interfaces()
    by_name = {item.interface: item for item in records}
    assert by_name["ge-0/0/0.0"].authentication_state == "weak"
    assert by_name["ge-0/0/1.0"].passive
    assert not by_name["ge-0/0/2.0"].active
    assert by_name["ge-0/0/3.0"].authentication_state == "unknown"
    findings = _routing_issues(PluginJunOSBaseline, parser)
    assert [item.rule_id for item in findings] == ["juniper.junos.routing.ospf.weak_authentication"]
    assert "CLEARTEXT" not in " ".join(findings[0].evidence)


def test_no_routing_process_is_not_applicable(tmp_path):
    ios = CiscoIOSParser(_file(tmp_path, "no-routing-ios.conf", "version 17.9\nhostname edge\n"))
    junos = JunOSParser(_file(tmp_path, "no-routing-junos.conf", "set version 22.4R1.10\nset system host-name edge\n"))
    assert _routing_issues(PluginIOSBaseline, ios) == []
    assert _routing_issues(PluginJunOSBaseline, junos) == []
