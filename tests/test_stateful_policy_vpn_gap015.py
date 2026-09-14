from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.analyze.fortinet.plugins.fortios_baseline_plugin import PluginFortiOSBaseline
from src.analyze.juniper.junos.core.process_junos_conf import process_junos_conf
from src.analyze.juniper.junos.plugins.junos_checks_plugin import PluginJunOSChecks
from src.devices.fortinet.fortios import FortiOSParser
from src.devices.juniper.junos import JunOSParser


def _fortios(tmp_path, config: str) -> FortiOSParser:
    path = tmp_path / "gap015-fortios.conf"
    path.write_text(config, encoding="utf-8")
    return FortiOSParser(str(path))


def _junos(tmp_path, config: str) -> JunOSParser:
    path = tmp_path / "gap015-junos.conf"
    path.write_text(config, encoding="utf-8")
    return JunOSParser(str(path))


def test_fortios_local_in_is_family_scope_negation_and_status_aware(tmp_path):
    parser = _fortios(
        tmp_path,
        """config firewall local-in-policy
edit 1
set intf wan1
set srcaddr all
set dstaddr all
set action accept
set service HTTPS SSH
set schedule always
next
edit 2
set intf wan1
set srcaddr MGMT-NETS
set action accept
set service HTTPS
set schedule always
next
edit 3
set intf wan1
set srcaddr all
set srcaddr-negate enable
set action accept
set service ALL
set schedule always
next
edit 4
set status disable
set intf wan1
set srcaddr all
set action accept
set service ALL
set schedule always
next
end
config firewall local-in-policy6
edit 10
set intf wan1
set srcaddr all6
set dstaddr all6
set action accept
set service SNMP
set schedule always
next
end
config firewall policy
edit 99
set srcintf any
set dstintf any
set srcaddr all
set dstaddr all
set action accept
set service ALL
next
end
""",
    )
    policies = parser.get_local_in_policies()
    assert [(item.family, item.name, item.enabled) for item in policies] == [
        ("ipv4", "1", True),
        ("ipv4", "2", True),
        ("ipv4", "3", True),
        ("ipv4", "4", False),
        ("ipv6", "10", True),
    ]
    plugin = PluginFortiOSBaseline()
    plugin.check_local_in_policy(parser)
    findings = plugin.get_issues()
    assert len(findings) == 2
    assert all(
        item.rule_id == "fortinet.fortios.local_in.unrestricted_management"
        for item in findings
    )
    observations = " ".join(item.observation for item in findings)
    assert "policy '1'" in observations and "policy '10'" in observations
    assert "policy '99'" not in observations


def test_fortios_ipsec_resolves_only_enabled_same_vdom_phase_chains(tmp_path):
    parser = _fortios(
        tmp_path,
        """config vdom
edit blue
config vpn ipsec phase1-interface
edit WEAK-P1
set ike-version 2
set proposal aes256-sha1 3des-md5
set dhgrp 2 14
set psksecret never-expose-this
next
edit DISABLED-P1
set status disable
set proposal 3des-md5
set dhgrp 2
next
edit UNUSED-P1
set proposal 3des-md5
set dhgrp 2
next
end
config vpn ipsec phase2-interface
edit WEAK-P2
set phase1name WEAK-P1
set proposal aes256-sha1
set pfs disable
set replay disable
next
edit DISABLED-P2
set phase1name DISABLED-P1
set proposal 3des-md5
next
edit WRONG-VDOM
set phase1name RED-P1
set proposal aes256-sha256
next
end
next
edit red
config vpn ipsec phase1-interface
edit RED-P1
set proposal aes256-sha256
set dhgrp 14
next
end
next
end
""",
    )
    tunnels = {(item.scope, item.name): item for item in parser.get_ipsec_tunnels()}
    assert tunnels[("blue", "WEAK-P2")].resolution_state == "resolved"
    assert tunnels[("blue", "WEAK-P2")].active
    assert not tunnels[("blue", "DISABLED-P2")].active
    assert tunnels[("blue", "WRONG-VDOM")].resolution_state == "unresolved"
    assert "never-expose-this" not in repr(tunnels)

    plugin = PluginFortiOSBaseline()
    plugin.check_ipsec_tunnels(parser)
    assert [item.rule_id for item in plugin.get_issues()] == [
        "fortinet.fortios.vpn.weak_proposal",
        "fortinet.fortios.vpn.unresolved",
    ]
    evidence = " ".join(value for item in plugin.get_issues() for value in item.evidence)
    assert "never-expose-this" not in evidence
    assert "UNUSED-P1" not in " ".join(item.observation for item in plugin.get_issues())


def test_fortios_strong_tunnel_and_non_always_local_in_are_not_findings(tmp_path):
    parser = _fortios(
        tmp_path,
        """config firewall local-in-policy
edit 1
set intf wan1
set srcaddr all
set action accept
set service HTTPS
set schedule BUSINESS-HOURS
next
end
config vpn ipsec phase1-interface
edit P1
set ike-version 2
set proposal aes256-sha256
set dhgrp 14 19
next
end
config vpn ipsec phase2-interface
edit P2
set phase1name P1
set proposal aes256gcm
set pfs enable
set dhgrp 14
set replay enable
next
end
""",
    )
    plugin = PluginFortiOSBaseline()
    plugin.check_local_in_policy(parser)
    plugin.check_ipsec_tunnels(parser)
    assert plugin.get_issues() == []


def test_junos_stateful_policy_resolves_address_books_defaults_and_zone_scope(tmp_path):
    parser = _junos(
        tmp_path,
        """set version 22.4R1.10
set security address-book TRUST address ALL-SOURCE 0.0.0.0/0
set security address-book TRUST address-set ALL-SOURCES address ALL-SOURCE
set security address-book TRUST attach zone trust
set security address-book global address ALL-DESTINATION 0.0.0.0/0
set security address-book OTHER address OTHER-ONLY 0.0.0.0/0
set security address-book OTHER attach zone other
set applications application HTTPS protocol tcp
set applications application HTTPS destination-port 443
set security policies from-zone trust to-zone untrust policy INHERITED-ANY match source-address ALL-SOURCES
set security policies from-zone trust to-zone untrust policy INHERITED-ANY match destination-address ALL-DESTINATION
set security policies from-zone trust to-zone untrust policy INHERITED-ANY then permit
set security policies from-zone trust to-zone untrust policy RESTRICTED-APP match source-address any
set security policies from-zone trust to-zone untrust policy RESTRICTED-APP match destination-address any
set security policies from-zone trust to-zone untrust policy RESTRICTED-APP match application HTTPS
set security policies from-zone trust to-zone untrust policy RESTRICTED-APP then permit
set security policies from-zone trust to-zone untrust policy WRONG-ZONE match source-address OTHER-ONLY
set security policies from-zone trust to-zone untrust policy WRONG-ZONE match destination-address any
set security policies from-zone trust to-zone untrust policy WRONG-ZONE match application any
set security policies from-zone trust to-zone untrust policy WRONG-ZONE then permit
set security policies from-zone trust to-zone untrust policy DISABLED match source-address any
set security policies from-zone trust to-zone untrust policy DISABLED match destination-address any
set security policies from-zone trust to-zone untrust policy DISABLED match application any
set security policies from-zone trust to-zone untrust policy DISABLED then permit
deactivate security policies from-zone trust to-zone untrust policy DISABLED
set security policies from-zone trust to-zone untrust policy DELETED match source-address any
set security policies from-zone trust to-zone untrust policy DELETED match destination-address any
set security policies from-zone trust to-zone untrust policy DELETED then permit
delete security policies from-zone trust to-zone untrust policy DELETED
""",
    )
    policies = {item.name: item for item in parser.get_security_policies()}
    assert policies["INHERITED-ANY"].source_resolution == "wildcard"
    assert policies["INHERITED-ANY"].destination_resolution == "wildcard"
    assert policies["INHERITED-ANY"].application_resolution == "default-any"
    assert policies["RESTRICTED-APP"].application_resolution == "resolved"
    assert policies["WRONG-ZONE"].source_resolution == "unresolved"
    assert not policies["DISABLED"].active
    assert "DELETED" not in policies

    plugin = PluginJunOSChecks()
    plugin.check_stateful_policies(parser)
    assert [item.rule_id for item in plugin.get_issues()] == [
        "juniper.junos.policy.broad_permit"
    ]
    assert "INHERITED-ANY" in plugin.get_issues()[0].observation


def test_junos_apply_groups_keeps_stateful_policy_uncertain(tmp_path):
    parser = _junos(
        tmp_path,
        """set version 22.4R1.10
set apply-groups POLICY-INHERITANCE
set security policies from-zone trust to-zone untrust policy ANY match source-address any
set security policies from-zone trust to-zone untrust policy ANY match destination-address any
set security policies from-zone trust to-zone untrust policy ANY then permit
""",
    )
    assert parser.get_security_policies()[0].inheritance_unknown
    plugin = PluginJunOSChecks()
    plugin.check_stateful_policies(parser)
    assert plugin.get_issues() == []


def _junos_vpn_chain(prefix: str, weak: bool) -> str:
    ike_encryption = "3des-cbc" if weak else "aes-256-cbc"
    authentication = "sha1" if weak else "sha-256"
    dh_group = "group2" if weak else "group14"
    ipsec_encryption = "des-cbc" if weak else "aes-256-gcm"
    ipsec_authentication = "hmac-md5-96" if weak else "hmac-sha-256-128"
    return f"""set security ike proposal {prefix}-IKE encryption-algorithm {ike_encryption}
set security ike proposal {prefix}-IKE authentication-algorithm {authentication}
set security ike proposal {prefix}-IKE dh-group {dh_group}
set security ike policy {prefix}-IKE-POL proposals {prefix}-IKE
set security ike gateway {prefix}-GW ike-policy {prefix}-IKE-POL
set security ipsec proposal {prefix}-IPSEC encryption-algorithm {ipsec_encryption}
set security ipsec proposal {prefix}-IPSEC authentication-algorithm {ipsec_authentication}
set security ipsec policy {prefix}-IPSEC-POL proposals {prefix}-IPSEC
set security ipsec policy {prefix}-IPSEC-POL perfect-forward-secrecy keys {dh_group}
set security ipsec vpn {prefix}-VPN ike gateway {prefix}-GW
set security ipsec vpn {prefix}-VPN ike ipsec-policy {prefix}-IPSEC-POL
"""


def test_junos_vpn_grades_only_attached_or_interface_bound_complete_chains(tmp_path):
    config = "set version 22.4R1.10\n"
    config += _junos_vpn_chain("WEAK", True)
    config += _junos_vpn_chain("STRONG", False)
    config += _junos_vpn_chain("UNUSED", True)
    config += _junos_vpn_chain("DISABLED", True)
    config += "set security ipsec vpn STRONG-VPN bind-interface st0.0\n"
    config += "deactivate security ipsec vpn DISABLED-VPN\n"
    config += "set security policies from-zone trust to-zone untrust policy VPN-TRAFFIC match source-address any\n"
    config += "set security policies from-zone trust to-zone untrust policy VPN-TRAFFIC match destination-address any\n"
    config += "set security policies from-zone trust to-zone untrust policy VPN-TRAFFIC match application junos-https\n"
    config += "set security policies from-zone trust to-zone untrust policy VPN-TRAFFIC then permit tunnel ipsec-vpn WEAK-VPN\n"
    config += "set security policies from-zone trust to-zone untrust policy DISABLED-VPN-POLICY match source-address any\n"
    config += "set security policies from-zone trust to-zone untrust policy DISABLED-VPN-POLICY match destination-address any\n"
    config += "set security policies from-zone trust to-zone untrust policy DISABLED-VPN-POLICY then permit tunnel ipsec-vpn DISABLED-VPN\n"

    parser = _junos(tmp_path, config)
    vpns = {item.name: item for item in parser.get_ipsec_vpns()}
    assert set(vpns) == {"WEAK-VPN", "STRONG-VPN", "DISABLED-VPN"}
    assert vpns["WEAK-VPN"].resolution_state == "resolved"
    assert vpns["STRONG-VPN"].resolution_state == "resolved"
    assert not vpns["DISABLED-VPN"].active
    assert "UNUSED-VPN" not in vpns

    plugin = PluginJunOSChecks()
    plugin.check_ipsec_vpns(parser)
    assert [item.rule_id for item in plugin.get_issues()] == [
        "juniper.junos.vpn.weak_proposal"
    ]
    assert "WEAK-VPN" in plugin.get_issues()[0].observation


def test_junos_unresolved_attached_vpn_and_public_processors(tmp_path):
    junos = _junos(
        tmp_path,
        """set version 22.4R1.10
set security policies from-zone trust to-zone untrust policy VPN match source-address any
set security policies from-zone trust to-zone untrust policy VPN match destination-address any
set security policies from-zone trust to-zone untrust policy VPN match application junos-https
set security policies from-zone trust to-zone untrust policy VPN then permit tunnel ipsec-vpn MISSING
""",
    )
    assert junos.get_ipsec_vpns()[0].resolution_state == "unresolved"
    assert "juniper.junos.vpn.unresolved" in {
        item.rule_id for item in process_junos_conf(junos).values()
    }

    forti = _fortios(
        tmp_path,
        """config firewall local-in-policy
edit 1
set intf wan1
set srcaddr all
set action accept
set service HTTPS
set schedule always
next
end
""",
    )
    assert "fortinet.fortios.local_in.unrestricted_management" in {
        item.rule_id for item in process_fortios_conf(forti).values()
    }


def test_junos_builtin_proposal_sets_and_unsupported_export_remain_unknown(tmp_path):
    parser = _junos(
        tmp_path,
        """set version 22.4R1.10
set security ike policy BUILTIN-IKE proposal-set standard
set security ike gateway GW ike-policy BUILTIN-IKE
set security ipsec policy BUILTIN-IPSEC proposal-set standard
set security ipsec vpn BUILTIN-VPN ike gateway GW
set security ipsec vpn BUILTIN-VPN ike ipsec-policy BUILTIN-IPSEC
set security ipsec vpn BUILTIN-VPN bind-interface st0.0
""",
    )
    assert parser.get_ipsec_vpns()[0].resolution_state == "vendor-default"
    plugin = PluginJunOSChecks()
    plugin.check_ipsec_vpns(parser)
    assert plugin.get_issues() == []

    unsupported = _junos(
        tmp_path,
        "Policy: runtime-only\n  State: enabled\n  Sessions: 42\n",
    )
    assert unsupported.parse_error
    assert unsupported.get_security_policies() == []
