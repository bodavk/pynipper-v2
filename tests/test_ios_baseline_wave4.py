from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.devices.cisco.ios import CiscoIOSParser


def _analyze(tmp_path, config):
    path = tmp_path / "ios.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    plugin = PluginIOSBaseline()
    plugin.analyze(parser)
    return parser, plugin.get_issues()


VULNERABLE = """version 15.2(4)M7
hostname vulnerable
username admin privilege 15 password 0 Password123
enable password 0 Enable123
service tcp-small-servers
snmp-server community public rw
ntp server 192.0.2.123
interface GigabitEthernet0/0
 ip address 198.51.100.1 255.255.255.0
 no shutdown
line con 0
 exec-timeout 0 0
line aux 0
 exec
 exec-timeout 0 0
 transport input all
 transport output telnet
line vty 0 4
 exec-timeout 0 0
 password cisco
 transport input all
crypto isakmp policy 10
 encryption 3des
 hash md5
 group 2
crypto ipsec transform-set WEAK esp-3des esp-md5-hmac
"""


SECURE = """version 15.2(4)M7
hostname secure
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa authorization commands 15 default group tacacs+ local
aaa accounting exec default start-stop group tacacs+
username admin privilege 15 algorithm-type scrypt secret REDACTED
enable algorithm-type scrypt secret REDACTED
no ip source-route
logging host 192.0.2.50
logging trap informational
archive
 log config
  logging enable
  hidekeys
  notify syslog
ntp authenticate
ntp authentication-key 1 md5 REDACTED
ntp trusted-key 1
ntp server 192.0.2.123 key 1
banner login ^Authorized access only^
snmp-server group SECURE v3 priv
interface GigabitEthernet0/0
 ip address 198.51.100.1 255.255.255.0
 no ip redirects
 no ip proxy-arp
 no shutdown
ip access-list extended COPP-MGMT
 permit tcp 192.0.2.0 0.0.0.255 any eq 22
class-map match-any COPP-MGMT
 match access-group name COPP-MGMT
policy-map COPP
 class COPP-MGMT
  police 128000 conform-action transmit exceed-action drop
 class class-default
  police 64000 conform-action transmit exceed-action drop
control-plane
 service-policy input COPP
line con 0
 exec-timeout 5 0
 login local
line aux 0
 no exec
 exec-timeout 0 1
 no password
 transport input none
 transport output none
line vty 0 4
 exec-timeout 5 0
 login authentication default
 transport input ssh
 access-class MGMT in
crypto isakmp policy 10
 encryption aes 256
 hash sha256
 group 19
crypto ipsec transform-set STRONG esp-aes 256 esp-sha256-hmac
"""


def test_ios_baseline_vulnerable_rule_snapshot(tmp_path):
    _, issues = _analyze(tmp_path, VULNERABLE)
    rule_ids = {issue.rule_id for issue in issues}
    assert rule_ids == {
        "cisco.ios.aaa.new_model",
        "cisco.ios.vty.telnet",
        "cisco.ios.vty.session_timeout",
        "cisco.ios.vty.authentication",
        "cisco.ios.console.session_timeout",
        "cisco.ios.console.authentication",
        "cisco.ios.auxiliary.enabled",
        "cisco.ios.auxiliary.authentication",
        "cisco.ios.auxiliary.session_timeout",
        "cisco.ios.credentials.local_storage",
        "cisco.ios.credentials.enable_storage",
        "cisco.ios.credentials.line_password_storage",
        "cisco.ios.credentials.known_default_value",
        "cisco.ios.snmp.legacy_community",
        "cisco.ios.snmp.default_community",
        "cisco.ios.logging.remote_destination",
        "cisco.ios.ntp.authentication",
        "cisco.ios.banner.login",
        "cisco.ios.services.unnecessary",
        "cisco.ios.ip.source_route",
        "cisco.ios.interface.ip_hardening",
        "cisco.ios.control_plane.copp",
        "cisco.ios.configuration.change_logging",
        "cisco.ios.crypto.legacy_ike",
        "cisco.ios.crypto.legacy_ipsec",
    }
    assert all("Password123" not in " ".join(issue.evidence) for issue in issues)
    assert all("Enable123" not in " ".join(issue.evidence) for issue in issues)


def test_ios_baseline_secure_configuration_has_no_findings(tmp_path):
    _, issues = _analyze(tmp_path, SECURE)
    assert issues == []


def test_ios_baseline_unknown_version_is_explicitly_not_applied(tmp_path):
    _, issues = _analyze(tmp_path, "hostname unknown-release\n")
    assert issues == []


def test_ios_ntp_associations_resolve_keys_independently_and_redact_material(tmp_path):
    parser, issues = _analyze(
        tmp_path,
        '''version 17.9
ntp authenticate
ntp authentication-key 1 md5 TOPSECRET
ntp trusted-key 1
ntp server vrf MGMT 192.0.2.1 key 1
ntp authentication-key 2 md5 OTHERSECRET
ntp trusted-key 2
ntp peer 192.0.2.2 key 2
no ntp authentication-key 2
ntp server 192.0.2.3
''',
    )
    associations = parser.get_ntp_associations()
    assert [(item.role, item.address, item.authentication_state) for item in associations] == [
        ("server", "192.0.2.1", "authenticated"),
        ("peer", "192.0.2.2", "unresolved"),
        ("server", "192.0.2.3", "unauthenticated"),
    ]
    ntp_findings = [item for item in issues if item.rule_id == "cisco.ios.ntp.authentication"]
    assert len(ntp_findings) == 2
    assert {item.observation.split("'")[1] for item in ntp_findings} == {
        "192.0.2.2",
        "192.0.2.3",
    }
    assert all(
        secret not in " ".join(evidence for item in ntp_findings for evidence in item.evidence)
        for secret in ("TOPSECRET", "OTHERSECRET")
    )


def test_ios_baseline_negations_and_shutdown_interfaces(tmp_path):
    config = SECURE.replace(
        "interface GigabitEthernet0/0\n ip address 198.51.100.1 255.255.255.0\n no ip redirects\n no ip proxy-arp\n no shutdown",
        "interface GigabitEthernet0/0\n ip address 198.51.100.1 255.255.255.0\n shutdown",
    )
    _, issues = _analyze(tmp_path, config)
    assert "cisco.ios.interface.ip_hardening" not in {issue.rule_id for issue in issues}


def test_management_lines_resolve_named_lists_overrides_and_disabled_aux(tmp_path):
    parser, _ = _analyze(
        tmp_path,
        '''version 17.9
aaa new-model
aaa authentication login OPS group tacacs+ local
aaa authorization exec OPS group tacacs+ local
aaa authorization commands 15 OPS group tacacs+ local
username recovery algorithm-type scrypt secret REDACTED
line aux 0
 exec
 no exec
 transport input all
 transport input none
 transport output none
 exec-timeout 0 1
 no password
line vty 0 4
 login authentication MISSING
 authorization exec OPS
 authorization commands 15 OPS
 transport input telnet
 no transport input telnet
 transport input ssh
 exec-timeout 5 0
''',
    )
    auxiliary, vty = parser.get_management_lines()
    assert auxiliary.line_type == "aux"
    assert auxiliary.exec_enabled is False
    assert auxiliary.transports == ("none",)
    assert auxiliary.output_transports == ("none",)
    assert vty.transports == ("ssh",)
    assert vty.login_list == "MISSING"
    assert dict(vty.command_authorization) == {15: "OPS"}

    plugin = PluginIOSBaseline()
    plugin.check_management_lines(parser)
    ids = {issue.rule_id for issue in plugin.get_issues()}
    assert ids == {"cisco.ios.vty.authentication"}


def test_vty_authorization_requires_resolved_exec_and_command_lists(tmp_path):
    parser, _ = _analyze(
        tmp_path,
        '''version 17.9
aaa new-model
aaa authentication login default local
username recovery algorithm-type scrypt secret REDACTED
line vty 0 4
 login authentication default
 transport input ssh
''',
    )
    plugin = PluginIOSBaseline()
    plugin.check_management_lines(parser)
    findings = [
        issue for issue in plugin.get_issues()
        if issue.rule_id == "cisco.ios.vty.authorization"
    ]
    assert len(findings) == 1
    assert "EXEC authorization" in findings[0].observation
    assert "privilege-15 command authorization" in findings[0].observation


def test_named_login_list_with_missing_custom_server_group_does_not_resolve(tmp_path):
    parser, _ = _analyze(
        tmp_path,
        '''version 17.9
aaa new-model
aaa authentication login OPS group MISSING local
username recovery algorithm-type scrypt secret REDACTED
line vty 0 4
 login authentication OPS
 transport input ssh
''',
    )
    plugin = PluginIOSBaseline()
    plugin.check_management_lines(parser)
    assert "cisco.ios.vty.authentication" in {
        issue.rule_id for issue in plugin.get_issues()
    }


def test_explicit_weak_ssh_algorithms_and_host_key_are_reported(tmp_path):
    parser, _ = _analyze(
        tmp_path,
        '''version 17.9
ip ssh version 2
ip ssh server algorithm encryption aes256-ctr 3des-cbc
ip ssh server algorithm mac hmac-sha2-512 hmac-sha1
ip ssh server algorithm kex curve25519-sha256 diffie-hellman-group14-sha1
ip ssh server algorithm hostkey rsa-sha2-512 ssh-rsa
crypto key generate rsa modulus 1024
line vty 0 4
 transport input ssh
''',
    )
    plugin = PluginIOSBaseline()
    plugin.check_ssh_policy(parser)
    assert {issue.rule_id for issue in plugin.get_issues()} == {
        "cisco.ios.ssh.weak_algorithms",
        "cisco.ios.ssh.weak_host_key",
    }


def test_unknown_or_reset_ssh_algorithm_defaults_are_not_asserted(tmp_path):
    parser, _ = _analyze(
        tmp_path,
        '''version 17.9
ip ssh version 2
ip ssh server algorithm encryption 3des-cbc
default ip ssh server algorithm encryption
crypto key generate rsa modulus invalid
line vty 0 4
 transport input ssh
''',
    )
    plugin = PluginIOSBaseline()
    plugin.check_ssh_policy(parser)
    assert plugin.get_issues() == []


def test_disabled_vty_does_not_require_authentication_or_authorization(tmp_path):
    parser, _ = _analyze(
        tmp_path,
        '''version 17.9
aaa new-model
line vty 0 4
 no exec
 transport input none
 exec-timeout many
''',
    )
    plugin = PluginIOSBaseline()
    plugin.check_management_lines(parser)
    assert plugin.get_issues() == []


def test_snmpv3_users_are_evaluated_independently_with_views_and_references(tmp_path):
    parser, issues = _analyze(
        tmp_path,
        '''version 17.9
snmp-server view LIMITED system included
snmp-server view BROAD iso included
snmp-server group SECURE v3 priv read LIMITED access SNMP-NMS
snmp-server group BROAD-GROUP v3 auth read BROAD
snmp-server user secure SECURE v3 auth sha AUTHSECRET priv aes 128 PRIVSECRET
snmp-server user hidden-keys SECURE v3 auth sha priv aes 128
snmp-server user weak BROAD-GROUP v3 auth md5 WEAKAUTH priv des WEAKPRIV
snmp-server user orphan MISSING v3 auth sha ORPHANAUTH priv aes 128 ORPHANPRIV
''',
    )
    _, groups, users = parser.get_snmpv3_relationships()
    assert {group.name for group in groups} == {"SECURE", "BROAD-GROUP"}
    assert {user.name: user.authentication_key_state for user in users} == {
        "secure": "present",
        "hidden-keys": "unknown",
        "weak": "present",
        "orphan": "present",
    }
    snmp = [issue for issue in issues if issue.rule_id.startswith("cisco.ios.snmp.v3_")]
    assert [(issue.rule_id, issue.observation.split("'")[1]) for issue in snmp] == [
        ("cisco.ios.snmp.v3_protection", "weak"),
        ("cisco.ios.snmp.v3_weak_algorithm", "weak"),
        ("cisco.ios.snmp.v3_access_scope", "weak"),
        ("cisco.ios.snmp.v3_reference", "orphan"),
    ]
    all_evidence = " ".join(value for issue in snmp for value in issue.evidence)
    assert all(secret not in all_evidence for secret in ("AUTHSECRET", "PRIVSECRET", "WEAKAUTH", "WEAKPRIV", "ORPHANAUTH", "ORPHANPRIV"))


def test_snmpv3_view_exclusion_and_effective_removals_are_honored(tmp_path):
    parser, issues = _analyze(
        tmp_path,
        '''version 17.9
snmp-server view LIMITED iso included
snmp-server view LIMITED system excluded
snmp-server group OLD v3 noauth
no snmp-server group OLD v3
snmp-server group SECURE v3 priv read LIMITED access SNMP-NMS
snmp-server user removed SECURE v3 auth sha ONE priv aes 128 TWO
no snmp-server user removed SECURE v3
snmp-server user monitor SECURE v3 auth sha THREE priv aes 128 FOUR
''',
    )
    _, groups, users = parser.get_snmpv3_relationships()
    assert [group.name for group in groups] == ["SECURE"]
    assert [user.name for user in users] == ["monitor"]
    assert not [issue for issue in issues if issue.rule_id.startswith("cisco.ios.snmp.v3_")]
