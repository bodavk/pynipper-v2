from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.analyze.cisco.asa.plugins.baseline_plugin import PluginASABaseline
from src.devices.cisco.asa import CiscoASAParser


def _analyze(tmp_path, config):
    path = tmp_path / "asa.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoASAParser(str(path))
    plugin = PluginASABaseline()
    plugin.analyze(parser)
    return parser, plugin.get_issues()


VULNERABLE = """ASA Version 9.18(4)
hostname vulnerable
username admin password cisco privilege 15
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 198.51.100.1 255.255.255.0
ssh 0.0.0.0 0.0.0.0 outside
http server enable
http 0.0.0.0 0.0.0.0 outside
ntp server 192.0.2.123 source inside
crypto ikev1 policy 10
 encryption 3des
 hash md5
 group 2
crypto ipsec ikev1 transform-set WEAK esp-3des esp-md5-hmac
failover
"""


SECURE = """ASA Version 9.18(4)
hostname secure
username admin password opaquehash pbkdf2 privilege 15
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 198.51.100.1 255.255.255.0
ssh 192.0.2.0 255.255.255.0 outside
http server enable
http 192.0.2.0 255.255.255.0 outside
aaa authentication ssh console TACACS LOCAL
aaa authentication http console TACACS LOCAL
aaa accounting ssh console TACACS
aaa accounting http console TACACS
aaa-server TACACS protocol tacacs+
console timeout 15
ssl trust-point MGMT-CERT outside
crypto ca trustpoint MGMT-CERT
 enrollment terminal
crypto ca certificate chain MGMT-CERT
 certificate 01
ntp authenticate
ntp trusted-key 1
ntp authentication-key 1 sha256 REDACTED
ntp server 192.0.2.123 source inside key 1
threat-detection basic-threat
ip verify reverse-path interface outside
crypto ikev1 policy 10
 encryption aes-256
 hash sha256
 group 19
crypto ipsec ikev1 transform-set STRONG esp-aes-256 esp-sha-256-hmac
"""


def test_asa_baseline_vulnerable_rule_snapshot_and_redaction(tmp_path):
    _, issues = _analyze(tmp_path, VULNERABLE)
    rule_ids = {issue.rule_id for issue in issues}
    assert rule_ids == {
        "cisco.asa.aaa.management_authentication",
        "cisco.asa.aaa.management_accounting",
        "cisco.asa.credentials.local_user_storage",
        "cisco.asa.management.unrestricted_http",
        "cisco.asa.management.certificate",
        "cisco.asa.ntp.authentication",
        "cisco.asa.threat_detection.basic",
        "cisco.asa.interface.reverse_path",
        "cisco.asa.crypto.legacy_vpn",
        "cisco.asa.crypto.legacy_transform",
        "cisco.asa.failover.authentication",
        "cisco.asa.console.session_timeout",
    }
    assert all("cisco" not in " ".join(issue.evidence).casefold() for issue in issues)


def test_asa_baseline_secure_configuration_has_no_findings(tmp_path):
    _, issues = _analyze(tmp_path, SECURE)
    assert issues == []


def test_asa_baseline_not_applicable_states(tmp_path):
    _, unknown = _analyze(tmp_path, "hostname unknown\n")
    assert unknown == []

    _, no_management = _analyze(
        tmp_path,
        "ASA Version 9.18(4)\nthreat-detection basic-threat\nntp server 192.0.2.1 key 1\n",
    )
    assert not {
        "cisco.asa.aaa.management_authentication",
        "cisco.asa.aaa.management_accounting",
    } & {issue.rule_id for issue in no_management}


def test_asa_ntp_resolves_each_key_and_uses_release_algorithm_boundary(tmp_path):
    parser, issues = _analyze(
        tmp_path,
        '''ASA Version 9.18(4)
ntp authenticate
ntp trusted-key 1
ntp authentication-key 1 sha256 TOPSECRET
ntp server 192.0.2.1 key 1 source inside
ntp trusted-key 2
ntp authentication-key 2 md5 OTHERSECRET
ntp server 192.0.2.2 key 2 source inside
ntp server 192.0.2.3 source inside
threat-detection basic-threat
''',
    )
    associations = parser.get_ntp_associations()
    assert [item.authentication_state for item in associations] == [
        "authenticated",
        "authenticated",
        "unauthenticated",
    ]
    ntp_issues = [item for item in issues if item.rule_id.startswith("cisco.asa.ntp.")]
    assert [item.rule_id for item in ntp_issues] == [
        "cisco.asa.ntp.weak_algorithm",
        "cisco.asa.ntp.authentication",
    ]
    assert "192.0.2.2" in ntp_issues[0].observation
    assert "192.0.2.3" in ntp_issues[1].observation
    assert all(
        secret not in " ".join(evidence for item in ntp_issues for evidence in item.evidence)
        for secret in ("TOPSECRET", "OTHERSECRET")
    )


def test_asa_pre_913_preserves_md5_only_platform_capability(tmp_path):
    _, issues = _analyze(
        tmp_path,
        '''ASA Version 9.12(4)
ntp authenticate
ntp trusted-key 1
ntp authentication-key 1 md5 secret
ntp server 192.0.2.1 key 1
threat-detection basic-threat
''',
    )
    assert "cisco.asa.ntp.weak_algorithm" not in {item.rule_id for item in issues}


def test_public_asa_pipeline_has_stable_unique_rule_ids(tmp_path):
    path = tmp_path / "asa.conf"
    path.write_text(VULNERABLE, encoding="utf-8")
    issues = list(process_asa_conf(CiscoASAParser(str(path))).values())
    identities = [(issue.rule_id, issue.evidence) for issue in issues]
    assert len(identities) == len(set(identities))
    assert "cisco.asa.failover.authentication" in {issue.rule_id for issue in issues}


def test_asa_aaa_bindings_are_resolved_per_active_protocol(tmp_path):
    parser, _ = _analyze(
        tmp_path,
        '''ASA Version 9.18(4)
username admin password opaquehash pbkdf2 privilege 15
aaa-server TACACS protocol tacacs+
ssh 192.0.2.0 255.255.255.0 outside
http server enable
http 192.0.2.0 255.255.255.0 outside
aaa authentication ssh console TACACS LOCAL
aaa accounting ssh console TACACS
console timeout 15
''',
    )
    plugin = PluginASABaseline()
    plugin.check_aaa(parser)
    findings = plugin.get_issues()
    assert len(findings) == 1
    assert findings[0].rule_id == "cisco.asa.aaa.management_authentication"
    assert "HTTP" in findings[0].observation


def test_asa_aaa_undefined_group_and_negation_do_not_pass(tmp_path):
    parser, _ = _analyze(
        tmp_path,
        '''ASA Version 9.18(4)
ssh 192.0.2.0 255.255.255.0 outside
aaa-server TACACS protocol tacacs+
no aaa-server TACACS
aaa authentication ssh console TACACS LOCAL
aaa accounting ssh console TACACS
''',
    )
    bindings = parser.get_administrative_aaa_bindings()
    assert bindings and not all(item.resolved for item in bindings)


def test_asa_ssh_version_defaults_are_release_aware(tmp_path):
    old, _ = _analyze(
        tmp_path,
        "ASA Version 9.8(4)\nssh 192.0.2.0 255.255.255.0 outside\nconsole timeout 15\n",
    )
    modern, _ = _analyze(
        tmp_path,
        "ASA Version 9.18(4)\nssh 192.0.2.0 255.255.255.0 outside\nconsole timeout 15\n",
    )
    old_plugin = PluginASABaseline()
    old_plugin.check_management_sessions_and_ssh(old)
    modern_plugin = PluginASABaseline()
    modern_plugin.check_management_sessions_and_ssh(modern)
    assert "cisco.asa.ssh.protocol_version" in {
        issue.rule_id for issue in old_plugin.get_issues()
    }
    assert "cisco.asa.ssh.protocol_version" not in {
        issue.rule_id for issue in modern_plugin.get_issues()
    }


def test_asa_explicit_weak_ssh_policy_and_malformed_timeout(tmp_path):
    parser, _ = _analyze(
        tmp_path,
        '''ASA Version 9.18(4)
ssh 192.0.2.0 255.255.255.0 outside
ssh timeout never
ssh cipher encryption custom 3des-cbc:aes256-ctr
ssh cipher integrity custom hmac-md5:hmac-sha2-256
ssh key-exchange group dh-group14-sha1
console timeout 15
''',
    )
    assert parser.get_ssh_timeout().value is None
    assert parser.get_ssh_timeout().parse_error
    plugin = PluginASABaseline()
    plugin.check_management_sessions_and_ssh(parser)
    assert [issue.rule_id for issue in plugin.get_issues()] == [
        "cisco.asa.ssh.weak_algorithms"
    ]


def test_disabled_asa_https_server_does_not_activate_stale_grant(tmp_path):
    parser, _ = _analyze(
        tmp_path,
        '''ASA Version 9.18(4)
http 192.0.2.0 255.255.255.0 outside
http server enable
no http server enable
console timeout 15
''',
    )
    assert parser.get_services()["http"] is False
    plugin = PluginASABaseline()
    plugin.check_aaa(parser)
    assert plugin.get_issues() == []


def test_gap006_asa_baseline_is_not_applied_to_unqualified_pix_alias(tmp_path):
    parser, _ = _analyze(
        tmp_path,
        "version 6.3\nssh 0.0.0.0 0.0.0.0 outside\n",
    )
    parser.device_type = "PIX"
    plugin = PluginASABaseline()
    plugin.analyze(parser)
    assert plugin.get_issues() == []
