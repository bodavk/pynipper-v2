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
ssl trust-point MGMT-CERT outside
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


def test_public_asa_pipeline_has_stable_unique_rule_ids(tmp_path):
    path = tmp_path / "asa.conf"
    path.write_text(VULNERABLE, encoding="utf-8")
    issues = list(process_asa_conf(CiscoASAParser(str(path))).values())
    identities = [(issue.rule_id, issue.evidence) for issue in issues]
    assert len(identities) == len(set(identities))
    assert "cisco.asa.failover.authentication" in {issue.rule_id for issue in issues}
