from src.analyze.cisco.iosxe.core.process_iosxe_conf import process_iosxe_conf
from src.analyze.cisco.iosxe.plugins.iosxe_checks_plugin import PluginIOSXEChecks
from src.devices.cisco.iosxe import CiscoIOSXEParser


def _analyze(tmp_path, config):
    path = tmp_path / "iosxe.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoIOSXEParser(str(path))
    plugin = PluginIOSXEChecks()
    plugin.analyze(parser)
    return parser, plugin.get_issues()


def test_macsec_only_checks_active_layer2_links(tmp_path):
    config = """interface Loopback0
 ip address 192.0.2.1 255.255.255.255
interface Tunnel10
 tunnel source Loopback0
interface GigabitEthernet1
 no switchport
interface GigabitEthernet2
 switchport
 shutdown
interface GigabitEthernet3
 switchport
"""
    _, issues = _analyze(tmp_path, config)
    macsec = [issue for issue in issues if issue.rule_id == "cisco.iosxe.macsec.missing"]
    assert len(macsec) == 1
    assert macsec[0].evidence[0] == "interface GigabitEthernet3"


def test_valid_macsec_references_and_cipher_pass(tmp_path):
    config = """mka policy MKA-SECURE
 macsec-cipher-suite gcm-aes-256
key chain MKA-KEYS macsec
 key 1
  key-string 7 REDACTED
interface Port-channel10
 switchport mode trunk
 mka policy MKA-SECURE
 mka pre-shared-key key-chain MKA-KEYS
 macsec network-link
"""
    _, issues = _analyze(tmp_path, config)
    assert "cisco.iosxe.macsec.missing" not in {issue.rule_id for issue in issues}


def test_dangling_macsec_references_are_reported(tmp_path):
    config = """interface TenGigabitEthernet1/0/1
 switchport
 mka policy MISSING-POLICY
 mka pre-shared-key key-chain MISSING-KEYS
 macsec network-link
"""
    _, issues = _analyze(tmp_path, config)
    finding = next(issue for issue in issues if issue.rule_id == "cisco.iosxe.macsec.missing")
    assert "defined MKA policy" in finding.observation
    assert "defined MACsec key chain" in finding.observation


def test_only_referenced_ikev2_proposals_are_evaluated(tmp_path):
    config = """crypto ikev2 proposal UNUSED-WEAK
 encryption 3des
 integrity md5
 prf sha1
 group 2
crypto ikev2 proposal ACTIVE-STRONG
 encryption aes-gcm-256
 prf sha384
 group 20
crypto ikev2 policy 10
 proposal ACTIVE-STRONG
"""
    _, issues = _analyze(tmp_path, config)
    assert "cisco.iosxe.crypto.legacy_ikev2" not in {issue.rule_id for issue in issues}


def test_active_ikev2_complete_weak_suite_is_reported(tmp_path):
    config = """crypto ikev2 proposal ACTIVE-WEAK
 encryption 3des
 integrity md5
 prf sha1
 group 14
crypto ikev2 policy 10
 proposal ACTIVE-WEAK
"""
    _, issues = _analyze(tmp_path, config)
    finding = next(issue for issue in issues if issue.rule_id == "cisco.iosxe.crypto.legacy_ikev2")
    assert "encryption" in finding.observation
    assert "integrity" in finding.observation
    assert "PRF" in finding.observation
    assert "Diffie-Hellman" in finding.observation


def test_active_ikev1_and_referenced_transform_sets_are_evaluated(tmp_path):
    config = """crypto isakmp policy 10
 encryption 3des
 hash md5
 group 2
crypto ipsec transform-set UNUSED esp-3des esp-md5-hmac
crypto ipsec transform-set ACTIVE esp-3des esp-md5-hmac
crypto map VPN 10 ipsec-isakmp
 set transform-set ACTIVE
"""
    _, issues = _analyze(tmp_path, config)
    rule_ids = [issue.rule_id for issue in issues]
    assert rule_ids.count("cisco.iosxe.crypto.legacy_ikev1") == 1
    assert rule_ids.count("cisco.iosxe.crypto.legacy_ipsec") == 1
    assert all("UNUSED" not in " ".join(issue.evidence) for issue in issues)


def test_iosxe_public_pipeline_composes_ios_baseline_once(tmp_path):
    config = """version 17.9
ip http server
ip http access-class MGMT
ip http authentication local
ip ssh version 1
ip ssh authentication-retries 3
ip ssh time-out 60
line vty 0 4
 transport input ssh
 access-class MGMT in
interface GigabitEthernet1
 switchport
crypto ikev2 proposal WEAK
 encryption 3des
 integrity md5
 prf sha1
 group 2
crypto ikev2 policy 10
 proposal WEAK
"""
    path = tmp_path / "composed.conf"
    path.write_text(config, encoding="utf-8")
    issues = list(process_iosxe_conf(CiscoIOSXEParser(str(path))).values())
    rule_ids = [issue.rule_id for issue in issues]

    assert "cisco.ios.http.cleartext_service" in rule_ids
    assert "cisco.ios.ssh.protocol_version" in rule_ids
    assert "cisco.iosxe.macsec.missing" in rule_ids
    assert "cisco.iosxe.crypto.legacy_ikev2" in rule_ids
    assert len(rule_ids) == len(set(rule_ids))
    assert all(issue.device == "IOS_XE" for issue in issues)
