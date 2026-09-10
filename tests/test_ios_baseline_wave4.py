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
aaa accounting exec default start-stop group tacacs+
username admin privilege 15 algorithm-type scrypt secret REDACTED
enable algorithm-type scrypt secret REDACTED
no ip source-route
logging host 192.0.2.50
logging trap informational
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
control-plane
 service-policy input COPP
line con 0
 exec-timeout 5 0
 login local
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
        "cisco.ios.credentials.local_storage",
        "cisco.ios.credentials.enable_storage",
        "cisco.ios.snmp.legacy_community",
        "cisco.ios.logging.remote_destination",
        "cisco.ios.ntp.authentication",
        "cisco.ios.banner.login",
        "cisco.ios.services.unnecessary",
        "cisco.ios.ip.source_route",
        "cisco.ios.interface.ip_hardening",
        "cisco.ios.control_plane.copp",
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


def test_ios_baseline_negations_and_shutdown_interfaces(tmp_path):
    config = SECURE.replace(
        "interface GigabitEthernet0/0\n ip address 198.51.100.1 255.255.255.0\n no ip redirects\n no ip proxy-arp\n no shutdown",
        "interface GigabitEthernet0/0\n ip address 198.51.100.1 255.255.255.0\n shutdown",
    )
    _, issues = _analyze(tmp_path, config)
    assert "cisco.ios.interface.ip_hardening" not in {issue.rule_id for issue in issues}
