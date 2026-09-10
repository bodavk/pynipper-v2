import pytest

from src.analyze.sonicwall.core.process_sonicos_conf import process_sonicos_conf
from src.analyze.sonicwall.plugins.sonicos_checks_plugin import PluginSonicOSChecks
from src.devices.common.models import KnowledgeState
from src.devices.sonicwall.sonicos import SonicOSParser, UnsupportedSonicOSFormat


VULNERABLE = """firmware-version "SonicOS 7.1.2-7019"
product-name "TZ 570"
firewall-name "edge-fw"
interface X1
  zone WAN
  ip-address 198.51.100.1
  management http https ssh snmp
access-rule ipv4 from any to any action allow source address any service any destination address any schedule always-on
  name "BROAD"
  enable
  no logging
vpn policy site-to-site "LEGACY-TUNNEL"
  enable
  proposal ike encryption triple-des
  proposal ike authentication sha1
  proposal ike dh-group 2
  proposal ipsec encryption des
  proposal ipsec authentication md5
no gateway-anti-virus enable
no intrusion-prevention enable
no anti-spyware enable
capture-atp enable
no cloud-gateway-anti-virus enable
"""


SECURE = """firmware-version "SonicOS 7.1.2-7019"
product-name "TZ 570"
firewall-name "secure-fw"
interface X0
  zone LAN
  ip-address 10.0.0.1
  management https ssh
access-rule ipv4 from LAN to WAN action allow source address name Corp service name HTTPS destination address name Updates schedule always-on
  name "CONTROLLED"
  enable
  logging
vpn policy site-to-site "MODERN-TUNNEL"
  enable
  proposal ike encryption aes-256
  proposal ike authentication sha256
  proposal ike dh-group 19
  proposal ipsec encryption aes-gcm16-256
  proposal ipsec authentication sha256
log syslog server 192.0.2.20 enable
ntp-server 192.0.2.30 md5 trust-key-no 1 key-number 1 password redacted
gateway-anti-virus enable
intrusion-prevention enable
anti-spyware enable
capture-atp enable
cloud-gateway-anti-virus enable
"""


def _parse(tmp_path, content):
    path = tmp_path / "sonicos.txt"
    path.write_text(content, encoding="utf-8")
    return SonicOSParser(str(path))


def _issues(parser):
    plugin = PluginSonicOSChecks()
    plugin.analyze(parser)
    return plugin.get_issues()


def test_identifies_supported_ecli_and_populates_typed_state(tmp_path):
    parser = _parse(tmp_path, VULNERABLE)
    assert parser.format_name == "sonicos7-ecli-current-config"
    assert parser.get_hostname() == "edge-fw"
    assert parser.get_version() == "7.1.2-7019"
    assert parser.get_model() == "TZ 570"
    assert parser.get_interfaces()[0].management == ("http", "https", "ssh", "snmp")
    assert parser.get_access_rules()[0].name == "BROAD"
    assert parser.get_vpn_policies()[0].ike_encryption == "triple-des"
    assert parser.get_normalized_config().policies.state == KnowledgeState.KNOWN
    assert parser.get_normalized_config().users.state == KnowledgeState.UNKNOWN


@pytest.mark.parametrize(
    "content, expected",
    [
        ("set service http enable\nset admin password password\n", "test-only"),
        ("preferences-base64 AAECAwQ=\n", "preferences"),
        ('firmware-version "SonicOS Enhanced 6.5.4.13"\n', "missing SonicOS 7"),
    ],
)
def test_rejects_unsupported_or_incompatible_export_dialects(tmp_path, content, expected):
    with pytest.raises(UnsupportedSonicOSFormat, match=expected):
        _parse(tmp_path, content)


def test_vulnerable_sonicos_has_exact_findings(tmp_path):
    issues = _issues(_parse(tmp_path, VULNERABLE))
    assert [issue.rule_id for issue in issues] == [
        "sonicwall.sonicos.management.http",
        "sonicwall.sonicos.management.external_interface",
        "sonicwall.sonicos.policy.broad_allow",
        "sonicwall.sonicos.policy.logging",
        "sonicwall.sonicos.vpn.weak_proposal",
        "sonicwall.sonicos.snmp.secure_user_missing",
        "sonicwall.sonicos.logging.remote_destination",
        "sonicwall.sonicos.ntp.servers",
        "sonicwall.sonicos.security_services.disabled",
        "sonicwall.sonicos.capture_atp.dependencies",
    ]
    assert all(issue.references for issue in issues)


def test_disabled_rules_and_vpn_policies_are_ignored(tmp_path):
    parser = _parse(
        tmp_path,
        SECURE
        + """access-rule ipv4 from any to any action allow source address any service any destination address any
  name "DISABLED"
  no enable
vpn policy site-to-site "DISABLED-LEGACY"
  no enable
  proposal ike encryption triple-des
""",
    )
    assert _issues(parser) == []


def test_secure_sonicos_has_no_findings(tmp_path):
    assert _issues(_parse(tmp_path, SECURE)) == []


def test_public_processor_has_stable_unique_finding_identities(tmp_path):
    findings = list(process_sonicos_conf(_parse(tmp_path, VULNERABLE)).values())
    identities = [(finding.rule_id, finding.evidence) for finding in findings]
    assert len(identities) == len(set(identities))


def test_unauthenticated_ntp_and_removed_server_are_distinguished(tmp_path):
    parser = _parse(
        tmp_path,
        SECURE.replace(
            "ntp-server 192.0.2.30 md5 trust-key-no 1 key-number 1 password redacted",
            "ntp-server 192.0.2.30\nno ntp-server 192.0.2.30\nntp-server 192.0.2.31",
        ),
    )
    records = parser.get_ntp_server_records()
    assert [(item.address, item.authenticated) for item in records] == [("192.0.2.31", False)]
    assert "sonicwall.sonicos.ntp.authentication" in {issue.rule_id for issue in _issues(parser)}
