"""SC-044: release-dependent insecure defaults for Cisco IOS / IOS-XE.

Row IDs refer to docs/agent_notes/INSECURE_DEFAULTS_BY_RELEASE.md."""

import contextlib
import io

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.devices import get_parser


def _run(tmp_path, text, device="IOS_ROUTER"):
    path = tmp_path / "device.conf"
    path.write_text(text, encoding="utf-8")
    parser = get_parser(device, str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        return list(process_cisco_ios_conf(parser).values())


def _rules(findings, rule):
    return [finding for finding in findings if finding.rule_id == rule]


def _conf(version, body=""):
    return f"version {version}\nhostname r1\n{body}end\n"


ROUTED = "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n"


@pytest.mark.parametrize("version,expected", [("16.3", True), ("16.6", False), ("17.9", False)])
def test_iosxe_small_servers_default(tmp_path, version, expected):  # IOS-01
    findings = _rules(_run(tmp_path, _conf(version), "IOS_XE"), "cisco.ios.services.legacy_default")
    assert bool(findings) is expected
    if findings:
        assert "16.6.4" in findings[0].observation


@pytest.mark.parametrize("version,body,expected", [
    ("15.2", "", {"pad", "bootp server", "mop"}),
    ("15.2", "no service pad\nno ip bootp server\n", {"mop"}),
    ("15.2", "ip dhcp bootp ignore\nno service pad\n", {"mop"}),
    ("17.9", "", {"pad", "bootp server"}),  # MOP default is platform dependent on IOS-XE
])
def test_default_enabled_services(tmp_path, version, body, expected):  # IOS-05/10/11
    findings = _rules(_run(tmp_path, _conf(version, body + ROUTED)), "cisco.ios.services.default_enabled")
    found = set()
    for finding in findings:
        assert finding.basis is FindingBasis.DOCUMENTED_DEFAULT
        found.update(item.split(":")[0] for item in finding.evidence)
    assert found == expected
    assert all(guidance_for(finding.rule_id) for finding in findings)


def test_mop_not_reported_when_disabled_or_shut(tmp_path):
    body = ("no service pad\nno ip bootp server\n" + ROUTED + " no mop enabled\n"
            "interface FastEthernet0/1\n ip address 192.0.2.5 255.255.255.252\n shutdown\n"
            "interface Serial0/0\n ip address 192.0.2.9 255.255.255.252\n")
    assert not _rules(_run(tmp_path, _conf("15.2", body)), "cisco.ios.services.default_enabled")


@pytest.mark.parametrize("body,expected", [
    ("", True), ("no ip domain lookup\n", False), ("no ip domain-lookup\n", False),
    ("no ip domain lookup\nip domain lookup\n", True),
])
def test_dns_lookup(tmp_path, body, expected):  # IOS-12
    assert bool(_rules(_run(tmp_path, _conf("15.2", body)), "cisco.ios.services.dns_lookup")) is expected


def test_tcp_keepalives(tmp_path):  # IOS-29
    assert _rules(_run(tmp_path, _conf("15.2")), "cisco.ios.services.tcp_keepalives")
    assert not _rules(_run(tmp_path, _conf("15.2", "service tcp-keepalives-in\n")), "cisco.ios.services.tcp_keepalives")


@pytest.mark.parametrize("version,body,basis", [
    ("15.2", "", FindingBasis.DOCUMENTED_DEFAULT),
    ("15.5", "", FindingBasis.MISSING_EXPLICIT_SETTING),
    ("17.9", "", FindingBasis.MISSING_EXPLICIT_SETTING),
])
def test_vty_transport_default(tmp_path, version, body, basis):  # IOS-03
    findings = _rules(_run(tmp_path, _conf(version, "line vty 0 4\n login local\n" + body)), "cisco.ios.vty.telnet")
    assert len(findings) == 1 and findings[0].basis is basis


def test_directed_broadcast_before_12_0(tmp_path):  # IOS-07
    old = _rules(_run(tmp_path, _conf("11.3", ROUTED)), "cisco.ios.interface.ip_hardening")
    assert "no ip directed-broadcast" in old[0].evidence
    new = _rules(_run(tmp_path, _conf("12.4", ROUTED)), "cisco.ios.interface.ip_hardening")
    assert "no ip directed-broadcast" not in new[0].evidence
    assert new[0].basis is FindingBasis.DOCUMENTED_DEFAULT


def test_global_proxy_arp_disable(tmp_path):  # IOS-08
    body = "ip arp proxy disable\n" + ROUTED + " no ip redirects\n"
    assert not _rules(_run(tmp_path, _conf("15.2", body)), "cisco.ios.interface.ip_hardening")


@pytest.mark.parametrize("body,expected", [
    ("line con 0\n password Console1\n login\n", True),
    ("enable secret 9 $9$abc\nline con 0\n password Console1\n login\n", False),
    ("aaa new-model\nline con 0\n password Console1\n", False),
    ("", False),
])
def test_enable_missing(tmp_path, body, expected):  # IOS-21
    findings = _rules(_run(tmp_path, _conf("15.2", body)), "cisco.ios.credentials.enable_missing")
    assert bool(findings) is expected
    if findings:
        assert "Console1" not in " ".join(str(item) for item in findings[0].evidence)


IKE = "crypto isakmp key Secret1 address 198.51.100.1\n"


@pytest.mark.parametrize("version,body,expected", [
    ("15.2", IKE, True),
    ("15.2", IKE + "no crypto isakmp default policy\n", False),
    ("15.2", IKE + "crypto isakmp policy 10\n encryption aes 256\n hash sha256\n group 19\n", False),
    ("12.4", IKE, False),  # default policies only from 12.4(20)T
    ("15.2", "", False),
])
def test_isakmp_default_policies(tmp_path, version, body, expected):  # IOS-22
    findings = [f for f in _rules(_run(tmp_path, _conf(version, body)), "cisco.ios.crypto.legacy_ike")
                if "built-in" in f.title]
    assert bool(findings) is expected
    if findings:
        assert "Secret1" not in " ".join(findings[0].evidence)


@pytest.mark.parametrize("policy,expected", [
    ("crypto isakmp policy 10\n hash sha256\n", True),
    ("crypto isakmp policy 10\n encryption aes 256\n hash sha256\n group 19\n", False),
])
def test_isakmp_policy_parameter_defaults(tmp_path, policy, expected):  # IOS-23
    findings = [f for f in _rules(_run(tmp_path, _conf("15.2", policy)), "cisco.ios.crypto.legacy_ike")
                if f.basis is FindingBasis.DOCUMENTED_DEFAULT]
    assert bool(findings) is expected


@pytest.mark.parametrize("body,expected", [
    ("crypto ikev2 profile P\n match identity remote address 198.51.100.1\n", True),
    ("crypto ikev2 proposal PR\n encryption aes-gcm-256\n prf sha384\n group 19\n"
     "crypto ikev2 profile P\n match identity remote address 198.51.100.1\n", False),
    ("no crypto ikev2 proposal default\ncrypto ikev2 profile P\n", False),
])
def test_ikev2_default_proposal(tmp_path, body, expected):  # IOS-25
    findings = _rules(_run(tmp_path, _conf("17.9", body), "IOS_XE"), "cisco.ios.crypto.ikev2_default_proposal")
    assert bool(findings) is expected


@pytest.mark.parametrize("device,body,expected", [
    ("IOS_SWITCH", "", FindingBasis.DOCUMENTED_DEFAULT),
    ("IOS_SWITCH", "vtp mode client\n", FindingBasis.EXPLICIT_VALUE),
    ("IOS_SWITCH", "vtp mode transparent\n", None),
    ("IOS_SWITCH", "vtp mode off\n", None),
    ("IOS_ROUTER", "", None),
])
def test_vtp_mode(tmp_path, device, body, expected):  # IOS-27
    findings = _rules(_run(tmp_path, _conf("15.2", body), device), "cisco.ios.vtp.mode")
    assert (findings[0].basis if findings else None) is expected


def test_system_mode_insecure(tmp_path):  # IOS-30
    findings = _rules(_run(tmp_path, _conf("26.1", "system mode insecure\n"), "IOS_XE"), "cisco.ios.system.insecure_mode")
    assert len(findings) == 1 and guidance_for(findings[0].rule_id)
