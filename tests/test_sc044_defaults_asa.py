"""SC-044: release-dependent insecure defaults for Cisco ASA and PIX 6.x.

Row IDs refer to docs/agent_notes/INSECURE_DEFAULTS_BY_RELEASE.md."""

import contextlib
import io

import pytest

from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.devices import get_parser


def _run(tmp_path, text, device="ASA"):
    path = tmp_path / "device.conf"
    path.write_text(text, encoding="utf-8")
    parser = get_parser(device, str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        return list(process_asa_conf(parser).values())


def _rules(findings, rule):
    return [finding for finding in findings if finding.rule_id == rule]


OUTSIDE = "interface GigabitEthernet0/0\n nameif outside\n security-level 0\n ip address 198.51.100.1 255.255.255.0\n"


def _asa(version, body=""):
    return f"ASA Version {version}\nhostname asa1\n{OUTSIDE}{body}"


def test_release_parsing(tmp_path):
    path = tmp_path / "a.conf"
    path.write_text(_asa("9.8(4)32"), encoding="utf-8")
    assert get_parser("ASA", str(path)).get_release() == ("ASA", (9, 8, 4))
    path.write_text("PIX Version 6.3(5)\nhostname pix\n", encoding="utf-8")
    assert get_parser("PIX", str(path)).get_release() == ("PIX", (6, 3, 5))


@pytest.mark.parametrize("version,body,expected", [
    ("9.2(4)", "http server enable\n", True),
    ("9.2(4)", "http server enable\nssl server-version tlsv1-only\n", False),
    ("9.3(2)", "http server enable\n", False),
    ("9.2(4)", "", False),  # no TLS service
])
def test_ssl_server_version_default(tmp_path, version, body, expected):  # ASA-02
    findings = [f for f in _rules(_run(tmp_path, _asa(version, body)), "cisco.asa.tls.minimum_version")
                if f.basis is FindingBasis.DOCUMENTED_DEFAULT]
    assert bool(findings) is expected


@pytest.mark.parametrize("body,expected", [
    ("http server enable\n", True),
    ("http server enable\nssl cipher tlsv1.2 high\n", False),
    ("http server enable\nssl cipher tlsv1.2 medium\n", False),  # explicit finding instead
    ("", False),
])
def test_ssl_cipher_default(tmp_path, body, expected):  # ASA-04
    findings = [f for f in _rules(_run(tmp_path, _asa("9.16(4)", body)), "cisco.asa.tls.weak_cipher")
                if f.basis is FindingBasis.DOCUMENTED_DEFAULT]
    assert bool(findings) is expected


@pytest.mark.parametrize("version,body,expected", [
    ("9.8(4)", "", {"key exchange", "encryption"}),
    ("9.12(1)", "", {"encryption"}),
    ("9.8(4)", "ssh key-exchange group dh-group14-sha1\nssh cipher encryption high\n", set()),
])
def test_ssh_default_algorithms(tmp_path, version, body, expected):  # ASA-06/08
    text = _asa(version, "ssh 192.0.2.0 255.255.255.0 outside\n" + body)
    found = set()
    for finding in _rules(_run(tmp_path, text), "cisco.asa.ssh.weak_algorithms"):
        if finding.basis is FindingBasis.DOCUMENTED_DEFAULT:
            found.update(item.split(":")[0] for item in finding.evidence[1:])
    assert found == expected


def test_ssh_version_default_basis(tmp_path):  # ASA-05
    findings = _rules(_run(tmp_path, _asa("9.8(4)", "ssh 192.0.2.0 255.255.255.0 outside\n")),
                      "cisco.asa.ssh.protocol_version")
    assert findings[0].basis is FindingBasis.DOCUMENTED_DEFAULT


VPN = "crypto ikev1 enable outside\ncrypto map VPN interface outside\n"


@pytest.mark.parametrize("body,basis", [
    (VPN, FindingBasis.DOCUMENTED_DEFAULT),
    (VPN + "sysopt connection permit-vpn\n", FindingBasis.EXPLICIT_VALUE),
    (VPN + "no sysopt connection permit-vpn\n", None),
    ("", None),
])
def test_sysopt_permit_vpn(tmp_path, body, basis):  # ASA-01
    findings = _rules(_run(tmp_path, _asa("9.16(4)", body)), "cisco.asa.vpn.sysopt_permit_vpn")
    assert (findings[0].basis if findings else None) is basis
    if findings:
        assert guidance_for(findings[0].rule_id)


@pytest.mark.parametrize("body,expected", [
    ("", True), ("icmp deny any outside\n", False), ("icmp permit any echo-reply outside\n", False),
])
def test_icmp_default(tmp_path, body, expected):  # ASA-19
    findings = _rules(_run(tmp_path, _asa("9.16(4)", body)), "cisco.asa.interface.icmp_unrestricted")
    assert bool(findings) is expected


@pytest.mark.parametrize("version,expected", [("9.8(4)", True), ("9.16(4)", False)])
def test_ikev1_policy_defaults(tmp_path, version, expected):  # ASA-14
    text = _asa(version, "crypto ikev1 policy 10\n authentication pre-share\n hash sha\n")
    findings = [f for f in _rules(_run(tmp_path, text), "cisco.asa.crypto.legacy_vpn")
                if f.basis is FindingBasis.DOCUMENTED_DEFAULT]
    assert bool(findings) is expected


PIX = "PIX Version 6.3(5)\nhostname pix\nnameif ethernet0 outside security0\n"


@pytest.mark.parametrize("body,basis", [
    ("isakmp enable outside\nisakmp policy 10 authentication pre-share\n", FindingBasis.DOCUMENTED_DEFAULT),
    ("isakmp enable outside\nisakmp policy 10 encryption 3des\nisakmp policy 10 group 2\n", FindingBasis.EXPLICIT_VALUE),
    ("isakmp enable outside\nisakmp policy 10 encryption aes-256\nisakmp policy 10 group 5\n", FindingBasis.EXPLICIT_VALUE),
    ("isakmp policy 10 authentication pre-share\n", None),
])
def test_pix_isakmp_policy(tmp_path, body, basis):  # PIX-01
    findings = _rules(_run(tmp_path, PIX + body, "PIX"), "cisco.asa.vpn.ike_weak_policy")
    assert (findings[0].basis if findings else None) is basis


def test_pix_ssh_and_sysopt(tmp_path):  # PIX-02/03
    findings = _run(tmp_path, PIX + "ssh 192.0.2.0 255.255.255.0 inside\nsysopt connection permit-ipsec\n", "PIX")
    assert _rules(findings, "cisco.asa.ssh.protocol_version")
    assert _rules(findings, "cisco.asa.vpn.sysopt_permit_vpn")[0].basis is FindingBasis.EXPLICIT_VALUE
    asa7 = _run(tmp_path, "PIX Version 7.2(4)\nhostname pix\nssh 192.0.2.0 255.255.255.0 inside\n", "PIX")
    assert not [f for f in _rules(asa7, "cisco.asa.ssh.protocol_version") if "PIX 6" in f.title]
