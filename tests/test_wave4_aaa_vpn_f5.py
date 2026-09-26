"""Wave 4 (SC-031, SC-034, SC-039, SC-041): AAA transport, IKE aggressive mode,
FortiGate SSL-VPN and F5 self-IP port lockdown."""

import contextlib
import io

import pytest

from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.analyze.f5.core.process_bigip_conf import process_bigip_conf
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices import get_parser


def _run(tmp_path, device, text, processor):
    path = tmp_path / "device.conf"
    path.write_text(text, encoding="utf-8")
    parser = get_parser(device, str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        return list(processor(parser).values())


def _rules(findings, rule):
    return [finding for finding in findings if finding.rule_id == rule]


IOS = "version 15.2\nhostname r1\naaa new-model\n"
ASA = "ASA Version 9.16(4)\nhostname asa1\n"
FORTI = "#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
F5 = "#TMSH-VERSION: 16.1.5\nsys global-settings {\n    hostname bigip1\n}\n"


# --- SC-031 IOS TACACS+ keys -------------------------------------------------------------

@pytest.mark.parametrize("body,count", [
    ("aaa authentication login default group tacacs+ local\ntacacs server T1\n address ipv4 192.0.2.6\n", 1),
    ("aaa authentication login default group tacacs+ local\ntacacs server T1\n address ipv4 192.0.2.6\n key 6 ABC\n", 0),
    ("aaa authentication login default group tacacs+ local\ntacacs-server host 192.0.2.7\ntacacs-server key 7 0822455D0A16\n", 0),
    ("tacacs server T1\n address ipv4 192.0.2.6\n", 0),  # not used by any method list
    ("aaa group server tacacs+ TG\n server name T1\naaa authentication login default group TG local\n"
     "tacacs server T1\n address ipv4 192.0.2.6\ntacacs server T2\n address ipv4 192.0.2.8\n", 1),
])
def test_ios_tacacs_key_missing(tmp_path, body, count):
    findings = _rules(_run(tmp_path, "IOS_ROUTER", IOS + body + "end\n", process_cisco_ios_conf),
                      "cisco.ios.aaa.tacacs_key_missing")
    assert len(findings) == count
    assert all(guidance_for(f.rule_id) for f in findings)


# --- SC-031 ASA TACACS+ and LDAP ---------------------------------------------------------

ASA_AAA = ASA + """aaa-server TAC protocol tacacs+
aaa-server TAC (inside) host 192.0.2.10
aaa-server AD protocol ldap
aaa-server AD (inside) host 192.0.2.20
 ldap-base-dn dc=example,dc=com
aaa authentication ssh console TAC LOCAL
tunnel-group RA type remote-access
tunnel-group RA general-attributes
 authentication-server-group AD
"""


def test_asa_bound_tacacs_and_ldap(tmp_path):
    findings = _run(tmp_path, "ASA", ASA_AAA, process_asa_conf)
    assert len(_rules(findings, "cisco.asa.aaa.tacacs_key_missing")) == 1
    assert len(_rules(findings, "cisco.asa.aaa.ldap_cleartext")) == 1


def test_asa_protected_or_unbound_servers(tmp_path):
    text = ASA_AAA.replace("host 192.0.2.10\n", "host 192.0.2.10\n key *****\n").replace(
        " ldap-base-dn dc=example,dc=com\n", " ldap-base-dn dc=example,dc=com\n ldap-over-ssl enable\n")
    findings = _run(tmp_path, "ASA", text, process_asa_conf)
    assert not _rules(findings, "cisco.asa.aaa.tacacs_key_missing")
    assert not _rules(findings, "cisco.asa.aaa.ldap_cleartext")
    unbound = ASA + "aaa-server TAC protocol tacacs+\naaa-server TAC (inside) host 192.0.2.10\n"
    assert not _rules(_run(tmp_path, "ASA", unbound, process_asa_conf), "cisco.asa.aaa.tacacs_key_missing")


# --- SC-031 FortiOS LDAP -----------------------------------------------------------------

def _forti_ldap(settings, member=True):
    group = 'config user group\n    edit "g"\n        set member "corp"\n    next\nend\n' if member else ""
    return (FORTI + 'config user ldap\n    edit "corp"\n        set server "10.0.0.5"\n'
            + settings + "    next\nend\n" + group)


@pytest.mark.parametrize("settings,rule,basis", [
    ("", "fortinet.fortios.aaa.ldap_cleartext", FindingBasis.DOCUMENTED_DEFAULT),
    ("        set secure disable\n", "fortinet.fortios.aaa.ldap_cleartext", FindingBasis.EXPLICIT_VALUE),
    ("        set secure ldaps\n        set server-identity-check disable\n",
     "fortinet.fortios.aaa.ldap_server_identity", FindingBasis.EXPLICIT_VALUE),
])
def test_fortios_ldap_transport(tmp_path, settings, rule, basis):
    findings = _rules(_run(tmp_path, "FORTIOS", _forti_ldap(settings), process_fortios_conf), rule)
    assert len(findings) == 1 and findings[0].basis is basis


def test_fortios_ldap_secure_or_unused(tmp_path):
    for text in (_forti_ldap("        set secure ldaps\n"), _forti_ldap("", member=False)):
        findings = _run(tmp_path, "FORTIOS", text, process_fortios_conf)
        assert not [f for f in findings if f.rule_id.startswith("fortinet.fortios.aaa.ldap")]


# --- SC-034 IKEv1 aggressive mode --------------------------------------------------------

@pytest.mark.parametrize("extra,expected", [
    ("", True),
    ("crypto isakmp aggressive-mode disable\n", False),
])
def test_ios_aggressive_mode(tmp_path, extra, expected):
    text = IOS + "crypto isakmp key Secret1 address 198.51.100.1\n" + extra + "end\n"
    findings = _rules(_run(tmp_path, "IOS_ROUTER", text, process_cisco_ios_conf), "cisco.ios.vpn.ike_aggressive_mode")
    assert bool(findings) is expected
    if findings:
        assert findings[0].basis is FindingBasis.DOCUMENTED_DEFAULT
        assert "Secret1" not in " ".join(findings[0].evidence)


def test_ios_aggressive_mode_needs_pre_shared_keys(tmp_path):
    assert not _rules(_run(tmp_path, "IOS_ROUTER", IOS + "end\n", process_cisco_ios_conf),
                      "cisco.ios.vpn.ike_aggressive_mode")


ASA_L2L = ASA + ("crypto ikev1 enable outside\ntunnel-group 198.51.100.1 type ipsec-l2l\n"
                 "tunnel-group 198.51.100.1 ipsec-attributes\n ikev1 pre-shared-key *****\n")


@pytest.mark.parametrize("text,expected", [
    (ASA_L2L, True),
    (ASA_L2L + "crypto ikev1 am-disable\n", False),
    (ASA_L2L + "crypto isakmp am-disable\n", False),
    (ASA_L2L.replace("crypto ikev1 enable outside\n", ""), False),
])
def test_asa_aggressive_mode(tmp_path, text, expected):
    findings = _rules(_run(tmp_path, "ASA", text, process_asa_conf), "cisco.asa.vpn.ike_aggressive_mode")
    assert bool(findings) is expected


@pytest.mark.parametrize("settings,expected", [
    ("        set mode aggressive\n", True),
    ("        set mode aggressive\n        set ike-version 2\n", False),
    ("        set mode aggressive\n        set authmethod signature\n", False),
    ("", False),
])
def test_fortios_aggressive_mode(tmp_path, settings, expected):
    text = (FORTI + 'config vpn ipsec phase1-interface\n    edit "b"\n        set interface "wan1"\n'
            + settings + "        set remote-gw 198.51.100.1\n    next\nend\n")
    findings = _rules(_run(tmp_path, "FORTIOS", text, process_fortios_conf), "fortinet.fortios.vpn.ike_aggressive_mode")
    assert bool(findings) is expected


@pytest.mark.parametrize("body,expected", [
    ("    mode aggressive\n    phase1-auth-method pre-shared-key\n", True),
    ("    mode aggressive\n    phase1-auth-method rsa-signature\n", False),
    ("    mode main\n    phase1-auth-method pre-shared-key\n", False),
    ("    mode aggressive\n    phase1-auth-method pre-shared-key\n    version { v2 }\n", False),
])
def test_f5_aggressive_mode(tmp_path, body, expected):
    text = F5 + "net ipsec ike-peer /Common/branch {\n" + body + "    remote-address 198.51.100.1\n}\n"
    findings = _rules(_run(tmp_path, "F5_BIGIP", text, process_bigip_conf), "f5.bigip.vpn.ike_aggressive_mode")
    assert bool(findings) is expected


# --- SC-039 FortiGate SSL-VPN ------------------------------------------------------------

def _sslvpn(settings, interface=True):
    source = '    set source-interface "wan1"\n' if interface else ""
    return FORTI + "config vpn ssl settings\n" + settings + source + "end\n"


@pytest.mark.parametrize("setting,rule", [
    ("    set ssl-min-proto-ver tls1-1\n", "fortinet.fortios.sslvpn.legacy_tls"),
    ("    set algorithm low\n", "fortinet.fortios.sslvpn.weak_algorithm"),
    ('    set servercert "Fortinet_Factory"\n', "fortinet.fortios.sslvpn.factory_certificate"),
    ("    set login-attempt-limit 0\n", "fortinet.fortios.sslvpn.unlimited_login_attempts"),
])
def test_sslvpn_weak_settings(tmp_path, setting, rule):
    findings = _rules(_run(tmp_path, "FORTIOS", _sslvpn(setting), process_fortios_conf), rule)
    assert len(findings) == 1 and guidance_for(rule) is not None
    inactive = _run(tmp_path, "FORTIOS", _sslvpn(setting, interface=False), process_fortios_conf)
    assert not _rules(inactive, rule)


def test_sslvpn_secure_settings(tmp_path):
    text = _sslvpn('    set servercert "vpn.example.com"\n    set ssl-min-proto-ver tls1-2\n'
                   "    set algorithm high\n    set login-attempt-limit 3\n")
    findings = _run(tmp_path, "FORTIOS", text, process_fortios_conf)
    assert not [f for f in findings if f.rule_id.startswith("fortinet.fortios.sslvpn")]


# --- SC-041 F5 self-IP port lockdown -----------------------------------------------------

@pytest.mark.parametrize("allow,expected", [
    ("    allow-service all\n", True),
    ("    allow-service {\n        default\n    }\n", True),
    ("    allow-service {\n        tcp:ssh\n    }\n", True),
    ("    allow-service {\n        udp:1026\n        tcp:4353\n    }\n", False),
    ("    allow-service none\n", False),
    ("", False),  # tmsh default is none
])
def test_f5_self_ip_port_lockdown(tmp_path, allow, expected):
    text = F5 + "net self ext {\n    address 192.0.2.1/24\n" + allow + "    vlan external\n}\n"
    findings = _rules(_run(tmp_path, "F5_BIGIP", text, process_bigip_conf),
                      "f5.bigip.management.self_ip_port_lockdown")
    assert bool(findings) is expected
    if findings:
        assert guidance_for(findings[0].rule_id) is not None
