"""SC-044: release-dependent insecure defaults for F5 BIG-IP.

Row IDs refer to docs/agent_notes/INSECURE_DEFAULTS_BY_RELEASE.md."""

import contextlib
import io

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.analyze.f5.core.process_bigip_conf import process_bigip_conf
from src.devices import get_parser


def _run(tmp_path, text):
    path = tmp_path / "bigip.scf"
    path.write_text(text, encoding="utf-8")
    parser = get_parser("F5_BIGIP", str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        return list(process_bigip_conf(parser).values())


def _defaults(findings, rule):
    return [f for f in findings if f.rule_id == rule and f.basis is FindingBasis.DOCUMENTED_DEFAULT]


def _conf(version, body=""):
    return f"#TMSH-VERSION: {version}\nsys global-settings {{\n    hostname bigip1\n}}\n{body}"


SELF = "net self ext {\n    address 192.0.2.1/24\n    vlan external\n}\n"


@pytest.mark.parametrize("version,expected", [("11.4.1", True), ("11.5.3", False), ("16.1.5", False)])
def test_self_ip_lockdown_default(tmp_path, version, expected):  # F5-01
    assert bool(_defaults(_run(tmp_path, _conf(version, SELF)), "f5.bigip.management.self_ip_port_lockdown")) is expected


HTTPD = "sys httpd {\n    redirect-http-to-https enabled\n}\n"


@pytest.mark.parametrize("version,severity", [("11.6.1", "High"), ("13.1.0", "Medium"), ("16.1.5", "Low")])
def test_httpd_protocol_default(tmp_path, version, severity):  # F5-02/03
    findings = _defaults(_run(tmp_path, _conf(version, HTTPD)), "f5.bigip.http.legacy_tls_protocol")
    assert len(findings) == 1 and findings[0].severity.value == severity


def test_httpd_defaults_need_the_object(tmp_path):
    findings = _run(tmp_path, _conf("16.1.5"))
    assert not [f for f in findings if f.rule_id.startswith("f5.bigip.http.")]


def test_httpd_other_defaults(tmp_path):  # F5-04/05
    findings = _run(tmp_path, _conf("16.1.5", HTTPD))
    assert _defaults(findings, "f5.bigip.http.weak_cipher_suite")
    assert _defaults(findings, "f5.bigip.http.unrestricted_sources")
    locked = _run(tmp_path, _conf("16.1.5", "sys httpd {\n    allow none\n}\n"))
    assert not [f for f in locked if f.rule_id.startswith("f5.bigip.http.")]


@pytest.mark.parametrize("body,expected", [
    ("sys sshd {\n    banner enabled\n}\n", {"f5.bigip.ssh.unrestricted_sources", "f5.bigip.ssh.idle_timeout_disabled"}),
    ("sys sshd {\n    allow { 192.0.2.0/255.255.255.0 }\n    inactivity-timeout 600\n}\n", set()),
    ("sys sshd {\n    login disabled\n}\n", set()),
])
def test_sshd_defaults(tmp_path, body, expected):  # F5-06/07
    findings = _run(tmp_path, _conf("16.1.5", body))
    found = {f.rule_id for f in findings if f.rule_id.startswith("f5.bigip.ssh.") and f.basis is FindingBasis.DOCUMENTED_DEFAULT}
    assert found == expected


def test_console_default(tmp_path):  # F5-08
    assert _defaults(_run(tmp_path, _conf("16.1.5")), "f5.bigip.console.idle_timeout_disabled")
    assert not _defaults(_run(tmp_path, _conf("12.1.0")), "f5.bigip.console.idle_timeout_disabled")


def _virtual(profile_body, profile="/Common/app_ssl"):
    return (f"ltm profile client-ssl /Common/app_ssl {{\n    defaults-from /Common/clientssl\n{profile_body}}}\n"
            f"ltm virtual /Common/vs {{\n    destination /Common/192.0.2.10:443\n"
            f"    profiles {{ {profile} {{ context clientside }} }}\n}}\n")


@pytest.mark.parametrize("version,body,expected", [
    ("11.4.1", "", "High"),
    ("12.1.3", "", "Medium"),
    ("13.1.0", "", None),
    ("12.1.3", "    ciphers ECDHE+AES-GCM\n", None),
])
def test_clientssl_default_ciphers(tmp_path, version, body, expected):  # F5-10/11/12
    findings = _defaults(_run(tmp_path, _conf(version, _virtual(body))), "f5.bigip.ltm.clientssl_weak_cipher")
    assert (findings[0].severity.value if findings else None) == expected


@pytest.mark.parametrize("body,profile,expected", [
    ("", "/Common/app_ssl", True),
    ("    options { no-tlsv1 no-tlsv1.1 }\n", "/Common/app_ssl", False),
    ("", "/Common/clientssl", True),  # built-in parent profile bound directly
    ("    ciphers ECDHE+AES-GCM\n", "/Common/app_ssl", False),
])
def test_clientssl_legacy_tls(tmp_path, body, profile, expected):  # F5-13
    findings = _defaults(_run(tmp_path, _conf("17.1.0", _virtual(body, profile))), "f5.bigip.ltm.clientssl_legacy_tls")
    assert bool(findings) is expected
    assert all(guidance_for(f.rule_id) for f in findings)


def test_clientssl_inherits_through_custom_parent(tmp_path):
    body = ("ltm profile client-ssl /Common/base_ssl {\n    ciphers ECDHE+AES-GCM\n    options { no-tlsv1 no-tlsv1.1 }\n}\n"
            "ltm profile client-ssl /Common/child_ssl {\n    defaults-from /Common/base_ssl\n}\n"
            "ltm virtual /Common/vs {\n    destination /Common/192.0.2.10:443\n"
            "    profiles { /Common/child_ssl { context clientside } }\n}\n")
    findings = _run(tmp_path, _conf("12.1.3", body))
    assert not [f for f in findings if f.rule_id.startswith("f5.bigip.ltm.clientssl_")]


@pytest.mark.parametrize("body,basis", [
    ("    mode main\n", FindingBasis.DOCUMENTED_DEFAULT),
    ("    mode main\n    version { v1 }\n", FindingBasis.EXPLICIT_VALUE),
    ("    mode main\n    version { v2 }\n", None),
])
def test_ike_version(tmp_path, body, basis):  # F5-22
    text = _conf("16.1.5", "net ipsec ike-peer /Common/p {\n" + body + "    remote-address 198.51.100.1\n}\n")
    findings = [f for f in _run(tmp_path, text) if f.rule_id == "f5.bigip.vpn.ikev1"]
    assert (findings[0].basis if findings else None) is basis


SNMP = ("sys snmp {{\n    allowed-addresses {{ 192.0.2.0/24 }}\n"
        "    communities {{ /Common/c1 {{ community-name monitor1 access ro }} }}\n{extra}}}\n")


@pytest.mark.parametrize("version,extra,basis", [
    ("16.1.5", "", FindingBasis.DOCUMENTED_DEFAULT),
    ("16.1.5", "    snmpv1 disable\n    snmpv2c disable\n", None),
    ("16.1.5", "    snmpv1 disable\n    snmpv2c enable\n", FindingBasis.EXPLICIT_VALUE),
    ("12.1.3", "", None),  # no documented default cell before v13
])
def test_snmp_v1_v2c_default(tmp_path, version, extra, basis):  # F5-19
    findings = [f for f in _run(tmp_path, _conf(version, SNMP.format(extra=extra)))
                if f.rule_id == "f5.bigip.snmp.legacy_version"]
    assert (findings[0].basis if findings else None) is basis
    assert all("monitor1" not in " ".join(map(str, f.evidence)) for f in findings)


def _cookie(profile_body, persist="/Common/app_cookie"):
    return (f"ltm persistence cookie /Common/app_cookie {{\n    defaults-from /Common/cookie\n{profile_body}}}\n"
            f"ltm virtual /Common/vs {{\n    destination /Common/192.0.2.10:80\n"
            f"    persist {{ {persist} {{ default yes }} }}\n}}\n")


@pytest.mark.parametrize("body,persist,basis", [
    ("", "/Common/app_cookie", FindingBasis.DOCUMENTED_DEFAULT),
    ("", "/Common/cookie", FindingBasis.DOCUMENTED_DEFAULT),  # built-in profile bound directly
    ("    cookie-encryption required\n", "/Common/app_cookie", None),
    ("    cookie-encryption disabled\n", "/Common/app_cookie", FindingBasis.EXPLICIT_VALUE),
    ("    method hash\n", "/Common/app_cookie", None),
])
def test_cookie_encryption_default(tmp_path, body, persist, basis):  # F5-15
    findings = [f for f in _run(tmp_path, _conf("16.1.5", _cookie(body, persist)))
                if f.rule_id == "f5.bigip.ltm.cookie_unencrypted"]
    assert len(findings) <= 1
    assert (findings[0].basis if findings else None) is basis


@pytest.mark.parametrize("version,body,expected", [
    ("13.1.0", "auth password-policy {\n    minimum-length 12\n}\n", True),
    ("13.1.0", "auth password-policy {\n    policy-enforcement enabled\n}\n", False),
    ("14.1.0", "auth password-policy {\n    minimum-length 12\n}\n", False),  # enabled by default from 14.0.0
    ("13.1.0", "", False),  # object not exported
])
def test_password_policy_default(tmp_path, version, body, expected):  # F5-21
    assert bool(_defaults(_run(tmp_path, _conf(version, body)), "f5.bigip.password_policy.enforcement_disabled")) is expected


SYS = "sys sshd {\n    allow { 192.0.2.0/255.255.255.0 }\n    inactivity-timeout 600\n}\nsys db ui.advisory.enabled {\n    value \"true\"\n}\n"


@pytest.mark.parametrize("version,body,basis", [
    ("16.1.5", SYS, FindingBasis.DOCUMENTED_DEFAULT),
    ("16.1.5", SYS + "sys db systemauth.disablerootlogin {\n    value \"true\"\n}\n", None),
    ("16.1.5", SYS + "sys db systemauth.disablerootlogin {\n    value \"false\"\n}\n", FindingBasis.EXPLICIT_VALUE),
    ("16.1.5", "sys sshd {\n    login enabled\n}\n", None),  # no sys db section exported
    ("11.5.4", SYS, None),
])
def test_root_login_default(tmp_path, version, body, basis):  # F5-17
    findings = [f for f in _run(tmp_path, _conf(version, body)) if f.rule_id == "f5.bigip.auth.root_login_enabled"]
    assert (findings[0].basis if findings else None) is basis


def _serverssl(profile_body, profile="/Common/app_serverssl"):
    return (f"ltm profile server-ssl /Common/app_serverssl {{\n    defaults-from /Common/serverssl\n{profile_body}}}\n"
            f"ltm virtual /Common/vs {{\n    destination /Common/192.0.2.10:443\n"
            f"    profiles {{ /Common/clientssl {{ context clientside }} {profile} {{ context serverside }} }}\n}}\n")


@pytest.mark.parametrize("body,profile,basis", [
    ("", "/Common/app_serverssl", FindingBasis.DOCUMENTED_DEFAULT),
    ("", "/Common/serverssl", FindingBasis.DOCUMENTED_DEFAULT),
    ("    peer-cert-mode require\n    ca-file /Common/ca-bundle.crt\n", "/Common/app_serverssl", None),
    ("    peer-cert-mode ignore\n", "/Common/app_serverssl", FindingBasis.EXPLICIT_VALUE),
])
def test_serverssl_peer_cert_mode(tmp_path, body, profile, basis):  # F5-14
    findings = [f for f in _run(tmp_path, _conf("16.1.5", _serverssl(body, profile)))
                if f.rule_id == "f5.bigip.ltm.serverssl_no_cert_validation"]
    assert (findings[0].basis if findings else None) is basis


ADMIN_HASH = "$6$Ab3dEf9h$ojcL1cvX0IaHRu0PeiGsPVFAORKVpsz2Ar8rttbtXPhQKDTKUt1houFPfFFycYDmQT82Bef7B35wxbQXYY.xn/"
OTHER_HASH = "$6$Ab3dEf9h$dbksKHA3ZfD6nrjagNQ6w.MyTIoJQ6R626DbfYhY5SQbYtbuQBPfMxkmt34hF13CElBXawQ/FtojN6V2pfUbm1"


@pytest.mark.parametrize("user,value,expected", [
    ("admin", ADMIN_HASH, True),
    ("admin", OTHER_HASH, False),
    ("operator", ADMIN_HASH, False),  # only the built-in accounts have documented defaults
    ("admin", "$1$Xy7wQpLm$HHWqZB39GsLnaQGlnZ0uV.", True),
])
def test_factory_admin_password(tmp_path, user, value, expected):  # F5-16
    text = _conf("15.1.8", f'auth user {user} {{\n    encrypted-password "{value}"\n    role admin\n}}\n')
    findings = [f for f in _run(tmp_path, text) if f.rule_id == "f5.bigip.credentials.known_default_value"]
    assert bool(findings) is expected
    assert all(value not in " ".join(map(str, f.evidence)) for f in findings)
