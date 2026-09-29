"""SC-044: release-dependent insecure defaults for FortiOS 6.4.14+.

Row IDs refer to docs/agent_notes/INSECURE_DEFAULTS_BY_RELEASE.md."""

import contextlib
import io

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices import get_parser


def _run(tmp_path, text):
    path = tmp_path / "device.conf"
    path.write_text(text, encoding="utf-8")
    parser = get_parser("FORTIOS", str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        return list(process_fortios_conf(parser).values())


def _rules(findings, rule):
    return [finding for finding in findings if finding.rule_id == rule]


def _conf(version, global_settings="", body="", access="https ssh"):
    return (f"#config-version=FGT60F-{version}-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
            f"config system global\n    set hostname fw\n{global_settings}end\n"
            f'config system interface\n    edit "port1"\n        set allowaccess {access}\n    next\nend\n' + body)


@pytest.mark.parametrize("version,settings,expected", [
    ("6.4.14", "", True),
    ("6.4.14", "    set admin-https-ssl-versions tlsv1-2 tlsv1-3\n", False),
    ("7.0.1", "", False),
    ("6.4.13", "", False),  # no verified default cell
])
def test_admin_https_versions(tmp_path, version, settings, expected):  # FOS-01
    findings = [f for f in _rules(_run(tmp_path, _conf(version, settings)), "fortinet.fortios.tls.minimum_version")
                if f.basis is FindingBasis.DOCUMENTED_DEFAULT]
    assert bool(findings) is expected


def test_static_key_ciphers_default(tmp_path):  # FOS-02
    found = _rules(_run(tmp_path, _conf("7.4.4")), "fortinet.fortios.crypto.ssl_static_key_ciphers")
    assert found and found[0].basis is FindingBasis.DOCUMENTED_DEFAULT
    quiet = _run(tmp_path, _conf("7.4.4", "    set ssl-static-key-ciphers disable\n"))
    assert not _rules(quiet, "fortinet.fortios.crypto.ssl_static_key_ciphers")
    no_https = _run(tmp_path, _conf("7.4.4", access="ping"))
    assert not _rules(no_https, "fortinet.fortios.crypto.ssl_static_key_ciphers")


@pytest.mark.parametrize("version,expected", [("7.0.1", 3), ("6.4.15", 3), ("7.0.2", 0)])
def test_ssh_legacy_switches(tmp_path, version, expected):  # FOS-03/04/05
    findings = [f for f in _run(tmp_path, _conf(version))
                if f.rule_id in {"fortinet.fortios.crypto.ssh_cbc_cipher", "fortinet.fortios.crypto.ssh_hmac_md5",
                                 "fortinet.fortios.crypto.ssh_kex_sha1"}]
    assert len(findings) == expected
    assert all(guidance_for(f.rule_id) for f in findings)


def test_ssh_explicit_weak_switch(tmp_path):
    findings = _run(tmp_path, _conf("7.0.1", "    set ssh-hmac-md5 enable\n    set ssh-cbc-cipher disable\n    set ssh-kex-sha1 disable\n"))
    md5 = _rules(findings, "fortinet.fortios.crypto.ssh_hmac_md5")
    assert len(md5) == 1 and md5[0].basis is not FindingBasis.DOCUMENTED_DEFAULT
    assert not _rules(findings, "fortinet.fortios.crypto.ssh_cbc_cipher")


@pytest.mark.parametrize("version,settings,basis", [
    ("7.2.5", "", FindingBasis.DOCUMENTED_DEFAULT),
    ("7.2.5", "    set admin-maintainer enable\n", FindingBasis.EXPLICIT_VALUE),
    ("7.2.5", "    set admin-maintainer disable\n", None),
    ("7.4.4", "", None),
])
def test_admin_maintainer(tmp_path, version, settings, basis):  # FOS-07
    findings = _rules(_run(tmp_path, _conf(version, settings)), "fortinet.fortios.admin.maintainer_account")
    assert (findings[0].basis if findings else None) is basis


SSLVPN = 'config vpn ssl settings\n    set source-interface "port1"\n{extra}end\n'


@pytest.mark.parametrize("version,extra,expected", [
    ("7.0.12", "", True), ("6.4.14", "", True), ("7.2.5", "", False),
    ("7.0.12", '    set servercert "vpn.example.com"\n', False),
])
def test_sslvpn_servercert_default(tmp_path, version, extra, expected):  # FOS-09
    findings = [f for f in _rules(_run(tmp_path, _conf(version, body=SSLVPN.format(extra=extra))),
                                  "fortinet.fortios.sslvpn.factory_certificate")
                if f.basis is FindingBasis.DOCUMENTED_DEFAULT]
    assert bool(findings) is expected


SYSLOG = "config log syslogd setting\n    set status enable\n    set server 192.0.2.20\n{extra}end\n"


@pytest.mark.parametrize("extra,expected", [
    ("", True), ("    set mode reliable\n", True),
    ("    set mode reliable\n    set enc-algorithm high\n", False),
])
def test_syslog_default_cleartext(tmp_path, extra, expected):  # FOS-11
    findings = [f for f in _rules(_run(tmp_path, _conf("7.4.4", body=SYSLOG.format(extra=extra))),
                                  "fortinet.fortios.logging.remote_cleartext")
                if f.basis is FindingBasis.DOCUMENTED_DEFAULT]
    assert bool(findings) is expected


def test_password_policy_default_from_6414(tmp_path):  # FOS-12
    assert _rules(_run(tmp_path, _conf("6.4.14")), "fortinet.fortios.password_policy.disabled")
    assert not _rules(_run(tmp_path, _conf("6.4.13")), "fortinet.fortios.password_policy.disabled")


RADIUS = ('config user radius\n    edit "rad"\n        set server "192.0.2.40"\n        set secret ENC xyz\n    next\nend\n'
          'config user group\n    edit "admins"\n        set member "rad"\n    next\nend\n'
          'config system admin\n    edit "radadmin"\n        set remote-auth enable\n        set accprofile "super_admin"\n'
          '        set wildcard enable\n        set remote-group "admins"\n    next\nend\n')


@pytest.mark.parametrize("version,expected", [("7.2.10", True), ("7.4.5", True), ("7.6.0", True),
                                              ("7.2.11", False), ("7.4.6", False), ("7.6.1", False)])
def test_blastradius_releases(tmp_path, version, expected):  # FOS-13
    findings = [f for f in _rules(_run(tmp_path, _conf(version, body=RADIUS)),
                                  "fortinet.fortios.aaa.radius_message_authenticator")
                if f.basis is FindingBasis.DOCUMENTED_DEFAULT]
    assert bool(findings) is expected
    assert all("xyz" not in " ".join(map(str, f.evidence)) for f in findings)
