"""Explicit insecure settings from Cisco's IOS XE security-warnings reference."""

import contextlib
import io

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis, Severity
from src.devices import get_parser


def _run(tmp_path, body, device="IOS_XE", version="17.9"):
    path = tmp_path / "xe.conf"
    path.write_text(f"version {version}\nhostname xe1\n!\n{body}end\n", encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        return list(process_cisco_ios_conf(get_parser(device, str(path))).values())


def _rules(findings, rule):
    return [finding for finding in findings if finding.rule_id == rule]


TLS_PROFILE = "logging tls-profile SYSLOG\n tls-version TLSv1.1\n ciphersuite aes-128-cbc-sha\n!\n"


def test_bound_weak_logging_tls_profile(tmp_path):
    body = TLS_PROFILE + "logging host 192.0.2.10 transport tls profile SYSLOG\n"
    findings = _rules(_run(tmp_path, body), "cisco.ios.logging.remote_weak_tls")
    assert len(findings) == 1
    assert "tlsv1.1" in findings[0].observation and "aes-128-cbc-sha" in findings[0].observation
    assert findings[0].basis is FindingBasis.EXPLICIT_VALUE
    assert guidance_for("cisco.ios.logging.remote_weak_tls")


@pytest.mark.parametrize("body", [
    TLS_PROFILE,
    "logging tls-profile SYSLOG\n tls-version TLSv1.2\n!\nlogging host 192.0.2.10 transport tls profile SYSLOG\n",
])
def test_unbound_or_strong_profile_not_reported(tmp_path, body):
    assert not _rules(_run(tmp_path, body), "cisco.ios.logging.remote_weak_tls")


NTP = "ntp authentication-key 1 md5 0 Secr3tKey\nntp authenticate\nntp trusted-key 1\nntp server 192.0.2.1 key 1\n"


def test_ntp_md5_on_iosxe(tmp_path):
    findings = _rules(_run(tmp_path, NTP), "cisco.ios.ntp.weak_algorithm")
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "Secr3tKey" not in repr(findings[0])
    assert guidance_for("cisco.ios.ntp.weak_algorithm")


def test_ntp_md5_not_graded_on_classic_ios(tmp_path):
    assert not _rules(_run(tmp_path, NTP, device="IOS_ROUTER", version="15.4"), "cisco.ios.ntp.weak_algorithm")


@pytest.mark.parametrize("line,rule,severity", [
    ("router odr\n", "cisco.ios.routing.odr_enabled", Severity.MEDIUM),
    ("secure-webauth-disable\n", "cisco.ios.webauth.insecure_http", Severity.HIGH),
    ("ip ssh pubkey-chain\n username admin\n  key-hash ssh-rsa A3453F0A611C53FEBBE3B3F58B7801EA\n!\n",
     "cisco.ios.ssh.weak_pubkey_hash", Severity.LOW),
])
def test_explicit_insecure_features(tmp_path, line, rule, severity):
    findings = _rules(_run(tmp_path, line), rule)
    assert len(findings) == 1
    assert findings[0].severity is severity
    assert guidance_for(rule)


def test_disabled_or_sha2_not_reported(tmp_path):
    body = ("router odr\nno router odr\nip ssh pubkey-chain\n username admin\n"
            "  key-hash ssh-rsa " + "AB" * 32 + "\n!\n")
    findings = _run(tmp_path, body)
    assert not _rules(findings, "cisco.ios.routing.odr_enabled")
    assert not _rules(findings, "cisco.ios.ssh.weak_pubkey_hash")


AAA_RULE = "cisco.ios.aaa.servers_without_tls"


def test_aaa_servers_without_tls_single_informational(tmp_path):
    body = ("radius server R1\n address ipv4 192.0.2.1 auth-port 1812 acct-port 1813\n key 7 0822455D0A16\n!\n"
            "radius server R2\n address ipv4 192.0.2.2\n dtls port 2083\n!\n"
            "tacacs server T1\n address ipv4 192.0.2.3\n key 7 0822455D0A16\n!\n"
            "tacacs-server host 192.0.2.4\n")
    findings = _rules(_run(tmp_path, body), AAA_RULE)
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFORMATIONAL
    assert "1 RADIUS" in findings[0].observation and "2 TACACS+" in findings[0].observation
    assert "0822455D0A16" not in repr(findings[0])
    assert guidance_for(AAA_RULE)


def test_aaa_servers_not_graded_on_classic_ios(tmp_path):
    body = "tacacs server T1\n address ipv4 192.0.2.3\n!\n"
    assert not _rules(_run(tmp_path, body, device="IOS_ROUTER", version="15.4"), AAA_RULE)
