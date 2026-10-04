"""SC-031 IOS LDAP servers used for AAA without 'mode secure'."""

import contextlib
import io

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis, Severity
from src.devices import get_parser

RULE = "cisco.ios.aaa.ldap_cleartext"
SERVER = ("ldap server DC1\n ipv4 192.0.2.30\n bind authenticate root-dn cn=svc,dc=example,dc=test password 0 BindPw1\n"
          " base-dn dc=example,dc=test\n{extra}!\n")


def _run(tmp_path, extra="", method="aaa authentication login default group LDAPG local\n", group=True):
    body = "aaa new-model\n" + SERVER.format(extra=extra)
    if group:
        body += "aaa group server ldap LDAPG\n server DC1\n!\n"
    body += method
    path = tmp_path / "r.conf"
    path.write_text("version 17.9\nhostname r\n!\n" + body + "end\n", encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_cisco_ios_conf(get_parser("IOS_XE", str(path))).values()
    return [finding for finding in findings if finding.rule_id == RULE]


def test_used_ldap_without_secure_mode(tmp_path):
    findings = _run(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].basis is FindingBasis.REQUIRED_SETTING_MISSING
    assert "LDAPG" in findings[0].observation
    assert "BindPw1" not in repr(findings[0])
    assert guidance_for(RULE)


def test_global_ldap_group_method(tmp_path):
    assert _run(tmp_path, method="aaa authentication login default group ldap local\n", group=False)


@pytest.mark.parametrize("extra,method", [
    (" mode secure\n", "aaa authentication login default group LDAPG local\n"),
    (" transport port 636\n", "aaa authentication login default group LDAPG local\n"),
    ("", "aaa authentication login default local\n"),
])
def test_not_reported(tmp_path, extra, method):
    assert not _run(tmp_path, extra=extra, method=method)
