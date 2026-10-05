"""SC-005 Junos IS-IS authentication (Juniper "Configuring IS-IS Authentication")."""

import contextlib
import io

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis, Severity
from src.analyze.juniper.junos.core.process_junos_conf import process_junos_conf
from src.devices.juniper.junos import JunOSParser

BASE = "set version 22.4R1\nset system host-name r1\nset protocols isis interface ge-0/0/0.0\nset protocols isis interface lo0.0\n"


def _rules(tmp_path, extra, rule):
    path = tmp_path / "junos.conf"
    path.write_text(BASE + extra, encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_junos_conf(JunOSParser(str(path))).values()
    return [finding for finding in findings if finding.rule_id == rule]


def test_unauthenticated_isis_documented_default(tmp_path):
    findings = _rules(tmp_path, "", "juniper.junos.routing.isis.authentication")
    assert len(findings) == 1
    assert findings[0].basis is FindingBasis.DOCUMENTED_DEFAULT
    assert "ge-0/0/0.0" in findings[0].observation and "lo0.0" not in findings[0].observation
    assert guidance_for("juniper.junos.routing.isis.authentication")


def test_simple_authentication_is_cleartext(tmp_path):
    extra = ("set protocols isis level 2 authentication-key \"$9$abc\"\n"
             "set protocols isis level 2 authentication-type simple\n")
    findings = _rules(tmp_path, extra, "juniper.junos.routing.isis.cleartext_authentication")
    assert len(findings) == 1 and findings[0].severity is Severity.MEDIUM
    assert not _rules(tmp_path, extra, "juniper.junos.routing.isis.authentication")
    assert guidance_for("juniper.junos.routing.isis.cleartext_authentication")


def test_no_authentication_check(tmp_path):
    extra = ("set protocols isis level 2 authentication-key \"$9$abc\"\n"
             "set protocols isis level 2 authentication-type md5\nset protocols isis no-authentication-check\n")
    findings = _rules(tmp_path, extra, "juniper.junos.routing.isis.send_only")
    assert len(findings) == 1 and findings[0].severity is Severity.HIGH
    assert guidance_for("juniper.junos.routing.isis.send_only")


@pytest.mark.parametrize("extra", [
    "set protocols isis level 2 authentication-key \"$9$abc\"\nset protocols isis level 2 authentication-type md5\n",
    "set protocols isis interface ge-0/0/0.0 passive\n",
])
def test_not_reported(tmp_path, extra):
    for rule in ("authentication", "cleartext_authentication", "send_only"):
        assert not _rules(tmp_path, extra, f"juniper.junos.routing.isis.{rule}")
