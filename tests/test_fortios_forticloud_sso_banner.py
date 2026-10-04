"""FortiCloud SSO administrator login (FG-IR-26-060 / FG-IR-25-647) and pre-login banner checks."""

import contextlib
import io

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis, Severity
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices import get_parser


def _run(tmp_path, version, global_settings="", body=""):
    path = tmp_path / "fgt.conf"
    path.write_text(
        f"#config-version=FGT60F-{version}-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
        f"config system global\n    set hostname fw\n{global_settings}end\n{body}", encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        return list(process_fortios_conf(get_parser("FORTIOS", str(path))).values())


def _rules(findings, rule):
    return [finding for finding in findings if finding.rule_id == rule]


SSO = "    set admin-forticloud-sso-login enable\n"


@pytest.mark.parametrize("version,severity", [
    ("7.4.8", Severity.CRITICAL), ("7.0.18", Severity.CRITICAL), ("7.6.5", Severity.CRITICAL),
    ("7.2.12", Severity.CRITICAL), ("7.4.11", None), ("7.6.6", None), ("7.0.19", None),
])
def test_forticloud_sso_release_gate(tmp_path, version, severity):
    findings = _rules(_run(tmp_path, version, SSO), "fortinet.fortios.admin.forticloud_sso_login")
    assert (findings[0].severity if findings else None) is severity
    if findings:
        assert findings[0].basis is FindingBasis.EXPLICIT_VALUE
        assert guidance_for(findings[0].rule_id)


def test_forticloud_sso_disabled_or_absent(tmp_path):
    for settings in ("", "    set admin-forticloud-sso-login disable\n"):
        assert not _rules(_run(tmp_path, "7.4.8", settings), "fortinet.fortios.admin.forticloud_sso_login")


def test_forticloud_sso_unknown_release(tmp_path):
    path = tmp_path / "fgt.conf"
    path.write_text("config system global\n    set hostname fw\n" + SSO + "end\n", encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        findings = _rules(list(process_fortios_conf(get_parser("FORTIOS", str(path))).values()),
                          "fortinet.fortios.admin.forticloud_sso_login")
    assert findings and findings[0].severity is Severity.HIGH


ADMINS = ('config system admin\n    edit "support"\n        set accprofile "super_admin"\n    next\n'
          '    edit "netops"\n        set accprofile "super_admin"\n    next\nend\n')


def test_ioc_account_names_only_on_affected_enabled_release(tmp_path):
    hits = _rules(_run(tmp_path, "7.4.8", SSO, ADMINS), "fortinet.fortios.admin.forticloud_sso_ioc_account")
    assert len(hits) == 1 and "support" in hits[0].observation and "netops" not in hits[0].observation
    assert not _rules(_run(tmp_path, "7.4.11", SSO, ADMINS), "fortinet.fortios.admin.forticloud_sso_ioc_account")
    assert not _rules(_run(tmp_path, "7.4.8", "", ADMINS), "fortinet.fortios.admin.forticloud_sso_ioc_account")


@pytest.mark.parametrize("version,settings,basis", [
    ("7.4.4", "", FindingBasis.DOCUMENTED_DEFAULT),
    ("6.4.14", "", FindingBasis.DOCUMENTED_DEFAULT),
    ("7.4.4", "    set pre-login-banner disable\n", FindingBasis.EXPLICIT_VALUE),
    ("7.4.4", "    set pre-login-banner enable\n", None),
    ("6.4.13", "", None),  # no verified default cell
])
def test_pre_login_banner(tmp_path, version, settings, basis):
    findings = _rules(_run(tmp_path, version, settings), "fortinet.fortios.banner.login_disabled")
    assert (findings[0].basis if findings else None) is basis
