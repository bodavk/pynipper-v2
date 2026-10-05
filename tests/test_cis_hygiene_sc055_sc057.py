"""SC-055 FortiOS management hygiene and SC-057 ASA password recovery (CIS follow-ups)."""

import contextlib
import io

import pytest

from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis, Severity
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices import get_parser


def _fortios(tmp_path, global_settings, version="7.4.4", admin="admin"):
    path = tmp_path / "fgt.conf"
    path.write_text(
        f"#config-version=FGT60F-{version}-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
        f"config system global\n    set hostname fw\n{global_settings}end\n"
        "config system interface\n    edit \"port1\"\n        set allowaccess https ssh\n    next\nend\n"
        f"config system admin\n    edit \"{admin}\"\n        set accprofile \"super_admin\"\n    next\nend\n",
        encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        return {f.rule_id: f for f in process_fortios_conf(get_parser("FORTIOS", str(path))).values()}


def test_fortios_defaults_on_741_plus(tmp_path):
    rules = _fortios(tmp_path, "")
    assert rules["fortinet.fortios.banner.post_login_disabled"].severity is Severity.INFORMATIONAL
    assert "HTTPS 443" in rules["fortinet.fortios.management.default_admin_ports"].observation
    assert "fortinet.fortios.admin.default_account_name" in rules
    for rule in ("fortinet.fortios.management.default_admin_ports", "fortinet.fortios.admin.default_account_name",
                 "fortinet.fortios.management.login_hostname_disclosed"):
        assert guidance_for(rule)


def test_fortios_hardened_and_old_release(tmp_path):
    hardened = _fortios(tmp_path, "    set post-login-banner enable\n    set admin-sport 8443\n    set admin-ssh-port 2222\n",
                        admin="ops")
    assert not {"fortinet.fortios.banner.post_login_disabled", "fortinet.fortios.management.default_admin_ports",
                "fortinet.fortios.admin.default_account_name"} & set(hardened)
    old = _fortios(tmp_path, "", version="7.2.8", admin="ops")
    assert "fortinet.fortios.management.default_admin_ports" not in old
    assert "fortinet.fortios.management.login_hostname_disclosed" in _fortios(
        tmp_path, "    set gui-display-hostname enable\n")


def _asa(tmp_path, body):
    path = tmp_path / "asa.conf"
    path.write_text("ASA Version 9.18(4)\nhostname fw\n" + body, encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        return [f for f in process_asa_conf(get_parser("ASA", str(path))).values()
                if f.rule_id == "cisco.asa.platform.password_recovery"]


@pytest.mark.parametrize("body,basis", [("", FindingBasis.DOCUMENTED_DEFAULT),
                                        ("service password-recovery\n", FindingBasis.EXPLICIT_VALUE)])
def test_asa_password_recovery(tmp_path, body, basis):
    findings = _asa(tmp_path, body)
    assert len(findings) == 1 and findings[0].basis is basis and guidance_for(findings[0].rule_id)


def test_asa_password_recovery_disabled(tmp_path):
    assert not _asa(tmp_path, "no service password-recovery\n")


def test_fortios_security_depth(tmp_path):
    body = ("config system zone\n    edit \"DMZ\"\n        set intrazone allow\n    next\nend\n"
            "config system autoupdate schedule\n    set status disable\nend\n"
            "config antivirus settings\n    set grayware disable\nend\n")
    path = tmp_path / "fgt2.conf"
    path.write_text("#config-version=FGT60F-7.4.4-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
                    "config system global\n    set hostname fw\nend\n" + body, encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        rules = {f.rule_id: f for f in process_fortios_conf(get_parser("FORTIOS", str(path))).values()}
    for rule in ("fortinet.fortios.policy.intrazone_allow", "fortinet.fortios.updates.schedule_disabled",
                 "fortinet.fortios.policy.antivirus_detection_weakened", "fortinet.fortios.hardening.cis_hygiene"):
        assert rule in rules and guidance_for(rule)
    assert "CIS 2.1.12" in rules["fortinet.fortios.hardening.cis_hygiene"].observation
