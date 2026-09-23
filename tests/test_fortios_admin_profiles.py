"""Bound FortiOS custom administrator profile privileges (SC-011)."""

import json
import subprocess
import sys

import pytest

from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser


def _config(permission="read-write", profile="operators", admin_status="enable", protected=False):
    profile_block = (
        "config system accprofile\n"
        f"edit {profile}\nset sysgrp {permission}\nnext\nend\n"
        if profile == "operators" else ""
    )
    protection = "set trusthost1 192.0.2.0 255.255.255.0\nset two-factor fortitoken\n" if protected else ""
    return (
        "#config-version=FGT60F-7.4.2-FW-build1234-240101:opmode=0:vdom=0:user=admin\n"
        f"{profile_block}config system admin\nedit audit-admin\n"
        f"set accprofile {profile}\nset status {admin_status}\n{protection}next\nend\n"
    )


@pytest.mark.parametrize("permission,profile,status,protected,expected", [
    ("read-write", "operators", "enable", True, False),
    ("read-write", "operators", "enable", False, True),
    ("read", "operators", "enable", False, False),
    ("read-write", "operators", "disable", False, False),
    ("read-write", "missing", "enable", False, False),
])
def test_custom_privileged_profile_bound_to_admin(
    tmp_path, permission, profile, status, protected, expected,
):
    path = tmp_path / "fortios.conf"
    path.write_text(_config(permission, profile, status, protected), encoding="utf-8")
    parser = FortiOSParser(str(path))
    roles = parser.get_administrator_roles()
    if status == "enable":
        assert len(roles) == 1
        assert roles[0].privileged_state == (
            "privileged" if permission == "read-write" and profile == "operators" else "unknown"
        )
    else:
        assert not roles
    rules = {finding.rule_id for finding in process_fortios_conf(parser).values()}
    assert ("fortinet.fortios.admin.trusted_hosts" in rules) is expected
    assert ("fortinet.fortios.admin.mfa" in rules) is expected


def test_custom_profile_permission_override_and_nested_write(tmp_path):
    path = tmp_path / "fortios.conf"
    config = _config(permission="read")
    config = config.replace(
        "set sysgrp read\n",
        "set sysgrp read-write\nset sysgrp read\n"
        "set loggrp custom\nconfig loggrp-permission\n"
        "set mnt read-write\nend\n",
    )
    path.write_text(config, encoding="utf-8")
    parser = FortiOSParser(str(path))
    role = parser.get_administrator_roles()[0]
    assert role.writable_groups == ("loggrp",)
    assert role.privileged_state == "privileged"


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_report_custom_privileged_admin_is_redacted(tmp_path, output_type):
    path = tmp_path / "fortios.conf"
    secret = "synthetic-admin-private-value"
    path.write_text(
        _config() + "config system admin\nedit audit-admin\n"
        f"set password {secret}\nnext\nend\n",
        encoding="utf-8",
    )
    report = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "FORTIOS", "-i", str(path),
         "-o", output_type, "-f", str(report), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = report.read_text(encoding="utf-8")
    assert "Privileged administrator is not source restricted" in rendered
    assert secret not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(rendered)
        assert any(
            item["rule_id"] == "fortinet.fortios.admin.trusted_hosts"
            for item in data["security-audit"].values()
        )
