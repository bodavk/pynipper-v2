"""IOS/IOS-XE effective administrative AAA bindings (SC-001)."""

import json
import subprocess
import sys

import pytest

from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.devices.cisco.ios import CiscoIOSParser


BASE = """version 15.2(4)M7
hostname aaa-edge
aaa new-model
username rescue privilege 15 secret 9 REDACTED
aaa authentication login default group TAC local
aaa authorization exec default group TAC local
aaa authorization commands 15 default group TAC local
aaa accounting exec default start-stop group TAC
aaa group server tacacs+ TAC
 server-private 192.0.2.10 key synthetic-shared-secret
line vty 0 4
 login authentication default
 transport input ssh
"""


def _scan(tmp_path, config):
    path = tmp_path / "aaa.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    plugin = PluginIOSBaseline()
    plugin.analyze(parser)
    return parser, plugin.get_issues()


def _ids(findings):
    return {item.rule_id for item in findings}


def test_secure_default_lists_and_local_fallback(tmp_path):
    parser, findings = _scan(tmp_path, BASE)
    assert parser.get_aaa_server_group_records()[0].members == ("192.0.2.10",)
    assert not _ids(findings) & {
        "cisco.ios.vty.authentication", "cisco.ios.vty.authorization",
        "cisco.ios.vty.authorization_bypass", "cisco.ios.vty.accounting_unbound",
        "cisco.ios.vty.aaa_server_group_unusable",
    }
    assert "synthetic-shared-secret" not in str(findings)


@pytest.mark.parametrize("method", ["none", "if-authenticated"])
def test_bound_authorization_bypass_is_not_unauthenticated_login(tmp_path, method):
    _, findings = _scan(
        tmp_path,
        BASE.replace("aaa authorization exec default group TAC local",
                     f"aaa authorization exec default group TAC {method}"),
    )
    assert "cisco.ios.vty.authorization_bypass" in _ids(findings)
    assert "cisco.ios.vty.authentication" not in _ids(findings)


def test_named_accounting_declaration_is_not_effective_without_line_binding(tmp_path):
    _, findings = _scan(
        tmp_path,
        BASE.replace("aaa accounting exec default", "aaa accounting exec AUD"),
    )
    assert "cisco.ios.vty.accounting_unbound" in _ids(findings)


def test_explicitly_empty_bound_server_group(tmp_path):
    _, findings = _scan(tmp_path, BASE.replace(
        " server-private 192.0.2.10 key synthetic-shared-secret\n", ""
    ))
    assert "cisco.ios.vty.aaa_server_group_unusable" in _ids(findings)
    assert "cisco.ios.vty.authentication" not in _ids(findings)


def test_removed_group_member_is_not_treated_as_usable(tmp_path):
    _, findings = _scan(tmp_path, BASE.replace(
        " server-private 192.0.2.10 key synthetic-shared-secret\n",
        " server-private 192.0.2.10 key synthetic-shared-secret\n"
        " no server-private 192.0.2.10\n",
    ))
    assert "cisco.ios.vty.aaa_server_group_unusable" in _ids(findings)


def test_overlap_resolves_per_physical_line_and_ignores_inactive_vty(tmp_path):
    config = BASE.replace(
        "aaa authorization exec default group TAC local",
        "aaa authorization exec default group TAC local\n"
        "aaa authorization exec BYPASS none",
    ).replace(
        "line vty 0 4\n login authentication default\n transport input ssh\n",
        "line vty 0 15\n login authentication default\n"
        " authorization exec BYPASS\n transport input ssh\n"
        "line vty 0 4\n authorization exec default\n"
        "line vty 10 15\n transport input none\n",
    )
    parser, findings = _scan(tmp_path, config)
    assert [item.line for item in parser.get_effective_vty_aaa()] == [
        "line vty 0 4", "line vty 5 9", "line vty 10 15",
    ]
    bypass = [item for item in findings if item.rule_id == "cisco.ios.vty.authorization_bypass"]
    assert len(bypass) == 1
    assert "line vty 5 9" in bypass[0].observation


def test_accounting_removal_and_malformed_group_method(tmp_path):
    config = BASE.replace(
        "aaa accounting exec default start-stop group TAC",
        "aaa accounting exec default start-stop group TAC\n"
        "no aaa accounting exec default\n"
        "aaa accounting exec AUD start-stop group TAC",
    ).replace("aaa authorization exec default group TAC local",
              "aaa authorization exec default group")
    parser, findings = _scan(tmp_path, config)
    assert [item.name for item in parser.get_aaa_accounting_lists()] == ["AUD"]
    assert "cisco.ios.vty.authorization" in _ids(findings)
    assert "cisco.ios.vty.accounting_unbound" in _ids(findings)


def test_explicit_none_accounting_and_undefined_line_reference(tmp_path):
    _, findings = _scan(tmp_path, BASE.replace(
        "aaa accounting exec default start-stop group TAC",
        "aaa accounting exec default none",
    ))
    assert "cisco.ios.vty.accounting_disabled" in _ids(findings)
    assert "cisco.ios.vty.accounting_unbound" not in _ids(findings)

    _, findings = _scan(tmp_path, BASE + "line vty 0 4\n accounting exec MISSING\n")
    assert "cisco.ios.vty.accounting_unbound" in _ids(findings)


def test_inactive_vty_and_restored_transport(tmp_path):
    parser, findings = _scan(
        tmp_path,
        BASE + "line vty 0 4\n transport input none\n"
        "line vty 2 4\n no transport input\n",
    )
    assert [(item.line, item.active) for item in parser.get_effective_vty_aaa()] == [
        ("line vty 0 1", False), ("line vty 2 4", True),
    ]
    assert "cisco.ios.vty.accounting_unbound" not in _ids(findings)


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
@pytest.mark.parametrize("device", ["IOS_ROUTER", "IOS_XE"])
def test_public_cli_aaa_binding_and_secret_redaction(tmp_path, output_type, device):
    path = tmp_path / "aaa.conf"
    path.write_text(BASE.replace("aaa authorization exec default group TAC local",
                                 "aaa authorization exec default none"), encoding="utf-8")
    report = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", device, "-i", str(path),
         "-o", output_type, "-f", str(report), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = report.read_text(encoding="utf-8")
    assert "VTY authorization has an explicit bypass method" in rendered
    assert "synthetic-shared-secret" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(rendered)
        assert any(
            item["rule_id"] == "cisco.ios.vty.authorization_bypass"
            for item in data["security-audit"].values()
        )
