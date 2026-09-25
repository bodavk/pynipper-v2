"""PT-009: findings say whether they rest on an explicit value, a documented
default, or a hardening setting that is simply not configured."""

import json

import pytest

from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.analyze.common.issue import Finding, FindingBasis, Severity
from src.devices.cisco.ios import CiscoIOSParser
from src.main import main
from src.report.explanations import BASIS_TEXT, build_finding_views
from src.report.report import _generate_html_report
from tests.test_report_readability_pt005_007 import CORPUS


def _ios_vty(tmp_path, vty_body):
    path = tmp_path / "router.conf"
    path.write_text(
        "version 17.9\nhostname r1\nline vty 0 4\n" + vty_body + "end\n", encoding="utf-8"
    )
    parser = CiscoIOSParser(str(path))
    plugin = PluginIOSBaseline()
    plugin.analyze(parser)
    return {item.rule_id: item for item in plugin.get_issues()}


def test_ios_vty_telnet_basis_follows_the_branch(tmp_path):
    missing = _ios_vty(tmp_path, " login local\n")["cisco.ios.vty.telnet"]
    assert missing.basis is FindingBasis.MISSING_EXPLICIT_SETTING
    explicit = _ios_vty(tmp_path, " login local\n transport input telnet ssh\n")["cisco.ios.vty.telnet"]
    assert explicit.basis is FindingBasis.EXPLICIT_VALUE


def _audit(tmp_path, device, relative):
    report = tmp_path / "report.json"
    assert main(["-d", device, "-i", str(CORPUS / relative), "-o", "JSON", "-f", str(report), "-x"]) == 0
    return json.loads(report.read_text(encoding="utf-8"))["security-audit"].values()


@pytest.mark.parametrize(
    "device,relative,expected",
    [
        ("cisco-ios", "cisco_ios/vulnerable.conf", {
            "cisco.ios.vty.telnet": "explicit-value",  # transport input all
            "cisco.ios.ssh.protocol_version": "explicit-value",
            "cisco.ios.ssh.authentication_retries": "explicit-value",
            "cisco.ios.ip.source_route": "missing-explicit-setting",
        }),
        ("ASA", "cisco_asa/vulnerable.conf", {
            "cisco.asa.management.certificate": "missing-explicit-setting",
        }),
        ("fortios", "fortios/vulnerable.conf", {
            "fortinet.fortios.password_policy.disabled": "explicit-value",
            "fortinet.fortios.management.insecure_protocol": "explicit-value",
        }),
        ("JUNOS", "junos/vulnerable.conf", {"juniper.junos.ssh.root_login": "explicit-value"}),
    ],
)
def test_corpus_findings_carry_the_declared_basis(tmp_path, device, relative, expected):
    records = list(_audit(tmp_path, device, relative))
    by_rule = {}
    for record in records:
        by_rule.setdefault(record["rule_id"], set()).add(record["basis"])
    for rule, basis in expected.items():
        assert by_rule[rule] == {basis}, rule
    for record in records:
        assert "basis" in record
        if record["basis"] is None:
            assert record["basis-note"] is None


def test_fortios_absent_password_policy_is_a_documented_default(tmp_path):
    source = tmp_path / "fgt.conf"
    source.write_text(
        "#config-version=FGT60F-7.4.6-FW-build0001-240101:opmode=0:vdom=0:user=admin\n"
        "config system global\nset hostname fgt\nend\n",
        encoding="utf-8",
    )
    report = tmp_path / "report.json"
    assert main(["-d", "fortios", "-i", str(source), "-o", "JSON", "-f", str(report), "-x"]) == 0
    records = json.loads(report.read_text(encoding="utf-8"))["security-audit"].values()
    policy, = [r for r in records if r["rule_id"] == "fortinet.fortios.password_policy.disabled"]
    assert policy["basis"] == "documented-default"
    assert policy["basis-note"] == BASIS_TEXT[FindingBasis.DOCUMENTED_DEFAULT][1]


def _finding(basis):
    return Finding(
        rule_id="cisco.ios.vty.telnet", device="IOS_ROUTER", title="VTY permits Telnet",
        observation="obs", impact="impact", recommendation="Configure 'transport input ssh'.",
        severity=Severity.HIGH, basis=basis,
    )


def test_basis_is_validated_and_serialized():
    assert _finding(None).to_dict()["basis"] is None
    assert _finding("missing-explicit-setting").basis is FindingBasis.MISSING_EXPLICIT_SETTING
    with pytest.raises(ValueError):
        _finding("guessed")


def test_html_shows_the_note_only_when_declared(tmp_path):
    output = tmp_path / "r.html"
    issues = {"a": _finding(FindingBasis.MISSING_EXPLICIT_SETTING), "b": _finding(None)}
    _generate_html_report(str(output), issues, [], {"device-type": "IOS_ROUTER", "hostname": "r1"})
    html = output.read_text(encoding="utf-8")
    label, note = BASIS_TEXT[FindingBasis.MISSING_EXPLICIT_SETTING]
    assert html.count('class="basis ') == 1
    assert f"<strong>{label}:</strong>" in html and "may already be" in note
    views = build_finding_views(issues)
    assert [view["basis"] for view in views] == ["missing-explicit-setting", None]


@pytest.mark.parametrize("device,relative,rule", [
    ("F5_BIGIP", "f5_bigip/vulnerable.scf", "f5.bigip.snmp.default_community"),
    ("ARISTA_EOS", "arista_eos/vulnerable.conf", "arista.eos.snmp.default_community"),
    ("HP_PROCURVE", "hp_procurve/vulnerable.conf", "hp.procurve.snmp.default_community"),
    ("cisco-ios", "cisco_ios/vulnerable.conf", "cisco.ios.snmp.default_community"),
])
def test_configured_default_communities_are_explicit_values(tmp_path, device, relative, rule):
    bases = {record["basis"] for record in _audit(tmp_path, device, relative) if record["rule_id"] == rule}
    assert bases == {"explicit-value"}


def test_absent_required_controls_use_the_required_setting_basis(tmp_path):
    findings = _ios_vty(tmp_path, " login local\n transport input ssh\n")
    for rule in ("cisco.ios.ntp.servers", "cisco.ios.logging.remote_destination", "cisco.ios.banner.login"):
        assert findings[rule].basis is FindingBasis.REQUIRED_SETTING_MISSING
    label, note = BASIS_TEXT[FindingBasis.REQUIRED_SETTING_MISSING]
    assert label == "Required setting not configured" and "not provide it by default" in note
