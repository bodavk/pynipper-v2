"""Effective SRX fallback policy and report coverage (RV-011)."""

import json
import subprocess
import sys

import pytest

from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.devices.juniper.junos import JunOSParser
from src.report.coverage import build_report_context


def _analyze(tmp_path, content):
    path = tmp_path / "srx.conf"
    path.write_text(content, encoding="utf-8")
    parser = JunOSParser(str(path))
    plugin = PluginJunOSBaseline()
    plugin.check_default_security_policy(parser)
    return parser, plugin.get_issues()


def test_hierarchical_permit_all_is_visible_as_transit_fallback(tmp_path):
    parser, issues = _analyze(tmp_path, """security {
    policies {
        default-policy { permit-all; }
    }
    zones { security-zone trust { host-inbound-traffic { system-services { ssh; } } } }
}
""")
    assert parser.get_default_security_policy().action == "permit-all"
    assert [issue.rule_id for issue in issues] == ["juniper.junos.policy.default_permit_all"]
    assert "host-inbound" in issues[0].observation
    normalized = parser.get_normalized_config()
    assert [(item.name, item.action, item.scope) for item in normalized.policies.items] == [
        ("security/default-policy", "permit-all", "security:unmatched-transit"),
    ]
    policy_field = next(item for item in build_report_context(parser)["coverage"]["fields"]
                        if item["name"] == "security-policies")
    assert (policy_field["knowledge-state"], policy_field["item-count"]) == ("known", 1)


def test_ordered_override_delete_and_explicit_deny(tmp_path):
    cases = [
        ("set security policies default-policy permit-all\n"
         "set security policies default-policy deny-all\n", "deny-all", "explicit"),
        ("set security policies default-policy permit-all\n"
         "delete security policies default-policy\n", None, "not-configured"),
        ("set security policies default-policy deny-all\n", "deny-all", "explicit"),
    ]
    for content, action, resolution in cases:
        parser, issues = _analyze(tmp_path, content)
        state = parser.get_default_security_policy()
        assert (state.action, state.resolution_state) == (action, resolution)
        assert issues == []


def test_restrictive_zone_policy_does_not_cancel_permit_all_fallback(tmp_path):
    parser, issues = _analyze(tmp_path, """set security policies from-zone trust to-zone untrust policy DENY match source-address any
set security policies from-zone trust to-zone untrust policy DENY match destination-address any
set security policies from-zone trust to-zone untrust policy DENY match application junos-ssh
set security policies from-zone trust to-zone untrust policy DENY then deny
set security policies default-policy permit-all
""")
    assert len(parser.get_security_policies()) == 1
    assert [issue.rule_id for issue in issues] == ["juniper.junos.policy.default_permit_all"]


def test_group_inheritance_unknown_and_explicit_override(tmp_path):
    parser, issues = _analyze(tmp_path, "set apply-groups MISSING\n")
    assert parser.get_default_security_policy().resolution_state == "unknown"
    assert parser.get_normalized_config().policies.state.value == "unknown"
    assert issues == []

    group = """set groups EDGE security policies default-policy permit-all
set apply-groups EDGE
"""
    parser, issues = _analyze(tmp_path, group)
    assert parser.get_default_security_policy().resolution_state == "inherited"
    assert [issue.rule_id for issue in issues] == ["juniper.junos.policy.default_permit_all"]

    parser, issues = _analyze(
        tmp_path, group + "set security policies default-policy deny-all\n"
    )
    assert parser.get_default_security_policy().action == "deny-all"
    assert issues == []


def test_malformed_and_deactivated_default_remain_unknown(tmp_path):
    for content in (
        "set security policies default-policy maybe\n",
        "set security policies default-policy permit-all\n"
        "deactivate security policies default-policy\n",
    ):
        parser, issues = _analyze(tmp_path, content)
        assert parser.get_default_security_policy().resolution_state == "unknown"
        assert parser.get_normalized_config().policies.state.value == "unknown"
        assert issues == []


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_cli_reports_permit_all_with_policy_coverage(tmp_path, output_type):
    source = tmp_path / "srx.conf"
    source.write_text("security { policies { default-policy { permit-all; } } }\n", encoding="utf-8")
    output = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "JUNOS", "-i", str(source),
         "-o", output_type, "-f", str(output), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = output.read_text(encoding="utf-8")
    assert "Unmatched SRX transit traffic is permitted" in report
    if output_type == "JSON":
        data = json.loads(report)
        assert "juniper.junos.policy.default_permit_all" in {
            item["rule_id"] for item in data["security-audit"].values()
        }
        coverage = next(item for item in data["coverage"]["fields"]
                        if item["name"] == "security-policies")
        assert coverage["item-count"] == 1
