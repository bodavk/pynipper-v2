"""SC-046: independent, bounded IPv6 management ACL evaluation."""

import json

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.common.assessment import AssessmentContext
from src.devices.cisco.ios import CiscoIOSParser
from src.main import main
from src.report.coverage import build_report_context


SSH6 = "cisco.ios.ssh.ipv6_unrestricted_sources"
HTTP6 = "cisco.ios.http.ipv6_unrestricted_sources"
SSH4 = "cisco.ios.ssh.unrestricted_sources"
HTTP4 = "cisco.ios.http.unrestricted_sources"


def scan(tmp_path, commands, *, device="IOS_XE"):
    source = tmp_path / "dual-stack.conf"
    source.write_text("version 17.9\nip ssh version 2\n" + commands, encoding="utf-8")
    parser = CiscoIOSParser(str(source))
    parser.device_type = device
    findings = {item.rule_id: item for item in process_cisco_ios_conf(parser).values()}
    return parser, findings


@pytest.mark.parametrize("rule,state", [
    ("permit ipv6 any any", "permit-all"),
    ("permit any any", "permit-all"),
    ("permit tcp any any", "permit-all"),
    ("permit ipv6 ::/0 ::/0 sequence 10", "permit-all"),
    ("20 permit ipv6 any any\n 10 deny ipv6 host 2001:db8::1 any", "restrictive"),
    ("permit ipv6 2001:db8::/32 any", "restrictive"),
    ("permit ipv6 any host 2001:db8::1", "unsupported"),
    ("permit tcp any any eq 22", "unsupported"),
    ("permit ipv6 any any time-range HOURS", "unsupported"),
    ("permit udp any any\n permit ipv6 any any", "unsupported"),
    ("permit ipv6 any6 any", "unsupported"),
])
def test_ipv6_acl_grammar_is_bounded(tmp_path, rule, state):
    parser, findings = scan(
        tmp_path, "line vty 0 4\n transport input ssh\n ipv6 access-class V6 in\n"
        "ipv6 access-list V6\n " + rule + "\n",
    )
    assert parser.get_management_ipv6_acl("V6").state == state
    assert (SSH6 in findings) is (state == "permit-all")


def test_ipv4_and_ipv6_vty_attachments_are_independent(tmp_path):
    parser, findings = scan(
        tmp_path, "line vty 0 4\n transport input ssh\n"
        " access-class V4 in\n ipv6 access-class V6 in\n"
        "ip access-list standard V4\n permit host 192.0.2.1\n"
        "ipv6 access-list V6\n permit ipv6 any any\n",
    )
    assert {profile.ipv6_access_class for profile in parser.get_management_acl_vty_profiles()} == {"V6"}
    assert SSH6 in findings and SSH4 not in findings
    assert findings[SSH6].basis.value == "explicit-value"


def test_overlapping_vty_mutations_and_removals(tmp_path):
    parser, findings = scan(
        tmp_path, "line vty 0 4\n transport input ssh\n ipv6 access-class V6 in\n"
        "line vty 2 4\n no ipv6 access-class V6 in\n"
        "ipv6 access-list V6\n 10 deny ipv6 host 2001:db8::1 any\n"
        " 20 permit ipv6 any any\n no 10\n",
    )
    assert parser.get_management_ipv6_acl("V6").state == "permit-all"
    assert SSH6 in findings
    assert "VTY lines 0, 1" in findings[SSH6].observation


def test_removed_or_unresolved_ipv6_acl_is_coverage_only(tmp_path):
    parser, findings = scan(
        tmp_path, "line vty 0 4\n transport input ssh\n ipv6 access-class V6 in\n"
        "ipv6 access-list V6\n permit ipv6 any any\n"
        "no ipv6 access-list V6\n",
    )
    assert parser.get_management_ipv6_acl("V6").state == "unresolved"
    assert SSH6 not in findings
    notes = build_report_context(parser)["coverage"]["diagnostics"]
    assert any("attached IPv6 ACL definition was not resolved" in note for note in notes)
    assert all("V6" not in note for note in notes)


def test_ipv6_diagnostics_respect_rule_exclusion(tmp_path):
    parser, _ = scan(
        tmp_path, "line vty 0 4\n transport input ssh\n ipv6 access-class MISSING in\n",
    )
    assert any("IPv6 ACL" in note for note in parser.diagnostics)
    parser.set_assessment_context(AssessmentContext(excluded_categories=frozenset({"ssh"})))
    assert not any("IPv6 ACL" in note for note in parser.diagnostics)


def test_web_ipv6_binding_does_not_replace_ipv4_binding(tmp_path):
    parser, findings = scan(
        tmp_path, "ip http secure-server\nip http access-class ipv4 V4\n"
        "ip http access-class ipv6 V6\n"
        "ip access-list standard V4\n permit host 192.0.2.1\n"
        "ipv6 access-list V6\n permit ipv6 any any\n",
    )
    assert parser.get_http_access_class() == "V4"
    assert parser.get_http_ipv6_access_class() == "V6"
    assert HTTP6 in findings and HTTP4 not in findings
    assert SSH6 not in findings


def test_web_ipv6_disabled_removed_and_non_xe_are_ungraded(tmp_path):
    commands = ("ip http secure-server\nip http access-class ipv6 V6\n"
                "ipv6 access-list V6\n permit ipv6 any any\n")
    for tail, device in (
        ("no ip http secure-server\n", "IOS_XE"),
        ("no ip http access-class ipv6 V6\n", "IOS_XE"),
        ("", "IOS_ROUTER"),
    ):
        _, findings = scan(tmp_path, commands + tail, device=device)
        assert HTTP6 not in findings


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_ipv6_report_and_redaction(tmp_path, output_type):
    source = tmp_path / "dual-stack.conf"
    source.write_text(
        "version 17.9\nip ssh version 2\nip http secure-server\n"
        "ip http access-class ipv6 V6\nline vty 0 4\n transport input ssh\n"
        " ipv6 access-class V6 in\nipv6 access-list V6\n"
        " permit ipv6 any any\nusername auditor secret 0 DoNotExposeThisSecret\n",
        encoding="utf-8",
    )
    report = tmp_path / f"report.{output_type.lower()}"
    assert main(["-d", "ios-xe", "-i", str(source), "-o", output_type,
                 "-f", str(report)]) == 0
    rendered = report.read_text(encoding="utf-8")
    assert "SSH management ACL permits every IPv6 source" in rendered
    assert "Web management ACL permits every IPv6 source" in rendered
    assert "DoNotExposeThisSecret" not in rendered
    if output_type == "JSON":
        payload = json.loads(rendered)
        assert {SSH6, HTTP6}.issubset(
            {item["rule_id"] for item in payload["security-audit"].values()}
        )
