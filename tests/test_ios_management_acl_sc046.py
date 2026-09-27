import pytest
import json
from src.main import main

from src.devices.cisco.ios import CiscoIOSParser
from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.common.assessment import AssessmentContext
from src.report.coverage import build_report_context


def parse(tmp_path, acl, tail=""):
    source = tmp_path / "ios.conf"
    source.write_text("version 15.2\nip ssh version 2\nip http secure-server\n"
                      "ip http access-class ipv4 MGMT\nline vty 0 4\n transport input ssh\n"
                      " access-class MGMT in\n!\n" + acl + tail, encoding="utf-8")
    return CiscoIOSParser(str(source))


@pytest.mark.parametrize("rules,state", [
    ("10 permit any", "permit-all"),
    ("10 permit 0.0.0.0 255.255.255.255", "permit-all"),
    ("20 permit any\n 10 deny host 192.0.2.1", "restrictive"),
    ("10 permit host 192.0.2.1", "restrictive"),
    ("10 permit any time-range HOURS", "unsupported"),
    ("10 permit any\n no 10", "unsupported"),
    ("10 permit host 192.0.2.1\n 10 permit any", "permit-all"),
    ("10 permit any6", "unsupported"),
])
def test_standard_acl_order_and_unsupported_predicates(tmp_path, rules, state):
    parser = parse(tmp_path, "ip access-list standard MGMT\n " + rules + "\n")
    assert parser.get_management_ipv4_acl("MGMT").state == state
    findings = [item for item in process_cisco_ios_conf(parser).values() if item.rule_id.endswith("unrestricted_sources")]
    assert len(findings) == (2 if state == "permit-all" else 0)
    if findings:
        assert all(item.evidence_locations for item in findings)


def test_removed_and_unresolved_references_are_not_permit_all(tmp_path):
    parser = parse(tmp_path, "ip access-list standard MGMT\n permit any\n!\nno ip access-list standard MGMT\n")
    assert parser.get_management_ipv4_acl("MGMT").state == "unresolved"
    parser = parse(tmp_path, "access-list 10 permit any\nno access-list 10 permit any\n")
    assert parser.get_management_ipv4_acl("10").state != "permit-all"


def test_disabled_services_and_ipv6_attachment_do_not_trigger(tmp_path):
    parser = parse(tmp_path, "ip access-list standard MGMT\n permit any\n!\n",
                   "no ip http secure-server\nline vty 0 4\n transport input none\n")
    assert not [item for item in process_cisco_ios_conf(parser).values() if item.rule_id.endswith("unrestricted_sources")]


def test_overlapping_vty_override_preserves_other_lines(tmp_path):
    parser = parse(tmp_path, "ip access-list standard MGMT\n permit any\n!\n",
                   "line vty 2 4\n transport input none\n")
    ssh = [item for item in process_cisco_ios_conf(parser).values()
           if item.rule_id == "cisco.ios.ssh.unrestricted_sources"]
    assert len(ssh) == 1
    assert "VTY lines 0, 1 uses" in ssh[0].observation


@pytest.mark.parametrize("format", ["HTML", "JSON"])
def test_public_reports_management_acl_findings(tmp_path, format):
    parse(tmp_path, "ip access-list standard MGMT\n permit any\n")
    output = tmp_path / ("report." + format.lower())
    assert main(["-d", "cisco-ios", "-i", str(tmp_path / "ios.conf"),
                 "-o", format, "-f", str(output)]) == 0
    report = output.read_text(encoding="utf-8")
    assert "SSH management ACL permits every IPv4 source" in report
    assert "Web management ACL permits every IPv4 source" in report
    if format == "JSON":
        assert json.loads(report)["security-audit"]


@pytest.mark.parametrize("rules,state", [
    ("10 permit ip any any", "permit-all"),
    ("10 permit tcp any any log", "permit-all"),
    ("10 permit ip 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255", "permit-all"),
    ("20 permit ip any any\n 10 deny ip host 192.0.2.1 any", "restrictive"),
    ("10 permit tcp host 192.0.2.1 any", "restrictive"),
    ("10 permit ip any any\n 20 deny ip any any", "permit-all"),
    ("10 deny ip any any\n no 10\n 20 permit ip any any", "permit-all"),
    ("10 deny ip any any\n 10 permit ip any any", "permit-all"),
    ("10 permit ip any any\n no permit ip any any", "unsupported"),
    ("10 permit tcp any any eq 22", "unsupported"),
    ("10 permit ip any host 192.0.2.1", "unsupported"),
    ("10 permit tcp any any established", "unsupported"),
    ("10 permit ip any any time-range HOURS", "unsupported"),
    ("10 deny udp any any\n 20 permit ip any any", "unsupported"),
    ("10 permit ip object-group SOURCES any\n 20 permit ip any any", "unsupported"),
    ("10 permit ip 192.0.2.1 any", "unsupported"),
    ("10 permit ip any6 any", "unsupported"),
    ("10 permit ip any any6", "unsupported"),
    ("10 permit ip any", "unsupported"),
    ("10 permit ip invalid 0.0.0.255 any", "unsupported"),
    ("9" * 5000 + " permit ip any any", "unsupported"),
])
def test_extended_acl_bounded_ssh_proof(tmp_path, rules, state):
    parser = parse(tmp_path, "ip access-list extended MGMT\n " + rules + "\n")
    assert parser.get_management_ipv4_acl("MGMT", allow_extended=True).state == state
    assert parser.get_management_ipv4_acl("MGMT").state == "unsupported"
    findings = [item for item in process_cisco_ios_conf(parser).values()
                if item.rule_id.endswith("unrestricted_sources")]
    assert len(findings) == (1 if state == "permit-all" else 0)
    if findings:
        assert findings[0].rule_id == "cisco.ios.ssh.unrestricted_sources"
        assert findings[0].evidence_locations


@pytest.mark.parametrize("name", ["100", "199", "2000", "2699"])
def test_numbered_extended_acl_removals(tmp_path, name):
    parser = parse(tmp_path, f"access-list {name} deny ip host 192.0.2.1 any\n"
                   f"access-list {name} permit ip any any\n"
                   f"no access-list {name} deny ip host 192.0.2.1 any\n")
    assert parser.get_management_ipv4_acl(name, allow_extended=True).state == "permit-all"
    parser = parse(tmp_path, f"access-list {name} permit ip any any\nno access-list {name}\n")
    assert parser.get_management_ipv4_acl(name, allow_extended=True).state == "unresolved"


@pytest.mark.parametrize("tail", [
    "no ip access-list extended MGMT\n",
    "line vty 0 4\n transport input none\n",
    "line vty 0 4\n access-class MISSING in\n",
    "line vty 0 4\n no access-class MGMT in\n ipv6 access-class MGMT in\n",
])
def test_extended_acl_removed_unbound_or_disabled(tmp_path, tail):
    parser = parse(tmp_path, "ip access-list extended MGMT\n permit ip any any\n!\n", tail)
    assert not [item for item in process_cisco_ios_conf(parser).values()
                if item.rule_id.endswith("unrestricted_sources")]


@pytest.mark.parametrize("device", ["cisco-ios", "ios-xe"])
@pytest.mark.parametrize("format", ["HTML", "JSON"])
def test_extended_acl_public_reports_and_secret_redaction(tmp_path, device, format):
    parse(tmp_path, "ip access-list extended MGMT\n permit ip any any\n!\n",
          "username auditor secret 0 DoNotExposeThisSecret\n")
    output = tmp_path / ("extended." + format.lower())
    assert main(["-d", device, "-i", str(tmp_path / "ios.conf"),
                 "-o", format, "-f", str(output)]) == 0
    report = output.read_text(encoding="utf-8")
    assert "SSH management ACL permits every IPv4 source" in report
    assert "Web management ACL permits every IPv4 source" not in report
    assert "DoNotExposeThisSecret" not in report


@pytest.mark.parametrize("acl,reason", [
    ("", "definition was not resolved"),
    ("ip access-list standard MGMT\n permit any\n!\nno ip access-list standard MGMT\n",
     "definition was not resolved"),
    ("ip access-list standard MGMT\n", "outside the supported evaluation grammar"),
    ("ip access-list standard MGMT\n permit any time-range HOURS\n",
     "outside the supported evaluation grammar"),
])
def test_management_acl_unknowns_are_coverage_not_findings(tmp_path, acl, reason):
    parser = parse(tmp_path, acl)
    before = build_report_context(parser)["coverage"]["diagnostics"]
    findings = process_cisco_ios_conf(parser).values()
    assert not [item for item in findings if item.rule_id.endswith("unrestricted_sources")]
    assert before == build_report_context(parser)["coverage"]["diagnostics"] == parser.diagnostics
    assert len(before) == 2
    assert all(reason in note and "manual review is required" in note for note in before)
    assert any("SSH (VTY lines" in note for note in before)
    assert any("HTTPS (global listener)" in note for note in before)


@pytest.mark.parametrize("rule", ["permit any", "permit host 192.0.2.1"])
def test_resolved_acl_does_not_generate_incomplete_note(tmp_path, rule):
    assert parse(tmp_path, f"ip access-list standard MGMT\n {rule}\n").diagnostics == []


def test_inactive_removed_and_excluded_bindings_do_not_generate_notes(tmp_path):
    parser = parse(tmp_path, "", "no ip http secure-server\nline vty 0 4\n transport input none\n")
    assert parser.diagnostics == []
    parser = parse(tmp_path, "", "no ip http access-class\nline vty 0 4\n no access-class MGMT in\n")
    assert parser.diagnostics == []
    parser = parse(tmp_path, "")
    parser.set_assessment_context(AssessmentContext(excluded_categories=frozenset({"ssh", "http"})))
    assert parser.diagnostics == []


def test_partial_vty_override_and_independent_http_listeners(tmp_path):
    parser = parse(tmp_path, "", "ip http server\nline vty 2 4\n transport input none\n")
    notes = parser.diagnostics
    assert len(notes) == 3
    assert "VTY lines 0, 1" in notes[0] and "VTY lines 0, 1, 2" not in notes[0]
    assert any("HTTP (global listener)" in note for note in notes)
    assert any("HTTPS (global listener)" in note for note in notes)


@pytest.mark.parametrize("device", ["cisco-ios", "ios-xe"])
@pytest.mark.parametrize("format", ["HTML", "JSON"])
def test_unresolved_acl_public_coverage_is_sanitized(tmp_path, device, format):
    parser = parse(tmp_path, "", "ip http access-class ipv4 DoNotExposeThisIdentifier\n")
    notes = build_report_context(parser)["coverage"]["diagnostics"]
    assert all("DoNotExposeThisIdentifier" not in note for note in notes)
    output = tmp_path / ("coverage." + format.lower())
    assert main(["-d", device, "-i", parser.config_filepath, "-o", format, "-f", str(output)]) == 0
    report = output.read_text(encoding="utf-8")
    assert "Management ACL assessment incomplete" in report
    assert "Source restriction is unassessed" in report
    if format == "JSON":
        payload = json.loads(report)
        assert payload["coverage"]["diagnostics"] == notes
