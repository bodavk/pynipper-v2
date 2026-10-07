"""Additive context pilots preserve offline detection and scoped source proof."""

import json
import socket
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from src.analyze.common.issue import Finding
from src.devices.common.evidence_context import bounded_context, context_statement
from src.devices.common.models import ConfigEvidence, EvidencePresentation
from src.devices.paloalto.panos import PaloAltoPANOSParser
from src.devices.checkpoint.fw1 import CheckPointFW1Parser
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.juniper.screenos import JuniperScreenOSParser
from src.main import main
from src.report.report import _generate_html_report


RULE = '''<entry name="ALLOW&lt;ALL&gt;">
<from><member>trust</member></from><to><member>untrust</member></to>
<source><member>any</member></source><destination><member>any</member></destination>
<application><member>any</member></application><service><member>any</member></service>
<action>allow</action><log-end>no</log-end>
<description>UNRELATED-SECRET</description><password>RULE-SECRET</password>
{attachment}</entry>'''


def panos(tmp_path, attachment="", profiles="", suffix="", inherited=False):
    path = tmp_path / "policy.xml"
    text = '<config version="11.2.3"><devices><entry name="device-A"><vsys><entry name="vsys1">'
    text += profiles + '<rulebase><security><rules>' + RULE.format(attachment=attachment)
    text += '</rules></security></rulebase></entry>' + suffix + '</vsys></entry></devices>'
    if inherited:
        text += '<template><entry name="unmerged"/></template>'
    path.write_text(text + '</config>', encoding="utf-8")
    return PaloAltoPANOSParser(str(path))


@pytest.mark.parametrize("output_type", ["HTML", "JSON"])
def test_panos_public_offline_rule_context(tmp_path, monkeypatch, output_type):
    parser = panos(tmp_path)
    def forbidden(*args, **kwargs):
        pytest.fail("Audit attempted networking")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    output = tmp_path / ("report." + output_type.lower())
    assert main(["-i", parser.config_filepath, "-d", "panos", "-o", output_type, "-f", str(output)]) == 0
    text = output.read_text(encoding="utf-8")
    assert "UNRELATED-SECRET" not in text and "RULE-SECRET" not in text
    if output_type == "JSON":
        finding = next(item for item in json.loads(text)["security-audit"].values()
                       if item["rule_id"] == "paloalto.panos.policy.broad_service")
        context = finding["evidence_locations"][0]["context"]
        assert any(item["text"] == "action: allow" and item["line"] == 5 for item in context["lines"])
        assert "device-A/vsys1/rulebase" in context["title"]
        assert any("not configured" in note for note in context["notes"])
        assert finding["evidence"] == ["device-A/vsys1/rulebase: security rule 1 ALLOW<ALL>"]
    else:
        assert "ALLOW&lt;ALL&gt;" in text and "ALLOW<ALL>" not in text
        assert "policy.xml:5" in text
        assert "decisive settings" in text
        assert '<details class="evidence-context">' in text
        assert '<details class="coverage-disclosure">' in text


def test_panos_profiles_scope_and_inheritance(tmp_path):
    attachment = '<profile-setting><group><member>GROUP</member></group></profile-setting>'
    profiles = '<profile-group><entry name="GROUP"><spyware><member>LOCAL</member></spyware><secret>HIDDEN</secret></entry></profile-group>'
    neighbor = '<entry name="vsys2"><profile-group><entry name="GROUP"><spyware><member>NEIGHBOR</member></spyware></entry></profile-group></entry>'
    parser = panos(tmp_path, attachment, profiles, neighbor)
    context = parser.get_security_rules()[0].evidence[0].context
    assert len(context.related) == 1
    assert "LOCAL" in repr(context) and "NEIGHBOR" not in repr(context) and "HIDDEN" not in repr(context)
    assert all(item.line_number for item in context.related[0].lines)
    parser = panos(tmp_path, attachment, profiles, neighbor, inherited=True)
    context = parser.get_security_rules()[0].evidence[0].context
    assert not context.related and any("inheritance" in note for note in context.notes)


def test_checkpoint_related_files_shadow_rules_and_field_locations(tmp_path):
    rules = '''(:layer (:rule-1 (:name (FIRST) :src (NET) :dst (any) :services (HTTPS) :action (accept) :track (None))
    :rule-2 (:name (LATER) :src (NET) :dst (any) :services (HTTPS) :action (drop) :install-on (GW))))'''
    objects = '''(:objects (:NET (:type (network) :ipaddr (192.0.2.0) :netmask (255.255.255.0) :secret (OBJECT-SECRET))
    :HTTPS (:type (tcp) :port (443)) :GW (:type (host) :ipaddr (192.0.2.1))))'''
    (tmp_path / "rules.C").write_text(rules, encoding="utf-8")
    (tmp_path / "objects.C").write_text(objects, encoding="utf-8")
    parser = CheckPointFW1Parser(str(tmp_path))
    first, second = parser.get_policy_rules()
    assert first.evidence[0].context.title != second.evidence[0].context.title
    assert any(":src (NET)" == item.text and item.line_number == 1 for item in first.evidence[0].context.lines)
    assert {Path(item.source).name for item in first.evidence[0].context.related[0].lines} == {"objects.C"}
    assert "192.0.2.0" in repr(first.evidence[0].context)
    assert "OBJECT-SECRET" not in repr(first.evidence[0].context)
    assert any("not configured" in note for note in second.evidence[0].context.notes)
    finding = Finding(rule_id="checkpoint.fw1.policy.shadowed_rule", device="CHECKPOINT_FW1",
        title="Shadow", observation="Observed", impact="Impact", recommendation="Fix",
        evidence=first.evidence + second.evidence)
    assert len(finding.evidence_contexts) >= 4
    data = finding.to_dict()
    assert data["evidence_locations"][0]["context"]["related-contexts"][0]["lines"][0]["source"] == "objects.C"


def test_ios_overlap_removal_and_selected_methods_no_secrets(tmp_path):
    path = tmp_path / "ios.conf"
    path.write_text('''version 15.2
aaa new-model
aaa authentication login SELECTED group TAC local
aaa authentication login UNUSED none
aaa group server tacacs+ TAC
 server-private 192.0.2.1 key SERVER-SECRET
ip access-list standard OLD
 permit any
ip access-list standard NEW
 permit 192.0.2.0 0.0.0.255
line vty 0 4
 transport input ssh
 access-class OLD in
 login authentication SELECTED
 password LINE-SECRET
line vty 2 4
 no access-class OLD in
 access-class NEW in
 no login authentication SELECTED
 login local
''', encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    evidence = parser.get_vty_evidence("line vty 0 4")
    context = evidence.context
    assert evidence.text == "line vty 0 4" and evidence.line_number == 11
    assert "LINE-SECRET" not in repr(context) and "SERVER-SECRET" not in repr(context)
    assert "UNUSED" not in repr(context)
    assert "Selected IPv4 management ACL: OLD" in repr(context)
    assert "Selected IPv4 management ACL: NEW" in repr(context)
    later = parser.get_vty_evidence("line vty 2 4").context
    assert not any("Selected AAA login_authentication" in related.title for related in later.related)
    assert "login kind: local" in repr(later)
    assert all(line.line_number is None for line in later.lines if line.presentation in {EvidencePresentation.DERIVED, EvidencePresentation.OMITTED})


def test_screenos_evidence_membership_preserves_semantic_gate(tmp_path):
    path = tmp_path / "screenos.conf"
    path.write_text('''set policy id 1 from "Trust" to "Untrust" "Any" "Any" "ANY" permit
set log session-init
set ike p1-proposal "LEGACY" preshare pre-g2 3des md5
set future-policy-predicate opaque
''', encoding="utf-8")
    parser = JuniperScreenOSParser(str(path))
    policy = next(iter(parser.policies.values()))
    assert all("ike" not in item.text and "opaque" not in item.text for item in policy.evidence)
    assert "ike" in policy.unsupported_predicates
    assert "future-policy-predicate" in policy.unsupported_predicates
    assert any("log session-init" in item.text for item in policy.evidence)


def test_context_bounds_and_annotations_are_additive():
    lines = [context_statement(f"support {n}", "rules.C", n + 1) for n in range(230)]
    lines.append(context_statement("action accept", "objects.C", 250, decisive=True))
    context = bounded_context("Selected", lines, notes=("Protection not configured.",))
    assert len(context.lines) == 200 and context.omitted_line_count == 31
    assert context.preview[0].text == "action accept"
    assert context_statement("x" * 2000, "rules.C", 5).presentation == EvidencePresentation.TRUNCATED
    derived = context_statement("effective login local", "ios.conf", presentation=EvidencePresentation.DERIVED)
    assert derived.line_number is None
    plain = ConfigEvidence("action accept", "objects.C", 250)
    assert replace(plain, decisive=True, presentation=EvidencePresentation.ORIGINAL) == plain
    many = bounded_context("Many decisive selectors", [context_statement(f"selector {n}", "config.conf", n + 1, decisive=True) for n in range(20)])
    assert len(many.preview) == 6 and many.preview_remaining_count == 14


def test_report_javascript_navigation_and_print_restoration():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is optional; report interaction harness requires a JavaScript runtime")
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([node, str(root / "tests/report_interactions.cjs"),
                             str(root / "src/report/templates/report.js")],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert "restoration passed" in result.stdout


@pytest.mark.parametrize("family,relative", [
    ("IOS_ROUTER", "cisco_ios/vulnerable.conf"),
    ("IOS_XE", "cisco_iosxe/vulnerable.conf"),
    ("CHECKPOINT_FW1", "checkpoint_fw1/vulnerable"),
])
@pytest.mark.parametrize("output_type", ["HTML", "JSON"])
def test_pilot_public_reports_remain_offline(tmp_path, monkeypatch, family, relative, output_type):
    root = Path(__file__).resolve().parent / "test_data/regression"
    def forbidden(*args, **kwargs):
        pytest.fail("Audit attempted networking")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    output = tmp_path / ("report." + output_type.lower())
    assert main(["-i", str(root / relative), "-d", family, "-o", output_type, "-f", str(output)]) == 0
    text = output.read_text(encoding="utf-8")
    if output_type == "JSON":
        locations = [location for item in json.loads(text)["security-audit"].values()
                     for location in item["evidence_locations"]]
        assert any("context" in location for location in locations)
    else:
        assert "Configuration context" in text or "VTY management binding" in text or "Policy:" in text
        assert '<details class="coverage-disclosure">' in text


def test_long_legacy_evidence_and_context_notes_stay_compact(tmp_path):
    context = bounded_context("Selected policy", [context_statement(f"setting {n}", "rules.C", n + 1)
                             for n in range(12)], notes=("Protection not configured — no source line.",))
    evidence = tuple(ConfigEvidence(f"evidence {n}", "rules.C", n + 1, context if n == 0 else None)
                     for n in range(12))
    finding = Finding(rule_id="checkpoint.fw1.policy.broad_accept", device="CHECKPOINT_FW1",
                      title="Selected", observation="Observed", impact="Impact", recommendation="Fix", evidence=evidence)
    output = tmp_path / "compact.html"
    _generate_html_report(str(output), {"one": finding}, [], {"device-type": "CHECKPOINT_FW1", "hostname": "test"})
    text = output.read_text(encoding="utf-8")
    assert '<details class="legacy-evidence">' in text
    assert '<details class="legacy-evidence" open' not in text
    assert text.index("Protection not configured") < text.index('<details class="evidence-context">')
    assert "rules.C:12" in text


def test_unrecognized_panos_attachment_never_exposes_credential_like_field(tmp_path):
    parser = panos(tmp_path, '<profile-setting><profiles><password><member>HIDDEN-CREDENTIAL</member></password></profiles></profile-setting>')
    context = parser.get_security_rules()[0].evidence[0].context
    assert "HIDDEN-CREDENTIAL" not in repr(context)
    assert any("withheld" in note for note in context.notes)


def test_panos_group_profiles_are_separate_ordered_contexts(tmp_path):
    profiles = '''<profile-group><entry name="GROUP"><spyware><member>LOCAL</member></spyware></entry></profile-group>
    <profiles><spyware><entry name="LOCAL"><rules><entry name="FIRST"><severity><member>critical</member></severity><action><alert/></action></entry>
    <entry name="SECOND"><action><reset-both/></action><password>PRIVATE</password></entry>
    <entry name="UNSUPPORTED"><action><password>SECRET-ACTION</password></action></entry></rules></entry></spyware></profiles>'''
    parser = panos(tmp_path, '<profile-setting><group><member>GROUP</member></group></profile-setting>', profiles)
    context = parser.get_security_rules()[0].evidence[0].context
    assert len(context.related) == 2
    profile = context.related[1]
    text = "\n".join(line.text for line in profile.lines)
    assert "profile rule FIRST" in text and "profile rule SECOND" in text
    assert text.index("alert") < text.index("reset-both")
    assert "PRIVATE" not in repr(context) and "SECRET-ACTION" not in repr(context)


def test_checkpoint_nested_unknown_fields_are_withheld_not_dumped(tmp_path):
    (tmp_path / "rules.C").write_text('(:rule-1 (:src (NET) :dst (any) :services (any) :action (accept)))', encoding="utf-8")
    (tmp_path / "objects.C").write_text('(:NET (:type (group) :members (:password (HIDDEN-MEMBER))))', encoding="utf-8")
    parser = CheckPointFW1Parser(str(tmp_path))
    context = parser.get_policy_rules()[0].evidence[0].context
    assert "HIDDEN-MEMBER" not in repr(context)
    assert any(line.presentation == EvidencePresentation.WITHHELD for item in context.related for line in item.lines)
