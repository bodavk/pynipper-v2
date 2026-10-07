"""Finding context is scoped parser evidence, never an arbitrary raw-file dump."""

import json
import socket
from html import unescape

import pytest

from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.analyze.common.issue import Finding
from src.devices.common.models import ConfigEvidence, EvidenceContext
from src.devices.fortinet.fortios import FortiOSParser
from src.main import main


HEADER = "#config-version=FGT100F-7.4.6-FW-build0001-240101:opmode=0:vdom=0:user=admin\n"
ADMIN = '''config system admin
edit "fgadmin"
set accprofile "super_admin"
set password ENC CLIENT-SECRET
set two-factor disable
next
edit "neighbor"
set accprofile "super_admin"
set password ENC NEIGHBOR-SECRET
set trusthost1 192.0.2.42 255.255.255.255
next
end
'''
POLICY = '''config firewall policy
edit 618
set name "ALLOW-ALL"
set srcintf "lan"
set dstintf "wan"
set srcaddr "all"
set dstaddr "all"
set schedule "always"
set service "ALL"
set action accept
set logtraffic disable
next
end
'''


def _parser(tmp_path, text):
    source = tmp_path / "context.conf"
    source.write_text(HEADER + text, encoding="utf-8")
    return FortiOSParser(str(source))


def _finding(parser, rule, name):
    return next(
        finding for finding in process_fortios_conf(parser).values()
        if finding.rule_id == rule and name in finding.observation
    )


def test_admin_context_proves_role_and_missing_trusted_hosts_without_neighbor_secrets(tmp_path):
    parser = _parser(tmp_path, ADMIN)
    finding = _finding(parser, "fortinet.fortios.admin.trusted_hosts", "fgadmin")
    assert finding.evidence == ('edit "fgadmin"',)
    assert len(finding.evidence_contexts) == 1
    context = finding.evidence_contexts[0]
    assert [line.text for line in context.lines] == [
        "config system admin", 'edit "fgadmin"', 'set accprofile "super_admin"',
        "set two-factor disable",
    ]
    assert any("IPv4 trusted-host settings are not configured" in note for note in context.notes)
    assert any("IPv6 trusted-host settings are not configured" in note for note in context.notes)
    serialized = json.dumps(finding.to_dict())
    assert "CLIENT-SECRET" not in serialized
    assert "NEIGHBOR-SECRET" not in serialized
    assert not any('edit "neighbor"' in line.text for line in context.lines)
    assert "192.0.2.42" not in serialized
    assert finding.to_dict()["evidence_locations"][0]["context"]["lines"][2]["line"] == 4


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_offline_cli_policy_context_contains_rule_and_long_excerpts_are_collapsed(tmp_path, monkeypatch, output_type):
    parser = _parser(tmp_path, ADMIN + POLICY)

    def prohibit_network(*args, **kwargs):
        pytest.fail("Report evidence must remain offline")

    monkeypatch.setattr(socket.socket, "connect", prohibit_network)
    monkeypatch.setattr(socket, "getaddrinfo", prohibit_network)
    output = tmp_path / f"context-report.{output_type.lower()}"
    assert main(["-i", parser.config_filepath, "-f", str(output), "-o", output_type]) == 0
    text = output.read_text(encoding="utf-8")
    assert "CLIENT-SECRET" not in text
    assert "NEIGHBOR-SECRET" not in text
    if output_type == "JSON":
        payload = json.loads(text)
        policy = next(item for item in payload["security-audit"].values()
                      if item["rule_id"] == "fortinet.fortios.policy.broad_accept")
        context = policy["evidence_locations"][0]["context"]
        lines = [item["text"] for item in context["lines"]]
        assert "edit 618" in lines
        assert 'set srcintf "lan"' in lines
        assert 'set dstintf "wan"' in lines
        assert 'set srcaddr "all"' in lines
        assert 'set dstaddr "all"' in lines
        assert 'set service "ALL"' in lines
        assert "set action accept" in lines
        assert "set logtraffic disable" in lines
        assert all(item["source"] == "context.conf" for item in context["lines"])
    else:
        assert '<details class="evidence-context">' in text
        assert '<details class="evidence-context" open' not in text
        assert "statements; expand to inspect" in text
        assert 'set srcaddr "all"' in unescape(text)
        assert 'set dstaddr "all"' in unescape(text)
        assert 'set service "ALL"' in unescape(text)
        assert "set action accept" in text
        assert "set logtraffic disable" in text
        assert '<h4>Configuration context: system admin / fgadmin</h4>' in text


def test_context_handles_ordered_override_unset_delete_and_recreation(tmp_path):
    parser = _parser(tmp_path, '''config system admin
edit fgadmin
set accprofile super_admin
set trusthost1 0.0.0.0 0.0.0.0
set trusthost1 192.0.2.0 255.255.255.0
unset trusthost1
next
delete fgadmin
edit fgadmin
set accprofile super_admin
set two-factor disable
next
end
''')
    context = parser.field_evidence(("system admin", "fgadmin"))[0].context
    text = "\n".join(line.text for line in context.lines)
    assert "192.0.2.0" not in text
    assert "0.0.0.0" not in text
    assert any("IPv4 trusted-host settings are not configured" in note for note in context.notes)


def test_context_never_crosses_vdoms_or_exposes_unknown_fields_and_multiline_keys(tmp_path):
    parser = _parser(tmp_path, '''config vdom
edit A
config system admin
edit fgadmin
set accprofile super_admin
set private-key "PRIVATE-BEGIN
PRIVATE-CONTINUATION"
set future-token DO-NOT-EXPOSE
next
end
next
edit B
config system admin
edit fgadmin
set accprofile super_admin
set trusthost1 203.0.113.99 255.255.255.255
next
end
next
end
''')
    context = parser.field_evidence(("vdom", "A", "system admin", "fgadmin"))[0].context
    text = repr(context)
    assert "PRIVATE-BEGIN" not in text
    assert "PRIVATE-CONTINUATION" not in text
    assert "DO-NOT-EXPOSE" not in text
    assert "203.0.113.99" not in text
    assert "vdom / A / system admin / fgadmin" in context.title
    section_context = parser.field_evidence(("vdom", "B", "system admin"))[0].context
    assert not any("trusted-host settings are not configured" in note for note in section_context.notes)


def test_append_context_distinguishes_source_statement_from_derived_effective_value(tmp_path):
    parser = _parser(tmp_path, POLICY.replace('set srcaddr "all"', 'set srcaddr "all"\nappend srcaddr EXTRA'))
    context = parser.field_evidence(("firewall policy", "618"))[0].context
    assert any(line.text == "append srcaddr EXTRA" and line.line_number for line in context.lines)
    assert any(line.text == "Effective srcaddr: all EXTRA" and line.line_number is None for line in context.lines)


def test_large_context_is_bounded_and_keeps_the_cited_field(tmp_path):
    fields = "".join(f"set opaque-{number} UNKNOWN-SECRET-{number}\n" for number in range(230))
    parser = _parser(tmp_path, f"config system global\n{fields}set admintimeout 0\nend\n")
    context = parser.field_evidence(("system global", "admintimeout"))[0].context
    assert len(context.lines) == 200
    assert context.omitted_line_count == 32
    assert context.lines[-1].text == "set admintimeout 0"
    assert "UNKNOWN-SECRET" not in repr(context)


def test_common_context_is_additive_and_deduplicated_without_changing_evidence_identity():
    line = ConfigEvidence("set action accept", "config.conf", 12)
    context = EvidenceContext("Policy settings", (line,))
    finding = Finding(
        rule_id="test.policy.example", device="FORTIOS", title="Example",
        observation="Observation", impact="Impact", recommendation="Fix",
        evidence=(ConfigEvidence("edit 618", "config.conf", 5, context),
                  ConfigEvidence("set action accept", "config.conf", 12, context)),
    )
    assert finding.evidence == ("edit 618", "set action accept")
    assert finding.evidence_contexts == (context,)
    assert finding.to_dict()["evidence_locations"][0]["context"]["lines"][0]["line"] == 12
