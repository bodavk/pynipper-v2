"""SC-046: keep IOS-XE WebUI ACL bindings separate by listener family."""

import contextlib
import io
import json

import pytest

from src.common.assessment import AssessmentContext
from src.devices.cisco.ios import CiscoIOSParser
from src.main import main


INTERFACE = ('interface Vlan10\n'
             ' ipv6 address 2001:db8:10::1/64\n no shutdown\n!\n')
WEB = ('ip http secure-server\n'
       'ip http access-class ipv4 WEB4\n'
       'ip access-list standard WEB4\n permit host 192.0.2.10\n!\n')


def _parser(tmp_path, *, version="17.9", interface=INTERFACE, web=WEB):
    source = tmp_path / "ios-xe.conf"
    source.write_text(f"version {version}\n" + interface + web, encoding="utf-8")
    parser = CiscoIOSParser(str(source))
    parser.device_type = "IOS_XE"
    return parser


def test_ipv4_web_acl_does_not_establish_ipv6_source_restriction(tmp_path):
    parser = _parser(tmp_path)
    assert parser.has_qualified_ipv6_web_listener()
    notes = parser.diagnostics
    assert len(notes) == 1
    assert "HTTPS (global IPv6 listener)" in notes[0]
    assert "IPv4 ACL does not establish IPv6 source restriction" in notes[0]
    assert "2001:db8" not in notes[0] and "WEB4" not in notes[0]


def test_explicit_ipv6_acl_is_independent_in_normalized_inventory(tmp_path):
    parser = _parser(tmp_path, web=WEB + 'ip http access-class ipv6 WEB6\n'
                     'ipv6 access-list WEB6\n permit ipv6 2001:db8:20::/64 any\n')
    assert not parser.diagnostics
    web = [item for item in parser.get_normalized_config().management_services.items
           if item.protocol == "https"]
    assert len(web) == 1
    assert web[0].permitted_sources == ("ipv4-acl:WEB4", "ipv6-acl:WEB6")


@pytest.mark.parametrize("version,interface,web", [
    ("16.12", INTERFACE, WEB),
    ("?", INTERFACE, WEB),
    ("17.9", 'interface Vlan10\n ipv6 address 2001:db8:10::1/64\n shutdown\n', WEB),
    ("17.9", 'interface Vlan10\n ipv6 address fe80::1/64\n no shutdown\n', WEB),
    ("17.9", '', WEB),
    ("17.9", INTERFACE, WEB.replace('ip http secure-server', 'no ip http secure-server')),
])
def test_unqualified_or_inactive_ipv6_web_listener_has_no_note(
    tmp_path, version, interface, web,
):
    parser = _parser(tmp_path, version=version, interface=interface, web=web)
    assert not parser.has_qualified_ipv6_web_listener()
    assert not any("global IPv6 listener" in note for note in parser.diagnostics)


def test_excluded_http_category_suppresses_ipv6_coverage_note(tmp_path):
    parser = _parser(tmp_path)
    parser.set_assessment_context(AssessmentContext(excluded_categories=frozenset({"http"})))
    assert not any("global IPv6 listener" in note for note in parser.diagnostics)


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_report_contains_sanitized_manual_review_note(tmp_path, output_type):
    parser = _parser(tmp_path)
    report = tmp_path / f"report.{output_type.lower()}"
    with contextlib.redirect_stdout(io.StringIO()):
        assert main(["-d", "ios-xe", "-i", parser.config_filepath,
                     "-o", output_type, "-f", str(report)]) == 0
    rendered = report.read_text(encoding="utf-8")
    assert "global IPv6 listener" in rendered
    assert "2001:db8:10" not in rendered and "WEB4" not in rendered
    if output_type == "JSON":
        assert any("global IPv6 listener" in note
                   for note in json.loads(rendered)["coverage"]["diagnostics"])
