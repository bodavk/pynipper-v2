"""Sanitized reproductions of unresolved PAN-OS and FortiOS templates (RV-009)."""

import json
import subprocess
import sys

import pytest

from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.analyze.paloalto.core.process_panos_conf import process_panos_conf
from src.devices.fortinet.fortios import FortiOSParser
from src.devices.paloalto.panos import PaloAltoPANOSParser
from src.report.coverage import build_report_context


PAN_TEMPLATE = """<config><devices><entry name="device"><deviceconfig><system>
<hostname>{{ hostname }}</hostname>
<update-schedule><threats><recurring><daily><action>download-only</action></daily></recurring></threats></update-schedule>
</system></deviceconfig></entry></devices></config>"""

FORTI_TEMPLATE = """#config-version=FGT60F-7.2.8-FW-build1639-240313:opmode=0:vdom=0:user=admin
config system global
set hostname <###PLACEHOLDER_DEVICE_NAME###>
end
config system interface
edit wan1
set allowaccess http ping
next
end
config system ntp
set ntpsync enable
set type custom
config ntpserver
edit 1
set server 192.0.2.123
set authentication disable
end
end
"""


@pytest.mark.parametrize("device,content,expected", [
    ("PAN_OS", PAN_TEMPLATE, "paloalto.panos.updates.threat_content"),
    ("FORTIOS", FORTI_TEMPLATE, "fortinet.fortios.management.insecure_protocol"),
])
@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_report_preserves_explicit_choices_but_discloses_incomplete_scope(
    tmp_path, device, content, expected, output_type,
):
    config = tmp_path / ("template.xml" if device == "PAN_OS" else "template.conf")
    config.write_text(content, encoding="utf-8")
    output = tmp_path / ("report." + output_type.lower())
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", device, "-i", str(config),
         "-o", output_type, "-f", str(output), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = output.read_text(encoding="utf-8")
    assert "Unresolved deployment substitutions" in report or "unrendered-template" in report
    assert "No NTP servers are configured" not in report
    if output_type == "JSON":
        data = json.loads(report)
        assert data["coverage"]["input-completeness"] == "unrendered-template"
        assert data["coverage"]["suppressed-finding-count"] > 0
        assert data["configuration-inventory"] == {}
        assert expected in {issue["rule_id"] for issue in data["security-audit"].values()}
        assert all(field["knowledge-state"] != "known" for field in data["coverage"]["fields"])


@pytest.mark.parametrize("device,content", [
    ("PAN_OS", '<config><!-- {{ unresolved }} --><devices><entry/></devices></config>'),
    ("FORTIOS", '# {{ unresolved }}\nconfig system global\nset hostname rendered\nend\n'),
])
def test_comment_only_marker_does_not_downgrade_complete_input(tmp_path, device, content):
    path = tmp_path / ("complete.xml" if device == "PAN_OS" else "complete.conf")
    path.write_text(content, encoding="utf-8")
    parser = PaloAltoPANOSParser(str(path)) if device == "PAN_OS" else FortiOSParser(str(path))
    assert not parser.template_unresolved
    assert "input-completeness" not in build_report_context(parser)["coverage"]


def test_template_filter_preserves_only_explicit_fortios_findings(tmp_path):
    path = tmp_path / "firewall.conf"
    path.write_text(FORTI_TEMPLATE, encoding="utf-8")
    parser = FortiOSParser(str(path))
    rules = {finding.rule_id for finding in process_fortios_conf(parser).values()}
    assert "fortinet.fortios.management.insecure_protocol" in rules
    assert "fortinet.fortios.ntp.authentication" in rules
    assert "fortinet.fortios.logging.missing" not in rules
    assert "fortinet.fortios.admin.mfa" not in rules


def test_template_without_threat_schedule_does_not_infer_absence(tmp_path):
    path = tmp_path / "template.xml"
    path.write_text(PAN_TEMPLATE.replace(
        "<update-schedule><threats><recurring><daily><action>download-only</action></daily></recurring></threats></update-schedule>",
        "",
    ), encoding="utf-8")
    parser = PaloAltoPANOSParser(str(path))
    rules = {finding.rule_id for finding in process_panos_conf(parser).values()}
    assert "paloalto.panos.updates.threat_content" not in rules
    assert "paloalto.panos.logging.system_forwarding" not in rules
