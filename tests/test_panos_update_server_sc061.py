"""SC-061 (CIS PAN-OS 11 1.6.1): explicit disabled update-server identity verification."""

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis, Severity
from src.analyze.paloalto.plugins.panos_checks_plugin import PluginPANOSChecks
from src.devices.paloalto.panos import PaloAltoPANOSParser

RULE = "paloalto.panos.update.server_unverified"


def _scan(tmp_path, element):
    xml = ('<config version="11.1"><devices><entry name="localhost.localdomain"><deviceconfig><system>'
           '<hostname>fw</hostname>' + element + '</system></deviceconfig></entry></devices></config>')
    path = tmp_path / "panos.xml"
    path.write_text(xml, encoding="utf-8")
    plugin = PluginPANOSChecks()
    plugin.check_updates_and_system_logging(PaloAltoPANOSParser(str(path)))
    return [item for item in plugin.get_issues() if item.rule_id == RULE]


def test_explicit_no(tmp_path):
    findings = _scan(tmp_path, "<server-verification>no</server-verification>")
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH and findings[0].basis is FindingBasis.EXPLICIT_VALUE
    assert guidance_for(RULE)


@pytest.mark.parametrize("element", ["<server-verification>yes</server-verification>", ""])
def test_enabled_or_absent(tmp_path, element):
    assert not _scan(tmp_path, element)
