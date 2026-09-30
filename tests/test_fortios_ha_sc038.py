"""SC-038: release-qualified heartbeat defaults and explicit exceptions."""

import pytest

from src.analyze.common.issue import FindingBasis
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser


RULE = "fortinet.fortios.ha.heartbeat_protection"


def _scan(tmp_path, version, body):
    path = tmp_path / "fortios.conf"
    header = (f"#config-version=FGT60F-{version}-FW-build1-240101:opmode=0:vdom=0:user=admin\n"
              if version else "")
    path.write_text(header + f"config system ha\n{body}end\n", encoding="utf-8")
    parser = FortiOSParser(str(path))
    findings = [item for item in process_fortios_conf(parser).values() if item.rule_id == RULE]
    return parser, findings


@pytest.mark.parametrize("version,body,basis", [
    ("7.4.2", "set mode a-p\n", FindingBasis.DOCUMENTED_DEFAULT),
    ("7.6.1", "set mode a-a\n", FindingBasis.DOCUMENTED_DEFAULT),
    ("6.4.15", "set mode a-p\n", FindingBasis.DOCUMENTED_DEFAULT),
    ("6.4.14", "set mode a-p\n", None),
    (None, "set mode a-p\n", None),
    ("7.4.2", "set mode standalone\n", None),
    (None, "set mode a-p\nset authentication disable\nset encryption enable\n",
     FindingBasis.EXPLICIT_VALUE),
    ("7.4.2", "set mode a-p\nset authentication enable\nset encryption enable\n", None),
    ("7.4.2", "set mode a-p\nset authentication unknown\nset encryption enable\n", None),
])
def test_ha_default_inference_is_release_qualified(tmp_path, version, body, basis):
    parser, findings = _scan(tmp_path, version, body)
    assert (findings[0].basis if findings else None) is basis
    assert bool(parser.get_ha_weak_heartbeats()) is (basis is not None)


def test_unknown_release_mixed_explicit_and_absent_only_reports_explicit(tmp_path):
    _, findings = _scan(tmp_path, None, "set mode a-a\nset authentication disable\n")
    assert len(findings) == 1
    assert findings[0].basis is FindingBasis.EXPLICIT_VALUE
    assert "authentication" in findings[0].observation
    assert "encryption" not in findings[0].observation
