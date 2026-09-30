"""Release and explicit-value boundaries for FortiOS VPN and secret storage."""

import pytest

from src.analyze.common.issue import FindingBasis
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser


IKE_RULE = "fortinet.fortios.vpn.ike_aggressive_mode"
SECRET_RULE = "fortinet.fortios.credentials.private_data_storage"


def _scan(tmp_path, version, body, rule):
    source = tmp_path / "fortios.conf"
    header = (f"#config-version=FGT60F-{version}-FW-build0000:opmode=0:vdom=0:user=admin\n"
              if version else "")
    source.write_text(header + body, encoding="utf-8")
    parser = FortiOSParser(str(source))
    return [finding for finding in process_fortios_conf(parser).values()
            if finding.rule_id == rule]


@pytest.mark.parametrize("version,fields,expected_basis", [
    ("7.2.5", "", FindingBasis.DOCUMENTED_DEFAULT),
    ("6.4.15", "", FindingBasis.DOCUMENTED_DEFAULT),
    ("7.6.1", "", FindingBasis.DOCUMENTED_DEFAULT),
    ("6.4.14", "", None),
    ("6.0.0", "", None),
    (None, "", None),
    (None, "set ike-version 1\nset authmethod psk\n", FindingBasis.EXPLICIT_VALUE),
    (None, "set ike-version 1\n", None),
    ("7.2.5", "set ike-version 2\n", None),
    ("7.2.5", "set authmethod signature\n", None),
])
def test_aggressive_mode_defaults_are_release_qualified(
    tmp_path, version, fields, expected_basis
):
    body = ("config vpn ipsec phase1-interface\nedit branch\n"
            "set mode aggressive\nset psksecret ENC SYNTHETIC_SECRET\n"
            + fields + "next\nend\n")
    findings = _scan(tmp_path, version, body, IKE_RULE)
    assert bool(findings) is (expected_basis is not None)
    if findings:
        assert findings[0].basis is expected_basis
        assert "SYNTHETIC_SECRET" not in " ".join(findings[0].evidence)
        if expected_basis is FindingBasis.DOCUMENTED_DEFAULT:
            assert any("docs.fortinet.com" in source for source in findings[0].references)


@pytest.mark.parametrize("version,setting,expected_basis", [
    ("7.2.5", "", FindingBasis.DOCUMENTED_DEFAULT),
    ("6.4.10", "", FindingBasis.DOCUMENTED_DEFAULT),
    ("7.6.1", "", FindingBasis.DOCUMENTED_DEFAULT),
    ("6.4.9", "", None),
    ("6.0.0", "", None),
    (None, "", None),
    (None, "set private-data-encryption disable", FindingBasis.EXPLICIT_VALUE),
    ("6.0.0", "set private-data-encryption enable", None),
    ("7.2.5", "set private-data-encryption enable", None),
])
def test_private_data_default_requires_documented_release(
    tmp_path, version, setting, expected_basis
):
    body = (
        (f"config system global\n{setting}\nend\n" if setting else "")
        + "config vpn ipsec phase1-interface\nedit branch\n"
          "set psksecret ENC SYNTHETIC_SECRET\nnext\nend\n"
    )
    findings = _scan(tmp_path, version, body, SECRET_RULE)
    assert bool(findings) is (expected_basis is not None)
    if findings:
        assert findings[0].basis is expected_basis
        assert "SYNTHETIC_SECRET" not in " ".join(findings[0].evidence)
        if expected_basis is FindingBasis.DOCUMENTED_DEFAULT:
            assert any("docs.fortinet.com" in source for source in findings[0].references)
