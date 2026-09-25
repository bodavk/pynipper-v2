"""SC-016 time stage: BIG-IP NTP authentication (F5 K14120)."""

import pytest

from src.analyze.f5.core.process_bigip_conf import process_bigip_conf
from src.analyze.common.issue import FindingBasis
from src.devices.f5.bigip import F5BIGIPParser

BASE = "#TMSH-VERSION: 16.1.5\nsys global-settings {\n    hostname bigip1\n}\n"
RULE = "f5.bigip.ntp.unauthenticated_server"


def _run(tmp_path, ntp):
    path = tmp_path / "bigip.scf"
    path.write_text(BASE + ntp, encoding="utf-8")
    parser = F5BIGIPParser(str(path))
    return parser, [f for f in process_bigip_conf(parser).values() if f.rule_id.startswith("f5.bigip.ntp")]


def test_tmsh_servers_are_reported_as_unauthenticated(tmp_path):
    parser, findings = _run(tmp_path, "sys ntp {\n    servers { 192.0.2.1 time.example.test }\n}\n")
    assert [f.rule_id for f in findings] == [RULE, RULE]
    assert "tmsh/GUI" in findings[0].observation
    assert findings[0].basis is FindingBasis.EXPLICIT_VALUE
    assert findings[0].evidence_locations[0].line_number == 6


@pytest.mark.parametrize("include,expected", [
    ('"server 192.0.2.1 key 1 iburst\ntrustedkey 1"', []),
    ('"server 192.0.2.1 iburst"', ["has no key"]),
    ('"server 192.0.2.1 key 2 iburst\ntrustedkey 1"', ["key 2"]),
])
def test_include_servers_need_a_trusted_key(tmp_path, include, expected):
    _, findings = _run(tmp_path, f"sys ntp {{\n    include {include}\n}}\n")
    assert len(findings) == len(expected)
    for finding, text in zip(findings, expected):
        assert text in finding.observation


def test_missing_ntp_is_not_graded(tmp_path):
    parser, findings = _run(tmp_path, "")
    assert parser.get_ntp_servers() == () and findings == []


def test_provisioned_modules_are_read(tmp_path):
    parser, _ = _run(tmp_path, "sys provision ltm {\n    level nominal\n}\nsys provision asm {\n    level minimum\n}\n")
    assert parser.get_provisioned_modules() == {"ltm": "nominal", "asm": "minimum"}
