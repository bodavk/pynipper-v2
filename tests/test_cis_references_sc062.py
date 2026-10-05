"""SC-062: CIS recommendation numbers attached to rules that fully implement them."""

import contextlib
import io
import json
import pathlib
import re

import pytest

from src.analyze.common.cis_references import CIS_BENCHMARKS, CIS_RULE_REFERENCES, cis_references
from src.analyze.common.controls import control_coverage
from src.analyze.common.guidance import guidance_for
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.devices.juniper.junos import JunOSParser
from src.report.coverage import build_report_context
from src.report.report import generate_report


def test_references_are_numbers_for_known_rules_only():
    assert CIS_RULE_REFERENCES
    for rule_id, items in CIS_RULE_REFERENCES.items():
        assert guidance_for(rule_id) is not None, rule_id
        for key, number in items:
            assert key in CIS_BENCHMARKS
            assert re.fullmatch(r"\d+(\.\d+)*", number), (rule_id, number)


def test_no_cis_recommendation_text_is_stored():
    source = pathlib.Path("src/analyze/common/cis_references.py").read_text(encoding="utf-8")
    assert not re.search(r"\b(Ensure|Automated|Manual\))", source)


def test_verified_junos_and_check_point_mappings():
    assert "CIS Juniper OS Benchmark v2.1.0 5.6" in cis_references("juniper.junos.snmp.v3_security")
    assert "CIS Check Point Firewall Benchmark v1.1.0 3.2" in cis_references("checkpoint.fw1.layer.explicit_cleanup_missing")
    # Partial mappings (explicit weak SSH values only) carry no reference.
    assert cis_references("juniper.junos.ssh.weak_ciphers") == ()


def _junos(tmp_path, lines):
    path = tmp_path / "junos.conf"
    path.write_text("set version 22.4R1.10\nset system host-name r1\n" + lines, encoding="utf-8")
    return JunOSParser(str(path))


@pytest.mark.parametrize("auth,privacy,expected", [
    ("authentication-sha", "privacy-aes128", False),
    ("authentication-none", "privacy-aes128", True),
    ("authentication-sha", "privacy-3des", True),
    ("authentication-md5", "privacy-aes128", True),
    ("authentication-sha", "privacy-none", True),
])
def test_junos_snmpv3_user_algorithms(tmp_path, auth, privacy, expected):
    lines = (f'set snmp v3 usm local-engine user monitor {auth}'
             + (' authentication-password "$9$a"' if auth != "authentication-none" else "") + "\n"
             + f'set snmp v3 usm local-engine user monitor {privacy}'
             + (' privacy-password "$9$p"' if privacy != "privacy-none" else "") + "\n")
    plugin = PluginJunOSBaseline()
    plugin.check_snmp(_junos(tmp_path, lines))
    found = [item for item in plugin.get_issues() if item.rule_id == "juniper.junos.snmp.v3_security"]
    assert bool(found) is expected


def test_reports_and_controls_carry_cis_numbers(tmp_path):
    parser = _junos(tmp_path, 'set snmp v3 usm local-engine user monitor authentication-md5 authentication-password "$9$a"\n')
    plugin = PluginJunOSBaseline()
    plugin.check_snmp(parser)
    issues = {f"8.0.{index}. {item.title}": item for index, item in enumerate(plugin.get_issues())}
    data = {"hostname": "r1", "device-type": "JUNOS", **build_report_context(parser)}
    with contextlib.redirect_stdout(io.StringIO()):
        generate_report("JSON", str(tmp_path / "r.json"), issues, [], data)
        generate_report("HTML", str(tmp_path / "r.html"), issues, [], data)
    audit = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["security-audit"]
    record = next(item for item in audit.values() if item["rule_id"] == "juniper.junos.snmp.v3_security")
    assert "CIS Juniper OS Benchmark v2.1.0 5.7" in record["cis-references"]
    assert "CIS benchmark:" in (tmp_path / "r.html").read_text(encoding="utf-8")
    controls = control_coverage(parser)
    assert all("cis-references" in item for item in controls["results"])
