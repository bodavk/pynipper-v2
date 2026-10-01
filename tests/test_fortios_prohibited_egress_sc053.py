"""SC-053: optional exact outbound-port assessment policy."""

import contextlib
import io
import json

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.common.assessment import AssessmentContext
from src.devices.fortinet.fortios import FortiOSParser
from src.main import main


RULE = "fortinet.fortios.policy.prohibited_egress_port"
HEADER = "#config-version=FGT60F-7.4.1-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
INTERFACES = ('config system interface\n'
              '    edit "lan"\n        set status up\n    next\n'
              '    edit "wan1"\n        set status up\n    next\nend\n')


def _policy(service="HTTPS", destination="198.51.100.0/24", extra=""):
    return ('config firewall policy\n    edit 1\n'
            '        set srcintf "lan"\n        set dstintf "wan1"\n'
            '        set srcaddr "10.0.0.0/24"\n'
            f'        set dstaddr "{destination}"\n'
            f'        set service "{service}"\n        set schedule "always"\n'
            f'        set action accept\n{extra}    next\nend\n')


def _scan(tmp_path, ports=(), *, service="HTTPS", destination="198.51.100.0/24", extra="",
          body=None, roles=None):
    source = tmp_path / "fortigate.conf"
    source.write_text(HEADER + INTERFACES + (body or _policy(service, destination, extra)),
                      encoding="utf-8")
    parser = FortiOSParser(str(source))
    parser.set_assessment_context(AssessmentContext.from_mapping({
        "policy_version": "egress-v1",
        "interface_roles": roles if roles is not None else {"lan": "internal", "wan1": "external"},
        "fortios_prohibited_egress_ports": list(ports),
    }))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = list(process_fortios_conf(parser).values())
    return findings


@pytest.mark.parametrize("value", [
    "tcp/0", "tcp/65536", "tcp/00023", "TCP/23", "sctp/23", "23", "udp/-1",
])
def test_invalid_port_declarations_fail_closed(value):
    with pytest.raises(ValueError, match="fortios_prohibited_egress_ports"):
        AssessmentContext.from_mapping({"fortios_prohibited_egress_ports": [value]})


def test_duplicate_or_non_string_port_declarations_fail_closed():
    for values in (["tcp/23", "tcp/23"], [23], "tcp/23"):
        with pytest.raises(ValueError, match="fortios_prohibited_egress_ports"):
            AssessmentContext.from_mapping({"fortios_prohibited_egress_ports": values})


def test_explicit_https_prohibition_is_reported_only_when_supplied(tmp_path):
    assert not any(item.rule_id == RULE for item in _scan(tmp_path))
    findings = [item for item in _scan(tmp_path, ("tcp/443",)) if item.rule_id == RULE]
    assert len(findings) == 1
    assert findings[0].basis == FindingBasis.EXPLICIT_VALUE
    assert "tcp/443" in findings[0].observation
    assert "egress-v1" in findings[0].observation
    assert guidance_for(RULE) is not None


def test_protocol_identity_and_unrelated_port_are_respected(tmp_path):
    assert not any(item.rule_id == RULE for item in _scan(tmp_path, ("udp/443",)))
    assert not any(item.rule_id == RULE for item in _scan(tmp_path, ("tcp/8443",)))


def test_all_service_matches_opt_in_port_even_with_narrow_destination(tmp_path):
    findings = [item for item in _scan(tmp_path, ("udp/69",), service="ALL")
                if item.rule_id == RULE]
    assert len(findings) == 1
    assert "udp/69" in findings[0].observation


def test_explicit_prohibition_replaces_duplicate_generic_egress_finding(tmp_path):
    findings = _scan(tmp_path, ("tcp/23",), service="TELNET", destination="all")
    ids = [item.rule_id for item in findings]
    assert ids.count(RULE) == 1
    assert "fortinet.fortios.policy.risky_internet_egress" not in ids


def test_other_risky_ports_still_get_generic_egress_finding(tmp_path):
    body = _policy(service="TELNET", destination="all").replace(
        'set service "TELNET"', 'set service "TELNET" "FTP"')
    findings = _scan(tmp_path, ("tcp/23",), body=body)
    ids = [item.rule_id for item in findings]
    assert RULE in ids
    assert "fortinet.fortios.policy.risky_internet_egress" in ids


def test_overlapping_prior_policy_keeps_later_permission_ungraded(tmp_path):
    first = _policy().replace("edit 1", "edit 2")
    later = _policy().replace("edit 1", "edit 3")
    body = first.replace("end\n", "") + later.replace("config firewall policy\n", "")
    findings = [item for item in _scan(tmp_path, ("tcp/443",), body=body)
                if item.rule_id == RULE]
    assert len(findings) == 1
    assert "policy '2'" in findings[0].observation


def test_disjoint_prior_policy_allows_later_permission_finding(tmp_path):
    first = _policy(service="TELNET").replace("edit 1", "edit 2")
    later = _policy().replace("edit 1", "edit 3")
    body = first.replace("end\n", "") + later.replace("config firewall policy\n", "")
    findings = [item for item in _scan(tmp_path, ("tcp/443",), body=body)
                if item.rule_id == RULE]
    assert len(findings) == 1
    assert "policy '3'" in findings[0].observation


def test_missing_roles_or_unresolved_destination_prevents_finding(tmp_path):
    assert not any(item.rule_id == RULE for item in _scan(
        tmp_path, ("tcp/443",), roles={"lan": "internal"}))
    assert not any(item.rule_id == RULE for item in _scan(
        tmp_path, ("tcp/443",), destination="MISSING-OBJECT"))


@pytest.mark.parametrize("extra", [
    '        set users "staff"\n',
    '        set status disable\n',
    '        set dstaddr-negate enable\n',
])
def test_unproven_or_inactive_policy_is_not_a_policy_violation(tmp_path, extra):
    assert not any(item.rule_id == RULE for item in _scan(tmp_path, ("tcp/443",), extra=extra))


def test_public_json_report_records_declared_port_and_finding(tmp_path):
    source = tmp_path / "fortigate.conf"
    source.write_text(HEADER + INTERFACES + _policy(), encoding="utf-8")
    assessment = tmp_path / "assessment.json"
    assessment.write_text(json.dumps({
        "policy_version": "egress-v1",
        "interface_roles": {"lan": "internal", "wan1": "external"},
        "fortios_prohibited_egress_ports": ["tcp/443"],
    }), encoding="utf-8")
    report = tmp_path / "report.json"
    with contextlib.redirect_stdout(io.StringIO()):
        assert main(["-d", "fortios", "-i", str(source), "-o", "JSON", "-f", str(report),
                     "-x", "--assessment-policy", str(assessment)]) == 0
    payload = report.read_text(encoding="utf-8")
    assert RULE in payload
    assert '"fortios-prohibited-egress-ports"' in payload
