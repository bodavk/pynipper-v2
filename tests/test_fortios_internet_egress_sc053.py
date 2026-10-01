"""SC-053: bounded, role-qualified FortiOS Internet-bound risky ports."""

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


RULE = "fortinet.fortios.policy.risky_internet_egress"
INGRESS_RULE = "fortinet.fortios.policy.risky_untrusted_ingress"
HEADER = "#config-version=FGT60F-7.4.1-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"


def _interfaces(*, status="up", vdom=""):
    vdom_line = f'        set vdom "{vdom}"\n' if vdom else ""
    return ("config system interface\n"
            f'    edit "lan"\n{vdom_line}        set status {status}\n    next\n'
            f'    edit "wan1"\n{vdom_line}        set status {status}\n    next\nend\n')


def _policy(*, family="ipv4", service="TELNET", destination="all", extra=""):
    section = "firewall policy" if family == "ipv4" else "firewall policy6"
    source = "10.0.0.0/24" if family == "ipv4" else "2001:db8:1::/64"
    return (f'config {section}\n    edit 1\n'
            '        set srcintf "lan"\n        set dstintf "wan1"\n'
            f'        set srcaddr "{source}"\n        set dstaddr "{destination}"\n'
            f'        set service "{service}"\n        set schedule "always"\n'
            f'        set action accept\n{extra}    next\nend\n')


def _scan(tmp_path, body, roles=None, rule=RULE):
    source = tmp_path / "fortigate.conf"
    source.write_text(HEADER + body, encoding="utf-8")
    parser = FortiOSParser(str(source))
    parser.set_assessment_context(AssessmentContext.from_mapping({
        "interface_roles": roles or {},
    }))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = list(process_fortios_conf(parser).values())
    return [item for item in findings if item.rule_id == rule]


@pytest.mark.parametrize("family,destination", [("ipv4", "all"), ("ipv6", "all_ipv6")])
def test_risky_egress_requires_explicit_boundary(tmp_path, family, destination):
    findings = _scan(tmp_path, _interfaces() + _policy(family=family, destination=destination),
                     {"lan": "internal", "wan1": "external"})
    assert len(findings) == 1
    assert findings[0].basis == FindingBasis.EXPLICIT_VALUE
    assert "Telnet" in findings[0].observation
    assert "not proof of Internet reachability" in findings[0].observation
    assert guidance_for(RULE) is not None


@pytest.mark.parametrize("roles", [
    {}, {"lan": "internal"}, {"lan": "external", "wan1": "external"},
    {"lan": "internal", "wan1": "internal"},
])
def test_missing_or_wrong_boundary_roles_are_ungraded(tmp_path, roles):
    assert not _scan(tmp_path, _interfaces() + _policy(), roles)


@pytest.mark.parametrize("service,destination,extra", [
    ("HTTPS", "all", ""),
    ("ALL", "all", ""),
    ("TELNET", "10.0.0.0/24", ""),
    ("TELNET", "all", "        set status disable\n"),
    ("TELNET", "all", "        set action deny\n"),
    ("TELNET", "all", '        set groups "staff"\n'),
    ("TELNET", "all", "        set internet-service enable\n"),
])
def test_safe_or_unresolved_egress_is_not_reported(tmp_path, service, destination, extra):
    assert not _scan(tmp_path, _interfaces() + _policy(
        service=service, destination=destination, extra=extra
    ), {"lan": "internal", "wan1": "external"})


def test_configured_down_interface_is_not_an_active_boundary(tmp_path):
    assert not _scan(tmp_path, _interfaces(status="down") + _policy(),
                     {"lan": "internal", "wan1": "external"})


def test_later_policy_is_ungraded_until_first_match_is_resolved(tmp_path):
    prior = _policy().replace("edit 1", "edit 2").replace("set action accept", "set action deny")
    later = _policy().replace("edit 1", "edit 3")
    policies = prior.replace("end\n", "") + later.replace("config firewall policy\n", "")
    assert not _scan(tmp_path, _interfaces() + policies,
                     {"lan": "internal", "wan1": "external"})


def test_named_service_group_resolves_tcp_but_not_udp_telnet_port(tmp_path):
    objects = ('config firewall service custom\n'
               '    edit "TCP23"\n        set tcp-portrange 23\n    next\n'
               '    edit "UDP23"\n        set udp-portrange 23\n    next\nend\n'
               'config firewall service group\n    edit "EGRESS"\n'
               '        set member "TCP23"\n    next\nend\n')
    roles = {"lan": "internal", "wan1": "external"}
    assert len(_scan(tmp_path, _interfaces() + objects + _policy(service="EGRESS"), roles)) == 1
    assert not _scan(tmp_path, _interfaces() + objects + _policy(service="UDP23"), roles)


@pytest.mark.parametrize("family,destination", [("ipv4", "10.1.0.0/24"),
                                                 ("ipv6", "2001:db8:2::/64")])
def test_narrow_external_source_to_internal_risky_port(tmp_path, family, destination):
    findings = _scan(tmp_path, _interfaces() + _policy(family=family, destination=destination),
                     {"lan": "external", "wan1": "internal"}, INGRESS_RULE)
    assert len(findings) == 1
    assert findings[0].basis == FindingBasis.EXPLICIT_VALUE
    assert "Telnet" in findings[0].observation
    assert guidance_for(INGRESS_RULE) is not None


def test_ingress_requires_narrow_resolved_source_and_risky_service(tmp_path):
    roles = {"lan": "external", "wan1": "internal"}
    narrow_destination = "10.1.0.0/24"
    assert not _scan(tmp_path, _interfaces() + _policy(service="HTTPS", destination=narrow_destination),
                     roles, INGRESS_RULE)
    policy = _policy(destination=narrow_destination).replace('set srcaddr "10.0.0.0/24"',
                                                              'set srcaddr "all"')
    assert not _scan(tmp_path, _interfaces() + policy, roles, INGRESS_RULE)
    assert not _scan(tmp_path, _interfaces() + _policy(destination="UNKNOWN"),
                     roles, INGRESS_RULE)


def test_later_ingress_rule_is_not_claimed_first_match(tmp_path):
    first = _policy(destination="10.1.0.0/24").replace("edit 1", "edit 2")
    second = _policy(destination="10.1.0.0/24").replace("edit 1", "edit 3")
    policies = first.replace("end\n", "") + second.replace("config firewall policy\n", "")
    findings = _scan(tmp_path, _interfaces() + policies,
                     {"lan": "external", "wan1": "internal"}, INGRESS_RULE)
    assert len(findings) == 1
    assert "policy '2'" in findings[0].observation


def test_vdom_interface_binding_must_match_policy_scope(tmp_path):
    tenant = ('config vdom\n    edit "tenant"\n'
              + _policy().replace("config firewall policy", "        config firewall policy")
              + '    next\nend\n')
    findings = _scan(tmp_path, _interfaces(vdom="tenant") + tenant,
                     {"lan": "internal", "wan1": "external"})
    assert len(findings) == 1
    assert "scope 'tenant'" in findings[0].observation
    assert not _scan(tmp_path, _interfaces() + tenant,
                     {"lan": "internal", "wan1": "external"})


@pytest.mark.parametrize("output_type,suffix", [("JSON", "json"), ("HTML", "html")])
def test_public_cli_includes_bounded_finding(tmp_path, output_type, suffix):
    source = tmp_path / "fortigate.conf"
    source.write_text(HEADER + _interfaces() + _policy(), encoding="utf-8")
    assessment = tmp_path / "assessment.json"
    assessment.write_text(json.dumps({
        "policy_version": "sc053-test",
        "interface_roles": {"lan": "internal", "wan1": "external"},
    }), encoding="utf-8")
    report = tmp_path / f"report.{suffix}"
    with contextlib.redirect_stdout(io.StringIO()):
        assert main(["-d", "fortios", "-i", str(source), "-o", output_type, "-f", str(report),
                     "-x", "--assessment-policy", str(assessment)]) == 0
    assert RULE in report.read_text(encoding="utf-8")
