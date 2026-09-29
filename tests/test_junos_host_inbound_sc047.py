"""SC-047: SRX host-inbound admission of enabled management services."""

import json

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis, Severity
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.common.assessment import AssessmentContext
from src.devices.juniper.junos import JunOSParser
from src.main import main

RULE = "juniper.junos.host_inbound.management_exposed"
SERVICES = ("set system services ssh\n"
            "set system services telnet\n"
            "set system services web-management https interface ge-0/0/0.0\n"
            "set snmp community S3cretCommunity authorization read-only\n")
ZONE = "set security zones security-zone untrust interfaces ge-0/0/0.0\n"


def _parser(tmp_path, body, *, model="SRX345", roles=None):
    source = tmp_path / "srx.conf"
    source.write_text(f"## Model: {model}\nset version 22.4R1.10\nset system host-name fw1\n{body}", encoding="utf-8")
    parser = JunOSParser(str(source))
    parser.set_assessment_context(AssessmentContext.from_mapping({
        "interface_roles": roles if roles is not None else {"ge-0/0/0": "external"}
    }))
    return parser


def _findings(parser):
    plugin = PluginJunOSBaseline()
    plugin.check_host_inbound(parser)
    return [item for item in plugin.get_issues() if item.rule_id == RULE]


def _services(finding):
    return set(finding.observation.split("admits the enabled service(s) ")[1].split(" to the device")[0].split(", "))


def test_narrow_list_reports_only_enabled_admitted_services(tmp_path):
    body = SERVICES + ZONE + (
        "set security zones security-zone untrust host-inbound-traffic system-services ssh\n"
        "set security zones security-zone untrust host-inbound-traffic system-services ike\n"
        "set security zones security-zone untrust host-inbound-traffic system-services http\n")  # http not enabled
    findings = _findings(_parser(tmp_path, body))
    assert len(findings) == 1
    assert _services(findings[0]) == {"ssh"}
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].basis is FindingBasis.EXPLICIT_VALUE
    assert guidance_for(RULE) is not None


def test_all_with_exceptions(tmp_path):
    body = SERVICES + ZONE + (
        "set security zones security-zone untrust host-inbound-traffic system-services all\n"
        "set security zones security-zone untrust host-inbound-traffic system-services telnet except\n")
    findings = _findings(_parser(tmp_path, body))
    assert _services(findings[0]) == {"ssh", "https", "snmp"}
    assert findings[0].severity is Severity.HIGH
    assert "except telnet" in findings[0].observation
    assert "S3cretCommunity" not in " ".join(map(str, findings[0].evidence))


def test_any_service_includes_cleartext(tmp_path):
    body = SERVICES + ZONE + "set security zones security-zone untrust host-inbound-traffic system-services any-service\n"
    finding = _findings(_parser(tmp_path, body))[0]
    assert "telnet" in _services(finding) and "'any-service'" in finding.observation


def test_interface_list_overrides_zone(tmp_path):
    body = SERVICES + ZONE + (
        "set security zones security-zone untrust host-inbound-traffic system-services all\n"
        "set security zones security-zone untrust interfaces ge-0/0/0.0 host-inbound-traffic system-services ike\n")
    assert _findings(_parser(tmp_path, body)) == []
    narrowed = body.replace("system-services ike", "system-services ssh")
    assert _services(_findings(_parser(tmp_path, narrowed))[0]) == {"ssh"}


def test_interface_protocols_only_keeps_precedence_unknown(tmp_path):
    body = SERVICES + ZONE + (
        "set security zones security-zone untrust host-inbound-traffic system-services all\n"
        "set security zones security-zone untrust interfaces ge-0/0/0.0 host-inbound-traffic protocols bgp\n")
    parser = _parser(tmp_path, body)
    assert parser.get_host_inbound_admissions()[0].source == "unknown"
    assert _findings(parser) == []


@pytest.mark.parametrize("extra", [
    "set interfaces lo0 unit 0 family inet filter input PROTECT-RE\n"
    "set firewall family inet filter PROTECT-RE term a from source-address 198.51.100.0/24\n"
    "set firewall family inet filter PROTECT-RE term a then accept\n",
    "set interfaces ge-0/0/0 unit 0 family inet filter input EDGE-IN\n",
])
def test_input_filters_leave_exposure_unknown(tmp_path, extra):
    body = SERVICES + ZONE + "set security zones security-zone untrust host-inbound-traffic system-services all\n" + extra
    assert _findings(_parser(tmp_path, body)) == []


@pytest.mark.parametrize("roles,model", [
    ({"ge-0/0/0": "internal"}, "SRX345"),
    ({}, "SRX345"),
    ({"ge-0/0/0": "external"}, "EX4300-48T"),
])
def test_role_and_platform_gates(tmp_path, roles, model):
    body = SERVICES + ZONE + "set security zones security-zone untrust host-inbound-traffic system-services all\n"
    assert _findings(_parser(tmp_path, body, roles=roles, model=model)) == []


def test_default_zone_admits_nothing_and_disabled_services_are_ignored(tmp_path):
    assert _findings(_parser(tmp_path, SERVICES + ZONE)) == []
    body = ZONE + "set security zones security-zone untrust host-inbound-traffic system-services all\n"
    assert _findings(_parser(tmp_path, body)) == []  # nothing enabled


def test_web_management_interface_restriction(tmp_path):
    body = ("set system services web-management https interface ge-0/0/1.0\n" + ZONE +
            "set security zones security-zone untrust host-inbound-traffic system-services https\n")
    assert _findings(_parser(tmp_path, body)) == []


def test_deactivated_and_deleted_statements(tmp_path):
    body = SERVICES + ZONE + (
        "set security zones security-zone untrust host-inbound-traffic system-services all\n"
        "deactivate security zones security-zone untrust host-inbound-traffic system-services all\n")
    assert _findings(_parser(tmp_path, body)) == []
    deleted = SERVICES + ZONE + (
        "set security zones security-zone untrust host-inbound-traffic system-services ssh\n"
        "delete system services ssh\n")
    assert _findings(_parser(tmp_path, deleted)) == []


def test_apply_groups_are_not_guessed(tmp_path):
    body = SERVICES + ZONE + (
        "set security zones security-zone untrust apply-groups EDGE\n"
        "set security zones security-zone untrust host-inbound-traffic system-services all\n")
    assert _findings(_parser(tmp_path, body)) == []


def test_management_functional_zone(tmp_path):
    body = SERVICES + (
        "set security zones functional-zone management interfaces ge-0/0/0.0\n"
        "set security zones functional-zone management host-inbound-traffic system-services ssh\n")
    finding = _findings(_parser(tmp_path, body))[0]
    assert "management (functional zone)" in finding.observation


def test_hierarchical_format(tmp_path):
    source = tmp_path / "srx-h.conf"
    source.write_text("""## Model: SRX345
version 22.4R1.10;
system {
    host-name fw1;
    services {
        ssh;
    }
}
security {
    zones {
        security-zone untrust {
            host-inbound-traffic {
                system-services {
                    all;
                }
            }
            interfaces {
                ge-0/0/0.0;
            }
        }
    }
}
""", encoding="utf-8")
    parser = JunOSParser(str(source))
    parser.set_assessment_context(AssessmentContext.from_mapping({"interface_roles": {"ge-0/0/0": "external"}}))
    assert _services(_findings(parser)[0]) == {"ssh"}


def test_public_pipeline_json(tmp_path):
    config = tmp_path / "srx.conf"
    config.write_text("## Model: SRX345\nset version 22.4R1.10\nset system host-name fw1\n" + SERVICES + ZONE +
                      "set security zones security-zone untrust host-inbound-traffic system-services all\n",
                      encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"interface_roles": {"ge-0/0/0": "external"}}), encoding="utf-8")
    report = tmp_path / "report.json"
    assert main(["-d", "JUNOS", "-i", str(config), "-o", "JSON", "-f", str(report), "-x",
                 "--assessment-policy", str(policy)]) == 0
    text = report.read_text(encoding="utf-8")
    assert RULE in text and "S3cretCommunity" not in text


def test_accept_all_input_filter_does_not_restrict(tmp_path):
    body = SERVICES + ZONE + (
        "set security zones security-zone untrust host-inbound-traffic system-services ssh\n"
        "set firewall family inet filter EDGE term permit-any from source-address 0.0.0.0/0\n"
        "set firewall family inet filter EDGE term permit-any then accept\n"
        "set interfaces ge-0/0/0 unit 0 family inet filter input EDGE\n")
    assert _services(_findings(_parser(tmp_path, body))[0]) == {"ssh"}
    restrictive = body.replace("from source-address 0.0.0.0/0", "from source-address 198.51.100.0/24")
    assert _findings(_parser(tmp_path, restrictive)) == []
    unresolved = body.replace("filter input EDGE", "filter input MISSING")
    assert _findings(_parser(tmp_path, unresolved)) == []
