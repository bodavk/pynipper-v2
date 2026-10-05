"""SC-047 stage: unauthenticated OSPF/IS-IS admitted by host-inbound protocols on an external SRX interface."""

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import Severity
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.common.assessment import AssessmentContext
from src.devices.juniper.junos import JunOSParser

RULE = "juniper.junos.host_inbound.routing_exposed"
ZONE = "set security zones security-zone untrust interfaces ge-0/0/0.0\n"
OSPF = "set protocols ospf area 0.0.0.0 interface ge-0/0/0.0\n"


def _findings(tmp_path, body, role="external"):
    source = tmp_path / "srx.conf"
    source.write_text(f"## Model: SRX345\nset version 22.4R1.10\nset system host-name fw1\n{body}", encoding="utf-8")
    parser = JunOSParser(str(source))
    parser.set_assessment_context(AssessmentContext.from_mapping({"interface_roles": {"ge-0/0/0": role}}))
    plugin = PluginJunOSBaseline()
    plugin.check_host_inbound_routing(parser)
    return [item for item in plugin.get_issues() if item.rule_id == RULE]


def test_unauthenticated_ospf_admitted_externally(tmp_path):
    body = ZONE + OSPF + "set security zones security-zone untrust host-inbound-traffic protocols ospf\n"
    findings = _findings(tmp_path, body)
    assert len(findings) == 1 and findings[0].severity is Severity.HIGH
    assert "OSPF (no authentication)" in findings[0].observation
    assert guidance_for(RULE)


def test_all_protocols_with_isis(tmp_path):
    body = ZONE + "set protocols isis interface ge-0/0/0.0\nset security zones security-zone untrust host-inbound-traffic protocols all\n"
    assert "ISIS (no authentication)" in _findings(tmp_path, body)[0].observation


@pytest.mark.parametrize("body,role", [
    (ZONE + OSPF + "set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key \"$9$x\"\n"
     "set security zones security-zone untrust host-inbound-traffic protocols ospf\n", "external"),
    (ZONE + OSPF + "set security zones security-zone untrust host-inbound-traffic protocols bgp\n", "external"),
    (ZONE + OSPF + "set security zones security-zone untrust host-inbound-traffic protocols ospf\n", "internal"),
    (ZONE + OSPF + "set security zones security-zone untrust host-inbound-traffic protocols all except ospf\n", "external"),
])
def test_not_reported(tmp_path, body, role):
    assert not _findings(tmp_path, body, role)
