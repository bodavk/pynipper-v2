import json
from types import SimpleNamespace

import pytest

from src.analyze.common.issue import Finding, Severity
from src.common.assessment import AssessmentContext
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.cisco.iosxe import CiscoIOSXEParser
from src.devices.cisco.asa import CiscoASAParser
from src.devices.checkpoint.fw1 import CheckPointFW1Parser
from src.devices.fortinet.fortios import FortiOSParser
from src.devices.juniper.junos import JunOSParser
from src.devices.paloalto.panos import PaloAltoPANOSParser
from src.report.coverage import build_report_context
from src.report.report import _generate_html_report, _generate_json_report


def _ios(tmp_path, context=None):
    path = tmp_path / "inventory.conf"
    path.write_text(
        """hostname <img-src=x-onerror=alert(1)>
version 17.9
username auditor privilege 15 secret SUPERSECRET
interface GigabitEthernet0/1
 description users
 ip address 192.0.2.1 255.255.255.0
 no shutdown
access-list 10 permit 192.0.2.0 0.0.0.255
line vty 0 4
 transport input ssh
 access-class 10 in
""",
        encoding="utf-8",
    )
    parser = CiscoIOSParser(str(path))
    if context is not None:
        parser.set_assessment_context(context)
    return parser


def _panos_inventory(tmp_path, context):
    path = tmp_path / "inventory.xml"
    path.write_text(
        """<config version="12.1.2"><mgt-config><users><entry name="auditor"><phash>SUPERSECRET</phash></entry></users></mgt-config>
        <devices><entry name="fw-a"><deviceconfig><system><hostname>&lt;img-src=x-onerror=alert(1)&gt;</hostname></system></deviceconfig>
        <network><interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="192.0.2.1/24"/></ip></layer3></entry></ethernet></interface></network>
        <vsys><entry name="vsys1"><zone><entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone>
        <rulebase><security><rules><entry name="ALLOW-WEB"><from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>192.0.2.0/24</member></source><destination><member>198.51.100.10</member></destination>
        <application><member>ssl</member></application><service><member>application-default</member></service><action>allow</action></entry>
        </rules></security></rulebase></entry></vsys></entry></devices></config>""",
        encoding="utf-8",
    )
    parser = PaloAltoPANOSParser(str(path))
    parser.set_assessment_context(context)
    return parser


def _finding():
    return Finding(
        rule_id="vendor.os.management.example",
        device="VENDOR_OS",
        title="Example <unsafe>",
        observation="Observed <script>alert(1)</script>",
        impact="Impact",
        exploitability="Exploitability",
        recommendation="Fix <now>",
        severity=Severity.HIGH,
        evidence=("safe evidence",),
        references=("https://example.com/security",),
    )


def test_policy_validates_opt_in_inventory_categories():
    context = AssessmentContext.from_mapping({
        "report_inventory": ["interfaces", "policies"]
    })
    assert context.report_inventory == ("interfaces", "policies")
    assert context.to_dict()["report-inventory"] == ["interfaces", "policies"]
    with pytest.raises(ValueError):
        AssessmentContext.from_mapping({"report_inventory": ["users"]})
    with pytest.raises(ValueError):
        AssessmentContext.from_mapping({"report_inventory": ["interfaces", "interfaces"]})


def test_coverage_is_always_present_but_inventory_is_opt_in(tmp_path):
    context = build_report_context(_ios(tmp_path))
    assert context["configuration-inventory"] == {}
    coverage = context["coverage"]
    assert coverage["parser"] == "CiscoIOSParser"
    assert coverage["input-kind"] == "file"
    assert len(coverage["fields"]) == 9
    assert {item["knowledge-state"] for item in coverage["fields"]}.issubset({
        "known", "unknown", "unsupported", "parse_error"
    })
    assert "not a passed security check" in coverage["scope-note"]


def test_selected_inventory_is_sanitized_and_exclusions_are_visible(tmp_path):
    parser = _panos_inventory(tmp_path, AssessmentContext.from_mapping({
        "report_inventory": ["interfaces", "management-services", "policies"],
        "excluded_categories": ["policy"],
    }))
    context = build_report_context(parser)
    assert set(context["configuration-inventory"]) == {
        "interfaces", "management-services", "policies"
    }
    policy_coverage = next(
        item for item in context["coverage"]["fields"]
        if item["name"] == "security-policies"
    )
    assert policy_coverage["audit-selection"] == "excluded"
    rendered = json.dumps(context)
    assert "SUPERSECRET" not in rendered
    assert "evidence" not in rendered.casefold()
    assert "auditor" not in rendered


def test_checkpoint_export_limitations_are_reported_as_coverage_not_passes(tmp_path):
    export = tmp_path / "fw1"
    export.mkdir()
    (export / "rules.C").write_text(
        "(:rule-base (:Layer (:rule-1 (:name (Cleanup) :src (Any) :dst (Any) :services (Any) :action (drop)))))",
        encoding="utf-8",
    )
    coverage = build_report_context(CheckPointFW1Parser(str(export)))["coverage"]
    states = {item["name"]: item for item in coverage["fields"]}
    assert states["management-services"]["knowledge-state"] == "unsupported"
    assert "do not describe gateway management daemons" in states["management-services"]["detail"]
    assert coverage["input-kind"] == "directory"
    assert coverage["input-artifact-count"] == 1


def test_panorama_diagnostic_is_preserved_without_inventing_effective_state(tmp_path):
    path = tmp_path / "panorama.xml"
    path.write_text(
        '<config><devices><entry name="local"><device-group><entry name="DG"/></device-group></entry></devices></config>',
        encoding="utf-8",
    )
    coverage = build_report_context(PaloAltoPANOSParser(str(path)))["coverage"]
    assert coverage["diagnostics"]
    assert "not resolved" in coverage["diagnostics"][0]


def test_json_and_html_expose_equivalent_coverage_summary_and_escape_markup(tmp_path):
    parser = _panos_inventory(tmp_path, AssessmentContext.from_mapping({
        "report_inventory": ["interfaces"]
    }))
    context = build_report_context(parser)
    data = {
        "device-type": parser.device_type,
        "hostname": parser.get_hostname(),
        "assessment-policy": parser.assessment_context.to_dict(),
        **context,
    }
    issues = {"1. Example": _finding()}
    json_path, html_path = tmp_path / "report.json", tmp_path / "report.html"
    _generate_json_report(str(json_path), issues, [], data)
    _generate_html_report(str(html_path), issues, [], data)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    html = html_path.read_text(encoding="utf-8")
    assert payload["coverage"] == context["coverage"]
    assert payload["configuration-inventory"] == context["configuration-inventory"]
    assert payload["remediation-summary"]["severity-counts"] == {"High": 1}
    assert payload["remediation-summary"]["priority-actions"][0]["rule-id"] == _finding().rule_id
    assert "Assessment coverage" in html and "Configuration inventory" in html
    assert "Remediation summary" in html and "High: 1" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "SUPERSECRET" not in html + json_path.read_text(encoding="utf-8")


def test_legacy_caller_without_coverage_gets_explicit_unassessed_message(tmp_path):
    output = tmp_path / "legacy.html"
    _generate_html_report(
        str(output), {}, [], {"device-type": "UNKNOWN", "hostname": "unknown"}
    )
    html = output.read_text(encoding="utf-8")
    assert "Coverage metadata was not supplied" in html
    assert "does not mean every control passed" in html


def test_software_advisory_summary_is_html_escaped(tmp_path):
    output = tmp_path / "advisory.html"
    advisory = SimpleNamespace(
        title="Advisory",
        summary="<img src=x onerror=alert(1)>",
        cves=("CVE-2099-0001",),
        cvss=9.8,
        url="https://example.com/advisory",
    )
    _generate_html_report(
        str(output), {}, [advisory], {"device-type": "IOS", "hostname": "edge"}
    )
    html = output.read_text(encoding="utf-8")
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html


def test_asa_native_normalized_adapter_supports_safe_opt_in_inventory(tmp_path):
    source = tmp_path / "asa.conf"
    source.write_text(
        """ASA Version 9.18(4)
hostname edge-asa
username auditor privilege 5 password TOPSECRET
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 198.51.100.1 255.255.255.0
 no shutdown
ssh 192.0.2.0 255.255.255.0 outside
http server enable
http 192.0.2.0 255.255.255.0 outside
access-list OUTSIDE extended permit tcp host 192.0.2.10 host 198.51.100.10 eq 443
access-list UNUSED extended permit ip any any
access-group OUTSIDE in interface outside
logging enable
logging trap warnings
logging host outside 192.0.2.50
ssl server-version tlsv1.2
""",
        encoding="utf-8",
    )
    parser = CiscoASAParser(str(source))
    parser.set_assessment_context(AssessmentContext.from_mapping({
        "report_inventory": [
            "interfaces", "management-services", "policies", "logging-destinations"
        ]
    }))
    normalized = parser.get_normalized_config()
    assert normalized.hostname.value == "edge-asa"
    assert normalized.software_version.value == "9.18(4)"
    assert [item.username for item in normalized.users.items] == ["auditor"]
    assert [(item.name, item.zone, item.state.value) for item in normalized.interfaces.items] == [
        ("GigabitEthernet0/0", "outside", "enabled")
    ]
    assert [item.name for item in normalized.policies.items] == ["OUTSIDE:1"]
    assert {item.protocol for item in normalized.management_services.items} == {"ssh", "https"}
    context = build_report_context(parser)
    rendered = json.dumps(context)
    assert set(context["configuration-inventory"]) == {
        "interfaces", "management-services", "policies", "logging-destinations"
    }
    assert "TOPSECRET" not in rendered
    assert "UNUSED" not in rendered


def test_ios_native_normalized_adapter_is_attachment_aware_and_secret_free(tmp_path):
    source = tmp_path / "ios-normalized.conf"
    source.write_text(
        """version 17.9.4
hostname edge-ios
username auditor privilege 15 secret TOPSECRET
ip http secure-server
ip http access-class WEB-MGMT
ip ssh version 2
ip ssh server algorithm encryption aes256-ctr aes128-ctr
crypto key generate rsa general-keys modulus 3072
logging host 192.0.2.50
logging trap warnings
interface GigabitEthernet0/0
 description outside
 ip address 198.51.100.1 255.255.255.0
 ip access-group EDGE-IN in
 no shutdown
interface GigabitEthernet0/1
 shutdown
ipv6 access-list UNUSED-V6
 permit ipv6 any any
ip access-list extended EDGE-IN
 10 permit tcp 192.0.2.0 0.0.0.255 host 198.51.100.10 eq 443 log
 20 deny ip any any
ip access-list extended UNUSED
 permit ip any any
line vty 0 4
 transport input ssh
 access-class VTY-MGMT in
""",
        encoding="utf-8",
    )
    parser = CiscoIOSParser(str(source))
    parser.set_assessment_context(AssessmentContext.from_mapping({
        "report_inventory": [
            "interfaces", "management-services", "policies", "logging-destinations"
        ]
    }))
    normalized = parser.get_normalized_config()

    assert normalized.hostname.value == "edge-ios"
    assert normalized.software_version.value == "17.9.4"
    assert normalized.device_model.state.value == "unknown"
    assert [item.username for item in normalized.users.items] == ["auditor"]
    assert [
        (item.name, item.state.value, item.addresses)
        for item in normalized.interfaces.items
    ] == [
        ("GigabitEthernet0/0", "enabled", ("198.51.100.1 255.255.255.0",)),
        ("GigabitEthernet0/1", "disabled", ()),
    ]
    assert {item.protocol for item in normalized.management_services.items} == {
        "ssh", "https"
    }
    ssh = next(item for item in normalized.management_services.items if item.protocol == "ssh")
    assert ssh.permitted_sources == ("ipv4-acl:VTY-MGMT",)
    assert [item.name for item in normalized.policies.items] == [
        "EDGE-IN:10@GigabitEthernet0/0:in:ipv4",
        "EDGE-IN:20@GigabitEthernet0/0:in:ipv4",
    ]
    assert normalized.policies.items[0].tracking == "log"
    assert [item.address for item in normalized.logging_destinations.items] == ["192.0.2.50"]
    assert normalized.logging_destinations.items[0].severity == "warnings"
    assert {item.name for item in normalized.crypto_settings.items} == {
        "ssh-version", "ssh-encryption", "ssh-rsa-key-modulus"
    }

    report_context = build_report_context(parser)
    rendered = json.dumps(report_context)
    assert set(report_context["configuration-inventory"]) == {
        "interfaces", "management-services", "policies", "logging-destinations"
    }
    assert "TOPSECRET" not in rendered
    assert "UNUSED" not in rendered


def test_junos_normalized_inventory_includes_stateless_and_srx_policies(tmp_path):
    source = tmp_path / "junos-normalized.conf"
    source.write_text(
        """set version 22.4R1.10
set system host-name edge-srx
set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.1/24
set interfaces ge-0/0/0 unit 0 family inet filter input EDGE-IN
set security zones security-zone trust interfaces ge-0/0/1.0
set security zones security-zone untrust interfaces ge-0/0/0.0
set firewall family inet filter EDGE-IN term ALLOW-SSH from source-address 192.0.2.0/24
set firewall family inet filter EDGE-IN term ALLOW-SSH from protocol tcp
set firewall family inet filter EDGE-IN term ALLOW-SSH then accept
set security policies from-zone trust to-zone untrust policy WEB match source-address USERS
set security policies from-zone trust to-zone untrust policy WEB match destination-address SERVER
set security policies from-zone trust to-zone untrust policy WEB match application junos-https
set security policies from-zone trust to-zone untrust policy WEB then permit
set security policies from-zone trust to-zone untrust policy WEB then log session-init
set security policies from-zone trust to-zone untrust policy RETIRED match source-address any
set security policies from-zone trust to-zone untrust policy RETIRED match destination-address any
set security policies from-zone trust to-zone untrust policy RETIRED match application any
set security policies from-zone trust to-zone untrust policy RETIRED then deny
deactivate security policies from-zone trust to-zone untrust policy RETIRED
""",
        encoding="utf-8",
    )
    parser = JunOSParser(str(source))
    parser.set_assessment_context(AssessmentContext.from_mapping({
        "report_inventory": ["interfaces", "policies"]
    }))
    normalized = parser.get_normalized_config()
    assert [item.name for item in normalized.policies.items] == [
        "EDGE-IN/ALLOW-SSH",
        "trust->untrust/WEB",
        "trust->untrust/RETIRED",
    ]
    assert normalized.policies.items[0].source_interfaces == ("ge-0/0/0:input",)
    assert normalized.policies.items[1].scope == "security:trust->untrust"
    assert normalized.policies.items[1].services == ("junos-https",)
    assert normalized.policies.items[1].tracking == "session-init"
    assert normalized.policies.items[2].state.value == "disabled"
    inventory = build_report_context(parser)["configuration-inventory"]
    assert [item["name"] for item in inventory["policies"]] == [
        "EDGE-IN/ALLOW-SSH",
        "trust->untrust/WEB",
        "trust->untrust/RETIRED",
    ]


def test_fortios_normalized_inventory_keeps_ipv4_and_ipv6_policy_families(tmp_path):
    source = tmp_path / "fortios-normalized.conf"
    source.write_text(
        """#config-version=FGT100F-7.6.4-FW-build0001-260101:opmode=0:vdom=1:user=admin
config system global
set hostname edge-fgt
end
config firewall policy
edit 10
set name WEB-V4
set srcintf lan
set dstintf wan1
set srcaddr CLIENTS
set dstaddr SERVER
set service HTTPS
set action accept
set logtraffic all
next
end
config firewall policy6
edit 20
set name WEB-V6
set srcintf lan
set dstintf wan1
set srcaddr V6-CLIENTS
set dstaddr V6-SERVER
set service HTTPS
set action accept
set status disable
next
end
""",
        encoding="utf-8",
    )
    normalized = FortiOSParser(str(source)).get_normalized_config()
    assert [(item.name, item.state.value) for item in normalized.policies.items] == [
        ("10", "enabled"),
        ("20", "disabled"),
    ]
    assert [item.scope for item in normalized.policies.items] == ["root", "root"]
    assert normalized.policies.items[0].tracking == "all"
    assert normalized.policies.items[1].sources == ("V6-CLIENTS",)


def test_iosxe_inherits_normalized_adapter_and_effective_removals(tmp_path):
    source = tmp_path / "iosxe-normalized.conf"
    source.write_text(
        """version 17.12.1
hostname edge-xe
logging host 192.0.2.10
no logging host 192.0.2.10
logging host vrf MGMT 192.0.2.20 transport tcp port 6514
logging trap informational
interface GigabitEthernet1
 ip address 192.0.2.1 255.255.255.0
 ip access-group OLD in
 shutdown
interface GigabitEthernet1
 no ip address 192.0.2.1 255.255.255.0
 ip address 198.51.100.1 255.255.255.0
 no ip access-group OLD in
 ip access-group CURRENT in
 no shutdown
ip access-list extended OLD
 permit ip any any
ip access-list extended CURRENT
 permit tcp any host 198.51.100.1 eq 22
""",
        encoding="utf-8",
    )
    normalized = CiscoIOSXEParser(str(source)).get_normalized_config()
    assert normalized.device_type == "IOS_XE"
    assert [(item.address, item.scope, item.severity) for item in normalized.logging_destinations.items] == [
        ("192.0.2.20", "MGMT", "informational")
    ]
    assert [item.addresses for item in normalized.interfaces.items] == [
        ("198.51.100.1 255.255.255.0",)
    ]
    assert [item.name for item in normalized.policies.items] == [
        "CURRENT:1@GigabitEthernet1:in:ipv4"
    ]
