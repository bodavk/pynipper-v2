"""Effective NETCONF/RESTCONF service ACLs on IOS-XE (SC-026)."""

import pytest

from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.analyze.common.guidance import guidance_for
from src.devices.cisco.ios import CiscoIOSParser
from src.devices.cisco.iosxe import CiscoIOSXEParser
from src.main import main


ACL4 = "ip access-list standard OPEN\n permit any\n"
ACL6 = "ipv6 access-list OPEN6\n permit ipv6 any any\n"
ENABLED = "version 17.9\nnetconf-yang\nrestconf\nip http secure-server\n"
BINDINGS = ("netconf-yang ssh ipv4 access-list name OPEN\n"
            "netconf-yang ssh ipv6 access-list name OPEN6\n"
            "restconf ipv4 access-list name OPEN\n"
            "restconf ipv6 access-list name OPEN6\n")


def scan(tmp_path, body, parser_class=CiscoIOSXEParser):
    source = tmp_path / "router.conf"
    source.write_text(body, encoding="utf-8")
    parser = parser_class(str(source))
    plugin = PluginIOSBaseline()
    plugin.check_programmability_api_acls(parser)
    return parser, plugin.get_issues()


def test_attached_ipv4_and_ipv6_permit_all_are_reported(tmp_path):
    parser, findings = scan(tmp_path, ENABLED + BINDINGS + ACL4 + ACL6)
    assert len(parser.get_programmability_apis()) == 2
    assert {item.rule_id for item in findings} == {
        "cisco.ios.management.netconf_unrestricted_sources",
        "cisco.ios.management.netconf_ipv6_unrestricted_sources",
        "cisco.ios.management.restconf_unrestricted_sources",
        "cisco.ios.management.restconf_ipv6_unrestricted_sources",
    }
    assert all(item.evidence_locations and guidance_for(item.rule_id) for item in findings)


@pytest.mark.parametrize("body", [
    ENABLED + ACL4 + ACL6,  # No binding is not graded in this stage.
    ENABLED + BINDINGS.replace("OPEN6", "MISSING") + ACL4,
    ENABLED + BINDINGS + ACL4.replace("permit any", "permit host 192.0.2.1")
    + ACL6.replace("permit ipv6 any any", "permit ipv6 2001:db8::/32 any"),
    ENABLED + BINDINGS + ACL4 + ACL6 + "no netconf-yang\nno restconf\n",
    "version 17.9\nnetconf-yang\nnetconf-yang ssh port disable\n"
    "netconf-yang ssh ipv4 access-list name OPEN\n" + ACL4,
    "version 17.9\nrestconf\nrestconf ipv4 access-list name OPEN\n" + ACL4,
])
def test_unbound_restrictive_disabled_or_internal_only_not_reported(tmp_path, body):
    _, findings = scan(tmp_path, body)
    if "MISSING" in body:
        # The unresolved IPv6 binding is unknown, while IPv4 remains provably open.
        assert {item.rule_id for item in findings} == {
            "cisco.ios.management.netconf_unrestricted_sources",
            "cisco.ios.management.restconf_unrestricted_sources",
        }
    else:
        assert findings == []


def test_binding_removal_and_replacement_obey_source_order(tmp_path):
    body = (ENABLED + BINDINGS + ACL4 + ACL6
            + "no netconf-yang ssh ipv4 access-list name OPEN\n"
            + "no restconf ipv6 access-list name OPEN6\n")
    _, findings = scan(tmp_path, body)
    assert {item.rule_id for item in findings} == {
        "cisco.ios.management.netconf_ipv6_unrestricted_sources",
        "cisco.ios.management.restconf_unrestricted_sources",
    }


def test_unresolved_service_acl_is_manual_review_without_leaking_name(tmp_path):
    parser, findings = scan(
        tmp_path, ENABLED + "netconf-yang ssh ipv4 access-list name HiddenACL\n"
    )
    assert findings == []
    notes = parser.diagnostics
    assert any("NETCONF" in note and "manual review" in note for note in notes)
    assert all("HiddenACL" not in note for note in notes)


def test_restrictive_shared_http_acl_compensates_restconf(tmp_path):
    body = (ENABLED + BINDINGS + ACL4 + ACL6
            + "ip access-list standard WEB\n permit host 192.0.2.1\n"
            + "ip http access-class ipv4 WEB\n")
    _, findings = scan(tmp_path, body)
    assert "cisco.ios.management.restconf_unrestricted_sources" not in {
        item.rule_id for item in findings
    }
    assert "cisco.ios.management.netconf_unrestricted_sources" in {
        item.rule_id for item in findings
    }


def test_not_applied_to_classic_ios(tmp_path):
    parser, findings = scan(tmp_path, ENABLED + BINDINGS + ACL4 + ACL6, CiscoIOSParser)
    assert parser.get_programmability_apis() == ()
    assert findings == []


@pytest.mark.parametrize("format", ["JSON", "HTML"])
def test_public_report(tmp_path, format):
    scan(tmp_path, ENABLED + "netconf-yang ssh ipv4 access-list name OPEN\n" + ACL4)
    output = tmp_path / ("report." + format.lower())
    assert main(["-d", "ios_xe", "-i", str(tmp_path / "router.conf"), "-o", format,
                 "-f", str(output)]) == 0
    assert "NETCONF service ACL permits every IPv4 source" in output.read_text(encoding="utf-8")
