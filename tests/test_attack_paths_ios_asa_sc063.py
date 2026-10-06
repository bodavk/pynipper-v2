"""SC-063: clear-text administration (IOS VTY, ASA Telnet) and writable default SNMP (IOS)."""

import contextlib
import io

import pytest

from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.common.attack_paths import attack_path_section
from src.common.assessment import AssessmentContext
from src.devices import get_parser
from src.devices.cisco.asa import CiscoASAParser

CLEAR = "cleartext-admin-unrestricted"
SNMP = "writable-default-snmp"
IOS_HEADER = "version 15.4\nhostname r1\n!\n"
EXCLUDED_CATEGORY = "vty"  # assessment categories are rule-ID tokens
USERS = "username admin privilege 15 secret 9 $9$abcdefghijklmn$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ\n"


def _ios(tmp_path, body, header=IOS_HEADER, excluded=()):
    path = tmp_path / "r1.conf"
    path.write_text(header + body + "end\n", encoding="utf-8")
    parser = get_parser("IOS_ROUTER", str(path))
    if excluded:
        parser.set_assessment_context(AssessmentContext.from_mapping({"excluded_categories": list(excluded)}))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_cisco_ios_conf(parser)
    findings = list(findings.values()) if isinstance(findings, dict) else list(findings or [])
    return findings, attack_path_section(parser)


def _paths(section, pattern):
    return [item for item in section["results"] if item["pattern-id"] == pattern]


def _status(section, pattern):
    return next(item for item in section["patterns"] if item["pattern-id"] == pattern)


# --- IOS clear-text administration ----------------------------------------------------

def test_ios_telnet_vty_without_access_class_forms_a_path(tmp_path):
    _, section = _ios(tmp_path, USERS + "line vty 0 4\n login local\n transport input telnet ssh\n")
    [path] = _paths(section, CLEAR)
    assert path["instance-key"] == "system/vty:0-4/ipv4"
    assert [step["kind"] for step in path["steps"]] == ["telnet-listener", "unrestricted-source", "password-login"]
    assert {item["rule-id"] for item in path["linked-findings"]} == {"cisco.ios.vty.telnet"}
    assert _status(section, CLEAR)["status"] == "path-found"


def test_ios_permit_all_access_class_forms_a_path(tmp_path):
    body = (USERS + "access-list 10 permit any\n"
            "line vty 0 4\n access-class 10 in\n login local\n transport input telnet\n")
    [path] = _paths(_ios(tmp_path, body)[1], CLEAR)
    assert "permits every source" in path["steps"][1]["predicate"]


def test_ios_restrictive_access_class_or_ssh_only_has_no_path(tmp_path):
    restricted = (USERS + "access-list 10 permit 10.0.0.0 0.255.255.255\n"
                  "line vty 0 4\n access-class 10 in\n login local\n transport input telnet\n")
    section = _ios(tmp_path, restricted)[1]
    assert _paths(section, CLEAR) == []
    assert _status(section, CLEAR)["status"] == "evaluated-no-path"
    ssh_only = _ios(tmp_path, USERS + "line vty 0 4\n login local\n transport input ssh\n")[1]
    assert _status(ssh_only, CLEAR)["status"] == "evaluated-no-path"


def test_ios_unresolved_access_class_is_not_assessed(tmp_path):
    body = USERS + "line vty 0 4\n access-class MISSING in\n login local\n transport input telnet\n"
    section = _ios(tmp_path, body)[1]
    assert _paths(section, CLEAR) == []
    status = _status(section, CLEAR)
    assert status["status"] == "not-assessed"
    assert "MISSING" in status["reasons"][0]


def test_ios_no_login_is_not_a_password_path(tmp_path):
    section = _ios(tmp_path, "line vty 0 4\n no login\n transport input telnet\n")[1]
    assert _paths(section, CLEAR) == []


def test_ios_line_password_requires_an_exported_password(tmp_path):
    without = _ios(tmp_path, "line vty 0 4\n login\n transport input telnet\n")[1]
    assert _status(without, CLEAR)["status"] == "not-assessed"
    with_password = _ios(tmp_path, "line vty 0 4\n password 7 0822455D0A16\n login\n transport input telnet\n")[1]
    [path] = _paths(with_password, CLEAR)
    assert "line password" in path["steps"][2]["predicate"]


def test_ios_aaa_login_list_is_resolved(tmp_path):
    body = (USERS + "aaa new-model\naaa authentication login VTY local\n"
            "line vty 0 4\n login authentication VTY\n transport input telnet\n")
    [path] = _paths(_ios(tmp_path, body)[1], CLEAR)
    assert "AAA login list 'VTY'" in path["steps"][2]["predicate"]
    undefined = _ios(tmp_path, USERS + "aaa new-model\nline vty 0 4\n login authentication NOPE\n transport input telnet\n")[1]
    assert _status(undefined, CLEAR)["status"] == "not-assessed"


def test_ios_omitted_transport_uses_documented_legacy_default_only(tmp_path):
    body = USERS + "line vty 0 4\n login local\n"
    legacy = _ios(tmp_path, body, header="version 15.2\nhostname r1\n!\n")[1]
    [path] = _paths(legacy, CLEAR)
    assert "default" in path["steps"][0]["predicate"]
    current = _ios(tmp_path, body, header="version 15.9\nhostname r1\n!\n")[1]
    assert _paths(current, CLEAR) == []
    assert _status(current, CLEAR)["status"] == "not-assessed"


def test_ios_overlapping_vty_ranges_are_not_assessed(tmp_path):
    body = USERS + "line vty 0 4\n login local\n transport input telnet\nline vty 0 15\n transport input ssh\n"
    section = _ios(tmp_path, body)[1]
    assert _paths(section, CLEAR) == []
    assert "overlap" in _status(section, CLEAR)["reasons"][0]


def test_ios_component_exclusion(tmp_path):
    body = USERS + "line vty 0 4\n login local\n transport input telnet\n"
    section = _ios(tmp_path, body, excluded=(EXCLUDED_CATEGORY,))[1]
    assert _paths(section, CLEAR) == []
    assert _status(section, CLEAR)["status"] == "excluded"


# --- IOS writable default SNMP --------------------------------------------------------

def test_ios_default_rw_community_without_acl_forms_a_path(tmp_path):
    findings, section = _ios(tmp_path, "snmp-server community private RW\n")
    [path] = _paths(section, SNMP)
    assert path["instance-key"].startswith("system/snmp-community:line-")
    assert {item["rule-id"] for item in path["linked-findings"]} >= {"cisco.ios.snmp.default_community"}
    text = str(path)
    assert "private" not in text and "public" not in text


def test_ios_default_rw_community_with_permit_any_acl(tmp_path):
    [path] = _paths(_ios(tmp_path, "access-list 5 permit any\nsnmp-server community public RW 5\n")[1], SNMP)
    assert "permits every source" in path["steps"][1]["predicate"]


@pytest.mark.parametrize("body", [
    "snmp-server community private RO\n",
    "snmp-server community Un1que-Value RW\n",
    "access-list 5 permit 10.1.1.1\nsnmp-server community private RW 5\n",
    "snmp-server community private RW\nno snmp-server\n",
])
def test_ios_snmp_no_path(tmp_path, body):
    section = _ios(tmp_path, body)[1]
    assert _paths(section, SNMP) == []
    assert _status(section, SNMP)["status"] == "evaluated-no-path"


@pytest.mark.parametrize("body,reason", [
    ("snmp-server community private view LIMITED RW\n", "view"),
    ("snmp-server community private RW MISSING\n", "MISSING"),
])
def test_ios_snmp_not_assessed(tmp_path, body, reason):
    section = _ios(tmp_path, body)[1]
    status = _status(section, SNMP)
    assert status["status"] == "not-assessed"
    assert reason in status["reasons"][0]


def test_asa_has_no_snmp_write_producer(tmp_path):
    path = tmp_path / "asa.conf"
    path.write_text("ASA Version 9.18(4)\nhostname fw1\nsnmp-server community private\n", encoding="utf-8")
    parser = CiscoASAParser(str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        process_asa_conf(parser)
    assert _status(attack_path_section(parser), SNMP)["status"] == "not-implemented-for-device"


# --- ASA clear-text administration ----------------------------------------------------

ASA = ("ASA Version 9.18(4)\nhostname fw1\n"
       "interface GigabitEthernet0/0\n nameif outside\n security-level 0\n ip address 192.0.2.1 255.255.255.0\n"
       "interface GigabitEthernet0/1\n nameif inside\n security-level 100\n ip address 10.0.0.1 255.255.255.0\n"
       "interface GigabitEthernet0/2\n nameif dmz\n security-level 50\n ip address 10.9.0.1 255.255.255.0\n")


def _asa(tmp_path, body, head=ASA):
    path = tmp_path / "asa.conf"
    path.write_text(head + body, encoding="utf-8")
    parser = CiscoASAParser(str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        process_asa_conf(parser)
    return attack_path_section(parser)


def test_asa_any_source_telnet_with_aaa_forms_a_path(tmp_path):
    section = _asa(tmp_path, "telnet 0.0.0.0 0.0.0.0 inside\naaa authentication telnet console LOCAL\n")
    [path] = _paths(section, CLEAR)
    assert path["instance-key"] == "system/telnet:inside/ipv4"
    assert {item["rule-id"] for item in path["linked-findings"]} == {"cisco.asa.management.telnet"}
    assert "LOCAL" in path["steps"][2]["predicate"]


def test_asa_login_password_without_aaa(tmp_path):
    section = _asa(tmp_path, "passwd 2KFQnbNIdI.2KYOU encrypted\ntelnet 0.0.0.0 0.0.0.0 dmz\n")
    [path] = _paths(section, CLEAR)
    assert "'passwd'" in path["steps"][2]["predicate"]


def test_asa_lowest_security_interface_has_no_path(tmp_path):
    section = _asa(tmp_path, "telnet 0.0.0.0 0.0.0.0 outside\naaa authentication telnet console LOCAL\n")
    assert _paths(section, CLEAR) == []
    assert _status(section, CLEAR)["status"] == "evaluated-no-path"


def test_asa_restricted_grant_has_no_path(tmp_path):
    section = _asa(tmp_path, "telnet 10.0.0.0 255.255.255.0 inside\naaa authentication telnet console LOCAL\n")
    assert _status(section, CLEAR)["status"] == "evaluated-no-path"


def test_asa_unresolved_login_or_interface_is_not_assessed(tmp_path):
    no_login = _asa(tmp_path, "telnet 0.0.0.0 0.0.0.0 inside\n")
    assert _status(no_login, CLEAR)["status"] == "not-assessed"
    missing = _asa(tmp_path, "telnet 0.0.0.0 0.0.0.0 ghost\naaa authentication telnet console LOCAL\n")
    assert _status(missing, CLEAR)["status"] == "not-assessed"


def test_asa_tied_lowest_level_is_not_assessed(tmp_path):
    head = ASA.replace("security-level 50", "security-level 0")
    section = _asa(tmp_path, "telnet 0.0.0.0 0.0.0.0 dmz\naaa authentication telnet console LOCAL\n", head=head)
    assert _status(section, CLEAR)["status"] == "not-assessed"


def test_asa_shutdown_interface_has_no_path(tmp_path):
    head = ASA.replace(" nameif dmz\n", " shutdown\n nameif dmz\n")
    section = _asa(tmp_path, "telnet 0.0.0.0 0.0.0.0 dmz\naaa authentication telnet console LOCAL\n", head=head)
    assert _paths(section, CLEAR) == []
