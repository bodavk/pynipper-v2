"""SC-049 second batch: IOS/ASA management-plane control outcomes."""

import contextlib
import io

import pytest

from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.common.controls import control_coverage
from src.devices import get_parser
from src.devices.cisco.asa import CiscoASAParser

IOS_HEADER = "version 15.4\nhostname r1\n!\n"
ASA_HEADER = "ASA Version 9.18(4)\nhostname fw1\n"


def _ios(tmp_path, body):
    path = tmp_path / "r1.conf"
    path.write_text(IOS_HEADER + body + "end\n", encoding="utf-8")
    parser = get_parser("IOS_ROUTER", str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_cisco_ios_conf(parser)
    rules = {issue.rule_id for issue in (findings.values() if isinstance(findings, dict) else findings or [])}
    return {item["control-id"]: item["outcome"] for item in control_coverage(parser)["results"]}, rules


def _asa(tmp_path, body):
    path = tmp_path / "asa.conf"
    path.write_text(ASA_HEADER + body, encoding="utf-8")
    parser = CiscoASAParser(str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_asa_conf(parser)
    rules = {issue.rule_id for issue in findings.values()}
    return {item["control-id"]: item["outcome"] for item in control_coverage(parser)["results"]}, rules


@pytest.mark.parametrize("control,body,outcome,rule", [
    ("cisco.ios.vty-transport", "line vty 0 4\n transport input telnet ssh\n", "finding", "cisco.ios.vty.telnet"),
    ("cisco.ios.vty-transport", "line vty 0 4\n transport input ssh\nline vty 5 15\n transport input ssh\n",
     "evaluated-no-finding", "cisco.ios.vty.telnet"),
    ("cisco.ios.vty-transport", "", "unknown", "cisco.ios.vty.telnet"),
    ("cisco.ios.ssh-protocol", "ip ssh time-out 60\nline vty 0 4\n transport input ssh\n", "finding",
     "cisco.ios.ssh.protocol_version"),
    ("cisco.ios.ssh-protocol", "ip ssh version 2\nline vty 0 4\n transport input ssh\n", "evaluated-no-finding",
     "cisco.ios.ssh.protocol_version"),
    ("cisco.ios.ssh-protocol", "", "not-applicable", "cisco.ios.ssh.protocol_version"),
    ("cisco.ios.snmp-community", "snmp-server community S3cretValue RO\n", "finding", "cisco.ios.snmp.legacy_community"),
    ("cisco.ios.snmp-community", "", "evaluated-no-finding", "cisco.ios.snmp.legacy_community"),
    ("cisco.ios.ntp-authentication", "ntp server 192.0.2.1\n", "finding", "cisco.ios.ntp.authentication"),
    ("cisco.ios.ntp-authentication",
     "ntp authenticate\nntp authentication-key 1 md5 KEYVALUE\nntp trusted-key 1\nntp server 192.0.2.1 key 1\n",
     "evaluated-no-finding", "cisco.ios.ntp.authentication"),
    ("cisco.ios.ntp-authentication", "", "not-applicable", "cisco.ios.ntp.authentication"),
    ("cisco.ios.remote-logging", "", "finding", "cisco.ios.logging.remote_destination"),
    ("cisco.ios.remote-logging", "logging host 192.0.2.10\n", "evaluated-no-finding",
     "cisco.ios.logging.remote_destination"),
])
def test_ios_control_outcomes(tmp_path, control, body, outcome, rule):
    outcomes, rules = _ios(tmp_path, body)
    assert outcomes[control] == outcome
    assert (rule in rules) == (outcome == "finding")


def test_ios_vty_one_open_range_is_a_finding(tmp_path):
    outcomes, _ = _ios(tmp_path, "line vty 0 4\n transport input ssh\nline vty 5 15\n transport input all\n")
    assert outcomes["cisco.ios.vty-transport"] == "finding"


def test_ios_ntp_mixed_associations_is_a_finding(tmp_path):
    outcomes, _ = _ios(tmp_path, "ntp authenticate\nntp authentication-key 1 md5 KEYVALUE\nntp trusted-key 1\n"
                                 "ntp server 192.0.2.1 key 1\nntp server 192.0.2.2\n")
    assert outcomes["cisco.ios.ntp-authentication"] == "finding"


@pytest.mark.parametrize("control,body,outcome,rule", [
    ("cisco.asa.snmp-community", "snmp-server community private rw\n", "finding", "cisco.asa.snmp.write_community"),
    ("cisco.asa.snmp-community", "snmp-server community public\n", "finding", "cisco.asa.snmp.default_community"),
    ("cisco.asa.snmp-community", "", "evaluated-no-finding", "cisco.asa.snmp.default_community"),
    ("cisco.asa.ntp-authentication", "ntp server 192.0.2.3 source inside\n", "finding", "cisco.asa.ntp.authentication"),
    ("cisco.asa.ntp-authentication",
     "ntp authenticate\nntp trusted-key 1\nntp authentication-key 1 sha256 TOPSECRET\nntp server 192.0.2.1 key 1 source inside\n",
     "evaluated-no-finding", "cisco.asa.ntp.authentication"),
    ("cisco.asa.ntp-authentication", "", "not-applicable", "cisco.asa.ntp.authentication"),
    ("cisco.asa.remote-logging", "logging enable\n", "finding", "cisco.asa.logging.missing"),
    ("cisco.asa.remote-logging", "logging enable\nlogging host inside 10.0.0.10\n", "evaluated-no-finding",
     "cisco.asa.logging.missing"),
])
def test_asa_control_outcomes(tmp_path, control, body, outcome, rule):
    outcomes, rules = _asa(tmp_path, body)
    assert outcomes[control] == outcome
    assert (rule in rules) == (outcome == "finding")


# SC-049 third batch: IOS HTTP server, ASA Telnet and SSH source restriction.
ASA_INTERFACES = (
    "interface GigabitEthernet0/0\n nameif outside\n security-level 0\n ip address 203.0.113.1 255.255.255.0\n"
    "interface GigabitEthernet0/1\n nameif inside\n security-level 100\n ip address 10.0.0.1 255.255.255.0\n"
)


@pytest.mark.parametrize("body,outcome,rules", [
    ("ip http server\n", "finding", {"cisco.ios.http.cleartext_service", "cisco.ios.http.access_restriction"}),
    ("ip http server\nip http access-class 10\naccess-list 10 permit 10.0.0.0 0.0.0.255\n", "finding",
     {"cisco.ios.http.cleartext_service"}),
    ("no ip http server\n", "evaluated-no-finding", set()),
    ("", "evaluated-no-finding", set()),
])
def test_ios_http_server_control(tmp_path, body, outcome, rules):
    outcomes, emitted = _ios(tmp_path, body)
    assert outcomes["cisco.ios.http-server"] == outcome
    http_rules = {"cisco.ios.http.cleartext_service", "cisco.ios.http.access_restriction"}
    assert emitted & http_rules == rules


@pytest.mark.parametrize("control,body,outcome,rule", [
    ("cisco.asa.management-telnet", ASA_INTERFACES + "telnet 10.0.0.0 255.255.255.0 inside\n", "finding",
     "cisco.asa.management.telnet"),
    ("cisco.asa.management-telnet", ASA_INTERFACES, "evaluated-no-finding", "cisco.asa.management.telnet"),
    ("cisco.asa.ssh-source-restriction", ASA_INTERFACES + "ssh 0.0.0.0 0.0.0.0 outside\n", "finding",
     "cisco.asa.management.unrestricted_ssh"),
    ("cisco.asa.ssh-source-restriction", ASA_INTERFACES + "ssh 198.51.100.0 255.255.255.0 outside\n",
     "evaluated-no-finding", "cisco.asa.management.unrestricted_ssh"),
    ("cisco.asa.ssh-source-restriction", ASA_INTERFACES, "not-applicable", "cisco.asa.management.unrestricted_ssh"),
])
def test_asa_management_access_controls(tmp_path, control, body, outcome, rule):
    outcomes, rules = _asa(tmp_path, body)
    assert outcomes[control] == outcome
    assert (rule in rules) == (outcome == "finding")


def test_asa_ssh_mixed_grants_is_a_finding(tmp_path):
    outcomes, _ = _asa(tmp_path, ASA_INTERFACES + "ssh 10.0.0.0 255.255.255.0 inside\nssh 0.0.0.0 0.0.0.0 outside\n")
    assert outcomes["cisco.asa.ssh-source-restriction"] == "finding"
