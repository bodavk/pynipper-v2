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
