"""SC-049 completion for hp.procurve: AOS-S control outcomes match the mapped findings."""

import contextlib
import io

import pytest

from src.analyze.common.controls import CONTROLS, control_coverage
from src.analyze.hp.core.process_hp_conf import process_hp_conf
from src.common.assessment import AssessmentContext
from src.devices.hp.procurve import HPProCurveParser

H10 = "; J9772A Configuration Editor; Created on release #YA.16.10.0023\n"
H11 = "; J9772A Configuration Editor; Created on release #YA.16.11.0001\n"
H0 = ""  # no release header: documented defaults are not qualified
HP_CONTROLS = tuple(control for control in CONTROLS if control.startswith("hp.procurve."))
EDGE_ROLES = {"1": "access-edge", "2": "access-edge", "24": "uplink"}

SECURE = """hostname "secure-switch"
no telnet-server
no web-management
ip ssh
web-management ssl
ip authorized-managers 192.0.2.0 255.255.255.0 access manager
aaa authentication ssh login radius local
aaa authentication ssh enable radius local
aaa accounting exec start-stop radius
radius-server host 192.0.2.10 key ciphertext
logging 192.0.2.20
timesync sntp
sntp unicast
sntp authentication
sntp authentication key-id 55 authentication-mode md5 key-value ciphertext trusted
sntp server priority 1 192.0.2.30 3 key-id 55
snmpv3 user monitor auth sha auth-secret priv aes privacy-secret
password manager user-name admin sha256 0123456789abcdef
password configuration-control
banner motd "Authorized access only"
console idle-timeout 600
console idle-timeout serial-usb 600
vlan 10 name "USERS"
dhcp-snooping vlan 10
no ip ssh cipher 3des-cbc
no ip ssh cipher aes128-cbc
no ip ssh cipher aes192-cbc
no ip ssh cipher aes256-cbc
no ip ssh cipher rijndael-cbc@lysator.liu.se
no ip ssh kex diffie-hellman-group14-sha1
no ip ssh mac hmac-md5
no ip ssh mac hmac-md5-96
no ip ssh mac hmac-sha1
no ip ssh mac hmac-sha1-96
"""

EDGE = """vlan 10
 untagged 1-2
 tagged 24
dhcp-snooping vlan 10
dhcp-snooping trust 24
arp-protect vlan 10
arp-protect trust 24
ip source-lockdown 1-2
port-security 1-2 learn-mode limited-continuous
spanning-tree 1-2 bpdu-protection
aaa port-access authenticator 1-2 control auto
"""


def run(tmp_path, body, header=H10, roles=None):
    """Return ({control: item}, fired rule IDs); asserts the completion invariants."""
    path = tmp_path / "switch.conf"
    path.write_text(header + body, encoding="utf-8")
    parser = HPProCurveParser(str(path))
    if roles is not None:
        parser.set_assessment_context(AssessmentContext.from_mapping({"interface_roles": roles}))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_hp_conf(parser)
    rules = {issue.rule_id for issue in findings.values()}
    coverage = {item["control-id"]: item for item in control_coverage(parser)["results"]}
    for control in HP_CONTROLS:
        outcome = coverage[control]["outcome"]
        assert outcome != "not-recorded", control
        assert (outcome == "finding") == bool(set(CONTROLS[control].rule_ids) & rules), (control, outcome, rules)
    return coverage, rules


def outcome(tmp_path, control, body, header=H10, roles=None):
    return run(tmp_path, body, header, roles)[0][control]["outcome"]


def test_hp_controls_are_registered_with_versions():
    assert len(HP_CONTROLS) == 23
    for control in HP_CONTROLS:
        definition = CONTROLS[control]
        assert definition.version == 1 and definition.rule_ids
        assert definition.device_types == frozenset({"HP_PROCURVE"})


def test_every_recorded_hp_control_is_registered(tmp_path):
    for body, header, roles in ((SECURE, H10, None), ("", H10, None), ("", H0, None), (EDGE, H11, EDGE_ROLES)):
        path = tmp_path / "switch.conf"
        path.write_text(header + body, encoding="utf-8")
        parser = HPProCurveParser(str(path))
        if roles:
            parser.set_assessment_context(AssessmentContext.from_mapping({"interface_roles": roles}))
        with contextlib.redirect_stdout(io.StringIO()):
            process_hp_conf(parser)
        recorded = {item["control-id"] for item in control_coverage(parser)["results"]
                    if item["outcome"] != "not-recorded"}
        assert {control for control in recorded if control.startswith("hp.")} <= set(CONTROLS)
        assert set(HP_CONTROLS) <= recorded


def test_every_emitted_rule_is_mapped():
    import pathlib
    import re
    source = pathlib.Path("src/analyze/hp/plugins/hp_checks_plugin.py").read_text(encoding="utf-8")
    emitted = set(re.findall(r'"(hp\.procurve\.[a-z0-9_.]+)"', source)) - set(CONTROLS)
    emitted |= {f"hp.procurve.layer2.access_edge.{suffix}" for suffix in ("arp_protection", "source_lockdown", "port_security")}
    mapped = {rule for control in HP_CONTROLS for rule in CONTROLS[control].rule_ids}
    assert emitted == mapped
    assert set(re.findall(r'"(hp\.procurve\.[a-z0-9-]+)"', source)) <= set(CONTROLS)


def test_secure_baseline_has_no_hp_control_finding(tmp_path):
    coverage, _ = run(tmp_path, SECURE)
    findings = [control for control in HP_CONTROLS if coverage[control]["outcome"] == "finding"]
    assert findings == []


@pytest.mark.parametrize("control,body,header,expected", [
    # Clear-text management (per protocol); omitted telnet/web on 16.10 is a documented-default finding.
    ("hp.procurve.cleartext-management", "", H10, "finding"),
    ("hp.procurve.cleartext-management", "no telnet-server\n", H10, "finding"),
    ("hp.procurve.cleartext-management", "no telnet-server\nno web-management\n", H10, "evaluated-no-finding"),
    ("hp.procurve.cleartext-management", "", H0, "unknown"),
    # Management source restriction.
    ("hp.procurve.management-source-restriction", "ip ssh\n", H10, "finding"),
    ("hp.procurve.management-source-restriction", "ip ssh\nip authorized-managers 192.0.2.1 255.255.255.255\n", H10, "evaluated-no-finding"),
    ("hp.procurve.management-source-restriction", "", H10, "not-applicable"),
    ("hp.procurve.management-source-restriction", "", H0, "unknown"),
    # SNMP communities.
    ("hp.procurve.snmp-community", 'snmp-server community "public" operator restricted\n', H10, "finding"),
    ("hp.procurve.snmp-community", 'snmp-server community "n0tDefault" unrestricted\n', H10, "finding"),
    ("hp.procurve.snmp-community", 'snmp-server community "n0tDefault" operator restricted\n', H10, "evaluated-no-finding"),
    ("hp.procurve.snmp-community", "", H10, "not-applicable"),
    # SNMPv3 secure user alongside communities.
    ("hp.procurve.snmpv3-secure-user", 'snmp-server community "n0tDefault" operator restricted\n', H10, "finding"),
    ("hp.procurve.snmpv3-secure-user", 'snmp-server community "n0tDefault" operator restricted\n'
     "snmpv3 user mon auth sha a-secret priv aes p-secret\n", H10, "evaluated-no-finding"),
    ("hp.procurve.snmpv3-secure-user", "", H10, "not-applicable"),
    # SNMPv3 user protection.
    ("hp.procurve.snmpv3-user-protection", "snmpv3 user mon auth md5 a-secret priv aes p-secret\n", H10, "finding"),
    ("hp.procurve.snmpv3-user-protection", "snmpv3 user mon auth sha a-secret\n", H10, "finding"),
    ("hp.procurve.snmpv3-user-protection", "snmpv3 user mon auth sha a-secret priv aes p-secret\n", H10, "evaluated-no-finding"),
    ("hp.procurve.snmpv3-user-protection", "snmpv3 user mon auth a-secret priv aes p-secret\n", H10, "unknown"),
    ("hp.procurve.snmpv3-user-protection", "", H10, "not-applicable"),
    ("hp.procurve.snmpv3-user-protection", "no snmpv3 enable\nsnmpv3 user mon auth md5 a priv des p\n", H10, "not-applicable"),
    # SNMPv3 source restriction.
    ("hp.procurve.snmpv3-source-restriction", "snmpv3 user mon auth sha a-secret priv aes p-secret\n", H10, "finding"),
    ("hp.procurve.snmpv3-source-restriction", "snmpv3 user mon auth sha a-secret priv aes p-secret\n"
     "ip authorized-managers 192.0.2.1 255.255.255.255\n", H10, "evaluated-no-finding"),
    ("hp.procurve.snmpv3-source-restriction", "", H10, "not-applicable"),
    # SSH algorithms.
    ("hp.procurve.ssh-algorithms", "ip ssh\n", H10, "finding"),
    ("hp.procurve.ssh-algorithms", SECURE, H10, "evaluated-no-finding"),
    ("hp.procurve.ssh-algorithms", SECURE, H11, "evaluated-no-finding"),
    ("hp.procurve.ssh-algorithms", "ip ssh\nno ip ssh cipher 3des-cbc\n", H11, "unknown"),
    ("hp.procurve.ssh-algorithms", "ip ssh\nip ssh mac hmac-md5\n", H11, "finding"),
    ("hp.procurve.ssh-algorithms", "no ip ssh\n", H10, "not-applicable"),
    ("hp.procurve.ssh-algorithms", "", H0, "unknown"),
    # Centralized authentication.
    ("hp.procurve.centralized-authentication", "ip ssh\n", H10, "finding"),
    ("hp.procurve.centralized-authentication", "aaa authentication ssh login tacacs local\n", H10, "evaluated-no-finding"),
    ("hp.procurve.centralized-authentication", "no telnet-server\nno web-management\n", H10, "not-applicable"),
    ("hp.procurve.centralized-authentication", "", H0, "unknown"),
    # Manager credential with effective local authentication.
    ("hp.procurve.manager-credential", "include-credentials\n", H10, "finding"),
    ("hp.procurve.manager-credential", "password manager user-name admin sha256 0123abcd\n", H10, "evaluated-no-finding"),
    ("hp.procurve.manager-credential", "", H10, "unknown"),
    ("hp.procurve.manager-credential", "", H0, "unknown"),
    # Administrative authentication methods (per channel/level).
    ("hp.procurve.admin-authentication-methods", "aaa authentication console enable local authorized\n", H10, "finding"),
    ("hp.procurve.admin-authentication-methods", "aaa authentication console login radius local\n", H10, "evaluated-no-finding"),
    ("hp.procurve.admin-authentication-methods", "", H0, "unknown"),
    # Login banner.
    ("hp.procurve.login-banner", "", H10, "finding"),
    ("hp.procurve.login-banner", 'banner motd "Authorized use only"\n', H10, "evaluated-no-finding"),
    ("hp.procurve.login-banner", "", H0, "unknown"),
    # Idle timeouts (per channel); the remote CLI default is disabled.
    ("hp.procurve.idle-timeout", "", H10, "finding"),
    ("hp.procurve.idle-timeout", "console idle-timeout 600\nconsole idle-timeout serial-usb 300\n", H10, "evaluated-no-finding"),
    ("hp.procurve.idle-timeout", "console idle-timeout 7200\n", H10, "finding"),
    ("hp.procurve.idle-timeout", "", H0, "unknown"),
    # Management accounting.
    ("hp.procurve.management-accounting", "aaa authentication ssh login radius local\n", H10, "finding"),
    ("hp.procurve.management-accounting", "aaa authentication ssh login radius local\n"
     "aaa accounting exec start-stop radius\n", H10, "evaluated-no-finding"),
    ("hp.procurve.management-accounting", "", H10, "not-applicable"),
    # Password complexity.
    ("hp.procurve.password-complexity", "password manager user-name admin sha256 0123abcd\n", H10, "finding"),
    ("hp.procurve.password-complexity", "password manager user-name admin sha256 0123abcd\n"
     "password configuration-control\n", H10, "evaluated-no-finding"),
    ("hp.procurve.password-complexity", "include-credentials\n", H10, "not-applicable"),
    ("hp.procurve.password-complexity", "", H10, "unknown"),
    # DHCP snooping (per VLAN).
    ("hp.procurve.dhcp-snooping", "vlan 10\n", H10, "finding"),
    ("hp.procurve.dhcp-snooping", "vlan 10\ndhcp-snooping vlan 10\n", H10, "evaluated-no-finding"),
    ("hp.procurve.dhcp-snooping", "vlan 10\ndhcp-snooping vlan 10\n", H11, "evaluated-no-finding"),
    ("hp.procurve.dhcp-snooping", "vlan 10\n", H11, "unknown"),
    ("hp.procurve.dhcp-snooping", "", H10, "not-applicable"),
    # Remote logging.
    ("hp.procurve.remote-logging", "", H10, "finding"),
    ("hp.procurve.remote-logging", "logging 192.0.2.20\nno debug destination logging\n", H10, "finding"),
    ("hp.procurve.remote-logging", "logging 192.0.2.20\n", H10, "evaluated-no-finding"),
    # Remote Event Log forwarding.
    ("hp.procurve.remote-event-logging", "logging 192.0.2.20\nno debug event\n", H10, "finding"),
    ("hp.procurve.remote-event-logging", "logging 192.0.2.20\nlogging severity major\n", H11, "finding"),
    ("hp.procurve.remote-event-logging", "logging 192.0.2.20\nlogging severity error\n", H10, "evaluated-no-finding"),
    ("hp.procurve.remote-event-logging", "logging 192.0.2.20\n", H10, "evaluated-no-finding"),
    ("hp.procurve.remote-event-logging", "logging 192.0.2.20\nlogging severity bogus\n", H10, "unknown"),
    ("hp.procurve.remote-event-logging", "logging 192.0.2.20\nno debug event\n", H0, "unknown"),
    ("hp.procurve.remote-event-logging", "", H10, "not-applicable"),
    # SNTP servers.
    ("hp.procurve.ntp-servers", "", H10, "finding"),
    ("hp.procurve.ntp-servers", "sntp server priority 1 192.0.2.30\n", H10, "evaluated-no-finding"),
    # SNTP authentication (per server).
    ("hp.procurve.ntp-authentication", "sntp server priority 1 192.0.2.30\n", H10, "finding"),
    ("hp.procurve.ntp-authentication", "sntp authentication\nsntp server priority 1 192.0.2.30 key-id 9\n", H10, "finding"),
    ("hp.procurve.ntp-authentication", "sntp authentication\n"
     "sntp authentication key-id 55 authentication-mode md5 key-value ciphertext trusted\n"
     "sntp server priority 1 192.0.2.30 key-id 55\n", H11, "evaluated-no-finding"),
    ("hp.procurve.ntp-authentication", "sntp server priority 1 192.0.2.30\n", H0, "unknown"),
    ("hp.procurve.ntp-authentication", "", H10, "not-applicable"),
])
def test_device_and_service_controls(tmp_path, control, body, header, expected):
    assert outcome(tmp_path, control, body, header) == expected


@pytest.mark.parametrize("control,extra,expected", [
    ("hp.procurve.access-edge-vlan-trust", "", "evaluated-no-finding"),
    ("hp.procurve.access-edge-vlan-trust", "dhcp-snooping trust 1\n", "finding"),
    ("hp.procurve.access-edge-vlan-trust", "vlan 20\n tagged 2\n", "finding"),
    ("hp.procurve.access-edge-dot1x", "", "evaluated-no-finding"),
    ("hp.procurve.access-edge-dot1x", "aaa port-access authenticator 2 control authorized\n", "finding"),
    ("hp.procurve.access-edge-dot1x", "no aaa port-access authenticator 1-2\n", "not-applicable"),
    ("hp.procurve.access-edge-bpdu-protection", "", "evaluated-no-finding"),
    ("hp.procurve.access-edge-bpdu-protection", "no spanning-tree 1 bpdu-protection\n", "finding"),
    ("hp.procurve.access-edge-bpdu-protection", "spanning-tree 2 bpdu-filter\n", "finding"),
    # Omitted per-port BPDU protection is known state; the check reports only explicit disablement.
    ("hp.procurve.access-edge-bpdu-protection", "no spanning-tree 1-2 bpdu-protection\nspanning-tree 1-2 bpdu-protection\n", "evaluated-no-finding"),
    ("hp.procurve.access-edge-spoofing-protection", "", "evaluated-no-finding"),
    ("hp.procurve.access-edge-spoofing-protection", "no port-security 2\n", "finding"),
    ("hp.procurve.access-edge-spoofing-protection", "no ip source-lockdown 1\n", "finding"),
])
def test_access_edge_controls(tmp_path, control, extra, expected):
    assert outcome(tmp_path, control, EDGE + extra, H11, EDGE_ROLES) == expected


def test_access_edge_omitted_bpdu_protection_is_evaluated(tmp_path):
    body = EDGE.replace("spanning-tree 1-2 bpdu-protection\n", "")
    assert outcome(tmp_path, "hp.procurve.access-edge-bpdu-protection", body, H11, EDGE_ROLES) == "evaluated-no-finding"


def test_access_edge_controls_are_per_port(tmp_path):
    coverage, _ = run(tmp_path, EDGE + "aaa port-access authenticator 2 control authorized\n", H11, EDGE_ROLES)
    instances = {item["instance-key"]: item["outcome"] for item in coverage["hp.procurve.access-edge-dot1x"]["instances"]}
    assert instances == {"port 1": "evaluated-no-finding", "port 2": "finding"}


def test_access_edge_not_applicable_and_unknown(tmp_path):
    for control in ("hp.procurve.access-edge-vlan-trust", "hp.procurve.access-edge-dot1x",
                    "hp.procurve.access-edge-bpdu-protection", "hp.procurve.access-edge-spoofing-protection"):
        assert outcome(tmp_path, control, EDGE, H11) == "not-applicable"
        assert outcome(tmp_path, control, EDGE, H11, {"24": "uplink"}) == "not-applicable"
        assert outcome(tmp_path, control, EDGE, "; J9772A Configuration Editor; Created on release #KB.15.18.0001\n",
                       EDGE_ROLES) == "unknown"


def test_tagged_access_edge_leaves_other_edge_controls_unevaluated(tmp_path):
    coverage, _ = run(tmp_path, EDGE + "vlan 20\n tagged 1-2\n", H11, EDGE_ROLES)
    assert coverage["hp.procurve.access-edge-vlan-trust"]["outcome"] == "finding"
    assert coverage["hp.procurve.access-edge-dot1x"]["outcome"] == "unknown"


def test_unknown_release_records_every_control(tmp_path):
    coverage, _ = run(tmp_path, "", H0)
    assert all(coverage[control]["outcome"] != "not-recorded" for control in HP_CONTROLS)
