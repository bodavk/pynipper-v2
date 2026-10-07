"""SC-049 completion for cisco.ios: management-plane control outcomes (IOS/IOS-XE)."""

import contextlib
import io

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.analyze.cisco.iosxe.core.process_iosxe_conf import process_iosxe_conf
from src.analyze.common.controls import CONTROLS, control_coverage
from src.common.assessment import AssessmentContext
from src.devices import get_parser

HEADERS = {
    "IOS_ROUTER": "version 15.4\nhostname r1\n!\n",
    "IOS_SWITCH": "version 15.2\nhostname sw1\n!\n",
    "IOS_XE": "version 17.9\nhostname xe1\n!\n",
}
PROCESSORS = {"IOS_ROUTER": process_cisco_ios_conf, "IOS_SWITCH": process_cisco_ios_conf, "IOS_XE": process_iosxe_conf}
# Controls added by the SC-049 completion for this vendor group.
COMPLETION = tuple(
    control for control in CONTROLS
    if control.startswith(("cisco.ios.", "cisco.iosxe.")) and control not in {
        "cisco.ios.smart-install", "cisco.ios.pptp-dialin", "cisco.ios.ldap-transport", "cisco.ios.vty-transport",
        "cisco.ios.ssh-protocol", "cisco.ios.snmp-community", "cisco.ios.ntp-authentication",
        "cisco.ios.remote-logging", "cisco.ios.http-server",
    }
)
SECRET = "secret 9 $9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM"
USER = f"username admin privilege 15 {SECRET}\n"


def run(tmp_path, body, device="IOS_ROUTER", policy=None, header=None):
    """Return {control: item} and the fired rule IDs; asserts the completion invariants."""
    path = tmp_path / "device.conf"
    path.write_text((HEADERS[device] if header is None else header) + body + "end\n", encoding="utf-8")
    parser = get_parser(device, str(path))
    if policy:
        parser.set_assessment_context(AssessmentContext.from_mapping(policy))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = PROCESSORS[device](parser)
    rules = {issue.rule_id for issue in findings.values()}
    coverage = {item["control-id"]: item for item in control_coverage(parser)["results"]}
    for control in COMPLETION:
        if control not in coverage:
            continue
        outcome = coverage[control]["outcome"]
        assert outcome != "not-recorded", control
        assert (outcome == "finding") == bool(set(CONTROLS[control].rule_ids) & rules), (control, outcome)
    return coverage, rules


def outcome(tmp_path, control, body, device="IOS_ROUTER", policy=None, header=None):
    return run(tmp_path, body, device, policy, header)[0][control]["outcome"]


def test_completion_controls_are_registered_with_versions():
    assert len(COMPLETION) == 67
    for control in COMPLETION:
        definition = CONTROLS[control]
        assert definition.version == 1 and definition.rule_ids and definition.device_types


def test_unknown_release_records_unknown_instead_of_not_recorded(tmp_path):
    coverage, _ = run(tmp_path, "line vty 0 4\n transport input ssh\n", header="hostname r1\n!\n")
    assert coverage["cisco.ios.aaa-baseline"]["outcome"] == "unknown"
    assert coverage["cisco.ios.control-plane-policing"]["outcome"] == "unknown"


AAA = "aaa new-model\naaa authentication login VTY local\n"
VTY_AAA = "line vty 0 4\n login authentication VTY\n transport input ssh\n"
AUTHZ = ("aaa authorization exec default local\naaa authorization commands 15 default local\n")
ACCT = ("aaa accounting exec default start-stop group tacacs+\n"
        "aaa accounting commands 15 default start-stop group tacacs+\n")


@pytest.mark.parametrize("control,body,expected", [
    ("cisco.ios.aaa-baseline", "", "finding"),
    ("cisco.ios.aaa-baseline", "aaa new-model\n", "finding"),
    ("cisco.ios.aaa-baseline", AAA + ACCT, "evaluated-no-finding"),
    ("cisco.ios.line-timeout", "line vty 0 4\n exec-timeout 30 0\n transport input ssh\n", "finding"),
    ("cisco.ios.line-timeout", "line con 0\n exec-timeout 0 0\n", "finding"),
    ("cisco.ios.line-timeout", "line vty 0 4\n exec-timeout 5 0\n transport input ssh\n", "evaluated-no-finding"),
    ("cisco.ios.line-timeout", "line vty 0 4\n transport input ssh\n", "evaluated-no-finding"),
    ("cisco.ios.line-timeout", "", "unknown"),
    ("cisco.ios.vty-output-transport", "line vty 0 4\n transport input ssh\n transport output telnet\n", "finding"),
    ("cisco.ios.vty-output-transport", "line vty 0 4\n transport input ssh\n transport output ssh\n",
     "evaluated-no-finding"),
    ("cisco.ios.vty-output-transport", "", "unknown"),
    ("cisco.ios.console-authentication", "line con 0\n", "finding"),
    ("cisco.ios.console-authentication", USER + "line con 0\n login local\n", "evaluated-no-finding"),
    ("cisco.ios.console-authentication", "", "unknown"),
    ("cisco.ios.aux-line", "line aux 0\n", "finding"),
    ("cisco.ios.aux-line", "line aux 0\n no exec\n transport input none\n transport output none\n",
     "evaluated-no-finding"),
    ("cisco.ios.aux-line", "", "not-applicable"),
    ("cisco.ios.vty-authentication", "line vty 0 4\n transport input ssh\n", "finding"),
    ("cisco.ios.vty-authentication", USER + "line vty 0 4\n login local\n transport input ssh\n", "evaluated-no-finding"),
    ("cisco.ios.vty-authentication", "", "unknown"),
    ("cisco.ios.vty-authorization", USER + AAA + VTY_AAA, "finding"),
    ("cisco.ios.vty-authorization", USER + AAA + AUTHZ + VTY_AAA, "evaluated-no-finding"),
    ("cisco.ios.vty-authorization", USER + AAA + "aaa authorization exec default if-authenticated\n"
     "aaa authorization commands 15 default local\n" + VTY_AAA, "finding"),
    ("cisco.ios.vty-authorization", USER + "line vty 0 4\n login local\n transport input ssh\n", "not-applicable"),
    ("cisco.ios.vty-accounting", USER + AAA + VTY_AAA, "not-applicable"),
    ("cisco.ios.vty-accounting", USER + AAA + ACCT + VTY_AAA, "evaluated-no-finding"),
    ("cisco.ios.vty-accounting", USER + AAA + "aaa accounting exec default none\n" + VTY_AAA, "finding"),
    ("cisco.ios.vty-accounting", USER + AAA + "aaa accounting exec OTHER start-stop group tacacs+\n" + VTY_AAA,
     "finding"),
    ("cisco.ios.vty-aaa-server-groups", USER + "aaa new-model\naaa authentication login VTY group TAC local\n"
     + VTY_AAA, "finding"),
    ("cisco.ios.vty-aaa-server-groups", USER + "aaa new-model\naaa authentication login VTY group TAC local\n"
     "aaa group server tacacs+ TAC\n server name T1\n" + VTY_AAA, "evaluated-no-finding"),
    ("cisco.ios.vty-aaa-server-groups", USER + AAA + VTY_AAA, "not-applicable"),
])
def test_line_and_aaa_controls(tmp_path, control, body, expected):
    assert outcome(tmp_path, control, body) == expected


def test_line_timeout_is_per_line(tmp_path):
    item = run(tmp_path, "line con 0\n exec-timeout 5 0\nline vty 0 4\n exec-timeout 60 0\n"
                         " transport input ssh\n")[0]["cisco.ios.line-timeout"]
    states = {row["instance-key"]: row["outcome"] for row in item["instances"]}
    assert item["outcome"] == "finding"
    assert states["line con 0"] == "evaluated-no-finding" and states["line vty 0 4"] == "finding"


SSH = "ip ssh version 2\nline vty 0 4\n transport input ssh\n"
ALGS = ("ip ssh server algorithm encryption aes256-ctr\nip ssh server algorithm mac hmac-sha2-256\n"
        "ip ssh server algorithm kex ecdh-sha2-nistp256\nip ssh server algorithm hostkey rsa-sha2-256\n")


@pytest.mark.parametrize("control,body,expected,device", [
    ("cisco.ios.ssh-algorithms", SSH + "ip ssh server algorithm encryption aes128-cbc aes256-ctr\n", "finding",
     "IOS_ROUTER"),
    ("cisco.ios.ssh-algorithms", SSH + ALGS, "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.ssh-algorithms", SSH, "unknown", "IOS_ROUTER"),
    ("cisco.ios.ssh-algorithms", SSH, "finding", "IOS_XE"),
    ("cisco.ios.ssh-algorithms", "", "not-applicable", "IOS_ROUTER"),
    ("cisco.ios.ssh-host-key", SSH + "crypto key generate rsa modulus 1024\n", "finding", "IOS_ROUTER"),
    ("cisco.ios.ssh-host-key", SSH + "crypto key generate rsa modulus 4096\n", "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.ssh-host-key", SSH, "unknown", "IOS_ROUTER"),
    ("cisco.ios.ssh-host-key", "", "not-applicable", "IOS_ROUTER"),
    ("cisco.ios.ssh-limits", SSH + "ip ssh authentication-retries 10\n", "finding", "IOS_ROUTER"),
    ("cisco.ios.ssh-limits", SSH + "ip ssh time-out 120\n", "finding", "IOS_ROUTER"),
    ("cisco.ios.ssh-limits", SSH + "ip ssh time-out 60\nip ssh authentication-retries 3\n", "evaluated-no-finding",
     "IOS_ROUTER"),
    ("cisco.ios.ssh-limits", "", "not-applicable", "IOS_ROUTER"),
    ("cisco.ios.ssh-source-restriction", SSH, "finding", "IOS_ROUTER"),
    ("cisco.ios.ssh-source-restriction", "access-list 10 permit any\nip ssh version 2\nline vty 0 4\n"
     " access-class 10 in\n transport input ssh\n", "finding", "IOS_ROUTER"),
    ("cisco.ios.ssh-source-restriction", "access-list 10 permit 192.0.2.0 0.0.0.255\nip ssh version 2\n"
     "line vty 0 4\n access-class 10 in\n transport input ssh\n", "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.ssh-source-restriction", "ip ssh version 2\nline vty 0 4\n access-class 10 in\n"
     " transport input ssh\n", "unknown", "IOS_ROUTER"),
    ("cisco.ios.ssh-source-restriction", "", "not-applicable", "IOS_ROUTER"),
    ("cisco.ios.ssh-pubkey-hash", "ip ssh pubkey-chain\n username admin\n  key-hash ssh-rsa "
     "0123456789abcdef0123456789abcdef\n", "finding", "IOS_XE"),
    ("cisco.ios.ssh-pubkey-hash", "", "evaluated-no-finding", "IOS_XE"),
])
def test_ssh_controls(tmp_path, control, body, expected, device):
    assert outcome(tmp_path, control, body, device) == expected


HTTP = "ip http server\n"
HTTPS = "ip http secure-server\n"


@pytest.mark.parametrize("control,body,expected,device", [
    ("cisco.ios.http-authentication", HTTP, "finding", "IOS_ROUTER"),
    ("cisco.ios.http-authentication", HTTP + "ip http authentication local\n", "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.http-authentication", "no ip http server\n", "not-applicable", "IOS_ROUTER"),
    ("cisco.ios.web-acl-sources", "access-list 20 permit any\n" + HTTPS + "ip http access-class 20\n", "finding",
     "IOS_ROUTER"),
    ("cisco.ios.web-acl-sources", "access-list 20 permit 192.0.2.0 0.0.0.255\n" + HTTPS + "ip http access-class 20\n",
     "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.web-acl-sources", HTTPS + "ip http access-class 20\n", "unknown", "IOS_ROUTER"),
    ("cisco.ios.web-acl-sources", HTTPS, "not-applicable", "IOS_ROUTER"),
    ("cisco.ios.web-acl-sources", "ipv6 access-list V6\n permit ipv6 any any\n" + HTTPS
     + "ip http access-class ipv6 V6\n", "finding", "IOS_XE"),
    ("cisco.ios.https-tls", HTTPS + "ip http tls-version TLSv1.1\n", "finding", "IOS_ROUTER"),
    ("cisco.ios.https-tls", HTTPS + "ip http secure-ciphersuite aes-128-cbc-sha\n", "finding", "IOS_ROUTER"),
    ("cisco.ios.https-tls", HTTPS + "ip http tls-version TLSv1.2\n"
     "ip http secure-ciphersuite ecdhe-rsa-aes-gcm-sha2\n", "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.https-tls", HTTPS, "unknown", "IOS_ROUTER"),
    ("cisco.ios.https-tls", "", "not-applicable", "IOS_ROUTER"),
    ("cisco.ios.https-certificate", HTTPS, "unknown", "IOS_ROUTER"),
    ("cisco.ios.https-certificate", "", "not-applicable", "IOS_ROUTER"),
    ("cisco.ios.programmability-acl", "ip access-list standard NC\n permit any\nnetconf-yang\n"
     "netconf-yang ssh ipv4 access-list name NC\n", "finding", "IOS_XE"),
    ("cisco.ios.programmability-acl", "ip access-list standard NC\n permit 192.0.2.0 0.0.0.255\nnetconf-yang\n"
     "netconf-yang ssh ipv4 access-list name NC\n", "evaluated-no-finding", "IOS_XE"),
    ("cisco.ios.programmability-acl", "netconf-yang\nnetconf-yang ssh ipv4 access-list name NC\n", "unknown",
     "IOS_XE"),
    ("cisco.ios.programmability-acl", "", "not-applicable", "IOS_XE"),
    ("cisco.ios.gnmi-tls", "gnxi\ngnxi server\n", "finding", "IOS_XE"),
    ("cisco.ios.gnmi-tls", "gnxi\ngnxi secure-server\n", "evaluated-no-finding", "IOS_XE"),
    ("cisco.ios.webauth-https", "secure-webauth-disable\n", "finding", "IOS_XE"),
    ("cisco.ios.webauth-https", "", "evaluated-no-finding", "IOS_XE"),
    ("cisco.ios.login-lockout", "", "finding", "IOS_ROUTER"),
    ("cisco.ios.login-lockout", "login block-for 120 attempts 3 within 60\n", "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.login-banner", "", "finding", "IOS_ROUTER"),
    ("cisco.ios.login-banner", "banner login ^CAuthorized use only^C\n", "evaluated-no-finding", "IOS_ROUTER"),
    ("cisco.ios.insecure-mode", "system mode insecure\n", "finding", "IOS_XE"),
    ("cisco.ios.insecure-mode", "", "evaluated-no-finding", "IOS_XE"),
])
def test_web_and_management_controls(tmp_path, control, body, expected, device):
    assert outcome(tmp_path, control, body, device) == expected


@pytest.mark.parametrize("control,body,expected", [
    ("cisco.ios.credential-storage", "username admin password 0 Cisco123\n", "finding"),
    ("cisco.ios.credential-storage", "enable password 7 0822455D0A16\n", "finding"),
    ("cisco.ios.credential-storage", "enable " + SECRET + "\n" + USER, "evaluated-no-finding"),
    ("cisco.ios.credential-storage", "", "not-applicable"),
    ("cisco.ios.embedded-credentials", "ip ftp password Cleartext1\n", "finding"),
    ("cisco.ios.embedded-credentials", "", "evaluated-no-finding"),
    ("cisco.ios.enable-secret", "line con 0\n password 7 0822455D0A16\n login\n", "finding"),
    ("cisco.ios.enable-secret", "enable " + SECRET + "\nline con 0\n password 7 0822455D0A16\n login\n",
     "evaluated-no-finding"),
    ("cisco.ios.enable-secret", "aaa new-model\nline con 0\n password 7 0822455D0A16\n", "not-applicable"),
    ("cisco.ios.tacacs-keys", "aaa new-model\naaa authentication login default group tacacs+ local\n"
     "tacacs server T1\n address ipv4 192.0.2.5\n", "finding"),
    ("cisco.ios.tacacs-keys", "aaa new-model\naaa authentication login default group tacacs+ local\n"
     "tacacs server T1\n address ipv4 192.0.2.5\n key 6 ABCDEFGHIJKLMNOP\n", "evaluated-no-finding"),
    ("cisco.ios.tacacs-keys", "", "not-applicable"),
    ("cisco.ios.snmpv3-users", "snmp-server group G v3 auth\nsnmp-server user u1 G v3 auth md5 AUTHKEY12\n", "finding"),
    ("cisco.ios.snmpv3-users", "snmp-server user u1 MISSING v3 auth sha AUTHKEY12 priv aes 128 PRIVKEY12\n", "finding"),
    ("cisco.ios.snmpv3-users", "access-list 30 permit 192.0.2.0 0.0.0.255\nsnmp-server view V ifMIB included\n"
     "snmp-server group G v3 priv read V access 30\n"
     "snmp-server user u1 G v3 auth sha AUTHKEY12 priv aes 128 PRIVKEY12\n", "evaluated-no-finding"),
    ("cisco.ios.snmpv3-users", "", "not-applicable"),
    ("cisco.ios.snmp-notifications", "snmp-server host 192.0.2.9 version 2c COMMUNITY1\n", "finding"),
    ("cisco.ios.snmp-notifications", "snmp-server host 192.0.2.9 version 3 priv u1\n", "evaluated-no-finding"),
    ("cisco.ios.snmp-notifications", "", "not-applicable"),
    ("cisco.ios.syslog-transport", "logging host 192.0.2.10\n", "finding"),
    ("cisco.ios.syslog-transport", "logging host 192.0.2.10 transport tls port 6514\n", "evaluated-no-finding"),
    ("cisco.ios.syslog-transport", "", "not-applicable"),
    ("cisco.ios.syslog-severity", "logging host 192.0.2.10\nlogging trap warnings\n", "finding"),
    ("cisco.ios.syslog-severity", "logging host 192.0.2.10\nlogging trap informational\n", "evaluated-no-finding"),
    ("cisco.ios.syslog-severity", "", "not-applicable"),
    ("cisco.ios.config-change-logging", "", "finding"),
    ("cisco.ios.config-change-logging", "archive\n log config\n  logging enable\n", "finding"),
    ("cisco.ios.config-change-logging", "archive\n log config\n  logging enable\n  notify syslog contenttype plaintext\n"
     "  hidekeys\n", "evaluated-no-finding"),
    ("cisco.ios.config-archive", "archive\n path tftp://192.0.2.4/r1\n write-memory\n", "finding"),
    ("cisco.ios.config-archive", "archive\n path flash:r1\n", "finding"),
    ("cisco.ios.config-archive", "archive\n path scp://192.0.2.4/r1\n write-memory\n", "evaluated-no-finding"),
    ("cisco.ios.config-archive", "", "not-applicable"),
    ("cisco.ios.ntp-servers", "", "finding"),
    ("cisco.ios.ntp-servers", "ntp server 192.0.2.1\n", "evaluated-no-finding"),
    ("cisco.ios.ntp-access", "ntp server 192.0.2.1\n", "finding"),
    ("cisco.ios.ntp-access", "ntp server 192.0.2.1\nntp access-group peer 40\n", "evaluated-no-finding"),
    ("cisco.ios.ntp-access", "", "not-applicable"),
])
def test_credential_aaa_snmp_logging_controls(tmp_path, control, body, expected):
    assert outcome(tmp_path, control, body) == expected


def test_config_archive_required_by_policy(tmp_path):
    assert outcome(tmp_path, "cisco.ios.config-archive", "",
                   policy={"configuration_backup_scope": "on-device-required"}) == "finding"


NTP_MD5 = "ntp authenticate\nntp authentication-key 1 md5 KEYVALUE\nntp trusted-key 1\nntp server 192.0.2.1 key 1\n"


@pytest.mark.parametrize("body,device,expected", [
    (NTP_MD5, "IOS_XE", "finding"),
    ("ntp server 192.0.2.1\n", "IOS_XE", "not-applicable"),
    ("", "IOS_XE", "not-applicable"),
    (NTP_MD5, "IOS_ROUTER", "not-applicable"),
])
def test_ntp_key_algorithm(tmp_path, body, device, expected):
    assert outcome(tmp_path, "cisco.ios.ntp-key-algorithm", body, device) == expected


def test_ntp_key_algorithm_sha2_is_no_finding(tmp_path):
    body = ("ntp authenticate\nntp authentication-key 1 hmac-sha2-256 KEYVALUE\nntp trusted-key 1\n"
            "ntp server 192.0.2.1 key 1\n")
    assert outcome(tmp_path, "cisco.ios.ntp-key-algorithm", body, "IOS_XE") == "evaluated-no-finding"
