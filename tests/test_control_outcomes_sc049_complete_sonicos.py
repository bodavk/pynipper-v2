"""SC-049 completion for sonicwall.sonicos: control outcomes of the SonicOS 7 E-CLI checks."""

import contextlib
import io
import re
from pathlib import Path

import pytest

from src.analyze.common.controls import CONTROLS, control_coverage
from src.analyze.sonicwall.core.process_sonicos_conf import process_sonicos_conf
from src.devices.sonicwall.sonicos import SonicOSParser

PLUGIN = Path(__file__).resolve().parents[1] / "src" / "analyze" / "sonicwall" / "plugins" / "sonicos_checks_plugin.py"
SONICOS = tuple(control for control in CONTROLS if control.startswith("sonicwall.sonicos."))

LEGACY = 'firmware-version "SonicOS 7.1.2-7019"\nfirewall-name "fw"\n'  # documented 7.0-7.2 defaults apply
CURRENT = 'firmware-version "SonicOS 7.3.0-7012"\nfirewall-name "fw"\n'  # release defaults not qualified

LAN = "interface X0\n  zone LAN\n  ip-address 10.0.0.1\n  management https ssh\n"
ADMIN_OK = (
    "administration\n  admin one-time-password totp\n  password minimum-length 12\n"
    "  password complexity alpha-and-numeric-and-symbols\n  idle-logout-time 5\n"
    "  user-lockout\n    failures-per-minute 3\n    lockout-duration 10\n  max-login-attempts-cli 5\n"
    "  no log-without-lockout\n  tls-and-above\n  web-management certificate \"corp\"\n"
)
BANNER = 'cli banner connection "Authorized access only"\n'
RULE_OK = (
    "access-rule ipv4 from LAN to WAN action allow source address any service name HTTPS "
    "destination address any schedule always-on\n  name \"WEB\"\n  enable\n  logging\n"
)
VPN_OK = (
    'vpn policy site-to-site "T1"\n  enable\n  proposal ike encryption aes-256\n'
    "  proposal ike authentication sha256\n  proposal ike dh-group 19\n"
    "  proposal ipsec encryption aes-gcm16-256\n  proposal ipsec authentication sha256\n"
)
OPS_OK = (
    "log syslog server 192.0.2.20 enable\n"
    "ntp-server 192.0.2.30 md5 trust-key-no 1 key-number 1 password redacted\n"
)
SERVICES_OK = (
    "intrusion-prevention\n  enable\n  exit\ngateway-antivirus\n  enable\n  exit\n"
    "anti-spyware\n  enable\n  exit\ncapture-atp\n  enable\n  exit\ncloud-gateway-anti-virus enable\n"
)
ZONE_OK = 'zone "LAN"\n  intrusion-prevention\n  gateway-anti-virus\n  anti-spyware\n  exit\n'
SECURE = LAN + ADMIN_OK + BANNER + RULE_OK + VPN_OK + OPS_OK + SERVICES_OK + ZONE_OK


def run(tmp_path, body, header=LEGACY):
    """Return {control: item} and fired rule IDs; asserts the completion invariants."""
    path = tmp_path / "sonicos.txt"
    path.write_text(header + body, encoding="utf-8")
    parser = SonicOSParser(str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_sonicos_conf(parser)
    rules = {issue.rule_id for issue in findings.values()}
    coverage = {item["control-id"]: item for item in control_coverage(parser)["results"]}
    for control in SONICOS:
        outcome = coverage[control]["outcome"]
        assert outcome != "not-recorded", control
        assert (outcome == "finding") == bool(set(CONTROLS[control].rule_ids) & rules), (control, outcome)
    return coverage, rules


def outcome(tmp_path, control, body, header=LEGACY):
    return run(tmp_path, body, header)[0][control]["outcome"]


def test_sonicos_controls_are_registered_and_cover_emitted_rules():
    assert len(SONICOS) == 23
    source = PLUGIN.read_text(encoding="utf-8")
    recorded = set(re.findall(r'"(sonicwall\.sonicos\.[a-z0-9-]+)"', source))
    emitted = set(re.findall(r'"(sonicwall\.sonicos\.[a-z_0-9]+\.[a-z_0-9]+)"', source))
    assert recorded == set(SONICOS)  # every recorded control is registered and every registered one is recorded
    mapped = {rule for control in SONICOS for rule in CONTROLS[control].rule_ids}
    assert mapped == emitted
    for control in SONICOS:
        definition = CONTROLS[control]
        assert definition.version == 1 and definition.device_types == frozenset({"SONICOS"})


def test_secure_configuration_has_no_findings(tmp_path):
    coverage, rules = run(tmp_path, SECURE)
    assert rules == set()
    for control in SONICOS:
        if control in {"sonicwall.sonicos.snmpv3-security", "sonicwall.sonicos.policy-disabled-permissive"}:
            assert coverage[control]["outcome"] == "not-applicable", control
        else:
            assert coverage[control]["outcome"] == "evaluated-no-finding", control


# --- management ---------------------------------------------------------------

@pytest.mark.parametrize("body,expected", [
    ("interface X0\n  zone LAN\n  management http https\n", "finding"),
    ("interface X0\n  zone LAN\n  management https\n", "evaluated-no-finding"),
    ("interface X0\n  zone LAN\n  management http\n  shutdown\n", "not-applicable"),
    ("interface X0\n  zone LAN\n  management https\n  management http\n", "unknown"),
    ("", "unknown"),
])
def test_management_http(tmp_path, body, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.management-http", body) == expected


@pytest.mark.parametrize("body,expected", [
    ("interface X1\n  zone WAN\n  management https ssh\n", "finding"),
    ("interface X0\n  zone LAN\n  management https ssh\n", "evaluated-no-finding"),
    ("interface X1\n  zone WAN\n  management ping\n", "evaluated-no-finding"),
    ("interface X2\n  zone Partners\n  management ssh\n", "unknown"),
    ("interface X1\n  zone WAN\n  management ssh\n  shutdown\n", "not-applicable"),
])
def test_management_external_exposure(tmp_path, body, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.management-external-exposure", body) == expected


def test_management_is_per_interface(tmp_path):
    body = "interface X0\n  zone LAN\n  management https\ninterface X1\n  zone WAN\n  management http ssh\n"
    item = run(tmp_path, body)[0]["sonicwall.sonicos.management-http"]
    assert {row["instance-key"]: row["outcome"] for row in item["instances"]} == {
        "interface X0": "evaluated-no-finding", "interface X1": "finding"}


# --- administration -----------------------------------------------------------

CONFLICT = (
    "user local-users\n  user ops\n    password encrypted SECRET\n"
    '  group "SonicWall Read-Only Admins"\n    member ops\n  group "SonicWall Administrators"\n    member ops\n'
)
READ_ONLY = 'user local-users\n  user ops\n    password encrypted SECRET\n    member-of "SonicWall Read-Only Admins"\n'


@pytest.mark.parametrize("body,expected", [(CONFLICT, "finding"), (READ_ONLY, "evaluated-no-finding")])
def test_admin_role_separation(tmp_path, body, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.admin-role-separation", LAN + body) == expected


@pytest.mark.parametrize("body,header,expected", [
    ("", LEGACY, "finding"),  # documented 7.0-7.2 default: TOTP disabled
    ("administration\n  no admin one-time-password\n", CURRENT, "finding"),
    ("administration\n  admin one-time-password totp\n", LEGACY, "evaluated-no-finding"),
    ("administration\n  idle-logout-time 5\n", CURRENT, "unknown"),
])
def test_admin_mfa(tmp_path, body, header, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.admin-mfa", LAN + body, header) == expected


def test_admin_mfa_not_applicable_for_read_only_account(tmp_path):
    item = run(tmp_path, LAN + "administration\n  admin one-time-password totp\n" + READ_ONLY)[0][
        "sonicwall.sonicos.admin-mfa"]
    assert {row["instance-key"]: row["outcome"] for row in item["instances"]}["administrator ops"] == "not-applicable"


@pytest.mark.parametrize("body,header,expected", [
    ("", LEGACY, "finding"),  # documented minimum length 8 and complexity none
    ("administration\n  password minimum-length 14\n  password complexity alpha-and-numeric-and-symbols\n"
     "  password constraints-apply-to builtin-admin full-admins\n", CURRENT, "finding"),
    ("administration\n  password minimum-length 12\n  password complexity alpha-and-numeric-and-symbols\n",
     LEGACY, "evaluated-no-finding"),
    ("administration\n  password minimum-length 14\n", CURRENT, "unknown"),
])
def test_password_policy(tmp_path, body, header, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.password-policy", LAN + body, header) == expected


@pytest.mark.parametrize("body,header,expected", [
    ("", LEGACY, "finding"),  # documented default: lockout disabled
    ("administration\n  user-lockout\n    failures-per-minute 10\n    lockout-duration 10\n", LEGACY, "finding"),
    ("administration\n  user-lockout\n    failures-per-minute 3\n    lockout-duration 10\n  log-without-lockout\n",
     LEGACY, "finding"),
    ("administration\n  user-lockout\n    failures-per-minute 3\n    lockout-duration 10\n", LEGACY,
     "evaluated-no-finding"),
    ("administration\n  idle-logout-time 5\n", CURRENT, "unknown"),
])
def test_admin_lockout(tmp_path, body, header, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.admin-lockout", LAN + body, header) == expected


def test_admin_session_controls_not_applicable_without_management(tmp_path):
    coverage, _ = run(tmp_path, "interface X0\n  zone LAN\n  management ping\n")
    for control in ("admin-lockout", "admin-idle-timeout", "cli-login-attempts", "connection-banner",
                    "management-tls-version", "management-certificate", "snmpv3-security"):
        assert coverage[f"sonicwall.sonicos.{control}"]["outcome"] == "not-applicable", control
    coverage, _ = run(tmp_path, "")
    for control in ("admin-lockout", "admin-idle-timeout", "cli-login-attempts", "connection-banner"):
        assert coverage[f"sonicwall.sonicos.{control}"]["outcome"] == "unknown", control


@pytest.mark.parametrize("body,header,expected", [
    ("administration\n  idle-logout-time 30\n", LEGACY, "finding"),
    ("administration\n  idle-logout-time 5\n", CURRENT, "evaluated-no-finding"),
    ("", LEGACY, "evaluated-no-finding"),  # documented default: 5 minutes
    ("administration\n  max-login-attempts-cli 5\n", CURRENT, "unknown"),
])
def test_admin_idle_timeout(tmp_path, body, header, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.admin-idle-timeout", LAN + body, header) == expected


@pytest.mark.parametrize("body,header,expected", [
    (LAN + "administration\n  max-login-attempts-cli 10\n", LEGACY, "finding"),
    (LAN + "administration\n  max-login-attempts-cli 3\n", CURRENT, "evaluated-no-finding"),
    (LAN, CURRENT, "unknown"),
    ("interface X0\n  zone LAN\n  management https\n", LEGACY, "not-applicable"),
])
def test_cli_login_attempts(tmp_path, body, header, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.cli-login-attempts", body, header) == expected


@pytest.mark.parametrize("body,header,expected", [
    (LAN, LEGACY, "finding"),  # documented default: no connection banner
    (LAN + "no cli banner connection\n", CURRENT, "finding"),
    (LAN + BANNER, LEGACY, "evaluated-no-finding"),
    (LAN, CURRENT, "unknown"),
    ("interface X0\n  zone LAN\n  management https\n", LEGACY, "not-applicable"),
])
def test_connection_banner(tmp_path, body, header, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.connection-banner", body, header) == expected


@pytest.mark.parametrize("body,expected", [
    (LAN + "administration\n  no tls-and-above\n", "finding"),
    (LAN + "administration\n  tls-and-above\n", "evaluated-no-finding"),
    (LAN + "administration\n  idle-logout-time 5\n", "unknown"),
    ("interface X0\n  zone LAN\n  management ssh\n", "not-applicable"),
])
def test_management_tls_version(tmp_path, body, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.management-tls-version", body) == expected


@pytest.mark.parametrize("body,header,expected", [
    (LAN, LEGACY, "finding"),  # documented default: self-signed
    (LAN + "administration\n  web-management certificate self-signed\n", CURRENT, "finding"),
    (LAN + "administration\n  web-management certificate \"corp\"\n", LEGACY, "evaluated-no-finding"),
    (LAN, CURRENT, "unknown"),
    ("interface X0\n  zone LAN\n  management ssh\n", LEGACY, "not-applicable"),
])
def test_management_certificate(tmp_path, body, header, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.management-certificate", body, header) == expected


# --- access rules ---------------------------------------------------------------

def _rule(head, *children):
    return "access-rule ipv4 " + head + "\n" + "".join(f"  {child}\n" for child in children)


BROAD = _rule("from any to any action allow source address any service any destination address any schedule always-on",
              'name "BROAD"', "enable", "logging")
ANY_SERVICE = _rule("from LAN to WAN action allow source address any service any destination address any "
                    "schedule always-on", 'name "OUT"', "enable", "logging")
NO_LOG = _rule("from LAN to WAN action allow source address any service name HTTPS destination address any "
               "schedule always-on", 'name "WEB"', "enable", "no logging")
DENY = _rule("from LAN to WAN action deny source address any service any destination address any schedule always-on",
             'name "DROP"', "enable")


@pytest.mark.parametrize("body,expected", [
    (BROAD, "finding"), (ANY_SERVICE, "finding"), (RULE_OK, "evaluated-no-finding"),
    (DENY, "not-applicable"), ("", "unknown"),
])
def test_policy_scope(tmp_path, body, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.policy-scope", LAN + body) == expected


@pytest.mark.parametrize("body,expected", [
    (NO_LOG, "finding"), (RULE_OK, "evaluated-no-finding"), (DENY, "not-applicable"), ("", "unknown"),
])
def test_policy_logging(tmp_path, body, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.policy-logging", LAN + body) == expected


@pytest.mark.parametrize("body,expected", [
    (ANY_SERVICE + DENY, "finding"),  # the deny is fully covered by the earlier allow
    (RULE_OK + DENY, "evaluated-no-finding"),
    (_rule("from LAN to WAN action allow source address name Corp service name HTTPS destination address any "
           "schedule always-on", 'name "OBJ"', "enable", "logging"), "unknown"),
    (_rule("from LAN to WAN action allow source address any service any destination address any "
           "schedule always-on", 'name "OFF"', "no enable"), "not-applicable"),
])
def test_policy_order(tmp_path, body, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.policy-order", LAN + body) == expected


@pytest.mark.parametrize("body,expected", [
    (BROAD.replace("  enable\n", "  no enable\n"), "finding"),
    (ANY_SERVICE.replace("  enable\n", "  no enable\n"), "evaluated-no-finding"),
    (DENY.replace("  enable\n", "  no enable\n"), "not-applicable"),
    (RULE_OK, "not-applicable"),
    ("", "unknown"),
])
def test_policy_disabled_permissive(tmp_path, body, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.policy-disabled-permissive", LAN + body) == expected


# --- VPN, SNMP, logging, NTP ----------------------------------------------------

@pytest.mark.parametrize("body,expected", [
    (VPN_OK.replace("dh-group 19", "dh-group 2"), "finding"),
    (VPN_OK, "evaluated-no-finding"),
    (VPN_OK.replace("  proposal ipsec authentication sha256\n", ""), "unknown"),
    (VPN_OK.replace("  enable\n", "  no enable\n"), "not-applicable"),
    ("", "not-applicable"),
])
def test_vpn_crypto(tmp_path, body, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.vpn-crypto", LAN + body) == expected


SNMP = "interface X0\n  zone LAN\n  management snmp\n"


@pytest.mark.parametrize("body,expected", [
    (SNMP, "finding"),
    (SNMP + "snmp user ops auth sha AUTH priv aes PRIV\nsnmp user old auth md5 AUTH priv des PRIV\n", "finding"),
    (SNMP + "snmp user ops auth sha AUTH priv aes PRIV\n", "evaluated-no-finding"),
    (LAN + "snmp user old auth md5 AUTH priv des PRIV\n", "not-applicable"),
    ("", "unknown"),
])
def test_snmpv3_security(tmp_path, body, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.snmpv3-security", body) == expected


@pytest.mark.parametrize("body,expected", [
    ("", "finding"), ("log syslog server 192.0.2.20 enable\n", "evaluated-no-finding"),
])
def test_remote_logging(tmp_path, body, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.remote-logging", LAN + body) == expected


@pytest.mark.parametrize("body,servers,authentication", [
    ("", "finding", "not-applicable"),
    ("ntp-server 192.0.2.30\n", "evaluated-no-finding", "finding"),
    ("ntp-server 192.0.2.30 md5 trust-key-no 1 key-number 2 password redacted\n", "evaluated-no-finding", "finding"),
    ("ntp-server 192.0.2.30 md5 trust-key-no 1 key-number 1 password redacted\n",
     "evaluated-no-finding", "evaluated-no-finding"),
])
def test_ntp(tmp_path, body, servers, authentication):
    coverage, _ = run(tmp_path, LAN + body)
    assert coverage["sonicwall.sonicos.ntp-servers"]["outcome"] == servers
    assert coverage["sonicwall.sonicos.ntp-authentication"]["outcome"] == authentication


# --- security services ------------------------------------------------------------

@pytest.mark.parametrize("body,expected", [
    (SERVICES_OK.replace("anti-spyware\n  enable\n", "anti-spyware\n  no enable\n"), "finding"),
    (SERVICES_OK, "evaluated-no-finding"),
    ("intrusion-prevention\n  enable\n  exit\n", "unknown"),
])
def test_security_services(tmp_path, body, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.security-services", LAN + body) == expected


@pytest.mark.parametrize("body,expected", [
    (SERVICES_OK + 'zone "LAN"\n  no intrusion-prevention\n  exit\n', "finding"),
    (SERVICES_OK + ZONE_OK, "evaluated-no-finding"),
    (SERVICES_OK + 'zone "LAN"\n  exit\n', "unknown"),
    (SERVICES_OK + 'zone "DMZ"\n  no intrusion-prevention\n  exit\n', "not-applicable"),
    ("intrusion-prevention\n  no enable\n  exit\ngateway-antivirus\n  no enable\n  exit\n"
     "anti-spyware\n  no enable\n  exit\n" + 'zone "LAN"\n  no intrusion-prevention\n  exit\n', "not-applicable"),
    (SERVICES_OK, "unknown"),
])
def test_zone_security_services(tmp_path, body, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.zone-security-services", LAN + body) == expected


@pytest.mark.parametrize("body,expected", [
    ("capture-atp enable\nno cloud-gateway-anti-virus enable\n", "finding"),
    ("capture-atp enable\ngateway-anti-virus enable\ncloud-gateway-anti-virus enable\n", "evaluated-no-finding"),
    ("capture-atp enable\ngateway-anti-virus enable\n", "unknown"),
    ("no capture-atp enable\n", "not-applicable"),
    ("", "unknown"),
])
def test_capture_atp_dependencies(tmp_path, body, expected):
    assert outcome(tmp_path, "sonicwall.sonicos.capture-atp-dependencies", LAN + body) == expected
