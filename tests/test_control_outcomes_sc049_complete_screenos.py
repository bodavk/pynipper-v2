"""SC-049 completion for juniper.screenos: control outcomes recorded by the ScreenOS plugins."""

import ast
import contextlib
import io
import pathlib

import pytest

from src.analyze.common.controls import CONTROLS, control_coverage
from src.analyze.juniper.core.process_screenos_conf import process_screenos_conf
from src.devices import get_parser

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLUGINS = (
    ROOT / "src/analyze/juniper/plugins/screenos_baseline_plugin.py",
    ROOT / "src/analyze/juniper/plugins/screenos_checks_plugin.py",
)
SCREENOS = tuple(control for control in CONTROLS if control.startswith("juniper.screenos."))
# Deliberately unmapped: advisory/lifecycle notice raised for every identified export.
UNMAPPED = {"juniper.screenos.lifecycle.end_of_life"}

HEADER = 'set version "6.3.0r27.0"\nset hostname "fw"\n'
ADMIN = (
    'set admin name "ops"\n'
    'set admin password "nKVUM2rwMUzPcrkG5sWIHm8FPNASNW"\n'
    "set admin access attempts 3\n"
    "set admin manager-ip 192.0.2.10 255.255.255.255\n"
    'set admin auth banner telnet login "Authorized use only"\n'
    "set console timeout 10\n"
)
IFACE = 'set interface "ethernet0/0" zone "Trust"\nset interface "ethernet0/0" manage ssh ssl\n'
SERVICES = "set ssh version v2\nset ssl enable\nset ssl encrypt aes128\n"
OPS = "set syslog config 192.0.2.30 facilities local0 local0\nset syslog enable\nset ntp server 192.0.2.20\n"
BASE = ADMIN + IFACE + SERVICES + OPS
POLICY_RESTRICTED = 'set policy id 10 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit log\n'


def run(tmp_path, body, header=HEADER):
    """Return ({control: item}, fired rule IDs) and assert the completion invariants."""
    path = tmp_path / "screenos.conf"
    path.write_text(header + body, encoding="utf-8")
    parser = get_parser("SCREENOS", str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_screenos_conf(parser)
    rules = {issue.rule_id for issue in findings.values()}
    coverage = {item["control-id"]: item for item in control_coverage(parser)["results"]}
    for control in SCREENOS:
        outcome = coverage[control]["outcome"]
        assert outcome != "not-recorded", control
        assert (outcome == "finding") == bool(set(CONTROLS[control].rule_ids) & rules), (control, outcome)
    return coverage, rules


def outcome(tmp_path, control, body, header=HEADER):
    return run(tmp_path, body, header)[0][control]["outcome"]


def instances(tmp_path, control, body, header=HEADER):
    item = run(tmp_path, body, header)[0][control]
    return {row["instance-key"]: row["outcome"] for row in item["instances"]}


def _recorded_control_ids():
    found = set()
    for path in PLUGINS:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.startswith("juniper.screenos.")
                and node.value.count(".") == 2
            ):
                found.add(node.value)
    return found


def _emitted_rule_ids():
    found = set()
    for path in PLUGINS:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.startswith("juniper.screenos.")
                and node.value.count(".") >= 3
            ):
                found.add(node.value)
    return found


def test_screenos_controls_are_registered_and_cover_emitted_rules():
    assert len(SCREENOS) == 22
    for control in SCREENOS:
        definition = CONTROLS[control]
        assert definition.version == 1 and definition.rule_ids
        assert definition.device_types == frozenset({"SCREENOS"})
    recorded = _recorded_control_ids()
    assert recorded and recorded <= set(CONTROLS), recorded - set(CONTROLS)
    assert recorded == set(SCREENOS)
    mapped = {rule for control in SCREENOS for rule in CONTROLS[control].rule_ids}
    emitted = _emitted_rule_ids()
    assert mapped <= emitted, mapped - emitted
    assert emitted - mapped == UNMAPPED


@pytest.mark.parametrize("name", ["vulnerable.conf", "secure.conf", "syntax_variants.conf"])
def test_regression_corpus_records_every_screenos_control(name):
    path = ROOT / "tests/test_data/regression/screenos" / name
    parser = get_parser("SCREENOS", str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_screenos_conf(parser)
    rules = {issue.rule_id for issue in findings.values()}
    for item in control_coverage(parser)["results"]:
        if item["control-id"] in SCREENOS:
            assert item["outcome"] != "not-recorded", item["control-id"]
            assert (item["outcome"] == "finding") == bool(set(item["rule-ids"]) & rules), item["control-id"]


def test_hardened_baseline(tmp_path):
    coverage, _ = run(tmp_path, BASE + POLICY_RESTRICTED)
    expected_no_finding = {
        "manager-sources", "console-timeout", "web-timeout", "login-attempts", "ssh-protocol", "https-activation",
        "https-ciphers", "admin-credentials", "login-banner", "remote-logging", "ntp-servers", "management-telnet",
        "management-http", "policy-scope", "default-deny", "policy-order",
    }
    for name in expected_no_finding:
        assert coverage[f"juniper.screenos.{name}"]["outcome"] == "evaluated-no-finding", name
    for name in ("auth-server-timeout", "auth-server-references", "snmp-community", "policy-logging",
                 "disabled-permissive-policies", "vpn-proposals"):
        assert coverage[f"juniper.screenos.{name}"]["outcome"] == "not-applicable", name


NO_MANAGER = BASE.replace("set admin manager-ip 192.0.2.10 255.255.255.255\n", "")
UNSTATED = 'set interface "ethernet0/1" zone "Trust"\n'
NO_SERVICES = ADMIN + 'set interface "ethernet0/0" zone "Trust"\nset interface "ethernet0/0" manage ping\n' + OPS
SERVER = 'set auth-server "tac" type tacacs\nset admin auth server "tac"\n'


@pytest.mark.parametrize("control,body,expected", [
    ("manager-sources", NO_MANAGER, "finding"),
    ("manager-sources", NO_MANAGER + 'set interface "ethernet0/0" manage-ip 192.0.2.1\n', "unknown"),
    ("manager-sources", NO_SERVICES, "not-applicable"),
    ("manager-sources", NO_SERVICES + UNSTATED, "unknown"),
    ("console-timeout", BASE.replace("set console timeout 10", "set console timeout 0"), "finding"),
    ("console-timeout", BASE.replace("set console timeout 10", "set console timeout 30"), "finding"),
    ("console-timeout", BASE.replace("set console timeout 10\n", ""), "evaluated-no-finding"),
    ("console-timeout", BASE.replace("set console timeout 10", "set console timeout soon"), "unknown"),
    ("console-timeout", NO_SERVICES + "set console disable\n", "not-applicable"),
    ("web-timeout", BASE + "set admin auth web timeout 30\n", "finding"),
    ("web-timeout", BASE + "set admin auth web timeout 5\n", "evaluated-no-finding"),
    ("web-timeout", NO_SERVICES, "not-applicable"),
    ("web-timeout", NO_SERVICES + UNSTATED, "unknown"),
    ("auth-server-timeout", BASE + SERVER + 'set auth-server "tac" timeout 30\n', "finding"),
    ("auth-server-timeout", BASE + SERVER, "evaluated-no-finding"),
    ("auth-server-timeout", BASE + 'set auth-server "tac" type tacacs\n', "not-applicable"),
    ("auth-server-timeout", BASE + 'set admin auth server "missing"\n', "unknown"),
    ("auth-server-references", BASE + 'set admin auth server "missing"\n', "finding"),
    ("auth-server-references", BASE + SERVER, "evaluated-no-finding"),
    ("auth-server-references", BASE, "not-applicable"),
    ("login-attempts", BASE.replace("attempts 3", "attempts 7"), "finding"),
    ("login-attempts", BASE.replace("attempts 3", "attempts 1"), "evaluated-no-finding"),
    ("login-attempts", BASE.replace("set admin access attempts 3\n", ""), "unknown"),
    ("login-attempts", BASE.replace("attempts 3", "attempts many"), "unknown"),
    ("ssh-protocol", BASE.replace("set ssh version v2", "set ssh version v1"), "finding"),
    ("ssh-protocol", BASE.replace("set ssh version v2\n", ""), "finding"),
    ("ssh-protocol", NO_SERVICES, "not-applicable"),
    ("ssh-protocol", NO_SERVICES + UNSTATED, "unknown"),
    ("https-activation", BASE.replace("set ssl enable\n", ""), "finding"),
    ("https-activation", NO_SERVICES, "not-applicable"),
    ("https-ciphers", BASE.replace("set ssl encrypt aes128", "set ssl encrypt rc4 md5"), "finding"),
    ("https-ciphers", BASE.replace("set ssl encrypt aes128\n", ""), "unknown"),
    ("https-ciphers", NO_SERVICES, "not-applicable"),
    ("admin-credentials", BASE.replace('"nKVUM2rwMUzPcrkG5sWIHm8FPNASNW"', '"password"'), "finding"),
    ("admin-credentials", BASE.replace('set admin password "nKVUM2rwMUzPcrkG5sWIHm8FPNASNW"\n', ""), "unknown"),
    ("login-banner", BASE.replace('set admin auth banner telnet login "Authorized use only"\n', ""), "finding"),
    ("remote-logging", BASE.replace("set syslog enable\n", ""), "finding"),
    ("ntp-servers", BASE.replace("set ntp server 192.0.2.20\n", ""), "finding"),
    ("snmp-community", BASE + 'set interface "ethernet0/0" manage snmp\nset snmp community "public" Read-Only\n',
     "finding"),
    ("snmp-community", BASE + 'set interface "ethernet0/0" manage snmp\n', "evaluated-no-finding"),
    ("snmp-community", BASE + 'set snmp community "c1" Read-Only\n', "not-applicable"),
    ("snmp-community", BASE + UNSTATED + 'set snmp community "c1" Read-Only\n', "unknown"),
    ("management-telnet", BASE + 'set interface "ethernet0/0" manage telnet\n', "finding"),
    ("management-telnet", BASE + "set admin telnet\n", "finding"),
    ("management-telnet", BASE + UNSTATED, "unknown"),
    ("management-http", BASE + 'set interface "ethernet0/0" manage web\n', "finding"),
    ("management-http", BASE + UNSTATED, "unknown"),
    ("management-http", ADMIN + OPS, "unknown"),
    ("management-http", ADMIN + OPS + IFACE + 'set interface "ethernet0/0" disable\n', "not-applicable"),
    ("default-deny", BASE + "set policy default-permit-all\n", "finding"),
])
def test_device_controls(tmp_path, control, body, expected):
    assert outcome(tmp_path, f"juniper.screenos.{control}", body) == expected


@pytest.mark.parametrize("control", [
    "console-timeout", "web-timeout", "auth-server-timeout", "auth-server-references", "default-deny",
])
def test_unverified_release_defaults_are_unknown(tmp_path, control):
    header = 'set version "6.2.0r10.0"\nset hostname "fw"\n'
    assert outcome(tmp_path, f"juniper.screenos.{control}", BASE + SERVER, header=header) == "unknown"


@pytest.mark.parametrize("control", ["admin-credentials", "login-banner", "remote-logging", "ntp-servers"])
def test_unidentified_export_is_unknown(tmp_path, control):
    assert outcome(tmp_path, f"juniper.screenos.{control}", BASE, header='set hostname "fw"\n') == "unknown"


def test_management_and_credentials_are_per_instance(tmp_path):
    states = instances(tmp_path, "juniper.screenos.management-telnet",
                       BASE + 'set interface "ethernet0/2" zone "Untrust"\nset interface "ethernet0/2" manage telnet\n'
                       + UNSTATED)
    assert states == {"interface ethernet0/0": "evaluated-no-finding", "interface ethernet0/2": "finding",
                      "interface ethernet0/1": "unknown"}
    creds = instances(tmp_path, "juniper.screenos.admin-credentials",
                      BASE + 'set admin user "audit" password "netscreen" privilege read-only\n')
    assert creds == {"primary_admin ops": "evaluated-no-finding", "local_user audit": "finding"}


@pytest.mark.parametrize("policies,expected", [
    ('set policy id 1 from "Trust" to "Untrust" "Any" "Any" "ANY" permit log\n', "finding"),
    ('set policy id 1 from "Trust" to "Untrust" "Any" "Server" "ANY" permit log\n', "finding"),
    (POLICY_RESTRICTED, "evaluated-no-finding"),
    ('set policy id 1 from "Trust" to "Untrust" "Any" "Any" "NOSUCHSVC" permit log\n', "unknown"),
    ('set policy id 1 from "Trust" to "Untrust" "Any" "Any" "ANY" deny\n', "not-applicable"),
])
def test_policy_scope(tmp_path, policies, expected):
    assert outcome(tmp_path, "juniper.screenos.policy-scope", BASE + policies) == expected


@pytest.mark.parametrize("policies,expected", [
    ('set policy id 1 from "Untrust" to "Trust" "Any" "Any" "HTTP" permit\n', "finding"),
    ('set policy id 1 from "Untrust" to "Trust" "Any" "Any" "HTTP" permit log\n', "evaluated-no-finding"),
    ('set policy id 1 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit\n', "not-applicable"),
])
def test_policy_logging(tmp_path, policies, expected):
    assert outcome(tmp_path, "juniper.screenos.policy-logging", BASE + policies) == expected


@pytest.mark.parametrize("policies,expected", [
    ('set policy id 1 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit\n'
     'set policy id 2 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit\n', "finding"),
    ('set policy id 1 from "Trust" to "Untrust" "Any" "Any" "ANY" deny\n'
     'set policy id 2 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit\n', "finding"),
    ('set policy id 1 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit\n'
     'set policy id 2 from "Trust" to "Untrust" "Any" "Any" "HTTPS" permit\n', "evaluated-no-finding"),
    ('set policy id 1 from "Trust" to "Untrust" "Any" "Any" "NOSUCHSVC" permit\n'
     'set policy id 2 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit\n', "unknown"),
    ('set policy id 1 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit\nset policy id 1 disable\n',
     "not-applicable"),
])
def test_policy_order(tmp_path, policies, expected):
    assert outcome(tmp_path, "juniper.screenos.policy-order", BASE + policies) == expected


def test_policy_order_is_per_policy(tmp_path):
    states = instances(tmp_path, "juniper.screenos.policy-order", BASE
                       + 'set policy id 1 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit\n'
                       'set policy id 2 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit\n')
    assert states == {"policy 1": "evaluated-no-finding", "policy 2": "finding"}


@pytest.mark.parametrize("policies,expected", [
    ('set policy id 1 from "Trust" to "Untrust" "Any" "Any" "ANY" permit\nset policy id 1 disable\n', "finding"),
    ('set policy id 1 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit\nset policy id 1 disable\n',
     "evaluated-no-finding"),
    ('set policy id 1 from "Trust" to "Untrust" "Any" "Any" "ANY" deny\nset policy id 1 disable\n',
     "evaluated-no-finding"),
    ('set policy id 1 from "Trust" to "Untrust" "Any" "Any" "NOSUCHSVC" permit\nset policy id 1 disable\n',
     "unknown"),
    (POLICY_RESTRICTED, "not-applicable"),
])
def test_disabled_permissive_policies(tmp_path, policies, expected):
    assert outcome(tmp_path, "juniper.screenos.disabled-permissive-policies", BASE + policies) == expected


GATEWAY = 'set ike gateway "GW" address 192.0.2.50 Main outgoing-interface ethernet0/0 proposal "{}"\n'


@pytest.mark.parametrize("vpn,expected", [
    ('set ike p1-proposal "P1" preshare pre-g2 3des md5 second 28800\n' + GATEWAY.format("P1"), "finding"),
    ('set ike p1-proposal "P1" preshare pre-g14 aes256 sha-256 second 28800\n' + GATEWAY.format("P1"),
     "evaluated-no-finding"),
    (GATEWAY.format("pre-g2-3des-sha"), "unknown"),
    ('set ike gateway "GW" address 192.0.2.50 Main outgoing-interface ethernet0/0 sec-level standard\n', "unknown"),
    ('set ike gateway "GW" address 192.0.2.50 Main outgoing-interface ethernet0/0\n', "unknown"),
    ('set ike p1-proposal "P1" preshare pre-g2 3des md5 second 28800\n', "not-applicable"),
])
def test_vpn_proposals(tmp_path, vpn, expected):
    assert outcome(tmp_path, "juniper.screenos.vpn-proposals", BASE + vpn) == expected
