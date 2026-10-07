"""SC-049 completion for Check Point: FW1 policy and further Gaia control outcomes."""

import contextlib
import io
import re
from pathlib import Path

import pytest

from src.analyze.checkpoint.core.process_checkpoint_fw1_conf import process_checkpoint_fw1_conf
from src.analyze.checkpoint.core.process_checkpoint_gaia_conf import process_checkpoint_gaia_conf
from src.analyze.common.controls import CONTROLS, control_coverage
from src.devices.checkpoint.fw1 import CheckPointFW1Parser
from src.devices.checkpoint.gaia import CheckPointGaiaParser

FW1 = tuple(control for control in CONTROLS if control.startswith("checkpoint.fw1."))
GAIA = tuple(control for control in CONTROLS if control.startswith("checkpoint.gaia."))
PLUGIN_DIR = Path(__file__).resolve().parents[1] / "src" / "analyze" / "checkpoint" / "plugins"


def _check(parser, findings, controls):
    rules = {issue.rule_id for issue in findings.values()}
    coverage = {item["control-id"]: item for item in control_coverage(parser)["results"]}
    for control in controls:
        outcome = coverage[control]["outcome"]
        assert outcome != "not-recorded", control
        assert (outcome == "finding") == bool(set(CONTROLS[control].rule_ids) & rules), (control, outcome)
    return coverage


def test_checkpoint_controls_are_registered_and_recorded_ids_exist():
    assert len(FW1) == 11 and len(GAIA) == 17
    for control in FW1 + GAIA:
        definition = CONTROLS[control]
        assert definition.version == 1 and definition.rule_ids
        assert definition.device_types == frozenset({"CHECKPOINT_FW1" if ".fw1." in control else "CHECKPOINT_GAIA"})
    used = set()
    for path in PLUGIN_DIR.glob("*.py"):
        used |= set(re.findall(r'"(checkpoint\.(?:fw1|gaia)\.[a-z0-9-]+)"', path.read_text(encoding="utf-8")))
    assert used == set(FW1) | set(GAIA)


# --- FW1 ----------------------------------------------------------------------

OBJECTS = r'''(:objects (
  :network-objects (
    :Gateway-A (:type (gateway) :ipaddr (192.0.2.1) :firewall (installed))
    :Gateways (:type (group) :members (
      (ReferenceObject (:Name (Gateway-A)))
    ))
    :Admin-Networks (:type (network) :ipaddr (192.0.2.0) :netmask (255.255.255.0))
    :Internal-Networks (:type (network) :ipaddr (10.0.0.0) :netmask (255.0.0.0))
    :Web-01 (:type (host) :ipaddr (10.10.10.20))
  )
  :services (
    :SSH (:type (tcp) :port (22))
    :HTTPS (:type (tcp) :port (443))
    :Telnet-Service (:type (tcp) :port (23))
  )
))'''

NO_GATEWAY_OBJECTS = OBJECTS.replace(":Gateway-A (:type (gateway) :ipaddr (192.0.2.1) :firewall (installed))",
                                     ":Gateway-A (:type (host) :ipaddr (192.0.2.1))")


def rule(name, src="ReferenceObject (:Name (Admin-Networks))", dst="ReferenceObject (:Name (Web-01))",
         svc="ReferenceObject (:Name (HTTPS))", action="accept", track="Log", extra="",
         install='ReferenceObject (:Name ("Policy Targets"))'):
    install_text = f":install-on ({install})" if install else ""
    return (f"    :{name} (\n      :name ({name}) :src ({src}) :dst ({dst}) :services ({svc})\n"
            f"      :action ({action}) :track ({track}) {install_text} {extra}\n    )\n")


STEALTH = rule("Stealth", src="Any", dst="ReferenceObject (:Name (Gateways))", svc="Any", action="drop")
CLEANUP = rule("Cleanup", src="Any", dst="Any", svc="Any", action="drop")
GOOD = rule("Publish")


def layer(*rules, name="Network-Layer", kind="ordered-layer", implicit="drop"):
    return (f"  :{name} (\n    :type ({kind})\n    :implicit-cleanup-action ({implicit})\n"
            + "".join(rules) + "  )\n")


def policy(*layers):
    return "(:rule-base (\n" + "".join(layers) + "))"


SECURE = policy(layer(STEALTH, GOOD, CLEANUP),
                layer(rule("App-cleanup", src="Any", dst="Any", svc="Any"),
                      name="Application-Layer", kind="application-layer", implicit="accept"))


def fw1(tmp_path, rules=SECURE, objects=OBJECTS):
    directory = tmp_path / "fw1"
    directory.mkdir()
    if rules is not None:
        (directory / "rules.C").write_text(rules, encoding="utf-8")
    if objects is not None:
        (directory / "objects.C").write_text(objects, encoding="utf-8")
    parser = CheckPointFW1Parser(str(directory))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_checkpoint_fw1_conf(parser)
    return _check(parser, findings, FW1)


def fw1_outcome(tmp_path, control, rules=SECURE, objects=OBJECTS):
    return fw1(tmp_path, rules, objects)[control]["outcome"]


def test_fw1_secure_policy(tmp_path):
    coverage = fw1(tmp_path)
    outcomes = {control: coverage[control]["outcome"] for control in FW1}
    assert outcomes == {
        "checkpoint.fw1.layer-cleanup": "evaluated-no-finding",
        "checkpoint.fw1.stealth-rule": "evaluated-no-finding",
        "checkpoint.fw1.accept-scope": "evaluated-no-finding",
        "checkpoint.fw1.risky-service-exposure": "evaluated-no-finding",
        "checkpoint.fw1.accept-negation": "evaluated-no-finding",
        "checkpoint.fw1.install-scope": "evaluated-no-finding",
        "checkpoint.fw1.accept-tracking": "evaluated-no-finding",
        "checkpoint.fw1.rule-expiry": "evaluated-no-finding",
        "checkpoint.fw1.disabled-accept-rules": "evaluated-no-finding",
        # SC-017: implied rules are not exported, so absence of shadowing is never a pass.
        "checkpoint.fw1.policy-order": "unknown",
        "checkpoint.fw1.object-references": "evaluated-no-finding",
    }
    stealth = {row["instance-key"]: row["outcome"] for row in coverage["checkpoint.fw1.stealth-rule"]["instances"]}
    assert stealth == {"rule-base / Network-Layer": "evaluated-no-finding",
                       "rule-base / Application-Layer": "not-applicable"}


def test_fw1_no_rules_export_is_unknown(tmp_path):
    coverage = fw1(tmp_path, rules=None)
    assert {coverage[control]["outcome"] for control in FW1} == {"unknown"}


@pytest.mark.parametrize("rules,outcome", [
    (policy(layer(STEALTH, GOOD)), "finding"),
    (policy(layer(STEALTH, GOOD, rule("Cleanup", src="Any", dst="Any", svc="Any", action="drop", track="None"))),
     "finding"),
    (policy(layer(STEALTH, GOOD, CLEANUP)), "evaluated-no-finding"),
    (policy(layer(rule("Off", extra=":disabled (true)", action="drop"))), "not-applicable"),
])
def test_fw1_layer_cleanup(tmp_path, rules, outcome):
    assert fw1_outcome(tmp_path, "checkpoint.fw1.layer-cleanup", rules) == outcome


@pytest.mark.parametrize("rules,objects,outcome", [
    (policy(layer(GOOD, CLEANUP)), OBJECTS, "finding"),
    (policy(layer(STEALTH, GOOD, CLEANUP)), OBJECTS, "evaluated-no-finding"),
    (policy(layer(GOOD, CLEANUP)), NO_GATEWAY_OBJECTS, "unknown"),
    (policy(layer(GOOD, CLEANUP)), None, "unknown"),
    (policy(layer(GOOD, name="Application-Layer", kind="application-layer", implicit="accept")), OBJECTS,
     "not-applicable"),
])
def test_fw1_stealth_rule(tmp_path, rules, objects, outcome):
    assert fw1_outcome(tmp_path, "checkpoint.fw1.stealth-rule", rules, objects) == outcome


@pytest.mark.parametrize("rules,outcome", [
    (policy(layer(STEALTH, rule("Broad", src="Any", dst="Any", svc="Any"), CLEANUP)), "finding"),
    (policy(layer(STEALTH, rule("Two", src="Any", dst="Any"), CLEANUP)), "finding"),
    (policy(layer(STEALTH, GOOD, CLEANUP)), "evaluated-no-finding"),
    (policy(layer(STEALTH, rule("Vpn", src="Any", dst="Any", svc="Any", action="encrypt"), CLEANUP)), "unknown"),
    (policy(layer(STEALTH, CLEANUP)), "not-applicable"),
])
def test_fw1_accept_scope(tmp_path, rules, outcome):
    assert fw1_outcome(tmp_path, "checkpoint.fw1.accept-scope", rules) == outcome


def test_fw1_accept_scope_is_per_rule_across_plugins(tmp_path):
    rules = policy(layer(STEALTH, GOOD, rule("Broad", src="Any", dst="Any", svc="Any"), CLEANUP))
    item = fw1(tmp_path, rules)["checkpoint.fw1.accept-scope"]
    assert {row["instance-key"]: row["outcome"] for row in item["instances"]} == {
        "rule-base / Network-Layer #2 Publish": "evaluated-no-finding",
        "rule-base / Network-Layer #3 Broad": "finding"}


@pytest.mark.parametrize("rules,objects,outcome", [
    (policy(layer(STEALTH, rule("Telnet", src="Any", svc="ReferenceObject (:Name (Telnet-Service))"), CLEANUP)),
     OBJECTS, "finding"),
    (policy(layer(STEALTH, rule("Telnet", svc="ReferenceObject (:Name (Telnet-Service))"), CLEANUP)),
     OBJECTS, "evaluated-no-finding"),
    (policy(layer(STEALTH, rule("Web", src="Any"), CLEANUP)), OBJECTS, "evaluated-no-finding"),
    (policy(layer(STEALTH, rule("Web", src="Any", svc="ReferenceObject (:Name (Custom))"), CLEANUP)),
     OBJECTS, "unknown"),
    (policy(layer(STEALTH, CLEANUP)), OBJECTS, "not-applicable"),
])
def test_fw1_risky_service_exposure(tmp_path, rules, objects, outcome):
    assert fw1_outcome(tmp_path, "checkpoint.fw1.risky-service-exposure", rules, objects) == outcome


@pytest.mark.parametrize("rules,outcome", [
    (policy(layer(STEALTH, rule("Neg", extra=":src-op (not in)"), CLEANUP)), "finding"),
    (policy(layer(STEALTH, GOOD, CLEANUP)), "evaluated-no-finding"),
    (policy(layer(STEALTH, CLEANUP)), "not-applicable"),
])
def test_fw1_accept_negation(tmp_path, rules, outcome):
    assert fw1_outcome(tmp_path, "checkpoint.fw1.accept-negation", rules) == outcome


@pytest.mark.parametrize("rules,outcome", [
    (policy(layer(STEALTH, rule("AnyTarget", install="Any"), CLEANUP)), "finding"),
    (policy(layer(STEALTH, GOOD, CLEANUP)), "evaluated-no-finding"),
    # Install On omitted inside an exported rule: evaluated, not unknown.
    (policy(layer(STEALTH, rule("NoTarget", install=""), CLEANUP)), "evaluated-no-finding"),
    (policy(layer(STEALTH, CLEANUP)), "not-applicable"),
])
def test_fw1_install_scope(tmp_path, rules, outcome):
    assert fw1_outcome(tmp_path, "checkpoint.fw1.install-scope", rules) == outcome


@pytest.mark.parametrize("rules,outcome", [
    (policy(layer(STEALTH, rule("Two", src="Any", dst="Any", track="None"), CLEANUP)), "finding"),
    (policy(layer(STEALTH, rule("Two", src="Any", dst="Any"), CLEANUP)), "evaluated-no-finding"),
    (policy(layer(STEALTH, rule("Odd", src="Any", svc="ReferenceObject (:Name (Custom))", track="None"),
                  CLEANUP)), "unknown"),
    (policy(layer(STEALTH, rule("Quiet", track="None"), CLEANUP)), "not-applicable"),
])
def test_fw1_accept_tracking(tmp_path, rules, outcome):
    assert fw1_outcome(tmp_path, "checkpoint.fw1.accept-tracking", rules) == outcome


@pytest.mark.parametrize("extra,outcome", [
    (":expiration-date (2000-01-01)", "finding"),
    (":expiration-date (2999-01-01)", "evaluated-no-finding"),
    (":time (ReferenceObject (:Name (Any)))", "evaluated-no-finding"),
    ("", "evaluated-no-finding"),
    (":time (ReferenceObject (:Name (Weekdays)))", "unknown"),
])
def test_fw1_rule_expiry(tmp_path, extra, outcome):
    rules = policy(layer(STEALTH, rule("Timed", extra=extra), CLEANUP))
    assert fw1_outcome(tmp_path, "checkpoint.fw1.rule-expiry", rules) == outcome


def test_fw1_rule_expiry_not_applicable_without_enabled_rules(tmp_path):
    rules = policy(layer(rule("Off", extra=":disabled (true)", action="drop")))
    assert fw1_outcome(tmp_path, "checkpoint.fw1.rule-expiry", rules) == "not-applicable"


@pytest.mark.parametrize("rules,outcome", [
    (policy(layer(STEALTH, rule("Old", extra=":disabled (true)"), CLEANUP)), "finding"),
    (policy(layer(STEALTH, rule("OldDrop", action="drop", extra=":disabled (true)"), CLEANUP)),
     "evaluated-no-finding"),
    (SECURE, "evaluated-no-finding"),
])
def test_fw1_disabled_accept_rules(tmp_path, rules, outcome):
    assert fw1_outcome(tmp_path, "checkpoint.fw1.disabled-accept-rules", rules) == outcome


@pytest.mark.parametrize("rules,outcome", [
    (policy(layer(STEALTH, GOOD, rule("Again"), CLEANUP)), "finding"),
    (policy(layer(STEALTH, GOOD, rule("Deny", action="drop"), CLEANUP)), "finding"),
    (policy(layer(STEALTH, GOOD, CLEANUP)), "unknown"),
    (policy(layer(rule("Off", extra=":disabled (true)", action="drop"))), "not-applicable"),
])
def test_fw1_policy_order(tmp_path, rules, outcome):
    assert fw1_outcome(tmp_path, "checkpoint.fw1.policy-order", rules) == outcome


BROKEN_GROUP = OBJECTS.replace("    :Web-01 (", "    :Stale (:type (group) :members (\n"
                               "      (ReferenceObject (:Name (Gone)))\n    ))\n    :Web-01 (")


@pytest.mark.parametrize("rules,objects,outcome", [
    (policy(layer(STEALTH, rule("Ref", src="ReferenceObject (:Name (Missing-Host))"), CLEANUP)), OBJECTS, "finding"),
    (SECURE, BROKEN_GROUP, "finding"),
    (SECURE, OBJECTS, "evaluated-no-finding"),
    (SECURE, None, "unknown"),
])
def test_fw1_object_references(tmp_path, rules, objects, outcome):
    assert fw1_outcome(tmp_path, "checkpoint.fw1.object-references", rules, objects) == outcome


# --- Gaia ---------------------------------------------------------------------

HEADER = "#\n# Configuration of gw1\n# Language version: 15.0v1\n#\nset hostname gw1\n"
SNMP_ON = "set snmp agent on\n"
COMMUNITY = "add snmp community ops read-only\n"


def gaia(tmp_path, control, body):
    path = tmp_path / "gaia.conf"
    path.write_text(HEADER + body, encoding="utf-8")
    parser = CheckPointGaiaParser(str(path))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_checkpoint_gaia_conf(parser)
    return _check(parser, findings, GAIA)[control]


@pytest.mark.parametrize("body,outcome", [
    ("add allowed-client host any-host\n", "finding"),
    ("add allowed-client network ipv4-address 192.0.2.0 mask-length 24\n", "evaluated-no-finding"),
    ("add allowed-client host any-host\ndelete allowed-client host any-host\n"
     "add allowed-client host ipv4-address 192.0.2.10\n", "evaluated-no-finding"),
    ("", "unknown"),
    ("add allowed-client network ipv4-address 0.0.0.0 mask-length 0\n", "unknown"),
])
def test_gaia_allowed_clients(tmp_path, body, outcome):
    assert gaia(tmp_path, "checkpoint.gaia.allowed-clients", body)["outcome"] == outcome


@pytest.mark.parametrize("body,outcome", [
    (SNMP_ON + "set snmp agent-version any\n" + COMMUNITY, "finding"),
    (SNMP_ON + "set snmp agent-version v3-Only\n" + COMMUNITY, "evaluated-no-finding"),
    (SNMP_ON + "set snmp agent-version any\n", "evaluated-no-finding"),
    (SNMP_ON + COMMUNITY, "unknown"),
    ("set snmp agent off\n" + COMMUNITY, "not-applicable"),
    ("", "not-applicable"),
])
def test_gaia_snmp_version(tmp_path, body, outcome):
    assert gaia(tmp_path, "checkpoint.gaia.snmp-version", body)["outcome"] == outcome


def test_gaia_snmpv3_privacy_is_per_user(tmp_path):
    body = (SNMP_ON + "add snmp usm user mon security-level authNoPriv auth-pass-type SHA1 auth-pass-phrase x\n"
            "add snmp usm user ops security-level authPriv auth-pass-type SHA1 auth-pass-phrase x\n")
    item = gaia(tmp_path, "checkpoint.gaia.snmpv3-privacy", body)
    assert item["outcome"] == "finding"
    assert {row["instance-key"]: row["outcome"] for row in item["instances"]} == {
        "mon": "finding", "ops": "evaluated-no-finding"}


@pytest.mark.parametrize("body,outcome", [
    (SNMP_ON + "add snmp usm user ops security-level authPriv auth-pass-type SHA1 auth-pass-phrase x\n",
     "evaluated-no-finding"),
    (SNMP_ON, "not-applicable"),
    ("", "not-applicable"),
    ("set snmp agent maybe\n", "unknown"),
])
def test_gaia_snmpv3_privacy(tmp_path, body, outcome):
    assert gaia(tmp_path, "checkpoint.gaia.snmpv3-privacy", body)["outcome"] == outcome


@pytest.mark.parametrize("control,body,outcome", [
    ("checkpoint.gaia.unused-account-lockout", "", "finding"),
    ("checkpoint.gaia.unused-account-lockout", "set password-controls deny-on-nonuse enable off\n", "finding"),
    ("checkpoint.gaia.unused-account-lockout", "set password-controls deny-on-nonuse enable on\n", "evaluated-no-finding"),
    ("checkpoint.gaia.unused-account-lockout", "set password-controls deny-on-nonuse enable x\n", "unknown"),
    ("checkpoint.gaia.password-history", "set password-controls history-checking off\n", "finding"),
    ("checkpoint.gaia.password-history", "set password-controls history-checking on\n", "evaluated-no-finding"),
    ("checkpoint.gaia.password-history", "", "evaluated-no-finding"),
    ("checkpoint.gaia.password-history", "set password-controls history-checking x\n", "unknown"),
    ("checkpoint.gaia.password-complexity", "set password-controls complexity 1\n", "finding"),
    ("checkpoint.gaia.password-complexity", "set password-controls complexity 3\n", "evaluated-no-finding"),
    ("checkpoint.gaia.password-complexity", "", "evaluated-no-finding"),
    ("checkpoint.gaia.password-complexity", "set password-controls complexity high\n", "unknown"),
    ("checkpoint.gaia.ccp-encryption", "set cluster member ccpenc off\n", "finding"),
    ("checkpoint.gaia.ccp-encryption", "set cluster member ccpenc on\n", "evaluated-no-finding"),
    ("checkpoint.gaia.ccp-encryption", "", "unknown"),
    ("checkpoint.gaia.remote-syslog-transport", "add syslog log-remote-address 192.0.2.5 level info\n", "finding"),
    ("checkpoint.gaia.remote-syslog-transport",
     "add syslog log-remote-address 192.0.2.5 level info protocol udp\n", "finding"),
    ("checkpoint.gaia.remote-syslog-transport",
     "add syslog log-remote-address 192.0.2.5 level info protocol tcp\n", "evaluated-no-finding"),
    ("checkpoint.gaia.remote-syslog-transport",
     "add syslog log-remote-address 192.0.2.5 level info protocol sctp\n", "unknown"),
    ("checkpoint.gaia.remote-syslog-transport", "", "not-applicable"),
    ("checkpoint.gaia.user-shell", "add user ops uid 1001 homedir /home/ops\nset user ops shell /bin/bash\n", "finding"),
    ("checkpoint.gaia.user-shell", "add user ops uid 1001 homedir /home/ops\nset user ops shell /etc/cli.sh\n",
     "evaluated-no-finding"),
    ("checkpoint.gaia.user-shell", "add user ops uid 1001 homedir /home/ops\n", "evaluated-no-finding"),
    ("checkpoint.gaia.user-shell", "add user ops uid 1001 homedir /home/ops\nset user ops shell /bin/zsh\n", "unknown"),
    ("checkpoint.gaia.user-shell", "set user root shell /bin/bash\n", "not-applicable"),
    ("checkpoint.gaia.user-shell", "", "not-applicable"),
])
def test_gaia_release_and_account_controls(tmp_path, control, body, outcome):
    assert gaia(tmp_path, control, body)["outcome"] == outcome


def test_gaia_remote_syslog_is_per_server(tmp_path):
    body = ("add syslog log-remote-address 192.0.2.5 level info protocol tcp\n"
            "add syslog log-remote-address 192.0.2.6 level info\n")
    item = gaia(tmp_path, "checkpoint.gaia.remote-syslog-transport", body)
    assert {row["instance-key"]: row["outcome"] for row in item["instances"]} == {
        "192.0.2.5": "evaluated-no-finding", "192.0.2.6": "finding"}


VULNERABLE = policy(layer(
    rule("Broad", src="Any", dst="Any", svc="Any", track="None", install="Any"),
    rule("Again", src="Any", dst="Any", svc="Any"),
    rule("Expired", extra=":expiration-date (2000-01-01)"),
    rule("Neg", extra=":src-op (not in)", track="None"),
    rule("Telnet", src="Any", svc="ReferenceObject (:Name (Telnet-Service))", track="None"),
    rule("Old", src="Any", dst="Any", svc="Any", extra=":disabled (true)"),
    rule("Ref", src="ReferenceObject (:Name (Missing-Host))", action="drop"),
))
PER_RULE = ("checkpoint.fw1.accept-scope", "checkpoint.fw1.risky-service-exposure", "checkpoint.fw1.accept-negation",
            "checkpoint.fw1.install-scope", "checkpoint.fw1.accept-tracking", "checkpoint.fw1.rule-expiry",
            "checkpoint.fw1.disabled-accept-rules", "checkpoint.fw1.policy-order", "checkpoint.fw1.object-references")


def test_fw1_vulnerable_policy_instances_match_fired_rules(tmp_path):
    directory = tmp_path / "fw1"
    directory.mkdir()
    (directory / "rules.C").write_text(VULNERABLE, encoding="utf-8")
    (directory / "objects.C").write_text(OBJECTS, encoding="utf-8")
    parser = CheckPointFW1Parser(str(directory))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_checkpoint_fw1_conf(parser)
    coverage = _check(parser, findings, FW1)
    assert {coverage[control]["outcome"] for control in FW1} == {"finding"}
    for control in PER_RULE:
        expected = set()
        for issue in findings.values():
            if issue.rule_id in CONTROLS[control].rule_ids:
                match = re.search(r"Check Point layer '(.+?)' rule (\d+) '(.+?)'", str(issue.evidence[0]))
                expected.add(f"{match.group(1)} #{match.group(2)} {match.group(3)}")
        recorded = {row["instance-key"] for row in coverage[control]["instances"] if row["outcome"] == "finding"}
        assert recorded == expected, control
