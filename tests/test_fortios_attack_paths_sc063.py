"""SC-063: configuration-supported FortiOS attack paths."""

import contextlib
import io
import json

import pytest

from src.analyze.common.attack_paths import (
    PATTERNS, FactState, PathFact, PathResult, attack_path_section, record_path,
)
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.common.assessment import AssessmentContext
from src.devices.fortinet.fortios import FortiOSParser
from src.report.coverage import build_parse_error_context, build_report_context
from src.report.report import generate_report

HEADER = "#config-version=FGT60F-7.4.1-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
GLOBAL = "config system global\n    set admin-lockout-threshold 10\nend\n"
WAN = "config system interface\n    edit \"wan1\"\n        set allowaccess ping https ssh\n    next\nend\n"
ADMIN = ('config system admin\n    edit "fwadmin"\n        set accprofile "super_admin"\n'
         '        set password ENC SH2SyntheticHashValue\n    next\nend\n')
USER = ('config user local\n    edit "alice"\n        set status enable\n        set type password\n'
        '        set passwd "TopSecret42"\n        set two-factor disable\n    next\nend\n')
VPN = ('config vpn ssl settings\n    set status enable\n    set source-interface "wan1"\n'
       '    set source-address "all"\n    set source-address-negate disable\n'
       '    set login-attempt-limit 0\n    set reqclientcert disable\n'
       '    config authentication-rule\n        edit 1\n            set auth local\n'
       '            set users "alice"\n            set portal "full-access"\n'
       '            set client-cert disable\n        next\n    end\nend\n')
SERVICES = "config firewall service custom\n    edit \"TELNET\"\n        set tcp-portrange 23\n    next\nend\n"


def _policy(name, action, service="ALL", status="enable"):
    return (f"    edit {name}\n        set status {status}\n        set srcintf \"wan1\"\n        set dstintf \"lan\"\n"
            f"        set srcaddr \"all\"\n        set dstaddr \"all\"\n        set service \"{service}\"\n"
            f"        set schedule \"always\"\n        set action {action}\n    next\n")


ALLOW_THEN_DENY = SERVICES + "config firewall policy\n" + _policy(1, "accept") + _policy(2, "deny", "TELNET") + "end\n"
ROLES = {"wan1": "external", "lan": "internal"}


def _scan(tmp_path, body, header=HEADER, roles=ROLES, excluded=()):
    source = tmp_path / "fortigate.conf"
    source.write_text(header + body, encoding="utf-8")
    parser = FortiOSParser(str(source))
    mapping = {"interface_roles": roles} if roles else {}
    if excluded:
        mapping["excluded_categories"] = list(excluded)
    parser.set_assessment_context(AssessmentContext.from_mapping(mapping))
    with contextlib.redirect_stdout(io.StringIO()):
        issues = process_fortios_conf(parser)
    return parser, issues, attack_path_section(parser, template_unresolved=parser.template_unresolved)


def _paths(section, pattern):
    return [item for item in section["results"] if item["pattern-id"] == pattern]


def _status(section, pattern):
    return next(item for item in section["patterns"] if item["pattern-id"] == pattern)


# --- privileged administrator guessing -------------------------------------------------

def test_admin_path_joins_listener_account_mfa_and_lockout(tmp_path):
    _, issues, section = _scan(tmp_path, GLOBAL + WAN + ADMIN)
    [path] = _paths(section, "privileged-admin-guessing")
    assert path["instance-key"] == "root/admin:fwadmin"
    assert path["priority"] == "High"
    assert [step["kind"] for step in path["steps"]] == [
        "management-listener", "admin-source-restriction", "privileged-local-account", "second-factor", "lockout",
    ]
    linked = {item["rule-id"] for item in path["linked-findings"]}
    assert {"fortinet.fortios.admin.mfa", "fortinet.fortios.admin.trusted_hosts", "fortinet.fortios.admin.lockout"} <= linked
    assert all(step["state"] == "known" for step in path["steps"])
    assert any(item["line"] for step in path["steps"] for item in step["evidence"])
    assert _status(section, "privileged-admin-guessing")["status"] == "path-found"
    # The path is not a finding and does not change finding severities.
    assert not any("attack" in finding.rule_id or "path" in finding.rule_id for finding in issues.values())


def test_admin_path_does_not_change_findings(tmp_path):
    _, with_roles, _ = _scan(tmp_path, GLOBAL + WAN + ADMIN)
    _, without_roles, section = _scan(tmp_path, GLOBAL + WAN + ADMIN, roles=None)
    assert not section["results"]
    severities = lambda issues: sorted((f.rule_id, f.severity.value) for f in issues.values()
                                       if f.rule_id.startswith("fortinet.fortios.admin."))
    assert severities(with_roles) == severities(without_roles)


@pytest.mark.parametrize("body", [
    GLOBAL + WAN + ADMIN.replace('set accprofile "super_admin"', 'set accprofile "super_admin"\n        set trusthost1 10.0.0.0 255.0.0.0'),
    GLOBAL + WAN + ADMIN.replace('set accprofile "super_admin"', 'set accprofile "super_admin"\n        set two-factor fortitoken'),
    WAN + ADMIN,  # documented default lockout (3 attempts, 60 seconds)
    "config system global\n    set admin-lockout-threshold 3\n    set admin-lockout-duration 60\nend\n" + WAN + ADMIN,
    GLOBAL + WAN + ADMIN.replace('set accprofile "super_admin"', 'set accprofile "super_admin"\n        set status disable'),
    GLOBAL + WAN + ADMIN.replace('set accprofile "super_admin"', 'set accprofile "super_admin"\n        set remote-auth enable'),
    GLOBAL + WAN + ADMIN.replace('set accprofile "super_admin"', 'set accprofile "super_admin"\n        set peer-auth enable'),
    GLOBAL + WAN.replace("ping https ssh", "ping") + ADMIN,
    GLOBAL + WAN.replace("set allowaccess", "set status down\n        set allowaccess") + ADMIN,
    GLOBAL.replace("end", "    set admin-ssh-password disable\nend") + WAN.replace("ping https ssh", "ssh") + ADMIN,
])
def test_admin_path_requires_every_predicate(tmp_path, body):
    _, _, section = _scan(tmp_path, body)
    assert _paths(section, "privileged-admin-guessing") == []
    assert _status(section, "privileged-admin-guessing")["status"] == "evaluated-no-path"


def test_internal_interface_role_does_not_complete_admin_path(tmp_path):
    _, _, section = _scan(tmp_path, GLOBAL + WAN + ADMIN, roles={"wan1": "internal", "port9": "external"})
    assert _paths(section, "privileged-admin-guessing") == []


def test_absent_roles_block_and_explain(tmp_path):
    _, _, section = _scan(tmp_path, GLOBAL + WAN + ADMIN, roles=None)
    status = _status(section, "privileged-admin-guessing")
    assert status["status"] == "not-assessed"
    assert "external" in status["reasons"][0]


def test_absent_defaults_on_unqualified_release_are_not_assessed(tmp_path):
    header = HEADER.replace("7.4.1", "7.2.0")
    _, _, section = _scan(tmp_path, GLOBAL + WAN + ADMIN, header=header)
    assert _paths(section, "privileged-admin-guessing") == []
    assert _status(section, "privileged-admin-guessing")["status"] == "not-assessed"
    explicit = ADMIN.replace('set accprofile "super_admin"', 'set accprofile "super_admin"\n'
                             '        set trusthost1 0.0.0.0 0.0.0.0\n        set two-factor disable')
    _, _, section = _scan(tmp_path, GLOBAL + WAN + explicit, header=header)
    assert len(_paths(section, "privileged-admin-guessing")) == 1


def test_local_in_policy_or_restrict_local_blocks_admin_path(tmp_path):
    local_in = ('config firewall local-in-policy\n    edit 1\n        set intf "wan1"\n        set srcaddr "all"\n'
                '        set dstaddr "all"\n        set service "ALL"\n        set schedule "always"\n        set action deny\n    next\nend\n')
    _, _, section = _scan(tmp_path, GLOBAL + WAN + ADMIN + local_in)
    assert _paths(section, "privileged-admin-guessing") == []
    assert "local-in" in _status(section, "privileged-admin-guessing")["reasons"][0]
    remote = ('    edit "radius-admin"\n        set accprofile "super_admin"\n        set remote-auth enable\n'
              '        set remote-group "admins"\n    next\nend\n')
    body = (GLOBAL.replace("end", "    set admin-restrict-local enable\nend") + WAN
            + ADMIN.replace("    next\nend\n", "    next\n" + remote))
    _, _, section = _scan(tmp_path, body)
    assert _paths(section, "privileged-admin-guessing") == []
    assert _status(section, "privileged-admin-guessing")["status"] == "not-assessed"


def test_component_findings_on_different_accounts_do_not_chain(tmp_path):
    admins = ('config system admin\n'
              '    edit "broad"\n        set accprofile "super_admin"\n        set two-factor fortitoken\n    next\n'
              '    edit "nomfa"\n        set accprofile "super_admin"\n        set trusthost1 10.0.0.0 255.0.0.0\n'
              '        set two-factor disable\n    next\nend\n')
    _, issues, section = _scan(tmp_path, GLOBAL + WAN + admins)
    rules = {finding.rule_id for finding in issues.values()}
    assert {"fortinet.fortios.admin.trusted_hosts", "fortinet.fortios.admin.mfa",
            "fortinet.fortios.admin.lockout"} <= rules
    assert _paths(section, "privileged-admin-guessing") == []


def test_excluded_category_suppresses_pattern(tmp_path):
    _, _, section = _scan(tmp_path, GLOBAL + WAN + ADMIN, excluded=("admin",))
    assert _paths(section, "privileged-admin-guessing") == []
    assert _status(section, "privileged-admin-guessing")["status"] == "excluded"


def test_unrendered_template_blocks_paths(tmp_path):
    body = GLOBAL + WAN + ADMIN + 'config system dns\n    set primary {{ dns_server }}\nend\n'
    parser, _, section = _scan(tmp_path, body)
    assert parser.template_unresolved
    assert section["results"] == []
    assert _status(section, "privileged-admin-guessing")["status"] == "not-assessed"


# --- SSL-VPN password guessing ----------------------------------------------------------

def test_sslvpn_path_joins_listener_limit_and_user(tmp_path):
    _, _, section = _scan(tmp_path, WAN + USER + VPN)
    [path] = _paths(section, "sslvpn-password-guessing")
    assert path["instance-key"] == "root/sslvpn-user:alice"
    assert [step["kind"] for step in path["steps"]] == ["sslvpn-listener", "sslvpn-login-limit", "password-only-user"]
    linked = {item["rule-id"] for item in path["linked-findings"]}
    assert {"fortinet.fortios.sslvpn.unlimited_login_attempts", "fortinet.fortios.sslvpn.password_only_local_user"} <= linked
    assert "TopSecret42" not in json.dumps(section)


@pytest.mark.parametrize("body", [
    WAN + USER + VPN.replace("    set login-attempt-limit 0\n", ""),
    WAN + USER + VPN.replace("set login-attempt-limit 0", "set login-attempt-limit 3"),
    WAN + USER.replace("set two-factor disable", "set two-factor fortitoken") + VPN,
    WAN + USER.replace("set status enable", "set status disable") + VPN,
    WAN + USER + VPN.replace("    set status enable\n", "    set status disable\n", 1),
    WAN + USER + VPN.replace("set reqclientcert disable", "set reqclientcert enable"),
    WAN + USER + VPN.replace("set source-address-negate disable", "set source-address-negate enable"),
    WAN.replace("set allowaccess", "set status down\n        set allowaccess") + USER + VPN,
])
def test_sslvpn_path_requires_every_predicate(tmp_path, body):
    _, _, section = _scan(tmp_path, body)
    assert _paths(section, "sslvpn-password-guessing") == []


def test_sslvpn_restricted_source_and_unknown_source(tmp_path):
    restricted = ("config firewall address\n    edit \"corp\"\n        set subnet 10.0.0.0 255.0.0.0\n    next\nend\n"
                  + WAN + USER + VPN.replace('set source-address "all"', 'set source-address "corp"'))
    _, _, section = _scan(tmp_path, restricted)
    assert _paths(section, "sslvpn-password-guessing") == []
    _, _, section = _scan(tmp_path, WAN + USER + VPN.replace('    set source-address "all"\n', ""))
    assert _paths(section, "sslvpn-password-guessing") == []
    assert _status(section, "sslvpn-password-guessing")["status"] == "not-assessed"


def test_sslvpn_internal_listener_and_missing_roles(tmp_path):
    _, _, section = _scan(tmp_path, WAN + USER + VPN, roles={"wan1": "internal", "x": "external"})
    assert _paths(section, "sslvpn-password-guessing") == []
    _, _, section = _scan(tmp_path, WAN + USER + VPN, roles=None)
    assert _status(section, "sslvpn-password-guessing")["status"] == "not-assessed"


def test_sslvpn_instances_are_bounded_and_deterministic(tmp_path):
    names = [f"user{index:02d}" for index in range(20)]
    users = "config user local\n" + "".join(
        f'    edit "{name}"\n        set status enable\n        set type password\n'
        f'        set passwd "x"\n        set two-factor disable\n    next\n' for name in names) + "end\n"
    vpn = VPN.replace('set users "alice"', "set users " + " ".join(f'"{name}"' for name in names))
    _, _, first = _scan(tmp_path, WAN + users + vpn)
    _, _, second = _scan(tmp_path, WAN + users + vpn)
    assert len(first["results"]) == 12
    assert first["omitted-result-count"] == 8
    assert _status(first, "sslvpn-password-guessing")["instance-count"] == 20
    assert [item["instance-key"] for item in first["results"]] == [item["instance-key"] for item in second["results"]]


# --- protective deny defeated ------------------------------------------------------------

def test_deny_defeated_by_earlier_allow(tmp_path):
    _, issues, section = _scan(tmp_path, ALLOW_THEN_DENY)
    [path] = _paths(section, "protective-deny-defeated")
    assert path["instance-key"] == "root/ipv4/policy:2"
    assert path["linked-findings"][0]["rule-id"] == "fortinet.fortios.policy.shadowed_rule"
    shadowed = [f for f in issues.values() if f.rule_id == "fortinet.fortios.policy.shadowed_rule"]
    assert len(shadowed) == 1 and shadowed[0].severity.value == "High"


@pytest.mark.parametrize("rules", [
    _policy(2, "deny", "TELNET") + _policy(1, "accept"),           # deny first: effective
    _policy(1, "accept", "TELNET") + _policy(2, "deny"),           # partial cover
    _policy(1, "accept", status="disable") + _policy(2, "deny", "TELNET"),
    _policy(1, "deny") + _policy(2, "accept", "TELNET"),           # allow shadowed by deny is not this path
    _policy(1, "accept") + _policy(2, "accept", "TELNET"),         # redundant allow
])
def test_deny_path_requires_first_match_proof(tmp_path, rules):
    _, _, section = _scan(tmp_path, SERVICES + "config firewall policy\n" + rules + "end\n")
    assert _paths(section, "protective-deny-defeated") == []
    assert _status(section, "protective-deny-defeated")["status"] == "evaluated-no-path"


# --- framework and report contract ------------------------------------------------------

def test_catalogue_is_bounded_and_gated_patterns_never_emit():
    assert len(PATTERNS) <= 12
    gated = [pattern for pattern in PATTERNS.values() if pattern.gated]
    assert gated
    with pytest.raises(ValueError):
        record_path(object(), PathResult(gated[0].pattern_id, "x", "root", "ipv4", ()))


def test_unknown_or_mismatched_steps_never_emit(tmp_path):
    parser, _, _ = _scan(tmp_path, "")
    unknown = PathFact("lockout", "root/system-global", "root", "any", FactState.UNKNOWN, "unknown lockout")
    assert record_path(parser, PathResult("privileged-admin-guessing", "root/admin:x", "root", "ipv4", (unknown,))) is False
    other = PathFact("lockout", "vdom2/system-global", "vdom2", "any", FactState.KNOWN, "x")
    with pytest.raises(ValueError):
        record_path(parser, PathResult("privileged-admin-guessing", "root/admin:x", "root", "ipv4", (other,)))
    v6 = PathFact("listener", "root/x", "root", "ipv6", FactState.KNOWN, "x")
    with pytest.raises(ValueError):
        record_path(parser, PathResult("privileged-admin-guessing", "root/admin:x", "root", "ipv4", (v6,)))
    section = attack_path_section(parser)
    assert section["results"] == []
    assert _status(section, "privileged-admin-guessing")["status"] == "not-assessed"


def test_json_and_html_reports_carry_the_section(tmp_path):
    parser, issues, _ = _scan(tmp_path, GLOBAL + WAN + ADMIN + USER + VPN + ALLOW_THEN_DENY)
    data = {"hostname": "fw", "device-type": "FORTIOS",
            "assessment-policy": parser.assessment_context.to_dict(), **build_report_context(parser)}
    with contextlib.redirect_stdout(io.StringIO()):
        generate_report("JSON", str(tmp_path / "r.json"), issues, [], data)
        generate_report("HTML", str(tmp_path / "r.html"), issues, [], data)
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    section = report["attack-paths"]
    assert section["schema-version"] == 1
    assert {item["pattern-id"] for item in section["results"]} == {
        "privileged-admin-guessing", "sslvpn-password-guessing", "protective-deny-defeated"}
    assert report["coverage"]["attack-path-patterns"] == section["patterns"]
    assert "not tested" in section["scope-note"]
    html = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert html.index('id="attack-paths"') < html.index('id="security-issues"')
    for text in (json.dumps(report), html):
        assert "TopSecret42" not in text and "SH2SyntheticHashValue" not in text


def test_parse_error_and_other_callers_report_not_assessed(tmp_path):
    context = build_parse_error_context("FORTIOS", "FortiOSParser", 3)
    statuses = {item["pattern-id"]: item["status"] for item in context["attack-paths"]["patterns"]}
    assert statuses["privileged-admin-guessing"] == "not-assessed"
    assert statuses["unauthenticated-management-api"] == "not-implemented-for-device"
    with contextlib.redirect_stdout(io.StringIO()):
        generate_report("JSON", str(tmp_path / "e.json"), {}, [], {"hostname": "x", "device-type": "IOS_ROUTER"})
    report = json.loads((tmp_path / "e.json").read_text(encoding="utf-8"))
    assert report["attack-paths"]["results"] == []
    assert {item["status"] for item in report["attack-paths"]["patterns"]} <= {
        "not-assessed", "gated", "not-implemented-for-device"}
