"""Adversarial offline accuracy cases for SC-064 through SC-067."""
import json
import socket

import pytest

from src.devices import get_parser
from src.analyze.paloalto.core.process_panos_conf import process_panos_conf
from src.analyze.common.controls import ControlOutcome, control_coverage, record_control
from src.report.coverage import build_report_context
from src.main import main
from src.common.assessment import AssessmentContext
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.analyze.common.attack_paths import attack_path_section
from src.analyze.common.issue import FindingBasis


FORTI_HEADER = "#config-version=FGT60F-7.4.1-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
INTERFACES = ('config system interface\n edit "lan"\n set status up\n next\n'
              ' edit "wan1"\n set status up\n next\nend\n')


def fpolicy(name, action="accept", source="all", extra=""):
    return (f' edit {name}\n set srcintf "lan"\n set dstintf "wan1"\n set srcaddr "{source}"\n'
            f' set dstaddr "all"\n set service "ALL"\n set schedule "always"\n set action {action}\n'
            f' set logtraffic disable\n set utm-status disable\n {extra}\n next\n')


def forti(tmp_path, body, roles=True):
    path = tmp_path / "forti.conf"
    path.write_text(FORTI_HEADER + body, encoding="utf-8")
    parser = get_parser("FORTIOS", str(path))
    if roles:
        parser.set_assessment_context(AssessmentContext.from_mapping({"interface_roles": {"lan": "internal", "wan1": "external"}}))
    findings = process_fortios_conf(parser)
    return parser, list(findings.values())


@pytest.mark.parametrize("suffix,family", [("", "ipv4"), ("6", "ipv6")])
def test_forti_explicit_logging_inspection_family_parity(tmp_path, suffix, family):
    parser, findings = forti(tmp_path, INTERFACES + f"config firewall policy{suffix}\n" + fpolicy(1) + "end\n")
    rules = {f.rule_id for f in findings}
    assert {"fortinet.fortios.policy.logging", "fortinet.fortios.policy.security_profiles"} <= rules
    assert all(f.basis == FindingBasis.EXPLICIT_VALUE for f in findings if f.rule_id in {
        "fortinet.fortios.policy.logging", "fortinet.fortios.policy.security_profiles"})
    assert all(family in f.observation for f in findings if f.rule_id in {
        "fortinet.fortios.policy.logging", "fortinet.fortios.policy.security_profiles"})


@pytest.mark.parametrize("suffix", ["", "6"])
def test_forti_fully_blocked_policy_retains_shadow_only(tmp_path, suffix):
    parser, findings = forti(tmp_path, INTERFACES + f"config firewall policy{suffix}\n" + fpolicy(1, "deny") + fpolicy(2) + "end\n")
    rules = {f.rule_id for f in findings}
    assert "fortinet.fortios.policy.shadowed_rule" in rules
    assert not rules & {"fortinet.fortios.policy.logging", "fortinet.fortios.policy.security_profiles"}


@pytest.mark.parametrize("extra,roles", [("", False), ('set schedule "office-hours"', True),
                                          ('set srcaddr-negate enable', True), ('set internet-service enable', True)])
def test_forti_uncertain_boundary_never_claims_effective_inspection(tmp_path, extra, roles):
    parser, findings = forti(tmp_path, INTERFACES + "config firewall policy\n" + fpolicy(1, extra=extra) + "end\n", roles)
    assert not {f.rule_id for f in findings} & {"fortinet.fortios.policy.logging", "fortinet.fortios.policy.security_profiles"}
    controls = {r["control-id"]: r for r in control_coverage(parser)["results"]}
    assert controls["fortinet.fortios.policy-inspection"]["outcome"] == "unknown"


def test_forti_absent_logging_is_not_disabled_but_absent_utm_is_default_disable(tmp_path):
    # Omitted logtraffic is not "disabled" (the default is utm). Omitted utm-status
    # is the documented default disable on 7.x, so no profiles apply: a finding with
    # the documented-default basis, not an unknown.
    parser, findings = forti(tmp_path, INTERFACES + "config firewall policy\n" + fpolicy(1).replace("set logtraffic disable", "unset logtraffic").replace("set utm-status disable", "unset utm-status") + "end\n")
    rules = {f.rule_id: f for f in findings}
    assert "fortinet.fortios.policy.logging" not in rules
    assert rules["fortinet.fortios.policy.security_profiles"].basis == FindingBasis.DOCUMENTED_DEFAULT


def test_forti_omitted_interface_status_is_documented_default_up(tmp_path):
    interfaces = 'config system interface\n edit "lan"\n next\n edit "wan1"\n next\nend\n'
    _, findings = forti(tmp_path, interfaces + "config firewall policy\n" + fpolicy(1) + "end\n")
    assert {"fortinet.fortios.policy.logging", "fortinet.fortios.policy.security_profiles"} <= {f.rule_id for f in findings}
    down = interfaces.replace('edit "wan1"\n', 'edit "wan1"\n set status down\n')
    _, findings = forti(tmp_path, down + "config firewall policy\n" + fpolicy(1) + "end\n")
    assert not {f.rule_id for f in findings} & {"fortinet.fortios.policy.logging", "fortinet.fortios.policy.security_profiles"}


def prule(name, source, action):
    return (f'<entry name="{name}"><from><member>trust</member></from><to><member>untrust</member></to>'
            f'<source><member>{source}</member></source><destination><member>any</member></destination>'
            '<source-user><member>any</member></source-user><category><member>any</member></category>'
            '<application><member>any</member></application><service><member>any</member></service>'
            f'<action>{action}</action></entry>')


def pan_policy(tmp_path, rules, nat="", other=""):
    return panos(tmp_path, '<devices><entry name="fw-a"><vsys><entry name="vsys1"><rulebase>'
                 + nat + '<security><rules>' + rules + '</rules></security></rulebase></entry>'
                 + other + '</vsys></entry></devices>')


def protective_case(tmp_path, vendor, blocked):
    if vendor == "FORTIOS":
        objects = ('config firewall address\n edit "lower"\n set subnet 0.0.0.0 128.0.0.0\n next\n'
                   ' edit "upper"\n set subnet 128.0.0.0 128.0.0.0\n next\nend\n')
        prior = fpolicy(1, "deny", "lower") + (fpolicy(2, "deny", "upper") if blocked else "")
        parser, findings = forti(tmp_path, INTERFACES + objects + 'config firewall policy\n'
                                 + prior + fpolicy(3) + fpolicy(4, "deny") + 'end\n')
    elif vendor == "ASA":
        from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
        source = tmp_path / "asa.conf"
        prior = 'access-list EDGE extended deny ip 0.0.0.0 128.0.0.0 any\n'
        if blocked:
            prior += 'access-list EDGE extended deny ip 128.0.0.0 128.0.0.0 any\n'
        source.write_text('ASA Version 9.22\nhostname edge\ninterface GigabitEthernet0/0\n nameif outside\n'
                          ' security-level 0\n ip address 192.0.2.1 255.255.255.0\n' + prior
                          + 'access-list EDGE extended permit ip any any\naccess-list EDGE extended deny ip any any\n'
                          + 'access-group EDGE in interface outside\n', encoding="utf-8")
        parser = get_parser("ASA", str(source))
        findings = list(process_asa_conf(parser).values())
    else:
        prior = prule("lower", "0.0.0.0/1", "deny") + (prule("upper", "128.0.0.0/1", "deny") if blocked else "")
        parser, findings = pan_policy(tmp_path, prior + prule("allow", "any", "allow") + prule("deny", "any", "deny"))
    return parser, findings


@pytest.mark.parametrize("vendor", ["FORTIOS", "ASA", "PAN_OS"])
@pytest.mark.parametrize("blocked", [True, False])
def test_effective_allow_remainder_not_shadow_controls_path(tmp_path, vendor, blocked):
    parser, findings = protective_case(tmp_path, vendor, blocked)
    paths = [p for p in attack_path_section(parser)["results"] if p["pattern-id"] == "protective-deny-defeated"]
    assert bool(paths) == (not blocked)
    assert any(f.rule_id.endswith("shadowed_rule") for f in findings)
    if not blocked:
        assert "128.0.0.0" in paths[-1]["steps"][0]["predicate"]
        assert "not every" in paths[-1]["summary"]


GLOBAL = 'config system global\n set admin-lockout-threshold 10\nend\n'
ADMIN = 'config system admin\n edit "admin1"\n set accprofile "super_admin"\n set password ENC secret-never-export\n next\nend\n'
WAN6 = ('config system interface\n edit "wan1"\n config ipv6\n set ip6-address 2001:db8::1/64\n'
        ' set ip6-allowaccess https ssh\n end\n next\nend\n')


@pytest.mark.parametrize("value", ["not-an-ip", "192.0.2.1/24", "::/0", "::1/128"])
def test_malformed_ipv6_listener_is_not_assessed(tmp_path, value):
    parser, _ = forti(tmp_path, GLOBAL + WAN6.replace("2001:db8::1/64", value) + ADMIN)
    paths = attack_path_section(parser)
    assert not paths["results"]
    status = next(p for p in paths["patterns"] if p["pattern-id"] == "privileged-admin-guessing")
    assert status["status"] == "not-assessed"
    assert "address" in ' '.join(status["reasons"])


@pytest.mark.parametrize("value", ["not-an-ip", "192.0.2.0/24"])
def test_malformed_ipv6_trust_is_not_assessed(tmp_path, value):
    parser, _ = forti(tmp_path, GLOBAL + WAN6 + ADMIN.replace('set accprofile "super_admin"', f'set accprofile "super_admin"\n set ip6-trusthost1 {value}'))
    paths = attack_path_section(parser)
    assert not paths["results"]
    status = next(p for p in paths["patterns"] if p["pattern-id"] == "privileged-admin-guessing")
    assert status["status"] == "not-assessed" and "ip6-trusthost" in ' '.join(status["reasons"])


def test_remainder_budget_and_unsupported_predicate_unknown():
    from src.devices.common.policy_semantics import NetworkSemantics, ServiceSemantics, TrafficMatch, effective_permission
    match = TrafficMatch(NetworkSemantics(any=True), NetworkSemantics(any=True), ServiceSemantics(any=True))
    assert effective_permission(match, (match,), fragment_limit=0).state.value == "unknown"
    uncertain = TrafficMatch(match.sources, match.destinations, match.services, False, "unsupported prior")
    assert effective_permission(match, (uncertain,)).state.value == "unknown"
    assert effective_permission(match, (match,)).state.value == "disproven"


@pytest.mark.parametrize("nat,expected", [
    ('<entry name="disabled"><disabled>yes</disabled></entry>', True),
    ('<entry name="irrelevant"><from><member>elsewhere</member></from></entry>', True),
    ('<entry name="irrelevant"><from><member>trust</member></from><source><member>192.0.2.0/24</member></source><destination><member>any</member></destination><service>any</service></entry>', True),
    ('<entry name="relevant"><from><member>trust</member></from><source><member>any</member></source><destination><member>any</member></destination><service>any</service><destination-translation><translated-address>192.0.2.1</translated-address></destination-translation></entry>', False),
    ('<entry name="malformed"><disabled>maybe</disabled></entry>', False),
    ('<entry name="reverse"><from><member>elsewhere</member></from><source-translation><static-ip><bi-directional>yes</bi-directional></static-ip></source-translation></entry>', False),
])
def test_nat_qualification_shared_by_shadow_and_path(tmp_path, nat, expected):
    rules = prule("allow", "10.0.0.0/8", "allow") + prule("deny", "10.20.0.0/16", "deny")
    parser, findings = pan_policy(tmp_path, rules, '<nat><rules>' + nat + '</rules></nat>')
    assert any(f.rule_id.endswith("shadowed_rule") for f in findings) == expected
    assert bool(attack_path_section(parser)["results"]) == expected
    if not expected:
        assert next(p for p in attack_path_section(parser)["patterns"] if p["pattern-id"] == "protective-deny-defeated")["status"] == "not-assessed"


def test_nat_other_vsys_and_blocked_allow_remain_independent(tmp_path):
    other = '<entry name="vsys2"><rulebase><nat><rules><entry name="other-vsys"/></rules></nat></rulebase></entry>'
    parser, findings = pan_policy(tmp_path, prule("allow", "any", "allow") + prule("deny", "any", "deny"), other=other)
    assert attack_path_section(parser)["results"]
    parser, findings = pan_policy(tmp_path, prule("lower", "0.0.0.0/1", "deny") + prule("upper", "128.0.0.0/1", "deny")
                                 + prule("allow", "any", "allow") + prule("deny", "any", "deny"),
                                 '<nat><rules><entry name="disabled"><disabled>yes</disabled></entry></rules></nat>')
    assert not attack_path_section(parser)["results"]


def test_cross_vdom_user_names_cannot_complete_sslvpn_path(tmp_path):
    user = 'config user local\n edit "alice"\n set status enable\n set type password\n set passwd DontLeakThis\n set two-factor disable\n next\nend\n'
    vpn = ('config vpn ssl settings\n set status enable\n set source-interface "wan1"\n set source-address "all"\n'
           ' set source-address-negate disable\n set login-attempt-limit 0\n set reqclientcert disable\n'
           ' config authentication-rule\n edit 1\n set auth local\n set users "alice"\n set portal "full-access"\n'
           ' set client-cert disable\n next\n end\nend\n')
    interfaces = 'config system interface\n edit "wan1"\n set status up\n next\nend\n'
    body = 'config vdom\n edit "blue"\n' + user + 'next\n edit "red"\n' + interfaces + vpn + 'next\nend\n'
    parser, _ = forti(tmp_path, body)
    assert not attack_path_section(parser)["results"]
    assert not parser.get_sslvpn_password_only_users()
    assert any("VDOM" in k.reason for k in parser.get_sslvpn_auth_knowledge() if k.state.value == "unknown")
    assert next(p for p in attack_path_section(parser)["patterns"] if p["pattern-id"] == "sslvpn-password-guessing")["status"] == "not-assessed"
    assert "DontLeakThis" not in json.dumps(build_report_context(parser))


def panos(tmp_path, body):
    path = tmp_path / "pan.xml"
    path.write_text('<config version="11.1.0">' + body + '</config>', encoding="utf-8")
    parser = get_parser("PAN_OS", str(path))
    findings = process_panos_conf(parser)
    return parser, list(findings.values())


def password_outcome(parser):
    return next(r for r in control_coverage(parser)["results"] if r["control-id"] == "paloalto.panos.password-complexity")


@pytest.mark.parametrize("body", [
    '<devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>fragment</hostname></system></deviceconfig></entry></devices>',
    '<mgt-config><password-complexity><enabled>maybe</enabled><minimum-length>not-a-number</minimum-length></password-complexity></mgt-config>',
])
def test_unqualified_password_absence_is_unknown(tmp_path, body):
    parser, findings = panos(tmp_path, body)
    assert not any(f.rule_id == "paloalto.panos.credentials.password_complexity" for f in findings)
    result = password_outcome(parser)
    assert result["outcome"] == "unknown"
    assert parser.get_export_scope_knowledge("logging", "management").state.value == "unknown"


FULL_MGMT = ('<mgt-config><users><entry name="admin"><permissions><role-based><superuser>yes</superuser>'
             '</role-based></permissions></entry></users>{pc}</mgt-config><devices><entry name="localhost.localdomain">'
             '<deviceconfig><system><hostname>fw</hostname></system></deviceconfig></entry></devices>')


@pytest.mark.parametrize("pc", ["", "<password-complexity/>"])
def test_omitted_password_complexity_in_exported_management_is_not_configured(tmp_path, pc):
    # The management configuration is exported, so the omitted section/<enabled> is a
    # feature that is simply not configured, not an unknown.
    parser, findings = panos(tmp_path, FULL_MGMT.format(pc=pc))
    finding = next(f for f in findings if f.rule_id == "paloalto.panos.credentials.password_complexity")
    assert finding.basis == FindingBasis.REQUIRED_SETTING_MISSING
    assert "not configured" in finding.observation or "not enabled" in finding.observation
    assert password_outcome(parser)["outcome"] == "finding"


def test_threat_schedule_omission_depends_on_exported_management(tmp_path):
    parser, findings = panos(tmp_path, FULL_MGMT.format(pc=""))
    threat = next(f for f in findings if f.rule_id == "paloalto.panos.updates.threat_content")
    assert threat.basis == FindingBasis.REQUIRED_SETTING_MISSING
    parser, findings = panos(tmp_path, '<devices><entry name="fw"><deviceconfig><system><hostname>x</hostname></system></deviceconfig></entry></devices>')
    assert not any(f.rule_id == "paloalto.panos.updates.threat_content" for f in findings)
    assert result_for(parser, "paloalto.panos.threat-updates")["outcome"] == "unknown"


@pytest.mark.parametrize("enabled,length,outcome", [("no", 8, "finding"), ("yes", 12, "evaluated-no-finding")])
def test_explicit_password_policy(tmp_path, enabled, length, outcome):
    body = '<mgt-config><password-complexity><enabled>' + enabled + '</enabled><minimum-length>' + str(length) + '</minimum-length>'
    body += ''.join('<minimum-' + field + '>1</minimum-' + field + '>' for field in (
        "uppercase-letters", "lowercase-letters", "numeric-letters", "special-characters"))
    parser, findings = panos(tmp_path, body + '</password-complexity></mgt-config>')
    assert password_outcome(parser)["outcome"] == outcome
    assert any(f.rule_id == "paloalto.panos.credentials.password_complexity" for f in findings) == (outcome == "finding")


def test_scoped_unknown_survives_finding(tmp_path):
    parser, _ = panos(tmp_path, '<mgt-config><password-complexity><enabled>no</enabled></password-complexity></mgt-config>')
    result = password_outcome(parser)
    assert result["outcome"] == "finding" and result["unassessed-instance-count"] == 1
    record_control(parser, "paloalto.panos.password-complexity", ControlOutcome.UNKNOWN,
                   "Another supplied scope is unresolved.", instance="other-scope")
    assert password_outcome(parser)["unassessed-instance-count"] == 2


@pytest.mark.parametrize("format", ["JSON", "HTML"])
def test_partial_export_public_offline(tmp_path, monkeypatch, format):
    def forbidden(*args, **kwargs):
        raise AssertionError("Audit attempted network access")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    parser, _ = panos(tmp_path, '<devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>fragment</hostname></system></deviceconfig></entry></devices>')
    target = tmp_path / ("report." + format.lower())
    assert main(["-d", "PAN_OS", "-i", parser.config_filepath, "-o", format, "-f", str(target), "-x"]) == 0
    text = target.read_text(encoding="utf-8")
    if format == "JSON":
        coverage = json.loads(text)["coverage"]
        assert coverage["export-scopes"][0]["knowledge-state"] == "unknown"
        assert next(r for r in coverage["controls"]["results"] if r["control-id"] == "paloalto.panos.password-complexity")["outcome"] == "unknown"
    else:
        assert "Export evidence scope" in text and "unqualified" in text


def result_for(parser, control):
    return next(r for r in control_coverage(parser)["results"] if r["control-id"] == control)


@pytest.mark.parametrize("suffix", ["", "6"])
@pytest.mark.parametrize("group", [False, True])
@pytest.mark.parametrize("action,outcome", [("block", "evaluated-no-finding"), ("pass", "finding")])
def test_qualified_profile_content_family_and_group_parity(tmp_path, suffix, group, action, outcome):
    profile = ('config ips sensor\n edit "IPS"\n config entries\n edit 1\n'
               f' set status enable\n set action {action}\n next\n end\n next\nend\n')
    attachment = 'set ips-sensor "IPS"'
    if group:
        profile += 'config firewall profile-group\n edit "GROUP"\n set ips-sensor "IPS"\n next\nend\n'
        attachment = 'set profile-type group\n set profile-group "GROUP"'
    policy = fpolicy(1).replace("set utm-status disable", "set utm-status enable").replace(
        "set logtraffic disable", "set logtraffic all")
    parser, findings = forti(tmp_path, INTERFACES + profile + f"config firewall policy{suffix}\n"
                             + policy.replace(" next\n", f" {attachment}\n next\n") + "end\n")
    assert result_for(parser, "fortinet.fortios.policy-inspection")["outcome"] == outcome
    assert any(f.rule_id == "fortinet.fortios.policy.security_profile_ineffective" for f in findings) == (action == "pass")
    assert result_for(parser, "fortinet.fortios.policy-logging")["outcome"] == "evaluated-no-finding"


@pytest.mark.parametrize("suffix", ["", "6"])
def test_unresolved_utm_attachment_keeps_utm_only_logging_unknown(tmp_path, suffix):
    policy = fpolicy(1).replace("set utm-status disable", "set utm-status enable").replace(
        "set logtraffic disable", "set logtraffic utm\n set ips-sensor MISSING")
    parser, findings = forti(tmp_path, INTERFACES + f"config firewall policy{suffix}\n" + policy + "end\n")
    assert result_for(parser, "fortinet.fortios.policy-inspection")["outcome"] == "unknown"
    assert result_for(parser, "fortinet.fortios.policy-logging")["outcome"] == "unknown"
    assert not any(f.rule_id == "fortinet.fortios.policy.security_profile_unresolved" for f in findings)


def test_forti_known_finding_does_not_hide_other_family_unknown(tmp_path):
    parser, _ = forti(tmp_path, INTERFACES + "config firewall policy\n" + fpolicy(1) + "end\n"
                      + "config firewall policy6\n" + fpolicy(1, extra="set schedule unknown") + "end\n")
    result = result_for(parser, "fortinet.fortios.policy-inspection")
    assert result["outcome"] == "finding" and result["unassessed-instance-count"] == 1
    assert "ipv6" in result["unassessed-instances"][0]["instance-key"]


def test_forti_union_denies_suppress_effective_logging_and_inspection(tmp_path):
    parser, findings = protective_case(tmp_path, "FORTIOS", True)
    assert not any(f.rule_id in {"fortinet.fortios.policy.logging", "fortinet.fortios.policy.security_profiles"} for f in findings)
    assert result_for(parser, "fortinet.fortios.policy-inspection")["outcome"] == "not-applicable"


@pytest.mark.parametrize("extra", ["set ip6-mode dhcp", "unset ip6-address"])
def test_ipv6_listener_dynamic_or_removed_is_unknown(tmp_path, extra):
    parser, _ = forti(tmp_path, GLOBAL + WAN6.replace("set ip6-allowaccess", extra + "\n set ip6-allowaccess") + ADMIN)
    section = attack_path_section(parser)
    assert not section["results"]
    assert next(p for p in section["patterns"] if p["pattern-id"] == "privileged-admin-guessing")["status"] == "not-assessed"


def test_listener_name_collision_and_global_owner_are_unknown(tmp_path):
    body = ('config vdom\n edit blue\n' + GLOBAL + WAN6 + ADMIN + 'next\n edit red\n' + WAN6 + 'next\nend\n')
    parser, _ = forti(tmp_path, body)
    assert not attack_path_section(parser)["results"]
    assert any("collides" in r for p in attack_path_section(parser)["patterns"] for r in p["reasons"])
    parser, _ = forti(tmp_path, 'config global\n' + GLOBAL + WAN6.replace('edit "wan1"', 'edit "wan1"\n set vdom red') + ADMIN + 'end\n')
    assert not attack_path_section(parser)["results"]
    assert any("ownership" in r for p in attack_path_section(parser)["patterns"] for r in p["reasons"])


@pytest.mark.parametrize("vendor", ["FORTIOS", "ASA", "PAN_OS"])
def test_adapter_remainder_rule_budget_is_unknown(tmp_path, vendor):
    from dataclasses import replace
    parser, _ = protective_case(tmp_path, vendor, False)
    if vendor == "FORTIOS":
        lower, allow, deny = parser.get_firewall_policy_semantics()
        allow, deny = replace(allow, position=100), replace(deny, position=101)
        proof = parser.get_effective_policy_permission(allow, tuple(replace(lower, position=i) for i in range(1, 66)), deny)
    elif vendor == "ASA":
        lower, allow, deny = parser.get_acl_entries("EDGE")
        proof = parser.get_effective_acl_permission(allow, (lower,) * 65, deny)
    else:
        lower, allow, deny = parser.get_security_rules()
        allow, deny = replace(allow, position=100), replace(deny, position=101)
        proof = parser.get_effective_security_permission(allow, tuple(replace(lower, position=i) for i in range(1, 66)), deny)
    assert proof.state.value == "unknown" and "budget" in proof.reason.lower()


def test_remainder_protocol_alias_and_icmp_type_are_not_skipped():
    from src.devices.common.policy_semantics import NetworkSemantics, ServiceSemantics, ServiceInterval, TrafficMatch, effective_permission
    network = NetworkSemantics(any=True)
    def match(protocol, first=0, last=65535):
        return TrafficMatch(network, network, ServiceSemantics(intervals=(ServiceInterval(protocol, first, last),)))
    assert effective_permission(match("sctp"), (match("ip-132"),), families=(4,)).state.value == "disproven"
    assert effective_permission(match("icmp", 8, 8), (match("ip-1", 8, 8),), families=(4,)).state.value == "disproven"
    assert effective_permission(match("unknown-protocol"), (), families=(4,)).state.value == "unknown"


@pytest.mark.parametrize("vendor", ["FORTIOS", "ASA", "PAN_OS"])
@pytest.mark.parametrize("format", ["JSON", "HTML"])
def test_public_blocked_allow_is_offline_and_has_no_risk_path(tmp_path, monkeypatch, vendor, format):
    def forbidden(*args, **kwargs):
        raise AssertionError("Audit attempted network access")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    parser, _ = protective_case(tmp_path, vendor, True)
    target = tmp_path / (vendor + "." + format.lower())
    assert main(["-d", vendor, "-i", parser.config_filepath, "-o", format, "-f", str(target), "-x"]) == 0
    report = target.read_text(encoding="utf-8")
    if format == "JSON":
        data = json.loads(report)
        assert not data["attack-paths"]["results"]
        assert any(f["rule_id"].endswith("shadowed_rule") for f in data["security-audit"].values())
    else:
        assert "Effective allow defeating a later deny" not in report
        assert "Rule is shadowed" in report or "Firewall policy is shadowed" in report or "ACL entry is shadowed" in report


def test_nat_other_scope_malformed_state_and_prepost_disjoint(tmp_path):
    rules = prule("allow", "10.0.0.0/8", "allow") + prule("deny", "10.20.0.0/16", "deny")
    other = '<entry name="vsys2"><rulebase><nat><rules><entry name="other"><disabled>maybe</disabled></entry></rules></nat></rulebase></entry>'
    parser, _ = pan_policy(tmp_path, rules, other=other)
    assert attack_path_section(parser)["results"]
    for rulebase in ("pre-rulebase", "post-rulebase"):
        nat = ('<' + rulebase + '><nat><rules><entry name="disjoint"><from><member>elsewhere</member></from>'
               '<destination-translation><translated-address>UNRESOLVED</translated-address></destination-translation>'
               '</entry></rules></nat></' + rulebase + '>')
        body = '<devices><entry name="fw-a"><vsys><entry name="vsys1">' + nat + '<rulebase><security><rules>' + rules + '</rules></security></rulebase></entry></vsys></entry></devices>'
        parser, _ = panos(tmp_path, body)
        assert attack_path_section(parser)["results"]


@pytest.mark.parametrize("prior", [prule("unknown", "any", "allow").replace("<application><member>any", "<application><member>ssl"),
                                   prule("bad-action", "any", "not-an-action"),
                                   prule("ipv6-mapped", "::/96", "deny")])
def test_pan_unsupported_earlier_predicate_blocks_risk_not_hygiene(tmp_path, prior):
    parser, findings = pan_policy(tmp_path, prior + prule("allow", "any", "allow") + prule("deny", "any", "deny"))
    assert not attack_path_section(parser)["results"]
    assert next(p for p in attack_path_section(parser)["patterns"] if p["pattern-id"] == "protective-deny-defeated")["status"] == "not-assessed"
    assert any(f.rule_id.endswith("shadowed_rule") for f in findings)


def test_exclusions_hide_controls_and_paths_without_erasing_uncertainty(tmp_path):
    parser, _ = protective_case(tmp_path, "FORTIOS", False)
    parser.set_assessment_context(AssessmentContext.from_mapping({"excluded_categories": ["policy"]}))
    coverage = control_coverage(parser)
    result = next(r for r in coverage["results"] if r["control-id"] == "fortinet.fortios.policy-order")
    assert result["outcome"] == "excluded" and result["unassessed-instance-count"] == 0
    assert not attack_path_section(parser)["results"]


def test_template_instance_unknown_reason_survives_other_finding(tmp_path):
    parser, _ = panos(tmp_path, '<mgt-config><password-complexity><enabled>no</enabled></password-complexity></mgt-config>')
    record_control(parser, "paloalto.panos.password-complexity", ControlOutcome.NO_FINDING, "Explicit safe fields", instance="other")
    result = next(r for r in control_coverage(parser, template_unresolved=True)["results"] if r["control-id"] == "paloalto.panos.password-complexity")
    assert result["outcome"] == "finding"
    assert any(i["instance-key"] == "other" and "Unrendered" in i["reasons"][0] for i in result["unassessed-instances"])


@pytest.mark.parametrize("recurring,outcome", [
    ("<hourly><at>15</at><action>download-only</action></hourly>", "finding"),
    ("<hourly><at>15</at><action>download-and-install</action></hourly>", "evaluated-no-finding"),
    ("<none/>", "finding"),
    ("<hourly><at>not-a-time</at><action>download-and-install</action></hourly>", "unknown"),
    ("<hourly><action>download-and-install</action></hourly>", "unknown"),
    ("<hourly><at>15</at><action>download-only</action><action>download-and-install</action></hourly>", "unknown"),
    ("<unsupported><action>download-only</action></unsupported>", "unknown"),
])
def test_explicit_update_actions_and_malformed_schedule_knowledge(tmp_path, recurring, outcome):
    body = ('<devices><entry name="fw-a"><deviceconfig><system><update-schedule><threats><recurring>'
            + recurring + '</recurring></threats></update-schedule></system></deviceconfig></entry></devices>')
    parser, findings = panos(tmp_path, body)
    assert result_for(parser, "paloalto.panos.threat-updates")["outcome"] == outcome
    assert any(f.rule_id == "paloalto.panos.updates.threat_content" for f in findings) == (outcome == "finding")


def test_unexported_pan_role_is_unknown_but_omitted_rule_profiles_are_not_configured(tmp_path):
    body = '<mgt-config><users><entry name="operator"><authentication-profile>UNEXPORTED</authentication-profile><phash>HiddenPasswordHash</phash></entry></users></mgt-config>'
    body += '<devices><entry name="fw-a"><vsys><entry name="vsys1"><rulebase><security><rules>'
    body += prule("allow", "any", "allow") + '</rules></security></rulebase></entry></vsys></entry></devices>'
    parser, findings = panos(tmp_path, body)
    assert not {f.rule_id for f in findings} & {"paloalto.panos.admin.role_assignment",
        "paloalto.panos.admin.authentication_profile_unresolved"}
    assert result_for(parser, "paloalto.panos.administrator-policy")["outcome"] == "unknown"
    # The exported allow rule omits its profile attachment: not configured, a finding.
    profiles = next(f for f in findings if f.rule_id == "paloalto.panos.policy.security_profiles")
    assert profiles.basis == FindingBasis.REQUIRED_SETTING_MISSING
    assert result_for(parser, "paloalto.panos.policy-inspection")["outcome"] == "finding"
    assert "HiddenPasswordHash" not in json.dumps(build_report_context(parser))
    assert "HiddenPasswordHash" not in json.dumps([f.to_dict() for f in findings])


def test_asa_removed_aaa_is_not_configured_and_unexported_group_is_unknown(tmp_path):
    from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
    path = tmp_path / "aaa.conf"
    path.write_text('ASA Version 9.22\nhostname partial\nssh 0.0.0.0 0.0.0.0 outside\n'
                    'aaa authentication ssh console LOCAL\nno aaa authentication ssh console LOCAL\n'
                    'aaa accounting ssh console MISSING\n', encoding="utf-8")
    parser = get_parser("ASA", str(path))
    findings = list(process_asa_conf(parser).values())
    # The SSH grant is exported and its authentication binding was removed: not configured.
    authentication = [f for f in findings if f.rule_id == "cisco.asa.aaa.management_authentication"]
    assert len(authentication) == 1 and authentication[0].basis == FindingBasis.REQUIRED_SETTING_MISSING
    assert result_for(parser, "cisco.asa.management-authentication")["outcome"] == "finding"
    # Accounting references a server group that is not in the export: unknown, not a finding.
    assert not any(f.rule_id == "cisco.asa.aaa.management_accounting" for f in findings)
    result = result_for(parser, "cisco.asa.management-accounting")
    assert result["outcome"] == "unknown" and result["unassessed-instances"][0]["instance-key"] == "ssh"


@pytest.mark.parametrize("format", ["JSON", "HTML"])
def test_public_disabled_nat_restores_shadow_and_proven_path_offline(tmp_path, monkeypatch, format):
    def forbidden(*args, **kwargs):
        raise AssertionError("Audit attempted network access")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    parser, _ = pan_policy(tmp_path, prule("allow", "10.0.0.0/8", "allow") + prule("deny", "10.1.0.0/16", "deny"),
        '<nat><rules><entry name="disabled"><disabled>yes</disabled></entry></rules></nat>')
    target = tmp_path / ("nat." + format.lower())
    assert main(["-d", "PAN_OS", "-i", parser.config_filepath, "-o", format, "-f", str(target), "-x"]) == 0
    output = target.read_text(encoding="utf-8")
    if format == "JSON":
        data = json.loads(output)
        assert data["attack-paths"]["results"][0]["pattern-id"] == "protective-deny-defeated"
        assert any(f["rule_id"].endswith("shadowed_rule") for f in data["security-audit"].values())
    else:
        assert "Protective deny defeated by an earlier allow" in output and "Rule is shadowed" in output


def test_irrelevant_vsys_nat_does_not_consume_comparison_budget(tmp_path):
    other = '<entry name="other"><rulebase><nat><rules>' + ''.join(
        f'<entry name="n{i}"/>' for i in range(65)) + '</rules></nat></rulebase></entry>'
    parser, _ = pan_policy(tmp_path, prule("allow", "any", "allow") + prule("deny", "any", "deny"), other=other)
    assert attack_path_section(parser)["results"]


def rescan(parser):
    parser = get_parser(parser.device_type, parser.config_filepath)
    if parser.device_type == "FORTIOS":
        findings = process_fortios_conf(parser)
    elif parser.device_type == "ASA":
        from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
        findings = process_asa_conf(parser)
    else:
        findings = process_panos_conf(parser)
    return parser, list(findings.values())


@pytest.mark.parametrize("vendor", ["FORTIOS", "ASA", "PAN_OS"])
def test_single_covering_deny_also_blocks_allow_path(tmp_path, vendor):
    from pathlib import Path
    parser, _ = protective_case(tmp_path, vendor, True)
    path = Path(parser.config_filepath)
    source = path.read_text(encoding="utf-8")
    if vendor == "FORTIOS":
        source = source.replace("set subnet 0.0.0.0 128.0.0.0", "set subnet 0.0.0.0 0.0.0.0")
    elif vendor == "ASA":
        source = source.replace("deny ip 0.0.0.0 128.0.0.0 any", "deny ip any any log")
    else:
        source = source.replace("<member>0.0.0.0/1</member>", "<member>any</member>")
    path.write_text(source, encoding="utf-8")
    parser, findings = rescan(parser)
    assert not attack_path_section(parser)["results"]
    assert any(f.rule_id.endswith("shadowed_rule") for f in findings)


@pytest.mark.parametrize("vendor", ["FORTIOS", "ASA", "PAN_OS"])
def test_native_order_change_restores_effective_allow(tmp_path, vendor):
    from pathlib import Path
    parser, _ = protective_case(tmp_path, vendor, True)
    path = Path(parser.config_filepath)
    source = path.read_text(encoding="utf-8")
    if vendor == "FORTIOS":
        source += 'config firewall policy\n move 3 before 1\nend\n'
    elif vendor == "ASA":
        source += 'access-list EDGE line 1 extended permit ip any any\n'
    else:
        source = source.replace(prule("lower", "0.0.0.0/1", "deny"), "").replace(
            prule("allow", "any", "allow"), prule("allow", "any", "allow") + prule("lower", "0.0.0.0/1", "deny"))
        # Move the upper deny below the allow as well.
        source = source.replace(prule("upper", "128.0.0.0/1", "deny"), "").replace(
            prule("allow", "any", "allow"), prule("allow", "any", "allow") + prule("upper", "128.0.0.0/1", "deny"))
    path.write_text(source, encoding="utf-8")
    parser, _ = rescan(parser)
    assert attack_path_section(parser)["results"]


@pytest.mark.parametrize("vendor", ["FORTIOS", "ASA"])
def test_unsupported_prior_schedule_keeps_path_unassessed(tmp_path, vendor):
    from pathlib import Path
    parser, _ = protective_case(tmp_path, vendor, False)
    path = Path(parser.config_filepath)
    source = path.read_text(encoding="utf-8")
    if vendor == "FORTIOS":
        source = source.replace('set schedule "always"', 'set schedule "UNEXPORTED"', 1)
    else:
        source = source.replace('deny ip 0.0.0.0 128.0.0.0 any', 'deny ip 0.0.0.0 128.0.0.0 any time-range UNEXPORTED')
    path.write_text(source, encoding="utf-8")
    parser, findings = rescan(parser)
    assert not attack_path_section(parser)["results"]
    assert next(p for p in attack_path_section(parser)["patterns"] if p["pattern-id"] == "protective-deny-defeated")["status"] == "not-assessed"
    assert any(f.rule_id.endswith("shadowed_rule") for f in findings)


def test_repeated_asa_ace_does_not_move_first_deny_or_complete_path(tmp_path):
    from pathlib import Path
    parser, _ = protective_case(tmp_path, "ASA", True)
    path = Path(parser.config_filepath)
    path.write_text(path.read_text(encoding="utf-8").replace("deny ip 0.0.0.0 128.0.0.0", "deny ip any"), encoding="utf-8")
    parser, _ = rescan(parser)
    assert parser.get_acl_entries("EDGE")[0].action == "deny"
    assert not attack_path_section(parser)["results"]
    assert next(p for p in attack_path_section(parser)["patterns"] if p["pattern-id"] == "protective-deny-defeated")["status"] == "not-assessed"
    assert result_for(parser, "cisco.asa.policy-order")["outcome"] == "unknown"
