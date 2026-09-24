"""IDP policy inventory must follow an active permitting SRX security rule."""

from src.devices.juniper.junos import JunOSParser


POLICY = (
    "set security policies from-zone trust to-zone untrust policy web "
    "match source-address any\n"
    "set security policies from-zone trust to-zone untrust policy web "
    "match destination-address any\n"
    "set security policies from-zone trust to-zone untrust policy web "
    "match application junos-http\n"
)
DIRECT = (
    "set security policies from-zone trust to-zone untrust policy web "
    "then permit application-services idp-policy edge-idp\n"
)
LEGACY = (
    "set security idp active-policy edge-idp\n"
    "set security policies from-zone trust to-zone untrust policy web "
    "then permit application-services idp\n"
)
RULE = (
    "set security idp idp-policy edge-idp rulebase-ips rule catch "
    "match application default\n"
    "set security idp idp-policy edge-idp rulebase-ips rule catch "
    "then severity critical\n"
    "set security idp idp-policy edge-idp rulebase-ips rule catch "
    "then action no-action\n"
)


def _parser(tmp_path, body):
    source = tmp_path / "idp.conf"
    source.write_text("## Model: SRX345\nset version 22.4R1.10\n" + body,
                      encoding="utf-8")
    return JunOSParser(str(source))


def test_direct_policy_binding_resolves_active_rule_action_and_severity(tmp_path):
    binding, = _parser(tmp_path, POLICY + DIRECT + RULE).get_idp_bindings()
    assert binding.selection == "policy-direct"
    assert binding.idp_policy == "edge-idp"
    assert binding.resolution_state == "resolved"
    rule, = binding.rules
    assert (rule.name, rule.action, rule.severity, rule.has_match) == (
        "catch", "no-action", "critical", True
    )


def test_legacy_binding_requires_active_global_selection(tmp_path):
    binding, = _parser(tmp_path, POLICY + LEGACY + RULE).get_idp_bindings()
    assert binding.selection == "legacy-active-policy"
    assert binding.resolution_state == "resolved"
    missing, = _parser(tmp_path, POLICY + LEGACY + RULE +
                       "deactivate security idp active-policy edge-idp\n").get_idp_bindings()
    assert missing.resolution_state == "missing-active-policy"
    assert missing.idp_policy is None


def test_inactive_or_denied_security_policy_does_not_bind_idp(tmp_path):
    inactive = _parser(tmp_path, POLICY + DIRECT + RULE +
                       "deactivate security policies from-zone trust to-zone untrust policy web\n")
    assert inactive.get_idp_bindings() == ()
    denied = _parser(tmp_path, POLICY + DIRECT + RULE +
                     "set security policies from-zone trust to-zone untrust policy web then deny\n")
    assert denied.get_idp_bindings() == ()


def test_unbound_or_inactive_idp_rules_do_not_establish_action(tmp_path):
    unbound = _parser(tmp_path, POLICY +
                      "set security policies from-zone trust to-zone untrust policy web then permit\n" + RULE)
    assert unbound.get_idp_bindings() == ()
    inactive = _parser(tmp_path, POLICY + DIRECT + RULE +
                       "deactivate security idp idp-policy edge-idp rulebase-ips rule catch\n")
    binding, = inactive.get_idp_bindings()
    assert binding.resolution_state == "unresolved-policy"
    assert binding.rules == ()


def test_inherited_idp_binding_is_not_claimed_resolved(tmp_path):
    parser = _parser(tmp_path, POLICY + DIRECT + RULE +
                     "set security apply-groups inherited-idp\n")
    binding, = parser.get_idp_bindings()
    assert binding.resolution_state == "inheritance-unknown"


def test_hierarchical_idp_binding_and_rule(tmp_path):
    source = tmp_path / "idp-hier.conf"
    source.write_text("""## Model: SRX345
version 22.4R1.10;
security {
    policies { from-zone trust to-zone untrust {
        policy web {
            match { source-address any; destination-address any; application junos-http; }
            then { permit { application-services { idp-policy edge-idp; } } }
        }
    } }
    idp { idp-policy edge-idp { rulebase-ips { rule catch {
        match { application default; }
        then { severity critical; action no-action; }
    } } } }
}
""", encoding="utf-8")
    binding, = JunOSParser(str(source)).get_idp_bindings()
    assert binding.resolution_state == "resolved"
    assert binding.rules[0].action == "no-action"


# Stage B detection: an applied IDP policy whose every active IPS rule is non-blocking.
from src.analyze.juniper.junos.core.process_junos_conf import process_junos_conf  # noqa: E402

IDP_RULE_ID = "juniper.junos.policy.idp_nonblocking"


def _rule(name, action):
    return (
        f"set security idp idp-policy edge-idp rulebase-ips rule {name} match application default\n"
        f"set security idp idp-policy edge-idp rulebase-ips rule {name} then action {action}\n"
    )


def _idp_findings(tmp_path, body, model="SRX345"):
    source = tmp_path / "idp-plugin.conf"
    source.write_text(f"## Model: {model}\nset version 22.4R1.10\n" + body, encoding="utf-8")
    return [item for item in process_junos_conf(JunOSParser(str(source))).values()
            if item.rule_id == IDP_RULE_ID]


def test_all_non_blocking_rules_are_reported(tmp_path):
    finding, = _idp_findings(
        tmp_path, POLICY + DIRECT + _rule("log-only", "no-action") + _rule("skip", "ignore-connection")
    )
    assert "edge-idp" in finding.observation and "ignore-connection, no-action" in finding.observation
    assert all(item.line_number for item in finding.evidence_locations)


def test_one_blocking_or_recommended_rule_suppresses_the_finding(tmp_path):
    assert _idp_findings(tmp_path, POLICY + DIRECT + _rule("a", "no-action") + _rule("b", "drop-connection")) == []
    assert _idp_findings(tmp_path, POLICY + DIRECT + _rule("a", "no-action") + _rule("b", "recommended")) == []


def test_unknown_or_unresolved_state_is_not_graded(tmp_path):
    ambiguous = POLICY + DIRECT + _rule("a", "no-action") + (
        "set security idp idp-policy edge-idp rulebase-ips rule b match application default\n"
    )
    assert _idp_findings(tmp_path, ambiguous) == []  # rule b has no explicit action
    assert _idp_findings(tmp_path, POLICY + DIRECT) == []  # no exported rules
    assert _idp_findings(tmp_path, POLICY + LEGACY + _rule("a", "no-action")
                         + "deactivate security idp active-policy edge-idp\n") == []
    assert _idp_findings(tmp_path, POLICY + DIRECT + _rule("a", "no-action")
                         + "set security apply-groups inherited\n") == []


def test_unbound_inactive_and_non_srx_cases_are_not_reported(tmp_path):
    unbound = POLICY + "set security policies from-zone trust to-zone untrust policy web then permit\n"
    assert _idp_findings(tmp_path, unbound + _rule("a", "no-action")) == []
    inactive = POLICY + DIRECT + _rule("a", "no-action") + (
        "deactivate security policies from-zone trust to-zone untrust policy web\n"
    )
    assert _idp_findings(tmp_path, inactive) == []
    assert _idp_findings(tmp_path, POLICY + DIRECT + _rule("a", "no-action"), model="EX4300") == []


def test_legacy_active_policy_binding_is_reported(tmp_path):
    finding, = _idp_findings(tmp_path, POLICY + LEGACY + _rule("a", "no-action"))
    assert "edge-idp" in finding.observation
