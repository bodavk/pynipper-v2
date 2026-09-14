from src.analyze.checkpoint.core.process_checkpoint_fw1_conf import (
    process_checkpoint_fw1_conf,
)
from src.analyze.checkpoint.plugins.fw1_baseline_plugin import (
    PluginCheckPointBaseline,
)
from src.devices.checkpoint.fw1 import CheckPointFW1Parser


OBJECTS = r'''(:objects (
  :network-objects (
    :Gateway-A (:type (gateway) :ipaddr (192.0.2.1) :firewall (installed))
    :Gateways (:type (group) :members (
      (ReferenceObject (:Name (Gateway-A)))
    ))
    :Admin-Networks (:type (network) :ipaddr (192.0.2.0) :netmask (255.255.255.0))
    :Internal-Networks (:type (network) :ipaddr (10.0.0.0) :netmask (255.0.0.0))
    :Web-Servers (:type (group) :members (
      (ReferenceObject (:Name (Web-01)))
    ))
    :Web-01 (:type (host) :ipaddr (10.10.10.20))
  )
  :services (
    :SSH (:type (tcp) :port (22))
    :HTTPS (:type (tcp) :port (443))
    :Telnet-Service (:type (tcp) :port (23))
    :Legacy-Admin (:type (group) :members (
      (ReferenceObject (:Name (Telnet-Service)))
    ))
  )
))'''


SECURE_RULES = r'''(:rule-base (
  :Network-Layer (
    :type (ordered-layer)
    :implicit-cleanup-action (drop)
    :rule-1 (
      :name ("Admin access")
      :comments ("Any and accept in comments are not rule fields")
      :src (ReferenceObject (:Name (Admin-Networks)))
      :dst (ReferenceObject (:Name (Gateways)))
      :services (ReferenceObject (:Name (SSH)))
      :action (accept) :track (Log)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
    :rule-2 (
      :name (Stealth)
      :src (Any) :dst (ReferenceObject (:Name (Gateways)))
      :services (Any) :action (drop) :track (Alert)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
    :rule-3 (
      :name ("Publish web")
      :src (ReferenceObject (:Name (Internal-Networks)))
      :dst (ReferenceObject (:Name (Web-Servers)))
      :services (ReferenceObject (:Name (HTTPS)))
      :action (accept) :track (Log)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
    :rule-4 (
      :name (Cleanup)
      :src (Any) :dst (Any) :services (Any)
      :action (drop) :track (Log)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
  )
  :Application-Layer (
    :type (application-layer)
    :implicit-cleanup-action (accept)
    :rule-1 (
      :name ("Approved web")
      :src (ReferenceObject (:Name (Internal-Networks)))
      :dst (Internet) :services (ReferenceObject (:Name (HTTPS)))
      :action (accept) :track (Log)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
    :rule-2 (
      :name ("Application cleanup")
      :src (Any) :dst (Any) :services (Any)
      :action (accept) :track (Log)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
  )
))'''


VULNERABLE_RULES = r'''(:rule-base (
  :Network-Layer (
    :type (ordered-layer)
    :implicit-cleanup-action (drop)
    :rule-1 (
      :name ("Broad first")
      :src (Any) :dst (Any) :services (Any)
      :action (accept) :track (None) :install-on (Any)
    )
    :rule-2 (
      :name ("Shadowed deny")
      :src (ReferenceObject (:Name (Admin-Networks)))
      :dst (ReferenceObject (:Name (Web-Servers)))
      :services (ReferenceObject (:Name (HTTPS)))
      :action (drop) :track (Log) :install-on (Any)
    )
    :rule-3 (
      :name ("Redundant broad")
      :comments ("drop Any cleanup words must not alter semantics")
      :src (Any) :dst (Any) :services (Any)
      :action (accept) :track (Log) :install-on (Any)
    )
    :rule-4 (
      :name ("Expired exception")
      :src (ReferenceObject (:Name (Admin-Networks)))
      :dst (ReferenceObject (:Name (Web-Servers)))
      :services (ReferenceObject (:Name (HTTPS)))
      :action (accept) :track (Log) :expiration-date (2000-01-01)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
    :rule-5 (
      :name ("Negated source")
      :src (ReferenceObject (:Name (Admin-Networks))) :src-op (not in)
      :dst (Any) :services (ReferenceObject (:Name (HTTPS)))
      :action (accept) :track (None)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
    :rule-6 (
      :name ("Legacy administration")
      :src (Any) :dst (ReferenceObject (:Name (Web-Servers)))
      :services (ReferenceObject (:Name (Legacy-Admin)))
      :action (accept) :track (None)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
    :rule-7 (
      :name ("Disabled temporary allow") :disabled (true)
      :src (Any) :dst (Any) :services (Any)
      :action (accept) :track (None)
    )
    :rule-8 (
      :name ("Broken reference")
      :src (ReferenceObject (:Name (Missing-Host)))
      :dst (ReferenceObject (:Name (Web-Servers)))
      :services (ReferenceObject (:Name (HTTPS)))
      :action (drop) :track (Log)
    )
  )
))'''


def _parser(tmp_path, rules, objects=OBJECTS, rulebases=None):
    (tmp_path / "rules.C").write_text(rules, encoding="utf-8")
    if objects is not None:
        (tmp_path / "objects.C").write_text(objects, encoding="utf-8")
    if rulebases is not None:
        (tmp_path / "rulebases.fws").write_text(rulebases, encoding="utf-8")
    return CheckPointFW1Parser(str(tmp_path))


def _issues(tmp_path, rules, objects=OBJECTS):
    parser = _parser(tmp_path, rules, objects)
    plugin = PluginCheckPointBaseline()
    plugin.analyze(parser)
    return parser, plugin.get_issues()


def test_checkpoint_parser_builds_typed_layers_objects_services_and_groups(tmp_path):
    parser = _parser(tmp_path, SECURE_RULES)

    layers = parser.get_policy_layers()
    assert [layer.name for layer in layers] == [
        "rule-base / Network-Layer",
        "rule-base / Application-Layer",
    ]
    assert [rule.position for rule in layers[0].rules] == [1, 2, 3, 4]
    assert layers[0].implicit_cleanup_action == "drop"
    assert layers[1].kind == "application-layer"

    objects = {item.name: item for item in parser.get_policy_objects()}
    services = {item.name: item for item in parser.get_service_objects()}
    assert objects["Gateway-A"].firewall is True
    assert objects["Gateways"].members == ("Gateway-A",)
    assert services["Telnet-Service"].port == "23"
    assert services["Legacy-Admin"].members == ("Telnet-Service",)


def test_secure_two_layer_policy_has_no_checkpoint_baseline_findings(tmp_path):
    parser, issues = _issues(tmp_path, SECURE_RULES)

    assert issues == [], [
        (issue.rule_id, issue.observation) for issue in issues
    ]
    assert process_checkpoint_fw1_conf(parser) == {}


def test_vulnerable_policy_emits_stable_rule_ids_and_references(tmp_path):
    _, issues = _issues(tmp_path, VULNERABLE_RULES)
    rule_ids = {issue.rule_id for issue in issues}

    assert rule_ids == {
        "checkpoint.fw1.layer.explicit_cleanup_missing",
        "checkpoint.fw1.layer.stealth_rule_missing",
        "checkpoint.fw1.policy.disabled_permissive_rule",
        "checkpoint.fw1.policy.expired_rule",
        "checkpoint.fw1.policy.negated_accept",
        "checkpoint.fw1.policy.install_scope_any",
        "checkpoint.fw1.policy.risky_service_exposure",
        "checkpoint.fw1.policy.sensitive_accept_untracked",
        "checkpoint.fw1.policy.shadowed_rule",
        "checkpoint.fw1.policy.redundant_rule",
        "checkpoint.fw1.policy.unresolved_reference",
    }
    assert all(issue.references for issue in issues)
    assert all("comments" not in " ".join(issue.evidence).casefold() for issue in issues)


def test_partial_breadth_and_untracked_cleanup_are_distinct_root_causes(tmp_path):
    rules = r'''(:rule-base (:Network-Layer (
      :type (ordered-layer) :implicit-cleanup-action (drop)
      :rule-1 (:name ("Broad web") :src (Any) :dst (Any)
        :services (HTTPS) :action (accept) :track (None))
      :rule-2 (:name (Cleanup) :src (Any) :dst (Any) :services (Any)
        :action (drop) :track (None))
    )))'''
    _, issues = _issues(tmp_path, rules)
    ids = {issue.rule_id for issue in issues}

    assert "checkpoint.fw1.policy.overly_broad_accept" in ids
    assert "checkpoint.fw1.policy.sensitive_accept_untracked" in ids
    assert "checkpoint.fw1.layer.cleanup_untracked" in ids
    assert "checkpoint.fw1.layer.explicit_cleanup_missing" not in ids


def test_disabled_rules_do_not_shadow_or_trigger_active_policy_checks(tmp_path):
    rules = r'''(:rule-base (:Network-Layer (
      :rule-1 (:name ("Disabled broad") :disabled (true)
        :src (Any) :dst (Any) :services (Any) :action (accept) :track (None))
    )))'''
    _, issues = _issues(tmp_path, rules, objects=None)

    assert {issue.rule_id for issue in issues} == {
        "checkpoint.fw1.policy.disabled_permissive_rule"
    }


def test_missing_object_export_is_unknown_not_unresolved(tmp_path):
    rules = r'''(:rule-base (:Network-Layer (
      :rule-1 (:name ("External object") :src (External-System)
        :dst (Internal-System) :services (Custom-App) :action (drop) :track (Log))
      :rule-2 (:name (Cleanup) :src (Any) :dst (Any) :services (Any)
        :action (drop) :track (Log))
    )))'''
    _, issues = _issues(tmp_path, rules, objects=None)

    assert "checkpoint.fw1.policy.unresolved_reference" not in {
        issue.rule_id for issue in issues
    }


def test_rules_file_wins_over_repeated_rulebase_metadata(tmp_path):
    parser = _parser(tmp_path, SECURE_RULES, rulebases=SECURE_RULES)

    assert len(parser.get_policy_rules()) == 6
    normalized = parser.get_normalized_config().policies.items
    assert len(normalized) == 6


def test_unresolved_nested_group_member_is_reported(tmp_path):
    objects = OBJECTS.replace(
        "(ReferenceObject (:Name (Telnet-Service)))",
        "(ReferenceObject (:Name (Missing-Service)))",
    )
    _, issues = _issues(tmp_path, SECURE_RULES, objects)

    findings = [
        issue
        for issue in issues
        if issue.rule_id == "checkpoint.fw1.object.unresolved_group_member"
    ]
    assert len(findings) == 1
    assert "Missing-Service" in findings[0].observation


def test_public_pipeline_has_unique_rule_bound_evidence(tmp_path):
    parser = _parser(tmp_path, VULNERABLE_RULES)
    findings = list(process_checkpoint_fw1_conf(parser).values())
    identities = [(finding.rule_id, finding.evidence) for finding in findings]

    assert "checkpoint.fw1.policy.broad_accept" in {
        finding.rule_id for finding in findings
    }
    assert len(identities) == len(set(identities))


def test_legacy_anonymous_object_and_rule_names_are_preserved(tmp_path):
    objects = r'''(
      :network_objects (
        : (Legacy-Gateway :type (gateway) :firewall (installed))
        : (Legacy-Group :type (group) :members (
          (ReferenceObject (:Name (Legacy-Gateway)))
        ))
      )
      :services (
        : (legacy-telnet :type (tcp) :port (23))
      )
    )'''
    rules = r'''(:rules (
      : (legacy-stealth :src (Any) :dst (Legacy-Group) :services (Any)
        :action (drop) :track (Log))
      : (legacy-cleanup :src (Any) :dst (Any) :services (Any)
        :action (drop) :track (Log))
    ))'''
    parser = _parser(tmp_path, rules, objects)

    assert [item.name for item in parser.get_policy_objects()] == [
        "Legacy-Gateway",
        "Legacy-Group",
    ]
    assert [item.name for item in parser.get_service_objects()] == ["legacy-telnet"]
    assert [rule.name for rule in parser.get_policy_rules()] == [
        "legacy-stealth",
        "legacy-cleanup",
    ]
    assert [rule.layer for rule in parser.get_policy_rules()] == ["rules", "rules"]


def test_negation_field_variants_and_future_expiry_are_handled(tmp_path):
    rules = r'''(:rule-base (:Network-Layer (
      :rule-1 (:name ("Source exclusion") :src (Admin-Networks)
        :source-negated (true) :dst (Web-Servers) :services (HTTPS)
        :action (accept) :track (Log))
      :rule-2 (:name ("Destination exclusion") :src (Admin-Networks)
        :destination-op (not-in) :dst (Web-Servers) :services (HTTPS)
        :action (accept) :track (Log))
      :rule-3 (:name ("Service exclusion") :src (Admin-Networks)
        :dst (Web-Servers) :services (HTTPS) :services-op (notin)
        :action (accept) :track (Log) :expires (2999-01-01))
      :rule-4 (:name (Cleanup) :src (Any) :dst (Any) :services (Any)
        :action (drop) :track (Log))
    )))'''
    _, issues = _issues(tmp_path, rules)

    negated = [
        issue for issue in issues
        if issue.rule_id == "checkpoint.fw1.policy.negated_accept"
    ]
    assert len(negated) == 3
    assert "checkpoint.fw1.policy.expired_rule" not in {
        issue.rule_id for issue in issues
    }


SEMANTIC_OBJECTS = r'''(:objects (
  :network-objects (
    :Wide-Net (:type (network) :ipaddr (10.0.0.0) :netmask (255.0.0.0))
    :Narrow-Net (:type (address-range) :ipaddr-first (10.20.0.0)
      :ipaddr-last (10.20.255.255))
    :App-Range (:type (address-range) :ipaddr-first (192.0.2.0)
      :ipaddr-last (192.0.2.127))
    :App-Host (:type (host) :ipaddr (192.0.2.42))
    :Partial-A (:type (address-range) :ipaddr-first (198.51.100.0)
      :ipaddr-last (198.51.100.127))
    :Partial-B (:type (network) :ipaddr (198.51.100.0) :netmask (255.255.255.0))
    :Equal-Net-A (:type (network) :ipaddr (203.0.113.0) :netmask (255.255.255.0))
    :Equal-Net-B (:type (address-range) :ipaddr-first (203.0.113.0)
      :ipaddr-last (203.0.113.255))
  )
  :services (
    :Web-Range (:type (tcp) :port (8000-8999))
    :Web-Subrange (:type (tcp) :port (8440-8450))
    :Web-Single (:type (tcp) :port (8443))
    :Disjoint-Service (:type (tcp) :port (9443))
    :Partial-Service-A (:type (tcp) :port (8000-8100))
    :Partial-Service-B (:type (tcp) :port (8000-8200))
  )
))'''


def test_parser_resolves_bounded_network_and_service_semantics(tmp_path):
    parser = _parser(tmp_path, SECURE_RULES, SEMANTIC_OBJECTS)

    network = parser.resolve_network_semantics(("Wide-Net", "App-Host"))
    service = parser.resolve_service_semantics(("Web-Range", "Web-Single"))

    assert network.complete is True
    assert [(item.family, item.last - item.first) for item in network.intervals] == [
        (4, 2**24 - 1),
        (4, 0),
    ]
    assert service.complete is True
    assert [
        (item.protocol, item.first_port, item.last_port)
        for item in service.intervals
    ] == [("tcp", 8000, 8999), ("tcp", 8443, 8443)]


def test_semantic_subnet_range_and_port_containment_reuses_shadow_ids(tmp_path):
    rules = r'''(:rule-base (:Network-Layer (
      :type (ordered-layer) :implicit-cleanup-action (drop)
      :rule-1 (:name (Semantic-parent) :src (Wide-Net) :dst (Equal-Net-A)
        :services (Web-Range) :action (accept) :track (Log)
        :install-on (Policy-Targets))
      :rule-2 (:name (Semantic-shadow) :src (Narrow-Net) :dst (Equal-Net-B)
        :services (Web-Subrange) :action (drop) :track (Log)
        :install-on (Policy-Targets))
      :rule-3 (:name (Semantic-redundant) :src (Narrow-Net) :dst (Equal-Net-B)
        :services (Web-Single) :action (accept) :track (Log)
        :install-on (Policy-Targets))
      :rule-4 (:name (Cleanup) :src (Any) :dst (Any) :services (Any)
        :action (drop) :track (Log) :install-on (Policy-Targets))
    )))'''
    parser = _parser(tmp_path, rules, SEMANTIC_OBJECTS)
    findings = list(process_checkpoint_fw1_conf(parser).values())
    semantic = [
        finding for finding in findings
        if finding.rule_id in {
            "checkpoint.fw1.policy.shadowed_rule",
            "checkpoint.fw1.policy.redundant_rule",
        }
    ]

    assert [finding.rule_id for finding in semantic] == [
        "checkpoint.fw1.policy.shadowed_rule",
        "checkpoint.fw1.policy.redundant_rule",
    ]
    assert "Semantic-shadow" in semantic[0].observation
    assert "Semantic-redundant" in semantic[1].observation
    identities = [(finding.rule_id, finding.evidence) for finding in findings]
    assert len(identities) == len(set(identities))


def test_partial_or_disjoint_semantics_do_not_prove_shadowing(tmp_path):
    rules = r'''(:rule-base (:Network-Layer (
      :type (ordered-layer) :implicit-cleanup-action (drop)
      :rule-1 (:name (Partial-parent) :src (Partial-A) :dst (App-Range)
        :services (Partial-Service-A) :action (accept) :track (Log))
      :rule-2 (:name (Partial-child) :src (Partial-B) :dst (App-Host)
        :services (Partial-Service-B) :action (drop) :track (Log))
      :rule-3 (:name (Disjoint-service) :src (Narrow-Net) :dst (App-Host)
        :services (Disjoint-Service) :action (drop) :track (Log))
      :rule-4 (:name (Cleanup) :src (Any) :dst (Any) :services (Any)
        :action (drop) :track (Log))
    )))'''
    _, issues = _issues(tmp_path, rules, SEMANTIC_OBJECTS)

    assert not {
        "checkpoint.fw1.policy.shadowed_rule",
        "checkpoint.fw1.policy.redundant_rule",
    }.intersection(issue.rule_id for issue in issues)


def test_unresolved_malformed_and_cyclic_semantics_remain_unproven(tmp_path):
    objects = r'''(:objects (
      :network-objects (
        :Cycle-A (:type (group) :members (Cycle-B))
        :Cycle-B (:type (group) :members (Cycle-A))
        :Bad-Net (:type (network) :ipaddr (not-an-address)
          :netmask (255.255.255.0))
      )
      :services (
        :Bad-Service (:type (tcp) :port (not-a-port))
      )
    ))'''
    rules = r'''(:rule-base (:Network-Layer (
      :rule-1 (:name (Unresolved-parent) :src (Cycle-A) :dst (Any)
        :services (Any) :action (accept) :track (Log))
      :rule-2 (:name (Unresolved-child) :src (Cycle-B) :dst (Any)
        :services (Any) :action (drop) :track (Log))
      :rule-3 (:name (Malformed-parent) :src (Bad-Net) :dst (Any)
        :services (Bad-Service) :action (accept) :track (Log))
      :rule-4 (:name (Malformed-child) :src (Bad-Net) :dst (Any)
        :services (Bad-Service) :action (drop) :track (Log))
    )))'''
    parser, issues = _issues(tmp_path, rules, objects)

    assert parser.resolve_network_semantics(("Cycle-A",)).complete is False
    assert parser.resolve_network_semantics(("Bad-Net",)).complete is False
    assert parser.resolve_network_semantics(()).complete is False
    assert parser.resolve_service_semantics(("Bad-Service",)).complete is False
    assert not {
        "checkpoint.fw1.policy.shadowed_rule",
        "checkpoint.fw1.policy.redundant_rule",
    }.intersection(issue.rule_id for issue in issues)


def test_time_install_scope_and_layer_boundaries_block_semantic_comparison(tmp_path):
    rules = r'''(:rule-base (
      :Layer-A (
        :type (ordered-layer)
        :rule-1 (:name (Timed-parent) :src (Wide-Net) :dst (App-Range)
          :services (Web-Range) :time (Business-Hours) :action (accept)
          :install-on (Gateway-A) :track (Log))
        :rule-2 (:name (Different-time) :src (Narrow-Net) :dst (App-Host)
          :services (Web-Single) :time (Always) :action (drop)
          :install-on (Gateway-A) :track (Log))
        :rule-3 (:name (Different-install) :src (Narrow-Net) :dst (App-Host)
          :services (Web-Single) :time (Business-Hours) :action (drop)
          :install-on (Gateway-B) :track (Log))
      )
      :Layer-B (
        :type (ordered-layer)
        :rule-1 (:name (Different-layer) :src (Narrow-Net) :dst (App-Host)
          :services (Web-Single) :time (Business-Hours) :action (drop)
          :install-on (Gateway-A) :track (Log))
      )
    ))'''
    _, issues = _issues(tmp_path, rules, SEMANTIC_OBJECTS)

    assert not {
        "checkpoint.fw1.policy.shadowed_rule",
        "checkpoint.fw1.policy.redundant_rule",
    }.intersection(issue.rule_id for issue in issues)
