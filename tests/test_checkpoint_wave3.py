from src.analyze.checkpoint.plugins.fw1_checks_plugin import PluginCheckPointChecks
from src.devices.checkpoint.fw1 import CheckPointFW1Parser


def _analyze(tmp_path, rules):
    (tmp_path / "rules.C").write_text(rules, encoding="utf-8")
    parser = CheckPointFW1Parser(str(tmp_path))
    plugin = PluginCheckPointChecks()
    plugin.analyze(parser)
    return parser, plugin.get_issues()


def test_checkpoint_evaluates_wildcards_within_each_rule_boundary(tmp_path):
    rules = r'''(:rule-base (
      :rule-1 (
        :name ("Narrow accept with any in comment")
        :comments ("accept Any Any")
        :src (ReferenceObject (:Name ("Admin Networks")))
        :dst (ReferenceObject (:Name ("Branch Firewall")))
        :services (ReferenceObject (:Name (ssh)))
        :action (accept)
      )
      :rule-2 (
        :name ("Any cleanup deny")
        :src (Any) :dst (Any) :services (Any) :action (drop)
      )
    ))'''
    _, issues = _analyze(tmp_path, rules)
    assert issues == []


def test_checkpoint_only_reports_enabled_broad_accept_rules(tmp_path):
    rules = r'''(:rule-base (
      :rule-1 (
        :name ("Disabled broad") :disabled (true)
        :src (Any) :dst (Any) :services (Any) :action (accept)
      )
      :rule-2 (
        :name ("Service restricted") :disabled (false)
        :src (Any) :dst (Any) :services (HTTPS) :action (accept)
      )
      :rule-3 (
        :name ("Broad installed rule") :disabled (false)
        :src (Any) :dst (Any) :services (Any) :action (accept)
        :track (Log)
        :install-on (ReferenceObject (:Name ("Internet Gateways")))
      )
    ))'''
    _, issues = _analyze(tmp_path, rules)
    assert len(issues) == 1
    finding = issues[0]
    assert "Broad installed rule" in finding.observation
    assert "position 3" in finding.observation
    assert "Log" in finding.observation
    assert "Internet Gateways" in finding.observation


def test_object_names_containing_any_are_not_wildcards(tmp_path):
    rules = r'''(:rule-base (
      :rule-1 (
        :name ("Company accept")
        :src (ReferenceObject (:Name ("Company-Network")))
        :dst (Any) :services (Any) :action (accept)
      )
    ))'''
    _, issues = _analyze(tmp_path, rules)
    assert issues == []
