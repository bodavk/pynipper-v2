from collections.abc import Mapping

import pytest

from src.devices.checkpoint.fw1 import CheckPointFW1Parser
from src.devices.checkpoint.parser import CheckPointFileParser, CheckPointParseError
from src.devices.common.models import ConfigurationState, KnowledgeState


CHECKPOINT_RULES = r'''(
    :rule-base (
        :rule-1 (
            :name ("Allow Admin SSH")
            :comments ("Operations only (ticket #42)")
            :disabled (false)
            :src (ReferenceObject (:Name ("Admin Networks")))
            :dst (ReferenceObject (:Name ("Branch Firewall")))
            :services (ReferenceObject (:Name (ssh)))
            :action (accept)
            :track (Log)
            :install-on (ReferenceObject (:Name ("Policy Targets")))
        )
        :rule-2 (
            :name ("Disabled Any Rule")
            :disabled (true)
            :src (any)
            :dst (any)
            :services (any)
            :action (accept)
            :track (None)
        )
    )
)'''


def test_checkpoint_file_parser_preserves_fields_quotes_and_rule_boundaries(tmp_path):
    source = tmp_path / "rules.C"
    source.write_text(CHECKPOINT_RULES, encoding="utf-8")

    document = CheckPointFileParser(str(source)).parse()
    rules = document["rule-base"]

    assert isinstance(document, Mapping)
    assert rules["rule-1"]["name"] == "Allow Admin SSH"
    assert rules["rule-1"]["comments"] == "Operations only (ticket #42)"
    assert rules["rule-1"]["action"] == "accept"
    assert rules["rule-2"]["disabled"] == "true"


def test_checkpoint_fw1_parser_normalizes_ordered_rule_semantics(tmp_path):
    (tmp_path / "rules.C").write_text(CHECKPOINT_RULES, encoding="utf-8")
    parser = CheckPointFW1Parser(str(tmp_path))

    policies = parser.get_normalized_config().policies

    assert policies.state == KnowledgeState.KNOWN
    assert [policy.name for policy in policies.items] == ["Allow Admin SSH", "Disabled Any Rule"]
    assert [policy.position for policy in policies.items] == [1, 2]
    assert policies.items[0].sources == ("Admin Networks",)
    assert policies.items[0].destinations == ("Branch Firewall",)
    assert policies.items[0].services == ("ssh",)
    assert policies.items[0].action == "accept"
    assert policies.items[0].tracking == "Log"
    assert policies.items[0].install_on == ("Policy Targets",)
    assert policies.items[1].state == ConfigurationState.DISABLED


@pytest.mark.parametrize(
    "content, message, line",
    [
        (")", "Unmatched closing parenthesis", 1),
        ("(:rules (:rule-1 (:action (accept)))", "Unclosed parenthesized expression", 1),
        ('(:comments "unterminated)', "Unterminated quoted string", 1),
        ("unexpected", "Expected an opening parenthesis", 1),
    ],
)
def test_checkpoint_parser_reports_structural_errors(tmp_path, content, message, line):
    source = tmp_path / "rules.C"
    source.write_text(content, encoding="utf-8")

    with pytest.raises(CheckPointParseError, match=message) as error:
        CheckPointFileParser(str(source)).parse()

    assert error.value.line == line
    assert error.value.column >= 1
    assert error.value.source.endswith("rules.C")


def test_checkpoint_parser_preserves_duplicate_fields_in_order(tmp_path):
    source = tmp_path / "objects.C"
    source.write_text('(:group (:members ("one") :members ("two")))', encoding="utf-8")

    document = CheckPointFileParser(str(source)).parse()
    assert document["group"]["members"] == ["one", "two"]
