"""SC-021: opt-in exact ASA IKE DH profile on enabled policy families."""

import pytest

from src.analyze.cisco.asa.plugins.baseline_plugin import PluginASABaseline
from src.common.assessment import AssessmentContext
from src.devices.cisco.asa import CiscoASAParser


RULE = "cisco.asa.crypto.ike_dh_policy"
BASE = """ASA Version 9.16(4)
crypto ikev1 enable outside
crypto ikev1 policy 10
 authentication pre-share
 encryption aes-256
 hash sha256
 group 15
"""


def _scan(tmp_path, config, groups=("16", "19")):
    path = tmp_path / "asa.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoASAParser(str(path))
    if groups is not None:
        parser.set_assessment_context(AssessmentContext.from_mapping({
            "policy_version": "reviewed-vpn-v1",
            "approved_asa_ike_dh_groups": list(groups),
        }))
    plugin = PluginASABaseline()
    plugin.check_vpn_crypto(parser)
    return parser, [item for item in plugin.get_issues() if item.rule_id == RULE]


def test_nonblacklisted_but_profile_disallowed_group(tmp_path):
    parser, findings = _scan(tmp_path, BASE)
    assert [(item.version, item.group) for item in parser.get_active_ike_dh_groups()] == [
        ("ikev1", "15"),
    ]
    assert [item.rule_id for item in findings] == [RULE]
    assert "reviewed-vpn-v1" in findings[0].observation


def test_approved_exact_group_and_unapproved_ec_alternative(tmp_path):
    parser, findings = _scan(
        tmp_path, BASE.replace("group 15", "group 16 19"), groups=("16",),
    )
    assert [item.group for item in parser.get_active_ike_dh_groups()] == ["16", "19"]
    assert [item.rule_id for item in findings] == [RULE]
    assert "group 19" in findings[0].observation


@pytest.mark.parametrize("config,groups", [
    (BASE, None),
    (BASE.replace("crypto ikev1 enable outside\n", ""), ("16",)),
    (BASE + "no crypto ikev1 enable outside\n", ("16",)),
    (BASE + "no crypto ikev1 policy 10\n", ("16",)),
    (BASE.replace("group 15", "group 19"), ("19",)),
    (BASE.replace("group 15", "group 14"), ("16",)),
])
def test_unselected_inactive_approved_or_already_legacy_group(tmp_path, config, groups):
    _, findings = _scan(tmp_path, config, groups)
    assert findings == []


def test_ikev2_policy_and_activation_are_independent(tmp_path):
    config = (BASE.replace("crypto ikev1 enable outside\n", "")
              + "crypto ikev2 enable outside\n"
              "crypto ikev2 policy 20\n encryption aes-256\n integrity sha256\n group 15\n")
    parser, findings = _scan(tmp_path, config)
    assert [(item.version, item.priority) for item in parser.get_active_ike_dh_groups()] == [
        ("ikev2", "20"),
    ]
    assert [item.rule_id for item in findings] == [RULE]


def test_policy_validation_and_normalization():
    context = AssessmentContext.from_mapping({"approved_asa_ike_dh_groups": [16, "019"]})
    assert context.approved_asa_ike_dh_groups == ("16", "19")
    with pytest.raises(ValueError, match="approved_asa_ike_dh_groups"):
        AssessmentContext.from_mapping({"approved_asa_ike_dh_groups": [16, "16"]})
    with pytest.raises(ValueError, match="approved_asa_ike_dh_groups"):
        AssessmentContext.from_mapping({"approved_asa_ike_dh_groups": ["weak"]})
