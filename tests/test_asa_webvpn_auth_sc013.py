"""SC-013: opt-in certificate requirement on explicit ASA WebVPN entry points."""

import pytest

from src.analyze.cisco.asa.plugins.baseline_plugin import PluginASABaseline
from src.common.assessment import AssessmentContext
from src.devices.cisco.asa import CiscoASAParser


RULE = "cisco.asa.remote_access.client_certificate_missing"
BASE = """ASA Version 9.16(4)
webvpn
 enable outside
tunnel-group EMPLOYEES type remote-access
tunnel-group EMPLOYEES webvpn-attributes
 authentication aaa
 group-url https://vpn.example.invalid/syntheticprivate enable
"""


def _scan(tmp_path, config, required=True):
    path = tmp_path / "asa.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoASAParser(str(path))
    parser.set_assessment_context(AssessmentContext.from_mapping({
        "asa_ra_require_client_certificate": required,
    }))
    plugin = PluginASABaseline()
    plugin.check_remote_access_authentication(parser)
    return parser, [item for item in plugin.get_issues() if item.rule_id == RULE]


def test_explicit_aaa_only_selectable_profile_under_certificate_policy(tmp_path):
    parser, findings = _scan(tmp_path, BASE)
    profile = parser.get_selectable_webvpn_profiles()[0]
    assert (profile.name, profile.authentication) == ("EMPLOYEES", "aaa")
    assert [item.rule_id for item in findings] == [RULE]
    assert "syntheticprivate" not in " ".join(item.text for item in profile.evidence)
    assert "syntheticprivate" not in " ".join(findings[0].evidence)


@pytest.mark.parametrize("config,required", [
    (BASE, False),
    (BASE.replace("authentication aaa", "authentication aaa certificate"), True),
    (BASE.replace("authentication aaa", "authentication certificate"), True),
    (BASE.replace("authentication aaa", "authentication saml"), True),
    (BASE + "no webvpn\n", True),
    (BASE.replace(" enable outside", " no enable outside"), True),
    (BASE.replace("group-url https://vpn.example.invalid/syntheticprivate enable",
                  "group-url https://vpn.example.invalid/syntheticprivate disable"), True),
    (BASE.replace("type remote-access", "type ipsec-l2l"), True),
    (BASE + " no authentication\n", True),
    (BASE.replace("ASA Version 9.16(4)", "ASA Version 9.12(1)"), True),
])
def test_unqualified_or_certificate_required_path_is_not_flagged(tmp_path, config, required):
    _, findings = _scan(tmp_path, config, required)
    assert findings == []


def test_policy_boolean_validation():
    context = AssessmentContext.from_mapping({"asa_ra_require_client_certificate": True})
    assert context.to_dict()["asa-ra-require-client-certificate"] is True
    with pytest.raises(ValueError, match="asa_ra_require_client_certificate"):
        AssessmentContext.from_mapping({"asa_ra_require_client_certificate": "true"})
