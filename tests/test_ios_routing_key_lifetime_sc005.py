"""SC-005: explicit UTC key-lifetime viability on active IOS routing interfaces."""

import pytest

from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.common.assessment import AssessmentContext
from src.devices.cisco.ios import CiscoIOSParser


RULE = "cisco.ios.routing.key_lifetime_unusable"
TIME = "2026-09-23T12:00:00Z"
EXPIRED = (
    "  send-lifetime 00:00:00 Jan 1 2020 00:00:00 Jan 1 2021\n"
    "  accept-lifetime 00:00:00 Jan 1 2020 00:00:00 Jan 1 2021\n"
)
FUTURE = (
    "  send-lifetime 00:00:00 Jan 1 2026 infinite\n"
    "  accept-lifetime 00:00:00 Jan 1 2026 infinite\n"
)
EIGRP = (
    "router eigrp 10\n network 192.0.2.0 0.0.0.255\n"
    "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n"
    " ip authentication mode eigrp 10 md5\n"
    " ip authentication key-chain eigrp 10 EDGE\n"
)


def _scan(tmp_path, config, assessment_time=TIME):
    path = tmp_path / "router.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    if assessment_time:
        parser.set_assessment_context(AssessmentContext.from_mapping({
            "assessment_time": assessment_time,
        }))
    plugin = PluginIOSBaseline()
    plugin.check_routing(parser)
    return parser, [item for item in plugin.get_issues() if item.rule_id == RULE]


def test_expired_eigrp_key_lifetime(tmp_path):
    config = ("version 17.9\nclock timezone UTC 0\nkey chain EDGE\n"
              " key 1\n  key-string 7 syntheticprivate\n" + EXPIRED + EIGRP)
    parser, findings = _scan(tmp_path, config)
    assert parser.get_routing_key_lifetime_states()["edge"][0] == "unusable"
    assert [item.rule_id for item in findings] == [RULE]
    assert "syntheticprivate" not in " ".join(findings[0].evidence)


@pytest.mark.parametrize("protocol", ["rip", "ospf"])
def test_other_active_routing_key_bindings(tmp_path, protocol):
    interface = (
        "router rip\n version 2\n network 192.0.2.0\n"
        "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n"
        " ip rip receive version 2\n ip rip authentication key-chain EDGE\n"
        " ip rip authentication mode md5\n"
        if protocol == "rip" else
        "router ospf 1\ninterface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n"
        " ip ospf 1 area 0\n ip ospf authentication key-chain EDGE\n"
    )
    _, findings = _scan(
        tmp_path, "version 17.9\nclock timezone UTC 0\nkey chain EDGE\n"
        " key 1\n  key-string 7 syntheticprivate\n" + EXPIRED + interface,
    )
    assert [item.rule_id for item in findings] == [RULE]


def test_valid_rollover_key_prevents_unusable_finding(tmp_path):
    config = ("version 17.9\nclock timezone UTC 0\nkey chain EDGE\n"
              " key 1\n  key-string 7 oldsecret\n" + EXPIRED
              + " key 2\n  key-string 7 newsecret\n" + FUTURE + EIGRP)
    parser, findings = _scan(tmp_path, config)
    assert parser.get_routing_key_lifetime_states()["edge"][0] == "usable"
    assert findings == []


@pytest.mark.parametrize("prefix,assessment_time", [
    ("version 17.9\n", TIME),
    ("version 17.9\nclock timezone UTC 0\nclock summer-time CET recurring\n", TIME),
    ("version 17.9\nclock timezone UTC 0\n", None),
])
def test_missing_time_or_ambiguous_device_clock_is_ungraded(tmp_path, prefix, assessment_time):
    parser, findings = _scan(
        tmp_path, prefix + "key chain EDGE\n key 1\n  key-string 7 syntheticprivate\n"
        + EXPIRED + EIGRP, assessment_time,
    )
    assert parser.get_routing_key_lifetime_states() == {}
    assert findings == []


def test_unknown_lifetime_syntax_is_not_called_expired(tmp_path):
    parser, findings = _scan(
        tmp_path, "version 17.9\nclock timezone UTC 0\nkey chain EDGE\n"
        " key 1\n  key-string 7 syntheticprivate\n"
        "  send-lifetime unknown syntax\n" + EIGRP,
    )
    assert parser.get_routing_key_lifetime_states()["edge"][0] == "unknown"
    assert findings == []


def test_no_lifetime_resets_to_default_and_removed_chain_is_ignored(tmp_path):
    config = ("version 17.9\nclock timezone UTC 0\nkey chain EDGE\n"
              " key 1\n  key-string 7 syntheticprivate\n" + EXPIRED
              + "  no send-lifetime\n  no accept-lifetime\n" + EIGRP)
    parser, findings = _scan(tmp_path, config)
    assert parser.get_routing_key_lifetime_states()["edge"][0] == "usable"
    assert findings == []
