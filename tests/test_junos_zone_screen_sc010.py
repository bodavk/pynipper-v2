"""Bounded SRX screen attachment and explicit inactive-option coverage."""

import pytest

from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.common.assessment import AssessmentContext
from src.devices.juniper.junos import JunOSParser


def _parser(tmp_path, body, *, model="SRX345", external=True):
    source = tmp_path / "junos-screen.conf"
    source.write_text(f"## Model: {model}\nset version 22.4R1.10\n{body}", encoding="utf-8")
    parser = JunOSParser(str(source))
    if external:
        parser.set_assessment_context(AssessmentContext.from_mapping({
            "interface_roles": {"ge-0/0/0": "external"}
        }))
    return parser


BOUND = (
    "set security zones security-zone untrust interfaces ge-0/0/0.0\n"
    "set security zones security-zone untrust screen edge-screen\n"
)
OPTION = "set security screen ids-option edge-screen tcp syn-flood attack-threshold 625\n"


def _findings(parser):
    plugin = PluginJunOSBaseline()
    plugin.check_zone_screens(parser)
    return plugin.get_issues()


def test_attached_inactive_syn_flood_reports_only_on_assessed_srx_zone(tmp_path):
    parser = _parser(tmp_path, BOUND + OPTION +
                     "deactivate security screen ids-option edge-screen tcp syn-flood\n")
    screens = parser.get_zone_screens()
    assert len(screens) == 1
    assert screens[0].syn_flood_state == "explicitly-inactive"
    findings = _findings(parser)
    assert len(findings) == 1
    assert findings[0].rule_id == "juniper.junos.screen.syn_flood_inactive"
    assert "ge-0/0/0.0" in findings[0].observation


def test_explicit_inactive_udp_flood_and_alarm_only_active_udp_flood(tmp_path):
    udp = "set security screen ids-option edge-screen udp flood threshold 1000\n"
    inactive = _parser(tmp_path, BOUND + udp +
                       "deactivate security screen ids-option edge-screen udp flood\n")
    assert [item.rule_id for item in _findings(inactive)] == [
        "juniper.junos.screen.udp_flood_inactive"
    ]
    alarm = _parser(tmp_path, BOUND + udp +
                    "set security screen ids-option edge-screen alarm-without-drop\n")
    assert [item.rule_id for item in _findings(alarm)] == [
        "juniper.junos.screen.udp_flood_alarm_only"
    ]


def test_alarm_only_requires_active_udp_and_effective_alarm_directive(tmp_path):
    udp = "set security screen ids-option edge-screen udp flood threshold 1000\n"
    alarm = "set security screen ids-option edge-screen alarm-without-drop\n"
    assert _findings(_parser(tmp_path, BOUND + alarm)) == []
    assert _findings(_parser(tmp_path, BOUND + udp + alarm +
                             "deactivate security screen ids-option edge-screen alarm-without-drop\n")) == []


def test_explicit_inactive_and_alarm_only_icmp_flood(tmp_path):
    icmp = "set security screen ids-option edge-screen icmp flood threshold 1000\n"
    inactive = _parser(tmp_path, BOUND + icmp +
                       "deactivate security screen ids-option edge-screen icmp flood\n")
    assert [item.rule_id for item in _findings(inactive)] == [
        "juniper.junos.screen.icmp_flood_inactive"
    ]
    alarm = _parser(tmp_path, BOUND + icmp +
                    "set security screen ids-option edge-screen alarm-without-drop\n")
    assert [item.rule_id for item in _findings(alarm)] == [
        "juniper.junos.screen.icmp_flood_alarm_only"
    ]


@pytest.mark.parametrize("body,model,external", [
    (BOUND + OPTION, "SRX345", True),
    (BOUND + "set security screen ids-option edge-screen tcp port-scan threshold 5000\n", "SRX345", True),
    (BOUND + OPTION + "deactivate security screen ids-option edge-screen tcp syn-flood\n"
     "activate security screen ids-option edge-screen tcp syn-flood\n", "SRX345", True),
    (BOUND + OPTION + "deactivate security screen ids-option edge-screen tcp syn-flood\n",
     "SRX345", False),
    (BOUND + OPTION + "deactivate security screen ids-option edge-screen tcp syn-flood\n",
     "EX4300", True),
    ("set security zones security-zone untrust interfaces ge-0/0/0.0\n" + OPTION +
     "deactivate security screen ids-option edge-screen tcp syn-flood\n", "SRX345", True),
    (BOUND + OPTION + "deactivate security screen ids-option edge-screen tcp syn-flood\n"
     "set security apply-groups screen-group\n", "SRX345", True),
    (BOUND + OPTION + "delete security screen ids-option edge-screen tcp syn-flood\n", "SRX345", True),
])
def test_unknown_unbound_restored_inherited_or_non_srx_state_is_not_reported(
    tmp_path, body, model, external
):
    assert _findings(_parser(tmp_path, body, model=model, external=external)) == []


def test_hierarchical_inactive_option_preserves_attachment_evidence(tmp_path):
    source = tmp_path / "junos-screen-hierarchical.conf"
    source.write_text("""## Model: SRX345
version 22.4R1.10;
security {
    zones { security-zone untrust {
        interfaces { ge-0/0/0.0; }
        screen edge-screen;
    } }
    screen { ids-option edge-screen {
        tcp { inactive: syn-flood { attack-threshold 625; } }
    } }
}
""", encoding="utf-8")
    parser = JunOSParser(str(source))
    parser.set_assessment_context(AssessmentContext.from_mapping({
        "interface_roles": {"ge-0/0/0": "external"}
    }))
    assert len(_findings(parser)) == 1
