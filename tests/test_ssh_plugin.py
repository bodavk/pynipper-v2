import pytest

from src.analyze.cisco.ios.plugins.ssh_plugin import PluginSSH
from src.devices.cisco.ios import CiscoIOSParser, ConfigurationState


def _analyze(tmp_path, config: str):
    path = tmp_path / "ios.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    plugin = PluginSSH()
    plugin.analyze(parser)
    return parser, {issue.rule_id for issue in plugin.get_issues()}


def _ssh_config(*global_commands: str, vty_children: tuple[str, ...] = ("transport input ssh",)):
    lines = [*global_commands, "line vty 0 4"]
    lines.extend(f" {child}" for child in vty_children)
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize(
    ("config", "state", "expected_rules"),
    [
        ("hostname router\n", ConfigurationState.ABSENT, set()),
        (
            _ssh_config("no ip ssh", vty_children=("transport input ssh",)),
            ConfigurationState.DISABLED,
            set(),
        ),
        (
            _ssh_config("ip ssh version 2", vty_children=("transport input telnet",)),
            ConfigurationState.ABSENT,
            set(),
        ),
    ],
)
def test_ssh_unconfigured_disabled_and_unreachable_states(
    tmp_path,
    config,
    state,
    expected_rules,
):
    parser, rules = _analyze(tmp_path, config)
    assert parser.get_ssh_state() == state
    assert rules == expected_rules


@pytest.mark.parametrize(
    ("version_command", "expects_protocol_finding"),
    [
        ("", True),
        ("ip ssh version 1", True),
        ("ip ssh version 2", False),
        ("ip ssh version invalid", True),
    ],
)
def test_ssh_protocol_modes(tmp_path, version_command, expects_protocol_finding):
    commands = tuple(command for command in (version_command, "ip ssh time-out 60") if command)
    _, rules = _analyze(
        tmp_path,
        _ssh_config(
            *commands,
            vty_children=("transport input ssh", "access-class MGMT in"),
        ),
    )
    assert ("cisco.ios.ssh.protocol_version" in rules) is expects_protocol_finding


def test_ssh_uses_documented_numeric_defaults(tmp_path):
    parser, rules = _analyze(
        tmp_path,
        _ssh_config(
            "ip ssh version 2",
            vty_children=("transport input ssh", "access-class MGMT in"),
        ),
    )

    assert parser.get_ssh_authentication_retries().value == 3
    assert parser.get_ssh_authentication_retries().configured is False
    assert "cisco.ios.ssh.authentication_retries" not in rules
    assert parser.get_ssh_timeout().value == 120
    assert parser.get_ssh_timeout().configured is False
    assert "cisco.ios.ssh.negotiation_timeout" in rules


@pytest.mark.parametrize(
    ("command", "rule_id", "expected"),
    [
        ("ip ssh authentication-retries 5", "cisco.ios.ssh.authentication_retries", False),
        ("ip ssh authentication-retries 6", "cisco.ios.ssh.authentication_retries", True),
        ("ip ssh authentication-retries 0", "cisco.ios.ssh.authentication_retries", True),
        ("ip ssh authentication-retries many", "cisco.ios.ssh.authentication_retries", True),
        ("ip ssh time-out 60", "cisco.ios.ssh.negotiation_timeout", False),
        ("ip ssh time-out 61", "cisco.ios.ssh.negotiation_timeout", True),
        ("ip ssh time-out 0", "cisco.ios.ssh.negotiation_timeout", True),
        ("ip ssh time-out long", "cisco.ios.ssh.negotiation_timeout", True),
        ("ip ssh timeout 60", "cisco.ios.ssh.negotiation_timeout", False),
    ],
)
def test_ssh_numeric_boundaries_and_invalid_tokens(tmp_path, command, rule_id, expected):
    _, rules = _analyze(
        tmp_path,
        _ssh_config(
            "ip ssh version 2",
            "ip ssh authentication-retries 3",
            "ip ssh time-out 60",
            command,
            vty_children=("transport input ssh", "access-class MGMT in"),
        ),
    )
    assert (rule_id in rules) is expected


@pytest.mark.parametrize(
    "access_command",
    ["access-class 23 in", "access-class MGMT in vrf-also", "ipv6 access-class V6-MGMT in"],
)
def test_ssh_accepts_ipv4_and_ipv6_vty_access_classes(tmp_path, access_command):
    _, rules = _analyze(
        tmp_path,
        _ssh_config(
            "ip ssh version 2",
            "ip ssh time-out 60",
            vty_children=("transport input all", access_command),
        ),
    )
    assert "cisco.ios.ssh.vty_access_restriction" not in rules


def test_outbound_source_interface_does_not_replace_vty_access_control(tmp_path):
    _, rules = _analyze(
        tmp_path,
        _ssh_config(
            "ip ssh version 2",
            "ip ssh time-out 60",
            "ip ssh source-interface Loopback0",
            vty_children=("transport input ssh",),
        ),
    )
    assert "cisco.ios.ssh.vty_access_restriction" in rules


def test_every_ssh_enabled_vty_range_must_be_restricted(tmp_path):
    config = """ip ssh version 2
ip ssh time-out 60
line vty 0 4
 transport input ssh
 access-class MGMT in
line vty 5 15
 transport input ssh
"""
    _, rules = _analyze(tmp_path, config)
    assert "cisco.ios.ssh.vty_access_restriction" in rules
